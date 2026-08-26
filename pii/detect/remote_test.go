package detect

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// nerServer 是可控的假 NER 服务。
type nerServer struct {
	*httptest.Server
	calls    atomic.Int64
	entities atomic.Value // []nerEntity
	status   atomic.Int32
	delay    atomic.Int64 // 纳秒
}

// newNERServer 启动假 NER 服务。
func newNERServer(t *testing.T, entities ...nerEntity) *nerServer {
	t.Helper()
	s := &nerServer{}
	s.entities.Store(entities)
	s.status.Store(http.StatusOK)

	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		if d := s.delay.Load(); d > 0 {
			time.Sleep(time.Duration(d))
		}
		if code := int(s.status.Load()); code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		var req nerRequest
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(nerResponse{Entities: s.entities.Load().([]nerEntity)})
	}))
	t.Cleanup(s.Close)
	return s
}

// newRemoteDetector 构造指向假服务的检测器。
func newRemoteDetector(t *testing.T, s *nerServer, mutate func(*RemoteNEROptions)) *RemoteNERDetector {
	t.Helper()
	opts := RemoteNEROptions{
		Endpoint: s.URL,
		Timeout:  2 * time.Second,
		CacheTTL: time.Minute,
	}
	if mutate != nil {
		mutate(&opts)
	}
	d, err := NewRemoteNERDetector(opts)
	if err != nil {
		t.Fatalf("构造检测器失败: %v", err)
	}
	return d
}

// TestRemoteNERDetectsNames 校验基本识别能力。
func TestRemoteNERDetectsNames(t *testing.T) {
	s := newNERServer(t, nerEntity{Type: "NAME", Value: "张伟", Confidence: 0.95})
	d := newRemoteDetector(t, s, nil)

	entities, err := d.Detect("请联系客户张伟处理工单")
	if err != nil {
		t.Fatalf("检测失败: %v", err)
	}
	if len(entities) != 1 || entities[0].Type != TypeName || entities[0].Value != "张伟" {
		t.Fatalf("识别结果错误: %+v", entities)
	}
}

// TestByteOffsetsCorrectForChinese 校验中文下偏移量为字节而非字符。
//
// 这是跨语言集成最隐蔽的坑：Python NER 服务返回的是字符索引，
// 一个中文字符占 3 字节，直接采信会把文本切碎——而且**只在含中文时出错**，
// 用英文测试完全正常，能一路带到生产。
//
// 本实现让服务只返回实体文本，由 Go 侧回原文定位，从根上消除这个可能。
func TestByteOffsetsCorrectForChinese(t *testing.T) {
	text := "客户张伟和李娜都在星辰科技工作"
	s := newNERServer(t,
		nerEntity{Type: "NAME", Value: "张伟", Confidence: 0.95},
		nerEntity{Type: "NAME", Value: "李娜", Confidence: 0.95},
		nerEntity{Type: "ORG", Value: "星辰科技", Confidence: 0.9},
	)
	d := newRemoteDetector(t, s, nil)

	entities, err := d.Detect(text)
	if err != nil {
		t.Fatalf("检测失败: %v", err)
	}
	if len(entities) != 3 {
		t.Fatalf("应识别 3 个实体，实际 %d: %+v", len(entities), entities)
	}
	// 核心断言：用返回的偏移切原文，必须精确等于实体文本
	for _, e := range entities {
		if e.Start < 0 || e.End > len(text) {
			t.Fatalf("偏移越界: [%d:%d] len=%d", e.Start, e.End, len(text))
		}
		if got := text[e.Start:e.End]; got != e.Value {
			t.Errorf("偏移错位：text[%d:%d]=%q，实体为 %q（字符偏移被当成字节了？）",
				e.Start, e.End, got, e.Value)
		}
	}
}

// TestHallucinatedEntityDiscarded 校验模型改写过的实体被丢弃。
//
// 模型可能补全、翻译或纠错实体（"张伟"→"张伟先生"），
// 此时片段在原文中不存在，用错误偏移替换会破坏正文。
func TestHallucinatedEntityDiscarded(t *testing.T) {
	s := newNERServer(t,
		nerEntity{Type: "NAME", Value: "张伟", Confidence: 0.95},
		nerEntity{Type: "NAME", Value: "王五先生", Confidence: 0.9}, // 原文中不存在
	)
	d := newRemoteDetector(t, s, nil)

	entities, err := d.Detect("客户张伟来电")
	if err != nil {
		t.Fatalf("检测失败: %v", err)
	}
	if len(entities) != 1 || entities[0].Value != "张伟" {
		t.Errorf("原文中不存在的实体应被丢弃，实际 %+v", entities)
	}
}

// TestRepeatedEntityAllMarked 校验同一实体多次出现时全部标记。
func TestRepeatedEntityAllMarked(t *testing.T) {
	s := newNERServer(t, nerEntity{Type: "NAME", Value: "张伟", Confidence: 0.95})
	d := newRemoteDetector(t, s, nil)

	entities, _ := d.Detect("张伟说，张伟做，张伟负责")
	if len(entities) != 3 {
		t.Errorf("应标记全部 3 处出现，实际 %d: %+v", len(entities), entities)
	}
}

// TestCacheAvoidsRepeatedInference 校验缓存省掉重复推理。
//
// 这是 NER 能否用于生产的关键：Agent 每轮携带完全相同的系统提示词，
// 不缓存则每轮多付一次全额推理延迟，直接压在 TTFT 上。
func TestCacheAvoidsRepeatedInference(t *testing.T) {
	s := newNERServer(t, nerEntity{Type: "NAME", Value: "张伟", Confidence: 0.95})
	d := newRemoteDetector(t, s, nil)

	sysPrompt := "你是企业助手。SOP：第一步核对客户张伟的信息……（此处省略数千字）"
	for i := 0; i < 50; i++ {
		if _, err := d.Detect(sysPrompt); err != nil {
			t.Fatalf("第 %d 次检测失败: %v", i, err)
		}
	}
	if n := s.calls.Load(); n != 1 {
		t.Errorf("相同文本应只推理 1 次，实际调用 %d 次", n)
	}
	hits, misses := d.CacheStats()
	if hits != 49 || misses != 1 {
		t.Errorf("缓存统计错误: hits=%d misses=%d", hits, misses)
	}
}

// TestCacheExpiry 校验缓存 TTL 生效。
func TestCacheExpiry(t *testing.T) {
	s := newNERServer(t, nerEntity{Type: "NAME", Value: "张伟"})
	d := newRemoteDetector(t, s, func(o *RemoteNEROptions) {
		o.CacheTTL = 20 * time.Millisecond
	})

	d.Detect("张伟")
	time.Sleep(40 * time.Millisecond)
	d.Detect("张伟")
	if n := s.calls.Load(); n != 2 {
		t.Errorf("缓存过期后应重新推理，实际调用 %d 次", n)
	}
}

// TestFailClosedBlocksOnServiceDown 校验服务不可用时默认阻断。
//
// 检测不了就不许出站——这是脱敏网关唯一安全的默认行为。
func TestFailClosedBlocksOnServiceDown(t *testing.T) {
	s := newNERServer(t)
	s.status.Store(http.StatusInternalServerError)
	d := newRemoteDetector(t, s, nil)

	if _, err := d.Detect("张伟"); err == nil {
		t.Error("服务不可用时 fail-closed 必须报错，让上层阻断请求")
	}
}

// TestFailOpenPassesThrough 校验显式开启 fail-open 时放行。
func TestFailOpenPassesThrough(t *testing.T) {
	s := newNERServer(t)
	s.status.Store(http.StatusInternalServerError)
	d := newRemoteDetector(t, s, func(o *RemoteNEROptions) { o.FailOpen = true })

	entities, err := d.Detect("张伟")
	if err != nil {
		t.Errorf("fail-open 不应报错: %v", err)
	}
	if len(entities) != 0 {
		t.Errorf("fail-open 应返回空实体，实际 %+v", entities)
	}
}

// TestCircuitBreakerAvoidsRepeatedTimeouts 校验熔断避免每个请求都白等超时。
//
// 没有熔断，一次 NER 服务故障会让**所有**请求延迟 +timeout，
// 故障从「脱敏失效」升级为「全站变慢」。
func TestCircuitBreakerAvoidsRepeatedTimeouts(t *testing.T) {
	s := newNERServer(t)
	s.status.Store(http.StatusInternalServerError)
	d := newRemoteDetector(t, s, func(o *RemoteNEROptions) {
		o.FailureThreshold = 3
		o.Cooldown = time.Minute
	})

	for i := 0; i < 20; i++ {
		d.Detect("文本" + string(rune('a'+i))) // 不同文本，避免缓存干扰
	}
	// 达阈值后熔断，后续请求不再真正发出
	if n := s.calls.Load(); n > 5 {
		t.Errorf("熔断后不应继续打服务，实际调用 %d 次", n)
	}
}

// TestTimeoutIsTight 校验超时生效——NER 延迟直接叠加在 TTFT 上。
func TestTimeoutIsTight(t *testing.T) {
	s := newNERServer(t, nerEntity{Type: "NAME", Value: "张伟"})
	s.delay.Store(int64(500 * time.Millisecond))
	d := newRemoteDetector(t, s, func(o *RemoteNEROptions) {
		o.Timeout = 50 * time.Millisecond
	})

	start := time.Now()
	_, err := d.Detect("张伟")
	elapsed := time.Since(start)

	if err == nil {
		t.Error("超时应报错")
	}
	if elapsed > 300*time.Millisecond {
		t.Errorf("超时未生效，耗时 %v——NER 延迟会直接压在 TTFT 上", elapsed)
	}
}

// TestUnrequestedTypesIgnored 校验服务返回未申请的类型时被忽略。
func TestUnrequestedTypesIgnored(t *testing.T) {
	s := newNERServer(t,
		nerEntity{Type: "NAME", Value: "张伟"},
		nerEntity{Type: "PHONE", Value: "张伟"}, // 未申请 PHONE（那是正则的活）
	)
	d := newRemoteDetector(t, s, func(o *RemoteNEROptions) {
		o.Types = []EntityType{TypeName}
	})

	entities, _ := d.Detect("张伟")
	for _, e := range entities {
		if e.Type != TypeName {
			t.Errorf("未申请的类型应被忽略，实际收到 %s", e.Type)
		}
	}
}

// TestCompositeWithRemoteNERClosesGap 校验接入 NER 后覆盖缺口被补上。
//
// 这正是接入 NER 的目的：不接的话，网关启动会告警
// 「NAME/ADDRESS/ORG 将完全裸奔」。
func TestCompositeWithRemoteNERClosesGap(t *testing.T) {
	s := newNERServer(t)
	d := newRemoteDetector(t, s, nil)

	before := NewCompositeDetector([]Detector{NewRegexDetector()}, 0)
	if len(before.Missing()) == 0 {
		t.Fatal("仅正则时应存在覆盖缺口")
	}

	after := NewCompositeDetector([]Detector{NewRegexDetector(), d}, 0)
	if missing := after.Missing(); len(missing) != 0 {
		t.Errorf("接入 NER 后缺口应被补上，仍缺: %v", missing)
	}
}

// TestEmptyTextSkipsCall 校验空文本不触发服务调用。
func TestEmptyTextSkipsCall(t *testing.T) {
	s := newNERServer(t)
	d := newRemoteDetector(t, s, nil)
	for _, text := range []string{"", "   ", "\n\t"} {
		d.Detect(text)
	}
	if s.calls.Load() != 0 {
		t.Errorf("空文本不应调用服务，实际 %d 次", s.calls.Load())
	}
}

// TestConcurrentDetect 校验并发检测的正确性。
func TestConcurrentDetect(t *testing.T) {
	s := newNERServer(t, nerEntity{Type: "NAME", Value: "张伟"})
	d := newRemoteDetector(t, s, nil)

	done := make(chan struct{})
	for i := 0; i < 32; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 20; j++ {
				if _, err := d.Detect("客户张伟的工单"); err != nil {
					t.Errorf("并发检测失败: %v", err)
					return
				}
			}
		}(i)
	}
	for i := 0; i < 32; i++ {
		<-done
	}
}
