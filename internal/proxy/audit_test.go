package proxy

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/internal/credential"
	"github.com/xinleishen84-afk/airlock-agent/internal/lifecycle"
	"github.com/xinleishen84-afk/airlock-agent/internal/ratelimit"
	"github.com/xinleishen84-afk/airlock-agent/internal/routing"
	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// buildTwoBackendHandler 构造一个双后端网关，用于验收失效转移。
func buildTwoBackendHandler(t *testing.T, urlA, urlB string, hitB *atomic.Int64) *Handler {
	t.Helper()
	targets := []*routing.Target{
		{Name: "primary", Tier: routing.Tier1Premium, BaseURL: urlA,
			Model: "premium", Weight: 100, Enabled: true},
		{Name: "standby", Tier: routing.Tier2Standard, BaseURL: urlB,
			Model: "standard", Weight: 100, Enabled: true, SelfHosted: true},
	}
	policy, err := routing.NewPolicy(targets, nil, routing.Tier1Premium,
		map[routing.Tier]routing.Tier{routing.Tier1Premium: routing.Tier2Standard}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return NewHandler(Deps{
		Policy: policy,
		Breakers: map[string]*routing.Breaker{
			"primary": routing.NewBreaker("primary", 5, time.Minute),
			"standby": routing.NewBreaker("standby", 5, time.Minute),
		},
		Creds:   map[string]*credential.BackendPolicy{},
		Limiter: ratelimit.NewLimiter(ratelimit.Limits{TokensPerWindow: 1e9, Window: time.Minute}),
		Vaults:  anonymize.NewVaultRegistry(time.Hour, 100),
		Client:  NewClient(DefaultTransportConfig()),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

// TestFailoverOnUpstreamConnectionError 验收「多模型 Fallback」：
// 首选后端连不上时，应转移到降级链上的下一个后端，而不是直接报错给客户端。
func TestFailoverOnUpstreamConnectionError(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // 立刻关闭，制造连接失败

	var hitB atomic.Int64
	standby := newUpstream(t, upstreamOpts{
		chunks:    []string{`{"choices":[{"delta":{"content":"来自备用"}}]}`},
		onRequest: func(*http.Request, []byte) { hitB.Add(1) },
	})
	defer standby.Close()

	h := buildTwoBackendHandler(t, deadURL, standby.URL, &hitB)
	rec := doRequest(t, h, `{"model":"m","stream":true,"messages":[]}`,
		map[string]string{"X-Workload-Priority": "6", "X-Workload-Task": "planning"})

	if rec.Code != http.StatusOK {
		t.Errorf("首选后端不可达时应转移到备用后端，实际返回 %d：%s", rec.Code, rec.Body.String())
	}
	if hitB.Load() != 1 {
		t.Errorf("备用后端未收到请求（转移未发生），命中次数 %d", hitB.Load())
	}
}

// TestFailoverOnUpstream5xx 验收：首选后端返回 5xx 时应转移。
// 5xx 是后端故障，换一个后端很可能就成功了；把 5xx 原样透传给客户端
// 等于把可恢复的故障变成了用户可见的失败。
func TestFailoverOnUpstream5xx(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal"}`))
	}))
	defer broken.Close()

	var hitB atomic.Int64
	standby := newUpstream(t, upstreamOpts{
		chunks:    []string{`{"choices":[{"delta":{"content":"来自备用"}}]}`},
		onRequest: func(*http.Request, []byte) { hitB.Add(1) },
	})
	defer standby.Close()

	h := buildTwoBackendHandler(t, broken.URL, standby.URL, &hitB)
	rec := doRequest(t, h, `{"model":"m","stream":true,"messages":[]}`,
		map[string]string{"X-Workload-Priority": "6", "X-Workload-Task": "planning"})

	if rec.Code != http.StatusOK {
		t.Errorf("首选后端 5xx 时应转移，实际返回 %d", rec.Code)
	}
	if hitB.Load() != 1 {
		t.Errorf("备用后端未收到请求，命中次数 %d", hitB.Load())
	}
}

// TestNo4xxFailover 验收：4xx 不应转移。
// 参数非法是调用方的问题，换后端也一样失败，只会白白放大延迟。
func TestNo4xxFailover(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid model"}`))
	}))
	defer bad.Close()

	var hitB atomic.Int64
	standby := newUpstream(t, upstreamOpts{chunks: []string{`{"delta":"x"}`},
		onRequest: func(*http.Request, []byte) { hitB.Add(1) }})
	defer standby.Close()

	h := buildTwoBackendHandler(t, bad.URL, standby.URL, &hitB)
	rec := doRequest(t, h, `{"model":"m","stream":true,"messages":[]}`,
		map[string]string{"X-Workload-Priority": "6", "X-Workload-Task": "planning"})

	if rec.Code != http.StatusBadRequest {
		t.Errorf("4xx 应原样透传，实际 %d", rec.Code)
	}
	if hitB.Load() != 0 {
		t.Errorf("4xx 不应触发转移，备用后端却被调用了 %d 次", hitB.Load())
	}
}

// TestUnredactionPreservesJSONValidity 验收「PII 双向脱敏」的复原侧。
//
// 复原是把占位符换回真实值。若真实值含有 JSON 特殊字符（引号、反斜杠、
// 换行——地址里换行很常见，姓名里带引号也存在），而复原是在**原始 JSON
// 文本**上做字符串替换，产出的就是非法 JSON，客户端解析器直接罢工。
//
// 这与「NER 污染协议」是同一类问题的反向：在结构化 JSON 上做裸文本操作。
func TestUnredactionPreservesJSONValidity(t *testing.T) {
	// 让上游回吐占位符，模拟模型引用了被脱敏的实体
	up := newUpstream(t, upstreamOpts{chunks: []string{
		`{"choices":[{"delta":{"content":"已通知 ANONYMIZED_NAME_0 处理"}}]}`,
	}})
	defer up.Close()

	h := newTestHandler(t, up.URL, false, true)
	// 名册里放一个含 JSON 特殊字符的姓名
	gaz, err := detect.NewGazetteerDetector(map[detect.EntityType][]string{
		detect.TypeName: {`李"小"娜`},
	}, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	h.deps.Redactor = anonymize.NewRedactor(
		detect.NewCompositeDetector([]detect.Detector{gaz}, 0), true)

	rec := doRequest(t, h,
		`{"model":"m","stream":true,"messages":[{"role":"user","content":"请联系李\"小\"娜"}]}`,
		map[string]string{"X-Session-Id": "s1"})

	if rec.Code != http.StatusOK {
		t.Fatalf("请求失败 %d: %s", rec.Code, rec.Body.String())
	}

	// 逐帧解析客户端收到的 SSE：每个 data 帧都必须是合法 JSON
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok || strings.TrimSpace(payload) == "[DONE]" {
			continue
		}
		var probe any
		if err := json.Unmarshal([]byte(payload), &probe); err != nil {
			t.Fatalf("复原后产出非法 JSON，客户端解析器将罢工：\n  帧内容 %s\n  错误 %v",
				payload, err)
		}
	}
}

// TestBreakerNotTrippedBy4xx 验收高可用：客户端参数错误不应熔断健康后端。
// 否则一个刷错参数的调用方就能把后端打进熔断，影响所有其他用户。
func TestBreakerNotTrippedBy4xx(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer bad.Close()

	var hitB atomic.Int64
	standby := newUpstream(t, upstreamOpts{chunks: []string{`{"d":"x"}`},
		onRequest: func(*http.Request, []byte) { hitB.Add(1) }})
	defer standby.Close()

	h := buildTwoBackendHandler(t, bad.URL, standby.URL, &hitB)
	for i := 0; i < 10; i++ {
		doRequest(t, h, `{"model":"m","stream":true,"messages":[]}`,
			map[string]string{"X-Workload-Task": "planning"})
	}
	if !h.deps.Breakers["primary"].Allow() {
		t.Error("4xx 不应触发熔断——否则刷错参数的调用方能打垮健康后端")
	}
}

// TestFailoverStopsAfterFirstByte 验收：已开始回传后不再转移。
// 否则用户会看到两个模型的输出拼在一起。
func TestFailoverStopsAfterFirstByte(t *testing.T) {
	// 首选后端先正常吐一帧，然后直接断开
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		rc := http.NewResponseController(w)
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"来自主用\"}}]}\n\n"))
		rc.Flush()
		// 不发 [DONE] 就结束，模拟中途断流
	}))
	defer flaky.Close()

	var hitB atomic.Int64
	standby := newUpstream(t, upstreamOpts{chunks: []string{`{"choices":[{"delta":{"content":"来自备用"}}]}`},
		onRequest: func(*http.Request, []byte) { hitB.Add(1) }})
	defer standby.Close()

	h := buildTwoBackendHandler(t, flaky.URL, standby.URL, &hitB)
	rec := doRequest(t, h, `{"model":"m","stream":true,"messages":[]}`,
		map[string]string{"X-Workload-Task": "planning"})

	body := rec.Body.String()
	if !strings.Contains(body, "来自主用") {
		t.Errorf("已回传的内容应保留: %q", body)
	}
	if strings.Contains(body, "来自备用") {
		t.Error("已开始回传后不应转移——两个模型的输出会拼在一起")
	}
	if hitB.Load() != 0 {
		t.Errorf("流已开始后不应再打备用后端，实际 %d 次", hitB.Load())
	}
}

// ---------------------------------------------------------------------------
// 优雅停机
// ---------------------------------------------------------------------------

// TestShutdownRejectsNewButFinishesActiveStream 是三阶段停机的核心验收。
//
// 一条正在吐字的 SSE 流，在停机进入收敛阶段后必须能完整吐完最后一个 token；
// 与此同时，新请求应拿到干净的 503 而不是被中断的连接。
//
// 暴力掐断的后果很具体：上游 Agent 收到截断的流，而它无法区分
// 「生成完毕」与「被掐断」——状态机直接破损。
func TestShutdownRejectsNewButFinishesActiveStream(t *testing.T) {
	up := newUpstream(t, upstreamOpts{
		chunks: []string{`{"choices":[{"delta":{"content":"1"}}]}`,
			`{"choices":[{"delta":{"content":"2"}}]}`,
			`{"choices":[{"delta":{"content":"3"}}]}`},
		delay: 60 * time.Millisecond,
	})
	defer up.Close()

	state := lifecycle.NewState()
	tracker := lifecycle.NewTracker()

	h := newTestHandler(t, up.URL, true, false)
	h.deps.Lifecycle = state
	h.deps.Tracker = tracker

	gw := httptest.NewServer(h)
	defer gw.Close()

	// 起一条流并读到第一帧，确保它已在途
	resp, err := http.Post(gw.URL, "application/json",
		strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatalf("发起流失败: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	firstLine, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(firstLine, `"1"`) {
		t.Fatalf("首帧异常: %q err=%v", firstLine, err)
	}
	if tracker.Streaming() != 1 {
		t.Fatalf("在途流应为 1，实际 %d", tracker.Streaming())
	}

	// 推进到收敛阶段：拒绝新请求，但已在途的流继续
	state.Advance(lifecycle.PhaseDraining)
	state.Advance(lifecycle.PhaseClosing)

	// 新请求应拿到干净的 503 + Retry-After
	newResp, err := http.Post(gw.URL, "application/json",
		strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatalf("新请求应得到 HTTP 响应而非连接错误: %v", err)
	}
	defer newResp.Body.Close()
	if newResp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("收敛阶段新请求应返回 503，实际 %d", newResp.StatusCode)
	}
	if newResp.Header.Get("Retry-After") == "" {
		t.Error("503 应带 Retry-After，否则客户端无从判断何时重试")
	}
	if newResp.Header.Get("X-Gateway-Phase") != "closing" {
		t.Errorf("应暴露当前阶段：%q", newResp.Header.Get("X-Gateway-Phase"))
	}

	// 原有的流必须吐完剩余全部 token
	var got []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "data: ") && !strings.Contains(line, "[DONE]") {
			got = append(got, strings.TrimSpace(line))
		}
	}
	joined := strings.Join(got, "|")
	for _, want := range []string{`"2"`, `"3"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("停机期间在途流被掐断，缺少 token %s：%s", want, joined)
		}
	}

	// 流结束后在途计数应归零，停机才能推进
	deadline := time.After(2 * time.Second)
	for tracker.Streaming() != 0 {
		select {
		case <-deadline:
			t.Fatalf("流结束后在途计数未归零：%d", tracker.Streaming())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestTrackerNotLeakedOnRejectedRequest 校验被拒的请求不计入在途。
//
// 若畸形请求或限流拒绝也被计入，停机时会一直等不到归零，
// 最终只能靠超时强杀——那正是三阶段设计要避免的。
func TestTrackerNotLeakedOnRejectedRequest(t *testing.T) {
	up := newUpstream(t, upstreamOpts{chunks: []string{`{"d":"x"}`}})
	defer up.Close()

	tracker := lifecycle.NewTracker()
	h := newTestHandler(t, up.URL, true, false)
	h.deps.Tracker = tracker

	doRequest(t, h, `{not json`, nil)                     // 400
	doRequest(t, h, `{"stream":true,"messages":[]}`, nil) // 200
	if tracker.InFlight() != 0 {
		t.Errorf("请求结束后在途数应归零，实际 %d——停机将永远等不到归零",
			tracker.InFlight())
	}
}
