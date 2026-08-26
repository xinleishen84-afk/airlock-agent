package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/gpuload"
	"github.com/xinleishen84-afk/airlock-agent/internal/affinity"
	"github.com/xinleishen84-afk/airlock-agent/internal/credential"
	"github.com/xinleishen84-afk/airlock-agent/internal/ratelimit"
	"github.com/xinleishen84-afk/airlock-agent/internal/routing"
	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// upstreamOpts 控制假上游的行为。
type upstreamOpts struct {
	chunks     []string      // 逐帧下发的 data 内容
	delay      time.Duration // 每帧之间的间隔，用于验证流式而非批式
	firstDelay time.Duration // 首帧前的延迟，模拟模型思考
	status     int
	nonSSE     bool
	onRequest  func(*http.Request, []byte)
}

// newUpstream 启动一个可控的假 LLM 上游。
func newUpstream(t *testing.T, opts upstreamOpts) *httptest.Server {
	t.Helper()
	if opts.status == 0 {
		opts.status = http.StatusOK
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if opts.onRequest != nil {
			opts.onRequest(r, body)
		}
		if opts.nonSSE {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(opts.status)
			w.Write([]byte(`{"choices":[{"message":{"content":"非流式响应"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(opts.status)
		rc := http.NewResponseController(w)
		rc.Flush()

		if opts.firstDelay > 0 {
			time.Sleep(opts.firstDelay)
		}
		for _, c := range opts.chunks {
			w.Write([]byte("data: " + c + "\n\n"))
			rc.Flush()
			if opts.delay > 0 {
				time.Sleep(opts.delay)
			}
		}
		w.Write([]byte("data: [DONE]\n\n"))
		rc.Flush()
	}))
}

// newTestHandler 装配一个完整的处理器，后端指向给定 URL。
func newTestHandler(t *testing.T, upstreamURL string, selfHosted bool, redact bool) *Handler {
	t.Helper()
	target := &routing.Target{
		Name: "backend", Tier: routing.Tier2Standard, BaseURL: upstreamURL,
		Model: "gpt-oss-120b", Weight: 100, Enabled: true, SelfHosted: selfHosted,
	}
	policy, err := routing.NewPolicy([]*routing.Target{target}, nil, routing.Tier2Standard, nil, nil)
	if err != nil {
		t.Fatalf("构造策略失败: %v", err)
	}

	deps := Deps{
		Policy:   policy,
		Breakers: map[string]*routing.Breaker{"backend": routing.NewBreaker("backend", 5, time.Minute)},
		Creds: map[string]*credential.BackendPolicy{"backend": {
			Name: "backend", SecretKey: "k", Mode: credential.InjectBearer,
			Provider: credential.NewStaticProvider(map[string]string{"k": "sk-ENTERPRISE"}),
		}},
		Limiter:      ratelimit.NewLimiter(ratelimit.Limits{TokensPerWindow: 10_000_000, Window: time.Minute}),
		Vaults:       anonymize.NewVaultRegistry(time.Hour, 1000),
		Client:       NewClient(DefaultTransportConfig()),
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		AlwaysRedact: redact,
	}
	if redact {
		gaz, _ := detect.NewGazetteerDetector(map[detect.EntityType][]string{
			detect.TypeName: {"张伟"},
		}, false, 2)
		deps.Redactor = anonymize.NewRedactor(
			detect.NewCompositeDetector([]detect.Detector{detect.NewRegexDetector(), gaz}, 0), true)
	}
	return NewHandler(deps)
}

// doRequest 发起一次代理请求，返回响应。
func doRequest(t *testing.T, h *Handler, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestStreamsEndToEnd 校验完整的 SSE 转发链路。
func TestStreamsEndToEnd(t *testing.T) {
	up := newUpstream(t, upstreamOpts{chunks: []string{
		`{"choices":[{"delta":{"content":"你"}}]}`,
		`{"choices":[{"delta":{"content":"好"}}]}`,
	}})
	defer up.Close()

	h := newTestHandler(t, up.URL, true, false)
	rec := doRequest(t, h, `{"model":"gpt-oss-120b","stream":true,"messages":[{"role":"user","content":"hi"}]}`, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d，响应 %s", rec.Code, rec.Body.String())
	}
	out := rec.Body.String()
	if !strings.Contains(out, `"你"`) || !strings.Contains(out, `"好"`) {
		t.Errorf("token 未转发: %q", out)
	}
	if !strings.Contains(out, "data: [DONE]") {
		t.Errorf("缺少结束标记: %q", out)
	}
}

// TestSSEHeadersPreventBuffering 校验防缓冲响应头。
//
// X-Accel-Buffering: no 尤其关键：即使网关逐帧 Flush，前面的 nginx
// 依然会攒包，TTFT 照样秒级——而排查时很容易怪到网关头上。
func TestSSEHeadersPreventBuffering(t *testing.T) {
	up := newUpstream(t, upstreamOpts{chunks: []string{`{"delta":"a"}`}})
	defer up.Close()

	rec := doRequest(t, newTestHandler(t, up.URL, true, false),
		`{"stream":true,"messages":[]}`, nil)

	want := map[string]string{
		"Content-Type":      "text/event-stream",
		"Cache-Control":     "no-cache",
		"X-Accel-Buffering": "no",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("响应头 %s = %q，期望 %q", k, got, v)
		}
	}
}

// TestNoCompressionRequested 校验向上游声明不接受压缩。
//
// 若上游 gzip 了 SSE 流，压缩器会攒够一个 block 才输出，
// token 就不再是涓涓细流而是一坨一坨到达——TTFT 从毫秒退化到秒级。
func TestNoCompressionRequested(t *testing.T) {
	var gotEncoding string
	up := newUpstream(t, upstreamOpts{
		chunks: []string{`{"delta":"a"}`},
		onRequest: func(r *http.Request, _ []byte) {
			gotEncoding = r.Header.Get("Accept-Encoding")
		},
	})
	defer up.Close()

	doRequest(t, newTestHandler(t, up.URL, true, false), `{"stream":true,"messages":[]}`, nil)
	if gotEncoding != "identity" {
		t.Errorf("应向上游声明 Accept-Encoding: identity，实际 %q", gotEncoding)
	}
}

// TestZeroTrustCredentialInjection 校验客户端凭证被剥离、企业凭证被注入。
func TestZeroTrustCredentialInjection(t *testing.T) {
	var gotAuth, gotApiKey string
	up := newUpstream(t, upstreamOpts{
		chunks: []string{`{"delta":"a"}`},
		onRequest: func(r *http.Request, _ []byte) {
			gotAuth = r.Header.Get("Authorization")
			gotApiKey = r.Header.Get("X-Api-Key")
		},
	})
	defer up.Close()

	doRequest(t, newTestHandler(t, up.URL, true, false), `{"stream":true,"messages":[]}`,
		map[string]string{
			"Authorization": "Bearer sk-DEVELOPER-PERSONAL",
			"X-Api-Key":     "stolen",
		})

	if gotAuth != "Bearer sk-ENTERPRISE" {
		t.Errorf("应注入企业凭证，上游实际收到 %q", gotAuth)
	}
	if gotApiKey != "" {
		t.Errorf("客户端自携的 X-Api-Key 应被剥离，上游收到 %q", gotApiKey)
	}
}

// TestPIIRedactedOutbound 校验出站脱敏：真实 PII 不得抵达上游。
func TestPIIRedactedOutbound(t *testing.T) {
	var gotBody string
	up := newUpstream(t, upstreamOpts{
		chunks:    []string{`{"choices":[{"delta":{"content":"已通知 ANONYMIZED_NAME_0"}}]}`},
		onRequest: func(_ *http.Request, b []byte) { gotBody = string(b) },
	})
	defer up.Close()

	h := newTestHandler(t, up.URL, false, true) // 非私有化后端 -> 触发脱敏
	rec := doRequest(t, h,
		`{"stream":true,"messages":[{"role":"user","content":"联系张伟，手机 13812345678"}]}`,
		map[string]string{"X-Session-Id": "s1"})

	for _, secret := range []string{"张伟", "13812345678"} {
		if strings.Contains(gotBody, secret) {
			t.Errorf("真实 PII %q 抵达了上游: %s", secret, gotBody)
		}
	}
	if !strings.Contains(gotBody, "ANONYMIZED_NAME_0") {
		t.Errorf("请求体未见占位符: %s", gotBody)
	}
	// 响应中的占位符应被复原
	if !strings.Contains(rec.Body.String(), "张伟") {
		t.Errorf("响应未复原真实值: %s", rec.Body.String())
	}
}

// TestSelfHostedSkipsRedaction 校验私有化后端默认不脱敏。
// 数据未出企业边界，脱敏只会白白损失模型精度。
func TestSelfHostedSkipsRedaction(t *testing.T) {
	var gotBody string
	up := newUpstream(t, upstreamOpts{
		chunks:    []string{`{"delta":"ok"}`},
		onRequest: func(_ *http.Request, b []byte) { gotBody = string(b) },
	})
	defer up.Close()

	h := newTestHandler(t, up.URL, true, false)
	doRequest(t, h, `{"stream":true,"messages":[{"role":"user","content":"张伟"}]}`, nil)
	if !strings.Contains(gotBody, "张伟") {
		t.Error("私有化后端不应脱敏")
	}
}

// TestRateLimitRejects 校验配额耗尽时返回 429 且带 Retry-After。
func TestRateLimitRejects(t *testing.T) {
	up := newUpstream(t, upstreamOpts{chunks: []string{`{"delta":"a"}`}})
	defer up.Close()

	h := newTestHandler(t, up.URL, true, false)
	h.deps.Limiter = ratelimit.NewLimiter(ratelimit.Limits{TokensPerWindow: 100, Window: time.Minute})

	rec := doRequest(t, h, `{"stream":true,"max_tokens":99999,"messages":[]}`, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("超配额应返回 429，实际 %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 应带 Retry-After")
	}
}

// TestQuotaRefundedAfterStream 校验流结束后按实际用量回填配额。
func TestQuotaRefundedAfterStream(t *testing.T) {
	up := newUpstream(t, upstreamOpts{chunks: []string{
		`{"choices":[{"delta":{"content":"a"}}]}`,
		`{"choices":[],"usage":{"prompt_tokens":50,"completion_tokens":20}}`,
	}})
	defer up.Close()

	h := newTestHandler(t, up.URL, true, false)
	limiter := ratelimit.NewLimiter(ratelimit.Limits{TokensPerWindow: 1_000_000, Window: time.Minute})
	h.deps.Limiter = limiter

	doRequest(t, h, `{"stream":true,"max_tokens":100000,"messages":[]}`,
		map[string]string{"X-Workload-Tenant": "acme", "X-Workload-App": "bot"})

	used, inflight, _ := limiter.Snapshot("acme/bot")
	if inflight != 0 {
		t.Errorf("流结束后在途数应归零，实际 %d", inflight)
	}
	// 预扣 10 万 token，实际只用 70，回填后应远小于预扣
	if used > 1000 {
		t.Errorf("配额应已按实际用量回填，实际仍占用 %d", used)
	}
}

// TestClientDisconnectReleasesQuota 校验客户端断连时释放预留。
// 若没有这一步，一次断连就永久占住一份配额，窗口会被慢慢漏干。
func TestClientDisconnectReleasesQuota(t *testing.T) {
	up := newUpstream(t, upstreamOpts{
		chunks: []string{`{"delta":"a"}`, `{"delta":"b"}`}, delay: 200 * time.Millisecond,
	})
	defer up.Close()

	h := newTestHandler(t, up.URL, true, false)
	limiter := ratelimit.NewLimiter(ratelimit.Limits{TokensPerWindow: 1_000_000, Window: time.Minute})
	h.deps.Limiter = limiter

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"stream":true,"max_tokens":50000,"messages":[]}`)).WithContext(ctx)
	req.Header.Set("X-Workload-Tenant", "acme")
	req.Header.Set("X-Workload-App", "bot")

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel() // 模拟客户端断连
	<-done

	_, inflight, _ := limiter.Snapshot("acme/bot")
	if inflight != 0 {
		t.Errorf("断连后预留应被释放，在途数仍为 %d", inflight)
	}
}

// TestNonSSEPassthrough 校验非流式响应正常透传。
func TestNonSSEPassthrough(t *testing.T) {
	up := newUpstream(t, upstreamOpts{nonSSE: true})
	defer up.Close()

	rec := doRequest(t, newTestHandler(t, up.URL, true, false), `{"messages":[]}`, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "非流式响应") {
		t.Errorf("非流式透传失败: %d %s", rec.Code, rec.Body.String())
	}
}

// TestBreakerBlocksWhenOpen 校验熔断状态下拒绝请求。
func TestBreakerBlocksWhenOpen(t *testing.T) {
	up := newUpstream(t, upstreamOpts{chunks: []string{`{"delta":"a"}`}})
	defer up.Close()

	h := newTestHandler(t, up.URL, true, false)
	b := h.deps.Breakers["backend"]
	for i := 0; i < 10; i++ {
		b.RecordFailure()
	}

	rec := doRequest(t, h, `{"stream":true,"messages":[]}`, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("熔断状态应返回 503，实际 %d", rec.Code)
	}
}

// TestMalformedBodyRejected 校验畸形请求体被拒。
func TestMalformedBodyRejected(t *testing.T) {
	up := newUpstream(t, upstreamOpts{chunks: []string{`{"delta":"a"}`}})
	defer up.Close()

	rec := doRequest(t, newTestHandler(t, up.URL, true, false), `{not json`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("畸形 JSON 应返回 400，实际 %d", rec.Code)
	}
}

// TestTTFTRecorded 校验 TTFT 指标被采集。
func TestTTFTRecorded(t *testing.T) {
	up := newUpstream(t, upstreamOpts{
		chunks: []string{`{"delta":"a"}`}, firstDelay: 30 * time.Millisecond,
	})
	defer up.Close()

	h := newTestHandler(t, up.URL, true, false)
	doRequest(t, h, `{"stream":true,"messages":[]}`, nil)

	if h.Stats().TTFTCount.Load() != 1 {
		t.Fatalf("应记录 1 次 TTFT，实际 %d", h.Stats().TTFTCount.Load())
	}
	if ttft := h.Stats().AvgTTFT(); ttft < 25*time.Millisecond {
		t.Errorf("TTFT 记录异常: %v", ttft)
	}
}

// TestActuallyStreamsIncrementally 校验数据是逐帧到达而非攒完一次性发出。
//
// 这是全链路流式最核心的断言：少了逐帧 Flush，功能完全正常，只是慢——
// 而且慢得毫无征兆。用真实 TCP 连接读取，才能测出这个差别。
func TestActuallyStreamsIncrementally(t *testing.T) {
	up := newUpstream(t, upstreamOpts{
		chunks: []string{`{"delta":"1"}`, `{"delta":"2"}`, `{"delta":"3"}`},
		delay:  80 * time.Millisecond,
	})
	defer up.Close()

	gw := httptest.NewServer(newTestHandler(t, up.URL, true, false))
	defer gw.Close()

	resp, err := http.Post(gw.URL, "application/json",
		strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	start := time.Now()
	var arrivals []time.Duration
	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "data: ") && !strings.Contains(line, "[DONE]") {
			arrivals = append(arrivals, time.Since(start))
		}
	}

	if len(arrivals) != 3 {
		t.Fatalf("应收到 3 帧，实际 %d", len(arrivals))
	}
	// 若是攒完一次性发出，三帧到达时间会几乎相同
	gap := arrivals[2] - arrivals[0]
	if gap < 100*time.Millisecond {
		t.Errorf("帧间隔仅 %v，数据被缓冲了——流式退化成了批式", gap)
	}
	// 首帧应远早于末帧，这正是 TTFT 的意义
	if arrivals[0] > 60*time.Millisecond {
		t.Errorf("首帧延迟 %v 过高，未能实现毫秒级 TTFT", arrivals[0])
	}
}

// TestHeartbeatPassedThrough 校验注释帧（保活心跳）原样透传。
func TestHeartbeatPassedThrough(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		rc := http.NewResponseController(w)
		w.Write([]byte(": keep-alive\n\n"))
		rc.Flush()
		w.Write([]byte("data: {\"delta\":\"a\"}\n\ndata: [DONE]\n\n"))
		rc.Flush()
	}))
	defer up.Close()

	rec := doRequest(t, newTestHandler(t, up.URL, true, false), `{"stream":true,"messages":[]}`, nil)
	if !strings.Contains(rec.Body.String(), ": keep-alive") {
		t.Errorf("心跳帧被吞掉了，中间设备可能因此断连: %q", rec.Body.String())
	}
}

// TestUsageExtraction 校验从末帧抽取 token 用量。
func TestUsageExtraction(t *testing.T) {
	var usage ratelimit.Usage
	accumulateUsage(&usage, []byte(`{"choices":[],"usage":{"prompt_tokens":123,"completion_tokens":45}}`))
	if usage.InputTokens != 123 || usage.OutputTokens != 45 {
		t.Errorf("用量抽取错误: %+v", usage)
	}

	// 普通 chunk 不含 usage，不应误改
	before := usage
	accumulateUsage(&usage, []byte(`{"choices":[{"delta":{"content":"a"}}]}`))
	if usage != before {
		t.Error("无 usage 的帧不应改动统计")
	}
}

// TestUnknownFieldsPreserved 校验未知字段原样透传给上游。
// 网关不该假设自己认识协议全貌，吃掉未知字段会让上游新特性失效。
func TestUnknownFieldsPreserved(t *testing.T) {
	var gotBody map[string]any
	up := newUpstream(t, upstreamOpts{
		chunks: []string{`{"delta":"a"}`},
		onRequest: func(_ *http.Request, b []byte) {
			json.Unmarshal(b, &gotBody)
		},
	})
	defer up.Close()

	h := newTestHandler(t, up.URL, false, true) // 开启脱敏，走 JSON 重写路径
	doRequest(t, h,
		`{"stream":true,"messages":[],"future_feature":{"nested":true},"top_p":0.9}`, nil)

	if _, ok := gotBody["future_feature"]; !ok {
		t.Errorf("未知字段被吃掉了: %+v", gotBody)
	}
	if gotBody["top_p"] != 0.9 {
		t.Errorf("已知但未声明的字段丢失: %+v", gotBody)
	}
}

// ---------------------------------------------------------------------------
// GPU 显存准入与前缀亲和
// ---------------------------------------------------------------------------

// TestGPUPressureShedsLowPriority 校验显存吃紧时在边缘拒绝低优先级请求。
//
// 这是防止 GPU 死锁的第一道闸：等到 KV 完全打满再一刀切，
// 队列里已经全是低价值请求，高价值请求照样排在后面。
func TestGPUPressureShedsLowPriority(t *testing.T) {
	up := newUpstream(t, upstreamOpts{chunks: []string{`{"delta":"a"}`}})
	defer up.Close()

	h := newTestHandler(t, up.URL, true, false)
	reg := gpuload.NewRegistry()
	st := reg.Register("backend", gpuload.DefaultThresholds())
	st.Update(gpuload.Snapshot{Valid: true, KVCacheUsage: 0.82}) // Elevated
	h.deps.GPULoad = reg

	// 批量作业（低优先级）应被挡掉
	rec := doRequest(t, h, `{"stream":true,"messages":[]}`,
		map[string]string{"X-Workload-Priority": "2"})
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("显存吃紧时低优先级应返回 429，实际 %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("边缘降级应给出 Retry-After，避免客户端立刻重试")
	}
	if h.Stats().GPUShed.Load() != 1 {
		t.Errorf("应计入 GPUShed，实际 %d", h.Stats().GPUShed.Load())
	}

	// 高优先级仍应放行
	rec = doRequest(t, h, `{"stream":true,"messages":[]}`,
		map[string]string{"X-Workload-Priority": "7"})
	if rec.Code != http.StatusOK {
		t.Errorf("显存吃紧时高优先级应放行，实际 %d", rec.Code)
	}
}

// TestCriticalPressureRejectsWithRetryAfter 校验唯一后端 Critical 时的响应语义。
//
// 返回 429 + Retry-After 而非 503：请求是因显存压力被主动降级的，
// 后端本身还在服务，告诉客户端「稍后重试」比「没有后端」准确得多——
// 前者会退避重试，后者可能触发上游的故障转移逻辑。
func TestCriticalPressureRejectsWithRetryAfter(t *testing.T) {
	up := newUpstream(t, upstreamOpts{chunks: []string{`{"delta":"a"}`}})
	defer up.Close()

	h := newTestHandler(t, up.URL, true, false)
	reg := gpuload.NewRegistry()
	st := reg.Register("backend", gpuload.DefaultThresholds())
	st.Update(gpuload.Snapshot{Valid: true, KVCacheUsage: 0.97}) // Critical
	h.deps.GPULoad = reg

	rec := doRequest(t, h, `{"stream":true,"messages":[]}`,
		map[string]string{"X-Workload-Priority": "5"})
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("唯一后端 Critical 时应返回 429，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("显存降级必须给出 Retry-After，否则客户端会立刻重试把刚腾出的 KV 又填满")
	}
}

// TestPreemptionTriggersShedding 校验抢占发生时立即降压。
//
// 抢占意味着 KV 已不够用、后端在反复换出重算，此时 KV 占用读数
// 可能反而下降，只看占用率会误判为好转。
func TestPreemptionTriggersShedding(t *testing.T) {
	up := newUpstream(t, upstreamOpts{chunks: []string{`{"delta":"a"}`}})
	defer up.Close()

	h := newTestHandler(t, up.URL, true, false)
	reg := gpuload.NewRegistry()
	st := reg.Register("backend", gpuload.DefaultThresholds())
	st.Update(gpuload.Snapshot{Valid: true, KVCacheUsage: 0.30, Preemptions: 0})
	st.Update(gpuload.Snapshot{Valid: true, KVCacheUsage: 0.25, Preemptions: 5})
	h.deps.GPULoad = reg

	rec := doRequest(t, h, `{"stream":true,"messages":[]}`,
		map[string]string{"X-Workload-Priority": "5"})
	if rec.Code == http.StatusOK {
		t.Error("抢占发生时中等优先级不应放行——KV 占用下降只是换出的假象")
	}
}

// TestPrefixAffinityPinsRequests 校验同前缀请求稳定落到同一后端。
//
// vLLM 的 prefix caching 是每副本本地的：请求被打散到 N 个副本，
// 命中率就降到 1/N。后端开了缓存，收益却被网关亲手摧毁。
func TestPrefixAffinityPinsRequests(t *testing.T) {
	var hitsA, hitsB atomic.Int64
	upA := newUpstream(t, upstreamOpts{
		chunks:    []string{`{"delta":"a"}`},
		onRequest: func(*http.Request, []byte) { hitsA.Add(1) },
	})
	defer upA.Close()
	upB := newUpstream(t, upstreamOpts{
		chunks:    []string{`{"delta":"b"}`},
		onRequest: func(*http.Request, []byte) { hitsB.Add(1) },
	})
	defer upB.Close()

	targets := []*routing.Target{
		{Name: "gpu-a", Tier: routing.Tier2Standard, BaseURL: upA.URL,
			Model: "m", Weight: 100, Enabled: true, SelfHosted: true},
		{Name: "gpu-b", Tier: routing.Tier2Standard, BaseURL: upB.URL,
			Model: "m", Weight: 100, Enabled: true, SelfHosted: true},
	}
	policy, err := routing.NewPolicy(targets, nil, routing.Tier2Standard, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	h := NewHandler(Deps{
		Policy: policy,
		Breakers: map[string]*routing.Breaker{
			"gpu-a": routing.NewBreaker("gpu-a", 5, time.Minute),
			"gpu-b": routing.NewBreaker("gpu-b", 5, time.Minute),
		},
		Creds:    map[string]*credential.BackendPolicy{},
		Limiter:  ratelimit.NewLimiter(ratelimit.Limits{TokensPerWindow: 100_000_000, Window: time.Minute}),
		Vaults:   anonymize.NewVaultRegistry(time.Hour, 1000),
		Client:   NewClient(DefaultTransportConfig()),
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Affinity: affinity.NewRing([]string{"gpu-a", "gpu-b"}, 1000),
	})

	// 同一系统前缀，用户消息每轮不同
	body := `{"model":"m","stream":true,"messages":[` +
		`{"role":"system","content":"你是企业助手，遵循以下 SOP……"},` +
		`{"role":"user","content":"第 %d 轮提问，内容每次都不同"}]}`

	for i := 0; i < 20; i++ {
		doRequest(t, h, fmt.Sprintf(body, i), nil)
	}

	a, b := hitsA.Load(), hitsB.Load()
	if a != 20 && b != 20 {
		t.Errorf("同前缀请求应全部钉在一个副本上，实际 gpu-a=%d gpu-b=%d", a, b)
	}
	if h.Stats().PrefixPinned.Load() != 20 {
		t.Errorf("应全部命中亲和路由，实际 %d", h.Stats().PrefixPinned.Load())
	}
}

// TestDifferentPrefixesSpread 校验不同前缀分散到不同副本。
func TestDifferentPrefixesSpread(t *testing.T) {
	var hitsA, hitsB atomic.Int64
	upA := newUpstream(t, upstreamOpts{chunks: []string{`{"d":"a"}`},
		onRequest: func(*http.Request, []byte) { hitsA.Add(1) }})
	defer upA.Close()
	upB := newUpstream(t, upstreamOpts{chunks: []string{`{"d":"b"}`},
		onRequest: func(*http.Request, []byte) { hitsB.Add(1) }})
	defer upB.Close()

	targets := []*routing.Target{
		{Name: "gpu-a", Tier: routing.Tier2Standard, BaseURL: upA.URL, Model: "m", Weight: 100, Enabled: true, SelfHosted: true},
		{Name: "gpu-b", Tier: routing.Tier2Standard, BaseURL: upB.URL, Model: "m", Weight: 100, Enabled: true, SelfHosted: true},
	}
	policy, _ := routing.NewPolicy(targets, nil, routing.Tier2Standard, nil, nil)
	h := NewHandler(Deps{
		Policy: policy,
		Breakers: map[string]*routing.Breaker{
			"gpu-a": routing.NewBreaker("gpu-a", 5, time.Minute),
			"gpu-b": routing.NewBreaker("gpu-b", 5, time.Minute),
		},
		Creds:    map[string]*credential.BackendPolicy{},
		Limiter:  ratelimit.NewLimiter(ratelimit.Limits{TokensPerWindow: 100_000_000, Window: time.Minute}),
		Vaults:   anonymize.NewVaultRegistry(time.Hour, 1000),
		Client:   NewClient(DefaultTransportConfig()),
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Affinity: affinity.NewRing([]string{"gpu-a", "gpu-b"}, 1000),
	})

	for i := 0; i < 40; i++ {
		doRequest(t, h, fmt.Sprintf(
			`{"model":"m","stream":true,"messages":[{"role":"system","content":"Agent-%d 的独立系统提示词"}]}`, i), nil)
	}

	if hitsA.Load() == 0 || hitsB.Load() == 0 {
		t.Errorf("不同前缀应分散到两个副本，实际 gpu-a=%d gpu-b=%d", hitsA.Load(), hitsB.Load())
	}
}

// TestCriticalStillAdmitsEmergency 锁定「Critical 下紧急请求仍放行」这个回归。
//
// 曾经的缺陷：pickTarget 无条件排除 Critical 后端，使 Admit 里
// 「priority>=8 仍放行」的保命通道永远走不到——所有副本吃紧时，
// 紧急请求拿到 503 而不是被送进队列。选路只应「优先健康」，
// 最终放行与否是准入检查的职责。
func TestCriticalStillAdmitsEmergency(t *testing.T) {
	up := newUpstream(t, upstreamOpts{chunks: []string{`{"delta":"a"}`}})
	defer up.Close()

	h := newTestHandler(t, up.URL, true, false)
	reg := gpuload.NewRegistry()
	st := reg.Register("backend", gpuload.DefaultThresholds())
	st.Update(gpuload.Snapshot{Valid: true, KVCacheUsage: 0.97}) // Critical
	h.deps.GPULoad = reg

	// 唯一后端 Critical：普通优先级应被拒
	if rec := doRequest(t, h, `{"stream":true,"messages":[]}`,
		map[string]string{"X-Workload-Priority": "5"}); rec.Code == http.StatusOK {
		t.Error("Critical 下普通优先级不应放行")
	}
	// 但紧急请求必须能走到准入检查并被放行
	rec := doRequest(t, h, `{"stream":true,"messages":[]}`,
		map[string]string{"X-Workload-Priority": "9"})
	if rec.Code != http.StatusOK {
		t.Errorf("Critical 下紧急请求应仍放行，实际 %d：%s", rec.Code, rec.Body.String())
	}
}

// TestPrefersHealthyOverCritical 校验有健康副本时不选 Critical 副本。
func TestPrefersHealthyOverCritical(t *testing.T) {
	var hitsHealthy atomic.Int64
	upSick := newUpstream(t, upstreamOpts{chunks: []string{`{"d":"sick"}`}})
	defer upSick.Close()
	upWell := newUpstream(t, upstreamOpts{chunks: []string{`{"d":"well"}`},
		onRequest: func(*http.Request, []byte) { hitsHealthy.Add(1) }})
	defer upWell.Close()

	targets := []*routing.Target{
		{Name: "sick", Tier: routing.Tier2Standard, BaseURL: upSick.URL, Model: "m", Weight: 100, Enabled: true, SelfHosted: true},
		{Name: "well", Tier: routing.Tier2Standard, BaseURL: upWell.URL, Model: "m", Weight: 100, Enabled: true, SelfHosted: true},
	}
	policy, _ := routing.NewPolicy(targets, nil, routing.Tier2Standard, nil, nil)

	reg := gpuload.NewRegistry()
	reg.Register("sick", gpuload.DefaultThresholds()).
		Update(gpuload.Snapshot{Valid: true, KVCacheUsage: 0.97})
	reg.Register("well", gpuload.DefaultThresholds()).
		Update(gpuload.Snapshot{Valid: true, KVCacheUsage: 0.20})

	h := NewHandler(Deps{
		Policy: policy,
		Breakers: map[string]*routing.Breaker{
			"sick": routing.NewBreaker("sick", 5, time.Minute),
			"well": routing.NewBreaker("well", 5, time.Minute),
		},
		Creds:   map[string]*credential.BackendPolicy{},
		Limiter: ratelimit.NewLimiter(ratelimit.Limits{TokensPerWindow: 100_000_000, Window: time.Minute}),
		Vaults:  anonymize.NewVaultRegistry(time.Hour, 1000),
		Client:  NewClient(DefaultTransportConfig()),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		GPULoad: reg,
		// 刻意开启亲和：同前缀本会钉到固定副本，但 Critical 必须让路
		Affinity: affinity.NewRing([]string{"sick", "well"}, 1000),
	})

	for i := 0; i < 10; i++ {
		doRequest(t, h, `{"model":"m","stream":true,"messages":[{"role":"system","content":"固定前缀"}]}`,
			map[string]string{"X-Workload-Priority": "5"})
	}
	if hitsHealthy.Load() != 10 {
		t.Errorf("有健康副本时应全部导向健康副本，实际只有 %d/10", hitsHealthy.Load())
	}
}

// TestStructuralFieldsNotRedacted 锁定「协议字段被脱敏导致请求破损」这个回归。
//
// 曾经的缺陷：redactValue 递归脱敏所有字符串值，包括 role 的 "user"、
// 工具的 name。只有正则检测器时这是隐形的（正则匹配不到这些词），
// 接入 NER 后才暴露——模型识别是概率性的，把 "user" 判成人名完全可能，
// 一旦发生，role 变成占位符，请求协议直接破损。
func TestStructuralFieldsNotRedacted(t *testing.T) {
	var gotBody map[string]any
	up := newUpstream(t, upstreamOpts{
		chunks:    []string{`{"delta":"a"}`},
		onRequest: func(_ *http.Request, b []byte) { json.Unmarshal(b, &gotBody) },
	})
	defer up.Close()

	// 构造一个「把任何文本都判成人名」的检测器，模拟 NER 最坏情况
	h := newTestHandler(t, up.URL, false, true)
	h.deps.Redactor = anonymize.NewRedactor(
		detect.NewCompositeDetector([]detect.Detector{everythingIsANameDetector{}}, 0), true)

	doRequest(t, h, `{"model":"m","stream":true,`+
		`"messages":[{"role":"user","content":"正文"}],`+
		`"tools":[{"type":"function","function":{"name":"query_order","description":"查单"}}]}`, nil)

	msgs, _ := gotBody["messages"].([]any)
	if len(msgs) == 0 {
		t.Fatal("消息丢失")
	}
	first, _ := msgs[0].(map[string]any)
	if first["role"] != "user" {
		t.Errorf("role 被脱敏了，协议已破损: %v", first["role"])
	}
	if first["content"] == "正文" {
		t.Error("正文应被脱敏")
	}

	tools, _ := gotBody["tools"].([]any)
	tool, _ := tools[0].(map[string]any)
	if tool["type"] != "function" {
		t.Errorf("工具 type 被脱敏: %v", tool["type"])
	}
	fn, _ := tool["function"].(map[string]any)
	if fn["name"] != "query_order" {
		t.Errorf("工具名被脱敏，模型将再也调不到该工具: %v", fn["name"])
	}
	if fn["description"] == "查单" {
		t.Error("工具描述应被脱敏——里面常写着示例数据")
	}
}

// everythingIsANameDetector 把任意非空文本整体判为人名，模拟 NER 最坏情况。
type everythingIsANameDetector struct{}

func (everythingIsANameDetector) Name() string { return "worst_case" }
func (everythingIsANameDetector) CoveredTypes() []detect.EntityType {
	return []detect.EntityType{detect.TypeName, detect.TypeAddress, detect.TypeOrg}
}
func (everythingIsANameDetector) Detect(text string) ([]detect.Entity, error) {
	if text == "" {
		return nil, nil
	}
	return []detect.Entity{{
		Type: detect.TypeName, Value: text, Start: 0, End: len(text),
		Confidence: 0.99, Detector: "worst_case",
	}}, nil
}
