package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/gpuload"
	"github.com/xinleishen84-afk/airlock-agent/internal/affinity"
	"github.com/xinleishen84-afk/airlock-agent/internal/credential"
	"github.com/xinleishen84-afk/airlock-agent/internal/identity"
	"github.com/xinleishen84-afk/airlock-agent/internal/lifecycle"
	"github.com/xinleishen84-afk/airlock-agent/internal/ratelimit"
	"github.com/xinleishen84-afk/airlock-agent/internal/routing"
	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/document"
)

// Deps 是处理器的依赖集合，由 main 装配后注入。
type Deps struct {
	Policy   *routing.Policy
	Breakers map[string]*routing.Breaker
	Creds    map[string]*credential.BackendPolicy
	Limiter  *ratelimit.Limiter
	Redactor *anonymize.Redactor
	Vaults   *anonymize.VaultRegistry
	Client   *http.Client
	Logger   *slog.Logger
	// GPULoad 提供各后端的 KV 显存压力，用于边缘准入控制。
	// 为 nil 时退化为纯 token 限流——只看 token 数不看显存，
	// 会在 GPU 已濒临 OOM 时继续放行。
	GPULoad *gpuload.Registry
	// Affinity 是前缀亲和哈希环。为 nil 时按健康度取首个后端，
	// 同前缀请求会被打散，vLLM 的 prefix caching 命中率降到 1/N。
	Affinity *affinity.Ring
	// Lifecycle 提供生命周期阶段，用于停机时拒绝新请求。
	// 为 nil 时永远接受新请求（不参与优雅停机）。
	Lifecycle *lifecycle.State
	// Tracker 跟踪在途请求，停机时据此判断何时可以安全退出。
	Tracker *lifecycle.Tracker
	// AlwaysRedact 为 true 时连私有化后端也脱敏。默认 false：
	// 数据未出企业边界，脱敏只会白白损失模型精度。
	AlwaysRedact bool
}

// Stats 是处理器的运行指标。
type Stats struct {
	Requests     atomic.Int64
	Streamed     atomic.Int64
	Rejected     atomic.Int64
	Upstream5xx  atomic.Int64
	ClientAbort  atomic.Int64
	LeakBlocked  atomic.Int64
	GPUShed      atomic.Int64 // 因显存压力在边缘拒绝的请求数
	PrefixPinned atomic.Int64 // 命中前缀亲和路由的请求数
	Failover     atomic.Int64 // 发生失效转移的请求数
	// ShutdownRejected 单独计数，不与限流/显存拒绝混在一起。
	// 停机轨迹验证需要精确归因：只有这个计数在 SIGTERM 后上涨，
	// 才能证明「拒绝新入站」这一步真的发生了。
	ShutdownRejected atomic.Int64
	// TTFT 只统计「用户看到第一个字」的延迟。工具调用轮单独计，
	// 两者混在一个均值里会得到一个双峰分布的中点——既不描述对话，
	// 也不描述工具调用，还不能用来定容量。
	TTFTNanosSum atomic.Int64
	TTFTCount    atomic.Int64
	// ToolCallTTFT 是到第一个工具调用帧的延迟。它不是「用户感知延迟」，
	// 而是 agent 编排的一环，性质与前者不同，因此分开而不是丢弃。
	ToolCallTTFTNanosSum atomic.Int64
	ToolCallTTFTCount    atomic.Int64
}

// AvgTTFT 返回平均首 token 延迟（只含用户可见正文）。
func (s *Stats) AvgTTFT() time.Duration {
	n := s.TTFTCount.Load()
	if n == 0 {
		return 0
	}
	return time.Duration(s.TTFTNanosSum.Load() / n)
}

// AvgToolCallTTFT 返回到第一个工具调用帧的平均延迟。
func (s *Stats) AvgToolCallTTFT() time.Duration {
	n := s.ToolCallTTFTCount.Load()
	if n == 0 {
		return 0
	}
	return time.Duration(s.ToolCallTTFTNanosSum.Load() / n)
}

// Handler 是全链路 SSE 流式代理处理器。
type Handler struct {
	deps  Deps
	stats Stats
}

// NewHandler 创建处理器。
func NewHandler(deps Deps) *Handler {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.Client == nil {
		deps.Client = NewClient(DefaultTransportConfig())
	}
	return &Handler{deps: deps}
}

// Stats 返回运行指标。
func (h *Handler) Stats() *Stats { return &h.stats }

// chatRequest 是 OpenAI 兼容请求体中我们关心的字段。
//
// 刻意只声明需要的字段并保留 raw：网关不该假设自己认识上游协议的全部，
// 未知字段必须原样透传，否则上游新增特性就会被网关悄悄吃掉。
type chatRequest struct {
	Model     string            `json:"model"`
	Stream    bool              `json:"stream"`
	MaxTokens int64             `json:"max_tokens"`
	Messages  []json.RawMessage `json:"messages"`
}

// ServeHTTP 处理一次推理请求。
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.stats.Requests.Add(1)
	start := time.Now()

	// 停机收敛阶段拒绝新请求。返回干净的 503 + Retry-After，
	// 而不是让 Shutdown 关掉监听——那样客户端拿到的是 connection refused，
	// 既没有重试提示，也不会触发上游的重试策略。
	if h.deps.Lifecycle != nil && !h.deps.Lifecycle.AcceptingNew() {
		h.stats.Rejected.Add(1)
		h.stats.ShutdownRejected.Add(1)
		w.Header().Set("Retry-After", "5")
		w.Header().Set("X-Gateway-Phase", h.deps.Lifecycle.Phase().String())
		h.reject(w, http.StatusServiceUnavailable, "网关正在停机，请重试到其他实例")
		return
	}

	id := identity.FromHeaders(r.Header)
	ctx := identity.NewContext(r.Context(), id)
	log := h.deps.Logger.With("workload", id.String(), "trace", id.TraceID)

	// --- 1. 读取并解析请求体 ---
	//
	// 读体必须在选路之前：前缀亲和路由需要请求体里的系统提示词与工具
	// Schema 才能算出哈希键。请求体上限 32MB 是第一道闸——
	// 突发流量下光是无限制地读体就能压垮网关。
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<20))
	if err != nil {
		h.reject(w, http.StatusBadRequest, "读取请求体失败")
		return
	}
	var req chatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.reject(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	prefixKey, hasPrefix := affinity.PrefixKey(body)

	// 登记在途。必须在这里而不是更早——更早的话，被 400 拒掉的畸形请求
	// 也会被计入，停机时白等。也不能更晚，否则选路耗时不受停机保护。
	if h.deps.Tracker != nil {
		defer h.deps.Tracker.Enter(req.Stream)()
	}

	// --- 2. 选路：熔断 + 显存压力 + 前缀亲和，产出有序候选列表 ---
	decision := h.deps.Policy.ApplyBudget(h.deps.Policy.Resolve(id))
	candidates := h.pickCandidates(decision, prefixKey, hasPrefix)
	if len(candidates) == 0 {
		h.reject(w, http.StatusServiceUnavailable,
			fmt.Sprintf("%s 及其降级链上无可用后端", decision.Tier.Label()))
		return
	}
	target, pinned := candidates[0].target, candidates[0].pinned
	if pinned {
		h.stats.PrefixPinned.Add(1)
	}
	log = log.With("tier", decision.Tier.Label(), "backend", target.Name,
		"reason", decision.Reason, "prefix_pinned", pinned)

	// --- 3. GPU 显存准入：在边缘挡住突发，别让 GPU 死锁 ---
	//
	// 这一步必须在 token 限流之前：token 配额是「预算」约束，
	// 显存是「物理」约束。配额充足但 KV 已满时放行，
	// 只会让后端开始抢占换出，把所有在途请求一起拖垮。
	if h.deps.GPULoad != nil {
		if st := h.deps.GPULoad.Get(target.Name); st != nil {
			if d := st.Admit(id.Priority); !d.Admit {
				h.stats.GPUShed.Add(1)
				h.stats.Rejected.Add(1)
				log.Warn("显存压力触发边缘降级", "pressure", d.Pressure.String(), "detail", d.Reason)
				w.Header().Set("Retry-After", strconv.Itoa(int(d.RetryAfter.Seconds())))
				h.reject(w, http.StatusTooManyRequests, d.Reason)
				return
			}
		}
	}

	// 记录在途，供有界负载哈希环判断副本是否过载
	if h.deps.Affinity != nil && pinned {
		h.deps.Affinity.Acquire(target.Name)
		defer h.deps.Affinity.Release(target.Name)
	}

	// --- 4. Token 滑窗限流：准入预扣 ---
	promptTokens := estimatePromptTokens(body)
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 4096 // 未声明时按保守上界预扣，宁可少放行也不超卖
	}
	reservation, err := h.deps.Limiter.Reserve(id.RateLimitSubject(), maxTokens, promptTokens)
	if err != nil {
		h.stats.Rejected.Add(1)
		w.Header().Set("Retry-After", "5")
		h.reject(w, http.StatusTooManyRequests, err.Error())
		return
	}
	// settled 保证预留在任何退出路径上都被结算——漏掉任何一条都会让配额泄漏
	settled := false
	defer func() {
		if !settled {
			_ = h.deps.Limiter.Release(reservation)
		}
	}()

	// --- 5. PII 出站脱敏 ---
	// 会话引用带租户：X-Session-Id 是调用方提供的字符串，
	// 两个租户传同一个值就会共用一个保险库，而保险库里是明文 PII。
	// The session reference carries the tenant: X-Session-Id is a
	// caller-supplied string, so two tenants sending the same value would
	// share one vault — and the vault holds plaintext PII.
	ref := anonymize.SessionRef{
		Tenant:  anonymize.Tenant(id.Tenant),
		Session: sessionKey(id, r),
	}
	var scope anonymize.StrategyScope
	redacting := h.deps.Redactor != nil && (h.deps.AlwaysRedact || !target.SelfHosted)
	if redacting {
		vault, err := h.deps.Vaults.Get(ref)
		if err != nil {
			h.reject(w, http.StatusServiceUnavailable, "会话资源不足")
			return
		}
		scope = anonymize.StrategyScope{Tenant: ref.Tenant, Vault: vault}
		body, err = h.redactBody(r.Context(), body, scope)
		if err != nil {
			log.Error("出站脱敏失败，已阻断", "err", err)
			h.reject(w, http.StatusBadGateway, "PII 脱敏失败，请求已阻断")
			return
		}
		// 纵深防御：脱敏后再断言一次载荷中不含任何已登记的真实值
		if leaked := vault.ScanLeak(string(body)); len(leaked) > 0 {
			h.stats.LeakBlocked.Add(1)
			log.Error("出站终检发现未脱敏 PII，已阻断", "types", leaked)
			h.reject(w, http.StatusBadGateway, "出站终检未通过")
			return
		}
	}

	// --- 6/7. 逐个候选尝试：构造请求 -> 注入凭证 -> 发起 ---
	//
	// 失效转移只在「尚未向客户端写出任何字节」时发生。一旦开始回传，
	// 就锁定当前后端——否则用户会看到两个模型的输出拼在一起。
	resp, target, err := h.dispatch(ctx, r, candidates, body, log)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			h.stats.ClientAbort.Add(1)
			return // 客户端已走，无需写响应
		}
		h.reject(w, http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()

	// --- 8. 流式回传 ---
	usage, err := h.stream(r.Context(), w, resp, scope, redacting, start, log)
	if err != nil {
		log.Warn("流式传输中断", "err", err)
	}

	// --- 9. 结算：按实际用量回填配额 ---
	settled = true
	if err := h.deps.Limiter.Commit(reservation, usage); err != nil {
		log.Warn("配额结算失败", "err", err)
	}

	// --- 10. 预算核算：私有化部署不计公有云支出 ---
	if !target.SelfHosted {
		cost := target.EstimateCost(usage.InputTokens, usage.OutputTokens)
		if b := h.deps.Policy.BudgetOf(target.Tier); b != nil && b.Record(cost) {
			log.Warn("梯队预算已跨过软阈值", "tier", target.Tier.Label(), "spent", b.Spent())
		}
	}
}

// dispatch 按候选顺序尝试后端，返回第一个成功的响应及其后端。
//
// 转移判据：
//   - 连接失败 / 超时 —— 后端不可达，转移
//   - 5xx —— 后端故障，换一个很可能就成功；把 5xx 透传给客户端
//     等于把可恢复的故障变成用户可见的失败
//   - 4xx —— 调用方的问题，换后端一样失败，原样透传不转移
//
// 熔断计数只记瞬时故障：4xx 不计，否则一个刷错参数的客户端
// 就能把健康后端熔断掉。
func (h *Handler) dispatch(
	ctx context.Context, r *http.Request, candidates []candidate,
	body []byte, log *slog.Logger,
) (*http.Response, *routing.Target, error) {
	var lastErr error

	for i, c := range candidates {
		t := c.target

		upstreamReq, err := h.buildUpstream(ctx, r, t, body)
		if err != nil {
			lastErr = fmt.Errorf("构造上游请求失败: %w", err)
			continue
		}
		if cp := h.deps.Creds[t.Name]; cp != nil {
			strip, secret, err := cp.Apply(upstreamReq.Header)
			if err != nil {
				// 凭证不可用是配置问题，不是后端故障——不转移，直接失败。
				// 转移只会让同样的配置错误在每个后端上重演一遍。
				log.Error("凭证注入失败，已阻断", "backend", t.Name, "err", err)
				return nil, nil, fmt.Errorf("凭证不可用")
			}
			if len(strip.Stripped) > 0 {
				log.Warn("剥离客户端自携凭证（零信任：一律不采信）", "headers", strip.Stripped)
			}
			log.Debug("凭证已注入", "backend", t.Name, "fingerprint", secret.Fingerprint())
		}

		breaker := h.deps.Breakers[t.Name]
		resp, err := h.deps.Client.Do(upstreamReq)
		if err != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil, nil, context.Canceled
			}
			if breaker != nil {
				breaker.RecordFailure()
			}
			lastErr = fmt.Errorf("后端 %s 不可达: %w", t.Name, err)
			log.Warn("上游不可达，尝试下一候选", "backend", t.Name,
				"remaining", len(candidates)-i-1, "err", err)
			continue
		}

		if resp.StatusCode >= 500 {
			h.stats.Upstream5xx.Add(1)
			if breaker != nil {
				breaker.RecordFailure()
			}
			// 还有候选就转移；这是最后一个则把 5xx 如实透传，
			// 让客户端看到真实的上游错误而非网关的臆断
			if i < len(candidates)-1 {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
				resp.Body.Close()
				lastErr = fmt.Errorf("后端 %s 返回 %d", t.Name, resp.StatusCode)
				log.Warn("上游 5xx，尝试下一候选", "backend", t.Name,
					"status", resp.StatusCode, "remaining", len(candidates)-i-1)
				continue
			}
			h.stats.Failover.Add(int64(i))
			return resp, t, nil
		}

		// 2xx/3xx/4xx 都算「后端可服务」：4xx 是调用方的问题，
		// 不该让健康后端因此被熔断
		if breaker != nil {
			breaker.RecordSuccess()
		}
		if i > 0 {
			h.stats.Failover.Add(1)
			log.Info("已转移到备用后端", "backend", t.Name, "attempts", i+1)
		}
		return resp, t, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("无可用后端")
	}
	return nil, nil, lastErr
}

// stream 把上游响应以 SSE 逐帧转发给客户端，同时做入站复原与用量统计。
func (h *Handler) stream(
	ctx context.Context, w http.ResponseWriter, resp *http.Response,
	scope anonymize.StrategyScope, redacting bool,
	start time.Time, log *slog.Logger,
) (ratelimit.Usage, error) {
	var usage ratelimit.Usage

	// 非流式响应（上游报错或客户端没要 stream）直接透传
	if !isSSE(resp.Header.Get("Content-Type")) {
		return h.passthrough(ctx, w, resp, scope, redacting)
	}

	rc := http.NewResponseController(w)

	// **解除写截止时间**。若服务端设了全局 WriteTimeout，长流会被无声掐断——
	// 这是 SSE 最常见的线上事故：短对话正常，长回答总在固定秒数处断掉。
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		log.Debug("无法解除写截止时间，长流可能被掐断", "err", err)
	}

	h.writeSSEHeaders(w)
	w.WriteHeader(resp.StatusCode)
	// 立即 Flush 响应头：让客户端尽早拿到 200 并进入接收状态，
	// 这一步就已经把「感知延迟」往前挪了一个 RTT
	_ = rc.Flush()

	buf := getReadBuf()
	defer putReadBuf(buf)

	scanner := NewScanner(resp.Body, len(*buf), DefaultMaxEventSize)
	var restorer *document.StreamRestorer
	if redacting && scope.Vault != nil {
		restorer = document.NewStreamRestorer(h.deps.Redactor, scope)
	}

	// firstFrameAt 记录首个数据帧的时刻，用作形状不可识别时的兜底。
	// 见下方 recordTTFT 的说明：宁可略微不精确，不可让指标静默消失。
	var firstFrameAt time.Time
	firstToken := true
	h.stats.Streamed.Add(1)

	for scanner.Next() {
		event := scanner.Event()

		// 注释帧是保活心跳，原样透传且不参与业务处理
		if event.Comment {
			if err := WriteEvent(w, event); err != nil {
				return usage, err
			}
			_ = rc.Flush()
			continue
		}

		if event.IsDone() {
			if restorer != nil {
				// 上游没吐 finish_reason 就结束时，屏障里仍压着工具调用。
				// 必须发出去——吞掉会让客户端永远等一个不会到来的调用。
				if frame := restorer.FlushToolCalls(ctx); frame != nil {
					_ = WriteEvent(w, &Event{Data: frame})
				}
				// 吐出滞留缓冲里的最后一截。包成合法的增量帧发出——
				// 里面可能压着占位符的后半截，丢掉就是丢内容。
				tail, flushErr := restorer.Flush(ctx)
				if flushErr != nil {
					// 复原失败时不得把滞留缓冲原样发出：里面压着的是
					// 未复原的占位符或令牌，发出去就是把脱敏后的符号
					// 当作原值交给终端用户。
					// Never emit the hold-back buffer on a restore failure:
					// it holds unrestored placeholders or tokens.
					return usage, flushErr
				}
				if tail != "" {
					if frame, err := document.MarshalPreserving(map[string]any{
						"choices": []any{map[string]any{
							"delta": map[string]any{"content": tail},
						}},
					}); err == nil {
						_ = WriteEvent(w, &Event{Data: frame})
					}
				}
			}
			recordFallbackTTFT(&h.stats, firstToken, firstFrameAt, start, log)
			firstToken = false
			_ = WriteDone(w)
			_ = rc.Flush()
			break
		}

		// 首个**有内容**的数据帧 = TTFT。
		//
		// 打点在收到帧时，早于复原与屏障缓冲，因此屏障的延迟 Flush
		// 不会污染这个数字——它量的是上游到网关，不是网关到客户端。
		//
		// 但帧的类别必须分开：工具调用帧里没有用户能看到的东西，
		// 与正文帧混进同一个均值会得到双峰分布的中点。
		if firstToken {
			if firstFrameAt.IsZero() {
				firstFrameAt = time.Now()
			}
			switch document.ClassifyFrame(event.Data) {
			case document.FrameText:
				firstToken = false
				ttft := time.Since(start)
				h.stats.TTFTNanosSum.Add(ttft.Nanoseconds())
				h.stats.TTFTCount.Add(1)
				log.Debug("首 token 抵达", "ttft_ms", ttft.Milliseconds())
			case document.FrameToolCall:
				firstToken = false
				d := time.Since(start)
				h.stats.ToolCallTTFTNanosSum.Add(d.Nanoseconds())
				h.stats.ToolCallTTFTCount.Add(1)
				log.Debug("首个工具调用帧抵达", "delay_ms", d.Milliseconds())
			}
			// FrameOther（role 声明、usage 帧等）不计——它不是 token，
			// 继续看下一帧。全程都识别不出来时由下方兜底补记。
		}

		// 从 chunk 中抽取用量（上游通常在末帧带 usage）
		accumulateUsage(&usage, event.Data)

		outs := []*Event{event}
		if restorer != nil {
			// 入站复原走结构化 AST：解析 JSON -> 在结构上替换 -> 重新序列化。
			// 绝不在原始 JSON 文本上做字符串替换——真实值含引号或换行时
			// 会直接产出非法 JSON，客户端解析器罢工。
			//
			// 占位符可能横跨两个 chunk，滞留缓冲会处理，因此本帧的
			// content 可能变成空串——那是正常的，不是丢帧，
			// 且必须照常发出（帧里可能还带着 finish_reason 等其他字段）。
			//
			// 可能返回多帧：工具调用屏障在放行时补发一个装着完整入参的帧。
			// 补发帧不带原帧的 event/id——它是本网关合成的，
			// 不是上游那一帧的一部分。
			frames := restorer.Frame(ctx, event.Data)
			outs = outs[:0]
			for i, f := range frames {
				if i == 0 {
					outs = append(outs, &Event{Event: event.Event, ID: event.ID, Data: f})
					continue
				}
				outs = append(outs, &Event{Data: f})
			}
		}

		for _, out := range outs {
			if err := WriteEvent(w, out); err != nil {
				// 写失败几乎总是客户端断连
				h.stats.ClientAbort.Add(1)
				return usage, err
			}
		}
		// **每帧必须 Flush**。少了这一句，token 会积在 net/http 的写缓冲里
		// 攒够 4KB 才发出——流式就退化成了批式。
		if err := rc.Flush(); err != nil {
			return usage, err
		}
	}

	recordFallbackTTFT(&h.stats, firstToken, firstFrameAt, start, log)

	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return usage, err
	}
	if restorer != nil {
		if phantom := restorer.Phantom(); len(phantom) > 0 {
			log.Warn("响应含模型捏造的占位符", "count", len(phantom))
		}
	}
	return usage, nil
}

// passthrough 透传非 SSE 响应（错误体、非流式调用）。
func (h *Handler) passthrough(
	ctx context.Context, w http.ResponseWriter, resp *http.Response,
	scope anonymize.StrategyScope, redacting bool,
) (ratelimit.Usage, error) {
	var usage ratelimit.Usage

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return usage, err
	}
	accumulateUsage(&usage, body)

	if redacting && scope.Vault != nil {
		// 非流式响应同样走结构化复原，不做裸文本替换
		body = document.RestoreBody(ctx, body, h.deps.Redactor, scope)
	}

	copyHeaders(w.Header(), resp.Header)
	w.Header().Del("Content-Length") // 复原后长度可能变化
	w.WriteHeader(resp.StatusCode)
	_, err = w.Write(body)
	return usage, err
}

// writeSSEHeaders 写出 SSE 必需的响应头。
func (h *Handler) writeSSEHeaders(w http.ResponseWriter) {
	head := w.Header()
	head.Set("Content-Type", "text/event-stream")
	head.Set("Cache-Control", "no-cache")
	head.Set("Connection", "keep-alive")
	// 关键：告诉 nginx 之类的反向代理不要缓冲。
	// 少了这一句，即使网关本身逐帧 Flush，前面的 nginx 依然会攒包，
	// TTFT 照样是秒级——而且排查时很容易怪到网关头上。
	head.Set("X-Accel-Buffering", "no")
}

// buildUpstream 构造发往后端的请求。
func (h *Handler) buildUpstream(
	ctx context.Context, r *http.Request, target *routing.Target, body []byte,
) (*http.Request, error) {
	url := strings.TrimSuffix(target.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	// 只透传安全的头部。凭证类头部由 credential.Strip 统一剥离，
	// 此处白名单再收一道，避免把 Host/Cookie 之类的东西带到上游。
	for _, name := range []string{"Content-Type", "Accept", "X-Request-Id"} {
		if v := r.Header.Get(name); v != "" {
			req.Header.Set(name, v)
		}
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "text/event-stream")
	// 显式声明不接受压缩：与 Transport.DisableCompression 呼应，
	// 双保险防止上游 gzip 把流式变批式
	req.Header.Set("Accept-Encoding", "identity")
	req.ContentLength = int64(len(body))
	return req, nil
}

// candidate 是一个待尝试的后端及其选中方式。
type candidate struct {
	target *routing.Target
	pinned bool // 是否由前缀亲和选中
}

// pickCandidates 生成有序的候选后端列表，供运行期失效转移逐个尝试。
//
// 两轮筛选，职责分离：
//
//	第一轮  排除熔断 + 排除显存 Critical，在健康副本里按前缀亲和排序
//	第二轮  若整条降级链上没有健康副本，放宽到「仅排除熔断」
//
// 第二轮不可省。若无条件排除 Critical 后端，gpuload.Admit 里
// 「最高优先级仍放行」的保命通道就永远走不到——所有副本都吃紧时，
// 紧急请求会拿到 503 而不是被送进队列。选路只负责「优先健康」，
// 由谁最终放行是准入检查的职责，两者不能互相越权。
//
// 返回列表而非单个目标：上游可能在运行期失败（连接不上、5xx），
// 那时必须能转移到下一个候选。只返回一个目标等于放弃了多模型 Fallback。
func (h *Handler) pickCandidates(d routing.Decision, prefixKey uint64, hasPrefix bool) []candidate {
	if out := h.collectFrom(d, prefixKey, hasPrefix, true); len(out) > 0 {
		return out
	}
	return h.collectFrom(d, prefixKey, hasPrefix, false)
}

// collectFrom 沿降级链收集候选后端。skipCritical 为 true 时排除显存濒临耗尽的副本。
func (h *Handler) collectFrom(
	d routing.Decision, prefixKey uint64, hasPrefix, skipCritical bool,
) []candidate {
	var out []candidate
	seen := map[string]bool{}
	tier := d.Tier
	visited := map[routing.Tier]bool{}

	for !visited[tier] {
		visited[tier] = true
		pool := h.deps.Policy.TargetsOf(tier)

		eligible := make(map[string]bool, len(pool))
		byName := make(map[string]*routing.Target, len(pool))
		for _, t := range pool {
			// 熔断是硬故障，任何轮次都排除
			if b := h.deps.Breakers[t.Name]; b != nil && !b.Allow() {
				continue
			}
			if skipCritical && h.deps.GPULoad != nil {
				if st := h.deps.GPULoad.Get(t.Name); st != nil &&
					st.Pressure() == gpuload.PressureCritical {
					continue
				}
			}
			eligible[t.Name] = true
			byName[t.Name] = t
		}

		// 前缀亲和选中的排在本梯队最前，其余按配置顺序跟随，
		// 使转移时仍优先命中缓存
		if h.deps.Affinity != nil && hasPrefix && len(eligible) > 0 {
			if name := h.deps.Affinity.Pick(prefixKey, eligible); name != "" {
				out = append(out, candidate{target: byName[name], pinned: true})
				seen[name] = true
			}
		}
		for _, t := range pool {
			if eligible[t.Name] && !seen[t.Name] {
				seen[t.Name] = true
				out = append(out, candidate{target: t})
			}
		}

		next, ok := h.deps.Policy.Fallback(tier)
		if !ok {
			break
		}
		tier = next
	}
	return out
}

// redactBody 对请求体执行结构化 AST 定向清洗。
//
// 不再递归净化所有字符串值，而是只遍历 sanitize.go 里显式白名单
// 列出的路径。协议骨架字段（role / model / function.name /
// parameters.enum / tool_call_id 等）在物理上根本不会被访问，
// NER 的概率性输出因此不可能污染协议结构。
func (h *Handler) redactBody(ctx context.Context, body []byte, scope anonymize.StrategyScope) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("解析请求体失败: %w", err)
	}

	err := document.SanitizeDocument(doc, func(_, text string) (string, error) {
		res, err := h.deps.Redactor.Redact(ctx, text, scope)
		if err != nil {
			return "", err
		}
		return res.Text, nil
	})
	if err != nil {
		return nil, err
	}
	return document.MarshalPreserving(doc)
}

// reject 返回一个 OpenAI 兼容格式的错误响应。
func (h *Handler) reject(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"message": message, "type": "gateway_error"},
	})
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

// usagePayload 是响应中携带用量的字段结构。
type usagePayload struct {
	Usage *struct {
		PromptTokens     int64 `json:"prompt_tokens"`
		CompletionTokens int64 `json:"completion_tokens"`
	} `json:"usage"`
}

// accumulateUsage 从 chunk 中抽取 token 用量。
// 上游通常只在末帧带 usage，抽不到不是错误。
func accumulateUsage(dst *ratelimit.Usage, data []byte) {
	if !bytes.Contains(data, []byte(`"usage"`)) {
		return // 快速跳过绝大多数帧，避免无谓的 JSON 解析
	}
	var p usagePayload
	if err := json.Unmarshal(data, &p); err != nil || p.Usage == nil {
		return
	}
	dst.InputTokens = p.Usage.PromptTokens
	dst.OutputTokens = p.Usage.CompletionTokens
}

// estimatePromptTokens 粗估输入 token 数，用于限流预扣。
//
// 刻意用字节数除以经验系数而非真实分词：网关做精确分词需要引入
// 模型词表，代价远超收益。预扣本就是保守上界，估算偏大反而更安全。
func estimatePromptTokens(body []byte) int64 {
	// 中英混合场景下约 3 字节 ≈ 1 token，取偏保守的估计
	return int64(len(body) / 3)
}

// isSSE 判断响应是否为 SSE 流。
func isSSE(contentType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "text/event-stream")
}

// sessionKey 决定脱敏映射的复用范围。
//
// 优先用显式的会话头；缺失时退回「租户+应用」——同一会话的多轮对话
// 必须落到同一个 vault，否则模型会在轮次之间失去实体一致性。
func sessionKey(id identity.Identity, r *http.Request) string {
	if id.SessionID != "" {
		return id.SessionID
	}
	if v := r.Header.Get("X-Conversation-Id"); v != "" {
		return v
	}
	return id.RateLimitSubject()
}

// copyHeaders 拷贝响应头，跳过逐跳头部。
func copyHeaders(dst, src http.Header) {
	hopByHop := map[string]bool{
		"Connection": true, "Keep-Alive": true, "Transfer-Encoding": true,
		"Upgrade": true, "Proxy-Authenticate": true, "Proxy-Authorization": true,
		"Te": true, "Trailer": true,
	}
	for k, vs := range src {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// recordFallbackTTFT 在帧形状无法识别时补记 TTFT。
// Records TTFT as a fallback when no frame shape could be classified.
//
// # 为什么必须有这条兜底
// # Why this fallback is mandatory
//
// TTFT 的归类依赖于认得出 choices[].delta 这个形状。上游换个协议
// （Anthropic 的 content_block_delta、某个自研网关的变体），分类器一律
// 返回 FrameOther，两个计数器都不涨——指标从 /metrics 上静默归零，
// 看起来像「没有流量」而不是「认不出形状」。
//
// 实测：一条 {"delta":"a"} 的桩流就足以让 TTFT 记录数变成 0。
//
// 因此形状认不出时退回「首个数据帧的时刻」，也就是本函数替换掉的那个
// 旧口径。精度略降，但指标不会消失。
//
// Classification depends on recognizing the choices[].delta shape. Against a
// different upstream protocol every frame classifies as FrameOther, neither
// counter moves, and the metric silently reads zero on /metrics — looking like
// "no traffic" rather than "unrecognized shape". Measured: a stub stream of
// {"delta":"a"} was enough to drop the TTFT count to zero. Falling back to the
// first data frame's timestamp — the old definition — loses precision but never
// loses the metric.
func recordFallbackTTFT(stats *Stats, pending bool, firstFrameAt, start time.Time,
	log *slog.Logger) {
	if !pending || firstFrameAt.IsZero() {
		return
	}
	ttft := firstFrameAt.Sub(start)
	stats.TTFTNanosSum.Add(ttft.Nanoseconds())
	stats.TTFTCount.Add(1)
	log.Debug("帧形状未能识别，TTFT 按首个数据帧计",
		"ttft_ms", ttft.Milliseconds())
}
