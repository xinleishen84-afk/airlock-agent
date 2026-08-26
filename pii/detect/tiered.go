package detect

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// TieredDetector separates detection into a synchronous fast tier and an
// optional slow tier, so a model call never lands on the streaming hot path
// unless it was explicitly put there.
// 把检测分成同步快速层与可选慢速层，除非明确配置，否则模型调用绝不会
// 落在流式 hot-path 上。
//
// # The problem it solves
// # 它解决的问题
//
// Running every detector in one loop makes the slowest one set the latency for
// all traffic. A remote NER call costs tens to hundreds of milliseconds and sits
// directly on TTFT, which is the metric streaming exists to protect. Worse, it
// cannot be turned off without editing code — so a deployment with no local
// model has no way to run at all.
// 把所有检测器放进一个循环，会让最慢的那个决定全部流量的延迟。
// 一次远程 NER 调用要几十到几百毫秒，直接压在 TTFT 上——而 TTFT 正是
// 流式架构存在的意义所在。更糟的是，不改代码就关不掉它，
// 于是没有本地模型的部署根本跑不起来。
//
// # The safety consequence of the split
// # 分层带来的安全后果
//
// Skipping the slow tier is not free: it is the tier that finds names and
// addresses. A deployment running fast-tier-only is knowingly accepting that
// name-class PII passes through. That is a legitimate choice for structured
// traffic, and an unacceptable one for free-form chat — so the mode is explicit,
// reported by Coverage(), and never inferred.
// 跳过慢速层不是免费的：找姓名和地址的正是这一层。只跑快速层的部署，
// 是在明知的前提下接受姓名类 PII 放行。对结构化流量这是正当选择，
// 对自由文本聊天则不可接受——因此模式是显式的、由 Coverage() 上报的，
// 绝不靠推断。
type TieredDetector struct {
	// Fast runs synchronously on every request. Regex, checksums and gazetteer
	// matching all belong here: they are microseconds and need no network.
	// 每个请求都同步运行。正则、校验和、名册匹配都属于这里：
	// 它们是微秒级的，且不需要网络。
	Fast []Detector

	// Slow holds model-backed detectors. Empty is a valid configuration.
	// 存放依赖模型的检测器。留空是合法配置。
	Slow []Detector

	// Mode decides whether and how Slow participates.
	// 决定慢速层是否参与、以何种方式参与。
	Mode TierMode

	// SlowTimeout bounds the slow tier when it runs inline. It is a hard ceiling
	// on the latency the slow tier can add to TTFT.
	// 慢速层内联运行时的时限。它是慢速层能给 TTFT 增加的延迟硬上限。
	SlowTimeout time.Duration

	// OnSlowResult receives slow-tier findings in async mode. Because the
	// request has already been forwarded by then, these findings cannot redact
	// anything — they exist to raise an alarm that PII escaped, so the incident
	// is discovered by monitoring rather than by a breach report.
	// 在异步模式下接收慢速层的结果。此时请求早已转发出去，这些结果无法
	// 脱敏任何东西——它们的作用是告警「有 PII 逃逸了」，
	// 让事故由监控发现，而不是由泄露通报发现。
	OnSlowResult func(text string, found []Entity)
}

// TierMode selects how the slow tier participates.
// 选择慢速层的参与方式。
type TierMode int

const (
	// TierFastOnly skips the slow tier entirely. Detection is microseconds and
	// needs no network, at the cost of everything only a model can find.
	// 完全跳过慢速层。检测是微秒级且无需网络，代价是一切只有模型能找到的东西。
	TierFastOnly TierMode = iota

	// TierInline runs the slow tier synchronously, bounded by SlowTimeout.
	// Correct for non-streaming and batch work, where latency is not the point.
	// 同步运行慢速层，受 SlowTimeout 约束。适用于非流式与批量场景，
	// 那里延迟本就不是重点。
	TierInline

	// TierAsync returns fast-tier results immediately and runs the slow tier in
	// the background.
	//
	// This mode cannot protect the current request — by the time the slow tier
	// answers, the payload is already at the vendor. It buys observability, not
	// protection, and must never be chosen because it "looks safer than
	// fast-only": both let name-class PII through; async merely tells you so.
	// 立即返回快速层结果，慢速层在后台运行。
	//
	// 本模式无法保护当前请求——慢速层给出答案时，载荷早已抵达厂商。
	// 它买到的是可观测性而非保护，绝不能因为「看起来比 fast-only 安全」
	// 而选择它：两者都会放行姓名类 PII，异步只是会告诉你这件事。
	TierAsync
)

// String returns the mode name.
// 返回模式名。
func (m TierMode) String() string {
	switch m {
	case TierFastOnly:
		return "fast-only"
	case TierInline:
		return "inline"
	case TierAsync:
		return "async"
	}
	return "unknown"
}

// Name returns the detector identifier.
// 返回检测器标识。
func (t *TieredDetector) Name() string { return "tiered(" + t.Mode.String() + ")" }

// CoveredTypes returns only what the current mode actually detects in time to
// redact. In async mode the slow tier's types are excluded, because a type found
// after the payload left the boundary was not protected.
// 只返回当前模式下**来得及用于脱敏**的类型。异步模式排除慢速层的类型，
// 因为在载荷离境之后才找到的类型并没有被保护到。
func (t *TieredDetector) CoveredTypes() []EntityType {
	seen := map[EntityType]bool{}
	var out []EntityType
	add := func(ds []Detector) {
		for _, d := range ds {
			for _, typ := range d.CoveredTypes() {
				if !seen[typ] {
					seen[typ] = true
					out = append(out, typ)
				}
			}
		}
	}
	add(t.Fast)
	if t.Mode == TierInline {
		add(t.Slow)
	}
	return out
}

// Detect runs the fast tier, then the slow tier according to Mode.
// 运行快速层，再按 Mode 运行慢速层。
func (t *TieredDetector) Detect(text string) ([]Entity, error) {
	found, err := runAll(t.Fast, text)
	if err != nil {
		// A fast-tier failure is a real failure: this tier has no network and no
		// model, so it can only fail on a code defect. Never degrade past it.
		// 快速层故障是真故障：这一层既无网络也无模型，只可能是代码缺陷。
		// 绝不允许降级绕过它。
		return nil, fmt.Errorf("快速层失败 / fast tier failed: %w", err)
	}

	switch t.Mode {
	case TierFastOnly:
		return ResolveOverlaps(found), nil

	case TierInline:
		slow, err := t.runSlowBounded(text)
		if err != nil {
			// Surface it rather than silently returning fast-tier-only results,
			// which would look identical to a healthy fast-only deployment while
			// actually meaning names are now unprotected.
			// 上报而非静默返回仅快速层的结果——那看起来与一个健康的
			// fast-only 部署一模一样，实际却意味着姓名从此不受保护。
			return ResolveOverlaps(found), fmt.Errorf(
				"慢速层失败，仅返回快速层结果 / slow tier failed, fast-tier results only: %w", err)
		}
		return ResolveOverlaps(append(found, slow...)), nil

	default: // TierAsync
		if t.OnSlowResult != nil && len(t.Slow) > 0 {
			go t.runSlowAsync(text)
		}
		return ResolveOverlaps(found), nil
	}
}

// runSlowBounded runs the slow tier under a timeout.
// 在超时约束下运行慢速层。
func (t *TieredDetector) runSlowBounded(text string) ([]Entity, error) {
	if len(t.Slow) == 0 {
		return nil, nil
	}
	timeout := t.SlowTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	type result struct {
		ents []Entity
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		ents, err := runAll(t.Slow, text)
		ch <- result{ents, err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.ents, r.err
	case <-timer.C:
		// The goroutine is left to finish and its result discarded. Cancelling
		// it would need every detector to accept a context, which the interface
		// deliberately does not require — a detector that ignores cancellation
		// would hang the caller anyway.
		// 让协程自行结束，结果丢弃。要取消它就得让每个检测器都接受 context，
		// 而接口刻意不作此要求——一个无视取消的检测器照样会挂住调用方。
		return nil, fmt.Errorf("慢速层超时 %v / slow tier timed out after %v", timeout, timeout)
	}
}

// runSlowAsync runs the slow tier off the request path.
// 在请求路径之外运行慢速层。
func (t *TieredDetector) runSlowAsync(text string) {
	defer func() {
		// A panic here must not take down the process: this goroutine is
		// detached from any request, so nothing would catch it.
		// 这里的 panic 不能拖垮进程：本协程已脱离任何请求，没有东西会兜住它。
		_ = recover()
	}()
	ents, err := runAll(t.Slow, text)
	if err != nil || len(ents) == 0 {
		return
	}
	t.OnSlowResult(text, ResolveOverlaps(ents))
}

// runAll executes detectors sequentially and concatenates their findings.
// 顺序执行检测器并汇总结果。
func runAll(ds []Detector, text string) ([]Entity, error) {
	var out []Entity
	for _, d := range ds {
		found, err := d.Detect(text)
		if err != nil {
			return nil, fmt.Errorf("检测器 %s: %w", d.Name(), err)
		}
		out = append(out, found...)
	}
	return out, nil
}

// BatchDetector applies the full pipeline off the hot path, for offline work
// such as vector-store construction or fine-tuning corpus cleaning.
// 在 hot-path 之外应用完整管道，用于离线工作，
// 如向量库构建或微调语料清洗。
//
// Latency is irrelevant here, so the slow tier always runs inline and
// concurrency is bounded to keep a batch job from saturating the model service
// that online traffic also depends on.
// 这里延迟无关紧要，因此慢速层总是内联运行；并发受限，
// 以免批量作业把在线流量同样依赖的模型服务打满。
type BatchDetector struct {
	Detector    Detector
	Concurrency int
}

// DetectBatch processes many texts, returning results in input order.
// 处理多段文本，按输入顺序返回结果。
func (b *BatchDetector) DetectBatch(ctx context.Context, texts []string) ([][]Entity, []error) {
	n := b.Concurrency
	if n <= 0 {
		n = 4
	}
	results := make([][]Entity, len(texts))
	errs := make([]error, len(texts))

	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i, text := range texts {
		select {
		case <-ctx.Done():
			// Mark the rest as cancelled rather than leaving nil results that
			// a caller could mistake for "no PII found".
			// 把余下的标记为已取消，而不是留下 nil 结果——
			// 调用方可能把 nil 误读为「未发现 PII」。
			for j := i; j < len(texts); j++ {
				errs[j] = ctx.Err()
			}
			wg.Wait()
			return results, errs
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, txt string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx], errs[idx] = b.Detector.Detect(txt)
		}(i, text)
	}
	wg.Wait()
	return results, errs
}
