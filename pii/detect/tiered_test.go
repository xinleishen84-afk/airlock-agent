package detect

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// slowDetector simulates a model-backed detector.
// 模拟依赖模型的检测器。
type slowDetector struct {
	delay time.Duration
	ents  []Entity
	err   error
	calls int
	mu    sync.Mutex
}

func (s *slowDetector) Name() string               { return "slow" }
func (s *slowDetector) CoveredTypes() []EntityType { return []EntityType{TypeName, TypeAddress} }
func (s *slowDetector) Detect(string) ([]Entity, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	time.Sleep(s.delay)
	return s.ents, s.err
}
func (s *slowDetector) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// TestFastOnlyNeverTouchesSlowTier is the guarantee a model-less deployment
// depends on.
// 是没有模型的部署所依赖的保证。
func TestFastOnlyNeverTouchesSlowTier(t *testing.T) {
	slow := &slowDetector{delay: time.Second}
	td := &TieredDetector{
		Fast: []Detector{NewRegexDetector()},
		Slow: []Detector{slow},
		Mode: TierFastOnly,
	}

	start := time.Now()
	got, err := td.Detect("联系 13812345678")
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("fast-only 不该等慢速层，实际耗时 %v", elapsed)
	}
	if slow.Calls() != 0 {
		t.Errorf("fast-only 下慢速层不该被调用，实际 %d 次", slow.Calls())
	}
	if len(got) != 1 {
		t.Errorf("快速层应仍然工作：%+v", got)
	}
}

// TestCoverageReportsWhatIsActuallyProtected guards against a dangerous
// self-report.
// 防止一个危险的自我报告。
//
// Async mode finds names *after* the payload has left. Counting those types as
// covered would make a deployment believe names are protected when they are not
// — and the coverage report is exactly what an operator checks to decide.
// 异步模式是在载荷离境**之后**才找到姓名的。把那些类型算作已覆盖，
// 会让部署方以为姓名受保护而实际并没有——
// 而覆盖度报告正是运维用来做判断的依据。
func TestCoverageReportsWhatIsActuallyProtected(t *testing.T) {
	build := func(mode TierMode) *TieredDetector {
		return &TieredDetector{
			Fast: []Detector{NewRegexDetector()},
			Slow: []Detector{&slowDetector{}},
			Mode: mode,
		}
	}
	hasName := func(types []EntityType) bool {
		for _, t := range types {
			if t == TypeName {
				return true
			}
		}
		return false
	}

	if hasName(build(TierFastOnly).CoveredTypes()) {
		t.Error("fast-only 不运行慢速层，不该声称覆盖 NAME")
	}
	if !hasName(build(TierInline).CoveredTypes()) {
		t.Error("inline 同步运行慢速层，应声称覆盖 NAME")
	}
	if hasName(build(TierAsync).CoveredTypes()) {
		t.Error("async 在载荷离境后才找到 NAME，那不算保护——不得声称覆盖")
	}
}

// TestInlineBoundsLatency verifies the timeout is a hard ceiling on what the
// slow tier can add to TTFT.
// 验证超时是慢速层能给 TTFT 增加延迟的硬上限。
func TestInlineBoundsLatency(t *testing.T) {
	td := &TieredDetector{
		Fast:        []Detector{NewRegexDetector()},
		Slow:        []Detector{&slowDetector{delay: 5 * time.Second}},
		Mode:        TierInline,
		SlowTimeout: 100 * time.Millisecond,
	}

	start := time.Now()
	got, err := td.Detect("联系 13812345678")
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Errorf("超时未生效，耗时 %v——慢速层能无限拖长 TTFT", elapsed)
	}
	if err == nil {
		t.Error("慢速层超时必须上报，不能静默返回部分结果")
	}
	if len(got) != 1 {
		t.Errorf("超时后仍应返回快速层结果：%+v", got)
	}
}

// TestSlowTierFailureIsReported covers the silent-degradation trap.
// 覆盖静默降级陷阱。
//
// Returning fast-tier results with no error would look identical to a healthy
// fast-only deployment, while actually meaning names are now unprotected.
// 无错误地返回快速层结果，看起来与一个健康的 fast-only 部署一模一样，
// 实际却意味着姓名从此不受保护。
func TestSlowTierFailureIsReported(t *testing.T) {
	td := &TieredDetector{
		Fast:        []Detector{NewRegexDetector()},
		Slow:        []Detector{&slowDetector{err: errors.New("模型服务不可用")}},
		Mode:        TierInline,
		SlowTimeout: time.Second,
	}
	got, err := td.Detect("联系 13812345678")
	if err == nil {
		t.Error("慢速层故障必须上报——静默降级看起来和健康部署一样")
	}
	if len(got) != 1 {
		t.Error("故障时快速层结果仍应返回")
	}
}

// TestFastTierFailureIsNeverDegraded covers the opposite direction.
// 覆盖相反方向。
//
// The fast tier has no network and no model, so it can only fail on a code
// defect. Degrading past it would ship a known-broken detector.
// 快速层既无网络也无模型，只可能因代码缺陷而失败。
// 绕过它等于发布一个已知损坏的检测器。
func TestFastTierFailureIsNeverDegraded(t *testing.T) {
	td := &TieredDetector{
		Fast: []Detector{&slowDetector{err: errors.New("代码缺陷")}},
		Mode: TierFastOnly,
	}
	if _, err := td.Detect("任意文本"); err == nil {
		t.Error("快速层故障必须上抛，绝不降级")
	}
}

// TestAsyncReturnsImmediatelyAndStillReports verifies async buys observability.
// 验证异步买到的是可观测性。
func TestAsyncReturnsImmediatelyAndStillReports(t *testing.T) {
	slow := &slowDetector{
		delay: 50 * time.Millisecond,
		ents:  []Entity{{Type: TypeName, Value: "张伟", Confidence: 0.9}},
	}
	reported := make(chan []Entity, 1)
	td := &TieredDetector{
		Fast:         []Detector{NewRegexDetector()},
		Slow:         []Detector{slow},
		Mode:         TierAsync,
		OnSlowResult: func(_ string, found []Entity) { reported <- found },
	}

	start := time.Now()
	got, err := td.Detect("联系张伟，电话 13812345678")
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Millisecond {
		t.Errorf("async 应立即返回，实际 %v", elapsed)
	}
	if len(got) != 1 {
		t.Errorf("应返回快速层结果：%+v", got)
	}

	select {
	case found := <-reported:
		if len(found) != 1 || found[0].Value != "张伟" {
			t.Errorf("慢速层结果应被上报以便告警：%+v", found)
		}
	case <-time.After(2 * time.Second):
		t.Error("慢速层结果未上报——异步模式连可观测性都没买到")
	}
}

// TestBatchProcessesOffHotPath covers the offline pipeline.
// 覆盖离线管道。
func TestBatchProcessesOffHotPath(t *testing.T) {
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	b := &BatchDetector{Detector: reg, Concurrency: 4}

	texts := []string{
		"联系 13812345678", "邮箱 a@b.com", "无敏感内容", "卡号 4111111111111111",
	}
	results, errs := b.DetectBatch(context.Background(), texts)
	for i, e := range errs {
		if e != nil {
			t.Fatalf("第 %d 条失败: %v", i, e)
		}
	}
	if len(results[0]) == 0 || len(results[1]) == 0 || len(results[3]) == 0 {
		t.Errorf("含 PII 的条目应有结果：%+v", results)
	}
	if len(results[2]) != 0 {
		t.Errorf("无 PII 的条目不该有结果：%+v", results[2])
	}
}

// TestBatchCancellationMarksRemaining guards a subtle misread.
// 防止一处微妙的误读。
//
// Leaving cancelled entries as nil results would let a caller mistake them for
// "scanned, no PII found" — and then ship unredacted text.
// 把已取消的条目留成 nil 结果，会让调用方误读为「已扫描、未发现 PII」，
// 进而发出未脱敏的文本。
func TestBatchCancellationMarksRemaining(t *testing.T) {
	reg, _ := NewDefaultRegistry()
	b := &BatchDetector{Detector: reg, Concurrency: 1}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, errs := b.DetectBatch(ctx, []string{"a", "b", "c"})

	for i, e := range errs {
		if e == nil {
			t.Errorf("第 %d 条被取消却未标记错误——调用方会误读为「无 PII」", i)
		}
	}
}

// TestPrefilterNeverCausesMissedDetection is the correctness constraint on the
// whole prefilter mechanism.
// 是整个前置门控机制的正确性约束。
//
// A prefilter may only produce false positives. A false negative silently
// disables a recognizer, which is precisely the failure this system exists to
// prevent — and it would show up as "detection got faster", not as an error.
// 门控只允许产生假阳性。假阴性会静默禁用一个识别器，
// 而这正是本系统要防的那种故障——它表现为「检测变快了」，而不是一个错误。
func TestPrefilterNeverCausesMissedDetection(t *testing.T) {
	texts := []string{
		"手机 13812345678", "邮箱 zhang@corp.com", "身份证 110101199003078515",
		"卡号 4111 1111 1111 1111", "IBAN GB82WEST12345698765432",
		"IP 192.168.1.1", "车牌 京A12345", "密钥 sk-abcdefghij1234567890",
		"SSN 123-45-6789", "固话 010-12345678", "国际 +8613812345678",
		"护照 E12345678", "统一代码 91110108MA01ABCD7X",
	}
	for _, text := range texts {
		withGate, err := NewDefaultRegistry()
		if err != nil {
			t.Fatal(err)
		}
		gated, _ := withGate.Detect(text)

		// 同样的识别器，但强制关闭门控
		bare := NewRegistry()
		for _, spec := range predefinedSpecs() {
			opts := make([]PatternOption, 0, len(spec.opts))
			for _, o := range spec.opts {
				opts = append(opts, o)
			}
			opts = append(opts, WithPrefilter(nil))
			r, err := NewPatternRecognizer(spec.name, spec.entityType, spec.expr, spec.score, opts...)
			if err != nil {
				t.Fatal(err)
			}
			bare.Register(r)
		}
		ungated, _ := bare.Detect(text)

		if len(gated) != len(ungated) {
			t.Errorf("门控导致漏检：%q\n  有门控 %d 个：%v\n  无门控 %d 个：%v",
				text, len(gated), summarize(gated), len(ungated), summarize(ungated))
		}
	}
}

// summarize renders entities compactly for failure messages.
// 为失败信息紧凑渲染实体。
func summarize(ents []Entity) string {
	parts := make([]string, len(ents))
	for i, e := range ents {
		parts[i] = string(e.Type) + ":" + e.Value
	}
	return strings.Join(parts, " ")
}
