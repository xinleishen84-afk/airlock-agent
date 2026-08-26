package routing

import (
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/internal/identity"
)

// newTestPolicy 构造与 Python 参考实现同配置的两级策略。
func newTestPolicy(t *testing.T, budgets map[Tier]*Budget) *Policy {
	t.Helper()
	targets := []*Target{
		{Name: "t1-cloud", Tier: Tier1Premium, Model: "claude-opus-5", Weight: 100,
			Enabled: true, InputPricePerMTok: 5, OutputPricePerMTok: 25},
		{Name: "t2-local", Tier: Tier2Standard, Model: "gpt-oss-120b", Weight: 100,
			Enabled: true, SelfHosted: true},
	}
	rules := []*Rule{
		{Name: "batch-offload", TargetTier: Tier2Standard, Enabled: true, Priority: 10,
			MatchApps: []string{"toolbench-agent", "*-batch"}},
		{Name: "planner-premium", TargetTier: Tier1Premium, Enabled: true, Priority: 20,
			MatchApps: []string{"planner-agent"}},
	}
	p, err := NewPolicy(targets, rules, Tier2Standard, nil, budgets)
	if err != nil {
		t.Fatalf("构造策略失败: %v", err)
	}
	return p
}

// TestIdentityRoutesBatchAppToTier2 校验题设场景：toolbench-agent 分流至本地集群。
func TestIdentityRoutesBatchAppToTier2(t *testing.T) {
	p := newTestPolicy(t, nil)
	d := p.Resolve(identity.Identity{App: "toolbench-agent", Task: identity.TaskExtraction})
	if d.Tier != Tier2Standard || d.RuleName != "batch-offload" {
		t.Errorf("应命中 batch-offload 分流至 Tier2，实际 %+v", d)
	}
}

// TestGlobPatternMatching 校验 app 名的 glob 匹配。
func TestGlobPatternMatching(t *testing.T) {
	p := newTestPolicy(t, nil)
	if d := p.Resolve(identity.Identity{App: "invoice-batch"}); d.Tier != Tier2Standard {
		t.Errorf("*-batch 应下沉至 Tier2，实际 %+v", d)
	}
}

// TestExplicitTierOverridesRules 校验显式头部优先级最高。
func TestExplicitTierOverridesRules(t *testing.T) {
	p := newTestPolicy(t, nil)
	// toolbench-agent 本应走 Tier2，显式指定后改走云端
	d := p.Resolve(identity.Identity{App: "toolbench-agent", TierHint: 1})
	if d.Tier != Tier1Premium || d.Reason != "explicit_header" {
		t.Errorf("显式头部应优先，实际 %+v", d)
	}
}

// TestExplicitTierWithoutBackendFallsBack 校验指定了空梯队时回落规则匹配，
// 而非硬失败——一个畸形头部不应让请求无法服务。
func TestExplicitTierWithoutBackendFallsBack(t *testing.T) {
	p := newTestPolicy(t, nil)
	d := p.Resolve(identity.Identity{App: "toolbench-agent", TierHint: 9})
	if d.Reason != "rule" {
		t.Errorf("空梯队应回落规则匹配，实际 %+v", d)
	}
}

// TestTaskDefaultWhenNoRuleMatches 校验未命中规则时按任务类型兜底。
func TestTaskDefaultWhenNoRuleMatches(t *testing.T) {
	p := newTestPolicy(t, nil)
	cases := []struct {
		task identity.TaskKind
		want Tier
	}{
		{identity.TaskReasoning, Tier1Premium},
		{identity.TaskClassification, Tier2Standard},
		{identity.TaskUnknown, Tier2Standard},
	}
	for _, c := range cases {
		d := p.Resolve(identity.Identity{App: "misc-app", Task: c.task})
		if d.Tier != c.want {
			t.Errorf("任务 %s 应定级 %s，实际 %s", c.task, c.want.Label(), d.Tier.Label())
		}
	}
}

// TestAnonymousDefaultsToTier2 校验身份不明一律走本地——默认省钱而非默认烧钱。
func TestAnonymousDefaultsToTier2(t *testing.T) {
	p := newTestPolicy(t, nil)
	if d := p.Resolve(identity.Anonymous); d.Tier != Tier2Standard {
		t.Errorf("匿名身份应走 Tier2，实际 %+v", d)
	}
}

// TestRulePriorityOrder 校验规则按优先级升序匹配，先命中者胜出。
func TestRulePriorityOrder(t *testing.T) {
	p := newTestPolicy(t, nil)
	// toolbench-agent 的规划任务：batch-offload(10) 优先于任务兜底
	d := p.Resolve(identity.Identity{App: "toolbench-agent", Task: identity.TaskPlanning})
	if d.Tier != Tier2Standard {
		t.Errorf("高优先级规则应胜出，实际 %+v", d)
	}
}

// TestSelfHostedCostsNothing 校验私有化部署不计公有云成本。
func TestSelfHostedCostsNothing(t *testing.T) {
	p := newTestPolicy(t, nil)
	local := p.TargetsOf(Tier2Standard)[0]
	if got := local.EstimateCost(100000, 50000); got != 0 {
		t.Errorf("自建集群成本应为 0，实际 %f", got)
	}
	cloud := p.TargetsOf(Tier1Premium)[0]
	// 1000 输入 * $5/M + 500 输出 * $25/M = $0.0175
	if got := cloud.EstimateCost(1000, 500); got < 0.01749 || got > 0.01751 {
		t.Errorf("云端成本估算错误: %f", got)
	}
}

// TestBudgetExhaustionDowngrades 校验预算耗尽后强制降级。
func TestBudgetExhaustionDowngrades(t *testing.T) {
	b := NewBudget(0.01)
	p := newTestPolicy(t, map[Tier]*Budget{Tier1Premium: b})

	d := p.ApplyBudget(p.Resolve(identity.Identity{App: "planner-agent"}))
	if d.Tier != Tier1Premium {
		t.Fatalf("预算未耗尽时应走 Tier1，实际 %+v", d)
	}

	b.Record(1.0) // 击穿预算
	d = p.ApplyBudget(p.Resolve(identity.Identity{App: "planner-agent"}))
	if d.Tier != Tier2Standard || d.DowngradedFrom != Tier1Premium {
		t.Errorf("预算耗尽应降级至 Tier2，实际 %+v", d)
	}
}

// TestBudgetSoftLimitWarnsOnce 校验软阈值告警只触发一次，避免日志洪泛。
func TestBudgetSoftLimitWarnsOnce(t *testing.T) {
	b := NewBudget(100)
	if b.Record(50) {
		t.Error("50% 不应触发软阈值告警")
	}
	if !b.Record(35) { // 累计 85% > 80%
		t.Error("跨过软阈值应告警")
	}
	if b.Record(5) {
		t.Error("软阈值告警应只触发一次")
	}
}

// TestPolicyValidationRejectsBadConfig 校验构造期配置校验。
func TestPolicyValidationRejectsBadConfig(t *testing.T) {
	good := &Target{Name: "a", Tier: Tier1Premium, Weight: 100, Enabled: true}
	cases := []struct {
		desc    string
		targets []*Target
		rules   []*Rule
	}{
		{"无后端", nil, nil},
		{"后端名重复", []*Target{good, {Name: "a", Tier: Tier2Standard, Weight: 1, Enabled: true}}, nil},
		{"权重非正", []*Target{{Name: "b", Tier: Tier1Premium, Weight: 0, Enabled: true}}, nil},
		{"规则引用不存在的后端", []*Target{good},
			[]*Rule{{Name: "r", TargetTier: Tier1Premium, PreferTargets: []string{"nope"}}}},
		{"非法 glob", []*Target{good},
			[]*Rule{{Name: "r", TargetTier: Tier1Premium, MatchApps: []string{"[invalid"}}}},
	}
	for _, c := range cases {
		if _, err := NewPolicy(c.targets, c.rules, Tier2Standard, nil, nil); err == nil {
			t.Errorf("%s：应校验失败", c.desc)
		}
	}
}

// ---------------------------------------------------------------------------
// 熔断器
// ---------------------------------------------------------------------------

// TestBreakerOpensAfterThreshold 校验连续失败达阈值后熔断。
func TestBreakerOpensAfterThreshold(t *testing.T) {
	b := NewBreaker("t", 2, time.Minute)
	if !b.Allow() {
		t.Fatal("初始应放行")
	}
	b.RecordFailure()
	if b.State() != StateClosed {
		t.Error("单次失败不应熔断")
	}
	b.RecordFailure()
	if b.State() != StateOpen {
		t.Error("达阈值应熔断")
	}
	if b.Allow() {
		t.Error("熔断后应拒绝")
	}
}

// TestBreakerRecoversAfterCooldown 校验冷却期满进入半开，试探成功即恢复。
func TestBreakerRecoversAfterCooldown(t *testing.T) {
	b := NewBreaker("t", 1, time.Minute)
	clock := time.Now()
	b.now = func() time.Time { return clock }

	b.RecordFailure()
	if b.State() != StateOpen {
		t.Fatal("应已熔断")
	}
	clock = clock.Add(2 * time.Minute)
	if b.State() != StateHalfOpen {
		t.Error("冷却期满应进入半开")
	}
	if !b.Allow() {
		t.Error("半开应允许试探")
	}
	b.RecordSuccess()
	if b.State() != StateClosed {
		t.Error("试探成功应恢复")
	}
}

// TestHalfOpenFailureReopens 校验半开态下一次失败即退回熔断。
func TestHalfOpenFailureReopens(t *testing.T) {
	b := NewBreaker("t", 3, time.Minute)
	clock := time.Now()
	b.now = func() time.Time { return clock }

	for i := 0; i < 3; i++ {
		b.RecordFailure()
	}
	clock = clock.Add(2 * time.Minute)
	b.Allow() // 进入半开并试探
	b.RecordFailure()
	if b.State() != StateOpen {
		t.Error("半开失败应立即退回熔断")
	}
}

// TestHalfOpenLimitsProbes 校验半开态下试探请求限量。
func TestHalfOpenLimitsProbes(t *testing.T) {
	b := NewBreaker("t", 1, time.Minute)
	clock := time.Now()
	b.now = func() time.Time { return clock }

	b.RecordFailure()
	clock = clock.Add(2 * time.Minute)
	allowed := 0
	for i := 0; i < 10; i++ {
		if b.Allow() {
			allowed++
		}
	}
	if allowed != 2 {
		t.Errorf("半开应只放行 2 个试探，实际 %d", allowed)
	}
}
