// Package routing 实现身份感知的多级性能路由。
//
// 分流决策三级优先，从高到低：
//  1. 显式指定 —— X-Workload-Tier 头直接钦点梯队（应急切换、灰度放量）
//  2. 规则匹配 —— 按 app / task / tenant / priority 匹配运维配置的规则
//  3. 任务兜底 —— 按任务类型的默认定级表
//
// 第 3 条是「预算精确保留给高价值任务」的核心资产：未登记的任务默认落
// Tier2，想上 Tier1 必须显式登记——默认省钱而不是默认烧钱。
package routing

import (
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/xinleishen84-afk/airlock-agent/internal/identity"
)

// Tier 是性能梯队。数值越小档次越高，便于用比较表达「不低于某档」。
type Tier int

const (
	Tier1Premium  Tier = 1 // 云端顶级模型：复杂推理、Agent 规划调度
	Tier2Standard Tier = 2 // 本地私有化集群：大批量、高频、结构化提取
)

// Label 返回中文可读名，用于日志与报表。
func (t Tier) Label() string {
	switch t {
	case Tier1Premium:
		return "Tier1-云端旗舰"
	case Tier2Standard:
		return "Tier2-本地集群"
	default:
		return fmt.Sprintf("Tier%d", int(t))
	}
}

// DefaultTaskTier 是任务类型的默认定级表。
var DefaultTaskTier = map[identity.TaskKind]Tier{
	identity.TaskPlanning:          Tier1Premium,
	identity.TaskReasoning:         Tier1Premium,
	identity.TaskCodeGeneration:    Tier1Premium,
	identity.TaskToolOrchestration: Tier1Premium,
	identity.TaskExtraction:        Tier2Standard,
	identity.TaskClassification:    Tier2Standard,
	identity.TaskSummarization:     Tier2Standard,
	identity.TaskTranslation:       Tier2Standard,
	identity.TaskRerank:            Tier2Standard,
	identity.TaskEmbeddingPrep:     Tier2Standard,
	identity.TaskUnknown:           Tier2Standard, // 身份不明 = 不给花钱
}

// Target 是一个可路由的后端实例。
type Target struct {
	Name       string
	Tier       Tier
	BaseURL    string
	Model      string
	Weight     int // 同梯队内的加权分流权重
	Enabled    bool
	SelfHosted bool // 私有化部署：不出企业边界，也不计公有云预算

	// InputPricePerMTok / OutputPricePerMTok 为美元每百万 token。
	// 为 0 表示未登记价格——自建集群是 GPU 摊销成本，按 token 计价本身就不对，
	// 不应编造单价让预算核算失真。
	InputPricePerMTok  float64
	OutputPricePerMTok float64

	// CredentialKey 是密钥源中的逻辑名，不是凭证本身。
	// 因此 Target 可以安全地写进配置文件、提交到代码仓库。
	CredentialKey string
}

// EstimateCost 按 token 数估算成本（美元）。未登记价格的后端返回 0。
func (t *Target) EstimateCost(inputTokens, outputTokens int64) float64 {
	if t.InputPricePerMTok == 0 && t.OutputPricePerMTok == 0 {
		return 0
	}
	return float64(inputTokens)/1e6*t.InputPricePerMTok +
		float64(outputTokens)/1e6*t.OutputPricePerMTok
}

// Rule 是一条身份路由规则。所有已填字段之间是「与」关系，留空表示不约束。
type Rule struct {
	Name            string
	TargetTier      Tier
	MatchApps       []string // 支持 glob，如 "toolbench-*"
	MatchTasks      []identity.TaskKind
	MatchTenants    []string
	MinPriority     int // 0 表示不约束
	MatchAttributes map[string]string
	PreferTargets   []string // 命中后优先选择的后端名
	Priority        int      // 规则自身优先级，越小越先匹配
	Enabled         bool
}

// Matches 判断身份是否命中本规则。
func (r *Rule) Matches(id identity.Identity) bool {
	if !r.Enabled {
		return false
	}
	if len(r.MatchApps) > 0 && !matchAny(r.MatchApps, id.App) {
		return false
	}
	if len(r.MatchTasks) > 0 && !containsTask(r.MatchTasks, id.Task) {
		return false
	}
	if len(r.MatchTenants) > 0 && !containsString(r.MatchTenants, id.Tenant) {
		return false
	}
	if r.MinPriority > 0 && id.Priority < r.MinPriority {
		return false
	}
	for k, want := range r.MatchAttributes {
		if id.Attributes[k] != want {
			return false
		}
	}
	return true
}

// Budget 是梯队预算，用于把昂贵的公有云额度锁死在高价值任务上。
//
// 达到硬上限后，本梯队的请求会被强制降级到下一档——这是兜底闸门：
// 即便有低价值任务误配成了 Tier1，也不会把额度吃穿。
type Budget struct {
	mu             sync.Mutex
	HardLimitUSD   float64 // 0 表示不限
	SoftLimitRatio float64
	spentUSD       float64
	warned         bool
}

// NewBudget 创建梯队预算。
func NewBudget(hardLimitUSD float64) *Budget {
	return &Budget{HardLimitUSD: hardLimitUSD, SoftLimitRatio: 0.8}
}

// Record 累计一次调用的花费，返回是否刚跨过软阈值（用于告警去重）。
func (b *Budget) Record(costUSD float64) (crossedSoftLimit bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.spentUSD += costUSD
	if b.HardLimitUSD <= 0 || b.warned {
		return false
	}
	if b.spentUSD >= b.HardLimitUSD*b.SoftLimitRatio {
		b.warned = true
		return true
	}
	return false
}

// Exhausted 判断预算是否已耗尽。
func (b *Budget) Exhausted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.HardLimitUSD > 0 && b.spentUSD >= b.HardLimitUSD
}

// Spent 返回已花费金额。
func (b *Budget) Spent() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.spentUSD
}

// Decision 是一次选路的结果，完整记录「为什么走了这一档」，便于审计与调优。
type Decision struct {
	Tier           Tier
	Identity       identity.Identity
	Reason         string // explicit_header / rule / task_default（可带 +budget_downgrade）
	RuleName       string
	PreferTargets  []string
	DowngradedFrom Tier // 非 0 表示因预算耗尽而降级
}

// Policy 是完整路由策略：后端清单 + 规则集 + 降级链 + 预算。
type Policy struct {
	targets       []*Target
	rules         []*Rule
	defaultTier   Tier
	fallbackChain map[Tier]Tier // 某梯队不可用时的下一站，缺省表示无
	budgets       map[Tier]*Budget
}

// NewPolicy 构造并校验策略。校验放在构造期：配置错误应该让进程起不来，
// 而不是在生产流量上暴露。
func NewPolicy(targets []*Target, rules []*Rule, defaultTier Tier,
	fallbackChain map[Tier]Tier, budgets map[Tier]*Budget) (*Policy, error) {

	if len(targets) == 0 {
		return nil, fmt.Errorf("路由策略未配置任何后端")
	}
	names := map[string]bool{}
	for _, t := range targets {
		if t.Name == "" {
			return nil, fmt.Errorf("后端名不能为空")
		}
		if names[t.Name] {
			return nil, fmt.Errorf("后端名重复: %s", t.Name)
		}
		names[t.Name] = true
		if t.Weight <= 0 {
			return nil, fmt.Errorf("后端 %s 的权重必须为正数", t.Name)
		}
	}
	for _, r := range rules {
		for _, p := range r.PreferTargets {
			if !names[p] {
				return nil, fmt.Errorf("规则 %s 引用了不存在的后端: %s", r.Name, p)
			}
		}
		// glob 模式在构造期就要验证，避免运行时静默失配
		for _, pattern := range r.MatchApps {
			if _, err := path.Match(pattern, "probe"); err != nil {
				return nil, fmt.Errorf("规则 %s 的 app 模式非法 %q: %w", r.Name, pattern, err)
			}
		}
	}

	sorted := make([]*Rule, len(rules))
	copy(sorted, rules)
	// 规则按自身优先级排序，保证匹配顺序稳定可预期
	stableSortRules(sorted)

	if fallbackChain == nil {
		fallbackChain = map[Tier]Tier{Tier1Premium: Tier2Standard}
	}
	if err := validateFallbackChain(fallbackChain); err != nil {
		return nil, err
	}
	if budgets == nil {
		budgets = map[Tier]*Budget{}
	}
	if defaultTier == 0 {
		defaultTier = Tier2Standard
	}
	return &Policy{
		targets: targets, rules: sorted, defaultTier: defaultTier,
		fallbackChain: fallbackChain, budgets: budgets,
	}, nil
}

// TargetsOf 取出某梯队下全部启用的后端。
func (p *Policy) TargetsOf(tier Tier) []*Target {
	var out []*Target
	for _, t := range p.targets {
		if t.Tier == tier && t.Enabled {
			out = append(out, t)
		}
	}
	return out
}

// Fallback 返回某梯队的下一站，ok=false 表示已是链尾。
func (p *Policy) Fallback(tier Tier) (Tier, bool) {
	next, ok := p.fallbackChain[tier]
	return next, ok
}

// BudgetOf 返回某梯队的预算，可能为 nil（不限）。
func (p *Policy) BudgetOf(tier Tier) *Budget { return p.budgets[tier] }

// Resolve 根据身份决定梯队。
func (p *Policy) Resolve(id identity.Identity) Decision {
	// 1. 显式指定：应急切换与灰度放量走这条路
	if id.TierHint > 0 {
		t := Tier(id.TierHint)
		if len(p.TargetsOf(t)) > 0 {
			return Decision{Tier: t, Identity: id, Reason: "explicit_header"}
		}
		// 指定了一个没有后端的梯队，回落到规则匹配而非硬失败
	}

	// 2. 规则匹配：运维可配置的主路径
	for _, r := range p.rules {
		if r.Matches(id) {
			return Decision{
				Tier: r.TargetTier, Identity: id,
				Reason: "rule", RuleName: r.Name, PreferTargets: r.PreferTargets,
			}
		}
	}

	// 3. 任务兜底：未登记的任务默认落 Tier2
	tier, ok := DefaultTaskTier[id.Task]
	if !ok {
		tier = p.defaultTier
	}
	return Decision{Tier: tier, Identity: id, Reason: "task_default"}
}

// ApplyBudget 是预算闸门：目标梯队预算耗尽时沿降级链下沉。
func (p *Policy) ApplyBudget(d Decision) Decision {
	original := d.Tier
	tier := d.Tier
	visited := map[Tier]bool{}

	for !visited[tier] {
		visited[tier] = true
		b := p.budgets[tier]
		if b == nil || !b.Exhausted() {
			break
		}
		next, ok := p.fallbackChain[tier]
		if !ok {
			break // 已是链尾，仍返回该档让请求以真实错误失败，便于上游感知
		}
		tier = next
	}

	if tier != original {
		d.Tier = tier
		d.Reason += "+budget_downgrade"
		d.DowngradedFrom = original
	}
	return d
}

// Describe 输出可读的策略概览，用于启动日志与配置核对。
func (p *Policy) Describe() string {
	var b strings.Builder
	b.WriteString("路由策略：\n")
	seen := map[Tier]bool{}
	for _, t := range p.targets {
		if seen[t.Tier] {
			continue
		}
		seen[t.Tier] = true
		quota := "预算不限"
		if bd := p.budgets[t.Tier]; bd != nil && bd.HardLimitUSD > 0 {
			quota = fmt.Sprintf("预算 $%.4f/$%.2f", bd.Spent(), bd.HardLimitUSD)
		}
		fmt.Fprintf(&b, "  %s（%s）\n", t.Tier.Label(), quota)
		for _, tt := range p.TargetsOf(t.Tier) {
			flag := "公有云"
			if tt.SelfHosted {
				flag = "私有化"
			}
			fmt.Fprintf(&b, "    - %s: %s [%s] 权重 %d\n", tt.Name, tt.Model, flag, tt.Weight)
		}
	}
	b.WriteString("  规则（按优先级）：\n")
	for _, r := range p.rules {
		fmt.Fprintf(&b, "    [%d] %s: apps=%v tasks=%v -> %s\n",
			r.Priority, r.Name, r.MatchApps, r.MatchTasks, r.TargetTier.Label())
	}
	return b.String()
}

// matchAny 判断值是否命中任一 glob 模式。
func matchAny(patterns []string, value string) bool {
	for _, p := range patterns {
		if ok, err := path.Match(p, value); err == nil && ok {
			return true
		}
	}
	return false
}

// containsTask 判断任务类型是否在列表中。
func containsTask(list []identity.TaskKind, v identity.TaskKind) bool {
	for _, t := range list {
		if t == v {
			return true
		}
	}
	return false
}

// containsString 判断字符串是否在列表中。
func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// stableSortRules 按规则优先级稳定排序。
func stableSortRules(rules []*Rule) {
	for i := 1; i < len(rules); i++ {
		for j := i; j > 0 && rules[j].Priority < rules[j-1].Priority; j-- {
			rules[j], rules[j-1] = rules[j-1], rules[j]
		}
	}
}

// validateFallbackChain 拒绝成环的降级链。
// Rejects a cyclic degradation chain.
//
// # 这是配置合理性检查，不是防挂死
// # This is a config-sanity check, not a hang guard
//
// 降级链有两处遍历，proxy.collectFrom 与 Policy 的预算降级，两处都用
// visited 集合防了环，成环时的实际行为是「走遍各档后停」，不会死循环。
//
// 拦在这里的理由是别的：成环几乎必然是运维漏写了链尾。而它的症状是安静的
// ——请求不报错，只是降级走到了不该走的档位上，从日志上看和正常降级
// 一模一样。构造期拒绝，让这种配置在启动时就说话。
//
// 同时这也让两处 visited 保护从「必需」降级为「冗余」：将来谁写第三处
// 遍历，忘了加保护也不会挂，因为成环的链根本进不来。
//
// Both walk sites — proxy.collectFrom and the budget downgrade — already guard
// with a visited set, so a cycle terminates rather than spinning. The reason to
// reject it here is different: a cycle almost always means an operator omitted
// the chain's terminal tier, and the symptom is quiet — requests still succeed,
// they just degrade onto a tier they should never reach, indistinguishable in
// the logs from a normal downgrade. Failing at construction makes it speak up.
//
// It also demotes those two visited guards from load-bearing to redundant: a
// future third walk site that forgets one still cannot hang, because a cyclic
// chain never gets built.
func validateFallbackChain(chain map[Tier]Tier) error {
	for start := range chain {
		visited := map[Tier]bool{start: true}
		tier := start
		for {
			next, ok := chain[tier]
			if !ok {
				break
			}
			if visited[next] {
				return fmt.Errorf(
					"降级链成环（%s 出发经 %s 回到已访问的梯队）——"+
						"降级会绕回起点，请求最终落在不该走的档位上，"+
						"而日志里看不出与正常降级的区别。"+
						"请让每条降级链有明确的链尾 / cyclic fallback chain",
					start.Label(), tier.Label())
			}
			visited[next] = true
			tier = next
		}
	}
	return nil
}
