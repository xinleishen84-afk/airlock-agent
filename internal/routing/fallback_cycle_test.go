package routing

import "testing"

// tierSynthetic 是一个当前没有后端的档位，只用来测链形状。
// 降级链的合法性只取决于链本身的形状，与档位是否有后端无关——
// 这也正是新增档位时最容易引入环的地方。
//
// A tier with no backends, used only to exercise chain shapes. A chain's
// validity depends on its shape alone, not on whether a tier has backends —
// which is exactly where adding a tier tends to introduce a cycle.
const tierSynthetic = Tier(3)

func cycleTestTargets() []*Target {
	return []*Target{
		{Name: "a", Tier: Tier1Premium, Weight: 1},
		{Name: "b", Tier: Tier2Standard, Weight: 1},
	}
}

// TestFallbackChainCycleRejected 证明成环的降级链在构造期就被拒绝。
// Proves a cyclic degradation chain is rejected at construction.
//
// 成环不会让网关挂死——两处遍历（proxy.collectFrom 与预算降级）都有
// visited 保护。它的危害是安静的：降级绕回起点，请求落在不该走的档位上，
// 日志里与正常降级无法区分。这类「不报错但走错」的配置只能靠启动期拦。
//
// A cycle does not hang the gateway — both walk sites guard with a visited
// set. Its damage is quiet: the chain loops back and requests land on a tier
// they should never reach, indistinguishable in the logs from a normal
// downgrade. Config that misbehaves without erroring can only be caught at
// startup.
func TestFallbackChainCycleRejected(t *testing.T) {
	cases := map[string]map[Tier]Tier{
		"两档互指": {Tier1Premium: Tier2Standard, Tier2Standard: Tier1Premium},
		"三档成环": {Tier1Premium: Tier2Standard, Tier2Standard: tierSynthetic, tierSynthetic: Tier1Premium},
		"自指":   {Tier2Standard: Tier2Standard},
	}
	for name, chain := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPolicy(cycleTestTargets(), nil, Tier2Standard, chain, nil); err == nil {
				t.Fatal("成环的降级链被接受了——候选枚举会在它上面无限循环")
			}
		})
	}
}

// TestFallbackChainAcyclicAccepted 确认环检测没有误杀正常链。
// Confirms cycle detection does not reject legitimate chains.
//
// 环检测的风险是过严：降级链允许多条链汇合到同一个链尾（多档最终都退到
// 本地集群是常见配置），汇合不是环。误杀会让合法配置启动失败。
//
// Over-strictness is the risk here: several tiers legitimately converge on one
// terminal tier, and convergence is not a cycle. Rejecting it would fail valid
// configs at startup.
func TestFallbackChainAcyclicAccepted(t *testing.T) {
	cases := map[string]map[Tier]Tier{
		"默认链":     nil,
		"线性链":     {Tier1Premium: Tier2Standard, Tier2Standard: tierSynthetic},
		"汇合到同一链尾": {Tier1Premium: tierSynthetic, Tier2Standard: tierSynthetic},
	}
	for name, chain := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPolicy(cycleTestTargets(), nil, Tier2Standard, chain, nil); err != nil {
				t.Fatalf("无环链被误拒: %v", err)
			}
		})
	}
}
