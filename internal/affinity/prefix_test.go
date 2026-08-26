package affinity

import (
	"encoding/json"
	"fmt"
	"math"
	"testing"
)

// TestPrefixKeyStableAcrossTurns 校验同一会话的多轮对话得到相同前缀键。
//
// 这是亲和路由的根本前提：若把每轮变化的用户消息也算进哈希，
// 每一轮都会得到不同的键，路由随之跳变——与不做亲和路由没有区别。
func TestPrefixKeyStableAcrossTurns(t *testing.T) {
	sysPrompt := `{"role":"system","content":"你是一个企业助手，遵循以下 SOP……"}`
	tools := `[{"type":"function","function":{"name":"query_order"}}]`

	turn1 := fmt.Sprintf(`{"model":"gpt-oss-120b","tools":%s,"messages":[%s,{"role":"user","content":"第一轮提问"}]}`, tools, sysPrompt)
	turn2 := fmt.Sprintf(`{"model":"gpt-oss-120b","tools":%s,"messages":[%s,{"role":"user","content":"第一轮提问"},{"role":"assistant","content":"回答"},{"role":"user","content":"第二轮完全不同的提问"}]}`, tools, sysPrompt)

	k1, ok1 := PrefixKey([]byte(turn1))
	k2, ok2 := PrefixKey([]byte(turn2))
	if !ok1 || !ok2 {
		t.Fatal("应能提取前缀键")
	}
	if k1 != k2 {
		t.Error("同一系统前缀的多轮对话必须得到相同的键，否则路由会跳变、缓存亲和失效")
	}
}

// TestPrefixKeyDiffersByModel 校验不同模型得到不同键。
// 不同模型的 KV 缓存互不相通，混在一起会路由到没加载该模型的副本。
func TestPrefixKeyDiffersByModel(t *testing.T) {
	body := `{"model":"%s","messages":[{"role":"system","content":"同样的提示词"}]}`
	k1, _ := PrefixKey([]byte(fmt.Sprintf(body, "gpt-oss-120b")))
	k2, _ := PrefixKey([]byte(fmt.Sprintf(body, "qwen-72b")))
	if k1 == k2 {
		t.Error("不同模型必须得到不同的前缀键")
	}
}

// TestPrefixKeyDiffersByTools 校验工具 Schema 变化会改变键。
func TestPrefixKeyDiffersByTools(t *testing.T) {
	base := `{"model":"m","tools":%s,"messages":[{"role":"system","content":"s"}]}`
	k1, _ := PrefixKey([]byte(fmt.Sprintf(base, `[{"name":"a"}]`)))
	k2, _ := PrefixKey([]byte(fmt.Sprintf(base, `[{"name":"b"}]`)))
	if k1 == k2 {
		t.Error("工具 Schema 不同应得到不同键——前缀实际内容变了")
	}
}

// TestPrefixKeyAbsentWithoutStablePrefix 校验无稳定前缀时不做亲和。
func TestPrefixKeyAbsentWithoutStablePrefix(t *testing.T) {
	if _, ok := PrefixKey([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`)); ok {
		t.Error("纯用户消息无稳定前缀，亲和路由没有意义")
	}
}

// TestPrefixKeyMalformedBody 校验畸形请求体不 panic。
func TestPrefixKeyMalformedBody(t *testing.T) {
	if _, ok := PrefixKey([]byte(`{not json`)); ok {
		t.Error("畸形请求体应返回 false")
	}
}

// TestRingAffinityStable 校验同一键稳定路由到同一副本。
//
// 这是 prefix caching 能生效的关键：vLLM 的缓存是每副本本地的，
// 请求被打散到 N 个副本，命中率就降到 1/N。
func TestRingAffinityStable(t *testing.T) {
	members := []string{"gpu-1", "gpu-2", "gpu-3", "gpu-4"}
	ring := NewRing(members, 1.25)
	eligible := toSet(members)

	key := uint64(0xDEADBEEF)
	first := ring.Pick(key, eligible)
	if first == "" {
		t.Fatal("应选出副本")
	}
	for i := 0; i < 100; i++ {
		if got := ring.Pick(key, eligible); got != first {
			t.Fatalf("第 %d 次选路跳变: %s -> %s", i, first, got)
		}
	}
}

// TestRingDistributesDifferentKeys 校验不同前缀分散到不同副本。
func TestRingDistributesDifferentKeys(t *testing.T) {
	members := []string{"gpu-1", "gpu-2", "gpu-3", "gpu-4"}
	ring := NewRing(members, 1.25)
	eligible := toSet(members)

	hits := map[string]int{}
	for i := 0; i < 4000; i++ {
		hits[ring.Pick(hashOf(i), eligible)]++
	}
	if len(hits) != len(members) {
		t.Errorf("所有副本都应分到流量，实际只有 %d 个: %v", len(hits), hits)
	}
	// 虚拟节点 128 个，分布应大致均匀（允许 ±50%）
	expect := 4000.0 / float64(len(members))
	for m, n := range hits {
		if math.Abs(float64(n)-expect)/expect > 0.5 {
			t.Errorf("副本 %s 分布严重不均: %d（期望约 %.0f）", m, n, expect)
		}
	}
}

// TestBoundedLoadSpillsOver 校验热点前缀超载后下溢到其他副本。
//
// 前缀分布极不均匀：一个热门 Agent 的系统提示词可能占 80% 流量。
// 朴素一致性哈希会把它全压到一个副本，其余闲置。
func TestBoundedLoadSpillsOver(t *testing.T) {
	members := []string{"gpu-1", "gpu-2", "gpu-3"}
	ring := NewRing(members, 1.25)
	eligible := toSet(members)

	hotKey := uint64(12345)
	primary := ring.Pick(hotKey, eligible)

	// 把同一个热点前缀灌进去，超过容量后应下溢
	assigned := map[string]int{}
	for i := 0; i < 60; i++ {
		m := ring.Pick(hotKey, eligible)
		ring.Acquire(m)
		assigned[m]++
	}

	if assigned[primary] == 60 {
		t.Error("热点前缀全压在一个副本上，有界负载未生效")
	}
	if assigned[primary] == 0 {
		t.Error("首选副本应承接大部分流量，否则缓存亲和失去意义")
	}
	// 首选副本仍应是最大承接方——亲和优先于均衡
	for m, n := range assigned {
		if m != primary && n > assigned[primary] {
			t.Errorf("下溢副本 %s(%d) 超过首选 %s(%d)，亲和性被破坏",
				m, n, primary, assigned[primary])
		}
	}
}

// TestReleaseFreesCapacity 校验请求结束后容量被释放。
func TestReleaseFreesCapacity(t *testing.T) {
	ring := NewRing([]string{"a", "b"}, 1.25)
	ring.Acquire("a")
	ring.Acquire("a")
	if ring.Load("a") != 2 {
		t.Fatalf("在途数应为 2，实际 %d", ring.Load("a"))
	}
	ring.Release("a")
	ring.Release("a")
	if ring.Load("a") != 0 {
		t.Errorf("释放后应归零，实际 %d", ring.Load("a"))
	}
	// 多余的 Release 不应让计数变负
	ring.Release("a")
	if ring.Load("a") != 0 {
		t.Errorf("配对失衡时计数不应为负，实际 %d", ring.Load("a"))
	}
}

// TestRingSkipsUnhealthyMembers 校验不健康副本被跳过。
func TestRingSkipsUnhealthyMembers(t *testing.T) {
	members := []string{"gpu-1", "gpu-2", "gpu-3"}
	ring := NewRing(members, 1.25)

	key := uint64(999)
	primary := ring.Pick(key, toSet(members))

	// 把首选副本标记为不可用
	eligible := toSet(members)
	delete(eligible, primary)

	got := ring.Pick(key, eligible)
	if got == primary {
		t.Error("不健康副本不应被选中")
	}
	if got == "" {
		t.Error("仍有健康副本时不应返回空")
	}
}

// TestRingNoEligibleMembers 校验无可用副本时返回空。
func TestRingNoEligibleMembers(t *testing.T) {
	ring := NewRing([]string{"a", "b"}, 1.25)
	if got := ring.Pick(1, map[string]bool{}); got != "" {
		t.Errorf("无可用副本应返回空，实际 %q", got)
	}
}

// TestRebuildPreservesAffinity 校验副本扩容时大部分键的归属不变。
//
// 一致性哈希的核心价值：扩容时只有约 1/N 的键需要迁移。
// 若用取模哈希，扩容会让几乎所有键重新映射，全部缓存瞬间失效。
func TestRebuildPreservesAffinity(t *testing.T) {
	before := []string{"gpu-1", "gpu-2", "gpu-3"}
	ring := NewRing(before, 1000) // 大 loadFactor 排除负载因素干扰

	keys := make([]uint64, 1000)
	original := make([]string, len(keys))
	for i := range keys {
		keys[i] = hashOf(i)
		original[i] = ring.Pick(keys[i], toSet(before))
	}

	after := append(append([]string{}, before...), "gpu-4")
	ring.Rebuild(after)

	moved := 0
	for i, k := range keys {
		if ring.Pick(k, toSet(after)) != original[i] {
			moved++
		}
	}
	// 3 -> 4 副本，理论迁移约 25%，放宽到 40% 以容忍虚拟节点分布偏差
	if float64(moved)/float64(len(keys)) > 0.40 {
		t.Errorf("扩容迁移了 %d/%d 个键（%.0f%%），一致性哈希未生效",
			moved, len(keys), float64(moved)/float64(len(keys))*100)
	}
	if moved == 0 {
		t.Error("扩容后应有部分键迁移到新副本，否则新副本永远拿不到流量")
	}
}

// toSet 把副本列表转成可用集合。
func toSet(members []string) map[string]bool {
	s := make(map[string]bool, len(members))
	for _, m := range members {
		s[m] = true
	}
	return s
}

// hashOf 为测试生成分散的键。
func hashOf(i int) uint64 {
	b, _ := json.Marshal(map[string]int{"k": i})
	k, _ := PrefixKey([]byte(fmt.Sprintf(
		`{"model":"m","messages":[{"role":"system","content":%q}]}`, string(b))))
	return k
}
