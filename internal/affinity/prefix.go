// Package affinity 实现前缀感知的缓存亲和路由。
//
// # 为什么网关决定 prefix caching 的成败
//
// Agent 每次调用都携带极长且几乎完全相同的前缀：系统提示词、工作 SOP、
// 工具 Schema，动辄数千 token。vLLM 的 prefix caching 能复用上一次请求
// 的 KV 状态，省掉重复 prefill，TTFT 最高下降 85%。
//
// **但缓存是每副本本地的。** 如果网关按轮询或随机把同前缀的请求
// 打散到 N 个副本，命中率直接降到 1/N——后端开了 prefix caching，
// 收益却被网关亲手摧毁。这个问题极难发现：功能完全正常，
// 只是 TTFT 一直下不去，而 GPU 侧的命中率指标看起来「就是这样」。
//
// 解法是按前缀哈希做一致性路由，让同前缀请求稳定落到同一副本。
//
// # 为什么不能是朴素一致性哈希
//
// 前缀分布极不均匀：一个热门 Agent 的系统提示词可能占全部流量的 80%，
// 朴素一致性哈希会把它全压到一个副本上，其余副本闲置。
// 因此采用**有界负载一致性哈希**（consistent hashing with bounded loads）：
// 首选副本超过平均负载的一定倍数时，顺环下溢到下一个副本。
// 在缓存亲和与负载均衡之间取得平衡。
package affinity

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"sort"
	"sync"
	"sync/atomic"
)

// virtualNodes 是每个真实副本在哈希环上的虚拟节点数。
// 太少会导致环上分布不均，太多会拖慢查找。128 是常用折中。
const virtualNodes = 128

// Ring 是有界负载的一致性哈希环。
type Ring struct {
	mu      sync.RWMutex
	nodes   []ringNode // 按哈希值升序
	members []string
	loads   map[string]*atomic.Int64
	// loadFactor 是允许的负载上限倍数。1.25 表示任一副本的在途请求数
	// 不得超过平均值的 1.25 倍，超过则下溢到环上下一个副本。
	loadFactor float64
	total      atomic.Int64
}

// ringNode 是环上的一个虚拟节点。
type ringNode struct {
	hash   uint64
	member string
}

// NewRing 创建哈希环。loadFactor 小于 1 时取默认值 1.25。
func NewRing(members []string, loadFactor float64) *Ring {
	if loadFactor < 1 {
		loadFactor = 1.25
	}
	r := &Ring{
		loads:      make(map[string]*atomic.Int64, len(members)),
		loadFactor: loadFactor,
	}
	r.Rebuild(members)
	return r
}

// Rebuild 重建哈希环。副本上下线时调用。
func (r *Ring) Rebuild(members []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.members = append(r.members[:0], members...)
	r.nodes = r.nodes[:0]
	for _, m := range members {
		if _, ok := r.loads[m]; !ok {
			r.loads[m] = &atomic.Int64{}
		}
		for i := 0; i < virtualNodes; i++ {
			r.nodes = append(r.nodes, ringNode{hash: hashNode(m, i), member: m})
		}
	}
	sort.Slice(r.nodes, func(i, j int) bool { return r.nodes[i].hash < r.nodes[j].hash })

	// 清理已下线副本的计数，避免 map 无限增长
	live := make(map[string]bool, len(members))
	for _, m := range members {
		live[m] = true
	}
	for m := range r.loads {
		if !live[m] {
			delete(r.loads, m)
		}
	}
}

// Pick 为给定前缀键选择副本。
//
// eligible 是当前健康且可用的副本集合（由熔断、压力等级筛出）。
// 返回空串表示无可用副本。
func (r *Ring) Pick(key uint64, eligible map[string]bool) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.nodes) == 0 {
		return ""
	}

	// 计算负载上限：平均在途数 × loadFactor，向上取整且至少为 1
	eligibleCount := 0
	for _, m := range r.members {
		if eligible == nil || eligible[m] {
			eligibleCount++
		}
	}
	if eligibleCount == 0 {
		return ""
	}
	avg := float64(r.total.Load()) / float64(eligibleCount)
	capacity := int64(avg*r.loadFactor) + 1

	// 从 key 的哈希位置顺环查找第一个「可用且未超载」的副本
	start := sort.Search(len(r.nodes), func(i int) bool { return r.nodes[i].hash >= key })
	seen := make(map[string]bool, eligibleCount)

	for i := 0; i < len(r.nodes); i++ {
		node := r.nodes[(start+i)%len(r.nodes)]
		if seen[node.member] {
			continue
		}
		if eligible != nil && !eligible[node.member] {
			seen[node.member] = true
			continue
		}
		if load, ok := r.loads[node.member]; ok && load.Load() < capacity {
			return node.member
		}
		seen[node.member] = true
		if len(seen) >= eligibleCount {
			break
		}
	}

	// 全部超载：退回首选副本，保住缓存亲和。
	// 此时负载均衡已无意义（都满了），不如让缓存继续命中——
	// 打散只会让每个副本都重新 prefill，情况更糟。
	for i := 0; i < len(r.nodes); i++ {
		node := r.nodes[(start+i)%len(r.nodes)]
		if eligible == nil || eligible[node.member] {
			return node.member
		}
	}
	return ""
}

// Acquire 记录一个请求进入某副本。必须与 Release 配对。
func (r *Ring) Acquire(member string) {
	r.mu.RLock()
	load, ok := r.loads[member]
	r.mu.RUnlock()
	if ok {
		load.Add(1)
		r.total.Add(1)
	}
}

// Release 记录一个请求离开某副本。
func (r *Ring) Release(member string) {
	r.mu.RLock()
	load, ok := r.loads[member]
	r.mu.RUnlock()
	if !ok {
		return
	}
	if load.Add(-1) < 0 {
		load.Store(0) // 防御：配对失衡时不让计数变负
	}
	if r.total.Add(-1) < 0 {
		r.total.Store(0)
	}
}

// Load 返回某副本当前在途请求数。
func (r *Ring) Load(member string) int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if load, ok := r.loads[member]; ok {
		return load.Load()
	}
	return 0
}

// hashNode 计算虚拟节点的环上位置。
func hashNode(member string, index int) uint64 {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(index))
	h := sha256.New()
	h.Write([]byte(member))
	h.Write(buf[:])
	return binary.BigEndian.Uint64(h.Sum(nil)[:8])
}

// ---------------------------------------------------------------------------
// 前缀键提取
// ---------------------------------------------------------------------------

// PrefixKey 从请求体中提取「稳定前缀」的哈希键。
//
// 关键在于**只哈希真正可缓存的部分**：
//
//	系统提示词 + 工具 Schema + 首条用户消息之前的一切
//
// 而不是整个请求体。若把每轮变化的用户消息也算进去，
// 同一会话的每一轮都会得到不同的键，路由随之跳变，
// 缓存亲和完全失效——这与不做亲和路由没有区别。
//
// vLLM 的 prefix caching 按 token block 前缀匹配，
// 因此只要请求的**开头部分**一致，就能命中。
func PrefixKey(body []byte) (uint64, bool) {
	var doc struct {
		Model    string            `json:"model"`
		System   json.RawMessage   `json:"system"`
		Tools    json.RawMessage   `json:"tools"`
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return 0, false
	}

	h := sha256.New()
	// 模型必须参与哈希：不同模型的 KV 缓存互不相通，
	// 混在一起会把请求路由到根本没加载该模型的副本
	h.Write([]byte(doc.Model))
	h.Write([]byte{0})

	wrote := false
	if len(doc.System) > 0 {
		h.Write(doc.System)
		h.Write([]byte{0})
		wrote = true
	}
	if len(doc.Tools) > 0 {
		h.Write(doc.Tools)
		h.Write([]byte{0})
		wrote = true
	}

	// 取消息列表中的前导 system 消息（OpenAI 格式把系统提示放这里）
	for _, raw := range doc.Messages {
		var msg struct {
			Role string `json:"role"`
		}
		if err := json.Unmarshal(raw, &msg); err != nil {
			break
		}
		if msg.Role != "system" && msg.Role != "developer" {
			break // 遇到第一条非系统消息即停止——后面都是每轮变化的内容
		}
		h.Write(raw)
		h.Write([]byte{0})
		wrote = true
	}

	if !wrote {
		// 无稳定前缀可言（纯用户消息），亲和路由没有意义
		return 0, false
	}
	return binary.BigEndian.Uint64(h.Sum(nil)[:8]), true
}
