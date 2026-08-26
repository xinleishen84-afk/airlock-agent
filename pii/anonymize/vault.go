package anonymize

import (
	"fmt"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"hash/fnv"
	"strings"
	"sync"
	"time"
)

// PlaceholderPrefix is the fixed prefix of every placeholder.
// Format: ANONYMIZED_<TYPE>_<N>
// 是占位符的固定前缀。格式：ANONYMIZED_<TYPE>_<N>
const PlaceholderPrefix = "ANONYMIZED_"

// SessionVault holds the bidirectional "real value <-> placeholder" mapping
// for a single session.
// 保存单个会话的「真实值 <-> 占位符」双向映射。
//
// Three invariants:
// 三条不变量：
//
//  1. The mapping lives in memory only. This type exposes no serialization
//     method and no internal fields — once it reaches disk or Redis it *is* a
//     privacy leak.
//     映射只存在于内存。本结构不提供任何序列化方法，也不导出内部字段——
//     映射一旦落盘或进入 Redis，就等于隐私泄露。
//  2. A given entity keeps a stable placeholder within the session. Otherwise
//     the model cannot reason across turns that "this is the same person",
//     and multi-turn conversations degrade immediately.
//     同一实体在会话内占位符稳定。否则模型无法跨轮次推理「这是同一个人」，
//     多轮对话会立刻退化。
//  3. Purge must be called when the session ends.
//     会话结束必须 Purge。
type SessionVault struct {
	sessionID string
	ttl       time.Duration
	createdAt time.Time

	mu       sync.RWMutex
	forward  map[string]string // 「类型\x00真实值」-> 占位符
	reverse  map[string]string // 占位符 -> 真实值
	counters map[detect.EntityType]int
}

// newSessionVault 创建一个会话保险库。
func newSessionVault(sessionID string, ttl time.Duration) *SessionVault {
	return &SessionVault{
		sessionID: sessionID,
		ttl:       ttl,
		createdAt: time.Now(),
		forward:   make(map[string]string),
		reverse:   make(map[string]string),
		counters:  make(map[detect.EntityType]int),
	}
}

// SessionID 返回会话标识。
func (v *SessionVault) SessionID() string { return v.sessionID }

// PlaceholderFor returns (or allocates) the placeholder for a real value.
// 取得（或首次分配）某真实值对应的占位符。
//
// Keyed by "type + value": a person and a company with the same name must get
// distinct placeholders, otherwise restoration cannot tell them apart.
// 以「类型 + 真实值」为键：同名的人和公司必须拿到不同占位符，
// 否则复原时无法区分。
func (v *SessionVault) PlaceholderFor(e detect.Entity) string {
	key := string(e.Type) + "\x00" + e.Value

	v.mu.RLock()
	if p, ok := v.forward[key]; ok {
		v.mu.RUnlock()
		return p
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()
	// 双重检查：升级锁期间可能已被其他 goroutine 分配
	if p, ok := v.forward[key]; ok {
		return p
	}
	idx := v.counters[e.Type]
	v.counters[e.Type] = idx + 1
	placeholder := fmt.Sprintf("%s%s_%d", PlaceholderPrefix, e.Type, idx)
	v.forward[key] = placeholder
	v.reverse[placeholder] = e.Value
	return placeholder
}

// Resolve looks up the real value behind a placeholder.
// Unknown placeholders return ok=false.
// 按占位符查回真实值；未知占位符返回 ok=false。
func (v *SessionVault) Resolve(placeholder string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	val, ok := v.reverse[strings.ToUpper(placeholder)]
	return val, ok
}

// Size returns the number of registered entities.
// 返回已登记的实体数量。
func (v *SessionVault) Size() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.reverse)
}

// Expired reports whether the session has outlived its TTL.
// 判断会话是否已超过 TTL。
func (v *SessionVault) Expired() bool {
	return time.Since(v.createdAt) >= v.ttl
}

// Purge clears the mapping. Must be called when the session ends.
// 清空映射。会话结束必须调用。
func (v *SessionVault) Purge() {
	v.mu.Lock()
	defer v.mu.Unlock()
	// 显式置空而非重建 map，让 GC 尽快回收底层数组里的真实值
	for k := range v.forward {
		delete(v.forward, k)
	}
	for k := range v.reverse {
		delete(v.reverse, k)
	}
	for k := range v.counters {
		delete(v.counters, k)
	}
}

// AuditCounts returns per-type entity counts. The audit view exposes counts
// only — never the real values.
// 返回各类型的实体计数。审计视图只暴露计数，绝不暴露真实值。
func (v *SessionVault) AuditCounts() map[string]int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	counts := make(map[string]int)
	for placeholder := range v.reverse {
		if t, ok := typeFromPlaceholder(placeholder); ok {
			counts[t]++
		}
	}
	return counts
}

// ScanLeak asserts that the given payload contains none of the registered
// real values. It returns the leaked entity *types* — never the values
// themselves, to avoid a second leak into the logs.
// 断言给定载荷中不含任何已登记的真实值。
// 返回泄露的实体类型列表（不含真实值本身，避免二次泄露到日志）。
//
// This is the last line of defense in depth: even if the redaction logic has a
// bug, it catches the leak before data actually crosses the boundary.
// 这是纵深防御的最后一道：即便脱敏逻辑有 bug，也能在数据真正离境前拦下。
func (v *SessionVault) ScanLeak(payload string) []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	var leaked []string
	seen := map[string]bool{}
	for placeholder, real := range v.reverse {
		if real == "" || !strings.Contains(payload, real) {
			continue
		}
		if t, ok := typeFromPlaceholder(placeholder); ok && !seen[t] {
			seen[t] = true
			leaked = append(leaked, t)
		}
	}
	return leaked
}

// typeFromPlaceholder extracts the type name from a placeholder:
// ANONYMIZED_<TYPE>_<N> -> TYPE.
// 从占位符中解出类型名：ANONYMIZED_<TYPE>_<N> -> TYPE。
func typeFromPlaceholder(placeholder string) (string, bool) {
	rest, ok := strings.CutPrefix(placeholder, PlaceholderPrefix)
	if !ok {
		return "", false
	}
	idx := strings.LastIndexByte(rest, '_')
	if idx <= 0 {
		return "", false
	}
	return rest[:idx], true
}

// ---------------------------------------------------------------------------
// Sharded registry / 分片注册表
// ---------------------------------------------------------------------------

// vaultShards is the shard count of the registry. Sharding keeps highly
// concurrent sessions off a single lock — the gateway is a per-connection hot
// path, and one lock would become the throughput ceiling.
// 是注册表的分片数。分片是为了让高并发会话不争用同一把锁——
// 网关是每连接热路径，单锁会直接成为吞吐天花板。
const vaultShards = 64

// VaultRegistry is the sharded registry of session vaults, with TTL-based
// reclamation.
// 是会话保险库的分片注册表，带 TTL 自动回收。
type VaultRegistry struct {
	shards      [vaultShards]vaultShard
	ttl         time.Duration
	maxPerShard int
}

// vaultShard 是单个分片。
type vaultShard struct {
	mu     sync.Mutex
	vaults map[string]*SessionVault
}

// NewVaultRegistry 创建注册表。maxSessions 为全局上限，会均摊到各分片。
func NewVaultRegistry(ttl time.Duration, maxSessions int) *VaultRegistry {
	if ttl <= 0 {
		ttl = time.Hour
	}
	if maxSessions <= 0 {
		maxSessions = 100_000
	}
	r := &VaultRegistry{ttl: ttl, maxPerShard: maxSessions/vaultShards + 1}
	for i := range r.shards {
		r.shards[i].vaults = make(map[string]*SessionVault)
	}
	return r
}

// shardFor 按会话 ID 哈希选择分片。
func (r *VaultRegistry) shardFor(sessionID string) *vaultShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(sessionID))
	return &r.shards[h.Sum32()%vaultShards]
}

// Get 取得（或创建）某会话的保险库，顺带回收本分片的过期会话。
func (r *VaultRegistry) Get(sessionID string) (*SessionVault, error) {
	shard := r.shardFor(sessionID)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if v, ok := shard.vaults[sessionID]; ok {
		if !v.Expired() {
			return v, nil
		}
		// 过期会话的映射必须先清干净再重建
		v.Purge()
		delete(shard.vaults, sessionID)
	}

	r.collectExpiredLocked(shard)
	if len(shard.vaults) >= r.maxPerShard {
		return nil, fmt.Errorf("会话分片已达上限 %d，拒绝创建新会话", r.maxPerShard)
	}

	v := newSessionVault(sessionID, r.ttl)
	shard.vaults[sessionID] = v
	return v, nil
}

// collectExpiredLocked 回收本分片内所有过期会话（调用方需已持锁）。
func (r *VaultRegistry) collectExpiredLocked(shard *vaultShard) {
	for id, v := range shard.vaults {
		if v.Expired() {
			v.Purge()
			delete(shard.vaults, id)
		}
	}
}

// Drop 显式结束会话并清除映射。
func (r *VaultRegistry) Drop(sessionID string) {
	shard := r.shardFor(sessionID)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if v, ok := shard.vaults[sessionID]; ok {
		v.Purge()
		delete(shard.vaults, sessionID)
	}
}

// PurgeAll 清空全部会话（进程退出或安全事件响应时调用）。
func (r *VaultRegistry) PurgeAll() {
	for i := range r.shards {
		shard := &r.shards[i]
		shard.mu.Lock()
		for id, v := range shard.vaults {
			v.Purge()
			delete(shard.vaults, id)
		}
		shard.mu.Unlock()
	}
}

// ActiveSessions 返回当前活跃会话数。
func (r *VaultRegistry) ActiveSessions() int {
	total := 0
	for i := range r.shards {
		shard := &r.shards[i]
		shard.mu.Lock()
		total += len(shard.vaults)
		shard.mu.Unlock()
	}
	return total
}

// StartJanitor starts a background goroutine that periodically reclaims
// expired sessions. The returned stop function is for graceful shutdown.
// 启动后台回收协程，定期清理过期会话。返回的 stop 函数用于优雅停机。
func (r *VaultRegistry) StartJanitor(interval time.Duration) (stop func()) {
	if interval <= 0 {
		interval = time.Minute
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				for i := range r.shards {
					shard := &r.shards[i]
					shard.mu.Lock()
					r.collectExpiredLocked(shard)
					shard.mu.Unlock()
				}
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}
