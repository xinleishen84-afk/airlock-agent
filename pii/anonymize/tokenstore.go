package anonymize

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
)

// # The token store
// # 令牌库
//
// SessionVault refuses to serialize because a placeholder map that outlives the
// conversation is a PII database. A token store is that same map, deliberately
// made durable — that is what buys reversibility across sessions, processes and
// systems. The trade is real and cannot be engineered away: tokenizing moves
// the secret from the payload into the store, so the store inherits every
// control the raw data had.
// SessionVault 拒绝序列化，是因为一张活得比会话久的占位符表就是 PII 数据库。
// 令牌库正是同一张表，只是刻意做成持久的——这就是跨会话、跨进程、跨系统
// 可逆的代价。这个取舍是真实的，工程上消不掉：
// 令牌化把秘密从载荷搬进了库，于是库继承了原始数据的全部管控要求。
//
// Which is why the tenant is in the key and not in a WHERE clause added by
// convention. A convention holds until the one call site that forgets it.
// 这也是租户必须在键里、而不是靠约定加在 WHERE 子句里的原因。
// 约定成立到某一个忘了它的调用点为止。

// ErrTokenStore reports a store-level failure.
// 报告存储层故障。
//
// Distinguished from "not found" on purpose. A distributed store that is
// unreachable must not look like a token that does not exist: the first is a
// retryable outage, the second means the model invented the token. Collapsing
// them makes an outage look like a hallucination and hides both.
// 刻意与「未找到」区分。一个连不上的分布式存储不能长得像一个不存在的令牌：
// 前者是可重试的故障，后者说明模型编造了令牌。
// 把两者混为一谈，会让故障看起来像幻觉，并同时掩盖两者。
var ErrTokenStore = errors.New("令牌库故障 / token store failure")

// TokenKey scopes every token operation.
// 限定每一次令牌操作的作用域。
//
// A struct rather than positional arguments: adding the tenant to a two-string
// signature would have compiled at every existing call site with the tenant
// silently landing in the namespace slot.
// 用结构体而非位置参数：往两个字符串的签名里加租户，
// 会让每一个现有调用点照样编译通过，而租户悄悄落进了命名空间那个位置。
type TokenKey struct {
	Tenant    Tenant
	Namespace string
}

// Validate checks the key.
// 校验键。
func (k TokenKey) Validate() error {
	if err := ValidateTenant(k.Tenant); err != nil {
		return err
	}
	if k.Namespace == "" {
		return fmt.Errorf("令牌命名空间不能为空 / token namespace is required")
	}
	// 命名空间同样要限制字符集，理由与租户一致：它会被拼进存储层的键。
	//
	// CacheTokenStore 的键是 前缀+租户+":"+命名空间+":t:"+令牌。租户的
	// 字符集禁止了冒号，命名空间此前只查非空——两个不同的
	// (命名空间, 令牌) 因此可以拼出同一个键，读到对方的原值。
	//
	// 现网走不到：复原路径上的命名空间由 tokenRe 的 [a-z0-9_]+ 捕获组
	// 限定，冒号进不来。但那是另一个文件里的正则顺手保住的，而这里正是
	// 校验这个键的地方，pii/* 又是文档里声明可单独 import 的公开包——
	// 任何直接调用 Issue/Resolve 的人都能把它重新打开。
	// composite() 的注释已经写明「分隔符必须是字符集禁止的字节」，
	// 这里只是让 tokenKey 也真正满足那个前提。
	//
	// The namespace is joined into storage keys, so it needs the same charset
	// restriction as the tenant. CacheTokenStore keys are
	// prefix+tenant+":"+namespace+":t:"+token; the tenant charset forbids the
	// colon while the namespace was only checked for emptiness, so two distinct
	// (namespace, token) pairs could render one key and read each other's
	// values.
	//
	// Not reachable in production today: on the restore path the namespace comes
	// from tokenRe's [a-z0-9_]+ capture group. But that is a regex in another
	// file holding the invariant by accident, while this is the function that
	// validates the key — and pii/* is documented as separately importable, so
	// any direct caller of Issue/Resolve reopens it. composite() already states
	// that the separator must be a byte the charset forbids; this makes
	// tokenKey actually satisfy that premise.
	if !namespacePattern.MatchString(k.Namespace) {
		return fmt.Errorf(
			"令牌命名空间 %q 非法：只允许小写字母、数字与下划线，最长 64——"+
				"它会被拼进存储层的键，其他字符可能让两个命名空间碰撞到同一个键 / "+
				"invalid token namespace %q", k.Namespace, k.Namespace)
	}
	return nil
}

// namespacePattern 限定命名空间字符集。与 tokenRe 的捕获组保持一致，
// 否则合法签发的令牌会在复原时被自己的校验拒掉。
//
// Kept in step with tokenRe's capture group; a mismatch would make legitimately
// issued tokens fail their own validation on the way back.
var namespacePattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// composite renders the key as a storage-level composite key.
// 把键渲染成存储层的复合键。
//
// The separator is a byte the tenant charset forbids, so no pair of distinct
// (tenant, namespace) can produce the same string.
// 分隔符是租户字符集禁止的字节，
// 因此任何两个不同的 (租户, 命名空间) 都不可能产出同一个字符串。
func (k TokenKey) composite() string {
	return string(k.Tenant) + "\x00" + k.Namespace
}

// TokenStore holds token → value mappings, scoped by tenant.
// 持有按租户限定作用域的「令牌 → 原值」映射。
type TokenStore interface {
	// Issue returns a stable token for (key, value), creating one on first
	// sight. The same triple must always map to the same token.
	// 为 (键, 原值) 返回稳定令牌，首次出现时创建。
	// 同一组三元组必须始终映射到同一令牌。
	Issue(ctx context.Context, key TokenKey, value string) (string, error)

	// Resolve returns the value behind a token. The bool reports whether the
	// token exists; a non-nil error means the store could not answer.
	// 返回令牌背后的原值。bool 报告令牌是否存在；
	// error 非空表示存储无法作答。
	Resolve(ctx context.Context, key TokenKey, token string) (string, bool, error)

	// Clear erases one tenant's tokens and reports how many were erased.
	// 抹除某个租户的令牌，并报告抹除了多少条。
	//
	// The count is not a convenience. Article 17 erasure has to be evidenced,
	// and "we called clear()" is not evidence — a clear that silently matched
	// nothing because the tenant string was wrong looks identical to a clear
	// that worked.
	// 这个计数不是便利功能。GDPR 第 17 条的擦除是要拿出证据的，
	// 而「我们调了 clear()」不算证据——一次因为租户串写错而静默匹配到零条的
	// 清除，与一次真正成功的清除，看起来完全一样。
	Clear(ctx context.Context, tenant Tenant) (int, error)
}

// newToken generates a random token.
// 生成随机令牌。
//
// Random rather than derived from the value: a derived token is a hash under
// another name and inherits the offline-enumeration problem. Randomness is also
// what makes tokens unlinkable across tenants without any per-tenant salt —
// there is nothing to salt.
// 随机而非由原值推导：推导出来的令牌不过是换了名字的哈希，
// 继承了同样的离线穷举问题。随机性也正是令牌无需任何租户级盐
// 就跨租户不可关联的原因——根本没有东西可加盐。
func newToken() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("%w: 生成令牌失败 / generating token: %v", ErrTokenStore, err)
	}
	return hex.EncodeToString(raw), nil
}

// ---------------------------------------------------------------------------
// MemoryTokenStore / 进程内令牌库
// ---------------------------------------------------------------------------

// MemoryTokenStore is an in-process TokenStore for development.
// 是供开发使用的进程内 TokenStore。
//
// Tokens do not survive a restart. That is not merely a durability gap: the
// point of tokenization is that a token means the same thing tomorrow and in
// the next process, so a store that forgets breaks correlation without breaking
// anything visibly — a rolling update silently turns every outstanding token
// into a phantom.
// 令牌不跨重启存活。这不只是持久性缺口：令牌化的意义就在于同一个令牌
// 明天、在另一个进程里含义相同，而一个会遗忘的库会在不显现任何故障的
// 情况下破坏关联性——一次滚动更新会静默地把所有在途令牌变成幻影。
type MemoryTokenStore struct {
	ttl time.Duration

	mu     sync.RWMutex
	byPair map[string]tokenEntry // composite\x00value -> token
	byTok  map[string]tokenEntry // composite\x00token -> value
}

type tokenEntry struct {
	payload string
	expires time.Time // zero 表示不过期 / zero means no expiry
}

func (e tokenEntry) expired(now time.Time) bool {
	return !e.expires.IsZero() && now.After(e.expires)
}

// NewMemoryTokenStore builds an in-process token store.
// 构造进程内令牌库。
//
// ttl of zero means tokens never expire.
// ttl 为 0 表示令牌永不过期。
func NewMemoryTokenStore(ttl time.Duration) *MemoryTokenStore {
	return &MemoryTokenStore{
		ttl:    ttl,
		byPair: map[string]tokenEntry{},
		byTok:  map[string]tokenEntry{},
	}
}

// Issue implements TokenStore.
func (s *MemoryTokenStore) Issue(_ context.Context, key TokenKey, value string) (string, error) {
	if err := key.Validate(); err != nil {
		return "", err
	}
	pairKey := key.composite() + "\x00" + value
	now := time.Now()

	s.mu.RLock()
	entry, ok := s.byPair[pairKey]
	s.mu.RUnlock()
	if ok && !entry.expired(now) {
		return entry.payload, nil
	}

	tok, err := newToken()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check: another goroutine may have issued one while this one was
	// generating randomness. Overwriting would hand out two tokens for one
	// value and break the stability guarantee.
	// 二次确认：本协程生成随机数期间可能已有其他协程签发了令牌。
	// 覆盖会让一个值对应两个令牌，破坏稳定性保证。
	if existing, ok := s.byPair[pairKey]; ok && !existing.expired(now) {
		return existing.payload, nil
	}

	var expires time.Time
	if s.ttl > 0 {
		expires = now.Add(s.ttl)
	}
	s.byPair[pairKey] = tokenEntry{payload: tok, expires: expires}
	s.byTok[key.composite()+"\x00"+tok] = tokenEntry{payload: value, expires: expires}
	return tok, nil
}

// Resolve implements TokenStore.
func (s *MemoryTokenStore) Resolve(_ context.Context, key TokenKey, token string) (string, bool, error) {
	if err := key.Validate(); err != nil {
		return "", false, err
	}
	s.mu.RLock()
	entry, ok := s.byTok[key.composite()+"\x00"+token]
	s.mu.RUnlock()
	if !ok || entry.expired(time.Now()) {
		return "", false, nil
	}
	return entry.payload, true, nil
}

// Clear implements TokenStore.
func (s *MemoryTokenStore) Clear(_ context.Context, tenant Tenant) (int, error) {
	if err := ValidateTenant(tenant); err != nil {
		return 0, err
	}
	prefix := string(tenant) + "\x00"

	s.mu.Lock()
	defer s.mu.Unlock()

	erased := 0
	for k := range s.byTok {
		if hasPrefix(k, prefix) {
			delete(s.byTok, k)
			erased++
		}
	}
	for k := range s.byPair {
		if hasPrefix(k, prefix) {
			delete(s.byPair, k)
		}
	}
	return erased, nil
}

// Size returns how many distinct values are tokenized.
// 返回已令牌化的不同值的数量。
func (s *MemoryTokenStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byPair)
}

// hasPrefix avoids importing strings for one check in a hot loop.
// 避免为热循环里的一次检查引入 strings。
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// ---------------------------------------------------------------------------
// CacheTokenStore / 分布式缓存令牌库
// ---------------------------------------------------------------------------

// Cache is the narrow contract a distributed cache must satisfy.
// 是分布式缓存必须满足的最小契约。
//
// Deliberately small enough to be implemented over Redis, DynamoDB, Memcached
// or a cloud KV store in a few dozen lines, and deliberately free of any
// vendor's types — a redis.Client in this package's signature would make every
// user of this library depend on that client's version.
// 刻意小到用 Redis、DynamoDB、Memcached 或任意云 KV 都能几十行实现完，
// 也刻意不含任何厂商类型——本包签名里出现 redis.Client，
// 会让本库的每个使用者都依赖那个客户端的版本。
// # 这个接口不是「任意 KV 都能实现」的
// # This interface is not implementable by any KV store
//
// 名字叫 Cache 是历史遗留，它的语义要求比「缓存」严格得多。想接一个后端
// 进来，先对着下面这几条逐条确认；有任何一条做不到，**不要接**。
// 为了「支持更多后端」而放松其中任何一条，等于把安全保证降级到最弱的那个
// 实现的水平，而使用者无从知道自己用的是哪一档。
//
// 一、FindOrCreate 必须是原子且线性化的。
//
//	两个并发调用必须恰好一个 created=true，其余拿到同一个 current。
//	用 GET 再 SET 组合出来的不算——那中间有间隙。
//
// 二、TTL 语义必须稳定。ttl 只在创建时生效，命中已有键不得续期。
//
//	后端若自带滑动过期且关不掉，不要接：一个被反复读到的 PII 映射会
//	因此永不过期。
//
// 三、租户隔离靠键前缀，因此 DeleteByPrefix 必须真的删干净。
//
//	做不到前缀删除的后端应当自行维护每租户索引集合，而不是在生产集群上
//	全量扫描键空间。
//
// 四、正常运行中不得静默丢映射。这一条把大多数「缓存」排除在外：
//
//	Memcached 与配了 allkeys-lru 的 Redis 会在内存压力下驱逐任意键，
//	而**令牌映射是恢复原值的唯一来源**——丢一条，就有一个已经发给模型
//	的令牌永远还不回去，且没有任何错误提示。
//	这个库存的不是缓存，是 PII 映射数据库，只是恰好放在一个 KV 里。
//
// 五、持久性由部署方显式选择。是否落盘、是否复制、丢失窗口多大，
//
//	这些必须是写下来的决定，不能是默认值碰巧如此。
//
// Naming it Cache is historical; the semantics are far stricter. Check each
// requirement before wiring a backend in, and if any cannot be met, do not wire
// it in: relaxing one to "support more backends" silently downgrades the
// guarantee to the weakest implementation, with no way for a user to tell which
// one they have. Requirement four excludes most caches — Memcached and Redis
// under allkeys-lru evict arbitrary keys, while this mapping is the only source
// from which a value can be recovered.
//
// # Redis 部署要求
// # Redis deployment requirements
//
// 单条命令做到 FindOrCreate 需要 Redis 7.0 起的 SET key val NX GET
// （6.2 引入了 SET ... GET，但与 NX 组合的行为在 7.0 才稳定下来）。
// 更早的版本用 Lua 脚本或 Redis Function。
//
// 本设计只写一个键，因此 Redis Cluster 下不涉及跨槽（CROSSSLOT）问题——
// 脚本若将来要触碰多个键，必须先保证它们落在同一个哈希槽。
//
// 生产上必须显式配置：
//
//	maxmemory-policy noeviction   驱逐会让已发出的令牌永久失去原值
//	容量监控                       noeviction 下内存打满表现为写入报错，
//	                              需要在到达之前就看见
//	持久化与复制                   由部署方按丢失窗口的容忍度选择
//
// One key per mapping means no CROSSSLOT concern in Redis Cluster. Eviction
// permanently orphans tokens already handed to a model, so noeviction is
// mandatory and capacity must be monitored before it is reached.
type Cache interface {
	// Get returns a value; ok=false means the key is absent.
	// 取值；ok=false 表示键不存在。
	Get(ctx context.Context, key string) (string, bool, error)

	// FindOrCreate atomically returns the value under key, creating it with
	// value when absent. It returns whichever value is authoritative afterward.
	// 原子地返回 key 上的值；键不存在时以 value 创建。
	// 无论走哪条路，返回的都是此后权威的那个值。
	//
	// # 这个接口为什么是「映射级」而不是「原语级」
	// # Why this is a mapping-level operation rather than a primitive
	//
	// 它取代的是 SetNX。SetNX 返回的是「我存进去了吗」，而调用方真正要的是
	// 「这个键上权威的值是什么」——于是每个调用方都得在 SetNX 返回 false 之后
	// 再补一次 Get。那次补读不在同一个原子步骤里：两次调用之间键可能过期，
	// 于是每个调用方还得各自处理「刚被拒绝、现在又不存在了」这个状态。
	//
	// 把「检查—创建—取回」压成一个操作，是把正确性的负担从每一个调用方
	// 移到唯一的实现方。这不是省一次往返的问题：组合处正是撕裂发生的地方，
	// 而组合是每个调用方各写一遍的。
	//
	// SetNX answers "did I store it" while callers need "what is authoritative
	// here", forcing every caller to follow up with a Get that is not in the
	// same atomic step — and to handle the key having expired in between.
	// Collapsing check-create-read into one operation moves the correctness
	// burden from every call site to the single implementation. The point is
	// not the saved round trip: composition is where tearing happens, and
	// composition is what each caller writes for itself.
	//
	// # 实现方必须保证的
	// # What an implementation must guarantee
	//
	// 原子：不存在任何时刻，别的调用方能观察到「键已被检查但尚未创建」。
	// 两个并发调用必须线性化——恰好一个拿到 created=true，其余拿到
	// created=false 与同一个 current 值。
	//
	// 直接写（Set）不行：两个副本同时令牌化同一个值时必须收敛到同一个令牌，
	// 而直接写会让后写者覆盖掉先写者已经返回给调用方的那个。
	//
	// Redis 6.2 起可用 SET key val NX GET EX ttl 一条命令做到；更早的版本
	// 用 Lua 脚本。做不到原子的存储不应实现这个接口——一个「大概率原子」的
	// 实现比没有更糟，因为调用方会按契约去信任它。
	//
	// Atomic: no other caller may observe a moment where the key has been
	// checked but not yet created. Two concurrent calls must linearize —
	// exactly one gets created=true, the rest get created=false and the same
	// current value. A plain Set is not acceptable: concurrent replicas
	// tokenizing one value must converge, and Set lets a later writer clobber
	// the token an earlier one already returned to its caller.
	//
	// Redis 6.2+ does this in one command (SET key val NX GET EX ttl); earlier
	// versions need a Lua script. A store that cannot do it atomically should
	// not implement this interface: a "usually atomic" implementation is worse
	// than none, because callers trust the contract.
	//
	// ttl 为 0 表示不过期。仅在 created=true 时设置 ttl——键已存在时不得
	// 续期，否则一条被反复读到的映射会永远不过期，而 TTL 正是 PII 保留期。
	//
	// A zero TTL means no expiry. The TTL applies only when created: an
	// existing key must not be refreshed, or a frequently-read mapping would
	// never expire — and that TTL is the PII retention period.
	FindOrCreate(ctx context.Context, key, value string, ttl time.Duration) (
		current string, created bool, err error)

	// DeleteByPrefix removes every key under a prefix and returns the count.
	// 删除某前缀下的全部键并返回条数。
	//
	// Prefix deletion is what makes tenant erasure a single operation. A store
	// that cannot do it (Redis without SCAN discipline, for instance) should
	// implement it by maintaining a per-tenant index set rather than by
	// scanning the whole keyspace on a live cluster.
	// 前缀删除是让租户擦除成为单次操作的关键。
	// 做不到的存储（例如未规范使用 SCAN 的 Redis）应当靠维护
	// 每租户索引集合来实现，而不是在生产集群上全量扫描键空间。
	DeleteByPrefix(ctx context.Context, prefix string) (int, error)
}

// CacheTokenStore is a TokenStore over a distributed cache.
// 是构建在分布式缓存之上的 TokenStore。
//
// This is the driver a multi-replica deployment needs: with an in-process
// store, a token issued by replica A is a phantom at replica B, and the failure
// appears as intermittent un-restorable responses that correlate with nothing.
// 这是多副本部署需要的驱动：用进程内库时，副本 A 签发的令牌在副本 B 就是幻影，
// 而故障表现为「偶发的还原不了的响应」，且与任何东西都关联不上。
type CacheTokenStore struct {
	cache   Cache
	keyring *Keyring
	ttl     time.Duration
	prefix  string

	// epoch 决定令牌身份用哪一代 K_token。轮换它会改变全部令牌身份，
	// 因此它跟随根密钥的生命周期，而不是运维随手可调的旋钮。
	// Rotating this changes every token identity, so it follows the root key's
	// lifecycle rather than being an operational dial.
	epoch TokenIdentityEpoch

	// dataVersion 是新记录使用的数据密钥版本。它可以随时向前推进：
	// 旧记录带着自己的版本号，Resolve 按记录里的版本派生。
	// Advancing this is safe at any time: old records name their own version.
	dataVersion DataKeyVersion
}

// CacheStoreOption 调整可选参数。
type CacheStoreOption func(*CacheTokenStore)

// WithIdentityEpoch 指定令牌身份 epoch。
//
// 只有根密钥轮换时才该动它。改了它，同一个 (租户, 命名空间, 原值) 会算出
// 新令牌，旧令牌仍可 Resolve（它们的记录还在），但不会再被签发出来。
//
// Change only when the root key rotates: the same input then yields a new
// token while old tokens remain resolvable but are never issued again.
func WithIdentityEpoch(e TokenIdentityEpoch) CacheStoreOption {
	return func(s *CacheTokenStore) { s.epoch = e }
}

// WithDataKeyVersion 指定新记录使用的数据密钥版本。
//
// 向前推进它即完成一次数据密钥轮换：新记录用新版本加密，旧记录照旧可解，
// 而**令牌身份完全不变**——这正是把两把密钥分开的目的。
//
// Advancing it performs a data-key rotation: new records use the new version,
// old ones still open, and token identity does not move — which is the point
// of separating the two keys.
func WithDataKeyVersion(v DataKeyVersion) CacheStoreOption {
	return func(s *CacheTokenStore) { s.dataVersion = v }
}

// NewCacheTokenStore builds a cache-backed token store.
// 构造基于缓存的令牌库。
//
// keyring 是必填的：令牌由租户密钥确定性派生，没有密钥就没有令牌。
// 见 deriveToken 里为什么这样设计。
//
// The keyring is required: tokens are derived deterministically under the
// tenant's key. See deriveToken for why.
func NewCacheTokenStore(c Cache, keyring *Keyring, ttl time.Duration,
	keyPrefix string, opts ...CacheStoreOption) (*CacheTokenStore, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: 缓存驱动不能为空 / cache is required", ErrTokenStore)
	}
	if keyring == nil {
		return nil, fmt.Errorf(
			"%w: 密钥环不能为空——令牌由租户密钥派生，"+
				"无密钥的派生可被任何拿到缓存读权限的人用「猜一个值、算一遍、"+
				"看键在不在」证实 / keyring is required", ErrTokenStore)
	}
	if ttl < 0 {
		// 负 TTL 会被 `if s.ttl > 0` 判成「不设到期时刻」，也就是永不过期
		// ——与调用方想表达的恰好相反。这类输入必须拒绝而不是猜。
		//
		// A negative TTL falls through the `> 0` check into "no expiry", the
		// opposite of what the caller meant. Refuse rather than guess.
		return nil, fmt.Errorf(
			"%w: TTL 不能为负（%s）——负值会被当成「永不过期」，"+
				"与调用方的本意相反；不过期请显式传 0 / negative TTL",
			ErrTokenStore, ttl)
	}
	if keyPrefix == "" {
		keyPrefix = "airlock:tok:"
	}
	s := &CacheTokenStore{
		cache: c, keyring: keyring, ttl: ttl, prefix: keyPrefix,
		epoch: DefaultTokenIdentityEpoch, dataVersion: DefaultDataKeyVersion,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.epoch == "" || s.dataVersion == "" {
		return nil, fmt.Errorf("%w: 身份 epoch 与数据密钥版本都不能为空 / "+
			"identity epoch and data key version are required", ErrTokenStore)
	}
	return s, nil
}

// tenantPrefix is the key prefix covering one tenant.
// 是覆盖单个租户的键前缀。
func (s *CacheTokenStore) tenantPrefix(t Tenant) string {
	return s.prefix + string(t) + ":"
}

// deriveToken 由 K_token 确定性地算出令牌身份。
//
// # 这是本驱动只需要写一条记录的原因
// # This is why the driver writes exactly one record
//
// 原来是「随机令牌 + 一个正向索引把值摘要指向它」。两条记录意味着两次写，
// 而缓存是分布式的：两次写之间可以断、可以崩、可以被各自驱逐。无论怎么
// 排序、怎么调 TTL，都只是把能观察到撕裂的窗口挪小，消不掉。
//
// 令牌确定性派生之后，正向索引整个不需要了——同一个值算出同一个令牌这件事
// 由函数保证，不需要存储去记。于是只剩一条记录，一次写。
//
// 用的是 K_token 而不是那把通用租户密钥：后者同时被 AES-GCM 用作加密密钥，
// 一把密钥承担两种代数结构没有安全证明可依，而分开只需在 HKDF 的 info 串里
// 多一段常量。见 Keyring.TokenIdentityKey。
//
// Derivation removes the forward index: that the same value yields the same
// token is guaranteed by the function rather than recorded by the store, so one
// record and one write remain. It uses K_token rather than the general-purpose
// tenant key, which also served as an AES-GCM key.
func (s *CacheTokenStore) deriveToken(k TokenKey, value string) (string, error) {
	ik, err := s.keyring.TokenIdentityKey(k.Tenant, s.epoch)
	if err != nil {
		return "", err
	}
	return deriveTokenIdentity(ik, k.Namespace, value), nil
}

// tokenKey is the reverse-lookup key.
// 是反向查找键。
func (s *CacheTokenStore) tokenKey(k TokenKey, token string) string {
	return s.tenantPrefix(k.Tenant) + k.Namespace + ":t:" + token
}

// Issue implements TokenStore.
//
// # 一次调用，一条记录，缓存里没有明文
// # One call, one record, and no plaintext in the cache
//
// 令牌身份由 K_token 确定性算出；原值用 K_data_vN 加密后连同 nonce、
// 密钥版本、身份 epoch、到期时刻组成一条 TokenRecord，经 FindOrCreate 一步落定。
//
// 安全不变量因此不靠顺序、补偿或进程内锁：
//
//   - 返回的令牌立即可 Resolve：FindOrCreate 返回的就是此后权威的那条记录。
//   - 不存在 partial mapping：只有一条记录，没有第二条可以撕裂。
//   - 并发签发线性化：各方算出同一个令牌，恰好一个创建，其余采纳赢家的记录。
//   - 提交后超时重试：下一次调用算出同一个令牌，FindOrCreate 返回已有记录。
//   - 令牌身份不含随机数；加密用的随机 nonce 只在密文里，不参与身份。
//
// Identity is derived; the value is encrypted and lands as one TokenRecord in a
// single FindOrCreate. The invariants rest on neither ordering, compensation,
// nor an in-process lock.
func (s *CacheTokenStore) Issue(ctx context.Context, key TokenKey, value string) (string, error) {
	if err := key.Validate(); err != nil {
		return "", err
	}
	tok, err := s.deriveToken(key, value)
	if err != nil {
		return "", err
	}

	dk, err := s.keyring.DataKey(key.Tenant, s.dataVersion)
	if err != nil {
		return "", err
	}
	aad := aeadAAD(key.Tenant, key.Namespace, tok, s.dataVersion, s.epoch)
	nonce, ct, err := sealValue(dk, value, aad)
	if err != nil {
		return "", err
	}
	rec := TokenRecord{
		KeyVersion:    s.dataVersion,
		IdentityEpoch: s.epoch,
		Nonce:         nonce,
		Ciphertext:    ct,
	}
	if s.ttl > 0 {
		rec.ExpiresAt = time.Now().Add(s.ttl)
	}

	current, _, err := s.cache.FindOrCreate(ctx, s.tokenKey(key, tok), rec.Encode(), s.ttl)
	if err != nil {
		return "", fmt.Errorf("%w: 签发令牌失败 / issuing token: %v", ErrTokenStore, err)
	}

	// 无论是本次创建的还是已存在的，都把权威记录解开核对一次再返回。
	//
	// 这不是多余的谨慎：Issue 的契约是「返回的令牌立即可 Resolve」，而这条
	// 契约的唯一诚实证明方式，就是在返回之前真的解一次。已存在的记录可能
	// 来自另一个数据密钥版本（轮换期间的正常情况），也可能来自另一套密钥环
	// 误写进同一前缀（配置错误）——前者必须解得开，后者必须响亮失败，
	// 而不是沉默地把一个解不开的令牌交出去。
	//
	// Issue promises the token resolves immediately, and the only honest proof
	// is to open it before returning. An existing record may come from another
	// data key version (normal during rotation) or from a different keyring
	// written under the same prefix (misconfiguration): the first must open,
	// the second must fail loudly rather than hand back an unusable token.
	plain, err := s.decodeAndOpen(key, tok, current)
	if err != nil {
		return "", err
	}
	if plain != value {
		return "", fmt.Errorf(
			"%w: 令牌 %s 已映射到另一个值——同一前缀下混用了不同的密钥环，"+
				"继续下去会让一个租户的令牌解析出另一份数据 / token collision",
			ErrTokenStore, tok)
	}
	return tok, nil
}

// decodeAndOpen 解析记录并认证解密。
//
// 记录里的 KeyVersion 决定用哪一代数据密钥，而不是用当前版本去撞——
// 这正是轮换之后旧记录仍然解得开的原因。IdentityEpoch 与 KeyVersion 同时
// 进 AAD，因此改标签不会让记录降级到另一把密钥，只会认证失败。
//
// The record names the data key version to derive, rather than the current one
// being assumed, which is why rotation does not orphan old records. Both labels
// enter the AAD, so relabelling fails authentication instead of downgrading.
func (s *CacheTokenStore) decodeAndOpen(key TokenKey, token, raw string) (string, error) {
	rec, err := DecodeTokenRecord(raw)
	if err != nil {
		return "", err
	}
	dk, err := s.keyring.DataKey(key.Tenant, rec.KeyVersion)
	if err != nil {
		return "", err
	}
	aad := aeadAAD(key.Tenant, key.Namespace, token, rec.KeyVersion, rec.IdentityEpoch)
	return openValue(dk, rec.Nonce, rec.Ciphertext, aad)
}

// Resolve implements TokenStore.
func (s *CacheTokenStore) Resolve(ctx context.Context, key TokenKey, token string) (string, bool, error) {
	if err := key.Validate(); err != nil {
		return "", false, err
	}
	raw, ok, err := s.cache.Get(ctx, s.tokenKey(key, token))
	if err != nil {
		return "", false, fmt.Errorf("%w: 解析令牌失败 / resolving token: %v", ErrTokenStore, err)
	}
	if !ok {
		return "", false, nil
	}

	rec, err := DecodeTokenRecord(raw)
	if err != nil {
		return "", false, err
	}
	// 记录里存了到期时刻，因此不必信任后端的 TTL：后端把键留久了，
	// 这里仍然按记录判过期。过期返回 (false, nil) 而不是报错——
	// 「这个令牌已经不在了」是确定的答案，不是故障。
	//
	// The record carries its own expiry, so a backend keeping the key longer
	// than intended does not extend the mapping. An expired record is a
	// definite answer, not a failure.
	if rec.Expired(time.Now()) {
		return "", false, nil
	}

	plain, err := s.decodeAndOpen(key, token, raw)
	if err != nil {
		return "", false, err
	}
	return plain, true, nil
}

// Clear implements TokenStore.
func (s *CacheTokenStore) Clear(ctx context.Context, tenant Tenant) (int, error) {
	if err := ValidateTenant(tenant); err != nil {
		return 0, err
	}
	n, err := s.cache.DeleteByPrefix(ctx, s.tenantPrefix(tenant))
	if err != nil {
		return 0, fmt.Errorf("%w: 擦除租户令牌失败 / erasing tenant tokens: %v", ErrTokenStore, err)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// SQLTokenStore / 加密关系型令牌库
// ---------------------------------------------------------------------------

// SQLExecutor is the subset of *sql.DB this store uses.
// 是本库用到的 *sql.DB 子集。
//
// An interface rather than *sql.DB so the store works with a transaction, a
// connection pool wrapper, or a test double — and so this package does not
// force a database driver on anyone who is not using it.
// 用接口而非 *sql.DB，使本库既能配事务、连接池包装，也能配测试替身——
// 同时不给任何不使用它的人强加数据库驱动。
type SQLExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (SQLResult, error)
	QueryRowContext(ctx context.Context, query string, args ...any) SQLRow
}

// SQLResult is the subset of sql.Result this store uses.
// 是本库用到的 sql.Result 子集。
type SQLResult interface {
	RowsAffected() (int64, error)
}

// SQLRow is the subset of *sql.Row this store uses.
// 是本库用到的 *sql.Row 子集。
type SQLRow interface {
	Scan(dest ...any) error
}

// ErrSQLNoRows must be returned by SQLRow.Scan when no row matched.
// SQLRow.Scan 在无匹配行时必须返回本错误。
//
// The adapter maps sql.ErrNoRows onto this so the store does not import
// database/sql, and so "no such token" stays distinguishable from a real
// database failure.
// 适配层把 sql.ErrNoRows 映射到这里，
// 使本库不必 import database/sql，也使「没有这个令牌」与真正的数据库故障
// 保持可区分。
var ErrSQLNoRows = errors.New("没有匹配的行 / no rows")

// SQLTokenStore is a TokenStore over an encrypted relational table.
// 是构建在加密关系表之上的 TokenStore。
//
// # Two things the schema must get right
// # 表结构必须做对的两件事
//
//  1. The composite primary key is (tenant_id, namespace, token). Not a
//     surrogate id with a tenant column beside it: a surrogate key makes
//     cross-tenant reads a matter of remembering the WHERE clause, and every
//     IDOR in this class is a forgotten WHERE clause.
//     复合主键是 (tenant_id, namespace, token)。不是「代理主键 + 旁边一个
//     租户列」：代理主键会把跨租户读取变成「记得写 WHERE 子句」的问题，
//     而这一类越权漏洞每一个都是一句忘掉的 WHERE。
//
//  2. The value is stored encrypted under the tenant's derived key, and looked
//     up by an HMAC digest of itself. Storing the plaintext would put every
//     tokenized value into the database's indexes, its backups, its replicas
//     and its query logs — which is the exposure tokenization was bought to
//     remove.
//     原值以租户派生密钥加密存储，并以自身的 HMAC 摘要作查找键。
//     存明文会把每一个被令牌化的值送进数据库的索引、备份、副本和查询日志——
//     而那正是买下令牌化本来要消除的暴露面。
type SQLTokenStore struct {
	db      SQLExecutor
	keyring *Keyring
	table   string
	ttl     time.Duration

	// dataVersion 是新行使用的数据密钥版本。旧行的 key_version 为空，
	// 按遗留方式解密——见 openRow。
	// New rows use this version; legacy rows have an empty key_version.
	dataVersion DataKeyVersion
}

// NewSQLTokenStore builds a database-backed token store.
// 构造基于数据库的令牌库。
func NewSQLTokenStore(db SQLExecutor, keyring *Keyring, table string, ttl time.Duration) (*SQLTokenStore, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: 数据库句柄不能为空 / db is required", ErrTokenStore)
	}
	if keyring == nil {
		return nil, fmt.Errorf(
			"%w: 缺少密钥环——没有它就只能存明文，"+
				"每个被令牌化的值都会进入数据库的索引、备份与副本 / keyring is required",
			ErrTokenStore)
	}
	if !safeIdentifier(table) {
		return nil, fmt.Errorf("%w: 表名 %q 非法 / invalid table name", ErrTokenStore, table)
	}
	return &SQLTokenStore{
		db: db, keyring: keyring, table: table, ttl: ttl,
		dataVersion: DefaultDataKeyVersion,
	}, nil
}

// Schema returns the DDL this store expects.
// 返回本库期望的建表语句。
//
// Shipped as code rather than as documentation so the composite primary key
// cannot drift from what the queries assume.
// 以代码而非文档形式提供，使复合主键不会与查询所假设的结构发生漂移。
func (s *SQLTokenStore) Schema() string {
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
  tenant_id     VARCHAR(64)  NOT NULL,
  namespace     VARCHAR(64)  NOT NULL,
  token         CHAR(32)     NOT NULL,
  value_digest  CHAR(64)     NOT NULL,
  value_cipher  BLOB         NOT NULL,
  value_nonce   BLOB         NULL,
  key_version   VARCHAR(16)  NULL,
  expires_at    BIGINT       NULL,
  PRIMARY KEY (tenant_id, namespace, token),
  UNIQUE (tenant_id, namespace, value_digest)
);`, s.table)
}

// digest computes the tenant-scoped lookup digest for a value.
// 计算某个值在租户作用域内的查找摘要。
func (s *SQLTokenStore) digest(key TokenKey, value string) (string, error) {
	k, err := s.keyring.Key(key.Tenant)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, k)
	mac.Write([]byte(key.Namespace))
	mac.Write([]byte{0})
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// sealRow 加密一行的值，返回 nonce、密文与所用的密钥版本。
//
// 用 K_data_vN 而不是那把通用租户密钥：后者同时被 HMAC 用作 digest 密钥，
// 一把密钥承担 HMAC 与 AES-GCM 两种代数结构没有安全证明可依。
// 见 Keyring.DataKey。
//
// AAD 绑定 (租户, 命名空间, 令牌, 密钥版本, 身份 epoch)。旧版只绑租户，
// 因此一行密文可以被搬到同租户的另一个令牌下照常解开——那正是这次收紧
// 要堵的搬运。
//
// Uses K_data_vN rather than the general-purpose tenant key, which also served
// as an HMAC key. The AAD now binds the namespace, token, key version and
// epoch: the previous version bound only the tenant, so a ciphertext could be
// moved to another token in the same tenant and still open.
func (s *SQLTokenStore) sealRow(key TokenKey, token, value string) (
	nonce, ct []byte, version DataKeyVersion, err error) {
	dk, err := s.keyring.DataKey(key.Tenant, s.dataVersion)
	if err != nil {
		return nil, nil, "", err
	}
	aad := aeadAAD(key.Tenant, key.Namespace, token, s.dataVersion, sqlIdentityEpoch)
	nonce, ct, err = sealValue(dk, value, aad)
	return nonce, ct, s.dataVersion, err
}

// openRow 解密一行，按行里记录的密钥版本选择密钥。
//
// # 空的 key_version 是遗留行，必须仍然解得开
// # An empty key_version marks a legacy row that must still open
//
// 本次整改之前写入的行没有 key_version、没有独立 nonce（nonce 拼在密文
// 前面），且 AAD 只绑了租户。直接切到新方案会让这些行全部解不开——
// 那不是「轮换」，那是数据丢失。因此保留一条遗留路径，按老规则解它们。
//
// 遗留路径只读不写：新行一律走新方案。随着 TTL 到期，遗留行自然消失。
//
// Rows written before this change carry no key version, no separate nonce (it
// was prefixed to the ciphertext) and an AAD binding only the tenant. Switching
// outright would make every one of them unreadable, which is data loss rather
// than rotation. The legacy path is read-only; new rows always use the new
// scheme and legacy rows drain away with their TTL.
func (s *SQLTokenStore) openRow(key TokenKey, token string, version DataKeyVersion,
	nonce, ct []byte) (string, error) {
	if version == "" {
		legacyKey, err := s.keyring.Key(key.Tenant)
		if err != nil {
			return "", err
		}
		gcm, err := newGCM(legacyKey)
		if err != nil {
			return "", err
		}
		if len(ct) < gcm.NonceSize() {
			return "", fmt.Errorf("%w: 遗留密文过短 / legacy ciphertext too short",
				ErrTokenStore)
		}
		n, body := ct[:gcm.NonceSize()], ct[gcm.NonceSize():]
		plain, err := gcm.Open(nil, n, body, []byte(key.Tenant))
		if err != nil {
			return "", fmt.Errorf("%w: 遗留行认证解密失败 / legacy decryption failed",
				ErrTokenStore)
		}
		return string(plain), nil
	}

	dk, err := s.keyring.DataKey(key.Tenant, version)
	if err != nil {
		return "", err
	}
	aad := aeadAAD(key.Tenant, key.Namespace, token, version, sqlIdentityEpoch)
	return openValue(dk, nonce, ct, aad)
}

// sqlIdentityEpoch 是 SQL 后端在 AAD 里使用的身份 epoch 常量。
//
// SQL 的令牌是随机生成后存下来的，不是派生的，因此它没有「身份随密钥轮换
// 而改变」的问题，也就不需要一个会变的 epoch。这里放一个固定值只是为了让
// 两个后端共用同一个 AAD 组装函数——把它做成可变量会暗示一个 SQL 并不具备
// 的语义。
//
// SQL tokens are random and stored rather than derived, so they have no
// identity-rotation problem and need no varying epoch. The constant exists so
// both backends share one AAD builder; making it configurable would imply a
// semantic SQL does not have.
const sqlIdentityEpoch TokenIdentityEpoch = "sql"

// Issue implements TokenStore.
func (s *SQLTokenStore) Issue(ctx context.Context, key TokenKey, value string) (string, error) {
	if err := key.Validate(); err != nil {
		return "", err
	}
	dig, err := s.digest(key, value)
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()

	var existing string
	row := s.db.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT token FROM %s WHERE tenant_id = ? AND namespace = ? AND value_digest = ?
		   AND (expires_at IS NULL OR expires_at > ?)`, s.table),
		string(key.Tenant), key.Namespace, dig, now)
	switch err := row.Scan(&existing); {
	case err == nil:
		return existing, nil
	case errors.Is(err, ErrSQLNoRows):
		// 首次出现，继续签发 / first sighting, fall through to issue
	default:
		return "", fmt.Errorf("%w: 查询令牌失败 / looking up token: %v", ErrTokenStore, err)
	}

	tok, err := newToken()
	if err != nil {
		return "", err
	}
	// 令牌先生成再加密：令牌进 AAD，因此密文与它绑定，
	// 一行密文被搬到另一个令牌下会认证失败。
	// The token is generated first because it enters the AAD, binding the
	// ciphertext to it: moving a row to another token fails authentication.
	nonce, sealed, version, err := s.sealRow(key, tok, value)
	if err != nil {
		return "", err
	}
	var expires any
	if s.ttl > 0 {
		expires = time.Now().Add(s.ttl).Unix()
	}

	if _, err := s.db.ExecContext(ctx, fmt.Sprintf(
		`INSERT INTO %s (tenant_id, namespace, token, value_digest, value_cipher,
		                 value_nonce, key_version, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, s.table),
		string(key.Tenant), key.Namespace, tok, dig, sealed,
		nonce, string(version), expires); err != nil {
		// 插入失败时先回头看一眼：唯一约束是并发的正常结果，不是故障。
		//
		// # 输家必须采纳赢家，而不是报错
		// # The loser must adopt the winner rather than fail
		//
		// SELECT 与 INSERT 之间有间隙，两个副本会同时落空、同时插入，
		// 而 UNIQUE (tenant, namespace, value_digest) 会拒绝后到的那个。
		// 原来的代码把这个拒绝当成写入故障直接抛出——实测真库语义下
		// 32 次并发签发有 4 次直接失败。它没有产生第二个令牌（约束挡住了），
		// 但调用方拿到的是错误，而正确结果是赢家那个令牌。
		//
		// 这不是补偿回滚：没有任何东西被撤销。原子性来自数据库的唯一约束
		// 本身，这里只是把「约束告诉我已经有一个了」翻译成「用那一个」。
		//
		// 之前这个缺陷被假 DB 藏住了：它用一把全局锁把 SELECT 与 INSERT
		// 串起来，比真数据库更原子，于是冲突从未发生。
		//
		// The gap between SELECT and INSERT lets two replicas both miss and
		// both insert, with the UNIQUE constraint rejecting the later one. That
		// rejection was raised as a write failure — measured, 4 of 32
		// concurrent issues failed outright. No second token was created, but
		// the caller got an error where the winner's token was the right
		// answer. This is not a compensating rollback: nothing is undone.
		// Atomicity comes from the constraint itself; this only translates
		// "one already exists" into "use that one".
		var winner string
		row := s.db.QueryRowContext(ctx, fmt.Sprintf(
			`SELECT token FROM %s WHERE tenant_id = ? AND namespace = ? AND value_digest = ?
			   AND (expires_at IS NULL OR expires_at > ?)`, s.table),
			string(key.Tenant), key.Namespace, dig, time.Now().Unix())
		if scanErr := row.Scan(&winner); scanErr == nil {
			return winner, nil
		}
		return "", fmt.Errorf("%w: 写入令牌失败 / storing token: %v", ErrTokenStore, err)
	}
	return tok, nil
}

// Resolve implements TokenStore.
func (s *SQLTokenStore) Resolve(ctx context.Context, key TokenKey, token string) (string, bool, error) {
	if err := key.Validate(); err != nil {
		return "", false, err
	}

	var (
		sealed  []byte
		nonce   []byte
		version string
	)
	row := s.db.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT value_cipher, value_nonce, key_version FROM %s
		   WHERE tenant_id = ? AND namespace = ? AND token = ?
		   AND (expires_at IS NULL OR expires_at > ?)`, s.table),
		string(key.Tenant), key.Namespace, token, time.Now().Unix())
	switch err := row.Scan(&sealed, &nonce, &version); {
	case errors.Is(err, ErrSQLNoRows):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("%w: 解析令牌失败 / resolving token: %v", ErrTokenStore, err)
	}

	// 按行里记的版本解密。空版本是本次整改之前写入的遗留行，走遗留路径。
	// Decrypt under the version the row names; an empty one is a legacy row.
	value, err := s.openRow(key, token, DataKeyVersion(version), nonce, sealed)
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// Clear implements TokenStore.
func (s *SQLTokenStore) Clear(ctx context.Context, tenant Tenant) (int, error) {
	if err := ValidateTenant(tenant); err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx,
		fmt.Sprintf(`DELETE FROM %s WHERE tenant_id = ?`, s.table), string(tenant))
	if err != nil {
		return 0, fmt.Errorf("%w: 擦除租户令牌失败 / erasing tenant tokens: %v", ErrTokenStore, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("%w: 读取擦除行数失败——擦除没有证据等于没有擦除 / "+
			"reading affected rows: %v", ErrTokenStore, err)
	}
	return int(n), nil
}

// safeIdentifier reports whether a name can be interpolated into SQL.
// 报告一个名字能否被拼进 SQL。
//
// Table names cannot be bound as parameters, so this is the only thing standing
// between a configured table name and injection.
// 表名无法作为参数绑定，因此这是配置来的表名与注入之间唯一的东西。
func safeIdentifier(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
