package anonymize

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
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
	keyPrefix string) (*CacheTokenStore, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: 缓存驱动不能为空 / cache is required", ErrTokenStore)
	}
	if keyring == nil {
		return nil, fmt.Errorf(
			"%w: 密钥环不能为空——令牌由租户密钥派生，"+
				"无密钥的派生可被任何拿到缓存读权限的人用「猜一个值、算一遍、"+
				"看键在不在」证实 / keyring is required", ErrTokenStore)
	}
	if keyPrefix == "" {
		keyPrefix = "airlock:tok:"
	}
	return &CacheTokenStore{cache: c, keyring: keyring, ttl: ttl, prefix: keyPrefix}, nil
}

// tenantPrefix is the key prefix covering one tenant.
// 是覆盖单个租户的键前缀。
func (s *CacheTokenStore) tenantPrefix(t Tenant) string {
	return s.prefix + string(t) + ":"
}

// deriveToken 由「租户密钥 + 命名空间 + 原值」确定性地算出令牌。
//
// # 这是本驱动只需要写一个键的原因
// # This is why the driver writes exactly one key
//
// 原来是「随机令牌 + 一个正向索引把值摘要指向它」。两个键意味着两次写，
// 而缓存是分布式的，两次写之间可以断、可以崩、可以被各自驱逐。无论怎么
// 排序、怎么调 TTL，都只是把「能观察到撕裂」的窗口挪小，消不掉——
// Cache 接口只有 Get/SetNX/DeleteByPrefix，没有跨键事务原语，而给它加一个
// 会逼每个实现都提供跨键原子性，做不到的只能假装。
//
// 令牌确定性派生之后，正向索引整个不需要了：同一个值算出同一个令牌，
// 这件事由函数本身保证，不需要存储去记。于是只剩一个键
// 「令牌 → 原值」，一次写。**不存在两个键，也就不存在撕裂。**
//
// 顺带修掉一处比撕裂更早的弱点：原来的正向索引键是不加密钥的
// sha256(租户+命名空间+原值)。任何拿到缓存读权限的人，猜一个手机号、
// 算一遍 sha256、看那个键在不在，就能证实这个号码在不在系统里——
// 一次不需要解密任何东西的存在性泄露。HMAC 把这条路堵死：没有租户密钥
// 就算不出键，而密钥在密钥环里，不在缓存里。
//
// 截断到 128 位：碰撞概率可忽略，且与原来 newToken 的长度一致，
// 复原侧的 tokenRe 与既有语料都不受影响。
//
// Deterministic derivation removes the forward index entirely: that the same
// value yields the same token is guaranteed by the function, not recorded by
// the store. One key remains — token to value — and one write. With no second
// key there is nothing to tear, which no ordering or TTL tuning could achieve:
// the Cache interface has no cross-key transaction, and adding one would force
// every implementation to provide cross-key atomicity or fake it.
//
// It also closes an older weakness: the previous forward key was an unkeyed
// sha256 of tenant, namespace and value, so anyone with read access to the
// cache could confirm a guessed phone number by computing that digest and
// checking whether the key existed — an existence oracle requiring no
// decryption. Under HMAC the key cannot be computed without the tenant key,
// which lives in the keyring rather than the cache.
func (s *CacheTokenStore) deriveToken(k TokenKey, value string) (string, error) {
	tk, err := s.keyring.Key(k.Tenant)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, tk)
	// 分隔符是命名空间字符集禁止的字节，因此任何两个不同的
	// (命名空间, 原值) 都不可能产出同一段输入。
	// The separator is a byte the namespace charset forbids, so no two distinct
	// (namespace, value) pairs can produce the same input.
	mac.Write([]byte(k.Namespace))
	mac.Write([]byte{0})
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil)[:16]), nil
}

// tokenKey is the reverse-lookup key.
// 是反向查找键。
func (s *CacheTokenStore) tokenKey(k TokenKey, token string) string {
	return s.tenantPrefix(k.Tenant) + k.Namespace + ":t:" + token
}

// Issue implements TokenStore.
//
// # 一次调用，因此没有可观察的中间态
// # One call, therefore no observable intermediate state
//
// 令牌由 deriveToken 从原值确定性算出，映射由 Cache.FindOrCreate 一步落定。
// 安全不变量因此不是靠顺序、补偿或进程内锁撑起来的：
//
//   - Issue 返回的令牌立即可 Resolve：FindOrCreate 返回的 current 就是此后
//     权威的那个值，不需要再补一次读去确认。
//   - 不存在「forward 存在而 reverse 不存在」：只有一个映射，没有第二个键。
//   - 并发签发线性化：各方算出同一个令牌，FindOrCreate 保证恰好一个创建、
//     其余拿到同一个 current。
//   - 崩溃与超时：单次调用要么发生要么没发生；超时含义不明时，下一次调用
//     算出同一个令牌，FindOrCreate 要么创建要么返回已有的。
//   - 不依赖进程内 mutex，也没有第二步可回滚。
//
// Tokens are derived from the value and the mapping lands in one call. The
// invariants rest on neither ordering, compensation, nor an in-process lock.
func (s *CacheTokenStore) Issue(ctx context.Context, key TokenKey, value string) (string, error) {
	if err := key.Validate(); err != nil {
		return "", err
	}
	tok, err := s.deriveToken(key, value)
	if err != nil {
		return "", err
	}

	current, _, err := s.cache.FindOrCreate(ctx, s.tokenKey(key, tok), value, s.ttl)
	if err != nil {
		return "", fmt.Errorf("%w: 签发令牌失败 / issuing token: %v", ErrTokenStore, err)
	}

	// 键已存在时，按派生方式它必然映射到同一个原值。这里核对而不是假定。
	//
	// 不符只可能出于两件事——HMAC 碰撞（可忽略），或者两套不同的密钥环写进了
	// 同一个缓存前缀（配置错误）。后者会让一个租户的令牌解析出另一份数据，
	// 必须响亮地失败，不能沉默地返回。
	//
	// 核对现在是纯本地比较：FindOrCreate 已经把权威值带回来了，不再需要
	// 一次额外的读，因此这条检查也不再有自己的过期窗口。
	//
	// A mismatch means either an HMAC collision (negligible) or two keyrings
	// under one cache prefix (misconfiguration) — the latter would resolve one
	// tenant's token to another's data and must fail loudly. The check is now a
	// local comparison: FindOrCreate already returned the authoritative value,
	// so it no longer carries an expiry window of its own.
	if current != value {
		return "", fmt.Errorf(
			"%w: 令牌 %s 已映射到另一个值——同一前缀下混用了不同的密钥环，"+
				"继续下去会让一个租户的令牌解析出另一份数据 / token collision",
			ErrTokenStore, tok)
	}
	return tok, nil
}

// Resolve implements TokenStore.
func (s *CacheTokenStore) Resolve(ctx context.Context, key TokenKey, token string) (string, bool, error) {
	if err := key.Validate(); err != nil {
		return "", false, err
	}
	v, ok, err := s.cache.Get(ctx, s.tokenKey(key, token))
	if err != nil {
		return "", false, fmt.Errorf("%w: 解析令牌失败 / resolving token: %v", ErrTokenStore, err)
	}
	return v, ok, nil
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
	return &SQLTokenStore{db: db, keyring: keyring, table: table, ttl: ttl}, nil
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

// seal encrypts a value under the tenant's key.
// 用租户密钥加密一个值。
func (s *SQLTokenStore) seal(tenant Tenant, value string) ([]byte, error) {
	k, err := s.keyring.Key(tenant)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(k)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("%w: 生成 nonce 失败 / generating nonce: %v", ErrTokenStore, err)
	}
	// The tenant is authenticated additional data: a ciphertext row moved to
	// another tenant's rows then fails to open rather than decrypting cleanly.
	// 租户作为附加认证数据：一行密文被挪到另一个租户名下时会解不开，
	// 而不是干干净净地解密出来。
	return gcm.Seal(nonce, nonce, []byte(value), []byte(tenant)), nil
}

// open decrypts a value.
// 解密一个值。
func (s *SQLTokenStore) open(tenant Tenant, cipherText []byte) (string, error) {
	k, err := s.keyring.Key(tenant)
	if err != nil {
		return "", err
	}
	gcm, err := newGCM(k)
	if err != nil {
		return "", err
	}
	if len(cipherText) < gcm.NonceSize() {
		return "", fmt.Errorf("%w: 密文过短 / ciphertext too short", ErrTokenStore)
	}
	nonce, body := cipherText[:gcm.NonceSize()], cipherText[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, body, []byte(tenant))
	if err != nil {
		return "", fmt.Errorf("%w: 解密失败 / decryption failed: %v", ErrTokenStore, err)
	}
	return string(plain), nil
}

// newGCM builds an AES-GCM cipher.
// 构造 AES-GCM。
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: 构造分组密码失败 / building cipher: %v", ErrTokenStore, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: 构造 GCM 失败 / building GCM: %v", ErrTokenStore, err)
	}
	return gcm, nil
}

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
	sealed, err := s.seal(key.Tenant, value)
	if err != nil {
		return "", err
	}
	var expires any
	if s.ttl > 0 {
		expires = time.Now().Add(s.ttl).Unix()
	}

	if _, err := s.db.ExecContext(ctx, fmt.Sprintf(
		`INSERT INTO %s (tenant_id, namespace, token, value_digest, value_cipher, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`, s.table),
		string(key.Tenant), key.Namespace, tok, dig, sealed, expires); err != nil {
		return "", fmt.Errorf("%w: 写入令牌失败 / storing token: %v", ErrTokenStore, err)
	}
	return tok, nil
}

// Resolve implements TokenStore.
func (s *SQLTokenStore) Resolve(ctx context.Context, key TokenKey, token string) (string, bool, error) {
	if err := key.Validate(); err != nil {
		return "", false, err
	}

	var sealed []byte
	row := s.db.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT value_cipher FROM %s WHERE tenant_id = ? AND namespace = ? AND token = ?
		   AND (expires_at IS NULL OR expires_at > ?)`, s.table),
		string(key.Tenant), key.Namespace, token, time.Now().Unix())
	switch err := row.Scan(&sealed); {
	case errors.Is(err, ErrSQLNoRows):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("%w: 解析令牌失败 / resolving token: %v", ErrTokenStore, err)
	}

	value, err := s.open(key.Tenant, sealed)
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
