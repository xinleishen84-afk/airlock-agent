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
	return nil
}

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

	// SetNX stores a value only if the key is absent, reporting whether it
	// stored. TTL of zero means no expiry.
	// 仅当键不存在时写入，并报告是否写入。ttl 为 0 表示不过期。
	//
	// Set-if-absent rather than Set: two gateway replicas tokenizing the same
	// value at the same moment must converge on one token, and a plain Set
	// lets the later writer overwrite the token the earlier one already
	// returned to a caller.
	// 用「不存在才写」而非「直接写」：两个网关副本同时令牌化同一个值时
	// 必须收敛到同一个令牌，而直接写会让后写者覆盖掉先写者已经返回给
	// 调用方的那个令牌。
	SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error)

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
	cache  Cache
	ttl    time.Duration
	prefix string
}

// NewCacheTokenStore builds a cache-backed token store.
// 构造基于缓存的令牌库。
//
// keyPrefix namespaces this store's keys inside a shared cache.
// keyPrefix 在共享缓存中为本库的键划出命名空间。
func NewCacheTokenStore(c Cache, ttl time.Duration, keyPrefix string) (*CacheTokenStore, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: 缓存驱动不能为空 / cache is required", ErrTokenStore)
	}
	if keyPrefix == "" {
		keyPrefix = "airlock:tok:"
	}
	return &CacheTokenStore{cache: c, ttl: ttl, prefix: keyPrefix}, nil
}

// tenantPrefix is the key prefix covering one tenant.
// 是覆盖单个租户的键前缀。
func (s *CacheTokenStore) tenantPrefix(t Tenant) string {
	return s.prefix + string(t) + ":"
}

// valueKey is the forward-lookup key, keyed by a digest rather than the value.
// 是正向查找键，以摘要而非原值作键。
//
// The raw value must never appear in a cache key: keys show up in slow-query
// logs, in monitoring dashboards, in KEYS output during an incident. A digest
// keeps the lookup working while keeping the PII out of every one of those.
// 原值绝不能出现在缓存键里：键会出现在慢查询日志、监控面板，
// 以及事故期间某人敲下的 KEYS 输出中。
// 用摘要既保住了查找，又让 PII 不出现在上述任何一处。
func (s *CacheTokenStore) valueKey(k TokenKey, value string) string {
	sum := sha256.Sum256([]byte(k.composite() + "\x00" + value))
	return s.tenantPrefix(k.Tenant) + k.Namespace + ":v:" + hex.EncodeToString(sum[:])
}

// tokenKey is the reverse-lookup key.
// 是反向查找键。
func (s *CacheTokenStore) tokenKey(k TokenKey, token string) string {
	return s.tenantPrefix(k.Tenant) + k.Namespace + ":t:" + token
}

// Issue implements TokenStore.
func (s *CacheTokenStore) Issue(ctx context.Context, key TokenKey, value string) (string, error) {
	if err := key.Validate(); err != nil {
		return "", err
	}
	vk := s.valueKey(key, value)

	if tok, ok, err := s.cache.Get(ctx, vk); err != nil {
		return "", fmt.Errorf("%w: 查询令牌失败 / looking up token: %v", ErrTokenStore, err)
	} else if ok {
		return tok, nil
	}

	tok, err := newToken()
	if err != nil {
		return "", err
	}

	// Forward mapping first, set-if-absent: whoever wins this race defines the
	// token, and the loser adopts it. Writing the reverse mapping first would
	// leave an orphan token→value entry behind on every lost race.
	// 先写正向映射，且「不存在才写」：竞争的胜者定义令牌，败者采纳它。
	// 先写反向映射会让每一次竞争失败都留下一条孤儿的「令牌→原值」记录。
	stored, err := s.cache.SetNX(ctx, vk, tok, s.ttl)
	if err != nil {
		return "", fmt.Errorf("%w: 写入令牌失败 / storing token: %v", ErrTokenStore, err)
	}
	if !stored {
		winner, ok, err := s.cache.Get(ctx, vk)
		if err != nil {
			return "", fmt.Errorf("%w: 读取竞争结果失败 / reading race winner: %v", ErrTokenStore, err)
		}
		if !ok {
			// Set-if-absent refused and the key is gone: it expired between the
			// two calls. Reporting an error beats returning a token nothing
			// can resolve.
			// 「不存在才写」被拒、键又不在了：它在两次调用之间过期了。
			// 报错好过返回一个谁也解析不了的令牌。
			return "", fmt.Errorf("%w: 令牌在写入竞争中过期，请重试 / token expired mid-race",
				ErrTokenStore)
		}
		return winner, nil
	}

	if _, err := s.cache.SetNX(ctx, s.tokenKey(key, tok), value, s.ttl); err != nil {
		return "", fmt.Errorf("%w: 写入反向映射失败 / storing reverse mapping: %v", ErrTokenStore, err)
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
