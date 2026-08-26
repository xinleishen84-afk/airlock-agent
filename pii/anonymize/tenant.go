package anonymize

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"regexp"
	"sync"
)

// # Tenants
// # 租户
//
// Every reversible construct in this package is a lookup: a placeholder or a
// token goes in, a real value comes out. A lookup with no tenant in its key is
// an IDOR by construction — whoever holds the opaque string gets the value,
// and opaque strings travel: through logs, through a model's response, through
// a support ticket someone pasted.
// 本包中每一个可逆构造都是一次查表：进去一个占位符或令牌，出来一个真实值。
// 键里没有租户的查表，在构造上就是一个越权漏洞——谁拿到那串不透明字符
// 谁就拿到值，而不透明字符是会流传的：流经日志、流经模型的回复、
// 流经某人粘进工单的那段文本。
//
// So the tenant is part of the key, not a filter applied afterwards. A filter
// can be forgotten at one call site; a key cannot.
// 因此租户是键的一部分，而不是事后施加的过滤。
// 过滤可能在某一个调用点被忘掉，键不会。

// Tenant identifies an isolation boundary.
// 标识一个隔离边界。
type Tenant string

// tenantPattern constrains tenant identifiers.
// 约束租户标识符。
//
// The charset matters because tenant IDs become part of composite keys and of
// key-derivation info strings. A tenant allowed to contain the separator byte
// could construct an ID that collides with another tenant's key — "a\x00b"
// against tenant "a" with namespace "b".
// 字符集是要紧的：租户 ID 会成为复合键与密钥派生 info 串的一部分。
// 允许租户 ID 含分隔字节，就等于允许它构造出与别的租户撞车的键——
// 「a\x00b」对上租户 "a" 加命名空间 "b"。
var tenantPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// ValidateTenant checks a tenant identifier.
// 校验租户标识符。
func ValidateTenant(t Tenant) error {
	if t == "" {
		return fmt.Errorf("租户标识不能为空——空租户会让所有调用方共用一个隔离域 / tenant is required")
	}
	if !tenantPattern.MatchString(string(t)) {
		return fmt.Errorf(
			"租户标识 %q 非法：只允许字母数字与 _.-，首字符须为字母数字，最长 64 / invalid tenant %q",
			t, t)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Per-tenant key derivation / 租户级密钥派生
// ---------------------------------------------------------------------------

// Keyring derives a per-tenant key from one root secret.
// 从单一根密钥派生每个租户的子密钥。
//
// # Why derivation rather than one key per tenant
// # 为什么用派生而不是每租户一把独立密钥
//
// Independent keys mean N secrets to mount, rotate and audit, and onboarding a
// tenant becomes a secret-management operation. Derivation keeps one root
// secret while giving each tenant a key that is computationally unlinkable to
// every other — rotating the root rotates all of them at once, which is the
// behaviour an incident actually wants.
// 独立密钥意味着有 N 份秘密要挂载、轮转和审计，
// 而新增一个租户会变成一次密钥管理操作。
// 派生只保留一份根密钥，同时让每个租户拿到一把与其他租户在计算上不可关联的
// 子密钥——轮转根密钥即一次性轮转全部，这正是事故处置真正想要的行为。
//
// # What this buys for the hash strategy
// # 它给哈希算子带来什么
//
// The hash operator is deterministic by design, so without per-tenant keys the
// same phone number produces the same digest in every tenant. Two tenants
// comparing warehouse exports could then confirm they share a customer —
// a cross-tenant disclosure neither of them consented to, made from data both
// of them believed was pseudonymized.
// 哈希算子按设计是确定性的，因此没有租户级密钥时，
// 同一个手机号在每个租户下都得到同一个摘要。
// 两个租户比对各自的数仓导出，就能确认他们共有一位客户——
// 这是一次谁都没同意的跨租户披露，而且是用双方都以为已经假名化的数据做到的。
//
// Tokens do not need this: they are random, so they are already unlinkable.
// The composite key is what protects them, not a salt.
// 令牌不需要这个：它们是随机的，本就不可关联。
// 保护它们的是复合键，而不是盐。
type Keyring struct {
	root []byte
	salt []byte

	mu     sync.RWMutex
	cached map[Tenant][]byte
}

// minRootKeyLen is the shortest root secret accepted.
// 是可接受的最短根密钥长度。
const minRootKeyLen = 32

// NewKeyring builds a keyring from a root secret.
// 用根密钥构造密钥环。
//
// salt may be empty; it is a deployment-wide domain separator, not a secret.
// salt 可以为空；它是部署级的域分隔符，不是秘密。
func NewKeyring(root, salt []byte) (*Keyring, error) {
	if len(root) < minRootKeyLen {
		return nil, fmt.Errorf(
			"根密钥至少 %d 字节，实际 %d——派生密钥的强度不会超过根密钥 / "+
				"root key must be >= %d bytes",
			minRootKeyLen, len(root), minRootKeyLen)
	}
	r := make([]byte, len(root))
	copy(r, root)
	s := make([]byte, len(salt))
	copy(s, salt)
	return &Keyring{root: r, salt: s, cached: map[Tenant][]byte{}}, nil
}

// Key returns the 32-byte key for one tenant.
// 返回某个租户的 32 字节密钥。
func (k *Keyring) Key(t Tenant) ([]byte, error) {
	if err := ValidateTenant(t); err != nil {
		return nil, err
	}

	k.mu.RLock()
	cached, ok := k.cached[t]
	k.mu.RUnlock()
	if ok {
		return cached, nil
	}

	// The info string carries a fixed prefix so that a future second use of
	// this keyring (a different purpose, same root) derives a disjoint key
	// space rather than colliding with tenant keys.
	// info 串带固定前缀，使本密钥环未来的第二种用途（同一根密钥、不同目的）
	// 派生出互不相交的密钥空间，而不是与租户密钥撞车。
	derived, err := hkdf.Key(sha256.New, k.root, k.salt, "airlock/tenant/"+string(t), 32)
	if err != nil {
		return nil, fmt.Errorf("派生租户密钥失败 / deriving tenant key: %w", err)
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	if existing, ok := k.cached[t]; ok {
		return existing, nil
	}
	k.cached[t] = derived
	return derived, nil
}
