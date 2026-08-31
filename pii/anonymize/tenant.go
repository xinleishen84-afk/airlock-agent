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
// # 这段曾经写着「令牌不需要这个：它们是随机的」
// # This paragraph used to say tokens did not need it because they are random
//
// 那个说法对 SQLTokenStore 仍然成立——它的令牌是随机生成后存下来的。
// 但 CacheTokenStore 的令牌改成了确定性派生，随机性没了，跨租户不可关联
// 这件事就完全落在密钥上：同一个手机号在两个租户下算出不同的令牌，
// 靠的是两把在计算上不可关联的租户密钥，而不是靠随机数。
//
// That remains true of SQLTokenStore, whose tokens are generated randomly and
// stored. CacheTokenStore derives its tokens deterministically, so
// cross-tenant unlinkability rests entirely on the keys: the same phone number
// yields different tokens in two tenants because their keys are
// computationally unlinkable, not because a random number was drawn.
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

// ---------------------------------------------------------------------------
// Purpose-separated subkeys / 按用途分离的子密钥
// ---------------------------------------------------------------------------

// TokenIdentityEpoch 标识一代令牌身份密钥。
//
// # 为什么必须有这个概念，而不能承诺「令牌永远稳定」
// # Why this exists rather than a promise that tokens are stable forever
//
// 派生式令牌的身份来自 K_token，而 K_token 派生自根密钥。根密钥一旦轮换，
// 同一个 (租户, 命名空间, 原值) 会算出不同的令牌——这不是缺陷，是派生的
// 定义决定的。承诺「令牌永远稳定」是做不到的，因此这里把它明确成一个有
// 边界的承诺：**令牌身份在一个 epoch 内稳定，根密钥轮换即开启新 epoch。**
//
// 数据密钥的轮换不受此影响：K_data 版本化，与 K_token 各走各的。
// 也就是说，日常的数据密钥轮换不会动令牌身份；只有根密钥轮换才会。
//
// epoch 记进 TokenRecord 并参与 AAD，因此上一代 epoch 的密文无法在新 epoch
// 下通过认证——不会出现「解出来了但语义已经变了」这种最难查的情形。
//
// A derived token's identity comes from K_token, itself derived from the root.
// Rotating the root changes every token: that is what derivation means, not a
// defect. Promising indefinite stability would be false, so the promise is
// bounded instead — identity is stable within an epoch, and rotating the root
// begins a new one. Data-key rotation is independent and does not touch
// identity. The epoch is recorded and bound into the AAD, so a previous
// epoch's ciphertext fails authentication rather than opening with stale
// semantics.
type TokenIdentityEpoch string

// DataKeyVersion 标识一代数据加密密钥。
//
// 版本只出现在 HKDF 的 info 串里，因此新增一个版本不需要新的密钥材料，
// 也不需要任何迁移动作——旧记录带着自己的版本号，Resolve 时按号派生。
//
// 要写清它保护的是什么：版本化让「某个版本的派生密钥泄漏」不牵连其他版本，
// 但根密钥泄漏时所有版本一起失效。真正需要抵抗根密钥泄漏的部署，
// 应当轮换根密钥——那同时会开启新的令牌身份 epoch。
//
// The version appears only in the HKDF info string, so adding one needs no new
// key material and no migration: an old record carries its own version and
// Resolve derives that one. What versioning buys is containment of a single
// derived key's compromise; a root compromise invalidates every version, and a
// deployment that must survive that should rotate the root — which also begins
// a new token identity epoch.
type DataKeyVersion string

const (
	// DefaultTokenIdentityEpoch 是首代令牌身份 epoch。
	DefaultTokenIdentityEpoch TokenIdentityEpoch = "e1"

	// DefaultDataKeyVersion 是首代数据加密密钥版本。
	DefaultDataKeyVersion DataKeyVersion = "v1"
)

// TokenIdentityKey 派生 K_token：只用于 HMAC 计算令牌身份。
//
// # 为什么不能与数据密钥共用一把
// # Why this cannot be the same key as the data key
//
// 同一把密钥既当 HMAC 密钥又当 AES-GCM 密钥，是把两套代数结构绑在同一份
// 密钥材料上。这类复用没有安全证明可依，而分开的成本只是 HKDF info 串里
// 多一段常量。本仓库此前正是这样：Keyring.Key(tenant) 一把密钥同时用于
// 令牌 HMAC、值摘要 HMAC、AES-GCM 加解密、哈希算子与审计指纹。
//
// Using one key as both an HMAC key and an AES-GCM key ties two algebraic
// structures to the same material with no security proof to lean on, while
// separating them costs one constant in an HKDF info string. This repository
// did exactly that: a single per-tenant key served token HMAC, digest HMAC,
// AES-GCM, the hash operator and audit fingerprints.
func (k *Keyring) TokenIdentityKey(t Tenant, epoch TokenIdentityEpoch) ([]byte, error) {
	if epoch == "" {
		return nil, fmt.Errorf("令牌身份 epoch 不能为空 / identity epoch is required")
	}
	return k.derive("airlock/token-identity/"+string(epoch)+"/"+string(t), t)
}

// DataKey 派生 K_data_vN：只用于 AEAD 加解密 PII。
func (k *Keyring) DataKey(t Tenant, version DataKeyVersion) ([]byte, error) {
	if version == "" {
		return nil, fmt.Errorf("数据密钥版本不能为空 / data key version is required")
	}
	return k.derive("airlock/token-data/"+string(version)+"/"+string(t), t)
}

// derive 是按 info 串派生子密钥的共用路径。
//
// 不走 Key() 的缓存：那份缓存以租户为键，而这里同一个租户会有多把不同用途、
// 不同版本的子密钥。派生是一次 HKDF，几微秒，不值得为它引入一个更复杂的
// 缓存键去换——而一个键设计错了的缓存，会把两把不同的密钥混成一把。
//
// Not routed through Key()'s cache, which is keyed by tenant alone while a
// tenant now has several subkeys of different purposes and versions. One HKDF
// is microseconds; a miskeyed cache would conflate two distinct keys.
func (k *Keyring) derive(info string, t Tenant) ([]byte, error) {
	if err := ValidateTenant(t); err != nil {
		return nil, err
	}
	out, err := hkdf.Key(sha256.New, k.root, k.salt, info, 32)
	if err != nil {
		return nil, fmt.Errorf("派生子密钥失败 / deriving subkey: %w", err)
	}
	return out, nil
}
