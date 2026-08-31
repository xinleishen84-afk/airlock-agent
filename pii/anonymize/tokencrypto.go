package anonymize

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ---------------------------------------------------------------------------
// 令牌库共用的密码学原语
// Cryptographic primitives shared by the token stores
//
// 抽出来是因为 Cache 与 SQL 两个后端此前各写了一套：各自取密钥、各自建 GCM、
// 各自决定 AAD 里放什么。密码学代码写两遍的问题不是重复，是两遍会慢慢分岔
// ——而分岔的那一处不会报错，只会在某一天以「这份密文解不开」或者更糟的
// 「解开了但不该解开」的形式出现。
//
// Extracted because the two backends each had their own copy: their own key
// lookup, their own GCM construction, their own idea of what belongs in the
// AAD. Duplicated crypto does not stay duplicated — it diverges, and the
// divergence surfaces either as a ciphertext that will not open or, worse, as
// one that opens when it should not.
// ---------------------------------------------------------------------------

// aeadAAD 组装附加认证数据。
//
// # 哪几项是承重的，哪几项是纵深
// # Which fields carry weight and which are depth
//
// 数据密钥本身是按 (租户, 密钥版本) 派生的，因此这两项在 AAD 里其实**冗余**
// ——跨租户或跨版本的密文在拿到 AAD 之前就已经因为密钥不对而解不开。
// 实测：把它们从 AAD 里去掉，没有任何用例变红。
//
// 真正承重的是另外三项，因为密钥的派生里不含它们：
//
//	namespace  挡住把手机号的密文当成姓名的密文去解
//	token      挡住把 A 令牌的密文换到 B 令牌下——没有它，一个能写缓存的人
//	           可以让 B 解出 A 的原值
//	epoch      挡住上一代令牌身份的密文在新 epoch 下通过认证
//
// 冗余的两项仍然保留：它们的代价是几十字节，而收益是密钥派生一旦被改动
// （比如有人把 version 从 info 串里拿掉去「简化」），AAD 还在兜着。
// 但注释必须说清哪些是纵深、哪些是唯一防线——把冗余说成承重，会让后来人
// 以为动密钥派生是安全的。
//
// The data key is derived from (tenant, version), so those two are redundant
// here: a cross-tenant or cross-version ciphertext already fails on the key
// before the AAD is consulted. Measured — removing them turns no test red.
//
// The other three carry weight because the key derivation does not include
// them. The redundant pair is kept as depth: tens of bytes against the day
// someone "simplifies" the derivation. But the comment must say which is which,
// or a later reader will think changing the derivation is safe.
func aeadAAD(tenant Tenant, namespace, token string,
	version DataKeyVersion, epoch TokenIdentityEpoch) []byte {
	// 分隔符用命名空间与租户字符集都禁止的字节，
	// 因此任意两组不同的字段不可能拼出同一段 AAD。
	// The separator is forbidden in both charsets, so no two distinct field
	// sets can render the same AAD.
	const sep = "\x00"
	return []byte(string(tenant) + sep + namespace + sep + token + sep +
		string(version) + sep + string(epoch))
}

// sealValue 用数据密钥加密一个值，返回 nonce 与密文。
//
// nonce 与密文分开返回而不是拼在一起：TokenRecord 要把它们分别存字段，
// 拼起来再切开只会多一处「切错位置」的可能。
//
// Returned separately rather than concatenated because TokenRecord stores them
// as distinct fields; joining and re-splitting only adds a place to slice wrong.
func sealValue(dataKey []byte, plaintext string, aad []byte) (nonce, ciphertext []byte, err error) {
	gcm, err := newGCM(dataKey)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("%w: 生成 nonce 失败 / generating nonce: %v",
			ErrTokenStore, err)
	}
	return nonce, gcm.Seal(nil, nonce, []byte(plaintext), aad), nil
}

// openValue 解密并验证。AAD 或密文任一被改动都会在这里失败。
func openValue(dataKey, nonce, ciphertext, aad []byte) (string, error) {
	gcm, err := newGCM(dataKey)
	if err != nil {
		return "", err
	}
	if len(nonce) != gcm.NonceSize() {
		return "", fmt.Errorf("%w: nonce 长度 %d 不符 / bad nonce length",
			ErrTokenStore, len(nonce))
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		// 不要把底层错误原样带出：它对区分「密文被改」与「AAD 不匹配」没有
		// 帮助，却可能被当成预言机。两种情况对调用方是同一件事——这份记录
		// 不可信。
		//
		// The underlying error does not distinguish tampered ciphertext from a
		// mismatched AAD and could serve as an oracle. Both mean the same thing
		// to the caller: this record cannot be trusted.
		return "", fmt.Errorf("%w: 认证解密失败——密文、AAD、租户、命名空间、"+
			"令牌、密钥版本或身份 epoch 中至少有一项与写入时不符 / "+
			"authenticated decryption failed", ErrTokenStore)
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

// deriveTokenIdentity 由 K_token 确定性地算出令牌身份。
//
// 输入里没有随机数，这是刻意的：令牌身份必须只由 (租户密钥, 命名空间, 原值)
// 决定，否则同一个值在两次调用、两个副本上会得到不同的令牌。加密用的随机
// nonce 走的是另一条路，不参与这里。
//
// No randomness participates: identity must be a function of the tenant key,
// namespace and value alone, or the same value would yield different tokens
// across calls and replicas. The random nonce used for encryption is on a
// separate path and never enters here.
func deriveTokenIdentity(identityKey []byte, namespace, value string) string {
	mac := hmac.New(sha256.New, identityKey)
	// 分隔符是命名空间字符集禁止的字节，因此任意两个不同的
	// (命名空间, 原值) 都不可能产出同一段输入。
	mac.Write([]byte(namespace))
	mac.Write([]byte{0})
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}
