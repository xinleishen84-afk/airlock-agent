package anonymize

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TokenRecord 是令牌映射的唯一逻辑事实。
//
// # 一条记录，不是两条
// # One record, not two
//
// 这个类型存在的意义之一是把「后端可以自己决定 value 里放什么」这件事关掉。
// 旧的 Cache 后端把原值直接当 value 写进去，SQL 后端另有自己的一套列——
// 两个后端对「一条令牌映射到底是什么」各有一份定义，于是任何一条不变量都要
// 分别论证两遍。
//
// 更要紧的是它不能退回成两条记录。曾经的 Cache 后端写「值摘要 → 令牌」与
// 「令牌 → 原值」两个键，两条记录互为对方的前提，而分布式缓存不保证它们
// 同生共死：写失败、崩溃、各自被驱逐，都会留下一半。撕裂的后果不落在失败的
// 那次调用上，落在之后每一次上。
//
// One reason this type exists is to stop each backend deciding for itself what
// a value holds. More importantly it must not decay back into two records: the
// cache backend once wrote a digest-to-token key and a token-to-value key that
// were each other's premise, while nothing made a distributed cache keep them
// alive together.
//
// # 为什么密钥版本与身份 epoch 要存进记录
// # Why the key version and identity epoch are stored
//
// 存了才能在轮换之后还解得开旧记录：Resolve 读到 key_version=v1 就派生 v1
// 的密钥，而不是拿当前的 v2 去撞。不存就只能假设「所有记录都用当前密钥」，
// 那等于宣布轮换即数据丢失。
//
// 两者同时进 AAD，因此改字段就解不开：把 v1 的记录标成 v2 不会让它降级到
// 一把已知的弱密钥，只会认证失败。
//
// Stored so a rotation does not orphan old records: Resolve derives the version
// the record names rather than assuming the current one, which would make
// rotation equivalent to data loss. Both also enter the AAD, so relabelling a
// v1 record as v2 fails authentication instead of downgrading it.
type TokenRecord struct {
	// KeyVersion 是加密本条记录所用的数据密钥版本。
	KeyVersion DataKeyVersion

	// IdentityEpoch 是签发本条记录时的令牌身份 epoch。
	IdentityEpoch TokenIdentityEpoch

	// Nonce 是 AEAD 的随机数。它只服务于加密，绝不参与令牌身份的计算。
	// Serves encryption only and never participates in token identity.
	Nonce []byte

	// Ciphertext 是原值的密文。后端里不存在原值的任何明文副本。
	// The value's ciphertext. No plaintext copy exists in any backend.
	Ciphertext []byte

	// ExpiresAt 是记录的到期时刻；零值表示不过期。
	//
	// 记录里存一份，是为了让「后端 TTL」与「记录语义」不必互相信任：
	// 后端把键留久了，Resolve 仍按记录里的时刻判过期。
	//
	// Recorded so backend TTL and record semantics need not trust each other:
	// if the backend keeps a key longer than intended, Resolve still expires it.
	ExpiresAt time.Time
}

// labelPattern 限定密钥版本与身份 epoch 的字符集。
//
// # 为什么这个校验必须存在
// # Why this validation must exist
//
// 记录用 "." 分隔字段。版本号里带一个点——`v1.2` 这种完全合理的写法——
// 会让编码出来的记录多出一段，解码时报「字段数为 7，期望 6」。那句错误指向
// 记录格式，而真正的原因在几百行之外的一个构造参数上，排查会从错误的一端开始。
//
// 与命名空间同理：一个会被拼进结构化文本的标识符，它的字符集是那段文本能否
// 被正确切分的前提，因此校验属于接受它的地方，而不是使用它的地方。
//
// The record is delimited by ".". A version like `v1.2` — an entirely
// reasonable spelling — adds a field and decoding reports "7 fields, expected
// 6", pointing at the record format while the cause sits in a constructor
// argument hundreds of lines away. Validation belongs where the identifier is
// accepted, not where it is used.
var labelPattern = regexp.MustCompile(`^[a-z0-9_-]{1,16}$`)

// validateLabel 校验密钥版本或身份 epoch。
func validateLabel(kind, label string) error {
	if !labelPattern.MatchString(label) {
		return fmt.Errorf(
			"%w: %s %q 非法：只允许小写字母、数字、下划线与短横，最长 16——"+
				"它会被拼进以「.」分隔的记录，带分隔符的标识符会让记录多出一段字段 / "+
				"invalid %s", ErrTokenStore, kind, label, kind)
	}
	return nil
}

// recordSchema 是编码格式的版本号。
//
// 放在最前面，是为了让格式变更能被识别而不是被误读。没有它的话，
// 一条新格式记录被旧代码读到，会按旧布局切分字段——切出来的东西仍然是
// 「合法的」字节，只是含义全错，而 AEAD 认证失败给出的信息只会是
// 「解不开」，指不到真正的原因。
//
// A format marker so a change is recognized rather than misread: without it,
// old code slicing a new record by the old layout gets bytes that are still
// "valid" and entirely wrong, while the AEAD failure only reports that it
// could not open.
const recordSchema = "atr1"

// Encode 把记录序列化成可存进任意 KV 后端的字符串。
//
// 用带分隔符的文本而不是 JSON：这条记录会被写进缓存的 value，而缓存的运维
// 工具、慢查询日志、监控面板都会把它照原样显示出来。文本格式让人一眼看出
// 「这里没有明文」，JSON 则会让人下意识去找一个 value 字段。
//
// A delimited text form rather than JSON: this lands in a cache value that
// operational tools display verbatim, and the text form makes the absence of
// plaintext visible at a glance.
func (r TokenRecord) Encode() string {
	var exp int64
	if !r.ExpiresAt.IsZero() {
		exp = r.ExpiresAt.Unix()
	}
	return strings.Join([]string{
		recordSchema,
		string(r.KeyVersion),
		string(r.IdentityEpoch),
		base64.RawStdEncoding.EncodeToString(r.Nonce),
		base64.RawStdEncoding.EncodeToString(r.Ciphertext),
		strconv.FormatInt(exp, 10),
	}, ".")
}

// DecodeTokenRecord 解析记录。
//
// 解析失败一律报错，不做任何「尽力而为」的兜底：一条读不懂的记录意味着
// 格式漂移或数据损坏，此时返回一个部分填充的记录，会让上层拿着半个记录
// 继续走下去。
//
// Any parse failure is an error with no best-effort fallback: an unreadable
// record means format drift or corruption, and returning a partly-filled one
// would let the caller proceed with half a record.
func DecodeTokenRecord(raw string) (TokenRecord, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 6 {
		return TokenRecord{}, fmt.Errorf(
			"%w: 令牌记录字段数为 %d，期望 6 / malformed token record",
			ErrTokenStore, len(parts))
	}
	if parts[0] != recordSchema {
		return TokenRecord{}, fmt.Errorf(
			"%w: 令牌记录格式为 %q，本版本只认 %q——"+
				"按旧布局去切分新格式会切出含义全错的字段 / unknown record schema",
			ErrTokenStore, parts[0], recordSchema)
	}
	nonce, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return TokenRecord{}, fmt.Errorf("%w: nonce 解码失败 / decoding nonce: %v",
			ErrTokenStore, err)
	}
	ct, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return TokenRecord{}, fmt.Errorf("%w: 密文解码失败 / decoding ciphertext: %v",
			ErrTokenStore, err)
	}
	exp, err := strconv.ParseInt(parts[5], 10, 64)
	if err != nil {
		return TokenRecord{}, fmt.Errorf("%w: 到期时刻解码失败 / decoding expiry: %v",
			ErrTokenStore, err)
	}
	rec := TokenRecord{
		KeyVersion:    DataKeyVersion(parts[1]),
		IdentityEpoch: TokenIdentityEpoch(parts[2]),
		Nonce:         nonce,
		Ciphertext:    ct,
	}
	if exp != 0 {
		rec.ExpiresAt = time.Unix(exp, 0)
	}
	return rec, nil
}

// Expired 判断记录是否已过期。
func (r TokenRecord) Expired(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt)
}
