// Package audit emits GDPR-safe security events to a SIEM.
// 向 SIEM 发送符合 GDPR 的安全审计事件。
//
// # The second leak
// # 第二次泄露
//
// A redaction gateway that logs what it redacted has moved the PII, not removed
// it. The audit trail is worse than the original: the request body reaches one
// model provider under a contract, while the audit log is shipped to a SIEM,
// indexed, replicated to a cold tier, retained for the seven years a compliance
// team asked for, and readable by every on-call engineer with a Splunk seat.
// 一个把「自己脱敏了什么」记下来的脱敏网关，是把 PII 搬了个地方，不是移除了它。
// 而审计轨迹比原文更糟：请求体只在合同约束下抵达一家模型厂商，
// 审计日志却会被送进 SIEM、建索引、复制到冷存储、
// 按合规团队要的年限保留七年，并且对每一个有 Splunk 账号的值班工程师可读。
//
// # Why the guarantee is structural
// # 为什么这个保证是结构性的
//
// "Do not log the value" is a rule a person follows until the day they add a
// field for debugging. So the event type carries no field that can hold
// caller-controlled text: counts, enumerations, and one keyed fingerprint.
// There is a test that walks this struct by reflection and fails on any new
// field whose type could carry free text, which is the only version of this
// promise that survives the next contributor.
// 「不要记录原值」是一条人会遵守的规则——直到某天有人为了排查加了一个字段。
// 因此事件类型不含任何能装下调用方可控文本的字段：只有计数、枚举，
// 和一个带密钥的指纹。有一条用例用反射遍历这个结构体，
// 遇到任何「类型上可能装下自由文本」的新字段就失败——
// 这是这个承诺唯一能活过下一位贡献者的形态。
package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
)

// Schema identifies the event format. SIEM rules are written against a schema
// version, and changing the shape without changing this silently breaks them.
// 标识事件格式。SIEM 规则是按 schema 版本写的，
// 改了结构却不改这个版本号，会静默地把那些规则弄坏。
const Schema = "airlock.audit.v1"

// Action is what the gateway did.
// 是网关做了什么。
type Action string

const (
	ActionRedact  Action = "redact"       // 出站脱敏 / outbound redaction
	ActionRestore Action = "restore"      // 入站复原 / inbound restoration
	ActionErase   Action = "tenant_erase" // 租户擦除 / tenant erasure
	ActionBlock   Action = "block"        // fail-closed 阻断 / fail-closed block
)

// Outcome is how it ended.
// 是结果如何。
type Outcome string

const (
	OutcomeOK      Outcome = "ok"
	OutcomeBlocked Outcome = "blocked"
	OutcomeFailed  Outcome = "failed"
)

// ErrorClass is a stable, enumerated failure reason.
// 是稳定的、枚举化的失败原因。
//
// # Never err.Error()
// # 绝不使用 err.Error()
//
// This is the leak path that survives every careful review. Error strings are
// written for humans debugging, so they quote the thing that went wrong: a
// validator rejecting a value, a parser failing on a token, a store refusing a
// key. Any of those can put the value into the audit event through a field
// nobody thought of as a PII field.
// 这是每一次仔细评审都会漏过的泄露路径。错误信息是写给排查的人看的，
// 因此它们会引用出问题的那个东西：校验器拒掉的值、解析器卡住的 token、
// 存储拒绝的键。这些都能通过一个「没人把它当成 PII 字段」的字段，
// 把原值送进审计事件。
//
// So the event carries a class, and the class comes from a closed set. The full
// error text goes to the operator's own log, where it is a debugging aid under
// the operator's control rather than a record shipped to a shared index.
// 因此事件携带的是一个类别，而类别取自一个封闭集合。
// 完整的错误文本进运维自己的日志——在那里它是运维可控的排查素材，
// 而不是一条被送进共享索引的记录。
type ErrorClass string

const (
	ErrNone            ErrorClass = ""
	ErrDetectorFailure ErrorClass = "detector_failure"
	ErrStrategyFailure ErrorClass = "strategy_failure"
	ErrTokenStore      ErrorClass = "token_store_failure"
	ErrTenantUnknown   ErrorClass = "tenant_unresolved"
	ErrLeakDetected    ErrorClass = "residual_pii_detected"
	ErrPayloadInvalid  ErrorClass = "payload_invalid"
)

// Event is one security audit record.
// 是一条安全审计记录。
//
// Every field is a count, an enumeration, or a keyed fingerprint. Adding a
// field that can hold caller-controlled text fails TestEventCarriesNoFreeText.
// 每个字段都是计数、枚举或带密钥的指纹。
// 新增一个能装下调用方可控文本的字段会让 TestEventCarriesNoFreeText 失败。
type Event struct {
	Schema    string    `json:"schema"`
	EventID   string    `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`

	// Tenant is an organizational identifier, not personal data, and the SIEM
	// needs it to route and scope the event.
	// 是组织标识而非个人数据，SIEM 需要它来路由与限定事件范围。
	Tenant string `json:"tenant"`

	// SessionFingerprint is a keyed digest of the session identifier.
	// 是会话标识的带密钥摘要。
	//
	// Not the identifier itself. It is a caller-supplied string, and callers use
	// whatever they have: a UUID, an order number, or — routinely — the user's
	// email address as the conversation id. Logging it verbatim leaks PII
	// through a field nobody classified as one, on requests where the payload
	// was redacted perfectly.
	// 不是标识本身。它是调用方提供的字符串，而调用方会拿手边有的东西来用：
	// 一个 UUID、一个订单号，或者——很常见地——用用户的邮箱地址当会话 ID。
	// 原样记录它，会在一个没人把它归类为 PII 的字段上泄露 PII，
	// 而这些请求的载荷本身是脱敏得干干净净的。
	//
	// Keyed per tenant so fingerprints are neither linkable across tenants nor
	// brute-forceable back to the identifier.
	// 按租户加密钥，使指纹既不可跨租户关联，也无法被穷举回原标识。
	SessionFingerprint string `json:"session_fingerprint,omitempty"`

	Action  Action  `json:"action"`
	Outcome Outcome `json:"outcome"`

	// Destination is the configured flow name, which comes from the operator's
	// own configuration rather than from the request.
	// 是配置的链路名，来自运维自己的配置而非请求。
	Destination string `json:"destination,omitempty"`

	// Entities counts detections per entity type.
	// 按实体类型统计命中数。
	Entities map[string]int `json:"entities,omitempty"`

	// Strategies counts operator applications.
	// 统计各算子的使用次数。
	Strategies map[string]int `json:"strategies,omitempty"`

	// Recognizers counts hits per recognizer, so a rule that has stopped firing
	// is visible before someone notices the leak it was catching.
	// 按识别器统计命中数，使一条已经不再命中的规则，
	// 在有人注意到它本该拦住的泄露之前就先暴露出来。
	Recognizers map[string]int `json:"recognizers,omitempty"`

	// Restored counts placeholders and tokens turned back into values.
	// 统计被还原回原值的占位符与令牌数量。
	Restored int `json:"restored,omitempty"`

	// Phantom counts placeholders the model invented.
	// 统计模型凭空捏造的占位符数量。
	//
	// A count, not the strings. A phantom is whatever the model emitted in
	// placeholder shape, so its text is model-controlled — and a model that has
	// seen a name can emit ANONYMIZED_ZHANGWEI_0. Shipping those strings to the
	// SIEM would hand it exactly the fragments the redaction removed.
	// 只记数量，不记字符串。幻影是模型按占位符形态吐出来的任意内容，
	// 因此它的文本由模型控制——一个见过某个姓名的模型可以吐出
	// ANONYMIZED_ZHANGWEI_0。把这些字符串送进 SIEM，
	// 等于把脱敏刚刚移除的那些片段原样交了过去。
	Phantom int `json:"phantom,omitempty"`

	// SessionsErased and TokensErased evidence an Article 17 erasure.
	// 为 GDPR 第 17 条擦除提供证据。
	SessionsErased int `json:"sessions_erased,omitempty"`
	TokensErased   int `json:"tokens_erased,omitempty"`

	// ErrorClass is an enumerated reason, never the error text.
	// 是枚举化的原因，绝不是错误文本。
	ErrorClass ErrorClass `json:"error_class,omitempty"`

	// DurationMicros is how long the operation took.
	// 是本次操作的耗时（微秒）。
	DurationMicros int64 `json:"duration_micros,omitempty"`
}

// Fingerprinter turns a session identifier into a keyed digest.
// 把会话标识转成带密钥的摘要。
type Fingerprinter struct {
	keyring *anonymize.Keyring
}

// NewFingerprinter builds a fingerprinter over a keyring.
// 基于密钥环构造指纹器。
func NewFingerprinter(keyring *anonymize.Keyring) (*Fingerprinter, error) {
	if keyring == nil {
		return nil, fmt.Errorf(
			"审计指纹需要密钥环——没有密钥的摘要可被穷举回原标识，" +
				"而会话标识常常就是用户邮箱 / fingerprinting requires a keyring")
	}
	return &Fingerprinter{keyring: keyring}, nil
}

// Fingerprint returns a short keyed digest of a session identifier.
// 返回会话标识的短摘要。
func (f *Fingerprinter) Fingerprint(tenant anonymize.Tenant, session string) (string, error) {
	if session == "" {
		return "", nil
	}
	key, err := f.keyring.Key(tenant)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("session"))
	mac.Write([]byte{0})
	mac.Write([]byte(session))
	return hex.EncodeToString(mac.Sum(nil))[:16], nil
}

// NewEventID returns a random identifier for deduplication.
// 返回用于去重的随机标识。
func NewEventID() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		// A failed event id is not a reason to lose the event: the id exists
		// for deduplication, and a duplicate is better than a hole.
		// 生成不出 ID 不是丢事件的理由：ID 是为去重而存在的，
		// 而重复一条好过缺一条。
		return "unknown"
	}
	return hex.EncodeToString(raw)
}
