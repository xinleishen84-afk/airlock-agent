// Package verify is the second stage: it re-examines ambiguous candidates from
// the extractor and decides KEEP or DROP with verbatim evidence.
// 是第二阶段：复查提取器给出的高歧义候选，并附原文证据给出 KEEP 或 DROP。
//
// # Why a second stage exists
// # 为什么需要第二阶段
//
// A single-stage extractor is cornered between two failure modes. Loosen it and
// recall rises but so does over-redaction, until the model receives a document
// so masked it can no longer answer. Tighten it and precision rises while real
// PII slips through. Neither knob escapes the trade-off, because the decision
// that would resolve it — *is this token PII in this sentence?* — needs evidence
// the extractor never looked at.
// 单阶段提取器被夹在两种失败模式之间。放松则召回上升、过度脱敏也上升，
// 直到模型收到一份糊到无法作答的文档；收紧则精确率上升、真实 PII 漏过。
// 调哪个旋钮都逃不出这个取舍，因为真正能解决它的判断——
// **这个词在这句话里是不是 PII**——依赖提取器从未看过的证据。
//
// Verification is that second look. It runs only on candidates the extractor
// itself marked ambiguous, so the cost lands where it changes outcomes.
// 验证就是那第二眼。它只跑在提取器自己标记为高歧义的候选上，
// 因此代价花在真正能改变结果的地方。
//
// # Evidence is mandatory, not decorative
// # 证据是强制的，不是装饰
//
// A verifier that returns only KEEP/DROP is unauditable: when it drops a real
// name, nothing explains why, and the failure is discovered by a breach rather
// than a review. Requiring a verbatim span from the source forces the decision
// to be grounded — and a verifier that cannot point at the text is treated as
// having failed, not as having decided.
// 只返回 KEEP/DROP 的验证器不可审计：它丢掉一个真实姓名时，没有任何东西
// 解释为什么，故障要靠泄露事件而非评审来发现。强制要求一段原文引用，
// 迫使决策必须有据可依——而指不出原文的验证器视为失败，而非视为已决策。
package verify

import (
	"fmt"
	"strings"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// Verdict is a verifier's decision on one candidate.
// 是验证器对一个候选的裁决。
type Verdict string

const (
	// VerdictKeep means the candidate really is PII and must be redacted.
	// 表示候选确实是 PII，必须脱敏。
	VerdictKeep Verdict = "KEEP"
	// VerdictDrop means the candidate is a false positive and must pass
	// through unchanged.
	// 表示候选是误报，应原样放行。
	VerdictDrop Verdict = "DROP"
	// VerdictUnknown means the verifier could not decide. It is never a silent
	// pass: the caller's fail-closed policy resolves it, because "the verifier
	// had no opinion" and "the verifier cleared it" are different facts.
	// 表示验证器无法判定。它绝不等于静默放行：由调用方的 fail-closed 策略裁决，
	// 因为「验证器没有意见」与「验证器判定无害」是两个不同的事实。
	VerdictUnknown Verdict = "UNKNOWN"
)

// Result is one verified candidate.
// 是一个已验证的候选。
type Result struct {
	Entity  detect.Entity
	Verdict Verdict

	// Evidence is a verbatim span copied from the source text that grounds the
	// verdict. It must appear in the source; a fabricated snippet invalidates
	// the whole decision.
	// 是从原文逐字截取、用以支撑裁决的片段。它必须在原文中出现；
	// 编造的片段会让整个决策作废。
	Evidence string

	// EvidenceStart / EvidenceEnd locate the evidence in the source, so a
	// reviewer can jump straight to it instead of searching.
	// 定位证据在原文中的位置，评审者可以直接跳过去而不必搜索。
	EvidenceStart int
	EvidenceEnd   int

	// Reason is a short human-readable rationale. It explains the evidence; it
	// does not replace it.
	// 是简短的人类可读理由。它解释证据，但不能取代证据。
	Reason string

	// Confidence is the verifier's own confidence, independent of the
	// extractor's.
	// 是验证器自身的置信度，与提取器的相互独立。
	Confidence float64
}

// Verifier re-examines ambiguous candidates.
// 复查高歧义候选。
type Verifier interface {
	// Name returns an identifier for audit.
	// 返回用于审计的标识。
	Name() string

	// Verify examines candidates in the context of the full source text.
	// Implementations must return one Result per input candidate, in order.
	// 在完整原文的语境下检查候选。实现必须按顺序为每个输入候选返回一个 Result。
	Verify(text string, candidates []detect.Entity) ([]Result, error)
}

// AmbiguityPolicy decides which candidates are worth a second look.
// 决定哪些候选值得第二眼。
//
// Verification costs a model call. Sending everything defeats the point of the
// hybrid split: an email that passed a syntactic check and a card number that
// passed Luhn are not ambiguous, and asking a model about them buys nothing
// while adding latency to the critical path.
// 验证要花一次模型调用。全部都送等于废掉混合分流的意义：
// 通过语法检查的邮箱、通过 Luhn 的卡号并不歧义，
// 拿去问模型换不来任何东西，只会给关键路径增加延迟。
type AmbiguityPolicy struct {
	// Types listed here are always verified. Addresses and organization names
	// are the canonical cases: whether a place name is PII depends entirely on
	// whether it is where someone lives or merely where something happened.
	// 列在此处的类型总是验证。地址和机构名是典型：
	// 一个地名是不是 PII，完全取决于它是某人的住处、还是仅仅是事件发生地。
	AlwaysVerify []detect.EntityType

	// ConfidenceBelow verifies any candidate whose extractor confidence falls
	// below this floor, regardless of type.
	// 无论类型，凡提取器置信度低于此下限的候选都验证。
	ConfidenceBelow float64

	// NeverVerify skips types that carry their own proof. A value that passed a
	// checksum has already been verified by mathematics; a model can only make
	// that worse.
	// 跳过自带证明的类型。通过校验和的值已经被数学验证过，模型只会让它变差。
	NeverVerify []detect.EntityType
}

// DefaultAmbiguityPolicy returns the policy implied by the hybrid split:
// checksum-backed types are never verified, context-dependent types always are.
// 返回混合分流所隐含的策略：带校验和的类型从不验证，上下文依赖的类型总是验证。
func DefaultAmbiguityPolicy() AmbiguityPolicy {
	return AmbiguityPolicy{
		AlwaysVerify: []detect.EntityType{
			detect.TypeAddress, detect.TypeOrg, detect.TypeName, detect.TypeAccount,
		},
		ConfidenceBelow: 0.75,
		NeverVerify: []detect.EntityType{
			// Every one of these is backed by a checksum or an unambiguous
			// syntactic shape. Mathematics already ruled; do not overrule it.
			// 以下每一类都有校验和或无歧义的语法形态支撑。
			// 数学已经裁定过了，不要推翻它。
			detect.TypeBankCard, detect.TypeIBAN, detect.TypeIDCard,
			detect.TypeUSCC, detect.TypeEmail, detect.TypeCredential,
		},
	}
}

// NeedsVerification reports whether a candidate warrants a second look.
// 判断某个候选是否值得第二眼。
func (p AmbiguityPolicy) NeedsVerification(e detect.Entity) bool {
	for _, t := range p.NeverVerify {
		if e.Type == t {
			return false
		}
	}
	for _, t := range p.AlwaysVerify {
		if e.Type == t {
			return true
		}
	}
	return p.ConfidenceBelow > 0 && e.Confidence < p.ConfidenceBelow
}

// Partition splits candidates into those needing verification and those that
// pass through untouched.
// 把候选分成需要验证的与直接放行的两组。
func (p AmbiguityPolicy) Partition(entities []detect.Entity) (verify, direct []detect.Entity) {
	for _, e := range entities {
		if p.NeedsVerification(e) {
			verify = append(verify, e)
		} else {
			direct = append(direct, e)
		}
	}
	return verify, direct
}

// ValidateEvidence checks that a verifier's evidence really came from the source.
// 检查验证器给出的证据确实来自原文。
//
// A verifier running on a language model can hallucinate a snippet that reads
// plausibly but appears nowhere in the input. Accepting it would make the audit
// trail fiction — and an audit trail nobody can trust is worse than none, because
// it is trusted anyway.
// 跑在语言模型上的验证器可能编造一段读起来合理、却在输入中根本不存在的片段。
// 接受它会让审计链条变成虚构——而一条无法信任的审计链比没有更糟，
// 因为人们照样会信任它。
func ValidateEvidence(text string, r *Result) error {
	if r.Verdict == VerdictUnknown {
		return nil // 无判定则无需证据 / no verdict, no evidence required
	}
	if strings.TrimSpace(r.Evidence) == "" {
		return fmt.Errorf("裁决 %s 缺少证据片段 / verdict %s has no evidence snippet",
			r.Verdict, r.Verdict)
	}
	idx := strings.Index(text, r.Evidence)
	if idx < 0 {
		return fmt.Errorf(
			"证据片段在原文中不存在（可能是模型编造）/ evidence snippet absent from source "+
				"(likely fabricated): %q", truncate(r.Evidence, 60))
	}
	// Trust the located position over any offsets the verifier reported: a
	// verifier written in another language may count characters where Go counts
	// bytes, and a wrong offset silently points a reviewer at the wrong text.
	// 以定位到的位置为准，不采信验证器自报的偏移：
	// 用其他语言写的验证器可能按字符计数而 Go 按字节计数，
	// 错误的偏移会静默地把评审者指向错误的文本。
	r.EvidenceStart = idx
	r.EvidenceEnd = idx + len(r.Evidence)
	return nil
}

// truncate shortens a string for error messages.
// 截短字符串以用于错误信息。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
