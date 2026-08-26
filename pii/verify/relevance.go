package verify

import (
	"strings"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// Contextual relevance assessment (CAPID).
// 上下文感知相关性评估（CAPID）。
//
// # The problem it addresses
// # 它要解决的问题
//
// Redacting every detected entity is safe and sometimes useless. Ask "what is
// the postcode for 北京市朝阳区建国路" and mask the address, and the model
// receives "what is the postcode for ANONYMIZED_ADDRESS_0" — a question with no
// answer. The redaction succeeded; the product failed.
// 把检出的实体全部脱敏是安全的，有时也是无用的。问「北京市朝阳区建国路的邮编
// 是多少」并把地址遮掉，模型收到的是「ANONYMIZED_ADDRESS_0 的邮编是多少」——
// 一个无法回答的问题。脱敏成功了，产品失败了。
//
// # Why this must be the most conservative component in the system
// # 为什么这必须是整个系统里最保守的组件
//
// Every other stage errs toward redacting. This one is the only stage that can
// decide to *not* redact something already judged to be PII, which makes it the
// only place where a bug leaks data rather than degrading utility. The asymmetry
// is stark: an over-redaction produces a worse answer that someone notices
// immediately; an under-redaction produces a perfect answer and a silent breach.
// 其他每个阶段的偏向都是「宁可脱敏」。只有这一个阶段能决定**不脱敏**
// 一个已被判定为 PII 的东西，因此它是唯一一处 bug 会导致数据泄露、
// 而非仅仅降低可用性的地方。这个不对称非常尖锐：过度脱敏产生一个更差的答案，
// 有人立刻会注意到；脱敏不足产生一个完美的答案，和一次无声的泄露。
//
// The design therefore inverts the usual default. Nothing is preserved unless
// its type is explicitly enumerated as preservable *and* the surrounding text
// shows the entity is the subject of the question rather than an attribute of a
// person. Both conditions, never either alone.
// 因此设计上反转了通常的默认值。除非类型被显式列为可保留，**并且**
// 上下文显示该实体是问题的主体而非某人的属性，否则一律不保留。
// 两个条件同时成立，绝不接受其一。

// RelevanceDecision records why an entity was left in the clear.
// 记录某个实体为何被保留明文。
type RelevanceDecision struct {
	Entity detect.Entity

	// Evidence is the verbatim span showing the entity is being asked *about*
	// rather than being someone's attribute.
	// 是逐字截取的片段，显示该实体是被**询问的对象**而非某人的属性。
	Evidence string

	// Reason explains the evidence in one line.
	// 用一行解释证据。
	Reason string
}

// RelevancePolicy decides which entities may be preserved.
// 决定哪些实体可以被保留。
type RelevancePolicy struct {
	// Preservable lists the only types eligible. Identity-bearing types must
	// never appear here: a name, an ID number or a card number is never
	// "necessary for the answer" in a way that justifies sending it to a third
	// party — if the task genuinely needs them, the task belongs on the
	// self-hosted tier, not behind a redaction gateway.
	// 列出唯一可保留的类型。承载身份的类型绝不能出现在这里：
	// 姓名、身份证号、银行卡号从来不会「为了答案而必需」到足以正当化
	// 把它发给第三方——如果任务确实需要它们，那这个任务属于私有化部署那一档，
	// 而不该走脱敏网关。
	Preservable []detect.EntityType

	// SubjectMarkers are phrases indicating the entity is the topic of the
	// question. Their presence is necessary but not sufficient.
	// 是表明该实体是问题主题的短语。它们的出现是必要条件，但不是充分条件。
	SubjectMarkers []string

	// PossessiveMarkers are phrases indicating the entity belongs to a person.
	// Any one of them present vetoes preservation outright, because possession
	// is what makes a datum personal in the first place.
	// 是表明该实体归属于某个人的短语。其中任何一个出现都直接否决保留，
	// 因为「归属」正是一个数据成为个人数据的根本原因。
	PossessiveMarkers []string

	// Window is how many bytes on each side are examined.
	// 是左右各检查多少字节。
	Window int
}

// DefaultRelevancePolicy returns a deliberately narrow policy.
// 返回一个刻意收窄的策略。
//
// Only ADDRESS and ORG are preservable, and only when asked about directly.
// Everything that identifies a person is excluded by construction, not by rule
// tuning — so no amount of misconfiguration can widen it to cover names or
// government identifiers.
// 只有 ADDRESS 和 ORG 可保留，且仅限被直接询问时。
// 一切能识别到个人的类型在结构上就被排除，而非靠调规则排除——
// 因此再怎么配错也无法把它放宽到覆盖姓名或证件号。
func DefaultRelevancePolicy() *RelevancePolicy {
	return &RelevancePolicy{
		Preservable: []detect.EntityType{detect.TypeAddress, detect.TypeOrg},
		SubjectMarkers: []string{
			// The entity is what the question is about.
			// 实体本身是问题所问的对象。
			"怎么走", "怎么去", "邮编", "邮政编码", "在哪", "位于", "距离",
			"营业时间", "电话是多少", "介绍一下", "是什么公司", "属于哪",
			"how to get to", "directions to", "postcode", "zip code",
			"where is", "opening hours", "what company",
		},
		PossessiveMarkers: []string{
			// The entity belongs to someone — this is exactly what makes it PII.
			// 实体归属于某人——这正是它成为 PII 的原因。
			"住址", "家住", "住在", "居住", "户籍", "的地址", "的住所",
			"收货地址", "联系地址", "身份证", "客户", "患者", "员工",
			"lives at", "resides at", "home address", "his address",
			"her address", "customer", "patient", "employee",
		},
		Window: 64,
	}
}

// Assess decides whether an entity may be preserved in the clear.
// 判断某个实体是否可以保留明文。
//
// Returns preserve=false in every uncertain case. Uncertainty here means
// "redact", because the failure mode of the alternative is a silent leak.
// 任何不确定的情况都返回 preserve=false。这里的不确定意味着「脱敏」，
// 因为相反选择的失败模式是一次无声的泄露。
func (p *RelevancePolicy) Assess(text string, e detect.Entity) (RelevanceDecision, bool) {
	if !p.isPreservableType(e.Type) {
		return RelevanceDecision{}, false
	}

	window, lo := p.contextWindow(text, e)
	lower := strings.ToLower(window)

	// A possessive marker vetoes outright, and is checked first so that a
	// sentence containing both — "他家住建国路，怎么走" — resolves to redact.
	// 归属标记直接否决，且优先检查，使得同时含两者的句子——
	//「他家住建国路，怎么走」——判定为脱敏。
	for _, marker := range p.PossessiveMarkers {
		if idx := strings.Index(lower, strings.ToLower(marker)); idx >= 0 {
			return RelevanceDecision{}, false
		}
	}

	for _, marker := range p.SubjectMarkers {
		idx := strings.Index(lower, strings.ToLower(marker))
		if idx < 0 {
			continue
		}
		// Report the evidence at its true offset in the source, not in the
		// window, so a reviewer lands on the right text.
		// 按证据在原文中的真实偏移上报，而非窗口内偏移，
		// 这样评审者才会落在正确的文本上。
		start := lo + idx
		end := start + len(marker)
		if end > len(text) {
			end = len(text)
		}
		return RelevanceDecision{
			Entity:   e,
			Evidence: text[start:end],
			Reason: "实体是问题的主体而非某人的属性，脱敏会让问题无法回答 / " +
				"entity is the subject of the question, not a person's attribute; " +
				"redacting it leaves the question unanswerable",
		}, true
	}

	return RelevanceDecision{}, false
}

// isPreservableType reports whether the type is eligible at all.
// 判断该类型是否有资格被保留。
func (p *RelevancePolicy) isPreservableType(t detect.EntityType) bool {
	for _, allowed := range p.Preservable {
		if t == allowed {
			return true
		}
	}
	return false
}

// contextWindow returns the surrounding text and its start offset, snapped to
// rune boundaries so a window edge cannot split a multi-byte character.
// 返回周围文本及其起始偏移，对齐到字符边界，避免窗口边缘切开多字节字符。
func (p *RelevancePolicy) contextWindow(text string, e detect.Entity) (string, int) {
	w := p.Window
	if w <= 0 {
		w = 64
	}
	lo := e.Start - w
	if lo < 0 {
		lo = 0
	}
	hi := e.End + w
	if hi > len(text) {
		hi = len(text)
	}
	for lo > 0 && text[lo]&0xC0 == 0x80 {
		lo--
	}
	for hi < len(text) && text[hi]&0xC0 == 0x80 {
		hi++
	}
	return text[lo:hi], lo
}
