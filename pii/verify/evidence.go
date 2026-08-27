package verify

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// # 证据链验证
// # Evidence-chain validation
//
// 概率性抽取器有两种典型失败，它们的形状完全不同，因此不能用同一招去治：
//
// A probabilistic extractor fails in two shapes, which need different remedies:
//
//  1. 边界不全。模型给出「北京市」，而原文是「北京市海淀区中关村大街 1 号」。
//     值被检出了，但脱敏只盖住了开头几个字，剩下的照样出境。
//     Incomplete boundary: the model returns 北京市 while the text says
//     北京市海淀区中关村大街 1 号. The value was found, but redaction covers
//     only its head and the rest still leaves.
//
//  2. 无中生有。模型把源代码里的 retry(n 判成人名。脱敏管线会照办，
//     把代码改坏。
//     Fabrication: the model labels retry(n in source code as a person name,
//     and the pipeline dutifully rewrites the code.
//
// 两者都不是「模型再准一点」能解决的——它们是分布外输入上的必然行为。
// 能解决的是：在实体周围找**客观证据**，据此拉伸边界或否决判定。
//
// Neither is fixed by "a better model": both are what happens on
// out-of-distribution input. What does fix them is looking for objective
// evidence around the entity, and stretching or rejecting on that basis.
//
// # 为什么是加权而不是布尔
// # Why weighted rather than boolean
//
// 「必须有『先生』才算人名」会漏掉绝大多数真实人名。「有任何一个线索就算」
// 会把代码也算进来。因此线索分 Must 与 Should：Must 不满足直接否决，
// Should 累加计分，过阈值才确认。这让「证据不足」与「证据相反」成为
// 两种不同的结论，而它们本来就该不同。
//
// "A person name must be preceded by 先生" misses nearly every real name.
// "Any single cue counts" admits source code. So cues are Must or Should: an
// unmet Must rejects outright, Shoulds accumulate toward a threshold. That
// keeps "not enough evidence" and "evidence to the contrary" as separate
// conclusions, which is what they are.

// Requirement is how strongly a cue is required.
// 是一条线索的要求强度。
type Requirement uint8

const (
	// Should 累加计分。
	Should Requirement = iota

	// Must 不满足即否决，无论其他线索加了多少分。
	// An unmet Must rejects regardless of how much else scored.
	Must

	// MustNot 出现即否决。
	// Presence rejects.
	MustNot
)

// Direction is where a cue may appear relative to the entity.
// 是线索相对实体可以出现的位置。
type Direction uint8

const (
	Either Direction = iota
	Before
	After
)

// Cue is one piece of evidence.
// 是一条证据。
type Cue struct {
	// Name identifies the cue in audit output, so a decision can be explained.
	// 在审计输出中标识本条线索，使一次判定可以被解释。
	Name string

	Words       []string
	Requirement Requirement
	Direction   Direction

	// Weight 是命中时累加的分数。Must / MustNot 忽略它。
	Weight float64

	// Window 是搜索距离（字节）。0 表示用链的默认值。
	//
	// 距离是有意义的：「张伟说」里的「说」紧贴实体，而三百字外的「说」
	// 与这个实体没有关系。邻近度就是证据强度的一部分。
	//
	// Distance carries meaning: 说 adjacent to the entity is evidence, while
	// 说 three hundred characters away is not about this entity. Proximity is
	// part of the evidence's strength.
	Window int
}

// ShapeRule rejects an entity by the shape of its own text.
// 按实体自身文本的形态否决它。
//
// # 与上下文线索的分工
// # How this differs from a context cue
//
// 上下文线索看的是实体**周围**有什么，形态规则看的是实体**本身**长什么样。
// 两者缺一不可，实测证明了这一点：
//
// A context cue looks at what surrounds the entity; a shape rule looks at the
// entity itself. Both are needed, as measured:
//
//   - retry(n 被判成人名，靠周围的 func / return 挡下——这是上下文的活
//
//   - deps、ST、SSE 被判成人名或机构，周围全是正常的中文散文，
//     没有任何代码特征。挡住它们只能靠一件事：它们自己不长得像人名
//
//   - retry(n is caught by the func / return around it — context's job
//
//   - deps, ST and SSE sit in ordinary Chinese prose with no code markers
//     nearby; the only thing that catches them is that they do not look like
//     names themselves
type ShapeRule struct {
	// Name identifies the rule in audit output.
	Name string

	// Reject 返回 true 时否决该实体。
	Reject func(value string) bool
}

// Chain is the evidence policy for one entity type.
// 是某个实体类型的证据策略。
type Chain struct {
	Type detect.EntityType
	Cues []Cue

	// Shapes 是对实体自身形态的否决规则。
	// Rejection rules on the entity's own shape.
	Shapes []ShapeRule

	// Threshold 是确认所需的 Should 总分。
	Threshold float64

	// DefaultWindow 是未指定 Window 的线索使用的搜索距离（字节）。
	DefaultWindow int

	// Extension 描述如何向后拉伸边界。nil 表示不拉伸。
	Extension *ExtensionRule

	// Backward 描述如何向前补全边界。nil 表示不补全。
	//
	// 与 Extension 是两件事，不是一件事的两个方向：地址丢的是后面的门牌，
	// 机构丢的是前面的字号，而后者才是识别到具体一家的那部分。
	//
	// Not two directions of one thing: an address loses its trailing house
	// number, an organization loses its leading distinctive name — and the
	// latter is the part that identifies one specific entity.
	Backward *BackwardExtension

	// RejectUnverified 决定证据不足时是否否决。
	//
	// 这是本文件里最要紧的一个开关，因为它决定「证据不足」倒向哪边。
	// 对代码误判这类问题，必须是 true——没有人类上下文的 retry(n 就该被放行。
	// 对真实人名，必须是 false——大多数人名周围没有任何线索词，
	// 把它们全否决掉等于关掉人名检测。
	//
	// 所以它不是一个可以统一设定的默认值，而是逐类型的判断：
	// 类型的裸形态越像非 PII，就越该开。
	//
	// The most consequential switch here: which way "insufficient evidence"
	// falls. For code misclassification it must be true. For real person names
	// it must be false — most names have no cue words nearby, and rejecting
	// them all disables name detection. It is a per-type judgement, not a
	// global default: the more a type's bare form resembles non-PII, the more
	// it should be on.
	RejectUnverified bool

	// RejectUnverifiedBelow 在 RejectUnverified 为 false 时，按置信度分档否决。
	//
	// 「按类型一刀切」是不够的，实测证明了这一点：给人名配 RejectUnverified
	// = false 是为了保住真实人名（大多数周围没有线索词），但同一条策略
	// 也放行了姓氏识别器产出的 0.45 分候选——于是「王者荣耀」里的「王者荣」、
	// 「李子」「杨梅」全部通过，反例语料上多出 14 处误报，而证据链一处都没拦。
	//
	// 真正的判据不是类型，是这个实体**从哪来**：名册命中（0.98）与启发式
	// 姓氏候选（0.45）都是 NAME，但前者是确定的、后者是猜的。
	// 置信度正好携带了这个信息。
	//
	// 0 表示不启用分档。
	//
	// Keying on type alone is not enough, as measured: RejectUnverified=false
	// protects real names (most have no cues) but also admits the 0.45-scored
	// candidates a surname generator emits — 王者荣 out of 王者荣耀, plus 李子
	// and 杨梅, fourteen false positives the chain caught none of.
	//
	// The real criterion is not the type but where the entity came from: a
	// roster hit (0.98) and a heuristic surname candidate (0.45) are both NAME,
	// but one is determined and the other is guessed. Confidence carries
	// exactly that. Zero disables the tier.
	RejectUnverifiedBelow float64
}

// ExtensionRule stretches an entity's boundary forward while evidence holds.
// 在证据成立期间向后拉伸实体边界。
type ExtensionRule struct {
	// Suffixes 是可以作为拉伸终点的特征字。
	//
	// 拉伸只在这些字上收尾。没有它，拉伸会一路吞到标点为止，
	// 把「北京市海淀区中关村大街 1 号的会议室」整段吞掉。
	//
	// Extension may only end on these. Without them it would run to the next
	// punctuation and swallow trailing prose.
	Suffixes []string

	// MaxRunes 是最多向后拉伸多少个字符。
	MaxRunes int

	// StopRunes 是遇到即停止的字符。
	StopRunes string
}

// Decision is the outcome of validating one entity.
// 是对一个实体的验证结论。
type Decision struct {
	// Verdict 是结论。
	Verdict Verdict

	// Entity 是调整后的实体。边界拉伸会改变它的 Start/End/Value。
	Entity detect.Entity

	// Score 是累计的 Should 得分。
	Score float64

	// Evidence 是命中的线索名，供审计与人工复核。
	//
	// 只给线索名，不给命中的文本片段——片段来自原文，会把 PII 带进审计日志。
	// Cue names only, never the matched text: the text comes from the payload
	// and would carry PII into the audit log.
	Evidence []string

	// Reason 说明为什么得到这个结论。
	Reason string

	// Extended 记录边界被向后拉伸了多少字节。
	Extended int
}

// EvidenceValidator applies evidence chains to entities.
// 对实体施加证据链。
type EvidenceValidator struct {
	chains map[detect.EntityType]*Chain
}

// NewEvidenceValidator builds a validator from chains.
// 用一组链构造验证器。
func NewEvidenceValidator(chains ...*Chain) (*EvidenceValidator, error) {
	v := &EvidenceValidator{chains: map[detect.EntityType]*Chain{}}
	for _, c := range chains {
		if c == nil {
			return nil, fmt.Errorf("证据链不能为 nil / nil chain")
		}
		if _, dup := v.chains[c.Type]; dup {
			return nil, fmt.Errorf("实体类型 %s 配了两条证据链 / duplicate chain for %s",
				c.Type, c.Type)
		}
		if c.DefaultWindow <= 0 {
			c.DefaultWindow = 48
		}
		v.chains[c.Type] = c
	}
	return v, nil
}

// Types returns the entity types this validator covers, for coverage checks.
// 返回本验证器覆盖的实体类型，供覆盖度自检使用。
func (v *EvidenceValidator) Types() []detect.EntityType {
	out := make([]detect.EntityType, 0, len(v.chains))
	for t := range v.chains {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Validate applies the chain for an entity's type.
// 对实体施加其类型对应的证据链。
//
// 没有配链的类型原样通过。这是刻意的：验证器只覆盖那些**需要**上下文才能
// 判定的类型（人名、地址），而带校验位的类型（身份证、卡号）已经由算术
// 给出了确定答案，再让上下文去否决它是错的——一个校验位正确的身份证号，
// 无论周围写着什么都是身份证号。
//
// A type with no chain passes through. Deliberate: the validator covers only
// types that need context. A checksum-backed identifier already has an
// arithmetic answer, and letting context overrule it is wrong — a valid ID
// number is one whatever the surrounding sentence says.
func (v *EvidenceValidator) Validate(text string, e detect.Entity) Decision {
	chain, ok := v.chains[e.Type]
	if !ok {
		return Decision{Verdict: VerdictKeep, Entity: e, Reason: "该类型未配置证据链，原样通过"}
	}

	entity := e
	extended := 0
	var backwardEvidence []string

	if chain.Extension != nil {
		if newEnd := extendBoundary(text, entity, chain.Extension); newEnd > entity.End {
			extended = newEnd - entity.End
			entity.End = newEnd
			entity.Value = text[entity.Start:entity.End]
		}
	}
	if chain.Backward != nil {
		newStart, _, evidence := chain.Backward.extendBackward(text, entity)
		if newStart < entity.Start {
			extended += entity.Start - newStart
			entity.Start = newStart
			entity.Value = text[entity.Start:entity.End]
			backwardEvidence = evidence
		}
	}

	// 形态规则先跑：它不需要看上下文，也不需要算分，而一个形态上就不可能
	// 是该类型的实体，再多的上下文证据也不该救它。
	//
	// Shape rules run first: they need neither context nor scoring, and no
	// amount of contextual evidence should rescue an entity whose own shape
	// rules it out.
	for _, shape := range chain.Shapes {
		if shape.Reject(entity.Value) {
			return Decision{
				Verdict:  VerdictDrop,
				Entity:   entity,
				Evidence: []string{shape.Name},
				Reason:   fmt.Sprintf("实体形态命中否决规则 %s", shape.Name),
				Extended: extended,
			}
		}
	}

	score := 0.0
	var evidence []string
	for _, cue := range chain.Cues {
		window := cue.Window
		if window <= 0 {
			window = chain.DefaultWindow
		}
		hit := cueMatches(text, entity, cue, window)

		switch cue.Requirement {
		case MustNot:
			if hit {
				return Decision{
					Verdict:  VerdictDrop,
					Entity:   entity,
					Score:    score,
					Evidence: append(evidence, cue.Name),
					Reason:   fmt.Sprintf("命中否决线索 %s", cue.Name),
					Extended: extended,
				}
			}
		case Must:
			if !hit {
				return Decision{
					Verdict:  VerdictDrop,
					Entity:   entity,
					Score:    score,
					Evidence: evidence,
					Reason:   fmt.Sprintf("缺少必要线索 %s", cue.Name),
					Extended: extended,
				}
			}
			evidence = append(evidence, cue.Name)
		case Should:
			if hit {
				score += cue.Weight
				evidence = append(evidence, cue.Name)
			}
		}
	}

	if score >= chain.Threshold {
		return Decision{
			Verdict: VerdictKeep, Entity: entity, Score: score,
			Evidence: append(evidence, backwardEvidence...),
			Reason:   fmt.Sprintf("证据得分 %.2f 达到阈值 %.2f", score, chain.Threshold),
			Extended: extended,
		}
	}
	if chain.RejectUnverified {
		return Decision{
			Verdict: VerdictDrop, Entity: entity, Score: score, Evidence: evidence,
			Reason: fmt.Sprintf("证据得分 %.2f 未达阈值 %.2f，且该类型证据不足即否决",
				score, chain.Threshold),
			Extended: extended,
		}
	}
	// 置信度为 0 表示「没有这个信息」，不表示「置信度很低」。
	//
	// 两者在脱敏系统里的后果是反的：把「没信息」当成「低置信度」会导致否决，
	// 而对人名来说否决就是不脱敏、就是泄露。任何未设置置信度的检出——
	// 手工构造的、或某个忘了填这个字段的检测器产出的——都必须走安全的
	// 那一边，也就是继续脱敏。
	//
	// A zero confidence means "no information", not "low confidence". In a
	// redaction system those have opposite consequences: treating the former
	// as the latter causes a rejection, and for a name a rejection means no
	// redaction, which means a leak. Anything with an unset confidence takes
	// the safe side.
	if chain.RejectUnverifiedBelow > 0 && entity.Confidence > 0 &&
		entity.Confidence < chain.RejectUnverifiedBelow {
		return Decision{
			Verdict: VerdictDrop, Entity: entity, Score: score, Evidence: evidence,
			Reason: fmt.Sprintf(
				"证据得分 %.2f 未达阈值 %.2f，且检出置信度 %.2f 低于 %.2f——"+
					"这是一个猜出来的候选，没有证据支撑就不该留下",
				score, chain.Threshold, entity.Confidence, chain.RejectUnverifiedBelow),
			Extended: extended,
		}
	}
	return Decision{
		Verdict: VerdictUnknown, Entity: entity, Score: score, Evidence: evidence,
		Reason: fmt.Sprintf("证据得分 %.2f 未达阈值 %.2f，但该类型证据不足不否决",
			score, chain.Threshold),
		Extended: extended,
	}
}

// cueMatches reports whether a cue appears within the window.
// 报告某条线索是否出现在窗口内。
func cueMatches(text string, e detect.Entity, cue Cue, window int) bool {
	before, after := contextAround(text, e, window)

	for _, word := range cue.Words {
		switch cue.Direction {
		case Before:
			if strings.Contains(before, word) {
				return true
			}
		case After:
			if strings.Contains(after, word) {
				return true
			}
		default:
			if strings.Contains(before, word) || strings.Contains(after, word) {
				return true
			}
		}
	}
	return false
}

// contextAround returns the text on each side, cut on rune boundaries.
// 返回实体两侧的文本，按字符边界切分。
//
// 按字节切会把一个汉字切成两半，让子串搜索在半个字符上做匹配——
// 那既可能漏掉线索，也可能匹配到不存在的东西。
//
// Cutting by byte splits a character in half and makes substring search
// operate on a fragment, which can both miss cues and match nonexistent ones.
func contextAround(text string, e detect.Entity, window int) (before, after string) {
	lo := e.Start - window
	if lo < 0 {
		lo = 0
	}
	for lo > 0 && !utf8RuneStart(text[lo]) {
		lo--
	}

	hi := e.End + window
	if hi > len(text) {
		hi = len(text)
	}
	for hi < len(text) && !utf8RuneStart(text[hi]) {
		hi++
	}

	return text[lo:e.Start], text[e.End:hi]
}

// extendBoundary stretches an entity forward while the evidence chain holds.
// 在证据链成立期间把实体边界向后拉伸。
//
// 只在特征字上收尾，并记住**最后一个**合法终点。中途出现不带特征字的片段
// 不立刻停止——「北京市海淀区中关村大街 1 号」里的「中关村」本身不是特征字，
// 但它后面的「大街」是。一遇到非特征字就停，会停在「海淀区」。
//
// Ends only on a suffix character, remembering the furthest valid endpoint. A
// segment without a suffix does not stop the scan: 中关村 in
// 北京市海淀区中关村大街 1 号 is not itself a suffix, but 大街 after it is.
// Stopping at the first non-suffix would stop at 海淀区.
func extendBoundary(text string, e detect.Entity, rule *ExtensionRule) int {
	if e.End >= len(text) {
		return e.End
	}

	maxRunes := rule.MaxRunes
	if maxRunes <= 0 {
		maxRunes = 20
	}

	lastValid := e.End
	pos := e.End
	for runes := 0; runes < maxRunes && pos < len(text); runes++ {
		r, size := utf8.DecodeRuneInString(text[pos:])
		if size == 0 || r == utf8.RuneError {
			break
		}
		if strings.ContainsRune(rule.StopRunes, r) {
			break
		}
		// 允许数字与汉字继续；其余（标点、字母）视为链断
		// Digits and Han continue; punctuation and letters break the chain.
		if !unicode.Is(unicode.Han, r) && !unicode.IsDigit(r) && r != ' ' {
			break
		}
		pos += size

		for _, suffix := range rule.Suffixes {
			if strings.HasSuffix(text[e.Start:pos], suffix) {
				lastValid = pos
				break
			}
		}
	}
	return lastValid
}

// utf8RuneStart reports whether a byte begins a UTF-8 rune.
// 报告一个字节是否为 UTF-8 字符的首字节。
func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// ResolveByEvidence picks among overlapping candidates using the evidence
// chain's verdict and score instead of raw length.
// 在重叠候选之间按证据链的结论与得分取舍，而不是按长度。
//
// # 为什么不能沿用 ResolveOverlaps
// # Why ResolveOverlaps cannot be reused here
//
// detect.ResolveOverlaps 的排序键是「先长度、再置信度」。对带校验位的类型
// 这是对的：更长的匹配通常意味着更完整的标识。对姓氏驱动的人名候选则相反——
// 「尉迟恭」与「尉迟恭负」同时产出时，长的那个多吞了一个动词。
//
// detect.ResolveOverlaps sorts by length first, then confidence. That is right
// for checksum-backed types, where a longer match usually means a more complete
// identifier. For surname-driven name candidates it is backwards: given
// 尉迟恭 and 尉迟恭负, the longer one has swallowed a verb.
//
// 证据链恰好能分辨这两者——实测「尉迟恭」得到 KEEP 而「尉迟恭负」得到
// UNKNOWN，因为后者的右侧上下文里少了「负责」这个人类动作线索。
// 于是取舍的依据应当是结论强度，长度只在结论相同时才作为最后的平手判据。
//
// The chain distinguishes them: measured, 尉迟恭 scores KEEP while 尉迟恭负
// scores UNKNOWN, because the latter consumed the 负责 cue that would have
// supported it. Verdict strength is therefore the key, with length demoted to
// a final tie-break.
func ResolveByEvidence(decisions []Decision) []Decision {
	// 没有「只有一个候选就直接返回」的快路径。
	//
	// 曾经有，而它跳过了下面的 DROP 过滤：只产出一个候选的文本，
	// 那个候选即使被否决也会被原样返回。实测「王者荣耀的新赛季已经开启」
	// 恰好只产出一个候选，于是「王者荣」被证据链判为 DROP 之后照样进了结果。
	// 反例语料上因此多出 7 处误报，而单独调 Validate 看到的却是 DROP——
	// 两处行为不一致，问题藏在那条为「省一次排序」而写的快路径里。
	//
	// There is no fast path for a single candidate. There used to be, and it
	// skipped the DROP filter below: a text producing exactly one candidate
	// returned it even when rejected. Measured, 王者荣 came back after the
	// chain had dropped it, because that sentence yields exactly one
	// candidate — seven false positives whose isolated Validate call said DROP.
	ranked := make([]Decision, 0, len(decisions))
	for _, d := range decisions {
		if d.Verdict == VerdictDrop {
			continue // 已被否决的不参与占位 / rejected candidates do not compete
		}
		ranked = append(ranked, d)
	}

	sort.SliceStable(ranked, func(i, j int) bool {
		vi, vj := verdictRank(ranked[i].Verdict), verdictRank(ranked[j].Verdict)
		if vi != vj {
			return vi > vj
		}
		if ranked[i].Score != ranked[j].Score {
			return ranked[i].Score > ranked[j].Score
		}
		if ranked[i].Entity.Confidence != ranked[j].Entity.Confidence {
			return ranked[i].Entity.Confidence > ranked[j].Entity.Confidence
		}
		// 平手时取更长的。
		//
		// 中文名的名部分以两字为主，因此在证据分不出高下时，更长的候选是
		// 更好的先验。反过来取短的会系统性地把两字名截成一字——
		// 而截断后的脱敏仍然会「成功」，只是把名字的后半截留在了原文里。
		//
		// Longer wins ties: two-character given names dominate, so on equal
		// evidence the longer candidate is the better prior. Preferring the
		// shorter systematically truncates two-character names — and a
		// truncated redaction still "succeeds", leaving half the name behind.
		li := ranked[i].Entity.End - ranked[i].Entity.Start
		lj := ranked[j].Entity.End - ranked[j].Entity.Start
		if li != lj {
			return li > lj
		}
		return ranked[i].Entity.Start < ranked[j].Entity.Start
	})

	var kept []Decision
	for _, d := range ranked {
		conflict := false
		for _, k := range kept {
			if d.Entity.Start < k.Entity.End && k.Entity.Start < d.Entity.End {
				conflict = true
				break
			}
		}
		if !conflict {
			kept = append(kept, d)
		}
	}

	sort.Slice(kept, func(i, j int) bool { return kept[i].Entity.Start < kept[j].Entity.Start })
	return kept
}

// verdictRank orders verdicts by strength.
// 按强度给结论排序。
func verdictRank(v Verdict) int {
	switch v {
	case VerdictKeep:
		return 2
	case VerdictUnknown:
		return 1
	}
	return 0
}

// ValidateAll validates a batch of entities and resolves their overlaps by
// evidence.
// 批量验证并按证据消解重叠。
func (v *EvidenceValidator) ValidateAll(text string, entities []detect.Entity) []Decision {
	decisions := make([]Decision, 0, len(entities))
	for _, e := range entities {
		decisions = append(decisions, v.Validate(text, e))
	}
	return ResolveByEvidence(decisions)
}
