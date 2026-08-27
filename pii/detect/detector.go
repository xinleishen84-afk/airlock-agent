package detect

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// EntityType is a PII entity type. Placeholder type names come from this enum.
// 是 PII 实体类型。占位符中的类型名取自本枚举。
type EntityType string

const (
	TypeName         EntityType = "NAME"          // natural person name / 自然人姓名
	TypePhone        EntityType = "PHONE"         // phone number / 电话号码
	TypeEmail        EntityType = "EMAIL"         //
	TypeIDCard       EntityType = "ID_CARD"       // national ID / 身份证号
	TypeBankCard     EntityType = "BANK_CARD"     // bank card / 银行卡号
	TypeAddress      EntityType = "ADDRESS"       // street address / 详细住址
	TypeOrg          EntityType = "ORG"           // organization / 机构名
	TypeIP           EntityType = "IP"            //
	TypeCredential   EntityType = "CREDENTIAL"    // API key or token / API 密钥、令牌
	TypePassport     EntityType = "PASSPORT"      //
	TypeLicensePlate EntityType = "LICENSE_PLATE" // license plate / 车牌
	TypeSSN          EntityType = "SSN"           // US SSN / 美国社会安全号
	TypeUSCC         EntityType = "USCC"          // unified social credit code / 统一社会信用代码
	// TypeAccount covers deployment-specific identifiers: employee numbers,
	// contract codes, customer references. No built-in recognizer produces it —
	// it exists so a custom recognizer has a type to report.
	// 涵盖部署特有的标识：工号、合同编号、客户代码。
	// 没有内置识别器产出它——它的存在是为了让自定义识别器有类型可报。
	TypeAccount EntityType = "ACCOUNT"
	TypeIBAN    EntityType = "IBAN" // international bank account / 国际银行账号
)

// NERDependentTypes are the types regexes cannot find, requiring a gazetteer or
// an NER model.
// 是正则无法识别、必须靠名册或 NER 模型检出的类型。
//
// Personal names have no stable lexical signature. Shipping with only the regex
// detector leaves these categories completely exposed.
// 人名没有稳定的字面特征——只装正则检测器就上线，这几类 PII 会完全裸奔。
var NERDependentTypes = []EntityType{TypeName, TypeAddress, TypeOrg}

// Entity is one detected PII entity. Start/End are byte offsets.
// 是一个被检出的 PII 实体。Start/End 为字节偏移。
type Entity struct {
	Type       EntityType
	Value      string
	Start      int // inclusive start / 闭区间起点
	End        int // exclusive end / 开区间终点
	Confidence float64
	Detector   string
}

// Len returns the byte length of the span, used for longest-wins overlap
// resolution.
// 返回实体片段的字节长度，用于重叠消解时的长度优先。
func (e Entity) Len() int { return e.End - e.Start }

// Overlaps reports whether two entities overlap in the source text.
// 判断两个实体在原文中是否重叠。
func (e Entity) Overlaps(other Entity) bool {
	return e.Start < other.End && other.Start < e.End
}

// Detector is the detector interface.
// 是检测器接口。
type Detector interface {
	Detect(text string) ([]Entity, error)
	CoveredTypes() []EntityType
	Name() string
}

// ---------------------------------------------------------------------------
// Regex detector / 正则检测器
// ---------------------------------------------------------------------------

// validatorFunc is a post-check that narrows "looks like" into "actually is".
// 是后置校验函数，用于把「看起来像」收紧为「确实是」。
type validatorFunc func(string) bool

// BoundaryClass is exported because jurisdiction packs and tenant YAML rules
// live outside this package and need the same boundary semantics as the
// built-ins. A recognizer that cannot express its boundaries is not equivalent
// to a built-in one, and the whole point of pluggable packs is that they are.
// 之所以导出，是因为司法管辖区包与租户 YAML 规则都在本包之外，
// 它们需要与内置识别器相同的边界语义。无法表达边界的识别器与内置识别器
// 并不等价，而可插拔包的全部意义正在于两者等价。
//
// BoundaryClass describes the character class forbidden on either side of an
// entity.
// 描述实体两侧不允许出现的字符类。
//
// Go's regexp is RE2-based and **supports neither lookbehind nor lookahead**.
// The boundary constraint written as `(?<!\d)` elsewhere becomes "bare pattern
// match + manual boundary check" here.
// Go 的 regexp 基于 RE2，**不支持 lookbehind / lookahead**。
// 用 `(?<!\d)` 表达的边界约束，这里改为「裸模式匹配 + 手工边界检查」。
//
// A wrong approach tried earlier: emulate it with sentinel groups,
// `(?:^|[^0-9])(...)(?:[^0-9]|$)`. Two fatal flaws — sentinels consume the
// adjacent character while FindAll scans non-overlapping, so in
// "13812345678 13900001111" the second number loses its leading sentinel and is
// missed. Worse, there is no backtracking between the regex match and the
// post-check, so a greedy match that fails validation pushes the scan position
// past the real target. Manual boundary checks have neither problem.
// 曾尝试过的错误做法：用哨兵组模拟。它有两个致命缺陷——哨兵会消费相邻字符，
// 而 FindAll 是非重叠扫描，于是「13812345678 13900001111」的第二个号码
// 会因失去前导哨兵而漏检；更严重的是，正则匹配与后置校验之间没有回溯，
// 一个贪婪但校验失败的匹配会把扫描位置推过真正的目标。
// 手工边界检查两个问题都不存在。
type BoundaryClass uint8

const (
	BoundaryNone     BoundaryClass = iota // no boundary constraint / 不做边界约束
	BoundaryDigit                         // no digit on either side / 两侧不得为数字
	BoundaryDigitSep                      // no digit or hyphen / 两侧不得为数字或连字符
	BoundaryAlnum                         // no alphanumeric / 两侧不得为字母数字
)

// isBoundaryOK checks whether the characters flanking an entity satisfy the
// boundary constraint.
// 检查实体两侧字符是否满足边界约束。
//
// Only the immediately adjacent byte matters: every forbidden set is ASCII, and
// the lead/trail bytes of a multi-byte UTF-8 rune are always >= 0x80, so they
// naturally fall outside all of them.
// 只看紧邻的一个字节：这几类约束的字符集都在 ASCII 内，
// 多字节 UTF-8 字符的首/尾字节恒 >= 0x80，天然不属于任何禁止集。
func isBoundaryOK(text string, start, end int, class BoundaryClass) bool {
	if class == BoundaryNone {
		return true
	}
	forbidden := func(b byte) bool {
		switch class {
		case BoundaryDigit:
			return b >= '0' && b <= '9'
		case BoundaryDigitSep:
			return (b >= '0' && b <= '9') || b == '-'
		case BoundaryAlnum:
			return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
		}
		return false
	}
	if start > 0 && forbidden(text[start-1]) {
		return false
	}
	if end < len(text) && forbidden(text[end]) {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Gazetteer detector / 名册检测器
// ---------------------------------------------------------------------------

// GazetteerDetector matches exactly against enterprise master data (employee
// rosters, customer CRM).
// 基于企业主数据（员工花名册、客户 CRM）做精确匹配。
//
// In enterprise settings this is often more accurate than general-purpose NER:
// the names worth protecting are already in the master data.
// 企业场景下这往往比通用 NER 更准：要保护的姓名本来就在主数据里。
type GazetteerDetector struct {
	// ac 是编译后的多模式自动机。
	//
	// 曾经这里是「把所有词条拼成一个正则大并集」。那条路的代价随词典大小
	// 增长——一万条员工姓名是一万个分支的 NFA——而企业主数据动辄十万条。
	// 换成 Aho-Corasick 之后，扫描代价与词典大小解耦，实测 100 条与 50000 条
	// 的耗时在同一量级。
	//
	// This was a regex alternation of every term, whose cost grows with the
	// dictionary. Aho-Corasick decouples scan cost from dictionary size.
	ac *AhoCorasick

	// patternType maps a pattern index to its entity type.
	// 把模式下标映射到实体类型。
	patternType []EntityType

	// original holds the term as written, for case-insensitive lookup.
	// 保存词条的原始写法，供不区分大小写时回写。
	caseSensitive bool
	covered       []EntityType
}

// NewGazetteerDetector builds a gazetteer detector from a term table.
// 从词条表构造名册检测器。
//
// Terms are joined into regex alternation in descending length order so that a
// longer name wins over a shorter prefix of it, preventing long entities from
// being sliced apart.
// 词条按长度降序拼进正则交替分支，保证长实体优先命中，避免被切碎。
func NewGazetteerDetector(entries map[EntityType][]string, caseSensitive bool, minLen int) (*GazetteerDetector, error) {
	if minLen < 1 {
		minLen = 2
	}
	d := &GazetteerDetector{caseSensitive: caseSensitive}

	// 词条按类型收集。同一个词条出现在两个类型下是主数据的问题，
	// 静默取其一会让「这个名字为什么被判成机构」变成一桩无头案。
	// The same term under two types is a master-data problem; silently picking
	// one makes "why was this name classed as an organization" unanswerable.
	seen := make(map[string]EntityType)
	var terms []string
	var types []EntityType

	typeOrder := make([]EntityType, 0, len(entries))
	for typ := range entries {
		typeOrder = append(typeOrder, typ)
	}
	sort.Slice(typeOrder, func(i, j int) bool { return typeOrder[i] < typeOrder[j] })

	for _, typ := range typeOrder {
		d.covered = append(d.covered, typ)
		for _, v := range entries[typ] {
			term := strings.TrimSpace(v)
			if len([]rune(term)) < minLen {
				continue // short terms flood false positives / 过短词条会让误报泛滥
			}
			key := term
			if !caseSensitive {
				key = strings.ToLower(term)
			}
			if prev, dup := seen[key]; dup {
				if prev != typ {
					return nil, fmt.Errorf(
						"名册词条 %q 同时出现在 %s 与 %s 下——请在主数据里消歧 / "+
							"term %q appears under both %s and %s",
						term, prev, typ, term, prev, typ)
				}
				continue
			}
			seen[key] = typ
			terms = append(terms, key)
			types = append(types, typ)
		}
	}

	if len(terms) == 0 {
		return d, nil
	}

	ac, err := NewAhoCorasick(terms)
	if err != nil {
		return nil, fmt.Errorf("构建名册自动机失败 / building roster automaton: %w", err)
	}
	d.ac = ac
	d.patternType = types
	return d, nil
}

// Name 返回检测器标识。
func (d *GazetteerDetector) Name() string { return "gazetteer" }

// Detect scans for gazetteer hits.
// 扫描名册命中项。
func (d *GazetteerDetector) Detect(text string) ([]Entity, error) {
	if d.ac == nil {
		return nil, nil
	}

	// 不区分大小写时在小写副本上匹配。偏移仍然对得上，因为 ToLower 只对
	// ASCII 字母改变字节，不改变长度——但这个前提对某些 Unicode 字符不成立
	// （例如 'İ' 小写后变成两个 code point）。因此这里断言长度不变，
	// 不成立就退回原文匹配，宁可漏掉大小写变体，也不能给出错位的偏移。
	//
	// Offsets still line up because ToLower changes bytes but not length for
	// ASCII — a premise that fails for some Unicode (e.g. 'İ'). The length is
	// asserted; if it does not hold, matching falls back to the original text.
	// Missing a case variant is acceptable; a misaligned offset is not.
	haystack := text
	if !d.caseSensitive {
		lowered := strings.ToLower(text)
		if len(lowered) == len(text) {
			haystack = lowered
		}
	}

	matches := d.ac.FindAll(haystack)
	if len(matches) == 0 {
		return nil, nil
	}

	found := make([]Entity, 0, len(matches))
	for _, m := range matches {
		found = append(found, Entity{
			Type:       d.patternType[m.Pattern],
			Value:      text[m.Start:m.End],
			Start:      m.Start,
			End:        m.End,
			Confidence: 0.98,
			Detector:   d.Name(),
		})
	}
	return found, nil
}

// CoveredTypes returns the types this detector covers.
// 返回本检测器覆盖的类型。
func (d *GazetteerDetector) CoveredTypes() []EntityType { return d.covered }

// ---------------------------------------------------------------------------
// Composition and overlap resolution / 组合与重叠消解
// ---------------------------------------------------------------------------

// CompositeDetector combines detectors and resolves overlaps.
// 组合多个检测器并消解重叠。
//
// Overlap resolution, in order: longer span wins, then higher confidence.
// Longest-wins matters because an 18-digit ID number is partially matched by
// both the ID rule and the bank-card rule; only the longer span carries the
// correct meaning.
// 重叠消解规则（按序）：更长的片段优先 > 置信度更高的优先。
// 长度优先的理由：18 位身份证会同时被身份证规则和银行卡规则部分命中，
// 取长的那个才是正确语义。
type CompositeDetector struct {
	// deferOverlaps 让本检测器保留重叠候选，把消解交给下游。
	//
	// 默认 false：绝大多数调用方要的是一份已经消解好的结果。
	//
	// 但接了证据链的管线不能用默认值。ResolveOverlaps 是「长者优先」，
	// 而姓氏识别器产出的是候选：「尉迟恭」与「尉迟恭负」同时出现时，
	// 长的那个多吞了一个动词却会赢——等验证器拿到结果，短的那个已经没了。
	//
	// 实测后果：Core 二进制把「尉迟恭负责本次验收」脱敏成
	// 「ANONYMIZED_NAME_1责本次验收」，而单独调验证器时它明明选对了。
	//
	// Defaults to false: most callers want a resolved result. A pipeline with
	// an evidence chain must not use the default. ResolveOverlaps prefers
	// length, and the surname recognizer emits candidates — 尉迟恭 and
	// 尉迟恭负 — where the longer one has swallowed a verb and still wins. By
	// the time the validator runs, the right candidate is gone.
	deferOverlaps bool

	detectors     []Detector
	minConfidence float64
	warnOnce      sync.Once
	missing       []EntityType
}

// NewCompositeDetector combines detectors, recording any name-class coverage
// gap so it can be surfaced — the most dangerous silent misconfiguration.
// 组合若干检测器。缺少姓名类检测能力时记录缺口——这是最危险的静默配置。
// NewCompositeDetectorDeferred is NewCompositeDetector with overlap resolution
// left to the caller.
// 与 NewCompositeDetector 相同，但把重叠消解留给调用方。
//
// 接了证据链时必须用这个：证据链要按结论强度与得分取舍，而那需要看到
// 全部候选，包括会被「长者优先」淘汰掉的那些。
//
// Required when an evidence chain follows: it resolves by verdict strength and
// score, which needs to see every candidate — including the ones length-first
// resolution would have discarded.
func NewCompositeDetectorDeferred(detectors []Detector, minConfidence float64) *CompositeDetector {
	d := NewCompositeDetector(detectors, minConfidence)
	d.deferOverlaps = true
	return d
}

func NewCompositeDetector(detectors []Detector, minConfidence float64) *CompositeDetector {
	covered := map[EntityType]bool{}
	for _, d := range detectors {
		for _, t := range d.CoveredTypes() {
			covered[t] = true
		}
	}
	var missing []EntityType
	for _, t := range NERDependentTypes {
		if !covered[t] {
			missing = append(missing, t)
		}
	}
	return &CompositeDetector{detectors: detectors, minConfidence: minConfidence, missing: missing}
}

// Name 返回检测器标识。
func (d *CompositeDetector) Name() string {
	if d.deferOverlaps {
		return "composite(deferred)"
	}
	return "composite"
}

// DefersOverlapResolution reports that this detector's output may overlap.
// 报告本检测器的输出可能存在重叠。
//
// 延后消解的检测器产出的是**候选**，直接拿去脱敏是不安全的：重叠区间之外的
// PII 会原样出境。实测在随机文本上，约四分之一的样本会出现重叠候选。
//
// 用一个方法而不是靠名字字符串匹配：名字是给人看的，会被改；
// 而下游据以判断「这批结果安不安全」的东西不该随一次改名而失效。
//
// A deferred detector emits candidates, and redacting them directly is unsafe:
// PII outside the overlapping region leaves verbatim. Measured on random text,
// roughly a quarter of samples produce overlapping candidates.
//
// A method rather than a name-string match: the name is for humans and will be
// changed, and what downstream uses to decide "is this output safe" should not
// break on a rename.
func (d *CompositeDetector) DefersOverlapResolution() bool { return d.deferOverlaps }

// GapReporter reports which NER-dependent entity types nothing covers.
// 报告哪些依赖 NER 的实体类型无人覆盖。
//
// # 为什么是接口而不是具体类型
// # Why an interface rather than a concrete type
//
// 覆盖缺口告警是这套系统里最要紧的一条运维信号：它说的是「姓名、地址、
// 机构名这几类完全裸奔」。而它此前靠 detector.(*CompositeDetector) 取，
// 一旦有人在检测器外面包一层（证据链就是这么包的），断言失败，
// 告警**静默消失**——不报错、日志里也不再出现，看起来像「没有缺口」。
//
// 实测发生过：证据链包上之后，sidecar 的 /stats coverage_gaps 与启动告警
// 一直是空的，而缺口一直在。
//
// The coverage-gap warning is the most consequential operational signal here:
// it says names, addresses and organizations are fully exposed. It used to be
// read via a concrete-type assertion, which any wrapper breaks — and the
// evidence chain is a wrapper. The assertion then fails and the warning
// silently disappears, looking exactly like "no gaps".
//
// Measured: after the chain was wrapped, the sidecar's coverage_gaps and its
// startup warning were empty while the gaps were still there.
type GapReporter interface {
	Missing() []EntityType
}

// Missing returns the uncovered NER-dependent types, for startup health checks.
// 返回未被覆盖的 NER 依赖类型，供启动期健康检查使用。
func (d *CompositeDetector) Missing() []EntityType { return d.missing }

// Detect aggregates every detector's results, resolves overlaps and returns
// entities in ascending position order.
// 汇总各检测器结果并消解重叠，返回按位置升序的实体列表。
//
// A single detector failure propagates so the redaction pipeline can apply its
// fail-closed policy: silently weakening protection is worse than failing the
// request.
// 单个检测器故障会整体上抛，由脱敏管道按 fail-closed 决策——
// 静默削弱防护比请求失败更危险。
func (d *CompositeDetector) Detect(text string) ([]Entity, error) {
	var candidates []Entity
	for _, sub := range d.detectors {
		found, err := sub.Detect(text)
		if err != nil {
			return nil, fmt.Errorf("检测器 %s 执行失败: %w", sub.Name(), err)
		}
		for _, e := range found {
			if e.Confidence >= d.minConfidence {
				candidates = append(candidates, e)
			}
		}
	}
	if d.deferOverlaps {
		return candidates, nil
	}
	return ResolveOverlaps(candidates), nil
}

// CoveredTypes returns the union of every sub-detector's covered types.
// 返回所有子检测器覆盖类型的并集。
func (d *CompositeDetector) CoveredTypes() []EntityType {
	seen := map[EntityType]bool{}
	var out []EntityType
	for _, sub := range d.detectors {
		for _, t := range sub.CoveredTypes() {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// ResolveOverlaps greedily resolves overlaps: longest first, then highest
// confidence.
// 贪心消解重叠：长度优先，其次置信度优先。
func ResolveOverlaps(entities []Entity) []Entity {
	if len(entities) < 2 {
		return append([]Entity(nil), entities...)
	}

	// 先按起点排序，把实体切成互不相交的「连通块」，再在每块内部做原来的贪心。
	//
	// 语义与逐个比对全部已接受实体的写法完全一致——两个不相交的连通块之间
	// 本来就不可能冲突，所以跨块的比较每一次都是在做无用功。
	// 区别只在复杂度：原来的内层循环长度是「已接受实体总数」，
	// 现在是「本块内的实体数」。在一份 384KB、检出三千多个实体的文档上，
	// 前者实测 8.8ms，而这份文档的整体处理也不过八十几毫秒。
	//
	// Sort by start, cut the entities into disjoint connected components, then
	// run the original greedy inside each. The semantics are identical —
	// entities in different components cannot conflict, so every cross-component
	// comparison was doing nothing. Only the complexity changes: the inner loop
	// was bounded by the total accepted count, and is now bounded by the size of
	// one component.
	ordered := make([]Entity, len(entities))
	copy(ordered, entities)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Start < ordered[j].Start })

	accepted := make([]Entity, 0, len(ordered))
	start := 0
	maxEnd := ordered[0].End

	flush := func(component []Entity) {
		accepted = append(accepted, resolveComponent(component)...)
	}

	for i := 1; i < len(ordered); i++ {
		if ordered[i].Start >= maxEnd {
			flush(ordered[start:i])
			start = i
			maxEnd = ordered[i].End
			continue
		}
		if ordered[i].End > maxEnd {
			maxEnd = ordered[i].End
		}
	}
	flush(ordered[start:])

	sort.Slice(accepted, func(i, j int) bool { return accepted[i].Start < accepted[j].Start })
	return accepted
}

// resolveComponent runs longest-wins greedy inside one overlapping group.
// 在一个相互重叠的分组内部执行「长者优先」的贪心。
//
// 排序键与原实现逐字相同：先长度、再置信度、最后起点。
// 这个顺序是有代价的判断——把「更长的匹配」排在「置信度更高的匹配」之前，
// 意味着一个跨越了两个实体的贪婪匹配会赢过它们两个。
// 边界检查与校验位存在的理由，正是让这种匹配根本不要产生。
//
// The sort key is identical to the original: length, then confidence, then
// start. That order is a judgement with a cost — a greedy match spanning two
// entities beats both of them — and boundary checks and check digits exist to
// stop such a match from being produced in the first place.
func resolveComponent(component []Entity) []Entity {
	if len(component) == 1 {
		return component
	}

	ranked := make([]Entity, len(component))
	copy(ranked, component)
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].Len() != ranked[j].Len() {
			return ranked[i].Len() > ranked[j].Len()
		}
		if ranked[i].Confidence != ranked[j].Confidence {
			return ranked[i].Confidence > ranked[j].Confidence
		}
		return ranked[i].Start < ranked[j].Start
	})

	kept := make([]Entity, 0, len(ranked))
	for _, e := range ranked {
		conflict := false
		for _, k := range kept {
			if e.Overlaps(k) {
				conflict = true
				break
			}
		}
		if !conflict {
			kept = append(kept, e)
		}
	}
	return kept
}
