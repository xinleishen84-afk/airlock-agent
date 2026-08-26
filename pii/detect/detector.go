package detect

import (
	"fmt"
	"regexp"
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
	TypeAccount EntityType = "ACCOUNT" // unified social credit code / 统一社会信用代码
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

// boundaryClass describes the character class forbidden on either side of an
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
type boundaryClass uint8

const (
	boundaryNone     boundaryClass = iota // no boundary constraint / 不做边界约束
	boundaryDigit                         // no digit on either side / 两侧不得为数字
	boundaryDigitSep                      // no digit or hyphen / 两侧不得为数字或连字符
	boundaryAlnum                         // no alphanumeric / 两侧不得为字母数字
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
func isBoundaryOK(text string, start, end int, class boundaryClass) bool {
	if class == boundaryNone {
		return true
	}
	forbidden := func(b byte) bool {
		switch class {
		case boundaryDigit:
			return b >= '0' && b <= '9'
		case boundaryDigitSep:
			return (b >= '0' && b <= '9') || b == '-'
		case boundaryAlnum:
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

// rule is one detection rule. The pattern is bare; the boundary constraint is
// expressed separately by the boundary field.
// 是一条检测规则。模式为裸模式，边界由 boundary 字段单独表达。
type rule struct {
	typ        EntityType
	re         *regexp.Regexp
	confidence float64
	boundary   boundaryClass
	validate   validatorFunc // post-check; nil means none / 后置校验，nil 表示无
	normalize  bool          // strip separators before validating / 校验前剥离分隔符
}

// buildRules builds the rule table. A function rather than a package-level var,
// so rules can be trimmed by configuration.
// 构造规则表。用函数而非包级变量，便于按配置裁剪。
func buildRules(disabled map[EntityType]bool) []rule {
	all := []rule{
		// Email: stable shape, no boundary needed / 邮箱：结构稳定，无需边界约束
		{typ: TypeEmail, confidence: 0.99, boundary: boundaryNone,
			re: regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)},

		// Chinese ID: 18 chars, last may be X / 身份证：18 位，末位可为 X
		{typ: TypeIDCard, confidence: 0.99, boundary: boundaryDigit, validate: CNIDCardValid,
			re: regexp.MustCompile(`[0-9]{17}[0-9Xx]`)},

		// Mainland China mobile number / 中国大陆手机号
		{typ: TypePhone, confidence: 0.95, boundary: boundaryDigitSep,
			re: regexp.MustCompile(`1[3-9][0-9]{9}`)},
		// Landline: area code - number / 国内固话：区号-号码
		{typ: TypePhone, confidence: 0.90, boundary: boundaryDigitSep,
			re: regexp.MustCompile(`0[0-9]{2,3}-[0-9]{7,8}`)},
		// International: requires a leading +, otherwise far too noisy
		// 国际号码：必须带 + 前缀，否则误报率过高
		{typ: TypePhone, confidence: 0.90, boundary: boundaryDigit,
			re: regexp.MustCompile(`\+[0-9]{1,3}[\s\-]?[0-9]{6,14}`)},

		// Bank card: two shapes — four-digit groups, or a continuous run.
		// Deliberately not `(?:[0-9][ \-]?){12,19}`: that greedily crosses
		// separators, joining two adjacent runs into one match that must fail
		// the checksum, swallowing the real card number.
		// 银行卡：分「四位分组」与「连续数字」两种形态。刻意不用贪婪模式——
		// 那会跨越分隔符把相邻数字串连成一个必然校验失败的匹配，吞掉真卡号。
		{typ: TypeBankCard, confidence: 0.95, boundary: boundaryDigitSep,
			validate: LuhnValid, normalize: true,
			re: regexp.MustCompile(`[0-9]{4}(?:[ \-][0-9]{4}){2,4}`)},
		{typ: TypeBankCard, confidence: 0.95, boundary: boundaryDigitSep,
			validate: LuhnValid,
			re:       regexp.MustCompile(`[0-9]{12,19}`)},

		// Unified social credit code: must pass the check digit
		// 统一社会信用代码：必须过校验位
		{typ: TypeUSCC, confidence: 0.95, boundary: boundaryAlnum, validate: CNUSCCValid,
			re: regexp.MustCompile(`[0-9A-HJ-NPQRTUWXY]{2}[0-9]{6}[0-9A-HJ-NPQRTUWXY]{10}`)},

		// US Social Security Number / 美国社会安全号
		{typ: TypeSSN, confidence: 0.90, boundary: boundaryDigit,
			re: regexp.MustCompile(`[0-9]{3}-[0-9]{2}-[0-9]{4}`)},

		// Chinese passport / 中国护照
		{typ: TypePassport, confidence: 0.80, boundary: boundaryAlnum,
			re: regexp.MustCompile(`[EG][0-9]{8}`)},

		// License plate (incl. 8-char NEV) / 车牌（含新能源 8 位）
		{typ: TypeLicensePlate, confidence: 0.90, boundary: boundaryNone,
			re: regexp.MustCompile(`[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-HJ-NP-Z][A-HJ-NP-Z0-9]{4,6}[A-HJ-NP-Z0-9挂学警港澳]`)},

		// IPv4
		{typ: TypeIP, confidence: 0.75, boundary: boundaryDigit,
			re: regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])`)},

		// Keys and tokens: worst blast radius, prefer false positives
		// 各类密钥与令牌：泄露后果最严重，宁可误报
		{typ: TypeCredential, confidence: 0.99, boundary: boundaryNone,
			re: regexp.MustCompile(`sk-[A-Za-z0-9_\-]{16,}`)},
		{typ: TypeCredential, confidence: 0.99, boundary: boundaryNone,
			re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{typ: TypeCredential, confidence: 0.99, boundary: boundaryNone,
			re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`)},
		{typ: TypeCredential, confidence: 0.99, boundary: boundaryNone,
			re: regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)},
	}

	out := all[:0:0]
	for _, r := range all {
		if !disabled[r.typ] {
			out = append(out, r)
		}
	}
	return out
}

// RegexDetector detects structured identifiers via regex plus check digits.
// 基于正则加校验位检测结构化标识。
type RegexDetector struct {
	rules []rule
}

// NewRegexDetector builds the regex detector; rules can be disabled per type
// (an internal-network deployment may not need IP redaction, for example).
// 构造正则检测器，可按类型关闭部分规则（例如内网场景不必脱敏 IP）。
func NewRegexDetector(disabledTypes ...EntityType) *RegexDetector {
	disabled := make(map[EntityType]bool, len(disabledTypes))
	for _, t := range disabledTypes {
		disabled[t] = true
	}
	return &RegexDetector{rules: buildRules(disabled)}
}

// Name 返回检测器标识。
func (d *RegexDetector) Name() string { return "regex" }

// Detect scans rule by rule. Rules with a check digit only match when the check
// passes.
// 逐条规则扫描。带校验位的规则须通过校验才算命中。
//
// Uses bare-pattern matching plus manual boundary checks, avoiding both the
// missed detections caused by sentinel groups consuming adjacent characters and
// the "greedy match then failed check" case that pushes the scan past the real
// target.
// 采用裸模式匹配 + 手工边界检查，避免哨兵组消费相邻字符导致的漏检，
// 也避免「贪婪匹配 + 校验失败」把扫描位置推过真正目标。
func (d *RegexDetector) Detect(text string) ([]Entity, error) {
	var found []Entity
	for _, r := range d.rules {
		for _, loc := range r.re.FindAllStringIndex(text, -1) {
			start, end := loc[0], loc[1]
			if !isBoundaryOK(text, start, end, r.boundary) {
				continue
			}
			raw := text[start:end]
			if r.validate != nil {
				candidate := raw
				if r.normalize {
					candidate = stripSeparators(raw)
				}
				if !r.validate(candidate) {
					continue
				}
			}
			found = append(found, Entity{
				Type: r.typ, Value: raw, Start: start, End: end,
				Confidence: r.confidence, Detector: d.Name(),
			})
		}
	}
	return found, nil
}

// CoveredTypes returns the types this detector covers.
// 返回本检测器覆盖的类型。
func (d *RegexDetector) CoveredTypes() []EntityType {
	seen := map[EntityType]bool{}
	var out []EntityType
	for _, r := range d.rules {
		if !seen[r.typ] {
			seen[r.typ] = true
			out = append(out, r.typ)
		}
	}
	return out
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
	re            *regexp.Regexp
	types         map[string]EntityType
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
	d := &GazetteerDetector{
		types:         map[string]EntityType{},
		caseSensitive: caseSensitive,
	}
	var terms []string
	for typ, values := range entries {
		d.covered = append(d.covered, typ)
		for _, v := range values {
			term := strings.TrimSpace(v)
			if len([]rune(term)) < minLen {
				continue // short terms flood false positives / 过短词条会让误报泛滥
			}
			key := term
			if !caseSensitive {
				key = strings.ToLower(term)
			}
			d.types[key] = typ
			terms = append(terms, term)
		}
	}
	if len(terms) == 0 {
		return d, nil
	}
	sort.Slice(terms, func(i, j int) bool { return len(terms[i]) > len(terms[j]) })

	quoted := make([]string, len(terms))
	for i, t := range terms {
		quoted[i] = regexp.QuoteMeta(t)
	}
	pattern := strings.Join(quoted, "|")
	if !caseSensitive {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("名册正则编译失败: %w", err)
	}
	d.re = re
	sort.Slice(d.covered, func(i, j int) bool { return d.covered[i] < d.covered[j] })
	return d, nil
}

// Name 返回检测器标识。
func (d *GazetteerDetector) Name() string { return "gazetteer" }

// Detect scans for gazetteer hits.
// 扫描名册命中项。
func (d *GazetteerDetector) Detect(text string) ([]Entity, error) {
	if d.re == nil {
		return nil, nil
	}
	var found []Entity
	for _, loc := range d.re.FindAllStringIndex(text, -1) {
		raw := text[loc[0]:loc[1]]
		key := raw
		if !d.caseSensitive {
			key = strings.ToLower(raw)
		}
		typ, ok := d.types[key]
		if !ok {
			continue
		}
		found = append(found, Entity{
			Type: typ, Value: raw, Start: loc[0], End: loc[1],
			Confidence: 0.98, Detector: d.Name(),
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
	detectors     []Detector
	minConfidence float64
	warnOnce      sync.Once
	missing       []EntityType
}

// NewCompositeDetector combines detectors, recording any name-class coverage
// gap so it can be surfaced — the most dangerous silent misconfiguration.
// 组合若干检测器。缺少姓名类检测能力时记录缺口——这是最危险的静默配置。
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
func (d *CompositeDetector) Name() string { return "composite" }

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
	ordered := make([]Entity, len(entities))
	copy(ordered, entities)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Len() != ordered[j].Len() {
			return ordered[i].Len() > ordered[j].Len()
		}
		if ordered[i].Confidence != ordered[j].Confidence {
			return ordered[i].Confidence > ordered[j].Confidence
		}
		return ordered[i].Start < ordered[j].Start
	})

	var accepted []Entity
	for _, e := range ordered {
		conflict := false
		for _, kept := range accepted {
			if e.Overlaps(kept) {
				conflict = true
				break
			}
		}
		if !conflict {
			accepted = append(accepted, e)
		}
	}
	sort.Slice(accepted, func(i, j int) bool { return accepted[i].Start < accepted[j].Start })
	return accepted
}
