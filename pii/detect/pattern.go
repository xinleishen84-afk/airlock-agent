package detect

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// PatternRecognizer recognizes one entity type by regex, optionally boosted by
// surrounding context words.
// 用正则识别一种实体，可选地按上下文词加权。
//
// # Why context matters
// # 为什么需要上下文
//
// Structured identifiers are ambiguous on their own. A 16-digit run could be a
// bank card, an order number, or a device serial. The checksum filters some of
// it, but plenty of order numbers happen to pass Luhn.
// 结构化标识单看是有歧义的。16 位数字可能是银行卡、订单号或设备序列号。
// 校验位能滤掉一部分，但相当多的订单号恰好能通过 Luhn。
//
// The surrounding words carry the disambiguating signal:
// 周围的词才带着区分性的信号：
//
//	"卡号 4111111111111111"    -> almost certainly a card / 几乎必然是卡号
//	"订单号 4111111111111111"  -> almost certainly not / 几乎必然不是
//
// Context words raise confidence when present; their absence never lowers the
// base score below the configured floor. Boosting up is safe; penalizing down
// would silently drop real PII that simply had no nearby keyword.
// 命中上下文词时提升置信度；未命中则不低于配置的基线。
// 向上加权是安全的；向下惩罚会静默漏掉「恰好附近没有关键词」的真实 PII。
type PatternRecognizer struct {
	// prefilter is a necessary condition checked before the regex. It may only
	// produce false positives; a false negative would silently disable this
	// recognizer.
	// 是在正则之前检查的必要条件。它只允许产生假阳性；
	// 假阴性会静默禁用本识别器。
	prefilter Prefilter

	name       string
	entityType EntityType
	pattern    *regexp.Regexp
	boundary   BoundaryClass
	validate   validatorFunc
	normalize  bool

	baseScore    float64
	contexts     []string
	contextBoost float64
	// requireContext turns the context words into a necessary condition.
	// 让上下文词成为必要条件。
	requireContext bool
	// contextWindow is how many bytes on either side are scanned for context
	// words. Too wide and unrelated text leaks in; too narrow and a natural
	// phrasing like "the customer's card number is ..." falls outside.
	// 是左右各扫描多少字节找上下文词。太宽会把无关文本算进来；
	// 太窄则「客户的银行卡号是……」这类自然表述会落在窗口之外。
	contextWindow int
}

// PatternOption configures a PatternRecognizer.
// 配置 PatternRecognizer。
type PatternOption func(*PatternRecognizer)

// WithValidator attaches a post-check that narrows "looks like" into
// "actually is" (Luhn, GB 11643, GB 32100).
// 附加后置校验，把「看起来像」收紧为「确实是」（Luhn、GB 11643、GB 32100）。
func WithValidator(fn func(string) bool, stripSeparators bool) PatternOption {
	return func(p *PatternRecognizer) {
		p.validate = fn
		p.normalize = stripSeparators
	}
}

// WithPrefilter attaches a cheap necessary condition evaluated before the regex.
// 附加一个在正则之前求值的廉价必要条件。
//
// The condition must be strictly implied by the pattern. Attaching one the
// pattern does not require silently disables the recognizer for any text that
// fails it — the exact failure this system exists to prevent.
// 该条件必须由模式严格蕴含。附加一个模式并不要求的条件，
// 会让任何不满足它的文本静默跳过本识别器——正是本系统要防的那种故障。
func WithPrefilter(f Prefilter) PatternOption {
	return func(p *PatternRecognizer) { p.prefilter = f }
}

// WithBoundary sets the character class forbidden on either side of a match.
// 设置匹配两侧不允许出现的字符类。
func WithBoundary(class BoundaryClass) PatternOption {
	return func(p *PatternRecognizer) { p.boundary = class }
}

// WithContext attaches context words and the confidence boost applied when one
// of them appears nearby.
// 附加上下文词，以及命中时施加的置信度提升。
//
// Words are matched case-insensitively. For Chinese, word boundaries are not
// meaningful, so a substring match within the window is used.
// 词匹配不区分大小写。中文没有有意义的词边界，因此在窗口内做子串匹配。
func WithContext(boost float64, words ...string) PatternOption {
	return func(p *PatternRecognizer) {
		p.contexts = append(p.contexts, words...)
		p.contextBoost = boost
	}
}

// WithContextWindow overrides how far context words are searched (bytes).
// 覆盖上下文词的搜索距离（字节）。
func WithContextWindow(bytes int) PatternOption {
	return func(p *PatternRecognizer) { p.contextWindow = bytes }
}

// NewPatternRecognizer builds a regex-based recognizer.
// 构造基于正则的识别器。
func NewPatternRecognizer(
	name string, entityType EntityType, expr string, baseScore float64,
	opts ...PatternOption,
) (*PatternRecognizer, error) {
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("识别器 %s 的正则非法 / invalid regex for %s: %w", name, name, err)
	}
	if baseScore <= 0 || baseScore > 1 {
		return nil, fmt.Errorf("识别器 %s 的基线分须在 (0,1] / base score for %s must be in (0,1]",
			name, name)
	}
	p := &PatternRecognizer{
		name: name, entityType: entityType, pattern: re,
		baseScore: baseScore, contextWindow: 48,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// Name returns the recognizer identifier.
// 返回识别器标识。
// Pattern returns the compiled regex, for building a combined scan gate.
// 返回已编译的正则，供构建合并扫描门控使用。
func (p *PatternRecognizer) Pattern() *regexp.Regexp { return p.pattern }

func (p *PatternRecognizer) Name() string { return p.name }

// EntityType returns the entity type produced.
// 返回产出的实体类型。
func (p *PatternRecognizer) EntityType() EntityType { return p.entityType }

// Recognize finds matches, applies the check digit, then adjusts confidence by
// surrounding context.
// 查找匹配、执行校验位，再按周围上下文调整置信度。
func (p *PatternRecognizer) Recognize(text string) ([]Entity, error) {
	// Rule the text out before paying for the regex. On a realistic prompt most
	// recognizers exit here, and the saving is the difference between scanning
	// the text once and scanning it once per recognizer.
	// 在付出正则代价之前先排除。真实提示词下多数识别器在此退出，
	// 省下的正是「扫一遍」与「每个识别器各扫一遍」之间的差距。
	if p.prefilter != nil && !p.prefilter(text) {
		return nil, nil
	}

	var found []Entity
	for _, loc := range p.pattern.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]
		if !isBoundaryOK(text, start, end, p.boundary) {
			continue
		}
		raw := text[start:end]
		if p.validate != nil {
			candidate := raw
			if p.normalize {
				candidate = stripSeparators(raw)
			}
			if !p.validate(candidate) {
				continue
			}
		}

		score := p.baseScore
		if p.hasContext(text, start, end) {
			score += p.contextBoost
			if score > 1 {
				score = 1
			}
		} else if p.requireContext {
			// 这个类型的裸形态与常见的无害文本字面相同，
			// 上下文是唯一可用的信号。见 WithRequiredContext。
			// This type's bare form is lexically identical to common harmless
			// text; context is the only signal available.
			continue
		}
		found = append(found, Entity{
			Type: p.entityType, Value: raw, Start: start, End: end,
			Confidence: score, Detector: p.name,
		})
	}
	return found, nil
}

// hasContext reports whether any context word appears within the window around
// the match.
// 判断窗口内是否出现了任一上下文词。
func (p *PatternRecognizer) hasContext(text string, start, end int) bool {
	if len(p.contexts) == 0 {
		return false
	}
	lo := start - p.contextWindow
	if lo < 0 {
		lo = 0
	}
	hi := end + p.contextWindow
	if hi > len(text) {
		hi = len(text)
	}
	// Snap to rune boundaries so a window edge cannot split a multi-byte
	// character and corrupt the substring search.
	// 对齐到字符边界，避免窗口边缘切开多字节字符、破坏子串查找。
	for lo > 0 && !utf8Start(text[lo]) {
		lo--
	}
	for hi < len(text) && !utf8Start(text[hi]) {
		hi++
	}

	window := strings.ToLower(text[lo:hi])
	for _, word := range p.contexts {
		if strings.Contains(window, strings.ToLower(word)) {
			return true
		}
	}
	return false
}

// utf8Start reports whether b is the first byte of a UTF-8 rune.
// 判断 b 是否为一个 UTF-8 字符的首字节。
func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// GazetteerRecognizer wraps a gazetteer as a single-type Recognizer.
// 把名册包装成单一类型的 Recognizer。
type GazetteerRecognizer struct {
	name       string
	entityType EntityType
	inner      *GazetteerDetector
}

// NewGazetteerRecognizer builds a recognizer from a term list.
// 从词条表构造识别器。
func NewGazetteerRecognizer(name string, entityType EntityType, terms []string) (*GazetteerRecognizer, error) {
	inner, err := NewGazetteerDetector(map[EntityType][]string{entityType: terms}, false, 2)
	if err != nil {
		return nil, err
	}
	return &GazetteerRecognizer{name: name, entityType: entityType, inner: inner}, nil
}

// Name returns the recognizer identifier.
// 返回识别器标识。
func (g *GazetteerRecognizer) Name() string { return g.name }

// EntityType returns the entity type produced.
// 返回产出的实体类型。
func (g *GazetteerRecognizer) EntityType() EntityType { return g.entityType }

// Recognize scans for roster hits.
// 扫描名册命中项。
func (g *GazetteerRecognizer) Recognize(text string) ([]Entity, error) {
	found, err := g.inner.Detect(text)
	if err != nil {
		return nil, err
	}
	for i := range found {
		found[i].Detector = g.name
	}
	return found, nil
}

// isWordChar reports whether r can be part of an ASCII word, used by callers
// that need their own boundary logic.
// 判断 r 是否可作为 ASCII 单词的一部分，供需要自定义边界逻辑的调用方使用。
func isWordChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

// WithoutPrefilter returns a copy with the prefilter removed.
// 返回一个摘掉前置过滤器的副本。
//
// Exists so tests outside this package can prove the prefilter changes only
// speed and never results. The prefilter is the one optimisation here that can
// silently cause a miss, so the equivalence has to be testable from wherever
// the recognizers are actually defined.
// 它的存在是为了让包外的测试能证明前置过滤只影响速度、绝不影响结果。
// 前置过滤是这里唯一可能静默导致漏检的优化，
// 因此这个等价性必须能在识别器真正定义的地方被检验。
func (p *PatternRecognizer) WithoutPrefilter() *PatternRecognizer {
	clone := *p
	clone.prefilter = nil
	return &clone
}

// WithRequiredContext makes a nearby context word a necessary condition rather
// than a confidence boost.
// 让附近出现上下文词成为必要条件，而不是置信度加权。
//
// # When this is the right tool, and when it is a mistake
// # 什么时候它是对的工具，什么时候是个错误
//
// WithContext boosts and never penalizes, because for a format with a
// distinctive shape the absence of a keyword says nothing — a card number is a
// card number whether or not the sentence mentions cards, and penalizing it
// would drop real PII that simply had no nearby keyword.
// WithContext 只加权、不惩罚，因为对形态独特的格式而言，
// 没有关键词什么也说明不了——一个卡号无论句子里提不提「卡」都是卡号，
// 惩罚它会漏掉「恰好附近没有关键词」的真实 PII。
//
// This option is for the other case: a format that is lexically identical to
// something common and harmless. An IPv4 address and a four-segment version
// number are the same string — 5.15.0.91 is a valid address and a plausible
// kernel version, and no pattern can separate them because there is nothing to
// separate. Context is the only signal available, so for these types it has to
// be a condition rather than a hint.
// 本选项用于另一种情形：某个格式与常见且无害的东西在字面上完全相同。
// IPv4 地址与四段式版本号就是同一个字符串——5.15.0.91 既是合法地址，
// 也是像模像样的内核版本号，而没有任何模式能把它们分开，
// 因为根本没有可分的东西。上下文是唯一可用的信号，
// 因此对这类类型它必须是条件而非提示。
//
// The cost is real and must be stated: an address in a bare log line with no
// surrounding words will be missed. That is a false negative bought
// deliberately, in exchange for not reporting every version string in every
// changelog as personal data.
// 代价是真实的，必须说明：一条没有任何周边文字的裸日志行里的地址会被漏掉。
// 这是一次刻意买下的漏报，换来的是不再把每份变更日志里的每个版本号
// 都报成个人数据。
func WithRequiredContext(words ...string) PatternOption {
	return func(p *PatternRecognizer) {
		p.contexts = append(p.contexts, words...)
		p.requireContext = true
		if p.contextBoost == 0 {
			p.contextBoost = 0.05
		}
	}
}
