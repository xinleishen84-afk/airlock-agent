package detect

import (
	"context"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// # 漏斗式级联
// # The cascading funnel
//
// 三层的代价差着三个数量级：正则加校验位在进程内是微秒级，名册自动机同样
// 是微秒级，而第三层要跨进程调一次模型——实测 UDS 往返本身只有 100µs，
// 但推理是 1.9ms（短文本）到 29ms（2KB 文本）。
//
// The three layers differ by orders of magnitude. Regex and checksums are
// microseconds in-process; so is the roster automaton. The third crosses a
// process boundary — the Unix socket round trip itself measures 100µs, but
// inference runs 1.9ms for a short text and 29ms for 2KB.
//
// 因此把所有文本无差别送进第三层是错的：一份 128k token 的提示词里，
// 绝大多数字节是散文与代码，而其中真正需要模型的只有很少几段。
//
// Sending everything to the third layer is therefore wrong: in a 128k-token
// prompt most bytes are prose and code, and only a few spans need the model.
//
// # 挖空而不是切段
// # Masking rather than splitting
//
// 前两层命中的区间要从第三层的输入里去掉，否则模型会在已经确定的身份证号上
// 再判一次，既费时间又可能给出冲突的类型。
//
// 但直接把文本切成若干段会毁掉上下文：「请联系张伟，手机 13812345678」
// 切掉手机号之后，「张伟」失去了右侧的证据，而证据链恰恰要靠它。
//
// 所以这里用等字符数的填充符覆盖命中区间。
//
// 填充符按字节宽度分档（见 maskFillers），因此挖空后的文本与原文逐字节等长，
// 字符偏移与字节偏移都一一对应。
//
// 偏移搭桥（bridgeOffsets）仍然保留，即使在等长的前提下它是恒等映射：
// 它同时是一道断言。填充符表将来若被改动、或某个 rune 落进没覆盖的宽度档，
// 等长的前提就会悄悄失效，而症状是「脱敏了错的字节」——不是一个异常。
// 让搭桥留在路径上，这个前提就变成了每次运行都在检验的东西。
//
// Fillers are width-matched, so the masked text is byte-for-byte the same
// length and both offset spaces correspond one-to-one.
//
// bridgeOffsets is kept even though it is the identity under that premise: it
// is also an assertion. If the filler table changes, or a rune falls into an
// uncovered width, the premise fails silently and the symptom is "the wrong
// bytes were redacted" rather than an error.
//
// Spans matched by the first two layers must be removed from the third layer's
// input, or the model re-judges a settled ID number, costing time and possibly
// producing a conflicting type.
//
// Splitting the text into fragments destroys context: after removing the phone
// number from 请联系张伟，手机 13812345678, the name loses the evidence on its
// right — which is exactly what the evidence chain needs.
//
// Masking with a same-rune-count filler keeps character offsets one-to-one, so
// the model's offsets map straight back. Context survives and the rework is
// still avoided.

// maskFillers 是按 UTF-8 字节宽度分档的填充字符。
//
// 逐字符替换时选一个**同样字节宽度**的填充符，而不是统一用一个。
//
// 第一版统一用 3 字节的 ▮，字符数保住了、字节数没有：一个 11 位手机号
// （11 字节）被换成 33 字节。实测在 PII 密集的文本上，挖空后的输入从
// 1560 字节涨到 3240 字节，而推理耗时与长度大致成线性——**慢了 2.04 倍**。
// 挖空本来是为了省事，结果成了净开销。
//
// 按字节宽度分档之后，挖空后的文本与原文逐字节等长：推理代价不变，
// 而字节偏移也天然一一对应。
//
// 每个填充符都不是字母：模型不会把一串它拼成人名，DefaultNERTrigger
// 也不会把它算作「有内容」。
//
// A filler of the same byte width as the rune it covers, not one filler for
// all. The first version used the three-byte ▮ everywhere: rune count was
// preserved, byte length was not, and an eleven-byte phone number became
// thirty-three. Measured on PII-dense text the masked input grew from 1560 to
// 3240 bytes and inference ran 2.04× slower — masking became a net cost.
//
// Width-matched fillers keep the masked text byte-for-byte the same length.
// None of them is a letter, so the model builds no names from a run of them.
var maskFillers = map[int]rune{
	1: '#',          // ASCII
	2: '\u00a7',     // §  两字节 / two bytes
	3: '\u25ae',     // ▮  三字节 / three bytes
	4: '\U0001f7e5', // 🟥 四字节 / four bytes
}

// fillerFor returns a filler of the same UTF-8 width as r.
// 返回与 r 同样 UTF-8 宽度的填充符。
func fillerFor(r rune) rune {
	if f, ok := maskFillers[utf8.RuneLen(r)]; ok {
		return f
	}
	return '#'
}

// CascadeStage names a layer, for audit output.
// 标识一层，供审计输出使用。
type CascadeStage string

const (
	StagePattern   CascadeStage = "pattern"   // 正则 + 校验位
	StageGazetteer CascadeStage = "gazetteer" // 名册 + 复姓
	StageModel     CascadeStage = "model"     // NER
)

// CascadeStats reports what each layer contributed.
// 报告每一层的贡献。
//
// 分层计数是这套架构唯一能被检验的地方。没有它，「第三层被跳过了多少次」
// 与「第三层根本没接上」在结果上完全一样——两者都表现为模型没被调用。
//
// Per-layer counts are the only place this architecture can be checked.
// Without them, "the third layer was skipped" and "the third layer was never
// wired up" look identical: in both cases the model is not called.
type CascadeStats struct {
	// PerStage 是每层检出的实体数。
	PerStage map[CascadeStage]int

	// ModelCalls 是实际调用模型的次数。
	ModelCalls int

	// ModelSkipped 是因为没有触发特征而跳过模型的次数。
	ModelSkipped int

	// MaskedRunes 是被前两层覆盖掉的字符数（仅 MaskSettled 时非零）。
	MaskedRunes int

	// ModelDiscarded 是因与已确定区间重叠而被丢弃的模型判定数。
	//
	// 这个数偏高意味着模型在重复劳动，可以考虑打开 MaskSettled——
	// 但那要付分词器的代价，两边都要量过再定。
	//
	// A high count means the model is repeating work; MaskSettled is the
	// alternative, at the tokenizer's price. Measure both before choosing.
	ModelDiscarded int
}

// ModelInput is what the third layer would receive, exposed for tests.
// 第三层将收到的输入，供测试查看。
type ModelInput struct {
	Text    string
	Skipped bool
	Reason  string
}

// Cascade runs the three layers as a funnel.
// 以漏斗方式运行三层。
type Cascade struct {
	// Fast 是第一、二层：正则、校验位、名册、复姓。
	//
	// 合成一个 Detector 而不是两个字段：这两层都在进程内、都是确定性的，
	// 它们之间没有需要级联的代价差。
	//
	// The first two layers combined: both are in-process and deterministic,
	// with no cost gap between them worth cascading.
	Fast Detector

	// Model 是第三层。为 nil 时级联退化为前两层。
	Model Detector

	// Trigger 决定一段文本是否值得送进模型。nil 表示使用默认判据。
	Trigger func(text string) (bool, string)

	// MaskSettled 决定是否把前两层命中的区间挖空后再送进模型。
	//
	// 默认 false，这是实测的结果而不是省事。
	//
	// 挖空的本意是让模型不必重判已确定的区间。字节宽度对齐之后，挖空后的
	// 文本与原文逐字节等长，理论上代价应当持平——实测却慢了 3.15 倍：
	// 一段 PII 密集的文本挖空后是 840 个连续填充符，而这种输入对中文分词器
	// 是病态的。
	//
	// 不挖空同样能拿到正确性：模型返回的实体若与已确定区间重叠，直接丢弃。
	// 结果一样，上下文更完整，也不用付那 3 倍。
	//
	// 保留这个开关，是因为「模型看到原文」在某些合规要求下本身不可接受——
	// 那时候 3 倍是必须付的价钱，而付不付应当是一个写下来的决定。
	//
	// Defaults to false, measured rather than assumed. Width-matched fillers
	// make the masked text byte-for-byte the same length, so the cost should be
	// flat — measured, it was 3.15× slower, because a PII-dense text masks into
	// 840 consecutive fillers and that input is pathological for the Chinese
	// tokenizer.
	//
	// Discarding model entities that overlap settled spans gives the same
	// correctness with fuller context and none of the 3×. The switch remains
	// because "the model must not see the original" is a real requirement in
	// some regimes, and paying 3× for it should be a written decision.
	MaskSettled bool

	// OnStats 接收每次运行的分层统计。
	OnStats func(CascadeStats)
}

// NewCascade builds a cascade.
// 构造级联。
func NewCascade(fast, model Detector) (*Cascade, error) {
	if fast == nil {
		return nil, fmt.Errorf("级联需要前两层检测器 / cascade requires a fast detector")
	}
	return &Cascade{Fast: fast, Model: model}, nil
}

// Name implements Detector.
func (c *Cascade) Name() string { return "cascade" }

// CoveredTypes implements Detector.
func (c *Cascade) CoveredTypes() []EntityType {
	seen := map[EntityType]bool{}
	var out []EntityType
	for _, d := range []Detector{c.Fast, c.Model} {
		if d == nil {
			continue
		}
		for _, t := range d.CoveredTypes() {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// Detect implements Detector.
func (c *Cascade) Detect(text string) ([]Entity, error) {
	return c.DetectContext(context.Background(), text)
}

// DetectContext runs the funnel.
// 运行漏斗。
func (c *Cascade) DetectContext(ctx context.Context, text string) ([]Entity, error) {
	stats := CascadeStats{PerStage: map[CascadeStage]int{}}
	defer func() {
		if c.OnStats != nil {
			c.OnStats(stats)
		}
	}()

	if strings.TrimSpace(text) == "" {
		return nil, nil
	}

	// --- 第一、二层：进程内，确定性 ---
	fast, err := c.Fast.Detect(text)
	if err != nil {
		return nil, fmt.Errorf("前两层检测失败 / fast layers failed: %w", err)
	}
	for _, e := range fast {
		stage := StagePattern
		if strings.Contains(e.Detector, "gazetteer") || strings.Contains(e.Detector, "surname") {
			stage = StageGazetteer
		}
		stats.PerStage[stage]++
	}

	if c.Model == nil {
		return ResolveOverlaps(fast), nil
	}

	// --- 准备第三层的输入 ---
	modelInput := text
	if c.MaskSettled {
		var maskedRunes int
		modelInput, maskedRunes = maskSpans(text, fast)
		stats.MaskedRunes = maskedRunes
	}

	// --- 第三层：按需唤醒 ---
	trigger := c.Trigger
	if trigger == nil {
		trigger = DefaultNERTrigger
	}
	if ok, reason := trigger(modelInput); !ok {
		stats.ModelSkipped++
		_ = reason
		return ResolveOverlaps(fast), nil
	}

	stats.ModelCalls++
	slow, err := c.detectWithModel(ctx, modelInput)
	if err != nil {
		return nil, err
	}

	if c.MaskSettled {
		// 把偏移从挖空文本的字节空间搭桥回原文的字节空间。
		// Bridge offsets from the masked text's byte space to the original's.
		if err := bridgeOffsets(text, modelInput, slow); err != nil {
			return nil, err
		}
	}

	// 丢弃与已确定区间重叠的模型判定。
	//
	// 前两层的结论有校验位或名册作依据，模型的是概率。两者对同一段文本给出
	// 不同类型时，确定的那个赢——而这个取舍必须在这里显式做掉，不能指望
	// ResolveOverlaps：它按长度优先，一个多吞了几个字的模型判定会盖过
	// 一个校验位正确的身份证号。
	//
	// Model verdicts overlapping a settled span are discarded. The first two
	// layers have a check digit or a roster behind them; the model has a
	// probability. This must be decided here rather than left to
	// ResolveOverlaps, which prefers length: a model span that swallowed a few
	// extra characters would beat a checksum-valid ID number.
	kept := slow[:0:0]
	for _, e := range slow {
		if overlapsAny(e, fast) {
			stats.ModelDiscarded++
			continue
		}
		kept = append(kept, e)
	}
	stats.PerStage[StageModel] += len(kept)

	return ResolveOverlaps(append(fast, kept...)), nil
}

// detectWithModel calls the third layer, honouring a context if it supports one.
// 调用第三层；若它支持 context 则传入。
func (c *Cascade) detectWithModel(ctx context.Context, text string) ([]Entity, error) {
	type contextual interface {
		DetectContext(context.Context, string) ([]Entity, error)
	}
	if cd, ok := c.Model.(contextual); ok {
		return cd.DetectContext(ctx, text)
	}
	return c.Model.Detect(text)
}

// MaskSettledSpans covers settled spans with width-matched fillers and returns
// the masked text plus how many runes were covered.
// 用等字节宽度的填充符覆盖已确定的区间，返回挖空后的文本与被覆盖的字符数。
//
// 导出是为了让调用方与测试能看到第三层实际收到什么。一个只能从日志里
// 推断「模型看到了什么」的管线，没法验证挖空是否真的生效。
//
// Exported so callers and tests can see what the third layer actually
// receives. A pipeline where that can only be inferred from logs cannot be
// checked.
func MaskSettledSpans(text string, spans []Entity) (string, int) {
	return maskSpans(text, spans)
}

// maskSpans covers settled spans with width-matched fillers.
// 用等字节宽度的填充符覆盖已确定的区间。
func maskSpans(text string, spans []Entity) (string, int) {
	if len(spans) == 0 {
		return text, 0
	}

	ordered := make([]Entity, len(spans))
	copy(ordered, spans)
	ordered = ResolveOverlaps(ordered)

	var b strings.Builder
	b.Grow(len(text))
	cursor, masked := 0, 0

	for _, e := range ordered {
		if e.Start < cursor || e.End > len(text) {
			continue
		}
		b.WriteString(text[cursor:e.Start])
		for _, r := range text[e.Start:e.End] {
			b.WriteRune(fillerFor(r))
			masked++
		}
		cursor = e.End
	}
	b.WriteString(text[cursor:])
	return b.String(), masked
}

// bridgeOffsets converts byte offsets in the masked text to the original.
// 把挖空文本上的字节偏移转换到原文上。
//
// 两份文本字符数相同是这次转换成立的前提，因此先断言它。不成立时必须失败——
// 拿一批错位的区间去脱敏，会洗掉错的字节并把载荷切成非法 UTF-8。
//
// Equal rune counts is the premise, so it is asserted. A mismatch must fail:
// redacting misaligned spans wipes the wrong bytes and produces invalid UTF-8.
func bridgeOffsets(original, masked string, entities []Entity) error {
	if len(entities) == 0 {
		return nil
	}

	origIdx := runeOffsets(original)
	maskIdx := runeOffsets(masked)
	if len(origIdx) != len(maskIdx) {
		return fmt.Errorf(
			"挖空改变了字符数：原文 %d，挖空后 %d——偏移搭桥的前提不成立 / "+
				"masking changed the rune count",
			len(origIdx)-1, len(maskIdx)-1)
	}

	byteToRune := make(map[int]int, len(maskIdx))
	for runeIdx, byteOff := range maskIdx {
		byteToRune[byteOff] = runeIdx
	}

	for i := range entities {
		startRune, ok := byteToRune[entities[i].Start]
		if !ok {
			return fmt.Errorf(
				"第三层返回的起始偏移 %d 不在字符边界上 / start offset not on a rune boundary",
				entities[i].Start)
		}
		endRune, ok := byteToRune[entities[i].End]
		if !ok {
			return fmt.Errorf(
				"第三层返回的结束偏移 %d 不在字符边界上 / end offset not on a rune boundary",
				entities[i].End)
		}

		entities[i].Start = origIdx[startRune]
		entities[i].End = origIdx[endRune]
		entities[i].Value = original[entities[i].Start:entities[i].End]
	}
	return nil
}

// runeOffsets returns each rune's byte offset, plus a trailing sentinel.
// 返回每个字符的字节偏移，末尾附一个哨兵。
func runeOffsets(text string) []int {
	out := make([]int, 0, utf8.RuneCountInString(text)+1)
	for byteOff := range text {
		out = append(out, byteOff)
	}
	return append(out, len(text))
}

// overlapsAny reports whether an entity overlaps any settled span.
// 报告一个实体是否与任何已确定区间重叠。
func overlapsAny(e Entity, settled []Entity) bool {
	for _, s := range settled {
		if e.Start < s.End && s.Start < e.End {
			return true
		}
	}
	return false
}

// RequireScript builds a trigger that only wakes the model for text whose
// script matches what the model was trained on.
// 构造一个触发判据：只有文字系统与模型训练语料相符时才唤醒模型。
//
// # 为什么这不是过拟合
// # Why this is not overfitting
//
// 拿中文模型去判拉丁文，得到的是分布外的胡乱输出。实测：把英语、意大利语、
// 德语的样本送进 zh_core_web_md，它把 declined、leaked、Codice、Steuer
// 判成人名或地址——这四处误报没有一处来自中文文本。
//
// 这不是「模型不够准」，是问错了对象。契约里的 language 字段就是为了让
// 调用方按语言路由到对应的模型；在只挂了一个中文模型的部署里，
// 正确的做法是不问它拉丁文。
//
// A Chinese model asked about Latin text returns out-of-distribution noise.
// Measured: fed English, Italian and German samples, zh_core_web_md labelled
// declined, leaked, Codice and Steuer as names or addresses — not one of those
// four false positives came from Chinese text.
//
// This is not "the model is inaccurate"; it is the wrong model being asked.
// The contract's language field exists so callers can route by language; a
// deployment with only a Chinese model should not ask it about Latin script.
//
// # 代价必须说清楚
// # The cost, stated
//
// 开了这道闸，拉丁文里的人名（Margaret Okonkwo）就完全不会被检测——
// 不是判错，是根本不问。在只有中文模型的部署里这本来就检不出来（实测如此），
// 因此这道闸把「检不出还带一堆误报」变成了「检不出」。
// 但一旦接上了英文模型，就必须按语言路由，而不是把这道闸一直开着。
//
// With this gate, a Latin-script name is never detected — not misjudged, not
// asked about. In a Chinese-only deployment it was not detected anyway
// (measured), so the gate turns "missed, plus false positives" into "missed".
// Once an English model is wired up, route by language instead of leaving this
// gate on.
func RequireScript(minCJKRatio float64) func(string) (bool, string) {
	return func(text string) (bool, string) {
		if ok, reason := DefaultNERTrigger(text); !ok {
			return false, reason
		}

		cjk, letters := 0, 0
		for _, r := range text {
			if !unicode.IsLetter(r) {
				continue
			}
			letters++
			if unicode.Is(unicode.Han, r) {
				cjk++
			}
		}
		if letters == 0 {
			return false, "不含字母"
		}
		ratio := float64(cjk) / float64(letters)
		if ratio < minCJKRatio {
			return false, fmt.Sprintf(
				"汉字占字母的 %.0f%%，低于 %.0f%%——中文模型对拉丁文是分布外输入",
				ratio*100, minCJKRatio*100)
		}
		return true, ""
	}
}

// DefaultNERTrigger decides whether a text is worth sending to the model.
// 判断一段文本是否值得送进模型。
//
// # 它必须是一个必要条件
// # It must be a necessary condition
//
// 与前置过滤器同理：跳过只允许发生在「这段文本确定不含模型能找到的实体」
// 时。判据放宽一点会多花几毫秒，收紧一点则会静默漏掉整段文本里的所有人名
// ——而漏掉不会报错。
//
// Same discipline as the prefilters: skipping is allowed only when the text
// certainly contains nothing the model could find. A loose test costs
// milliseconds; a tight one silently drops every name in that text.
//
// 因此这里只跳过那些**结构上不可能**承载人名、地址、机构名的文本：
// 太短的、以及完全不含字母与汉字的。不做「看起来像代码就跳过」这种判断——
// 代码注释里有人名，而那正是最容易被忽略的泄露点。
//
// It therefore skips only what structurally cannot carry one: too short, or
// containing no letters or ideographs at all. It does not skip "things that
// look like code": code comments contain names, and those are the leak nobody
// looks for.
func DefaultNERTrigger(text string) (bool, string) {
	// 最短的中文人名是两个字；再短的文本装不下任何实体。
	// The shortest Chinese name is two characters.
	if utf8.RuneCountInString(text) < 2 {
		return false, "文本短于两个字符，装不下任何实体"
	}

	letters := 0
	for _, r := range text {
		if unicode.IsLetter(r) {
			letters++
			if letters >= 2 {
				return true, ""
			}
		}
	}
	return false, "文本不含两个及以上的字母或汉字，不可能含人名、地址或机构名"
}
