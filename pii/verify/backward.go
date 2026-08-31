package verify

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// # 逆向边界补全
// # Backward boundary completion
//
// 地址与机构名的截断方向是相反的，因此不能用同一套机制补。
//
// Addresses and organization names truncate in opposite directions.
//
//   地址：模型给出「北京市」，丢的是后面的门牌 —— 向后拉伸
//   机构：模型给出「科技有限公司」，丢的是前面的字号 —— 向前拉伸
//
// 而丢掉的那一半恰恰是要紧的那一半：「科技有限公司」在中国有几十万家，
// 它不识别任何一家；「星辰科技有限公司」才识别一家。脱敏掉通名、留下字号，
// 等于什么都没脱敏，而审计日志会显示 ORG:1，看起来一切正常。
//
// The dropped half is the identifying half: 科技有限公司 matches hundreds of
// thousands of companies and identifies none; 星辰科技有限公司 identifies one.
// Redacting the generic suffix while leaving the distinctive head redacts
// nothing, and the audit log reads ORG:1.
//
// # 为什么向前比向后难
// # Why leftward is harder than rightward
//
// 向后拉伸有天然的终点：门牌特征字（号、室、层）本身就是收尾信号。
// 向前没有对应的东西——字号可以是任意词，「星辰」「临安远景」「阿里巴巴」
// 之间没有共同的字面特征。
//
// Rightward extension has natural terminators: 号, 室, 层 are themselves the
// signal to stop. Leftward has no equivalent — a distinctive name can be any
// word, with no shared lexical feature.
//
// 所以这里反过来做：先用 Aho-Corasick 确定这个实体确实以机构通名结尾
// （锚点），再向左滑窗，靠**停止字**划出候选边界，最后用邻近度评分决定
// 这次扩展是否可信。锚点让「要不要扩」是确定的，评分让「扩到哪」有依据。
//
// So the direction is inverted: an Aho-Corasick pass first confirms the entity
// ends in a generic organizational suffix (the anchor); a leftward window then
// bounds the candidate by stop characters; and a proximity score decides
// whether the extension is trustworthy. The anchor makes "extend or not"
// deterministic; the score makes "extend to where" evidenced.

// BackwardExtension stretches an entity's start leftward from an anchor.
// 从锚点出发把实体起点向左拉伸。
type BackwardExtension struct {
	// Anchors 是机构通名。实体必须以其中之一结尾才考虑扩展。
	//
	// 这一条是整个机制的闸门：不以通名结尾的实体，前面丢了什么无从判断，
	// 强行向左扩只会把动词和主语一起吞进来。
	//
	// The entity must end with one of these to be considered. Without that
	// gate, leftward extension has nothing to anchor on and swallows the verb
	// and subject before it.
	Anchors []string

	// AdministrativeMarkers 是行政区划特征字，出现在扩展段里加分。
	// Administrative-division markers; their presence in the extension scores.
	AdministrativeMarkers []string

	// IndustryMarkers 是行业修饰词，出现在扩展段里加分。
	IndustryMarkers []string

	// MinScore 是接受扩展所需的邻近度得分。
	MinScore float64

	// MaxRunes 是最多向左扩展多少个字符。
	MaxRunes int

	// StopRunes 是向左扫描时遇到即停止的字符。
	//
	// 这是防止过度扩展的主要手段。「合同方为星辰科技有限公司」里的「为」
	// 是助词，向左扫到它就该停——不停就会把「合同方为」一起吞进机构名。
	//
	// The main guard against over-extension: 为 in 合同方为星辰科技有限公司 is
	// a particle, and not stopping there swallows 合同方为 into the name.
	StopRunes string

	// anchors 是编译后的锚点自动机。
	anchors *detect.AhoCorasick
}

// DefaultBackwardExtension returns the built-in organization rule.
// 返回内置的机构名逆向扩展规则。
func DefaultBackwardExtension() (*BackwardExtension, error) {
	b := &BackwardExtension{
		Anchors: []string{
			"有限公司", "股份有限公司", "有限责任公司", "集团", "集团公司",
			"公司", "厂", "分厂", "工作室", "事务所", "研究院", "研究所",
			"设计院", "医院", "卫生院", "诊所", "学校", "学院", "大学",
			"中学", "小学", "幼儿园", "银行", "支行", "分行", "信用社",
			"法院", "检察院", "公安局", "派出所", "管理局", "监督局",
			"税务局", "海关", "委员会", "办公室", "中心", "协会", "商会",
			"基金会", "合作社", "俱乐部", "酒店", "宾馆", "超市", "药房",

			// 拉丁文机构通名。
			//
			// # 只加这一行不够，见 extendBackward 里的大小写边界
			// # This list alone is not enough; see the case boundary below
			//
			// 锚点表此前是纯中文的，因此拉丁文机构名连拉伸的门槛都进不去：
			// 实测 "invoice from Acme Global Ltd" 检出 Ltd 之后原样返回 Ltd，
			// 而 Acme Global 才是识别到具体一家的那部分——通名脱敏了，
			// 字号原样出境，审计里却显示 ORG:1。
			//
			// 这个仓库声称支持拉丁文（语言路由、en_core_web_lg），
			// 因此「向后拉伸只覆盖中文」是一处声称与实现不一致，不是取舍。
			//
			// The anchor list was Chinese-only, so a Latin organization name
			// never reached the gate: "Acme Global Ltd" detected as "Ltd" came
			// back as "Ltd" while the distinctive head left in the clear and
			// the audit read ORG:1. This repository claims Latin support, so
			// covering only Chinese was an inconsistency rather than a tradeoff.
			// 全大写写法。与下面的驼峰写法分开列，因为锚点是精确匹配——
			// 大小写不敏感的匹配会让 "inc" 这类词尾意外命中。
			// Listed separately from the mixed-case spellings because anchors
			// match exactly; case-insensitive matching would let a word ending
			// in "inc" hit by accident.
			"LTD", "LTD.", "INC", "INC.", "CORP", "CORP.", "GMBH",
			"Ltd", "Ltd.", "Limited", "LLC", "L.L.C.", "Inc", "Inc.",
			"Incorporated", "Corp", "Corp.", "Corporation", "Co", "Co.",
			"Company", "PLC", "plc", "LLP", "LP", "GmbH", "AG", "KG",
			"S.A.", "S.A.S.", "SARL", "S.r.l.", "SpA", "B.V.", "N.V.",
			"A/S", "AB", "AS", "Oy", "Pty", "Pte",
			"Foundation", "Institute", "University", "College", "Hospital",
			"Bank", "Group", "Holdings", "Partners", "Associates",
		},
		AdministrativeMarkers: []string{
			"省", "市", "区", "县", "镇", "乡", "村", "旗", "州", "盟",
			"中国", "全国", "国家",
			"北京", "上海", "天津", "重庆", "广东", "江苏", "浙江", "山东",
			"河南", "四川", "湖北", "湖南", "河北", "福建", "安徽", "陕西",
		},
		IndustryMarkers: []string{
			"科技", "技术", "信息", "网络", "数据", "智能", "软件", "电子",
			"机械", "制造", "工业", "建筑", "工程", "材料", "化工", "能源",
			"医疗", "生物", "医药", "健康", "食品", "农业", "贸易", "物流",
			"金融", "投资", "资本", "保险", "证券", "地产", "置业", "文化",
			"传媒", "教育", "咨询", "服务", "管理", "国际", "实业", "发展",
			"工商", "商业", "人民", "中级", "基层", "高级", "第一", "第二",
		},
		MinScore: 0.5,
		MaxRunes: 16,
		// 停止字必须把「机构名前面常出现的动词与介词」全覆盖。
		//
		// 实测漏了「到」的后果：「请到北京市第一中级人民法院」向左一路扩过
		// 「到」和「请」，把动词和敬语一起吞进了机构名。而它仍然通过了评分，
		// 因为扩展段里有「市」。
		//
		// 边界是靠停止字划的，评分只是事后的合理性检查——指望评分去拦
		// 一个停止字该拦的东西，是把两件事的职责搞混了。
		//
		// Measured: 到 was missing, so 请到北京市第一中级人民法院 extended
		// through the verb and the honorific — and still passed scoring,
		// because 市 was in the extension. The boundary is drawn by stop
		// characters; scoring is only a sanity check afterwards.
		StopRunes: "的和与及或是在有等把被将从对向为以了由于关于至于" +
			"到去往找问经给跟让叫使请该其此那这" +
			"，。；！？：、\n\t（）()「」《》\"' ",
	}

	ac, err := detect.NewAhoCorasick(b.Anchors)
	if err != nil {
		return nil, fmt.Errorf("构建机构通名自动机失败 / building anchor automaton: %w", err)
	}
	b.anchors = ac
	return b, nil
}

// Compile builds the anchor automaton for a hand-written rule.
// 为手工编写的规则构建锚点自动机。
func (b *BackwardExtension) Compile() error {
	if len(b.Anchors) == 0 {
		return fmt.Errorf("逆向扩展需要锚点词表 / backward extension needs anchors")
	}
	ac, err := detect.NewAhoCorasick(b.Anchors)
	if err != nil {
		return fmt.Errorf("构建锚点自动机失败 / building anchor automaton: %w", err)
	}
	b.anchors = ac
	if b.MaxRunes <= 0 {
		b.MaxRunes = 16
	}
	return nil
}

// endsWithAnchor reports whether the value ends in an organizational suffix.
// 报告该值是否以机构通名结尾。
//
// 用自动机而不是逐个 HasSuffix：锚点有几十个，而这个判断在热路径上，
// 每个模型返回的机构实体都要过一次。自动机一遍扫描同时匹配全部锚点。
//
// The automaton rather than a HasSuffix loop: there are dozens of anchors and
// this runs on the hot path for every organization the model returns.
func (b *BackwardExtension) endsWithAnchor(value string) (string, bool) {
	if b.anchors == nil {
		return "", false
	}
	longest := ""
	for _, m := range b.anchors.FindAll(value) {
		if m.End == len(value) && len(b.anchors.Pattern(m.Pattern)) > len(longest) {
			longest = b.anchors.Pattern(m.Pattern)
		}
	}
	return longest, longest != ""
}

// extendBackward returns the new start offset, or the original if not extended.
// 返回新的起点偏移；未扩展时返回原值。
func (b *BackwardExtension) extendBackward(text string, e detect.Entity) (int, float64, []string) {
	if _, ok := b.endsWithAnchor(e.Value); !ok {
		return e.Start, 0, nil
	}
	if e.Start == 0 {
		return e.Start, 0, nil
	}

	maxRunes := b.MaxRunes
	if maxRunes <= 0 {
		maxRunes = 16
	}

	// 拉丁文走另一条边界规则，见 extendLatin。
	// 中文里词与词之间没有分隔，边界靠停止字划；拉丁文靠空格分词，
	// 而空格本身就在停止字表里——两套规则混在一个循环里，结果是拉丁文
	// 永远走不了第一步。
	//
	// Latin script uses a different boundary rule: Chinese has no inter-word
	// separator and relies on stop characters, while Latin separates on spaces
	// which are themselves stop characters. One loop for both means Latin never
	// takes its first step.
	if isLatinBoundary(text, e.Start) {
		return b.extendLatin(text, e, maxRunes)
	}

	// 向左滑窗：逐字符退，遇到停止字或非机构名字符即止。
	// Slide leftward one rune at a time, stopping at a stop rune or a
	// character that cannot be part of an organization name.
	start := e.Start
	for runes := 0; runes < maxRunes && start > 0; runes++ {
		r, size := utf8.DecodeLastRuneInString(text[:start])
		if size == 0 || r == utf8.RuneError {
			break
		}
		if strings.ContainsRune(b.StopRunes, r) {
			break
		}
		if !unicode.Is(unicode.Han, r) && !unicode.IsDigit(r) &&
			!unicode.IsLetter(r) {
			break
		}
		start -= size
	}

	if start == e.Start {
		return e.Start, 0, nil
	}

	// 邻近度评分：扩展段里有没有行政区划或行业修饰词。
	//
	// 没有任何标志词的扩展段可能只是前一个词的尾巴，因此需要评分把关。
	// 「星辰」不含标志词，靠的是「科技」——它在实体内部而不在扩展段里，
	// 因此评分同时看扩展段与实体本身。
	//
	// An extension containing no marker may be the tail of the previous word.
	// 星辰 has no marker of its own; the evidence is 科技, which sits inside
	// the entity rather than in the extension, so both are scored.
	extension := text[start:e.Start]
	whole := text[start:e.End]

	score := 0.0
	var evidence []string
	for _, m := range b.AdministrativeMarkers {
		if strings.Contains(extension, m) {
			score += 0.6
			evidence = append(evidence, "行政区划")
			break
		}
	}
	for _, m := range b.IndustryMarkers {
		if strings.Contains(whole, m) {
			score += 0.5
			evidence = append(evidence, "行业修饰")
			break
		}
	}
	// 长度是硬约束，不是加分项。
	//
	// 原来它是加分项，于是一段 11 字的扩展（「请到北京市第一中级人民」）
	// 拿不到这一分、却靠「市」拿到 0.6 分照样通过。中文机构名的字号加
	// 行政区划前缀极少超过 12 字，超了几乎一定是吞进了散文。
	//
	// A hard constraint rather than a bonus. As a bonus, an eleven-character
	// extension simply forfeited it and passed on the administrative marker
	// alone. A Chinese organization's distinctive head plus its administrative
	// prefix rarely exceeds twelve characters; beyond that it has almost
	// certainly swallowed prose.
	const maxPlausibleHead = 12
	if n := utf8.RuneCountInString(extension); n > maxPlausibleHead {
		return e.Start, 0, []string{"扩展段过长，疑似吞入散文"}
	} else if n >= 1 && n <= 8 {
		score += 0.3
		evidence = append(evidence, "字号长度合理")
	}

	if score < b.MinScore {
		return e.Start, score, evidence
	}
	return start, score, evidence
}

// isLatinBoundary 判断实体左侧紧邻的是不是拉丁文语境。
//
// 只看紧邻的那一小段：整段文本可能中英混排，而边界规则该由**这个实体周围**
// 的文字系统决定，不是由全文的主要语言决定。
//
// Only the immediate vicinity is inspected: a document may mix scripts, and the
// boundary rule belongs to this entity's surroundings rather than to the
// document's dominant language.
func isLatinBoundary(text string, start int) bool {
	if start == 0 {
		return false
	}
	// 紧邻左侧必须是空格，且再往左是拉丁字母——这正是「Acme Global Ltd」
	// 这类写法的形状。中文里 " 有限公司" 前面若是空格，左侧多半是汉字或
	// 句读，走不到这条分支。
	r, size := utf8.DecodeLastRuneInString(text[:start])
	if r != ' ' {
		return false
	}
	prev, _ := utf8.DecodeLastRuneInString(text[:start-size])
	return unicode.Is(unicode.Latin, prev)
}

// extendLatin 用大小写划定拉丁文机构名的左边界。
//
// # 大小写是拉丁文里停止字的对应物
// # Capitalization is the Latin equivalent of a stop character
//
// 中文靠「的和与及在到」这类虚词划界。拉丁文没有对应的字符级信号，但机构名
// 按惯例逐词首字母大写，而它前面的介词、冠词、动词是小写的：
//
//	invoice from Acme Global Ltd
//	             ^^^^^ ^^^^^^      大写，属于机构名
//	        ^^^^                   小写，边界
//
// 因此向左逐词退，遇到首字母非大写的词即止。这不是启发式的猜测——它和中文
// 那条规则是同一种东西：用书写惯例里已有的边界信号，而不是去猜语义。
//
// 惯例会失效的地方也要写下来：全大写的 "ACME GLOBAL LTD" 里每个词都是大写，
// 于是左边界只能靠 maxRunes 和停止字兜底；而 "the Acme Ltd" 里的 the 是小写，
// 正确地被排除在外。
//
// Chinese draws boundaries with function words; Latin has no character-level
// equivalent but capitalizes organization names word by word while the
// prepositions and verbs before them are lowercase. Walking leftward word by
// word and stopping at the first non-capitalized one uses a boundary signal the
// writing system already provides rather than guessing at semantics. Where the
// convention fails — an all-caps name — only maxRunes and the stop runes bound
// the walk.
func (b *BackwardExtension) extendLatin(text string, e detect.Entity, maxRunes int) (
	int, float64, []string) {
	start := e.Start
	words := 0
	// 一个机构名很少超过 6 个词；再多多半是把整句话吞了进来。
	// Rarely more than six words; beyond that the walk is swallowing a sentence.
	const maxWords = 6

	for words < maxWords {
		// 跳过词间的单个空格
		r, size := utf8.DecodeLastRuneInString(text[:start])
		if r != ' ' || size == 0 {
			break
		}
		wordEnd := start - size

		// 往左读一个词
		wordStart := wordEnd
		for wordStart > 0 {
			wr, wsize := utf8.DecodeLastRuneInString(text[:wordStart])
			if wsize == 0 || wr == utf8.RuneError {
				break
			}
			if !unicode.IsLetter(wr) && !unicode.IsDigit(wr) &&
				wr != '.' && wr != '&' && wr != '-' {
				break
			}
			wordStart -= wsize
		}
		if wordStart == wordEnd {
			break
		}

		first, _ := utf8.DecodeRuneInString(text[wordStart:wordEnd])
		if !unicode.IsUpper(first) {
			break
		}
		if latinStopWords[strings.ToLower(text[wordStart:wordEnd])] {
			break
		}
		start = wordStart
		words++
		if (e.Start-start)/3 > maxRunes {
			break
		}
	}

	if start == e.Start {
		return e.Start, 0, nil
	}
	// 拉丁文这条路径不做邻近度评分：中文那套评分靠的是行政区划与行业修饰词
	// 的词表，那些词表是中文的。大小写边界本身已经是证据——它划出的是
	// 「书写者当作专名对待的那几个词」，而不是一段任意长度的窗口。
	//
	// No proximity scoring here: the Chinese score relies on Chinese marker
	// lists. The capitalization boundary is itself the evidence, delimiting the
	// words the writer treated as a proper noun rather than an arbitrary window.
	return start, 1.0, []string{"latin-title-case"}
}

// latinStopWords 是拉丁文里「虽然大写但不属于机构名」的词。
//
// # 只靠大小写会把句首吞进来
// # Capitalization alone swallows the start of a sentence
//
// 大写是拉丁文里最接近中文停止字的边界信号，但英文还会把句首、月份、星期、
// 章节标签都大写。实测五个句子里错了三个：
//
//	On Monday Acme Ltd filed        → 吞成 "On Monday Acme Ltd"
//	In January Contoso Inc reported → 吞成 "In January Contoso Inc"
//	See Appendix B Acme Ltd terms   → 吞成 "See Appendix B Acme Ltd"
//
// 过度脱敏是效用损失而不是泄露，但它同样是错的：把「On Monday」当成机构名
// 的一部分，下游拿到的是一个没人认得的实体，而运维从计数上看不出任何异常。
//
// 这张表与中文的 StopRunes 是同一种东西——用书写惯例里已有的边界信号，
// 而不是去猜语义。它必然不完备（专有名词可以是任何词），因此它只负责挡住
// 高频的那几类，剩下的交给词数上限。
//
// Capitalization is the closest Latin analogue to a Chinese stop character, but
// English also capitalizes sentence starts, months, weekdays and section
// labels. Measured: three of five sentences over-extended. Over-redaction is a
// utility loss rather than a leak, but it is still wrong — the downstream sees
// an entity nobody recognizes while the counters look normal. This list is
// necessarily incomplete, since a proper noun can be any word; it blocks the
// frequent cases and the word cap bounds the rest.
var latinStopWords = map[string]bool{
	// 句首与介词
	"the": true, "a": true, "an": true, "at": true, "by": true, "for": true,
	"from": true, "in": true, "of": true, "on": true, "to": true, "with": true,
	"and": true, "or": true, "but": true, "as": true, "into": true, "via": true,
	"per": true, "our": true, "your": true, "their": true, "his": true,
	"her": true, "its": true, "this": true, "that": true, "these": true,
	"those": true, "we": true, "i": true, "you": true, "they": true,
	"he": true, "she": true, "it": true,
	// 常见动词与文书用语
	"see": true, "paid": true, "sent": true, "sold": true, "billed": true,
	"invoice": true, "contract": true, "note": true, "notes": true,
	"appendix": true, "section": true, "table": true, "figure": true,
	"chapter": true, "page": true, "exhibit": true, "schedule": true,
	"attn": true, "re": true, "cc": true, "subject": true,
	// 月份
	"january": true, "february": true, "march": true, "april": true,
	"may": true, "june": true, "july": true, "august": true,
	"september": true, "october": true, "november": true, "december": true,
	"jan": true, "feb": true, "mar": true, "apr": true, "jun": true,
	"jul": true, "aug": true, "sep": true, "sept": true, "oct": true,
	"nov": true, "dec": true,
	// 星期
	"monday": true, "tuesday": true, "wednesday": true, "thursday": true,
	"friday": true, "saturday": true, "sunday": true,
}
