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
