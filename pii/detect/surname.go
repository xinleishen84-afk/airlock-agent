package detect

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// # 姓氏驱动的人名候选
// # Surname-driven person-name candidates
//
// 统计模型漏人名的方式是有规律的：越罕见的姓，训练语料里出现得越少，
// 漏得越彻底。实测 zh_core_web_md 对「张伟」这类常见名尚可，
// 对「欧阳志远」「尉迟恭」这类复姓则是零召回——不是判错，是根本不输出。
//
// A statistical model misses names in a patterned way: the rarer the surname,
// the less it appeared in training, and the more completely it is missed.
// Measured, zh_core_web_md handles common names but returns nothing at all for
// compound surnames like 欧阳志远 or 尉迟恭.
//
// 姓氏表是确定性的、封闭的、几百条就能覆盖绝大多数中国人。把它编进
// Aho-Corasick，一遍线性扫描就能定位所有可能的姓，再向后取一到两个汉字
// 作为名——这条路不依赖训练数据的分布，因此对罕见姓和常见姓一视同仁。
//
// The surname list is deterministic, closed, and a few hundred entries cover
// most of the population. Compiled into the automaton, one linear pass locates
// every possible surname; one or two following characters form the given name.
// This does not depend on training-data distribution, so it treats rare and
// common surnames alike.
//
// # 它单独用是不够的，这一点必须说清楚
// # It is not sufficient on its own, and that has to be said plainly
//
// 「王者荣耀」里有「王」，「李子」里有「李」，「陈述」里有「陈」。姓氏驱动
// 必然产出大量候选，其中很多不是人名。因此本识别器产出的是**候选**，
// 置信度刻意压低，交给证据链验证器（pii/verify）去确认或否决。
// 把它当作终审来用，会把误报灌进脱敏管线。
//
// 王 appears in 王者荣耀, 李 in 李子, 陈 in 陈述. Surname-driven detection
// necessarily produces many candidates that are not names. This recognizer
// therefore emits candidates at deliberately low confidence, for the evidence
// chain verifier to confirm or reject. Used as a final verdict, it floods the
// pipeline with false positives.

// CompoundSurnames 是常见复姓。
//
// 这份表是本识别器存在的主要理由：单姓模型多少还能认出一些，复姓则是
// 系统性零召回。
//
// The main reason this recognizer exists: models manage some single surnames
// but are systematically blind to compound ones.
var CompoundSurnames = []string{
	"欧阳", "司徒", "司马", "上官", "诸葛", "尉迟", "皇甫", "夏侯", "宇文", "长孙",
	"慕容", "独孤", "东方", "南宫", "公孙", "令狐", "闾丘", "钟离", "端木", "拓跋",
	"呼延", "万俟", "澹台", "公冶", "宗政", "濮阳", "淳于", "单于", "太叔", "申屠",
	"公羊", "颛孙", "轩辕", "第五", "梁丘", "左丘", "东郭", "南门", "百里", "东门",
	"西门", "羊舌", "微生", "岳帅", "缑亢", "况后", "有琴", "亓官", "仲孙", "巫马",
	"乐正", "漆雕", "壤驷", "夹谷", "宰父", "谷梁", "段干", "赫连", "皇象", "褚师",
}

// CommonSurnames 是百家姓中最常见的单姓。
//
// 只取高频部分。姓氏表越长，候选越多，而低频单姓带来的召回增益远小于
// 它带来的误报——这条边界画在哪里是可调的，但必须画。
//
// Only the high-frequency head. A longer list produces more candidates, and
// the recall gained from rare single surnames is far smaller than the false
// positives they bring.
var CommonSurnames = []string{
	"王", "李", "张", "刘", "陈", "杨", "黄", "赵", "吴", "周",
	"徐", "孙", "马", "朱", "胡", "郭", "何", "高", "林", "罗",
	"郑", "梁", "谢", "宋", "唐", "许", "邓", "冯", "韩", "曹",
	"曾", "彭", "萧", "蔡", "潘", "田", "董", "袁", "于", "余",
	"叶", "蒋", "杜", "苏", "魏", "程", "吕", "丁", "沈", "任",
	"姚", "卢", "傅", "钟", "姜", "崔", "谭", "廖", "范", "汪",
	"陆", "金", "石", "戴", "贾", "韦", "夏", "邱", "方", "侯",
	"邹", "熊", "孟", "秦", "白", "江", "阎", "薛", "尹", "段",
	"雷", "黎", "史", "龙", "陶", "贺", "顾", "毛", "郝", "龚",
	"邵", "万", "钱", "严", "覃", "武", "戚", "莫", "孔", "向",
}

// nameStopRunes 是不可能出现在名字里的字。
//
// 这些字若出现在姓之后，说明这个姓是别的词的一部分，或者句子在这里断开了。
// 「陈述」的「述」不在这里——它确实可能是名字用字，这类只能靠证据链去分。
// 这份表只挡住那些**在语法上就不可能**的：助词、连词、标点、数字。
//
// If one of these follows a surname, the surname is part of another word or
// the sentence breaks there. 述 in 陈述 is deliberately absent — it genuinely
// can be a given-name character, and only the evidence chain can separate
// those. This list holds only what is grammatically impossible.
var nameStopRunes = map[rune]bool{}

// namePrefixBlockers 是紧贴姓氏之前时说明「这不是姓」的字。
//
// 「小王」「老李」「大张」「阿花」里的姓是称呼的一部分，不是姓名的开头。
// 这是一个很短的封闭集合——正因为短，它不会像「左侧是汉字就跳过」
// 那样把真实人名一起挡掉。
//
// Characters that, immediately before a surname, mean it is not a surname:
// 小王, 老李, 大张, 阿花 are forms of address. A short closed set — which is
// why it does not block real names the way "any CJK" did.
var namePrefixBlockers = map[rune]bool{
	'小': true, '老': true, '大': true, '阿': true,
}

func init() {
	// 「儿」与「之」曾经在这张表里，是错的：「上官婉儿」「王羲之」都是人名，
	// 而把它们列为停止字，会把名字的最后一个字截掉——截断后的脱敏仍然会
	// 「成功」，只是把名字的后半截留在了原文里。
	//
	// 儿 and 之 used to be here, wrongly: 上官婉儿 and 王羲之 are names, and
	// listing them truncates the final character. A truncated redaction still
	// "succeeds", leaving the tail of the name in the payload.
	for _, r := range "的了是在和与及或就都很不没有把被将从对向为以但而且因所以如果虽然" +
		"这那些个们呢吗吧啊呀哦嗯其乃即则却" {
		nameStopRunes[r] = true
	}
}

// SurnameRecognizer emits person-name candidates driven by a surname list.
// 基于姓氏表产出人名候选。
type SurnameRecognizer struct {
	name       string
	ac         *AhoCorasick
	isCompound []bool
	maxGiven   int

	compoundScore float64
	singleScore   float64
}

// SurnameOptions configures the recognizer.
// 配置识别器。
type SurnameOptions struct {
	// MaxGivenRunes 是名（姓之后的部分）最多取几个汉字。
	// 中文名的名部分绝大多数是一到两字，取三会大幅增加误报。
	// Chinese given names are overwhelmingly one or two characters.
	MaxGivenRunes int

	// CompoundScore / SingleScore 是复姓与单姓候选的置信度。
	//
	// 复姓给得高于单姓，因为「欧阳」几乎只作姓用，而「王」「李」到处都是。
	// 两者都低于 0.85——它们是候选，不是判决。
	//
	// Compound scores higher than single: 欧阳 is almost only ever a surname,
	// while 王 and 李 are everywhere. Both stay below 0.85: these are
	// candidates, not verdicts.
	CompoundScore float64
	SingleScore   float64

	// IncludeSingle 决定是否启用单姓。
	//
	// 关掉它就只补复姓——这是「模型已经能认常见名、只想补上它系统性漏掉
	// 的那一类」时的配置，误报代价最小。
	//
	// Disabling it covers compound surnames only: the configuration for
	// "the model already handles common names, just fill the class it is
	// systematically blind to", at the lowest false-positive cost.
	IncludeSingle bool
}

// DefaultSurnameOptions returns the compound-only configuration.
// 返回「只补复姓」的配置。
func DefaultSurnameOptions() SurnameOptions {
	return SurnameOptions{
		MaxGivenRunes: 2,
		CompoundScore: 0.70,
		SingleScore:   0.45,
		IncludeSingle: false,
	}
}

// NewSurnameRecognizer builds the recognizer.
// 构造识别器。
func NewSurnameRecognizer(opts SurnameOptions) (*SurnameRecognizer, error) {
	if opts.MaxGivenRunes < 1 {
		opts.MaxGivenRunes = 2
	}
	if opts.MaxGivenRunes > 3 {
		return nil, fmt.Errorf(
			"名最多取 %d 字过长——中文名的名部分绝大多数是一到两字，"+
				"取三以上会让候选量与误报同步暴涨 / MaxGivenRunes too large",
			opts.MaxGivenRunes)
	}
	if opts.CompoundScore <= 0 || opts.CompoundScore > 1 ||
		opts.SingleScore <= 0 || opts.SingleScore > 1 {
		return nil, fmt.Errorf("置信度须在 (0,1] / scores must be in (0,1]")
	}

	surnames := make([]string, 0, len(CompoundSurnames)+len(CommonSurnames))
	isCompound := make([]bool, 0, cap(surnames))
	seen := map[string]bool{}

	for _, s := range CompoundSurnames {
		if seen[s] {
			continue
		}
		seen[s] = true
		surnames = append(surnames, s)
		isCompound = append(isCompound, true)
	}
	if opts.IncludeSingle {
		for _, s := range CommonSurnames {
			if seen[s] {
				continue
			}
			seen[s] = true
			surnames = append(surnames, s)
			isCompound = append(isCompound, false)
		}
	}

	ac, err := NewAhoCorasick(surnames)
	if err != nil {
		return nil, fmt.Errorf("构建姓氏自动机失败 / building surname automaton: %w", err)
	}

	return &SurnameRecognizer{
		name:          "cn_surname",
		ac:            ac,
		isCompound:    isCompound,
		maxGiven:      opts.MaxGivenRunes,
		compoundScore: opts.CompoundScore,
		singleScore:   opts.SingleScore,
	}, nil
}

// Name implements Recognizer.
func (s *SurnameRecognizer) Name() string { return s.name }

// EntityType implements Recognizer.
func (s *SurnameRecognizer) EntityType() EntityType { return TypeName }

// Recognize implements Recognizer.
//
// 对每个姓氏命中，向后取一到 MaxGivenRunes 个汉字，各产出一个候选。
// 两字名与三字名同时产出，由 ResolveOverlaps 的「长者优先」和证据链
// 共同决定谁留下——在这里就替它们决定，等于把一个需要上下文的判断
// 提前到了没有上下文的地方。
//
// For each surname hit, one candidate per given-name length. Both are emitted;
// longest-wins resolution and the evidence chain decide together. Deciding here
// would move a context-dependent judgement to where there is no context.
func (s *SurnameRecognizer) Recognize(text string) ([]Entity, error) {
	matches := s.ac.FindAll(text)
	if len(matches) == 0 {
		return nil, nil
	}

	var out []Entity
	for _, m := range matches {
		// 左边界只挡定向的几个前缀字，不挡「任何汉字」。
		//
		// 中文没有词间空格，真实语料里姓氏前面几乎总有汉字：「经办人欧阳志远」
		// 的「欧阳」前是「人」，「请联系张伟」的「张」前是「系」。
		// 用「左侧是汉字就跳过」做检查，会把这两类全部挡在门外——
		// 前两版分别在复姓和单姓上犯了这个错，实测双双返回空。
		//
		// 真正需要挡的是「小王」「老李」这种把姓当作词尾的构词，
		// 那是一个很短的封闭前缀集合，直接列出来。
		//
		// The left boundary blocks a targeted prefix set, not "any CJK". In
		// real prose a surname is nearly always preceded by a CJK character —
		// 人 before 欧阳, 系 before 张. Blocking on any CJK excludes both
		// classes; two earlier versions did exactly that and returned nothing.
		// What actually needs blocking is 小王 / 老李, a short closed set.
		if m.Start > 0 {
			r, size := utf8.DecodeLastRuneInString(text[:m.Start])
			if size > 0 && namePrefixBlockers[r] {
				continue
			}
		}

		given := text[m.End:]
		consumed := 0
		for n := 1; n <= s.maxGiven; n++ {
			r, size := utf8.DecodeRuneInString(given[consumed:])
			if size == 0 || r == utf8.RuneError {
				break
			}
			if !isCJK(r) || nameStopRunes[r] {
				break
			}
			consumed += size

			score := s.singleScore
			if s.isCompound[m.Pattern] {
				score = s.compoundScore
			}
			// 候选之间不按长度分高下，各长度同分。
			//
			// 曾经这里让置信度随长度递减，理由是「长的更可能多吞一个字」。
			// 实测证明那是错的补丁：证据链的得分本身已经能分辨——
			// 「尉迟恭」得 0.50 而「尉迟恭负」得 0.00，因为后者把「负责」
			// 这个人类动作线索吃掉了一半。而递减的置信度只在得分打平时起作用，
			// 那恰恰是它帮倒忙的场合：「欧阳志」与「欧阳志远」同分，
			// 递减让短的赢，把名字截断了。
			//
			// Candidates of different lengths score equally here.
			//
			// This used to decay confidence with length, on the theory that a
			// longer candidate is likelier to have swallowed a character.
			// Measured, that was the wrong patch: the evidence chain already
			// discriminates — 尉迟恭 scores 0.50 while 尉迟恭负 scores 0.00,
			// because the latter ate half of the 负责 cue. The decay only acted
			// on ties, which is exactly where it hurt: 欧阳志 and 欧阳志远 tie,
			// and the decay picked the truncated one.
			out = append(out, Entity{
				Type:       TypeName,
				Value:      text[m.Start : m.End+consumed],
				Start:      m.Start,
				End:        m.End + consumed,
				Confidence: score,
				Detector:   s.name,
			})
		}
	}
	return out, nil
}

// isCJK reports whether a rune is a CJK ideograph.
// 报告一个字符是否为 CJK 表意文字。
func isCJK(r rune) bool {
	return unicode.Is(unicode.Han, r)
}

// SurnameOf returns the surname prefix of a candidate, for audit output.
// 返回候选的姓氏部分，供审计输出使用。
func (s *SurnameRecognizer) SurnameOf(value string) string {
	for _, m := range s.ac.FindAll(value) {
		if m.Start == 0 {
			return s.ac.Pattern(m.Pattern)
		}
	}
	return ""
}

// Surnames returns the configured surname list, for the admin snapshot.
// 返回已配置的姓氏表，供管理快照使用。
func (s *SurnameRecognizer) Surnames() []string {
	out := make([]string, 0, len(s.isCompound))
	for i := range s.isCompound {
		out = append(out, s.ac.Pattern(i))
	}
	return out
}

var _ = strings.TrimSpace
