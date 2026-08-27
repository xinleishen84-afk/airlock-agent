package verify

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// # 内置证据链
// # Built-in evidence chains
//
// 这些链是针对实测出来的失败写的，不是凭空设计的。每一条都对应一个
// 在 eval 语料上真实发生过的问题。
//
// These chains were written against measured failures, not designed in the
// abstract. Each corresponds to something that actually happened on the corpus.

// AddressChain 补全地址边界。
//
// 实测问题：模型对「北京市海淀区中关村大街 1 号」只给出「北京市」。
// 值被检出了，但脱敏只盖住开头三个字，剩下的照样出境——而这种漏出
// 不会报错，审计日志里会显示「ADDRESS: 1」，看起来一切正常。
//
// Measured: the model returns 北京市 for 北京市海淀区中关村大街 1 号. The
// value is found but redaction covers only its head, and the audit log shows
// "ADDRESS: 1", which looks fine.
//
// 拉伸规则只在行政区划与门牌特征字上收尾，因此不会一路吞到句末。
// Extension ends only on administrative or street-number suffixes.
func AddressChain() *Chain {
	return &Chain{
		Type: detect.TypeAddress,
		// 地址链此前没有形态规则，于是 ST、registrado 这类拉丁缩写与外语词
		// 被判成地址后一路通过。人名链与机构链都有，唯独地址链漏了——
		// 三条链的形态约束本该一致，因为误判来自同一个源头（模型），
		// 只是落在了不同的类型上。
		//
		// The address chain had no shape rules, so ST and registrado passed
		// through as addresses. The name and organization chains had them; the
		// gap was in the third, though the misjudgements come from one source.
		Shapes: []ShapeRule{codeShape(), latinAbbreviationShape(), versionShape()},
		Extension: &ExtensionRule{
			Suffixes: []string{
				"省", "市", "区", "县", "镇", "乡", "村", "旗", "盟", "州",
				"路", "街", "道", "巷", "弄", "里", "胡同", "大街", "大道",
				"号", "号院", "栋", "幢", "座", "单元", "室", "层", "楼",
			},
			MaxRunes: 30,
			// 断链字符里必须包含助词，尤其是「的」。
			//
			// 「1号的会议室」以「室」结尾，而「室」是合法的门牌特征字，
			// 于是拉伸会把「的会议室」一起吞进来。实测中这条用例是红的：
			// 得到「北京市海淀区中关村大街1号的会议室」。
			//
			// 中文地址内部不出现「的」，因此它是一个可靠的断点。
			// 靠标点断链是不够的——「的」两侧都没有标点。
			//
			// Particles must break the chain, 的 above all: 1号的会议室 ends in
			// 室, a legitimate street-number suffix, so extension swallowed
			// 的会议室. A Chinese address never contains 的, which makes it a
			// reliable stop. Punctuation alone is not enough — there is none
			// around 的.
			StopRunes: "的和与及或是在有等把被从对向为以，。；！？\n\t、（）()「」\"'",
		},
		Cues: []Cue{
			{
				Name: "代码语法",
				Words: []string{
					"func ", "def ", "return ", "var ", "import ", "package ",
					"=>", "->", "::", "();", ");", "){", "int ", "bool ",
				},
				Requirement: MustNot, Direction: Either, Window: 64,
			},
			{
				Name:        "地址动词",
				Words:       []string{"住在", "位于", "寄往", "地址", "收货", "送到", "邮寄", "所在"},
				Requirement: Should, Direction: Before, Weight: 0.6, Window: 32,
			},
			{
				Name:        "门牌特征",
				Words:       []string{"号", "室", "层", "楼", "单元", "栋"},
				Requirement: Should, Direction: After, Weight: 0.4, Window: 24,
			},
		},
		Threshold: 0.4,
		// 地址证据不足时不否决：大量真实地址周围没有任何提示词，
		// 而「上海市浦东新区世纪大道 100 号」本身就已经是地址。
		// Insufficient evidence does not reject: many real addresses have no
		// cue words, and the string itself already is an address.
		RejectUnverified: false,
		DefaultWindow:    32,
	}
}

// PersonChain 否决落在代码里的人名误判。
//
// 实测问题：zh_core_web_sm 把源代码里的 func、nil 判成人名，md 把 retry(n
// 判成人名。脱敏管线会照办，把代码改坏——而这正是本项目的结构化白名单
// 一直在防的那类损坏，只不过这次是从检测侧进来的。
//
// Measured: the Chinese models label func, nil and retry(n in source code as
// person names. The pipeline dutifully rewrites the code — the same class of
// damage the structural allowlist exists to prevent, arriving from the
// detection side instead.
//
// # 为什么代码线索是 MustNot 而人类线索是 Should
// # Why code cues are MustNot while human cues are Should
//
// 绝大多数真实人名周围没有任何「先生」「经理」这类词——「请联系张伟处理」
// 就没有。把人类线索设成 Must，等于关掉人名检测。
// 而代码特征是相反的：一个人名周围出现 func、return、括号加分号，
// 几乎可以确定这不是人名而是标识符。
//
// Most real names have no 先生 or 经理 nearby — 请联系张伟处理 has none.
// Making human cues a Must would disable name detection. Code features are the
// opposite: func, return, or parentheses with semicolons around a "name" make
// it an identifier with near certainty.
func PersonChain() *Chain {
	return &Chain{
		Type:   detect.TypeName,
		Shapes: []ShapeRule{codeShape(), latinAbbreviationShape(), versionShape()},
		Cues: []Cue{
			{
				Name: "代码语法",
				Words: []string{
					"func ", "def ", "return ", "var ", "let ", "const ",
					"class ", "import ", "package ", "public ", "static ",
					"=>", "->", "::", "&&", "||", "!=", "==",
					"();", ");", "){", "};", "int ", "bool ", "string ",
				},
				Requirement: MustNot, Direction: Either, Window: 64,
			},
			{
				Name:        "人类称谓",
				Words:       []string{"先生", "女士", "小姐", "老师", "医生", "经理", "主管", "总监", "同学", "同事", "Mr.", "Ms.", "Mrs.", "Dr."},
				Requirement: Should, Direction: Either, Weight: 0.7, Window: 24,
			},
			{
				Name: "人类动作",
				// 这份词表的作用不只是「加分」，它同时是边界判据：
				// 「尉迟恭负责」里的「负责」紧跟在正确边界之后，
				// 而多吞一字的「尉迟恭负」把它咬掉了半个，于是得分更低。
				// 词表漏一个常见动词，对应的那个边界就分不出来——
				// 实测漏了「提出」，「诸葛亮提出隆中对」被切成「诸葛亮提」。
				//
				// This list is also a boundary criterion, not only a bonus:
				// 负责 sits just past the correct edge of 尉迟恭, and the
				// over-long 尉迟恭负 bites half of it away and scores lower. A
				// missing common verb means that boundary cannot be resolved —
				// measured, 提出 was missing and 诸葛亮提出 was cut to 诸葛亮提.
				Words: []string{
					"说", "问", "答", "联系", "通知", "告诉", "签字", "签署",
					"负责", "提交", "提出", "提议", "审批", "出席", "参会",
					"表示", "认为", "指出", "强调", "建议", "主张", "回复",
					"打电话", "发邮件", "来电", "到访", "入职", "离职",
				},
				Requirement: Should, Direction: Either, Weight: 0.5, Window: 32,
			},
			{
				Name:        "人称关系",
				Words:       []string{"的手机", "的邮箱", "的电话", "的身份证", "的地址", "客户", "员工", "用户", "经办人", "联系人", "收件人"},
				Requirement: Should, Direction: Either, Weight: 0.6, Window: 32,
			},
		},
		Threshold: 0.5,
		// 低置信度的候选，证据不足即否决。
		//
		// 0.5 这条线把「确定的」与「猜的」分开：名册命中是 0.98，
		// 复姓候选是 0.70，单姓候选是 0.45。单姓在中文里到处都是——
		// 「王者荣耀」「李子」「杨梅」「金额」里都有姓——因此它必须拿出证据；
		// 复姓与名册则不必。
		//
		// 这条线是实测定的：不设它时，反例语料上多出 14 处误报，
		// 而证据链一处都没拦下。
		//
		// The line separates determined from guessed: a roster hit scores 0.98,
		// a compound-surname candidate 0.70, a single-surname candidate 0.45.
		// Single surnames are everywhere in Chinese, so they must show
		// evidence; compound surnames and roster hits need not.
		RejectUnverifiedBelow: 0.5,
		// 人名证据不足时**不**否决。
		//
		// 这是本文件里最容易配错的一处。人名是最该被脱敏的实体，而大量真实
		// 人名周围确实没有任何线索词。设成 true 会让「证据不足」变成「放行」，
		// 于是脱敏系统在最要紧的类型上默认失效——而且不报错。
		//
		// The easiest thing here to get wrong. Names are the entity most worth
		// redacting, and many have no cue words nearby. Setting this true turns
		// "no evidence" into "let it through", disabling redaction on the type
		// that matters most, silently.
		RejectUnverified: false,
		DefaultWindow:    32,
	}
}

// OrgChain 补全机构名边界。
//
// 实测问题：模型对「星辰科技有限公司」给出「科技有限公司」——丢掉了字号，
// 而字号恰恰是能识别到具体一家公司的那部分。
//
// Measured: the model returns 科技有限公司 for 星辰科技有限公司, dropping the
// distinctive part — which is the part that identifies the company.
//
// 机构名的拉伸方向与地址相反：地址向后补行政区划，机构名的问题在**前面**
// 被截掉了。向后拉伸补不了它，因此这里只做证据评分，边界问题记在
// 已知缺口里，需要靠名册或更大的模型解决。
//
// Organization names truncate at the *front*, and forward extension cannot fix
// that. This chain only scores; the boundary problem is a known gap that needs
// a roster or a larger model.
func OrgChain() *Chain {
	backward, err := DefaultBackwardExtension()
	if err != nil {
		// 锚点词表是本包写死的常量，编译不了说明代码本身有问题，
		// 而不是配置问题——这时候返回一个「没有逆向补全」的链，
		// 会让机构名从此静默地只脱敏通名。
		//
		// The anchor list is a constant in this package; failing to compile it
		// is a bug, not a misconfiguration. Returning a chain without backward
		// completion would silently redact only the generic suffix from then on.
		panic("内置机构锚点词表无法编译 / built-in anchor list failed to compile: " + err.Error())
	}
	return &Chain{
		Backward: backward,
		Type:     detect.TypeOrg,
		Shapes:   []ShapeRule{codeShape(), latinAbbreviationShape(), versionShape()},
		Cues: []Cue{
			{
				Name:        "机构后缀",
				Words:       []string{"有限公司", "股份", "集团", "银行", "研究院", "事务所", "工作室", "中心", "协会", "基金会", "大学", "学院", "医院"},
				Requirement: Should, Direction: Either, Weight: 0.6, Window: 24,
			},
			{
				Name:        "商业关系",
				Words:       []string{"供应商", "合同方", "甲方", "乙方", "客户", "合作", "采购", "签约", "开票", "抬头"},
				Requirement: Should, Direction: Before, Weight: 0.5, Window: 32,
			},
			{
				Name: "代码语法",
				Words: []string{
					"func ", "def ", "return ", "var ", "import ", "package ",
					"=>", "->", "::", "();", ");", "){",
				},
				Requirement: MustNot, Direction: Either, Window: 64,
			},
		},
		Threshold:        0.5,
		RejectUnverified: false,
		DefaultWindow:    32,
	}
}

// codeShape 否决形如函数调用或标识符的实体。
//
// 对应方案里的「语法启发式」：retry(n)、doThing()、a.b.c 这类东西
// 无论周围写着什么都不是人名。它比上下文线索更硬——上下文可能恰好没有
// 代码特征词，而形态是实体自带的。
//
// The syntactic heuristic: retry(n), doThing(), a.b.c are not names whatever
// surrounds them. Harder than a context cue, which can be defeated by a code
// snippet that happens to contain no marker words.
func codeShape() ShapeRule {
	callOrIdent := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*[(\[.]`)
	return ShapeRule{
		Name: "代码形态",
		Reject: func(v string) bool {
			if callOrIdent.MatchString(v) {
				return true
			}
			// 含代码专属符号的，同样不是人名
			return strings.ContainsAny(v, "(){}[];=<>|&")
		},
	}
}

// latinAbbreviationShape 否决拉丁字母的缩写。
//
// 实测出来的：中文模型把散文里的 deps、ST、SSE 判成人名或机构，
// 而它们周围全是正常的中文，没有任何代码特征——上下文线索完全挡不住。
//
// 人名的拉丁写法有稳定形态：首字母大写、其余小写，且通常是两段
// （Margaret Okonkwo）。全大写的短串是缩写，全小写的短串是标识符或词根。
// 这条规则挡住后两者，放过前者。
//
// Measured: the Chinese model labels deps, ST and SSE in ordinary prose as
// names or organizations, with no code markers nearby for a context cue to
// catch. A Latin personal name has a stable shape — initial capital, the rest
// lower case, usually two tokens. An all-caps or all-lower short token is an
// abbreviation or an identifier.
func latinAbbreviationShape() ShapeRule {
	// 门槛取 8 而不是 5。
	//
	// 实测 uint64（6 字符）逃过了 5 的门槛。而拉丁人名极少是单段的——
	// Smith、Johnson 这类单段名靠上下文线索（Mr./Dr.）撑住，
	// 而含空格的多段名本来就被本规则放过。
	//
	// Eight rather than five: uint64 (six characters) slipped past five.
	// Single-token Latin names are rare and are carried by context cues;
	// multi-token names are exempted by the space check above.
	const maxAbbrev = 8
	return ShapeRule{
		Name: "拉丁缩写",
		Reject: func(v string) bool {
			v = strings.TrimSpace(v)
			if v == "" || strings.ContainsAny(v, " \t") {
				// 含空格的多段拉丁串是人名的常见写法，放过
				// A multi-token Latin string is the usual shape of a name.
				return false
			}
			letters, upper, lower, nonLatin := 0, 0, 0, 0
			for _, r := range v {
				switch {
				case r >= 'A' && r <= 'Z':
					letters++
					upper++
				case r >= 'a' && r <= 'z':
					letters++
					lower++
				case unicode.IsDigit(r) || r == '.' || r == '-' || r == '_':
				default:
					nonLatin++
				}
			}
			if nonLatin > 0 || letters == 0 {
				// 含中文等非拉丁字符的，不归本规则管
				return false
			}
			if len([]rune(v)) > maxAbbrev {
				return false
			}
			// 全大写（ST、SSE）或全小写（deps）的短串
			return upper == letters || lower == letters
		},
	}
}

// versionShape 否决含点分数字串的实体。
//
// 实测：英文模型把「kernel 5.15.0.91」整段判成人名。人名里不会出现
// 5.15.0.91 这样的点分数字——这是版本号、IP 或序列号的形态。
//
// 与「IPv4 与四段式版本号字面相同」那个问题方向相反：那里是要把版本号
// 从 IP 里分出去，这里是把它从人名里分出去。同一个形态，两处都要挡。
//
// Measured: the English model labels "kernel 5.15.0.91" as a person name. A
// dotted numeric run is a version, an address or a serial — not part of a name.
func versionShape() ShapeRule {
	dotted := regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+`)
	return ShapeRule{
		Name:   "点分数字",
		Reject: func(v string) bool { return dotted.MatchString(v) },
	}
}

// DefaultChains returns the built-in chains.
// 返回内置的证据链。
func DefaultChains() []*Chain {
	return []*Chain{AddressChain(), PersonChain(), OrgChain()}
}

// NewDefaultEvidenceValidator builds a validator with the built-in chains.
// 用内置证据链构造验证器。
func NewDefaultEvidenceValidator() (*EvidenceValidator, error) {
	return NewEvidenceValidator(DefaultChains()...)
}
