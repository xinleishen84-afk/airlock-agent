package verify

import "github.com/xinleishen84-afk/airlock-agent/pii/detect"

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
		Type: detect.TypeName,
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
				Name:        "人类动作",
				Words:       []string{"说", "问", "答", "联系", "通知", "告诉", "签字", "签署", "负责", "提交", "审批", "出席", "参会", "打电话", "发邮件"},
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
	return &Chain{
		Type: detect.TypeOrg,
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
