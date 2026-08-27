package verify

import (
	"strings"
	"testing"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

func addr(text, value string) detect.Entity {
	i := strings.Index(text, value)
	return detect.Entity{Type: detect.TypeAddress, Value: value, Start: i, End: i + len(value)}
}

func person(text, value string) detect.Entity {
	i := strings.Index(text, value)
	return detect.Entity{Type: detect.TypeName, Value: value, Start: i, End: i + len(value)}
}

func org(text, value string) detect.Entity {
	i := strings.Index(text, value)
	return detect.Entity{Type: detect.TypeOrg, Value: value, Start: i, End: i + len(value)}
}

func validator(t *testing.T) *EvidenceValidator {
	t.Helper()
	v, err := NewDefaultEvidenceValidator()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// ---------------------------------------------------------------------------
// 地址边界拉伸
// ---------------------------------------------------------------------------

// 模型只给出行政区划开头时，边界必须被拉伸到证据链断裂处。
// When the model returns only the leading administrative unit, the boundary
// must stretch to where the evidence chain breaks.
//
// 不拉伸的后果不是「检测失败」，而是**部分脱敏**：门牌号照样出境，
// 而审计日志显示 ADDRESS:1，看起来一切正常。
// The consequence of not stretching is not a miss but a partial redaction: the
// street number still leaves, while the audit log reads ADDRESS:1.
func TestAddressBoundaryExtension(t *testing.T) {
	v := validator(t)

	cases := []struct{ text, detected, want string }{
		{"寄往北京市海淀区中关村大街1号。", "北京市", "北京市海淀区中关村大街1号"},
		{"地址：上海市浦东新区世纪大道100号12层。", "上海市", "上海市浦东新区世纪大道100号12层"},
		{"住在广州市天河区。", "广州市", "广州市天河区"},
		{"公司在杭州市余杭区文一西路969号3栋502室办公。", "杭州市", "杭州市余杭区文一西路969号3栋502室"},
	}
	for _, c := range cases {
		t.Run(c.detected, func(t *testing.T) {
			d := v.Validate(c.text, addr(c.text, c.detected))
			if d.Entity.Value != c.want {
				t.Errorf("拉伸结果不符：\n得到 %q\n期望 %q", d.Entity.Value, c.want)
			}
			if c.text[d.Entity.Start:d.Entity.End] != d.Entity.Value {
				t.Errorf("拉伸后偏移与文本对不上")
			}
		})
	}
}

// 拉伸必须在证据断裂处停下，不能一路吞到句末。
// Extension must stop where the chain breaks, not run to the end of the clause.
func TestAddressExtensionStopsAtChainBreak(t *testing.T) {
	v := validator(t)

	cases := []struct{ text, detected, want string }{
		// 「的会议室」不以行政区划或门牌特征字结尾
		{"寄往北京市海淀区中关村大街1号的会议室。", "北京市", "北京市海淀区中关村大街1号"},
		// 标点即断
		{"住在广州市，联系电话另附。", "广州市", "广州市"},
		// 后面完全没有地址成分
		{"他从北京市出发去开会。", "北京市", "北京市"},
	}
	for _, c := range cases {
		t.Run(c.text[:12], func(t *testing.T) {
			d := v.Validate(c.text, addr(c.text, c.detected))
			if d.Entity.Value != c.want {
				t.Errorf("得到 %q，期望 %q", d.Entity.Value, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 代码误判否决
// ---------------------------------------------------------------------------

// 落在代码里的人名误判必须被否决。
// A person-name misclassification inside code must be rejected.
//
// 实测：zh_core_web_sm 把 func、nil 判成人名，md 把 retry(n 判成人名。
// 不否决就意味着脱敏管线去改写源代码。
func TestCodeMisclassificationIsRejected(t *testing.T) {
	v := validator(t)

	cases := []struct{ text, detected string }{
		{"func retry(n int) error { return nil }", "retry(n"},
		{"func retry(n int) error { return nil }", "nil"},
		{"const MASK = 0xDEAD; return MASK;", "MASK"},
		{"def handler(request): return None", "handler"},
		{"import package main; var x int", "main"},
		{"if (a == b) { doThing(); }", "doThing"},
	}
	for _, c := range cases {
		t.Run(c.detected, func(t *testing.T) {
			d := v.Validate(c.text, person(c.text, c.detected))
			if d.Verdict != VerdictDrop {
				t.Errorf("代码里的 %q 应被否决，实际 %s（证据 %v）",
					c.detected, d.Verdict, d.Evidence)
			}
			// 理由可以是形态规则也可以是上下文线索，两条路都成立。
			//
			// 形态规则先跑：它不需要看上下文。retry(n 自身就长得像函数调用，
			// nil / MASK / main 自身就是拉丁缩写形态——这些不需要周围有
			// func 或 return 才能判定。断言写死某一条理由，会让「换了一条
			// 更早、更硬的路把它挡下」看起来像回归。
			//
			// Either a shape rule or a context cue is a valid reason. Shape
			// rules run first because they need no context. Asserting one
			// specific reason makes "caught earlier by a harder rule" look
			// like a regression.
			rejectedBy := map[string]bool{"代码语法": true, "代码形态": true, "拉丁缩写": true}
			ok := false
			for _, name := range d.Evidence {
				if rejectedBy[name] {
					ok = true
				}
			}
			if !ok {
				t.Errorf("否决理由应来自代码或缩写规则，实际 %v", d.Evidence)
			}
		})
	}
}

// 有人类上下文的人名必须保留 —— 收紧误报不能以漏掉真人为代价。
// Names with human context must be kept: tightening precision must not cost
// real people.
func TestRealNamesWithHumanContextAreKept(t *testing.T) {
	v := validator(t)

	cases := []struct{ text, detected string }{
		{"请联系张伟处理此事。", "张伟"},
		{"经办人李娜已签字确认。", "李娜"},
		{"王强说下周交付。", "王强"},
		{"客户赵敏的手机是 13812345678。", "赵敏"},
		{"陈静经理出席了会议。", "陈静"},
		{"Mr. Smith will attend.", "Smith"},
	}
	for _, c := range cases {
		t.Run(c.detected, func(t *testing.T) {
			d := v.Validate(c.text, person(c.text, c.detected))
			if d.Verdict != VerdictKeep {
				t.Errorf("%q 应被保留，实际 %s（得分 %.2f 证据 %v）",
					c.detected, d.Verdict, d.Score, d.Evidence)
			}
		})
	}
}

// 没有任何线索的人名必须是 UNKNOWN，不能是 DROP。
// A name with no cues must be UNKNOWN, never DROP.
//
// 这是本包最容易配错的一处：人名是最该被脱敏的实体，而大量真实人名周围
// 确实没有线索词。把「证据不足」当成「放行」，等于在最要紧的类型上
// 静默关掉脱敏。
//
// The easiest thing to get wrong: names are the entity most worth redacting,
// and many have no cues nearby. Treating "no evidence" as "let it through"
// silently disables redaction on the type that matters most.
func TestNamesWithoutCuesAreNotDropped(t *testing.T) {
	v := validator(t)

	for _, text := range []string{
		"张三目前住在杭州。",
		"周慧敏昨天来过。",
		"名单：赵敏、孙悟空、钱多多。",
	} {
		t.Run(text[:9], func(t *testing.T) {
			name := strings.SplitN(strings.TrimPrefix(text, "名单："), "目前", 2)[0]
			name = strings.SplitN(name, "昨天", 2)[0]
			name = strings.SplitN(name, "、", 2)[0]
			d := v.Validate(text, person(text, name))
			if d.Verdict == VerdictDrop {
				t.Errorf("无线索的人名 %q 被否决了——这会让人名脱敏静默失效", name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 校验位类型不受上下文左右
// ---------------------------------------------------------------------------

// 带校验位的类型不配证据链，必须原样通过。
// Checksum-backed types have no chain and must pass through untouched.
//
// 一个校验位正确的身份证号，无论周围写着什么都是身份证号。让上下文去否决
// 算术已经给出的确定答案，是把「概率性抽取需要验证」错用到了不需要验证的
// 地方。
//
// A valid ID number is one whatever the sentence says. Letting context overrule
// an arithmetic answer misapplies "probabilistic extraction needs verification"
// to something that is not probabilistic.
func TestChecksumTypesArePassedThrough(t *testing.T) {
	v := validator(t)

	text := "func f() { return 11010519491231002X }"
	e := detect.Entity{
		Type: detect.TypeIDCard, Value: "11010519491231002X",
		Start: strings.Index(text, "11010519491231002X"),
	}
	e.End = e.Start + len(e.Value)

	d := v.Validate(text, e)

	if d.Verdict != VerdictKeep {
		t.Errorf("身份证号在代码里也是身份证号，应保留，实际 %s", d.Verdict)
	}
	if d.Entity.Value != e.Value {
		t.Errorf("不应被改动：%q", d.Entity.Value)
	}
}

// ---------------------------------------------------------------------------
// 构造与审计
// ---------------------------------------------------------------------------

func TestDuplicateChainRejected(t *testing.T) {
	if _, err := NewEvidenceValidator(PersonChain(), PersonChain()); err == nil {
		t.Fatal("同一类型配两条链应被拒绝")
	}
}

// 审计输出只给线索名，绝不给命中的文本片段。
// Audit output carries cue names only, never the matched text.
func TestEvidenceCarriesNoPayloadText(t *testing.T) {
	v := validator(t)
	const text = "客户赵敏的手机是 13812345678。"

	d := v.Validate(text, person(text, "赵敏"))

	for _, name := range d.Evidence {
		if strings.Contains(name, "赵敏") || strings.Contains(name, "138") {
			t.Errorf("证据里夹带了原文片段：%q", name)
		}
	}
	if strings.Contains(d.Reason, "赵敏") {
		t.Errorf("理由里夹带了原文片段：%q", d.Reason)
	}
	t.Logf("证据 %v，理由 %q", d.Evidence, d.Reason)
}

// 上下文窗口按字符边界切，不能把汉字切成两半。
// The context window cuts on rune boundaries.
func TestContextWindowRespectsRuneBoundaries(t *testing.T) {
	v := validator(t)
	// 让窗口边缘恰好落在汉字中间的构造
	for pad := range 12 {
		text := strings.Repeat("客", pad) + "请联系张伟处理"
		d := v.Validate(text, person(text, "张伟"))
		if d.Verdict == "" {
			t.Fatalf("pad=%d 时验证器返回了空结论", pad)
		}
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// 只有一个候选时，被否决的那个也必须被过滤掉。
// A single rejected candidate must still be filtered.
//
// ResolveByEvidence 曾经有一条「少于两个候选就直接返回」的快路径，
// 它跳过了 DROP 过滤。症状极其隐蔽：单独调 Validate 看到的是 DROP，
// 而走 ValidateAll 的流水线却把它留下了——两处行为不一致，
// 且只在「文本恰好只产出一个候选」时显形。
//
// ResolveByEvidence had a "fewer than two, return as-is" fast path that
// skipped the DROP filter. The symptom was subtle: an isolated Validate said
// DROP while the pipeline kept it, diverging only when a text yields exactly
// one candidate.
func TestSingleRejectedCandidateIsFiltered(t *testing.T) {
	v := validator(t)
	const text = "func retry(n int) error { return nil }"

	// 恰好一个候选，且它应当被否决
	one := []detect.Entity{person(text, "retry(n")}

	if d := v.Validate(text, one[0]); d.Verdict != VerdictDrop {
		t.Fatalf("前提不成立：单独验证应为 DROP，实际 %s", d.Verdict)
	}

	kept := v.ValidateAll(text, one)
	if len(kept) != 0 {
		t.Errorf("被否决的唯一候选必须被过滤掉，实际留下 %d 个：%+v", len(kept), kept)
	}
}

// 空输入与全部否决的输入都必须返回空。
// Empty input and all-rejected input must both return empty.
func TestValidateAllEdgeCases(t *testing.T) {
	v := validator(t)

	if got := v.ValidateAll("任意文本", nil); len(got) != 0 {
		t.Errorf("空输入应返回空，实际 %d", len(got))
	}

	const code = "func a() { return b(); }"
	all := []detect.Entity{person(code, "a"), person(code, "b")}
	if got := v.ValidateAll(code, all); len(got) != 0 {
		t.Errorf("全部否决时应返回空，实际 %d：%+v", len(got), got)
	}
}

// 低置信度候选无证据即否决，高置信度候选不受影响。
// Low-confidence candidates are rejected without evidence; high-confidence
// ones are not.
func TestConfidenceTieredRejection(t *testing.T) {
	v := validator(t)
	const text = "王者荣耀的新赛季已经开启。"

	// 启发式姓氏候选：0.45
	guess := detect.Entity{
		Type: detect.TypeName, Value: "王者荣", Confidence: 0.45,
		Start: 0, End: len("王者荣"),
	}
	if d := v.Validate(text, guess); d.Verdict != VerdictDrop {
		t.Errorf("0.45 的猜测候选无证据时应被否决，实际 %s（%s）", d.Verdict, d.Reason)
	}

	// 名册命中：0.98
	roster := guess
	roster.Confidence = 0.98
	if d := v.Validate(text, roster); d.Verdict == VerdictDrop {
		t.Errorf("0.98 的名册命中不应因缺证据被否决：%s", d.Reason)
	}
}

// 置信度未设置时必须走安全的那一边 —— 继续脱敏，而不是否决。
// An unset confidence must take the safe side: keep redacting, not reject.
//
// 「没有这个信息」与「置信度很低」在脱敏系统里后果相反：把前者当成后者
// 会导致否决，而对人名来说否决就是不脱敏、就是泄露。
func TestUnsetConfidenceTakesTheSafeSide(t *testing.T) {
	v := validator(t)
	const text = "张三目前住在杭州。"

	e := person(text, "张三") // person() 不设置 Confidence，即为 0
	if e.Confidence != 0 {
		t.Fatalf("前提不成立：本用例需要未设置的置信度，实际 %v", e.Confidence)
	}

	if d := v.Validate(text, e); d.Verdict == VerdictDrop {
		t.Errorf("置信度未设置的人名不应被否决——否决就是不脱敏：%s", d.Reason)
	}
}

// 形态规则挡住上下文挡不住的那一类。
// Shape rules catch what context cues cannot.
//
// 实测：中文模型把散文里的 deps、ST、SSE 判成人名或机构，而它们周围全是
// 正常的中文，没有任何代码特征——上下文线索完全挡不住。三层级联接上之后
// 的第一次评测，反例语料上正是这三处误报。
//
// Measured: the Chinese model labels deps, ST and SSE in ordinary prose, with
// no code markers nearby for a context cue to catch. These three were the only
// false positives in the first full-stack evaluation.
func TestLatinAbbreviationsAreRejected(t *testing.T) {
	v := validator(t)

	reject := []struct{ text, value string }{
		{"deps: react@18.2.0, typescript@5.3.3", "deps"},
		{"心电图示 ST 段压低，诊断为不稳定型心绞痛。", "ST"},
		{"网关 SSE 逐帧 flush 保持 TTFT。", "SSE"},
		{"用 API 调用即可。", "API"},
	}
	for _, c := range reject {
		t.Run(c.value, func(t *testing.T) {
			if d := v.Validate(c.text, person(c.text, c.value)); d.Verdict != VerdictDrop {
				t.Errorf("拉丁缩写 %q 不该被判成人名，实际 %s", c.value, d.Verdict)
			}
		})
	}
}

// 但真实的拉丁人名必须留下 —— 收紧不能以漏掉真人为代价。
// Real Latin names must survive: tightening must not cost real people.
func TestLatinNamesSurviveShapeRules(t *testing.T) {
	v := validator(t)

	keep := []struct{ text, value string }{
		{"Mr. Smith will attend the meeting.", "Smith"},
		{"请联系 Margaret Okonkwo 确认。", "Margaret Okonkwo"},
		{"经办人 Johnson 已签字。", "Johnson"},
		{"客户 Alexander 的订单。", "Alexander"},
	}
	for _, c := range keep {
		t.Run(c.value, func(t *testing.T) {
			d := v.Validate(c.text, person(c.text, c.value))
			if d.Verdict == VerdictDrop {
				t.Errorf("真实人名 %q 被形态规则误杀：%s", c.value, d.Reason)
			}
		})
	}
}

// 中文人名不归拉丁缩写规则管。
// The Latin-abbreviation rule must not touch Chinese names.
func TestChineseNamesUnaffectedByLatinRule(t *testing.T) {
	v := validator(t)
	for _, name := range []string{"张伟", "李娜", "欧阳志远", "周慧敏"} {
		text := "请联系" + name + "处理。"
		if d := v.Validate(text, person(text, name)); d.Verdict == VerdictDrop {
			t.Errorf("中文人名 %q 被误杀：%s", name, d.Reason)
		}
	}
}
