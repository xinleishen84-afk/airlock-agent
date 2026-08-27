package verify

import (
	"strings"
	"testing"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

func orgAt(text, value string) detect.Entity {
	i := strings.Index(text, value)
	if i < 0 {
		panic("测试文本里没有 " + value)
	}
	return detect.Entity{
		Type: detect.TypeOrg, Value: value, Start: i, End: i + len(value),
		Confidence: 0.6, Detector: "ner:test",
	}
}

// 前端截断必须被补全 —— 丢掉的那一半才是识别到具体一家的那部分。
// A truncated head must be completed: the dropped half is the identifying one.
//
// 「科技有限公司」在中国有几十万家，它不识别任何一家；「星辰科技有限公司」
// 才识别一家。脱敏掉通名、留下字号，等于什么都没脱敏，而审计日志会显示
// ORG:1，看起来一切正常。
func TestOrganizationHeadIsCompleted(t *testing.T) {
	v := validator(t)

	cases := []struct{ text, detected, want string }{
		{"合同方为星辰科技有限公司。", "科技有限公司", "星辰科技有限公司"},
		{"供应商是临安远景机械制造有限公司。", "机械制造有限公司", "临安远景机械制造有限公司"},
		{"由中国工商银行代扣。", "银行", "中国工商银行"},
		{"请到北京市第一中级人民法院。", "法院", "北京市第一中级人民法院"},
		{"就诊于浙江大学医学院附属第一医院。", "医院", "浙江大学医学院附属第一医院"},
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			d := v.Validate(c.text, orgAt(c.text, c.detected))
			if d.Entity.Value != c.want {
				t.Errorf("补全结果不符：\n得到 %q\n期望 %q", d.Entity.Value, c.want)
			}
			if c.text[d.Entity.Start:d.Entity.End] != d.Entity.Value {
				t.Errorf("补全后偏移与文本对不上")
			}
		})
	}
}

// 过度扩展必须被挡住 —— 这是逆向补全的主要失败模式。
// Over-extension must be blocked: it is the main failure mode here.
//
// 向后拉伸有天然终点（门牌特征字），向前没有。停止字是唯一的边界依据，
// 而它一旦漏掉一个常用动词，机构名就会把前面的谓语一起吞进来。
//
// 实测漏过一次：停止字表里没有「到」，于是「请到北京市…法院」扩成了
// 「请到北京市…法院」——而它仍然通过了评分，因为扩展段里有「市」。
func TestBackwardExtensionDoesNotSwallowProse(t *testing.T) {
	v := validator(t)

	cases := []struct{ text, detected, mustNotContain string }{
		{"请到北京市第一中级人民法院。", "法院", "请到"},
		{"他去了杭州市中医院。", "医院", "他去了"},
		{"我们找到了星辰科技有限公司。", "科技有限公司", "找到"},
		{"合同方为星辰科技有限公司。", "科技有限公司", "合同方"},
		{"付款给中国工商银行。", "银行", "付款"},
	}
	for _, c := range cases {
		t.Run(c.mustNotContain, func(t *testing.T) {
			d := v.Validate(c.text, orgAt(c.text, c.detected))
			if strings.Contains(d.Entity.Value, c.mustNotContain) {
				t.Errorf("扩展吞入了散文 %q：得到 %q", c.mustNotContain, d.Entity.Value)
			}
		})
	}
}

// 不以机构通名结尾的实体不做逆向扩展。
// An entity not ending in an organizational suffix is not extended.
//
// 锚点是整个机制的闸门：没有通名结尾，前面丢了什么无从判断，
// 强行向左扩只会把动词和主语一起吞进来。
func TestNoAnchorNoExtension(t *testing.T) {
	v := validator(t)

	for _, c := range []struct{ text, detected string }{
		{"他在阿里巴巴工作。", "阿里巴巴"},
		{"客户是腾讯。", "腾讯"},
		{"由华为提供设备。", "华为"},
	} {
		t.Run(c.detected, func(t *testing.T) {
			d := v.Validate(c.text, orgAt(c.text, c.detected))
			if d.Entity.Value != c.detected {
				t.Errorf("无锚点的实体不该被扩展：%q → %q", c.detected, d.Entity.Value)
			}
		})
	}
}

// 扩展段过长时整体放弃，而不是截一半。
// An implausibly long extension is abandoned entirely, not truncated.
//
// 截一半会产出一个既不是原值也不是正确答案的边界，而那个边界看起来
// 和一次正常的补全完全一样。
func TestOverlongExtensionIsAbandoned(t *testing.T) {
	v := validator(t)

	// 通名前面是一长段没有停止字的散文
	text := "这是一段很长的没有任何停止字的描述文字接着出现有限公司。"
	d := v.Validate(text, orgAt(text, "有限公司"))

	if d.Entity.Value != "有限公司" {
		t.Errorf("过长的扩展应整体放弃，实际得到 %q", d.Entity.Value)
	}
}

// 已经完整的机构名不该被再往左扩。
// A name that is already complete must not be extended further.
func TestCompleteNameIsNotExtended(t *testing.T) {
	v := validator(t)

	const text = "合同方为星辰科技有限公司。"
	d := v.Validate(text, orgAt(text, "星辰科技有限公司"))

	if d.Entity.Value != "星辰科技有限公司" {
		t.Errorf("完整的机构名不该被扩展：得到 %q", d.Entity.Value)
	}
}

// 锚点匹配取最长 —— 「有限公司」而不是「公司」。
// The longest anchor wins.
func TestLongestAnchorWins(t *testing.T) {
	b, err := DefaultBackwardExtension()
	if err != nil {
		t.Fatal(err)
	}
	anchor, ok := b.endsWithAnchor("星辰科技有限公司")
	if !ok {
		t.Fatal("应识别出锚点")
	}
	if anchor != "有限公司" {
		t.Errorf("应取最长锚点「有限公司」，实际 %q", anchor)
	}
}

// 逆向扩展与地址的向后拉伸互不干扰。
// Backward completion and forward address extension do not interfere.
func TestBothDirectionsCoexist(t *testing.T) {
	v := validator(t)

	// 地址：向后
	const addrText = "寄往北京市海淀区中关村大街1号。"
	addrDec := v.Validate(addrText, addr(addrText, "北京市"))
	if addrDec.Entity.Value != "北京市海淀区中关村大街1号" {
		t.Errorf("地址向后拉伸受影响：%q", addrDec.Entity.Value)
	}

	// 机构：向前
	const orgText = "合同方为星辰科技有限公司。"
	orgDec := v.Validate(orgText, orgAt(orgText, "科技有限公司"))
	if orgDec.Entity.Value != "星辰科技有限公司" {
		t.Errorf("机构向前补全受影响：%q", orgDec.Entity.Value)
	}
}
