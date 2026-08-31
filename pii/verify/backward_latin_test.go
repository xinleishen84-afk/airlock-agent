package verify

import (
	"strings"
	"testing"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// extendOrg 走一遍证据链，返回拉伸后的文本片段。
func extendOrg(t *testing.T, v *EvidenceValidator, text, detected string) (string, bool) {
	t.Helper()
	idx := strings.Index(text, detected)
	if idx < 0 {
		t.Fatalf("夹具错误：%q 不在 %q 里", detected, text)
	}
	e := detect.Entity{
		Type: detect.TypeOrg, Value: detected,
		Start: idx, End: idx + len(detected), Confidence: 0.9, Detector: "test",
	}
	out := v.ValidateAll(text, []detect.Entity{e})
	if len(out) == 0 {
		return "", false
	}
	return text[out[0].Entity.Start:out[0].Entity.End], true
}

// TestLatinOrgHeadIsCompleted 证明拉丁文机构名的字号会被补回来。
// Proves the distinctive head of a Latin organization name is recovered.
//
// # 这里此前一步都走不了
// # This path could not take its first step
//
// 锚点表原本是纯中文的，因此拉丁文机构名连拉伸的门槛都进不去：实测
// "invoice from Acme Global Ltd" 检出 Ltd 之后原样返回 Ltd——通名被脱敏，
// 而 Acme Global 这个真正识别到具体一家的部分原样出境，审计里显示 ORG:1。
//
// 只补锚点还不够：中文靠停止字划界，而拉丁文靠空格分词，空格本身就在停止字
// 表里，一步就停。所以拉丁文走单独的边界规则——首字母大写。
//
// The anchor list was Chinese-only, so the gate never opened. Adding anchors
// alone is insufficient: Chinese bounds with stop characters while Latin
// separates on spaces, which are themselves stop characters.
func TestLatinOrgHeadIsCompleted(t *testing.T) {
	v, err := NewDefaultEvidenceValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, text, detected, want string }{
		{"两词字号", "invoice from Acme Global Ltd today", "Ltd", "Acme Global Ltd"},
		{"德语通名", "contract with Northwind Trading GmbH", "GmbH", "Northwind Trading GmbH"},
		{"美式通名", "paid to Contoso Inc last week", "Inc", "Contoso Inc"},
		{"全大写", "ACME GLOBAL LTD INVOICE", "LTD", "ACME GLOBAL LTD"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := extendOrg(t, v, c.text, c.detected)
			if !ok {
				t.Fatalf("%q 被否决", c.detected)
			}
			if got != c.want {
				t.Errorf("拉伸结果 %q，期望 %q——字号没补全的话，"+
					"脱敏掉的只是通名，识别到具体一家的那部分原样出境", got, c.want)
			}
		})
	}
}

// TestLatinOrgDoesNotSwallowSentence 证明拉伸不会把句子吞进来。
// Proves the extension does not swallow the sentence.
//
// # 只靠大小写会吞掉句首
// # Capitalization alone swallows the start of a sentence
//
// 大写是拉丁文里最接近中文停止字的边界信号，但英文还会把句首、月份、星期、
// 章节标签都大写。第一版只看大小写，实测五个句子错了三个：
// "On Monday Acme Ltd" 整段被当成机构名。
//
// 过度脱敏是效用损失而不是泄露，但它同样是错的：下游拿到一个没人认得的实体，
// 而运维从计数上看不出任何异常——ORG:1 在两种情况下长得一样。
//
// Over-redaction is a utility loss rather than a leak, but it is still wrong:
// the downstream receives an entity nobody recognizes while ORG:1 reads the
// same either way.
func TestLatinOrgDoesNotSwallowSentence(t *testing.T) {
	v, err := NewDefaultEvidenceValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, text, detected, want string }{
		{"句首大写", "On Monday Acme Ltd filed a claim", "Ltd", "Acme Ltd"},
		{"月份", "In January Contoso Inc reported", "Inc", "Contoso Inc"},
		{"冠词", "the Acme Ltd invoice", "Ltd", "Acme Ltd"},
		{"物主代词", "Our client Northwind GmbH agreed", "GmbH", "Northwind GmbH"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := extendOrg(t, v, c.text, c.detected)
			if !ok {
				t.Fatalf("%q 被否决", c.detected)
			}
			if got != c.want {
				t.Errorf("拉伸到 %q，期望 %q——把句首/月份当成机构名的一部分，"+
					"下游拿到的是一个没人认得的实体", got, c.want)
			}
		})
	}
}

// TestChineseOrgExtensionUnchanged 确认拉丁文这条分支没有动到中文路径。
// Confirms the Latin branch left the Chinese path untouched.
func TestChineseOrgExtensionUnchanged(t *testing.T) {
	v, err := NewDefaultEvidenceValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ text, detected, want string }{
		{"我在星辰科技有限公司工作", "科技有限公司", "星辰科技有限公司"},
		{"客户是临安远景网络科技有限公司", "网络科技有限公司", "临安远景网络科技有限公司"},
	} {
		got, ok := extendOrg(t, v, c.text, c.detected)
		if !ok {
			t.Fatalf("%q 被否决", c.detected)
		}
		if got != c.want {
			t.Errorf("中文拉伸回归：得到 %q，期望 %q", got, c.want)
		}
	}
}
