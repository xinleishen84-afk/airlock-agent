package detect

import (
	"testing"
)

const (
	validID   = "110101199003078515"
	validCard = "4111111111111111"
)

// newTestDetector 构造与 Python 参考实现相同配置的组合检测器。
func newTestDetector(t *testing.T) *CompositeDetector {
	t.Helper()
	gaz, err := NewGazetteerDetector(map[EntityType][]string{
		TypeName: {"张伟", "李娜"},
		TypeOrg:  {"星辰科技有限公司"},
	}, false, 2)
	if err != nil {
		t.Fatalf("构造名册检测器失败: %v", err)
	}
	return NewCompositeDetector([]Detector{NewRegexDetector(), gaz}, 0)
}

// TestDetectStructuredIdentifiers 校验结构化标识全部检出，与 Python 版断言一致。
func TestDetectStructuredIdentifiers(t *testing.T) {
	text := "张伟 13812345678 " + validID + " " + validCard + " a@b.com sk-abcdefghij1234567890"
	entities, err := newTestDetector(t).Detect(text)
	if err != nil {
		t.Fatalf("检测失败: %v", err)
	}
	got := map[EntityType]bool{}
	for _, e := range entities {
		got[e.Type] = true
	}
	want := []EntityType{TypeName, TypePhone, TypeIDCard, TypeBankCard, TypeEmail, TypeCredential}
	for _, w := range want {
		if !got[w] {
			t.Errorf("未检出类型 %s；实际检出 %v", w, entities)
		}
	}
}

// TestNoFalsePositiveOnRandomDigits 校验随机长数字串不被误判为银行卡。
func TestNoFalsePositiveOnRandomDigits(t *testing.T) {
	entities, err := newTestDetector(t).Detect("订单号 12345678901234，序列号 98765432109876")
	if err != nil {
		t.Fatalf("检测失败: %v", err)
	}
	for _, e := range entities {
		if e.Type == TypeBankCard {
			t.Errorf("随机数字串被误判为银行卡: %q", e.Value)
		}
	}
}

// TestBoundaryRewriteKeepsPrecision 校验 RE2 哨兵组改写后边界依然有效。
// 这是移植中最容易出错的一处：lookbehind 改成哨兵组后，
// 若边界失效，长数字串中间的子串会被误当成手机号。
func TestBoundaryRewriteKeepsPrecision(t *testing.T) {
	d := NewRegexDetector()
	cases := []struct {
		text     string
		wantHits int
		desc     string
	}{
		{"13812345678", 1, "裸号"},
		{"电话13812345678。", 1, "中文包裹"},
		{"9913812345678", 0, "嵌在更长数字串中，不应命中"},
		{"13812345678901", 0, "尾部超长，不应命中"},
		{"13812345678 13900001111", 2, "空格分隔的两个号码"},
	}
	for _, c := range cases {
		entities, _ := d.Detect(c.text)
		hits := 0
		for _, e := range entities {
			if e.Type == TypePhone {
				hits++
			}
		}
		if hits != c.wantHits {
			t.Errorf("%s: %q 命中 %d 个手机号，期望 %d", c.desc, c.text, hits, c.wantHits)
		}
	}
}

// TestOffsetsAreAccurate 校验偏移量精确——哨兵组吃掉了前后字符，
// 若取整体匹配而非 group 1，偏移会整体偏移一位，替换后文本会被破坏。
func TestOffsetsAreAccurate(t *testing.T) {
	d := NewRegexDetector()
	text := "电话 13812345678 结束"
	entities, _ := d.Detect(text)
	for _, e := range entities {
		if text[e.Start:e.End] != e.Value {
			t.Errorf("偏移量不准: text[%d:%d]=%q 但 Value=%q", e.Start, e.End, text[e.Start:e.End], e.Value)
		}
	}
}

// TestOverlapResolutionPrefersLonger 校验重叠消解取语义正确的长片段。
func TestOverlapResolutionPrefersLonger(t *testing.T) {
	entities, err := newTestDetector(t).Detect("证件 " + validID)
	if err != nil {
		t.Fatalf("检测失败: %v", err)
	}
	if len(entities) != 1 || entities[0].Type != TypeIDCard {
		t.Errorf("期望仅检出 1 个 ID_CARD，实际: %+v", entities)
	}
}

// TestGazetteerLongestMatchFirst 校验名册优先匹配更长词条。
func TestGazetteerLongestMatchFirst(t *testing.T) {
	gaz, err := NewGazetteerDetector(map[EntityType][]string{
		TypeName: {"张三", "张三丰"},
	}, false, 2)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	found, _ := gaz.Detect("弟子张三丰求见")
	entities := ResolveOverlaps(found)
	if len(entities) != 1 || entities[0].Value != "张三丰" {
		t.Errorf("期望匹配「张三丰」，实际: %+v", entities)
	}
}

// TestCompositeReportsMissingNERTypes 校验缺少姓名类检测能力时能被发现。
func TestCompositeReportsMissingNERTypes(t *testing.T) {
	d := NewCompositeDetector([]Detector{NewRegexDetector()}, 0)
	missing := d.Missing()
	if len(missing) == 0 {
		t.Fatal("仅有正则检测器时应报告缺少 NAME/ADDRESS/ORG 覆盖")
	}
	found := false
	for _, m := range missing {
		if m == TypeName {
			found = true
		}
	}
	if !found {
		t.Errorf("缺口列表应含 NAME，实际: %v", missing)
	}
}

// TestDetectorFailurePropagates 校验单个检测器故障整体上抛。
func TestDetectorFailurePropagates(t *testing.T) {
	d := NewCompositeDetector([]Detector{brokenDetector{}}, 0)
	if _, err := d.Detect("任意文本"); err == nil {
		t.Fatal("检测器故障必须上抛，不能静默削弱防护")
	}
}

// brokenDetector 是故意失败的检测器，用于验证故障传播。
type brokenDetector struct{}

func (brokenDetector) Name() string               { return "broken" }
func (brokenDetector) CoveredTypes() []EntityType { return nil }
func (brokenDetector) Detect(string) ([]Entity, error) {
	return nil, errBroken
}

// errBroken 是测试用的固定错误。
var errBroken = &detectorError{"模型服务不可用"}

// detectorError 是测试用错误类型。
type detectorError struct{ msg string }

func (e *detectorError) Error() string { return e.msg }

// TestGreedyBankCardRegression 锁定「贪婪匹配吞掉真卡号」这个回归。
//
// 曾用 `(?:[0-9][ \-]?){12,19}` 匹配银行卡，它会跨过空格把身份证和卡号
// 连成一片，Luhn 校验失败后扫描位置已推进，真正的卡号被吞掉。
// 若有人改回贪婪写法，本用例会立刻失败。
func TestGreedyBankCardRegression(t *testing.T) {
	d := NewRegexDetector()
	text := validID + " " + validCard
	entities, _ := d.Detect(text)

	var cards, ids int
	for _, e := range entities {
		switch e.Type {
		case TypeBankCard:
			cards++
			if e.Value != validCard {
				t.Errorf("卡号识别错误: %q", e.Value)
			}
		case TypeIDCard:
			ids++
		}
	}
	if cards != 1 || ids != 1 {
		t.Errorf("紧邻的身份证与卡号应各检出 1 个，实际 card=%d id=%d；明细 %+v", cards, ids, entities)
	}
}

// TestGroupedBankCardFormats 校验四位分组书写的卡号能被识别。
func TestGroupedBankCardFormats(t *testing.T) {
	d := NewRegexDetector()
	for _, text := range []string{
		"4111 1111 1111 1111",
		"4111-1111-1111-1111",
		"4111111111111111",
	} {
		entities, _ := d.Detect("卡号 " + text + " 结束")
		hit := false
		for _, e := range entities {
			if e.Type == TypeBankCard {
				hit = true
			}
		}
		if !hit {
			t.Errorf("未识别卡号格式: %q", text)
		}
	}
}

// TestAdjacentEntitiesBothDetected 校验相邻实体不会因边界消费而互相遮蔽。
func TestAdjacentEntitiesBothDetected(t *testing.T) {
	d := NewRegexDetector()
	entities, _ := d.Detect("13812345678 13900001111 13700002222")
	count := 0
	for _, e := range entities {
		if e.Type == TypePhone {
			count++
		}
	}
	if count != 3 {
		t.Errorf("三个相邻手机号应全部检出，实际 %d 个: %+v", count, entities)
	}
}

// TestUTF8OffsetsSafe 校验中文环境下偏移量与边界检查不越界。
func TestUTF8OffsetsSafe(t *testing.T) {
	d := NewRegexDetector()
	text := "客户张伟的手机是13812345678，身份证" + validID + "。"
	entities, _ := d.Detect(text)
	if len(entities) == 0 {
		t.Fatal("中文文本中未检出任何实体")
	}
	for _, e := range entities {
		if e.Start < 0 || e.End > len(text) || text[e.Start:e.End] != e.Value {
			t.Errorf("偏移越界或不匹配: [%d:%d] = %q, Value=%q", e.Start, e.End, text[e.Start:e.End], e.Value)
		}
	}
}
