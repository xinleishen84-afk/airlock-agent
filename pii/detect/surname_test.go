package detect

import (
	"strings"
	"testing"
)

func surnameRec(t *testing.T, opts SurnameOptions) *SurnameRecognizer {
	t.Helper()
	r, err := NewSurnameRecognizer(opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// 复姓是统计模型系统性漏掉的那一类，也是本识别器存在的理由。
// Compound surnames are the class models are systematically blind to.
//
// 实测：zh_core_web_md 对「欧阳志远」「尉迟恭」返回空——不是判错，是不输出。
func TestCompoundSurnamesAreRecovered(t *testing.T) {
	r := surnameRec(t, DefaultSurnameOptions())

	cases := []struct{ text, want string }{
		{"经办人欧阳志远已签字。", "欧阳志远"},
		{"尉迟恭负责本次验收。", "尉迟恭"},
		{"司徒美堂出席了会议。", "司徒美堂"},
		{"诸葛亮提出隆中对。", "诸葛亮"},
		{"上官婉儿主持了朝会。", "上官婉儿"},
		{"请联系慕容复处理。", "慕容复"},
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			got, err := r.Recognize(c.text)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, e := range got {
				if e.Value == c.want {
					found = true
					if c.text[e.Start:e.End] != e.Value {
						t.Errorf("偏移与文本对不上：text[%d:%d]=%q", e.Start, e.End, c.text[e.Start:e.End])
					}
				}
			}
			if !found {
				var vals []string
				for _, e := range got {
					vals = append(vals, e.Value)
				}
				t.Errorf("未产出候选 %q，实际候选 %v", c.want, vals)
			}
		})
	}
}

// 姓氏前面几乎总有汉字 —— 中文没有词间空格。
// A surname is nearly always preceded by a CJK character: Chinese has no
// inter-word spaces.
//
// 第一版对复姓也做了「左侧不得是汉字」的检查，结果「经办人欧阳志远」返回空——
// 把它要补的那一类全挡在了门外。这条用例钉住这个回归。
//
// The first version applied a left-boundary check to compound surnames too,
// and 经办人欧阳志远 returned nothing — excluding exactly the class it exists
// to recover.
func TestCompoundSurnameNotBlockedByLeftContext(t *testing.T) {
	r := surnameRec(t, DefaultSurnameOptions())

	for _, text := range []string{
		"经办人欧阳志远已签字。",
		"由项目负责人司徒美堂签署。",
		"客户欧阳修来电。",
	} {
		got, _ := r.Recognize(text)
		if len(got) == 0 {
			t.Errorf("%q 未产出任何候选——左边界检查把复姓挡住了", text)
		}
	}
}

// 助词紧跟姓氏时不产出候选。
// No candidate when a particle immediately follows the surname.
func TestStopRunesPreventCandidates(t *testing.T) {
	r := surnameRec(t, DefaultSurnameOptions())

	for _, text := range []string{"欧阳的方案已通过。", "司徒是谁？", "诸葛在开会。"} {
		got, _ := r.Recognize(text)
		for _, e := range got {
			t.Errorf("%q 不应产出候选，实际得到 %q", text, e.Value)
		}
	}
}

// 单姓默认关闭 —— 开启它会让候选量与误报同步上升。
// Single surnames are off by default: enabling them raises candidates and
// false positives together.
func TestSingleSurnamesAreOptIn(t *testing.T) {
	off := surnameRec(t, DefaultSurnameOptions())
	got, _ := off.Recognize("请联系张伟处理。")
	if len(got) != 0 {
		t.Errorf("默认配置不应产出单姓候选，实际 %v", got)
	}

	opts := DefaultSurnameOptions()
	opts.IncludeSingle = true
	on := surnameRec(t, opts)
	got, _ = on.Recognize("请联系张伟处理。")
	found := false
	for _, e := range got {
		if e.Value == "张伟" {
			found = true
		}
	}
	if !found {
		t.Errorf("开启单姓后应产出「张伟」，实际 %v", got)
	}
}

// 单姓的左边界检查必须生效 —— 「小王」「老李」里的姓不是姓。
// The left-boundary check must apply to single surnames.
func TestSingleSurnameLeftBoundary(t *testing.T) {
	opts := DefaultSurnameOptions()
	opts.IncludeSingle = true
	r := surnameRec(t, opts)

	got, _ := r.Recognize("小王和老李都来了。")
	for _, e := range got {
		if strings.HasPrefix(e.Value, "王") || strings.HasPrefix(e.Value, "李") {
			t.Errorf("「小王」「老李」不应产出姓氏候选，实际 %q", e.Value)
		}
	}
}

func TestSurnameOptionsValidation(t *testing.T) {
	opts := DefaultSurnameOptions()
	opts.MaxGivenRunes = 5
	if _, err := NewSurnameRecognizer(opts); err == nil {
		t.Error("名取五字应被拒绝")
	}

	opts = DefaultSurnameOptions()
	opts.CompoundScore = 0
	if _, err := NewSurnameRecognizer(opts); err == nil {
		t.Error("置信度为 0 应被拒绝")
	}
}

// 各长度候选同分 —— 长度不该在这里分高下，那是证据链的事。
// Candidates of different lengths score equally: length is the chain's call.
func TestCandidateLengthsScoreEqually(t *testing.T) {
	r := surnameRec(t, DefaultSurnameOptions())

	got, _ := r.Recognize("尉迟恭负责本次验收。")
	if len(got) < 2 {
		t.Fatalf("应产出多个长度的候选，实际 %v", got)
	}
	first := got[0].Confidence
	for _, e := range got {
		if e.Confidence != first {
			t.Errorf("候选 %q 的置信度 %.2f 与 %.2f 不同——"+
				"按长度调整置信度会在证据打平时把名字截断",
				e.Value, e.Confidence, first)
		}
	}
}
