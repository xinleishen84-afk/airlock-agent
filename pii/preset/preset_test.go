package preset

import (
	"strings"
	"testing"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/verify"
)

// resolve 走完整路径：检测 → 证据链消解，与 sidecar 里的 verifyingDetector 相同。
func resolve(t *testing.T, d detect.Detector, v *verify.EvidenceValidator, text string) []string {
	t.Helper()
	found, err := d.Detect(text)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, dec := range v.ValidateAll(text, found) {
		out = append(out, dec.Entity.Value)
	}
	return out
}

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// 标准装配必须产出正确的边界 —— 这是本文件存在的理由。
// The standard assembly must produce correct boundaries.
//
// 曾经有两份装配：二进制在 main.go 里搭一个，评测在测试里手工搭一个。
// 评测那份装了复姓识别，二进制那份没装，于是评测的数字描述的是一个
// 二进制产不出的配置。这条用例量的就是二进制跑的那份。
//
// There used to be two assemblies, and the measured numbers described a
// configuration the binary could not produce. This exercises the one it runs.
func TestCoreAssemblyBoundaries(t *testing.T) {
	d, v, err := Core(DefaultCoreOptions([]string{"GEN", "CN"}))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		text string
		want string
	}{
		{"经办人欧阳志远，手机 13812345678。", "欧阳志远"},
		{"尉迟恭负责本次验收。", "尉迟恭"},
		{"司徒美堂出席了会议。", "司徒美堂"},
		{"诸葛亮提出隆中对。", "诸葛亮"},
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			got := resolve(t, d, v, c.text)
			if !has(got, c.want) {
				t.Errorf("应检出 %q，实际 %v", c.want, got)
			}
			// 截短或吞多都不行：正确答案之外不该有同一姓氏的其他变体
			for _, g := range got {
				if g != c.want && strings.HasPrefix(c.want, g[:min(len(g), 6)]) && g != c.want {
					t.Errorf("边界不对：得到 %q，应为 %q", g, c.want)
				}
			}
		})
	}
}

// 标准装配必须挡住候选带来的误报。
// The standard assembly must reject the candidates' false positives.
func TestCoreAssemblyRejectsFalsePositives(t *testing.T) {
	d, v, err := Core(DefaultCoreOptions([]string{"GEN", "CN"}))
	if err != nil {
		t.Fatal(err)
	}

	for _, text := range []string{
		"王者荣耀的新赛季已经开启。",
		"func retry(n int) error { return nil }",
		"李子和杨梅都是夏季水果。",
		"陈述事实比争辩更有力。",
	} {
		t.Run(text[:12], func(t *testing.T) {
			if got := resolve(t, d, v, text); len(got) != 0 {
				t.Errorf("不该有检出，实际 %v", got)
			}
		})
	}
}

// 结构化标识不能因为延后消解而受影响。
// Deferring overlap resolution must not affect structured identifiers.
func TestCoreAssemblyStructuredUnaffected(t *testing.T) {
	d, v, err := Core(DefaultCoreOptions([]string{"GEN", "CN", "US", "IT", "DE", "ES"}))
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"身份证 11010519491231002X":          "11010519491231002X",
		"卡号 4111111111111111":             "4111111111111111",
		"手机 13812345678":                  "13812345678",
		"邮箱 a.b@example.com":              "a.b@example.com",
		"统一代码 91110108MA01ABCD71":         "91110108MA01ABCD71",
		"Codice Fiscale MRTMTT25D09F205Z": "MRTMTT25D09F205Z",
	}
	for text, want := range cases {
		t.Run(want, func(t *testing.T) {
			if got := resolve(t, d, v, text); !has(got, want) {
				t.Errorf("应检出 %q，实际 %v", want, got)
			}
		})
	}
}

// 默认装配必须包含复姓识别 —— 实测数字是在这个前提上量的。
// The default assembly must include surname recognition: the reported numbers
// rest on it.
func TestDefaultOptionsMatchMeasuredConfiguration(t *testing.T) {
	opts := DefaultCoreOptions([]string{"GEN", "CN"})

	if !opts.Surnames {
		t.Error("默认装配必须启用复姓识别——README 报告的 90.5% 覆盖率含它")
	}
	if opts.SingleSurnames {
		t.Error("默认装配不该启用单姓识别——实测召回零增益、误报十四处")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
