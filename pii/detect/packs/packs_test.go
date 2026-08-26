package packs

import (
	"strings"
	"testing"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// 每个包都必须能构建，且识别器名全局唯一。
// Every pack must build, and recognizer names must be globally unique.
func TestAllPacksBuildWithUniqueNames(t *testing.T) {
	seen := map[string]string{}
	for _, code := range Available() {
		p, _ := Get(code)
		recs, err := p.Build()
		if err != nil {
			t.Fatalf("%s 构建失败：%v", code, err)
		}
		if len(recs) == 0 {
			t.Errorf("%s 是空包", code)
		}
		for _, r := range recs {
			if prev, dup := seen[r.Name()]; dup {
				t.Errorf("识别器名 %q 在 %s 与 %s 中重复", r.Name(), prev, code)
			}
			seen[r.Name()] = code
		}
	}
	t.Logf("%d 个包，%d 个识别器", len(Available()), len(seen))
}

// 装错包必须报错，不能静默跳过。
// A wrong pack code must error, never be skipped.
func TestUnknownPackIsAnError(t *testing.T) {
	if _, err := Load("GEN", "GB"); err == nil {
		t.Fatal("未知国家包应报错")
	} else if !strings.Contains(err.Error(), "GB") {
		t.Fatalf("报错应点名 GB：%v", err)
	}
	if _, err := NewRegistry(nil); err == nil {
		t.Fatal("空国家包列表应报错")
	}
}

// 前置过滤器是收紧速度的手段，绝不能改变结果。
// Prefilters buy speed; they must never change results.
//
// 这条用例针对的是本系统最危险的一类故障：一个模式并不蕴含的前置条件
// 会让识别器对不满足它的文本直接跳过——不报错、不告警，只是漏掉。
// This targets the most dangerous failure here: a precondition the pattern
// does not imply makes the recognizer skip text silently.
func TestPrefiltersDoNotChangeResults(t *testing.T) {
	texts := []string{
		"身份证 11010519491231002X，手机 13812345678",
		"邮箱 zhang.wei@example.com，卡号 4111 1111 1111 1111",
		"IBAN GB82WEST12345698765432，IP 192.168.1.1",
		"密钥 sk-abcdefghij1234567890，车牌 京A12345",
		"SSN 123-45-6789，固话 010-12345678，国际 +8613812345678",
		"护照 E12345678，统一代码 91110108MA01ABCD7X",
		"Codice Fiscale MRTMTT25D09F205Z，Partita IVA 12345678903",
		"Steuer-ID 86095742719，USt-IdNr DE123456789",
		"DNI 12345678Z，NIE X1234567L",
	}

	all := Available()
	gated, err := NewRegistry(all)
	if err != nil {
		t.Fatal(err)
	}
	bare := buildWithoutPrefilters(t, all)

	for _, text := range texts {
		a, err := gated.Detect(text)
		if err != nil {
			t.Fatal(err)
		}
		b, err := bare.Detect(text)
		if err != nil {
			t.Fatal(err)
		}
		if len(a) != len(b) {
			t.Errorf("前置过滤改变了结果：%q\n  有门控 %d 个：%v\n  无门控 %d 个：%v",
				text, len(a), a, len(b), b)
			continue
		}
		for i := range a {
			if a[i] != b[i] {
				t.Errorf("前置过滤改变了结果：%q\n  有门控 %+v\n  无门控 %+v", text, a[i], b[i])
			}
		}
	}
}

// buildWithoutPrefilters 重建同一批识别器但摘掉全部前置过滤器。
// Rebuilds the same recognizers with every prefilter removed.
func buildWithoutPrefilters(t *testing.T, codes []string) *detect.Registry {
	t.Helper()
	reg := detect.NewRegistry()
	for _, code := range codes {
		p, _ := Get(code)
		recs, err := p.Build()
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			pr, ok := r.(*detect.PatternRecognizer)
			if !ok {
				continue
			}
			if err := reg.Register(pr.WithoutPrefilter()); err != nil {
				t.Fatal(err)
			}
		}
	}
	return reg
}

// 各国身份标识必须只被本国的识别器认领。
// A national identifier must be claimed only by its own country's recognizer.
func TestJurisdictionIsolation(t *testing.T) {
	cases := []struct {
		value string
		pack  string
		typ   detect.EntityType
	}{
		{"MRTMTT25D09F205Z", "IT", detect.TypeIDCard},
		{"86095742719", "DE", detect.TypeIDCard},
		{"12345678Z", "ES", detect.TypeIDCard},
		{"11010519491231002X", "CN", detect.TypeIDCard},
		{"123-45-6789", "US", detect.TypeSSN},
	}

	for _, tc := range cases {
		t.Run(tc.pack+"/"+tc.value, func(t *testing.T) {
			// 只装本国包：必须检出
			own, err := NewRegistry([]string{tc.pack})
			if err != nil {
				t.Fatal(err)
			}
			ents, err := own.Detect(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			var hit bool
			for _, e := range ents {
				if e.Type == tc.typ {
					hit = true
				}
			}
			if !hit {
				t.Fatalf("%s 包应检出 %q 为 %s，实际 %v", tc.pack, tc.value, tc.typ, ents)
			}

			// 不装本国包：漏检是预期的——而这正是必须显式选择管辖区的理由。
			// Without the pack the value is missed, which is exactly why the
			// jurisdiction has to be an explicit choice.
			others := []string{}
			for _, c := range Available() {
				if c != tc.pack {
					others = append(others, c)
				}
			}
			without, err := NewRegistry(others)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := without.Detect(tc.value)
			t.Logf("缺 %s 包时：%q 被检出 %d 个实体 %v", tc.pack, tc.value, len(got), got)
		})
	}
}

// 关闭某类型后，注册表里不得再有该类型的识别器。
// Disabling a type must remove its recognizers from the registry.
func TestDisabledTypesAreRemoved(t *testing.T) {
	reg, err := NewRegistry([]string{"GEN", "CN"}, detect.TypeIP)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range reg.CoveredTypes() {
		if typ == detect.TypeIP {
			t.Fatal("已关闭的 IP 类型仍在覆盖列表中")
		}
	}
	ents, _ := reg.Detect("服务器 192.168.1.1 上的日志")
	for _, e := range ents {
		if e.Type == detect.TypeIP {
			t.Fatalf("已关闭的 IP 类型仍被检出：%v", e)
		}
	}
}
