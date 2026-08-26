package detect

import "testing"

// TestLuhnValid 校验 Luhn 算法，用例与 Python 参考实现对齐。
func TestLuhnValid(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"4111111111111111", true},
		{"4111111111111112", false},
		{"12345678901234", false}, // 随机长数字串不应被判为卡号
		{"411111111111", false},   // 12 位但校验失败
		{"", false},
		{"4111-1111-1111-111a", false}, // 含非数字
	}
	for _, c := range cases {
		if got := LuhnValid(c.in); got != c.want {
			t.Errorf("LuhnValid(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestCNIDCardValid 校验身份证校验位与出生日期合理性。
func TestCNIDCardValid(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"110101199003078515", true},
		{"11010119900307851X", false}, // 校验位错误
		{"110101199013078515", false}, // 13 月
		{"110101199000078515", false}, // 0 月
		{"11010119900307851", false},  // 长度不足
	}
	for _, c := range cases {
		if got := CNIDCardValid(c.in); got != c.want {
			t.Errorf("CNIDCardValid(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestCNUSCCValid 校验统一社会信用代码，重点是不把身份证误判为信用代码。
func TestCNUSCCValid(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"11010119900307851X", false}, // 身份证串不应通过 USCC 校验
		{"91110108MA01ABCD00", false}, // 构造的非法校验位
		{"110101199003078515", false},
		{"", false},
	}
	for _, c := range cases {
		if got := CNUSCCValid(c.in); got != c.want {
			t.Errorf("CNUSCCValid(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
