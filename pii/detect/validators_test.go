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
		{"12345678901234", false}, // 随机长数字串校验不过
		{"411111111111", false},   // 12 位但校验失败
		{"", false},
		{"4111-1111-1111-111a", false}, // 含非数字
		{"12345678903", true},          // 11 位：意大利增值税号长度，Luhn 通过
		{"4008217350", true},           // 10 位：企业内部账号长度，Luhn 通过
	}
	for _, c := range cases {
		if got := LuhnValid(c.in); got != c.want {
			t.Errorf("LuhnValid(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// 长度约束属于「卡号」这个概念，不属于 Luhn 这个算法。
// The length bound belongs to "card number", not to the Luhn algorithm.
//
// 这条用例针对一个已经发生过的故障：LuhnValid 里写死了 12-19 位，
// 于是意大利 11 位增值税号的识别器注册成功、运行正常、永不命中。
// 没有任何报错——只是那个国家的一整类标识扫不出来。
// This targets a failure that already happened here: LuhnValid hard-coded a
// 12-19 digit range, so Italy's 11-digit VAT recognizer registered fine, ran
// fine, and never matched. No error — just an entire identifier class going
// undetected in that country.
func TestBankCardLengthIsSeparateFromLuhn(t *testing.T) {
	const itVAT = "12345678903" // 11 位，Luhn 通过 / 11 digits, Luhn-valid

	if !LuhnValid(itVAT) {
		t.Fatal("11 位的 Luhn 值应通过纯 Luhn 校验")
	}
	if BankCardLuhnValid(itVAT) {
		t.Fatal("11 位不可能是支付卡号，卡号校验应拒绝")
	}
	if !BankCardLuhnValid("4111111111111111") {
		t.Fatal("16 位有效卡号应通过")
	}
	if BankCardLuhnValid("40082173504008217350") { // 20 位
		t.Fatal("20 位超出卡号长度上限，应拒绝")
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
