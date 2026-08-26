package detect

import "testing"

func TestIBANValid(t *testing.T) {
	cases := map[string]bool{
		"GB82 WEST 1234 5698 7654 32":  true,  // 官方示例 / official example
		"DE89 3704 0044 0532 0130 00":  true,
		"FR14 2004 1010 0505 0001 3M02 606": true,
		"GB82WEST12345698765433":       false, // 末位改动 / last digit altered
		"DE89370400440532013001":       false,
		"XX82WEST12345698765432":       false, // 未知国家 / unknown country
		"DE8937040044053201300":        false, // 长度不符 / wrong length
		"":                             false,
	}
	for in, want := range cases {
		if got := IBANValid(in); got != want {
			t.Errorf("IBANValid(%q) = %v, want %v", in, got, want)
		}
	}
}
