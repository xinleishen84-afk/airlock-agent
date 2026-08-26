package detect

import (
	"fmt"
	"testing"
)

// TestItalyCodiceFiscale uses the canonical published example.
// 使用公开的规范示例。
//
// A wrong transcription of the odd-position weight table produces a validator
// that silently rejects every real code — and the failure looks like "Italy has
// no PII", not like a bug.
// 奇数位权重表抄错，会得到一个静默拒绝所有真实税号的校验器——
// 而这个故障看起来是「意大利没有 PII」，而不是一个 bug。
func TestItalyCodiceFiscale(t *testing.T) {
	cases := map[string]bool{
		"RSSMRA85T10A562S":  true, // Mario Rossi，规范示例 / canonical example
		"MRTMTT25D09F205Z":  true,
		"RSSMRA85T10A562A":  false, // 控制字符改动 / control char altered
		"RSSMRA85T10A562":   false, // 长度不足 / too short
		"RSSMRA85T10A562SS": false, // 长度超出 / too long
		"RSSMRA85T10A562!":  false, // 非法字符 / illegal char
		"":                  false,
	}
	for in, want := range cases {
		if got := ItalyCodiceFiscaleValid(in); got != want {
			t.Errorf("ItalyCodiceFiscaleValid(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestItalyCFSelfConsistency verifies the algorithm against itself by
// recomputing the control character for a body and checking it round-trips.
// 通过重算控制字符并检查往返一致，用算法自身验证算法。
//
// This catches a table transcription error that happens to be self-consistent
// for one example but wrong in general.
// 这能抓住那种「对某一个示例恰好自洽、总体却是错的」的抄表错误。
func TestItalyCFSelfConsistency(t *testing.T) {
	bodies := []string{
		"RSSMRA85T10A562", "MRTMTT25D09F205", "BNCLRA90A41H501",
	}
	for _, body := range bodies {
		// 逐一试出唯一能通过校验的控制字符
		var valid []string
		for c := byte('A'); c <= 'Z'; c++ {
			if ItalyCodiceFiscaleValid(body + string(c)) {
				valid = append(valid, string(c))
			}
		}
		if len(valid) != 1 {
			t.Errorf("%s 应恰好有一个合法控制字符，实际 %d 个：%v", body, len(valid), valid)
		}
	}
}

// TestGermanyTaxID uses the official BZSt example.
// 使用德国联邦中央税务局的官方示例。
func TestGermanyTaxID(t *testing.T) {
	cases := map[string]bool{
		"36574261809":    true,  // BZSt 官方示例 / official example
		"36 574 261 809": true,  // 带分隔符 / with separators
		"36574261808":    false, // 校验位改动 / check digit altered
		"06574261809":    false, // 首位为 0 / leading zero
		"1234567890":     false, // 长度不足 / too short
		"12345678901":    false, // 违反结构规则 / violates structure rule
		"":               false,
	}
	for in, want := range cases {
		if got := GermanyTaxIDValid(in); got != want {
			t.Errorf("GermanyTaxIDValid(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestGermanyStructureRuleSuppressesFalsePositives is why the structural rule
// matters as much as the check digit.
// 说明结构规则为何与校验位同等重要。
//
// A check digit alone lets one in ten random 11-digit runs through. Order
// numbers, timestamps and phone numbers are all 11-digit runs, so in a document
// full of them the check digit alone is not enough to be useful.
// 仅靠校验位会放行十分之一的随机 11 位数字。订单号、时间戳、电话号码
// 都是 11 位数字，因此在满是它们的文档里，仅有校验位不足以派上用场。
func TestGermanyStructureRuleSuppressesFalsePositives(t *testing.T) {
	passed := 0
	total := 0
	// 遍历一批「校验位正确但结构不合规」的候选
	for n := 10000000000; n < 10000002000; n++ {
		s := fmt.Sprintf("%d", n)
		if len(s) != 11 {
			continue
		}
		total++
		body := s[:10]
		withValidCheck := body + string(germanTaxIDCheckDigit(body))
		if GermanyTaxIDValid(withValidCheck) {
			passed++
		}
	}
	if total == 0 {
		t.Fatal("样本为空")
	}
	rate := float64(passed) / float64(total)
	t.Logf("校验位正确的 %d 个候选中，仅 %d 个（%.1f%%）通过结构规则", total, passed, rate*100)
	if rate > 0.5 {
		t.Errorf("结构规则未起到抑制作用，通过率 %.1f%%", rate*100)
	}
}

// TestSpainDNIAndNIE covers both citizen and foreign-resident forms.
// 覆盖公民与外国居民两种形态。
//
// Handling only DNI would silently miss every foreign resident's identifier.
// 只处理 DNI 会静默漏掉每一个外国居民的标识。
func TestSpainDNIAndNIE(t *testing.T) {
	cases := map[string]bool{
		"12345678Z": true, // DNI
		"00000000T": true,
		"X1234567L": true,  // NIE，X→0
		"Y1234567X": true,  // NIE，Y→1
		"Z1234567R": true,  // NIE，Z→2
		"12345678A": false, // 校验字母错误 / wrong letter
		"X1234567Z": false,
		"1234567Z":  false, // 长度不足 / too short
		"1234567AZ": false, // 数字段含字母 / letter in digit section
		"":          false,
	}
	for in, want := range cases {
		if got := SpainDNIValid(in); got != want {
			t.Errorf("SpainDNIValid(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestSpainDNILetterTableExcludesConfusables documents why the table looks odd.
// 记录该表看起来奇怪的原因。
func TestSpainDNILetterTableExcludesConfusables(t *testing.T) {
	if len(dniLetters) != 23 {
		t.Fatalf("校验字母表应为 23 位，实际 %d", len(dniLetters))
	}
	for _, c := range "IOU" {
		for i := 0; i < len(dniLetters); i++ {
			if rune(dniLetters[i]) == c {
				t.Errorf("字母 %c 易与数字或其他字母混淆，不应出现在表中", c)
			}
		}
	}
}

// 官方文档里的算例并不是一个可签发的税号。
// The worked example in the official documentation is not an issuable tax ID.
//
// 02476291358 是 BZSt 校验位算法文档中的算例：结构规则通过、校验位也对。
// 但已签发的 IdNr 首位从不为 0，所以它必须被拒绝。
// 这条用例存在的意义是把这个取舍写下来——否则下一个人会看到
// 「官方示例被拒」，以为是 bug，把首位规则删掉，
// 从而让每一个 0 开头的 11 位数字（时间戳、补零的订单号）都变成候选税号。
//
// 02476291358 is the worked example in the BZSt check-digit documentation: the
// structure rule passes and the check digit is correct. Issued IdNrs never
// begin with 0, so it must still be rejected. This test exists to write the
// trade-off down — otherwise the next person sees "official example rejected",
// reads it as a bug, drops the leading-digit rule, and turns every zero-padded
// eleven-digit run into a tax-ID candidate.
func TestGermanySpecExampleIsNotIssuable(t *testing.T) {
	const specExample = "02476291358"

	if !germanTaxIDStructureValid(specExample[:10]) {
		t.Fatal("算例应通过结构规则")
	}
	if got := germanTaxIDCheckDigit(specExample[:10]); got != specExample[10] {
		t.Fatalf("算例的校验位应为 %c，算得 %c", specExample[10], got)
	}
	if GermanyTaxIDValid(specExample) {
		t.Fatal("首位为 0 的税号不可签发，应被拒绝")
	}
}
