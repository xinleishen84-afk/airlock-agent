package detect

import "strings"

// European national identifier check algorithms.
// 欧洲国家身份标识的校验算法。
//
// Each is a published, deterministic rule — not a heuristic. That is what makes
// them belong in the fast tier: arithmetic settles the question in nanoseconds,
// and a value that fails has no chance of being that identifier no matter what
// the surrounding text says.
// 每一个都是公开的确定性规则，而非启发式。这正是它们属于快速层的原因：
// 算术在纳秒内给出结论，而一个校验失败的值，无论上下文怎么说，
// 都不可能是那个标识。

// ---------------------------------------------------------------------------
// Italy — Codice Fiscale / 意大利税号
// ---------------------------------------------------------------------------

// cfOddValues maps a character at an odd position (1-indexed) to its weight.
// The table is deliberately irregular: it is defined by decree, not derived, so
// it must be transcribed rather than computed.
// 把奇数位（1-indexed）的字符映射到权重。该表刻意不规则：
// 它由法令规定而非推导得出，因此只能照抄，不能计算。
var cfOddValues = map[byte]int{
	'0': 1, '1': 0, '2': 5, '3': 7, '4': 9, '5': 13, '6': 15, '7': 17, '8': 19, '9': 21,
	'A': 1, 'B': 0, 'C': 5, 'D': 7, 'E': 9, 'F': 13, 'G': 15, 'H': 17, 'I': 19, 'J': 21,
	'K': 2, 'L': 4, 'M': 18, 'N': 20, 'O': 11, 'P': 3, 'Q': 6, 'R': 8, 'S': 12, 'T': 14,
	'U': 16, 'V': 10, 'W': 22, 'X': 25, 'Y': 24, 'Z': 23,
}

// cfEvenValue returns the weight of a character at an even position.
// Even positions are regular: digits map to themselves, letters to their index.
// 返回偶数位字符的权重。偶数位是规则的：数字映射到自身，字母映射到其序号。
func cfEvenValue(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'A' && c <= 'Z':
		return int(c - 'A'), true
	}
	return 0, false
}

// ItalyCodiceFiscaleValid validates the CIN (control character) of an Italian
// Codice Fiscale.
// 校验意大利税号的 CIN（控制字符）。
//
// The code is 16 characters: 6 from the name, 5 encoding birth date and sex,
// 4 for the birthplace, and a final control character. Only the control
// character is verified here — the name and place segments encode data this
// package has no way to check, and pretending otherwise would be false
// confidence.
// 税号共 16 位：6 位来自姓名，5 位编码出生日期与性别，4 位为出生地，
// 末位为控制字符。此处只校验控制字符——姓名与地点段编码的数据
// 本包无从核实，假装能核实是一种虚假的确定感。
func ItalyCodiceFiscaleValid(value string) bool {
	v := strings.ToUpper(strings.TrimSpace(value))
	if len(v) != 16 {
		return false
	}
	for i := 0; i < 16; i++ {
		c := v[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}

	sum := 0
	for i := 0; i < 15; i++ {
		// Position is 1-indexed in the specification, so index 0 is odd.
		// 规范中位置是 1-indexed，因此下标 0 属于奇数位。
		if i%2 == 0 {
			w, ok := cfOddValues[v[i]]
			if !ok {
				return false
			}
			sum += w
		} else {
			w, ok := cfEvenValue(v[i])
			if !ok {
				return false
			}
			sum += w
		}
	}
	return v[15] == byte('A'+sum%26)
}

// ---------------------------------------------------------------------------
// Germany — Steuerliche Identifikationsnummer / 德国税号
// ---------------------------------------------------------------------------

// GermanyTaxIDValid validates a German Steuer-ID (11 digits).
// 校验德国税号（11 位数字）。
//
// Two independent conditions must both hold, and checking only the check digit
// is the common mistake:
// 两个独立条件必须同时成立，而只校验校验位是常见的错误：
//
//  1. A structural rule on the first ten digits: exactly one digit appears
//     twice or three times, every other digit at most once, and a digit that
//     appears three times must not occupy three consecutive positions.
//     前十位的结构规则：恰有一个数字出现两次或三次，其余数字至多出现一次，
//     且出现三次的数字不得占据三个连续位置。
//  2. The eleventh digit is an ISO 7064 MOD 11,10 check digit.
//     第十一位是 ISO 7064 MOD 11,10 校验位。
//
// The structural rule is what makes this identifier hard to forge by accident:
// a random 11-digit run almost never satisfies it, so it suppresses the false
// positives that a check digit alone (1-in-10) would let through.
// 结构规则正是这个标识难以被偶然伪造的原因：随机 11 位数字几乎不可能满足它，
// 因此它压制了仅靠校验位（1/10 通过率）会放行的误报。
func GermanyTaxIDValid(value string) bool {
	v := strings.Map(func(r rune) rune {
		if r == ' ' || r == '/' || r == '-' {
			return -1
		}
		return r
	}, strings.TrimSpace(value))

	if len(v) != 11 {
		return false
	}
	for i := 0; i < 11; i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	// A leading zero is not issued.
	// 首位不会是 0。
	if v[0] == '0' {
		return false
	}

	if !germanTaxIDStructureValid(v[:10]) {
		return false
	}
	return v[10] == germanTaxIDCheckDigit(v[:10])
}

// germanTaxIDStructureValid checks the digit-repetition rule on the first ten.
// 检查前十位的数字重复规则。
func germanTaxIDStructureValid(first10 string) bool {
	var counts [10]int
	for i := 0; i < len(first10); i++ {
		counts[first10[i]-'0']++
	}

	repeated, triples := 0, 0
	for d, n := range counts {
		switch {
		case n == 2:
			repeated++
		case n == 3:
			repeated++
			triples++
			// Three occurrences must not be consecutive.
			// 出现三次的数字不得连续。
			target := byte('0' + d)
			for i := 0; i+2 < len(first10); i++ {
				if first10[i] == target && first10[i+1] == target && first10[i+2] == target {
					return false
				}
			}
		case n > 3:
			return false
		}
	}
	return repeated == 1 && triples <= 1
}

// germanTaxIDCheckDigit computes the ISO 7064 MOD 11,10 check digit.
// 计算 ISO 7064 MOD 11,10 校验位。
func germanTaxIDCheckDigit(first10 string) byte {
	product := 10
	for i := 0; i < len(first10); i++ {
		sum := (int(first10[i]-'0') + product) % 10
		if sum == 0 {
			sum = 10
		}
		product = (2 * sum) % 11
	}
	check := 11 - product
	if check == 10 {
		check = 0
	}
	return byte('0' + check)
}

// ---------------------------------------------------------------------------
// Spain — DNI / NIE
// ---------------------------------------------------------------------------

// dniLetters is the check-letter table indexed by number mod 23. The letters
// I, O, U and Ñ are omitted to avoid confusion with digits and each other.
// 是按数字模 23 索引的校验字母表。省略 I、O、U、Ñ 以避免与数字及彼此混淆。
const dniLetters = "TRWAGMYFPDXBNJZSQVHLCKE"

// SpainDNIValid validates a Spanish DNI or NIE.
// 校验西班牙 DNI 或 NIE。
//
// DNI is eight digits plus a check letter. NIE, issued to foreign residents,
// replaces the first digit with X, Y or Z, which map to 0, 1 and 2 — the same
// arithmetic then applies. Handling only DNI would silently miss every foreign
// resident's identifier, which in an immigration-heavy dataset is most of them.
// DNI 是八位数字加一位校验字母。发给外国居民的 NIE 把首位换成 X、Y、Z，
// 分别映射为 0、1、2，之后套用同一套算术。只处理 DNI 会静默漏掉
// 每一个外国居民的标识——而在移民密集的数据集里，那是大多数。
func SpainDNIValid(value string) bool {
	v := strings.ToUpper(strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return r
	}, strings.TrimSpace(value)))

	if len(v) != 9 {
		return false
	}

	digits := v[:8]
	// NIE prefix maps to a leading digit.
	// NIE 前缀映射为首位数字。
	switch v[0] {
	case 'X':
		digits = "0" + v[1:8]
	case 'Y':
		digits = "1" + v[1:8]
	case 'Z':
		digits = "2" + v[1:8]
	}

	n := 0
	for i := 0; i < 8; i++ {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	if v[8] < 'A' || v[8] > 'Z' {
		return false
	}
	return v[8] == dniLetters[n%23]
}
