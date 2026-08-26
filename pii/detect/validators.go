// Package detect finds PII spans in text: regexes with check digits,
// enterprise gazetteers, and an external NER service.
// 在文本中定位 PII 区间：带校验位的正则、企业名册、外部 NER 服务。
//
// Recognizers are managed by a Registry, so a deployment can add its own entity
// types without forking this library. Pattern recognizers support context-word
// boosting: the same 16-digit run scores differently next to "card number" than
// next to "order number".
// 识别器由 Registry 管理，部署方无需 fork 即可加入自己的实体类型。
// 正则识别器支持上下文词加权：同样 16 位数字，
// 旁边是「卡号」和「订单号」得分不同。
//
// This package only *detects*. Replacement and restoration live in
// airlock-agent/pii/anonymize.
// 本包只负责**检测**。替换与复原在 airlock-agent/pii/anonymize。
package detect

import "strings"

// LuhnValid runs the Luhn checksum on a digit run of any length.
// 对任意长度的数字串执行 Luhn 校验。
//
// Length is deliberately not checked here. Luhn is used by bank cards, but also
// by Italy's 11-digit Partita IVA, IMEIs, and plenty of company-internal
// account numbers — folding a card's length range into the function named
// "Luhn" makes it quietly wrong for all of them, and the wrongness shows up as
// a recognizer that never matches rather than as an error.
// 这里刻意不检查长度。Luhn 用于银行卡，也用于意大利 11 位的增值税号、
// IMEI，以及大量企业内部账号——把卡号的长度范围折进一个叫 "Luhn" 的函数里，
// 会让它对上述全部场景悄悄地错，而这种错表现为「识别器永不命中」，
// 不是一个报错。
//
// Callers that need a card-shaped length use BankCardLuhnValid.
// 需要卡号长度约束的调用方请用 BankCardLuhnValid。
func LuhnValid(digits string) bool {
	if len(digits) < 2 {
		return false
	}
	sum := 0
	// Walk right to left; double every second digit.
	// 从右往左，偶数位（0-indexed 的奇数位）翻倍。
	for i, pos := len(digits)-1, 0; i >= 0; i, pos = i-1, pos+1 {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		v := int(c - '0')
		if pos%2 == 1 {
			if v *= 2; v > 9 {
				v -= 9
			}
		}
		sum += v
	}
	return sum%10 == 0
}

// BankCardLuhnValid is LuhnValid plus the length range a payment card can have.
// 是 LuhnValid 加上支付卡可能的长度范围。
//
// Without the length bound, any digit run that happens to satisfy Luhn — one in
// ten of them — is reported as a card number, and those false positives bury
// the real alerts.
// 没有长度约束，任何碰巧满足 Luhn 的数字串（十分之一）都会被报成卡号，
// 而这些误报会淹没真正的告警。
func BankCardLuhnValid(digits string) bool {
	if len(digits) < 12 || len(digits) > 19 {
		return false
	}
	return LuhnValid(digits)
}

// idWeights are the weighting factors for the first 17 digits of a Chinese
// resident ID card (GB 11643-1999).
// 是二代身份证前 17 位的加权因子（GB 11643-1999）。
var idWeights = [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}

// idCheckChars is the check-digit table, indexed by the weighted sum mod 11.
// 是校验码字符表，下标为加权和模 11 的结果。
const idCheckChars = "10X98765432"

// CNIDCardValid validates a Chinese resident ID number (GB 11643-1999).
// 校验中国大陆二代身份证号（GB 11643-1999）。
//
// Besides the check digit it also sanity-checks the birth-date field, which
// rules out constructed strings such as all zeros.
// 除校验位外还检查出生日期字段的基本合理性，排除全零等构造串。
func CNIDCardValid(value string) bool {
	v := strings.ToUpper(strings.TrimSpace(value))
	if len(v) != 18 {
		return false
	}
	for i := 0; i < 17; i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	month := int(v[10]-'0')*10 + int(v[11]-'0')
	day := int(v[12]-'0')*10 + int(v[13]-'0')
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		sum += int(v[i]-'0') * idWeights[i]
	}
	return v[17] == idCheckChars[sum%11]
}

// usccChars is the base-31 alphabet used by the Unified Social Credit Code
// (the confusable letters I, O, S, V, Z are excluded).
// 是统一社会信用代码使用的 31 进制字符集（剔除易混淆的 I O S V Z）。
const usccChars = "0123456789ABCDEFGHJKLMNPQRTUWXY"

// usccWeights are the weighting factors for the first 17 characters
// (GB 32100-2015).
// 是统一社会信用代码前 17 位的加权因子（GB 32100-2015）。
var usccWeights = [17]int{1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28}

// CNUSCCValid validates a Unified Social Credit Code (GB 32100-2015).
// 校验统一社会信用代码（GB 32100-2015）。
//
// Without this check, any 18-character alphanumeric string would be misdetected
// as a credit code — including ID numbers whose check digit does not validate.
// 缺了这一步，任意 18 位字母数字串都会被误报为信用代码，
// 包括校验位不合法的身份证号。
func CNUSCCValid(value string) bool {
	v := strings.ToUpper(strings.TrimSpace(value))
	if len(v) != 18 {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		idx := strings.IndexByte(usccChars, v[i])
		if idx < 0 {
			return false
		}
		sum += idx * usccWeights[i]
	}
	if strings.IndexByte(usccChars, v[17]) < 0 {
		return false
	}
	return usccChars[(31-sum%31)%31] == v[17]
}

// stripSeparators removes spaces and hyphens from a digit run.
// 去掉数字串中的空格与连字符。
//
// Card numbers are commonly written in groups of four, so they must be
// normalized before the checksum runs.
// 银行卡常以 4 位一组书写，校验前必须归一化。
func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' && s[i] != '-' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// ibanLengths maps a country code to the exact total IBAN length for that
// country. Length is part of the standard, not a convention — a 22-character
// string claiming to be a German IBAN is invalid regardless of its check digits.
// 把国家代码映射到该国 IBAN 的确切总长度。长度是标准的一部分而非约定——
// 一个自称德国 IBAN 的 22 字符串，无论校验位如何都是非法的。
var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
	"BG": 22, "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28,
	"CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24,
	"FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18,
	"GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23,
	"IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32,
	"LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24,
	"ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15,
	"PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
	"SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25,
	"SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24,
	"XK": 20,
}

// IBANValid validates an IBAN per ISO 13616 / ISO 7064 mod-97-10.
// 按 ISO 13616 / ISO 7064 mod-97-10 校验 IBAN。
//
// The algorithm: move the first four characters to the end, map each letter to
// two digits (A=10 … Z=35), then read the result as one large integer and
// require it to be congruent to 1 modulo 97.
// 算法：把前四个字符移到末尾，每个字母映射为两位数字（A=10…Z=35），
// 再把结果当作一个大整数，要求它模 97 余 1。
//
// The number can reach 34 characters, far beyond int64, so the modulus is taken
// incrementally digit by digit. Trying to parse it as an integer first would
// overflow silently and validate garbage.
// 这个数最长可达 34 位，远超 int64，因此按位增量取模。
// 先解析成整数会静默溢出，从而放行垃圾数据。
func IBANValid(value string) bool {
	v := strings.ToUpper(strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return r
	}, strings.TrimSpace(value)))

	if len(v) < 15 || len(v) > 34 {
		return false
	}
	// First two characters are the country code, next two the check digits.
	// 前两位是国家代码，接下来两位是校验位。
	country := v[:2]
	want, known := ibanLengths[country]
	if !known || len(v) != want {
		return false
	}
	for i := 0; i < 2; i++ {
		if v[i] < 'A' || v[i] > 'Z' {
			return false
		}
		if v[i+2] < '0' || v[i+2] > '9' {
			return false
		}
	}

	rearranged := v[4:] + v[:4]
	remainder := 0
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		switch {
		case c >= '0' && c <= '9':
			remainder = (remainder*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			// A letter expands to two digits, so the modulus advances twice.
			// 字母展开为两位数字，因此取模要推进两次。
			n := int(c-'A') + 10
			remainder = (remainder*100 + n) % 97
		default:
			return false
		}
	}
	return remainder == 1
}

// cardNetworks are the issuer identification number ranges assigned by
// ISO/IEC 7812, with the card lengths each network issues.
// 是 ISO/IEC 7812 分配的发卡行识别号区间，以及各卡组织实际签发的长度。
//
// # Why Luhn alone is not enough
// # 为什么只靠 Luhn 不够
//
// Luhn is a single check digit, so one in ten arbitrary digit runs passes it.
// A production corpus is full of long digit runs — order numbers, millisecond
// timestamps, invoice sequences — and one in ten of them being reported as a
// card number buries the real alerts under noise that looks exactly like a
// finding.
// Luhn 只有一位校验位，因此任意数字串有十分之一的概率能通过。
// 真实语料里到处是长数字串——订单号、毫秒时间戳、发票流水——
// 其中十分之一被报成卡号，会把真正的告警埋在「看起来一模一样」的噪音底下。
//
// The IIN prefix is a second, independent structural constraint, and unlike a
// context keyword it is a property of the number itself: 20240131000012345 is
// not a card number no matter what sentence it appears in, because no issuer
// was ever assigned the 20 range.
// IIN 前缀是第二个独立的结构约束，而且与上下文关键词不同，
// 它是数字本身的属性：20240131000012345 无论出现在哪句话里都不是卡号，
// 因为 20 这个区间从未分配给任何发卡行。
var cardNetworks = []struct {
	name    string
	lengths []int
	match   func(d string) bool
}{
	{"Visa", []int{13, 16, 19}, func(d string) bool { return d[0] == '4' }},
	{"Mastercard", []int{16}, func(d string) bool {
		p2 := d[:2]
		if p2 >= "51" && p2 <= "55" {
			return true
		}
		p4 := d[:4]
		return p4 >= "2221" && p4 <= "2720"
	}},
	{"Amex", []int{15}, func(d string) bool { return d[:2] == "34" || d[:2] == "37" }},
	{"UnionPay", []int{16, 17, 18, 19}, func(d string) bool { return d[:2] == "62" }},
	{"JCB", []int{16, 17, 18, 19}, func(d string) bool {
		p4 := d[:4]
		return p4 >= "3528" && p4 <= "3589"
	}},
	{"Diners", []int{14, 16, 19}, func(d string) bool {
		p2 := d[:2]
		if p2 == "36" || p2 == "38" || p2 == "39" {
			return true
		}
		p3 := d[:3]
		return p3 >= "300" && p3 <= "305"
	}},
	{"Discover", []int{16, 19}, func(d string) bool {
		if d[:4] == "6011" || d[:2] == "65" {
			return true
		}
		p6 := d[:6]
		return p6 >= "622126" && p6 <= "622925"
	}},
	{"Maestro", []int{12, 13, 14, 15, 16, 17, 18, 19}, func(d string) bool {
		p4 := d[:4]
		return p4 == "5018" || p4 == "5020" || p4 == "5038" || p4 == "6304" ||
			p4 == "6759" || p4 == "6761" || p4 == "6762" || p4 == "6763"
	}},
}

// BankCardValid validates a payment card number: an assigned IIN prefix, a
// length that network issues, and the Luhn check digit.
// 校验支付卡号：已分配的 IIN 前缀、该卡组织实际签发的长度、以及 Luhn 校验位。
//
// All three must hold. Dropping any one of them was measured: with Luhn alone,
// a corpus of order numbers and timestamps produced false card detections at
// roughly the rate the single check digit predicts.
// 三者必须同时成立。少任何一个的后果是实测过的：只用 Luhn 时，
// 一份由订单号与时间戳构成的语料，产出误报卡号的比例
// 大致就是单位校验位所预测的那个比例。
func BankCardValid(digits string) bool {
	if len(digits) < 12 || len(digits) > 19 {
		return false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return false
		}
	}
	if !cardNetworkKnown(digits) {
		return false
	}
	return LuhnValid(digits)
}

// cardNetworkKnown reports whether the prefix and length match an issuer.
// 报告前缀与长度是否与某个发卡组织相符。
func cardNetworkKnown(digits string) bool {
	for _, n := range cardNetworks {
		if !n.match(digits) {
			continue
		}
		for _, l := range n.lengths {
			if len(digits) == l {
				return true
			}
		}
	}
	return false
}

// CardNetwork returns the issuing network's name, for audit output.
// 返回发卡组织名称，供审计输出使用。
//
// The name, never the number. Knowing that a Visa was redacted is useful for an
// analyst; knowing which one is the thing the redaction removed.
// 只给名称，绝不给号码。知道「一张 Visa 被脱敏了」对分析师有用；
// 知道是哪一张，恰恰是脱敏刚刚移除的东西。
func CardNetwork(digits string) string {
	for _, n := range cardNetworks {
		if n.match(digits) {
			for _, l := range n.lengths {
				if len(digits) == l {
					return n.name
				}
			}
		}
	}
	return ""
}
