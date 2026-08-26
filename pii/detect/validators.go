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

// LuhnValid runs the Luhn checksum (bank card numbers).
// 执行 Luhn 校验（银行卡号）。
//
// Without this step, any 12-19 digit run would be misdetected as a card number,
// and the false positives would bury the real alerts.
// 没有这一步，任意 12-19 位数字串都会被误判为银行卡，
// 真正的告警会被误报淹没。
func LuhnValid(digits string) bool {
	if len(digits) < 12 || len(digits) > 19 {
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
