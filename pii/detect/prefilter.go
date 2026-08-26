package detect

import "strings"

// Prefilter cheaply rules out text that cannot possibly contain an entity,
// before the expensive regex runs.
// 在昂贵的正则运行之前，用廉价手段排除不可能含有某类实体的文本。
//
// # Why this matters more than regex tuning
// # 为什么这比调正则更重要
//
// Every recognizer scans the whole text independently, so a request carrying a
// 4KB system prompt is scanned once per recognizer — sixteen full passes over
// text that, in the overwhelming majority of cases, contains none of what most
// of them look for. Measured on a realistic prompt, the IPv4 recognizer alone
// accounted for 27% of detection time while matching nothing.
// 每个识别器都独立扫描全文，因此一个带 4KB 系统提示词的请求会被扫描
// 十六遍——而绝大多数情况下，这段文本里根本没有其中大部分识别器要找的东西。
// 在真实提示词上实测，仅 IPv4 一个识别器就占了 27% 的检测时间，
// 而它什么也没匹配到。
//
// A prefilter is a necessary condition that is far cheaper to evaluate than the
// pattern itself: an IPv4 address must contain a '.', a Chinese ID must contain
// a digit, an email must contain '@'. IndexByte compiles to a vectorized scan,
// so ruling out a 4KB text costs microseconds where the regex costs tens of them.
// 前置门控是一个「必要条件」，其求值代价远低于模式本身：
// IPv4 必含 '.'，身份证必含数字，邮箱必含 '@'。IndexByte 会编译成向量化扫描，
// 因此排除一段 4KB 文本只需微秒，而正则要花几十微秒。
//
// # The correctness constraint
// # 正确性约束
//
// A prefilter may only ever produce false *positives* — text that passes but
// contains nothing. A false negative silently disables a recognizer, and a
// disabled PII recognizer is exactly the failure this whole system exists to
// prevent. Every prefilter below is therefore a strict necessary condition
// derived from the pattern, not a heuristic.
// 前置门控只允许产生**假阳性**——通过了但其实没有实体。假阴性会静默禁用
// 一个识别器，而被禁用的 PII 识别器正是整个系统要防的那种故障。
// 因此下面每个门控都是从模式推导出的严格必要条件，而非启发式规则。
type Prefilter func(text string) bool

// RequireByte returns a prefilter demanding at least one of the given bytes.
// 返回一个要求文本至少含给定字节之一的门控。
func RequireByte(bytes string) Prefilter {
	return func(text string) bool { return strings.ContainsAny(text, bytes) }
}

// RequireDigit demands at least one ASCII digit.
// 要求至少一个 ASCII 数字。
//
// Hand-rolled rather than strings.ContainsAny("0123456789"): this runs on every
// request for most recognizers, and a tight byte loop avoids the set-membership
// machinery ContainsAny uses for multi-byte input.
// 手写而非 strings.ContainsAny("0123456789")：多数识别器每个请求都要跑一次，
// 紧凑的字节循环省掉了 ContainsAny 为多字节输入准备的集合判定机制。
func RequireDigit(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] >= '0' && text[i] <= '9' {
			return true
		}
	}
	return false
}

// RequirePrefix returns a prefilter demanding a literal substring, used by
// recognizers whose pattern starts with a fixed marker.
// 返回一个要求含指定字面子串的门控，供模式以固定标记开头的识别器使用。
func RequirePrefix(literals ...string) Prefilter {
	return func(text string) bool {
		for _, lit := range literals {
			if strings.Contains(text, lit) {
				return true
			}
		}
		return false
	}
}

// RequireUpperAlpha demands at least one uppercase ASCII letter, which every
// IBAN, licence plate and credential prefix requires.
// 要求至少一个大写 ASCII 字母——IBAN、车牌、凭证前缀都必然含有。
func RequireUpperAlpha(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] >= 'A' && text[i] <= 'Z' {
			return true
		}
	}
	return false
}

// RequireCJK demands at least one CJK character, used by the licence-plate
// recognizer whose pattern begins with a province character.
// 要求至少一个 CJK 字符，供以省份汉字开头的车牌识别器使用。
//
// Checks only the UTF-8 lead byte range for U+4E00–U+9FFF, which is a necessary
// condition for the pattern to match and costs one comparison per byte.
// 只检查 U+4E00–U+9FFF 的 UTF-8 首字节范围，这是模式能匹配的必要条件，
// 每字节只花一次比较。
func RequireCJK(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] >= 0xE4 && text[i] <= 0xE9 {
			return true
		}
	}
	return false
}
