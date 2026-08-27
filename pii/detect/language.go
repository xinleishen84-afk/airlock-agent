package detect

import (
	"unicode"
)

// # 按文字系统路由
// # Routing by script
//
// 这里做的是**字符集识别，不是语言识别**。两者的区别要说清楚，否则会被
// 当成后者去用：
//
// This detects script, not language. The distinction matters, or it gets used
// as if it were the latter:
//
//   - 汉字与拉丁字母是不同的文字系统，分得开，而且分得可靠
//   - 英语、法语、德语、西班牙语共用拉丁字母，靠字符集分不开
//
//   - Han and Latin are different scripts, separable and reliably so
//   - English, French, German and Spanish share the Latin script and are not
//     separable this way
//
// 因此本函数能回答的是「该问中文模型还是拉丁语系模型」，不能回答
// 「这是英语还是法语」。把法语文本路由到英文模型仍然是不对的——但比路由到
// 中文模型好得多，因为后者是彻底的分布外，实测会把 declined、Codice、Steuer
// 判成人名。
//
// It answers "Chinese model or Latin-script model", not "English or French".
// Routing French to the English model is still wrong, but far less wrong than
// routing it to the Chinese model, which is fully out of distribution —
// measured, it labelled declined, Codice and Steuer as names.
//
// 真正的语言识别应当由调用方给出：HTTP 的 Accept-Language、文档的元数据、
// 或者租户的配置。契约里的 language 字段就是留给那个信息的；
// 本函数只是它缺席时的兜底。
//
// Real language identification should come from the caller — Accept-Language,
// document metadata, tenant configuration. The contract's language field is
// where that belongs; this is only the fallback when it is absent.

// Script names the writing system a text predominantly uses.
// 标识一段文本主要使用的文字系统。
type Script string

const (
	// ScriptHan 是汉字为主。
	ScriptHan Script = "zh"

	// ScriptLatin 是拉丁字母为主。
	//
	// 值取 "en" 而不是 "latin"，是因为它要直接填进契约的 language 字段，
	// 而那个字段的取值是语言代码。这个妥协有代价：法语文本会被标成 "en"。
	// 调用方若知道真实语言，应当覆盖它。
	//
	// The value is "en" rather than "latin" because it goes straight into the
	// contract's language field, which takes language codes. The compromise
	// costs accuracy: French is labelled "en". A caller that knows better
	// should override it.
	ScriptLatin Script = "en"

	// ScriptUnknown 表示分不出来：没有字母，或者两种文字势均力敌。
	ScriptUnknown Script = ""
)

// ScriptOf reports which writing system dominates a text.
// 报告一段文本以哪种文字系统为主。
//
// minRatio 是判定为某文字系统所需的占比。取 0.5 意味着「过半即算」，
// 而混排文本（中文夹英文术语）在真实语料里非常常见——门槛太高会让它们
// 落进 ScriptUnknown，从而完全跳过模型。
//
// minRatio is the share required to call a script dominant. Mixed text — a
// Chinese document with English technical terms — is extremely common, and too
// high a bar drops it into ScriptUnknown and skips the model entirely.
func ScriptOf(text string, minRatio float64) Script {
	if minRatio <= 0 || minRatio > 1 {
		minRatio = 0.5
	}

	han, latin, letters := 0, 0, 0
	for _, r := range text {
		if !unicode.IsLetter(r) {
			continue
		}
		letters++
		switch {
		case unicode.Is(unicode.Han, r):
			han++
		case unicode.Is(unicode.Latin, r):
			latin++
		}
	}
	if letters == 0 {
		return ScriptUnknown
	}

	// 汉字优先判定：中文里夹英文术语是常态，反之罕见。
	// 「网关 SSE 逐帧 flush」有 6 个汉字、8 个拉丁字母，按占比会被判成拉丁，
	// 而它显然该走中文模型。
	//
	// Han is checked first: Chinese text with English technical terms is
	// routine, the reverse is rare. 网关 SSE 逐帧 flush has six Han characters
	// and eight Latin letters; by share alone it would route to the Latin
	// model, which is clearly wrong.
	if float64(han)/float64(letters) >= minRatio*0.5 {
		return ScriptHan
	}
	if float64(latin)/float64(letters) >= minRatio {
		return ScriptLatin
	}
	return ScriptUnknown
}

// LanguageAwareDetector is a detector that can be told which language to use.
// 是一个可以被告知使用哪种语言的检测器。
//
// 可选接口：级联在模型实现了它时按文字系统路由，否则退回不带语言的调用。
// 用可选接口而不是加进 Detector，是为了让不关心语言的检测器（正则、名册）
// 不必实现一个对它们没有意义的方法。
//
// An optional interface: the cascade routes by script when the model
// implements it, and falls back to a language-free call otherwise. Optional
// rather than part of Detector, so that detectors for which language is
// meaningless need not implement it.
type LanguageAwareDetector interface {
	Detector
	DetectLanguage(text string, language string) ([]Entity, error)
}
