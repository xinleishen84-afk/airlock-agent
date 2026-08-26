package packs

import "github.com/xinleishen84-afk/airlock-agent/pii/detect"

// 中国大陆 / Mainland China.
func init() {
	register(Pack{
		Code: "CN",
		Name: "中国大陆 / Mainland China",
		Build: func() ([]detect.Recognizer, error) {
			return buildAll([]spec{
				{
					name: "cn_id_card", typ: detect.TypeIDCard, score: 0.90,
					expr: `[0-9]{17}[0-9Xx]`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequireDigit),
						detect.WithBoundary(detect.BoundaryDigit),
						detect.WithValidator(detect.CNIDCardValid, false),
						detect.WithContext(contextBoost, "身份证", "证件号", "identity", "id card"),
					},
				},
				{
					name: "cn_mobile", typ: detect.TypePhone, score: 0.85,
					expr: `1[3-9][0-9]{9}`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequireDigit),
						detect.WithBoundary(detect.BoundaryDigitSep),
						detect.WithContext(contextBoost, "手机", "电话", "联系", "phone", "mobile"),
					},
				},
				{
					name: "cn_landline", typ: detect.TypePhone, score: 0.85,
					expr: `0[0-9]{2,3}-[0-9]{7,8}`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequireByte("-")),
						detect.WithBoundary(detect.BoundaryDigitSep),
					},
				},
				{
					name: "cn_uscc", typ: detect.TypeUSCC, score: 0.90,
					expr: `[0-9A-HJ-NPQRTUWXY]{2}[0-9]{6}[0-9A-HJ-NPQRTUWXY]{10}`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequireUpperAlpha),
						detect.WithBoundary(detect.BoundaryAlnum),
						detect.WithValidator(detect.CNUSCCValid, false),
					},
				},
				{
					// Passport numbers overlap heavily with ordinary product
					// codes, so the base score sits low and context decides.
					// 护照号与普通产品编码大量重叠，因此基线分很低，主要靠上下文定夺。
					name: "cn_passport", typ: detect.TypePassport, score: 0.60,
					expr: `[EG][0-9]{8}`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequirePrefix("E", "G")),
						detect.WithBoundary(detect.BoundaryAlnum),
						detect.WithContext(0.30, "护照", "passport"),
					},
				},
				{
					name: "cn_license_plate", typ: detect.TypeLicensePlate, score: 0.90,
					expr: `[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领]` +
						`[A-HJ-NP-Z][A-HJ-NP-Z0-9]{4,6}[A-HJ-NP-Z0-9挂学警港澳]`,
					opts: []detect.PatternOption{detect.WithPrefilter(detect.RequireCJK)},
				},
			})
		},
	})
}
