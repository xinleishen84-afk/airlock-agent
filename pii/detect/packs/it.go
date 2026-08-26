package packs

import "github.com/xinleishen84-afk/airlock-agent/pii/detect"

// 意大利 / Italy.
func init() {
	register(Pack{
		Code: "IT",
		Name: "意大利 / Italy",
		Build: func() ([]detect.Recognizer, error) {
			return buildAll([]spec{
				{
					// The Codice Fiscale encodes name, birth date, sex and
					// birthplace, so it is far more revealing than a bare
					// account number — a leaked one discloses demographics even
					// without any surrounding text.
					// 意大利税号编码了姓名、出生日期、性别与出生地，
					// 因此比单纯的账号泄露得多——即便没有任何上下文，
					// 泄露一个税号也暴露了人口统计信息。
					name: "it_codice_fiscale", typ: detect.TypeIDCard, score: 0.90,
					expr: `[A-Za-z]{6}[0-9]{2}[A-Za-z][0-9]{2}[A-Za-z][0-9]{3}[A-Za-z]`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequireDigit),
						detect.WithBoundary(detect.BoundaryAlnum),
						detect.WithValidator(detect.ItalyCodiceFiscaleValid, false),
						detect.WithContext(contextBoost,
							"codice fiscale", "cf", "税号", "fiscal code"),
					},
				},
				{
					// Partita IVA: 11 digits with a Luhn check.
					// 增值税号：11 位数字，Luhn 校验。
					name: "it_partita_iva", typ: detect.TypeUSCC, score: 0.80,
					expr: `[0-9]{11}`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequireDigit),
						detect.WithBoundary(detect.BoundaryDigit),
						detect.WithValidator(detect.LuhnValid, false),
						detect.WithContext(0.15, "partita iva", "p.iva", "vat"),
					},
				},
			})
		},
	})
}
