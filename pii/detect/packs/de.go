package packs

import "github.com/xinleishen84-afk/airlock-agent/pii/detect"

// 德国 / Germany.
func init() {
	register(Pack{
		Code: "DE",
		Name: "德国 / Germany",
		Build: func() ([]detect.Recognizer, error) {
			return buildAll([]spec{
				{
					// The Steuer-ID carries both a MOD 11,10 check digit and a
					// digit-repetition rule. The structural rule does the heavy
					// lifting: a check digit alone would admit one in ten random
					// eleven-digit runs, and order numbers and timestamps are
					// eleven-digit runs.
					// 德国税号同时带 MOD 11,10 校验位和数字重复规则。
					// 结构规则承担了主要工作：仅靠校验位会放行十分之一的
					// 随机 11 位数字，而订单号和时间戳都是 11 位数字。
					name: "de_steuer_id", typ: detect.TypeIDCard, score: 0.90,
					expr: `[0-9]{11}`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequireDigit),
						detect.WithBoundary(detect.BoundaryDigit),
						detect.WithValidator(detect.GermanyTaxIDValid, false),
						detect.WithContext(contextBoost,
							"steuer", "steueridentifikationsnummer", "tax id", "税号"),
					},
				},
				{
					// German VAT number: DE followed by nine digits.
					// 德国增值税号：DE 后接九位数字。
					name: "de_ust_idnr", typ: detect.TypeUSCC, score: 0.85,
					expr: `DE[0-9]{9}`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequirePrefix("DE")),
						detect.WithBoundary(detect.BoundaryAlnum),
						detect.WithContext(contextBoost, "ust", "umsatzsteuer", "vat"),
					},
				},
			})
		},
	})
}
