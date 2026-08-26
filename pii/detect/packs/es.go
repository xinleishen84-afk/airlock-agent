package packs

import "github.com/xinleishen84-afk/airlock-agent/pii/detect"

// 西班牙 / Spain.
func init() {
	register(Pack{
		Code: "ES",
		Name: "西班牙 / Spain",
		Build: func() ([]detect.Recognizer, error) {
			return buildAll([]spec{
				{
					// One recognizer covers DNI and NIE alike: the NIE prefix
					// X/Y/Z maps to a leading digit and the same arithmetic
					// applies. Splitting them would risk shipping only DNI,
					// which silently misses every foreign resident.
					// 一个识别器同时覆盖 DNI 与 NIE：NIE 前缀 X/Y/Z 映射为首位数字，
					// 之后套用同一套算术。拆开会有只发布 DNI 的风险，
					// 那会静默漏掉每一个外国居民。
					name: "es_dni_nie", typ: detect.TypeIDCard, score: 0.90,
					expr: `[XYZxyz]?[0-9]{7,8}[-]?[A-Za-z]`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequireDigit),
						detect.WithBoundary(detect.BoundaryAlnum),
						detect.WithValidator(detect.SpainDNIValid, true),
						detect.WithContext(contextBoost, "dni", "nie", "documento", "身份证"),
					},
				},
			})
		},
	})
}
