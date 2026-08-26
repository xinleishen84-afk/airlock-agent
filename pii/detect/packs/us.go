package packs

import "github.com/xinleishen84-afk/airlock-agent/pii/detect"

// 美国 / United States.
func init() {
	register(Pack{
		Code: "US",
		Name: "美国 / United States",
		Build: func() ([]detect.Recognizer, error) {
			return buildAll([]spec{
				{
					// The SSN has no check digit — the format is its only
					// signal, so context carries more weight here than for any
					// checksum-backed identifier.
					// SSN 没有校验位——格式是它唯一的信号，
					// 因此上下文在这里比任何带校验和的标识都更重要。
					name: "us_ssn", typ: detect.TypeSSN, score: 0.75,
					expr: `[0-9]{3}-[0-9]{2}-[0-9]{4}`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequireByte("-")),
						detect.WithBoundary(detect.BoundaryDigit),
						detect.WithContext(0.20, "ssn", "social security", "社会安全号"),
					},
				},
			})
		},
	})
}
