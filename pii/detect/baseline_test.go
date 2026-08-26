package detect

import "testing"

// contextBoost 是基线识别器使用的上下文加权量，与 packs 中保持一致。
// The context boost used by the baseline recognizers, kept in step with packs.
const contextBoost = 0.15

// 引擎测试所需的基线识别器。
// The baseline recognizers the engine tests need.
//
// Deliberately a small hand-written set rather than the shipped recognizer
// table: this package tests the matching engine — boundaries, overlaps,
// prefilters, context boosting — not which identifiers a jurisdiction defines.
// That question belongs to the packs package, which owns the only copy of the
// real table.
// 刻意用一小组手写识别器，而不是随产品发布的识别器表：
// 本包测试的是匹配引擎——边界、重叠、前置过滤、上下文加权——
// 而不是某个司法管辖区定义了哪些标识。后者归 packs 包，
// 真实表的唯一副本在那里。
type baselineSpec struct {
	name  string
	typ   EntityType
	expr  string
	score float64
	opts  []PatternOption
}

func baselineSpecs() []baselineSpec {
	return []baselineSpec{
		{"email", TypeEmail, `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`, 0.99,
			[]PatternOption{WithPrefilter(RequireByte("@"))}},
		{"cn_id_card", TypeIDCard, `[0-9]{17}[0-9Xx]`, 0.99,
			[]PatternOption{WithPrefilter(RequireDigit), WithBoundary(BoundaryDigit),
				WithValidator(CNIDCardValid, false)}},
		{"cn_mobile", TypePhone, `1[3-9][0-9]{9}`, 0.90,
			[]PatternOption{WithPrefilter(RequireDigit), WithBoundary(BoundaryDigitSep)}},
		{"bank_card_grouped", TypeBankCard, `[0-9]{4}(?:[ \-][0-9]{4}){2,4}`, 0.80,
			[]PatternOption{WithPrefilter(RequireDigit), WithBoundary(BoundaryDigitSep),
				WithValidator(BankCardLuhnValid, true),
				WithContext(contextBoost, "卡号", "银行卡", "信用卡", "card", "credit")}},
		{"bank_card_plain", TypeBankCard, `[0-9]{12,19}`, 0.80,
			[]PatternOption{WithPrefilter(RequireDigit), WithBoundary(BoundaryDigitSep),
				WithValidator(BankCardLuhnValid, false),
				WithContext(contextBoost, "卡号", "银行卡", "信用卡", "card", "credit")}},
		{"cn_uscc", TypeUSCC, `[0-9A-HJ-NPQRTUWXY]{2}[0-9]{6}[0-9A-HJ-NPQRTUWXY]{10}`, 0.90,
			[]PatternOption{WithPrefilter(RequireUpperAlpha), WithBoundary(BoundaryAlnum),
				WithValidator(CNUSCCValid, false)}},
		{"ipv4", TypeIP,
			`(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}` +
				`(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])`, 0.85,
			[]PatternOption{WithPrefilter(RequireByte(".")), WithBoundary(BoundaryDigitSep)}},
		{"openai_key", TypeCredential, `sk-[A-Za-z0-9]{20,}`, 0.99,
			[]PatternOption{WithPrefilter(RequirePrefix("sk-"))}},
	}
}

func newBaselineRegistry(t testing.TB, disabled ...EntityType) *Registry {
	t.Helper()

	off := map[EntityType]bool{}
	for _, typ := range disabled {
		off[typ] = true
	}

	reg := NewRegistry()
	for _, s := range baselineSpecs() {
		if off[s.typ] {
			continue
		}
		rec, err := NewPatternRecognizer(s.name, s.typ, s.expr, s.score, s.opts...)
		if err != nil {
			t.Fatalf("构造基线识别器 %s 失败: %v", s.name, err)
		}
		if err := reg.Register(rec); err != nil {
			t.Fatalf("注册基线识别器 %s 失败: %v", s.name, err)
		}
	}
	return reg
}

// newBaselineRegistryNoPrefilter builds the same recognizers with every
// prefilter removed, so a test can prove the prefilters change only speed and
// never results.
// 构造同一批识别器但移除全部前置过滤器，
// 使测试能证明前置过滤只影响速度、绝不影响结果。
func newBaselineRegistryNoPrefilter(t testing.TB) *Registry {
	t.Helper()
	reg := NewRegistry()
	for _, s := range baselineSpecs() {
		opts := append(append([]PatternOption(nil), s.opts...), WithPrefilter(nil))
		rec, err := NewPatternRecognizer(s.name, s.typ, s.expr, s.score, opts...)
		if err != nil {
			t.Fatalf("构造无门控识别器 %s 失败: %v", s.name, err)
		}
		if err := reg.Register(rec); err != nil {
			t.Fatalf("注册无门控识别器 %s 失败: %v", s.name, err)
		}
	}
	return reg
}
