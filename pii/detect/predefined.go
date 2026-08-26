package detect

// Predefined recognizers, one per entity type.
// 预定义识别器，每种实体类型一个。
//
// Kept in a single file rather than a directory tree: Go resolves symbols per
// package, so splitting into files buys no encapsulation, and a single table is
// easier to review as a whole — and reviewing this table *as a whole* is the
// point. Every entry is a decision about what counts as PII.
// 放在单个文件而非目录树里：Go 按包解析符号，拆成多个文件换不来封装，
// 而单张表更容易整体评审——整体评审这张表正是关键。
// 每一条都是一次「什么算 PII」的判断。

// contextBoost is the confidence bump applied when a context word appears near
// a match. 0.15 is chosen so a 0.75 base clears a 0.85 threshold with context
// but stays below it without — the boost has to actually change decisions.
// 是命中上下文词时的置信度提升。取 0.15 的理由：0.75 的基线在有上下文时
// 越过 0.85 阈值、无上下文时不越过——加权必须真的改变判定才有意义。
const contextBoost = 0.15

// NewDefaultRegistry builds a registry with every predefined recognizer.
// 构造包含全部预定义识别器的注册中心。
//
// disabled turns off specific entity types. An internal-network deployment may
// legitimately not want IP addresses redacted; forcing it to would fill the
// audit log with noise and train operators to ignore it.
// disabled 用于关闭特定实体类型。内网部署可能确实不需要脱敏 IP；
// 强制脱敏只会让审计日志充满噪音，把运维训练成无视告警。
func NewDefaultRegistry(disabled ...EntityType) (*Registry, error) {
	off := make(map[EntityType]bool, len(disabled))
	for _, t := range disabled {
		off[t] = true
	}

	reg := NewRegistry()
	for _, spec := range predefinedSpecs() {
		if off[spec.entityType] {
			continue
		}
		rec, err := NewPatternRecognizer(
			spec.name, spec.entityType, spec.expr, spec.score, spec.opts...)
		if err != nil {
			return nil, err
		}
		if err := reg.Register(rec); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

// predefinedSpec describes one built-in recognizer.
// 描述一个内置识别器。
type predefinedSpec struct {
	name       string
	entityType EntityType
	expr       string
	score      float64
	opts       []PatternOption
}

// predefinedSpecs returns the built-in recognizer table.
// 返回内置识别器表。
func predefinedSpecs() []predefinedSpec {
	return []predefinedSpec{
		{
			name: "email", entityType: TypeEmail, score: 0.99,
			expr: `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
			// Email needs no boundary or context: the shape is unambiguous.
			// 邮箱不需要边界或上下文：形态本身就无歧义。
		},
		{
			name: "cn_id_card", entityType: TypeIDCard, score: 0.90,
			expr: `[0-9]{17}[0-9Xx]`,
			opts: []PatternOption{
				WithBoundary(boundaryDigit),
				WithValidator(CNIDCardValid, false),
				WithContext(contextBoost, "身份证", "证件号", "identity", "id card", "id no"),
			},
		},
		{
			name: "cn_mobile", entityType: TypePhone, score: 0.85,
			expr: `1[3-9][0-9]{9}`,
			opts: []PatternOption{
				WithBoundary(boundaryDigitSep),
				WithContext(contextBoost, "手机", "电话", "联系", "phone", "mobile", "tel"),
			},
		},
		{
			name: "cn_landline", entityType: TypePhone, score: 0.85,
			expr: `0[0-9]{2,3}-[0-9]{7,8}`,
			opts: []PatternOption{WithBoundary(boundaryDigitSep)},
		},
		{
			name: "intl_phone", entityType: TypePhone, score: 0.85,
			expr: `\+[0-9]{1,3}[\s\-]?[0-9]{6,14}`,
			opts: []PatternOption{WithBoundary(boundaryDigit)},
		},
		{
			// Grouped form: four-digit blocks. Deliberately separate from the
			// continuous form — one greedy pattern spanning separators would
			// join two adjacent runs into a match that must fail the checksum,
			// swallowing the real card number.
			// 分组形态：四位一组。刻意与连续形态分开——
			// 一个跨分隔符的贪婪模式会把相邻两串数字连成必然校验失败的匹配，
			// 吞掉真正的卡号。
			name: "bank_card_grouped", entityType: TypeBankCard, score: 0.80,
			expr: `[0-9]{4}(?:[ \-][0-9]{4}){2,4}`,
			opts: []PatternOption{
				WithBoundary(boundaryDigitSep),
				WithValidator(LuhnValid, true),
				WithContext(contextBoost, "卡号", "银行卡", "信用卡", "card", "credit"),
			},
		},
		{
			name: "bank_card_plain", entityType: TypeBankCard, score: 0.80,
			expr: `[0-9]{12,19}`,
			opts: []PatternOption{
				WithBoundary(boundaryDigitSep),
				WithValidator(LuhnValid, false),
				WithContext(contextBoost, "卡号", "银行卡", "信用卡", "card", "credit"),
			},
		},
		{
			// IBAN carries its own check digits, so a false positive is nearly
			// impossible once mod-97 passes — hence the high base score.
			// IBAN 自带校验位，一旦通过 mod-97 几乎不可能是误报，故基线分很高。
			name: "iban", entityType: TypeIBAN, score: 0.95,
			expr: `[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]{4}){2,7}[A-Z0-9]{0,4}`,
			opts: []PatternOption{
				WithBoundary(boundaryAlnum),
				WithValidator(IBANValid, true),
				WithContext(contextBoost, "iban", "账号", "account", "银行"),
			},
		},
		{
			name: "cn_uscc", entityType: TypeUSCC, score: 0.90,
			expr: `[0-9A-HJ-NPQRTUWXY]{2}[0-9]{6}[0-9A-HJ-NPQRTUWXY]{10}`,
			opts: []PatternOption{
				WithBoundary(boundaryAlnum),
				WithValidator(CNUSCCValid, false),
			},
		},
		{
			name: "us_ssn", entityType: TypeSSN, score: 0.85,
			expr: `[0-9]{3}-[0-9]{2}-[0-9]{4}`,
			opts: []PatternOption{
				WithBoundary(boundaryDigit),
				WithContext(contextBoost, "ssn", "social security"),
			},
		},
		{
			// Passport numbers overlap heavily with ordinary alphanumeric codes,
			// so the base score sits low and context does the real work.
			// 护照号与普通字母数字编码大量重叠，因此基线分很低，
			// 主要靠上下文来定夺。
			name: "cn_passport", entityType: TypePassport, score: 0.60,
			expr: `[EG][0-9]{8}`,
			opts: []PatternOption{
				WithBoundary(boundaryAlnum),
				WithContext(0.30, "护照", "passport"),
			},
		},
		{
			name: "cn_license_plate", entityType: TypeLicensePlate, score: 0.90,
			expr: `[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领]` +
				`[A-HJ-NP-Z][A-HJ-NP-Z0-9]{4,6}[A-HJ-NP-Z0-9挂学警港澳]`,
		},
		{
			name: "ipv4", entityType: TypeIP, score: 0.70,
			expr: `(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}` +
				`(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])`,
			opts: []PatternOption{WithBoundary(boundaryDigit)},
		},
		// Credentials: worst blast radius, so no context requirement and the
		// score is maxed. A leaked API key is unrecoverable in a way a leaked
		// phone number is not.
		// 凭证：泄露后果最严重，因此不要求上下文且分数拉满。
		// 泄露的 API 密钥是不可挽回的，泄露的手机号不是。
		{name: "openai_key", entityType: TypeCredential, score: 0.99,
			expr: `sk-[A-Za-z0-9_\-]{16,}`},
		{name: "aws_access_key", entityType: TypeCredential, score: 0.99,
			expr: `AKIA[0-9A-Z]{16}`},
		{name: "github_token", entityType: TypeCredential, score: 0.99,
			expr: `gh[pousr]_[A-Za-z0-9]{20,}`},
		{name: "jwt", entityType: TypeCredential, score: 0.99,
			expr: `eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`},
	}
}
