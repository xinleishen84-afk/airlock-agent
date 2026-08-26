package packs

import "github.com/xinleishen84-afk/airlock-agent/pii/detect"

// The jurisdiction-neutral pack: identifiers whose meaning does not change
// across borders.
// 与司法管辖区无关的包：含义不随国界改变的标识。
//
// A deployment must never have to enumerate countries to get an email address
// redacted. Anything that ends up here is something no country owns.
// 部署方绝不该为了脱敏一个邮箱地址而去枚举国家。
// 放进这里的，都是没有任何国家「拥有」的东西。
func init() {
	register(Pack{
		Code: "GEN",
		Name: "Jurisdiction-neutral / 通用",
		Build: func() ([]detect.Recognizer, error) {
			return buildAll([]spec{
				{
					name: "email", typ: detect.TypeEmail, score: 0.99,
					expr: `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequireByte("@")),
					},
				},
				{
					// Card networks are global; the issuing bank's country is
					// irrelevant to whether the number is a card number.
					// 卡组织是全球性的；发卡行属于哪个国家，
					// 与这串数字是不是卡号无关。
					name: "bank_card_grouped", typ: detect.TypeBankCard, score: 0.80,
					expr: `[0-9]{4}(?:[ \-][0-9]{4}){2,4}`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequireDigit),
						detect.WithBoundary(detect.BoundaryDigitSep),
						detect.WithValidator(detect.BankCardValid, true),
						detect.WithContext(contextBoost, "卡号", "银行卡", "信用卡", "card", "credit"),
					},
				},
				{
					name: "bank_card_plain", typ: detect.TypeBankCard, score: 0.80,
					expr: `[0-9]{12,19}`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequireDigit),
						detect.WithBoundary(detect.BoundaryDigitSep),
						detect.WithValidator(detect.BankCardValid, false),
						detect.WithContext(contextBoost, "卡号", "银行卡", "信用卡", "card", "credit"),
					},
				},
				{
					// IBAN spans 80-odd countries; the country code is inside
					// the value, so one recognizer covers all of them.
					// IBAN 横跨八十余国；国家代码在值内部，
					// 因此一个识别器覆盖全部。
					name: "iban", typ: detect.TypeIBAN, score: 0.95,
					expr: `[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]{4}){2,7}[A-Z0-9]{0,4}`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequireUpperAlpha),
						detect.WithBoundary(detect.BoundaryAlnum),
						detect.WithValidator(detect.IBANValid, true),
						detect.WithContext(contextBoost, "iban", "账号", "account", "银行"),
					},
				},
				{
					name: "intl_phone", typ: detect.TypePhone, score: 0.85,
					expr: `\+[0-9]{1,3}[\s\-]?[0-9]{6,14}`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequireByte("+")),
						detect.WithBoundary(detect.BoundaryDigit),
					},
				},
				{
					// IPv4 与四段式版本号在字面上完全相同：5.15.0.91 既是合法
					// 地址，也是像模像样的内核版本号，没有任何模式能把它们分开，
					// 因为根本没有可分的东西。上下文是唯一可用的信号，
					// 因此这里把它从「加权」提升为「必要条件」。
					//
					// 代价是真实的：一条没有任何周边文字的裸日志行里的地址会被
					// 漏掉。这是刻意买下的漏报，换来的是不再把每份变更日志里的
					// 每个版本号都报成个人数据。
					//
					// IPv4 and a four-segment version string are the same
					// string, so context is a condition here, not a hint. The
					// cost — an address in a bare log line is missed — is
					// bought deliberately.
					name: "ipv4", typ: detect.TypeIP, score: 0.70,
					expr: `(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}` +
						`(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])`,
					opts: []detect.PatternOption{
						detect.WithPrefilter(detect.RequireByte(".")),
						detect.WithBoundary(detect.BoundaryDigit),
						detect.WithRequiredContext(
							"ip", "IP", "地址", "服务器", "主机", "网关", "内网", "外网",
							"host", "server", "addr", "gateway", "endpoint", "上游"),
					},
				},
				// Credentials: the worst blast radius in the set. A leaked API
				// key is unrecoverable in a way a leaked phone number is not,
				// so these carry the maximum score and require no context.
				// 凭证：全集中泄露后果最严重的。泄露的 API 密钥是不可挽回的，
				// 泄露的手机号不是，因此分数拉满且不要求上下文。
				{
					name: "openai_key", typ: detect.TypeCredential, score: 0.99,
					expr: `sk-[A-Za-z0-9_\-]{16,}`,
					opts: []detect.PatternOption{detect.WithPrefilter(detect.RequirePrefix("sk-"))},
				},
				{
					name: "aws_access_key", typ: detect.TypeCredential, score: 0.99,
					expr: `AKIA[0-9A-Z]{16}`,
					opts: []detect.PatternOption{detect.WithPrefilter(detect.RequirePrefix("AKIA"))},
				},
				{
					name: "github_token", typ: detect.TypeCredential, score: 0.99,
					expr: `gh[pousr]_[A-Za-z0-9]{20,}`,
					opts: []detect.PatternOption{detect.WithPrefilter(detect.RequirePrefix("gh"))},
				},
				{
					name: "jwt", typ: detect.TypeCredential, score: 0.99,
					expr: `eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`,
					opts: []detect.PatternOption{detect.WithPrefilter(detect.RequirePrefix("eyJ"))},
				},
			})
		},
	})
}

// spec describes one recognizer inside a pack.
// 描述包内的一个识别器。
type spec struct {
	name  string
	typ   detect.EntityType
	expr  string
	score float64
	opts  []detect.PatternOption
}

// buildAll turns specs into recognizers, failing on the first bad pattern.
// 把 spec 转成识别器，遇到第一个非法模式即失败。
func buildAll(specs []spec) ([]detect.Recognizer, error) {
	out := make([]detect.Recognizer, 0, len(specs))
	for _, s := range specs {
		r, err := detect.NewPatternRecognizer(s.name, s.typ, s.expr, s.score, s.opts...)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
