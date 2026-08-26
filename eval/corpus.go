// Package eval measures the detection layer against a labelled corpus.
// 用带标注的语料衡量检测层。
//
// # What this can and cannot tell you
// # 它能说明什么、不能说明什么
//
// The positives here were written by the same person who wrote the recognizers.
// A recall number measured against them is close to circular: it says the
// patterns match the examples the patterns were written for. It is worth
// measuring anyway — a regression shows up immediately — but it is not the
// number a buyer should be quoted.
// 这里的正例，与识别器出自同一个人之手。用它们量出来的召回率近乎循环论证：
// 它说明的是「这些模式能匹配它们本来就是为之而写的例子」。
// 这个数字仍值得测——回归会立刻显形——但它不是可以拿去给客户报的那个数。
//
// The negatives are different, and they are where this corpus earns its keep.
// They were written adversarially: source code, version numbers, git hashes,
// order numbers, coordinates, timestamps — the things a production corpus is
// actually made of, chosen specifically to look like the identifiers the
// recognizers hunt for. A precision number measured against these is a real
// measurement, because nothing here was written to pass.
// 反例则不同，语料的价值就在这里。它们是对抗性地写出来的：
// 源代码、版本号、git 哈希、订单号、坐标、时间戳——
// 真实语料实际由这些东西构成，而且是特意挑那些「长得像识别器要找的标识」的。
// 用它们量出来的精确率是一次真实的测量，因为这里没有任何一条是为了通过而写的。
//
// # The number that matters most is not in here
// # 最要紧的那个数不在这里
//
// NAME, ADDRESS and ORG have no lexical signature. No regex finds them, so
// their recall in this corpus is whatever the roster happens to cover. On a
// real corpus with unknown names, recall for those types without an NER model
// is near zero — and no amount of tuning the patterns changes that.
// 姓名、地址、机构名没有字面特征。正则找不到它们，
// 因此它们在本语料中的召回率，取决于名册恰好覆盖了什么。
// 在一份含有未知姓名的真实语料上，不接 NER 模型时这几类的召回率接近零——
// 而且再怎么调正则也改变不了这一点。
package eval

import (
	"fmt"
	"strings"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// Span is one labelled entity occurrence.
// 是一处带标注的实体出现。
type Span struct {
	Start, End int
	Type       detect.EntityType
}

// Sample is one corpus document with ground truth.
// 是一份带标准答案的语料文档。
type Sample struct {
	Name string
	Text string
	// Gold holds every entity that should be found.
	// 存放所有应当被找到的实体。
	Gold []Span
	// Category groups samples in the report.
	// 在报告中对样本分组。
	Category string
}

// mark builds a sample from a template with {{TYPE|value}} annotations.
// 用带 {{TYPE|value}} 标注的模板构建样本。
//
// Writing spans by hand means writing byte offsets by hand, and a byte offset
// miscounted in a Chinese sentence produces a corpus that reports false
// negatives the detector never made — an evaluation harness that lies in the
// safe-looking direction.
// 手写 span 就是手写字节偏移，而在中文句子里数错一个偏移，
// 会产出一份报告「检测器根本没犯的漏报」的语料——
// 一个朝着「看起来安全」那个方向撒谎的评测框架。
func mark(name, category, template string) Sample {
	var text strings.Builder
	var gold []Span

	rest := template
	for {
		open := strings.Index(rest, "{{")
		if open < 0 {
			text.WriteString(rest)
			break
		}
		text.WriteString(rest[:open])
		rest = rest[open+2:]

		close := strings.Index(rest, "}}")
		if close < 0 {
			panic("语料模板 " + name + " 中有未闭合的标注 / unclosed annotation")
		}
		body := rest[:close]
		rest = rest[close+2:]

		bar := strings.Index(body, "|")
		if bar < 0 {
			panic("语料标注缺少 | 分隔符 / annotation missing separator: " + body)
		}
		typ := detect.EntityType(body[:bar])
		value := body[bar+1:]

		start := text.Len()
		text.WriteString(value)
		gold = append(gold, Span{Start: start, End: text.Len(), Type: typ})
	}
	return Sample{Name: name, Text: text.String(), Gold: gold, Category: category}
}

// clean builds a negative sample: text that must yield nothing.
// 构建反例样本：必须零命中的文本。
func clean(name, category, text string) Sample {
	return Sample{Name: name, Text: text, Category: category}
}

// Positives returns documents containing PII with ground-truth spans.
// 返回含 PII 的文档及其标准答案。
func Positives() []Sample {
	return []Sample{
		// --- 结构化标识：有校验位或强格式 ---
		mark("cn_id_plain", "结构化标识",
			"请核对客户身份证号 {{ID_CARD|11010519491231002X}} 后放行。"),
		mark("cn_id_lower_x", "结构化标识",
			"证件 {{ID_CARD|11010519491231002x}} 已归档。"),
		mark("cn_mobile_plain", "结构化标识",
			"联系电话 {{PHONE|13812345678}}，请在工作日拨打。"),
		mark("cn_mobile_two", "结构化标识",
			"主号 {{PHONE|13812345678}} 备用 {{PHONE|13900001111}}。"),
		mark("cn_landline", "结构化标识",
			"座机 {{PHONE|010-12345678}} 转 8006。"),
		mark("intl_phone", "结构化标识",
			"WhatsApp: {{PHONE|+8613812345678}}"),
		mark("card_plain", "结构化标识",
			"卡号 {{BANK_CARD|4111111111111111}} 已冻结。"),
		mark("card_grouped_space", "结构化标识",
			"信用卡 {{BANK_CARD|4111 1111 1111 1111}} 有效期 12/26。"),
		mark("card_grouped_dash", "结构化标识",
			"card {{BANK_CARD|4111-1111-1111-1111}} declined."),
		mark("uscc", "结构化标识",
			"开票信息：统一社会信用代码 {{USCC|91110108MA01ABCD71}}。"),
		mark("iban", "结构化标识",
			"Wire to {{IBAN|GB82WEST12345698765432}} before Friday."),
		mark("email_plain", "结构化标识",
			"发送到 {{EMAIL|zhang.wei@example.com}} 即可。"),
		mark("email_plus_tag", "结构化标识",
			"Reply to {{EMAIL|li.na+billing@sub.example.co.uk}} please."),
		mark("ipv4", "结构化标识",
			"服务器 {{IP|192.168.31.240}} 无响应。"),
		mark("passport", "结构化标识",
			"护照号 {{PASSPORT|E12345678}} 已过期。"),
		mark("plate", "结构化标识",
			"车牌 {{LICENSE_PLATE|京A12345}} 违章两次。"),
		mark("us_ssn", "结构化标识",
			"SSN {{SSN|123-45-6789}} on file."),
		mark("openai_key", "凭据",
			"export OPENAI_API_KEY={{CREDENTIAL|sk-abcdefghij1234567890}}"),
		mark("aws_key", "凭据",
			"aws_access_key_id = {{CREDENTIAL|AKIAIOSFODNN7EXAMPLE}}"),
		mark("github_token", "凭据",
			"token {{CREDENTIAL|ghp_1234567890abcdefghijklmnopqrstuvwxyz}} leaked"),

		// --- 欧洲国家包 ---
		mark("it_cf", "欧洲国家包",
			"Codice Fiscale: {{ID_CARD|MRTMTT25D09F205Z}}"),
		mark("de_steuer", "欧洲国家包",
			"Steuer-ID {{ID_CARD|86095742719}} bestätigt."),
		mark("es_dni", "欧洲国家包",
			"DNI {{ID_CARD|12345678Z}} verificado."),
		mark("es_nie", "欧洲国家包",
			"NIE {{ID_CARD|X1234567L}} registrado."),

		// --- 混合密度：一段里多个实体 ---
		mark("dense_mixed", "混合密度",
			"客户资料：手机 {{PHONE|13812345678}}，邮箱 {{EMAIL|zhang.wei@example.com}}，"+
				"身份证 {{ID_CARD|11010519491231002X}}，卡号 {{BANK_CARD|4111111111111111}}，"+
				"公司代码 {{USCC|91110108MA01ABCD71}}。"),
		mark("adjacent_no_space", "混合密度",
			"手机{{PHONE|13812345678}}邮箱{{EMAIL|a.b@example.com}}"),
		mark("in_json", "混合密度",
			`{"phone":"{{PHONE|13812345678}}","email":"{{EMAIL|a.b@example.com}}"}`),
		mark("in_markdown_table", "混合密度",
			"| 姓名 | 电话 |\n|---|---|\n| 客户A | {{PHONE|13812345678}} |"),

		// --- 姓名/机构：只有名册能覆盖 ---
		mark("roster_name", "名册可覆盖",
			"请联系 {{NAME|张伟}} 处理此事。"),
		mark("roster_org", "名册可覆盖",
			"合同方为 {{ORG|星辰科技}} 有限公司。"),
	}
}

// UnknownNames returns names deliberately absent from any roster.
// 返回刻意不在任何名册中的姓名。
//
// Separated from the main corpus because they measure a different thing: not
// whether the recognizers work, but what happens to the entity class that has
// no lexical signature. Folding them into the headline recall number would
// average away the single most important limitation of a regex-based engine.
// 与主语料分开，因为它们衡量的是另一件事：不是识别器管不管用，
// 而是「没有字面特征的那一类实体」会怎样。
// 把它们并进总召回率，会把一个基于正则的引擎最重要的那条局限平均掉。
func UnknownNames() []Sample {
	return []Sample{
		mark("unknown_name_1", "名册外姓名", "请联系 {{NAME|周慧敏}} 确认收货地址。"),
		mark("unknown_name_2", "名册外姓名", "经办人 {{NAME|欧阳志远}} 已签字。"),
		mark("unknown_name_3", "名册外姓名", "Please contact {{NAME|Margaret Okonkwo}} directly."),
		mark("unknown_address", "名册外地址", "寄往 {{ADDRESS|上海市浦东新区世纪大道 100 号 12 层}}。"),
		mark("unknown_org", "名册外机构", "供应商是 {{ORG|临安远景机械制造有限公司}}。"),
	}
}

// Negatives returns text that must produce zero detections.
// 返回必须零命中的文本。
//
// This is the adversarial half. Every entry was chosen because it resembles
// something a recognizer hunts for.
// 这是对抗的那一半。每一条都是因为「长得像识别器要找的东西」才被选进来的。
func Negatives() []Sample {
	return []Sample{
		// --- 源代码：误杀会直接改坏代码 ---
		clean("go_code", "源代码",
			"func hash(b []byte) uint64 { return 1469598103934665603 * 1099511628211 }"),
		clean("sql_code", "源代码",
			"SELECT id FROM orders WHERE created_at > 1700000000 LIMIT 100;"),
		clean("json_schema", "源代码",
			`{"type":"integer","minimum":1000000000000,"maximum":9999999999999}`),
		clean("hex_constants", "源代码",
			"const MASK = 0xDEADBEEFCAFEBABE; const SEED = 0x0123456789ABCDEF;"),
		clean("semver_list", "源代码",
			"deps: react@18.2.0, typescript@5.3.3, node@20.11.1, go@1.27.0"),
		clean("git_sha", "源代码",
			"commit 5b8aa5a2d2c872e8321cf37308d69df2 merged into main"),
		clean("uuid", "源代码",
			"request_id=550e8400-e29b-41d4-a716-446655440000 duration=12ms"),
		clean("base64_blob", "源代码",
			"payload=eyJhbGciOiJIUzI1NiJ9YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="),

		// --- 数字串：长得像卡号/证件号，但不是 ---
		clean("order_numbers", "业务编号",
			"订单号 20240131000012345，物流单号 780123456789012。"),
		clean("timestamps", "业务编号",
			"created 1706688000000, updated 1706774400000, ttl 86400000"),
		clean("isbn", "业务编号", "ISBN 978-7-121-38765-2 第三版"),
		clean("invoice_seq", "业务编号",
			"发票代码 011001900111 号码 12345678 金额 1234.56"),
		clean("port_and_pid", "业务编号",
			"listening on 8080, pid 13812, worker 13812345"),

		// --- 版本号与坐标：长得像 IP ---
		clean("version_dotted", "版本与坐标",
			"kernel 5.15.0.91, driver 535.129.03, firmware 1.2.3.4"),
		clean("coordinates", "版本与坐标",
			"定位 39.904200, 116.407396 精度 5 米"),
		clean("ratios", "版本与坐标",
			"分辨率 1920.1080.60.8 色深 10.10.10.2"),

		// --- 专业术语：中文分词与名册的误杀区 ---
		clean("medical_terms", "专业术语",
			"患者主诉：反复胸痛三月，心电图示 ST 段压低，诊断为不稳定型心绞痛。"),
		clean("legal_terms", "专业术语",
			"依据《中华人民共和国个人信息保护法》第十三条第一款之规定处理。"),
		clean("finance_terms", "专业术语",
			"本期加权平均净资产收益率 12.35%，每股收益 0.87 元。"),
		clean("tech_prose", "专业术语",
			"网关在 KV 显存超过 0.85 时进入分级降级，SSE 逐帧 flush 保持 TTFT。"),

		// --- 近似但校验失败：校验位层的价值就在这里 ---
		clean("bad_luhn", "校验失败",
			"测试卡号 4111111111111112 应当被拒绝。"),
		clean("bad_id_checksum", "校验失败",
			"错误证件号 11010519491231002A 无法识别。"),
		clean("bad_uscc", "校验失败",
			"代码 91110108MA01ABCD7Y 校验不通过。"),
		clean("bad_iban", "校验失败",
			"IBAN GB82WEST12345698765433 rejected by the bank."),
	}
}

// stripSep removes grouping separators before a checksum.
// 校验前去掉分组分隔符。
func stripSep(v string) string {
	return strings.NewReplacer(" ", "", "-", "").Replace(v)
}

// isDigitish reports whether a value looks like a digit run with a trailing X.
// 报告一个值是否形如「数字串 + 可能的末位 X」。
func isDigitish(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= '0' && c <= '9' {
			continue
		}
		if i == len(v)-1 && (c == 'X' || c == 'x') {
			continue
		}
		return false
	}
	return true
}

// Validate checks that every gold span actually matches the text it labels.
// 校验每一条标准答案确实对应它所标注的文本。
//
// An evaluation harness with a miscounted offset reports failures the detector
// never made, and the natural response to a surprising failure is to loosen the
// detector. A corpus is a measuring instrument and has to be calibrated before
// anything is measured with it.
// 一个偏移数错的评测框架，会报告检测器根本没犯的失败，
// 而面对意外失败的自然反应是去放松检测器。
// 语料是量具，在用它量任何东西之前必须先校准。
func Validate(samples []Sample) error {
	// 带校验位的类型必须真的通过校验。
	//
	// 只校对偏移是不够的：一个被标成 USCC 却过不了 GB 32100 的值，
	// 会让评测报告一次检测器根本没犯的漏报——而面对意外漏报的自然反应
	// 是去放松检测器。这条自检就是为了防住那次「放松」而存在的。
	//
	// Offsets alone are not enough: a value labelled USCC that fails GB 32100
	// makes the harness report a miss the detector never made, and the natural
	// response to a surprising miss is to loosen the detector.
	checksums := map[detect.EntityType]func(string) bool{
		detect.TypeUSCC:     detect.CNUSCCValid,
		detect.TypeBankCard: func(v string) bool { return detect.BankCardLuhnValid(stripSep(v)) },
		detect.TypeIBAN:     detect.IBANValid,
	}

	for _, s := range samples {
		for i, g := range s.Gold {
			if g.Start < 0 || g.End > len(s.Text) || g.Start >= g.End {
				return fmt.Errorf("样本 %s 的第 %d 条标注越界 [%d,%d) / span out of range",
					s.Name, i, g.Start, g.End)
			}
			if g.Type == "" {
				return fmt.Errorf("样本 %s 的第 %d 条标注缺少类型 / missing type", s.Name, i)
			}
			value := s.Text[g.Start:g.End]
			if check, ok := checksums[g.Type]; ok && !check(value) {
				return fmt.Errorf(
					"样本 %s 的标注 %q 被标为 %s，但它过不了该类型的校验位——"+
						"语料本身是错的，不是检测器漏报 / invalid %s in corpus",
					s.Name, value, g.Type, g.Type)
			}
			if g.Type == detect.TypeIDCard && len(value) == 18 && isDigitish(value) &&
				!detect.CNIDCardValid(value) {
				return fmt.Errorf(
					"样本 %s 的标注 %q 被标为身份证，但过不了 GB 11643 / invalid ID card in corpus",
					s.Name, value)
			}
		}
	}
	return nil
}
