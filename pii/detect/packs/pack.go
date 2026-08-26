// Package packs holds jurisdiction-scoped recognizer bundles.
// 存放按司法管辖区划分的识别器包。
//
// # Why jurisdiction is the unit
// # 为什么以司法管辖区为单位
//
// A flat dictionary of "sensitive things" quietly encodes the assumptions of
// whoever wrote it. A US-centric engine finds SSNs and misses Codice Fiscale; a
// CN-centric one finds 身份证 and misses Steuer-ID. Neither is wrong about its
// home market and both are useless outside it, and the failure is silent:
// scanning Italian documents with a US pack reports zero PII, which reads as
// clean data rather than as a missing pack.
// 一张扁平的「敏感数据」字典，悄悄编码了编写者的假设。
// 以美国为中心的引擎能找到 SSN 却漏掉意大利税号；以中国为中心的能找到身份证
// 却漏掉德国税号。两者在各自本土市场都没错，出了本土都没用——
// 而且故障是静默的：用美国包扫意大利文档会报告零 PII，
// 这读起来像「数据很干净」，而不是「装错了包」。
//
// Making the jurisdiction explicit turns that silence into a configuration
// decision someone has to make and can be asked about.
// 把司法管辖区显式化，就把这份静默变成了一个必须有人做、也可以被追问的配置决定。
//
// # What belongs in a pack
// # 什么该进包
//
// Only identifiers whose meaning is bound to a jurisdiction. Email addresses,
// IP addresses and API keys are the same everywhere and live in Generic — a
// deployment must never have to enumerate countries to get them.
// 只放含义绑定于某司法管辖区的标识。邮箱、IP、API 密钥在哪里都一样，
// 放在 Generic 里——部署方绝不该为了拿到它们而去枚举国家。
package packs

import (
	"fmt"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// Pack is a jurisdiction-scoped bundle of recognizers.
// 是按司法管辖区划分的识别器集合。
type Pack struct {
	// Code is an ISO 3166-1 alpha-2 country code, or "GEN" for the
	// jurisdiction-neutral bundle.
	// 是 ISO 3166-1 alpha-2 国家代码，或 "GEN" 表示与司法管辖区无关的包。
	Code string

	// Name is a human-readable label for audit output and startup logs.
	// 是供审计输出与启动日志使用的可读名称。
	Name string

	// Build constructs the recognizers. A function rather than a slice so that
	// regex compilation happens only for packs actually loaded — a deployment
	// serving one country should not pay to compile forty others.
	// 用函数而非切片，使正则编译只发生在真正加载的包上——
	// 服务单一国家的部署不该为编译另外四十个国家的正则付费。
	Build func() ([]detect.Recognizer, error)
}

// Registry maps country codes to packs.
// 把国家代码映射到包。
var registry = map[string]Pack{}

// register adds a pack at init time.
// 在 init 时注册一个包。
func register(p Pack) {
	if _, dup := registry[p.Code]; dup {
		panic("重复的国家包代码 / duplicate pack code: " + p.Code)
	}
	registry[p.Code] = p
}

// Available returns every registered pack code.
// 返回全部已注册的包代码。
func Available() []string {
	out := make([]string, 0, len(registry))
	for code := range registry {
		out = append(out, code)
	}
	return sortedStrings(out)
}

// Get returns a pack by code.
// 按代码取出一个包。
func Get(code string) (Pack, bool) {
	p, ok := registry[normalizeCode(code)]
	return p, ok
}

// Load builds recognizers for the named packs and returns them together.
// 为指定的包构建识别器并合并返回。
//
// An unknown code is an error rather than a skip. Silently ignoring "GB" would
// leave a UK deployment scanning with no UK recognizers while reporting success
// — the operator would learn about it from a regulator, not from a log line.
// 未知代码视为错误而非跳过。静默忽略 "GB" 会让一个英国部署在没有任何英国
// 识别器的情况下报告成功——运维会从监管机构而非日志里得知这件事。
func Load(codes ...string) ([]detect.Recognizer, error) {
	var out []detect.Recognizer
	seen := map[string]bool{}

	for _, raw := range codes {
		code := normalizeCode(raw)
		if seen[code] {
			continue
		}
		seen[code] = true

		p, ok := registry[code]
		if !ok {
			return nil, fmt.Errorf(
				"未知的国家包 %q，可用：%v / unknown pack %q, available: %v",
				raw, Available(), raw, Available())
		}
		recs, err := p.Build()
		if err != nil {
			return nil, fmt.Errorf("构建国家包 %s 失败 / building pack %s: %w", code, code, err)
		}
		out = append(out, recs...)
	}
	return out, nil
}

// LoadInto builds the named packs and registers them into a detect.Registry.
// 构建指定的包并注册进 detect.Registry。
func LoadInto(reg *detect.Registry, codes ...string) error {
	recs, err := Load(codes...)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if err := reg.Register(r); err != nil {
			return fmt.Errorf("注册识别器 %s 失败 / registering %s: %w", r.Name(), r.Name(), err)
		}
	}
	return nil
}

// normalizeCode upper-cases a code so "de", "De" and "DE" all resolve.
// 把代码转为大写，使 "de"、"De"、"DE" 都能解析。
func normalizeCode(code string) string {
	b := []byte(code)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

// sortedStrings returns a sorted copy.
// 返回排序后的副本。
func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// contextBoost is the confidence bump applied when a context word appears near
// a match, kept consistent with the built-in recognizers.
// 是命中上下文词时的置信度提升，与内置识别器保持一致。
const contextBoost = 0.15

// NewRegistry builds a detect.Registry from the named packs.
// 用指定的包构建一个 detect.Registry。
//
// There is deliberately no implicit default set. A default would have to pick a
// home market, and whichever one it picked would be right for its author and
// silently wrong everywhere else — the deployment scanning Italian contracts
// would inherit someone else's assumption without ever being asked.
// 这里刻意没有隐式默认集合。默认值必须选定一个本土市场，
// 而无论选哪个，对作者都对、在别处都静默地错——
// 扫描意大利合同的那套部署，会在从未被询问的情况下继承别人的假设。
//
// disabled turns off specific entity types after loading. An internal-network
// deployment may legitimately not want IP addresses redacted; forcing it would
// fill the audit log with noise and train operators to ignore it.
// disabled 在加载后关闭特定实体类型。内网部署可能确实不需要脱敏 IP；
// 强制脱敏只会让审计日志充满噪音，把运维训练成无视告警。
func NewRegistry(codes []string, disabled ...detect.EntityType) (*detect.Registry, error) {
	if len(codes) == 0 {
		return nil, fmt.Errorf(
			"未指定国家包；必须显式选择司法管辖区，可用：%v / no packs named, available: %v",
			Available(), Available())
	}
	recs, err := Load(codes...)
	if err != nil {
		return nil, err
	}

	off := make(map[detect.EntityType]bool, len(disabled))
	for _, t := range disabled {
		off[t] = true
	}

	reg := detect.NewRegistry()
	for _, r := range recs {
		if off[r.EntityType()] {
			continue
		}
		if err := reg.Register(r); err != nil {
			return nil, fmt.Errorf("注册识别器 %s 失败 / registering %s: %w", r.Name(), r.Name(), err)
		}
	}
	return reg, nil
}

// MustNewRegistry is NewRegistry for package-level initialisation and tests.
// 是供包级初始化与测试使用的 NewRegistry。
func MustNewRegistry(codes []string, disabled ...detect.EntityType) *detect.Registry {
	reg, err := NewRegistry(codes, disabled...)
	if err != nil {
		panic(err)
	}
	return reg
}
