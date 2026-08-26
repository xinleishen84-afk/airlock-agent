// Package telemetry redacts PII from traces, logs and metrics in transit.
// 在传输途中从链路追踪、日志与指标中脱敏 PII。
//
// # Why telemetry is its own problem
// # 为什么遥测是一个独立的问题
//
// The gateway redacts what the model sees. It does nothing about the copy of
// that same prompt sitting in a span attribute on its way to Datadog. And the
// telemetry copy is the worse one: the model provider has a contract and a
// retention policy, while the observability backend is readable by everyone
// with a dashboard login, retained for a year, and replicated into whatever
// log-analytics tier finance picked.
// 网关脱敏的是模型看到的东西。它管不到同一段提示词在 span 属性里、
// 正飞往 Datadog 的那份副本。而遥测里的那份更糟：
// 模型厂商有合同、有留存策略，而可观测性后端对每一个有看板账号的人可读、
// 留存一年，并被复制进财务当初选的那一档日志分析服务里。
//
// # Why the AST allowlist does not transfer
// # 为什么 AST 白名单在这里不适用
//
// The document sanitizer works from an allowlist of seven JSON paths because
// the OpenAI request schema is finite and known. Telemetry is the opposite:
// attribute keys are invented by every library in the dependency tree, and the
// one that carries PII next quarter does not exist yet. An allowlist here would
// be a list of the leaks somebody already found.
// 文档清洗器基于七条 JSON 路径的白名单，因为 OpenAI 请求 schema 是有限且已知的。
// 遥测恰恰相反：属性键由依赖树里每一个库自行发明，
// 而下个季度携带 PII 的那个键现在还不存在。
// 在这里用白名单，等于列出一份「已经被人发现过的泄露」清单。
//
// So this scans everything and skips only what is provably not text a human
// wrote — with the skip list justified by throughput, never by safety.
// 因此这里扫描一切，只跳过那些可证明不是人写的文本——
// 而跳过的理由只能是吞吐，绝不能是安全。
package telemetry

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// FieldKind classifies a redactable text field.
// 对可脱敏的文本字段分类。
//
// The kind matters because the right operator differs: a metric label rewritten
// to a per-value placeholder multiplies time series, while the same rewrite in a
// span attribute costs nothing.
// 分类是要紧的，因为合适的算子不同：
// 指标标签被改写成逐值不同的占位符会让时间序列成倍增长，
// 而同样的改写放在 span 属性里则毫无代价。
type FieldKind uint8

const (
	// KindSpanName is a span's name. Frequently a URL path, and URL paths carry
	// customer identifiers more often than any attribute does.
	// 是 span 名。它经常是 URL 路径，而 URL 路径携带客户标识的频率高过任何属性。
	KindSpanName FieldKind = iota

	// KindAttribute is a span, log or resource attribute value.
	// 是 span、日志或资源的属性值。
	KindAttribute

	// KindBody is a log record body — the free-text field, and the one most
	// likely to contain a raw prompt.
	// 是日志记录正文——自由文本字段，也是最可能装着原始提示词的那个。
	KindBody

	// KindEvent is a span event field, including exception messages and stack
	// traces. An exception message is a formatted string built from live
	// variables, which makes it the richest PII source in a trace.
	// 是 span 事件字段，含异常消息与堆栈。异常消息是用运行时变量拼出来的
	// 格式化字符串，因此是一条链路里最富含 PII 的地方。
	KindEvent

	// KindMetricLabel is a metric attribute. Cardinality applies here and
	// nowhere else.
	// 是指标属性。基数问题只在这里存在。
	KindMetricLabel
)

// String renders the kind for audit output.
// 为审计输出渲染分类。
func (k FieldKind) String() string {
	switch k {
	case KindSpanName:
		return "span.name"
	case KindAttribute:
		return "attribute"
	case KindBody:
		return "body"
	case KindEvent:
		return "event"
	case KindMetricLabel:
		return "metric.label"
	}
	return "unknown"
}

// Field is one redactable text field.
// 是一个可脱敏的文本字段。
type Field struct {
	// Kind classifies the field.
	Kind FieldKind

	// Key is the attribute key, or empty for structural fields such as a span
	// name or a log body.
	// 是属性键；span 名、日志正文这类结构字段为空。
	Key string

	// Value is the current text.
	Value string
}

// Walker exposes a telemetry payload's redactable text to the firewall.
// 把遥测载荷中可脱敏的文本暴露给防火墙。
//
// An interface rather than a concrete type so the firewall does not depend on
// the OpenTelemetry Collector's data model. The collector's pdata package pulls
// in a large dependency tree, and a library that redacts PII should not force
// that on a caller who only wants to scan their own JSON.
// 用接口而非具体类型，使防火墙不依赖 OpenTelemetry Collector 的数据模型。
// collector 的 pdata 包会带进一棵庞大的依赖树，
// 而一个做 PII 脱敏的库，不该把它强加给只想扫自己那份 JSON 的调用方。
//
// The implementation decides what is walkable, and is responsible for never
// exposing trace IDs, span IDs or parent span IDs — rewriting those does not
// redact anything and does break every trace they belong to.
// 由实现决定什么可遍历，并负责绝不暴露 trace ID、span ID 与 parent span ID——
// 改写它们脱不掉任何东西，却会打断它们所属的每一条链路。
type Walker interface {
	// Walk visits every redactable field. Returning a new value replaces the
	// field; returning changed=false leaves it untouched.
	// 访问每一个可脱敏字段。返回新值即替换该字段；changed=false 表示不动。
	Walk(fn func(Field) (string, bool)) error
}

// Policy configures the firewall.
// 配置防火墙。
type Policy struct {
	// SkipKeys are attribute keys not scanned.
	// 是不扫描的属性键。
	//
	// Justified by throughput only. Every entry is a bet that this key never
	// carries text a human wrote, and a wrong bet here is a silent leak — so
	// the default set holds only keys whose values are enumerated by the
	// semantic conventions themselves.
	// 理由只能是吞吐。每一条都是一次「这个键永远不会携带人写的文本」的赌注，
	// 而赌错就是一次静默泄露——因此默认集合只放那些取值由语义约定本身
	// 枚举出来的键。
	SkipKeys map[string]bool

	// MaxValueBytes caps how much of one value is scanned. Zero means no cap.
	// 限制单个值被扫描的字节数。0 表示不限制。
	//
	// A stack trace can be hundreds of kilobytes, and the regex layer is linear
	// in input size. Without a cap, one pathological span stalls the collector
	// pipeline for every other span behind it.
	// 一段堆栈可以有几百 KB，而正则层的耗时与输入长度成线性。
	// 没有上限时，一个病态的 span 会把它后面排队的每一个 span 都拖住。
	//
	// Values longer than the cap are truncated rather than skipped: skipping
	// would forward the whole thing unredacted, which is the opposite of what a
	// size guard is for.
	// 超长的值被截断而非跳过：跳过等于把整段原样转发，
	// 与「加个大小保护」的初衷正好相反。
	MaxValueBytes int
}

// DefaultSkipKeys returns keys whose values are enumerated by the OpenTelemetry
// semantic conventions and therefore cannot be free text.
// 返回那些取值由 OpenTelemetry 语义约定枚举出来、因而不可能是自由文本的键。
//
// Note what is deliberately absent: http.url, http.target, db.statement,
// http.request.body and every messaging destination. Those are the attributes
// that carry customer data, and they are exactly the ones an "obviously safe
// HTTP attributes" skip list tends to sweep in.
// 注意刻意不在其中的：http.url、http.target、db.statement、http.request.body
// 以及各类消息目的地。它们正是携带客户数据的属性，
// 也正是一份「HTTP 属性显然安全」的跳过清单最容易顺手扫进去的那些。
func DefaultSkipKeys() map[string]bool {
	keys := []string{
		"http.status_code", "http.response.status_code",
		"http.method", "http.request.method",
		"http.flavor", "http.scheme",
		"rpc.system", "rpc.grpc.status_code",
		"db.system", "messaging.system",
		"net.transport", "net.protocol.name", "net.protocol.version",
		"telemetry.sdk.name", "telemetry.sdk.language", "telemetry.sdk.version",
		"otel.status_code", "otel.library.name", "otel.library.version",
		"span.kind", "error.type",
	}
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[k] = true
	}
	return out
}

// Stats reports what one redaction pass did.
// 报告一次脱敏做了什么。
type Stats struct {
	// FieldsScanned is how many text fields were examined.
	FieldsScanned int

	// FieldsRedacted is how many were rewritten.
	FieldsRedacted int

	// EntityCounts is per entity type.
	EntityCounts map[string]int

	// Truncated is how many values hit MaxValueBytes.
	//
	// 非零意味着有内容被丢弃了。它必须可见：一个被截断的堆栈里，
	// 丢掉的那部分既没有被脱敏，也没有被送达——
	// 而运维会以为自己看到的是完整的那条。
	// A non-zero count means content was dropped, and that has to be visible:
	// the discarded tail of a truncated stack trace was neither redacted nor
	// delivered, while the operator believes they are looking at the whole one.
	Truncated int
}

// Firewall redacts telemetry payloads in transit.
// 在传输途中脱敏遥测载荷。
type Firewall struct {
	detector detect.Detector
	flow     anonymize.Flow
	policy   Policy
	redactor *anonymize.Redactor
}

// New builds a telemetry firewall.
// 构造遥测防火墙。
//
// The flow must not use the mask operator and must not declare Restores.
// 该链路不得使用 mask 算子，也不得声明 Restores。
//
// # Why mask is refused here
// # 为什么这里拒绝 mask
//
// Placeholders exist to keep a conversation coherent across turns, and they are
// minted per distinct value inside a session vault. Telemetry has no session
// and no second turn: every distinct value in the trace stream would mint a
// vault entry that nothing will ever resolve, so the vault grows with traffic
// until the process dies. On a metric label it is worse — a per-value
// placeholder multiplies time series exactly the way the raw value did, so the
// cardinality bomb survives the redaction intact.
// 占位符的存在是为了让一段对话跨轮次保持连贯，它按不同值在会话保险库中铸造。
// 而遥测既没有会话也没有下一轮：链路流里每个不同的值都会铸造一条
// 永远不会有人去解析的保险库记录，于是保险库随流量增长直到进程死掉。
// 放在指标标签上更糟——逐值不同的占位符会像原值一样让时间序列成倍增长，
// 于是基数炸弹原封不动地活过了这次脱敏。
//
// Hash keeps aggregation working (the same user is the same digest, so
// group-by still counts distinct users) at bounded cardinality. Drop is the
// choice where even that link is too much.
// 哈希在有界基数下保住了聚合能力（同一个用户是同一个摘要，group-by 仍能
// 统计去重用户数）。连这层关联都嫌多时，就用切除。
func New(detector detect.Detector, flow anonymize.Flow, policy Policy) (*Firewall, error) {
	if detector == nil {
		return nil, fmt.Errorf("遥测防火墙需要检测器 / firewall requires a detector")
	}
	if flow.Default == nil {
		return nil, fmt.Errorf("链路 %q 缺少默认算子 / flow %q has no default strategy",
			flow.Name, flow.Name)
	}
	if flow.Restores {
		return nil, fmt.Errorf(
			"遥测链路不得声明 restores：遥测是单向的，没有响应可以复原，" +
				"声明它只会让配置读起来像存在一条并不存在的回程 / " +
				"telemetry flow must not declare restores")
	}
	if bad := maskingOperators(flow); len(bad) > 0 {
		return nil, fmt.Errorf(
			"遥测链路不得使用 mask 算子（%s）：占位符按不同值在会话保险库中铸造，"+
				"而遥测没有会话——每个不同的值都会留下一条永不被解析的记录，"+
				"保险库随流量增长；用在指标标签上还会让基数炸弹原样存活。"+
				"请改用 hash（保住聚合）或 drop / "+
				"telemetry flow must not use the mask operator (%s)",
			strings.Join(bad, "、"), strings.Join(bad, ", "))
	}

	if policy.SkipKeys == nil {
		policy.SkipKeys = DefaultSkipKeys()
	}
	return &Firewall{
		detector: detector,
		flow:     flow,
		policy:   policy,
		redactor: anonymize.NewRedactorWith(detector, true),
	}, nil
}

// maskingOperators lists the flow's operators that require a session vault.
// 列出该链路中需要会话保险库的算子。
func maskingOperators(flow anonymize.Flow) []string {
	seen := map[string]bool{}
	var out []string
	check := func(s anonymize.Strategy) {
		if s == nil || s.Name() != "mask" || seen[s.Name()] {
			return
		}
		seen[s.Name()] = true
		out = append(out, s.Name())
	}
	check(flow.Default)
	for typ, s := range flow.ByType {
		if s != nil && s.Name() == "mask" {
			label := "mask@" + string(typ)
			if !seen[label] {
				seen[label] = true
				out = append(out, label)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Redact rewrites every redactable field in the payload.
// 改写载荷中每一个可脱敏字段。
//
// # Fail direction
// # 失败的方向
//
// A detector failure returns an error and the caller must drop the payload.
// This is the opposite of the request path, where blocking a request is
// expensive and visible. Here the trade runs the other way: a lost span costs a
// gap in a dashboard, while a leaked one is copied into a backend that retains
// it for a year and is readable by everyone with a login.
// 检测器故障时返回错误，调用方必须丢弃该载荷。
// 这与请求路径的方向相反：在那里阻断一个请求代价高昂且可见。
// 这里的取舍反过来——丢一个 span 的代价是看板上少一段，
// 而漏一个 span 会被复制进一个留存一年、人人可读的后端。
func (f *Firewall) Redact(ctx context.Context, tenant anonymize.Tenant, w Walker) (Stats, error) {
	stats := Stats{EntityCounts: map[string]int{}}
	scope := anonymize.StrategyScope{Tenant: tenant}

	var walkErr error
	err := w.Walk(func(field Field) (string, bool) {
		if walkErr != nil {
			return "", false
		}
		if field.Key != "" && f.policy.SkipKeys[field.Key] {
			return "", false
		}
		if field.Value == "" {
			return "", false
		}
		stats.FieldsScanned++

		value := field.Value
		if n := f.policy.MaxValueBytes; n > 0 && len(value) > n {
			value = truncateAtRune(value, n)
			stats.Truncated++
		}

		res, err := f.redactor.RedactTo(ctx, value, scope, f.flow)
		if err != nil {
			walkErr = fmt.Errorf("脱敏 %s%s 失败 / redacting %s%s: %w",
				field.Kind, keySuffix(field.Key), field.Kind, keySuffix(field.Key), err)
			return "", false
		}
		if len(res.Entities) == 0 && value == field.Value {
			return "", false
		}
		stats.FieldsRedacted++
		for typ, n := range res.TypeCounts {
			stats.EntityCounts[typ] += n
		}
		return res.Text, true
	})
	if walkErr != nil {
		return Stats{}, walkErr
	}
	if err != nil {
		return Stats{}, fmt.Errorf("遍历遥测载荷失败 / walking telemetry payload: %w", err)
	}
	return stats, nil
}

// keySuffix renders an attribute key for an error message.
// 为报错信息渲染属性键。
func keySuffix(key string) string {
	if key == "" {
		return ""
	}
	return "[" + key + "]"
}

// truncateAtRune cuts a string at or before n bytes without splitting a rune.
// 在不超过 n 字节处截断，且不切开一个字符。
//
// Cutting mid-rune would emit invalid UTF-8 into the telemetry backend, and
// several of them reject or mangle the whole batch rather than the one field.
// 从字符中间切开会向遥测后端送出非法 UTF-8，
// 而其中若干后端会因此拒绝或弄坏整个批次，而不只是那一个字段。
func truncateAtRune(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
