package telemetry

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
)

// # OTLP/JSON
//
// A walker over the OTLP/JSON wire format, implemented on plain maps so that
// this package stays free of the collector's data model. It is what lets the
// firewall run as an OTLP proxy, a Lambda extension, or a unit test — anywhere
// the payload arrives as bytes rather than as pdata.
// 一个基于普通 map 实现的 OTLP/JSON 遍历器，使本包不依赖 collector 的数据模型。
// 正是它让防火墙能作为 OTLP 代理、Lambda 扩展或单元测试运行——
// 只要载荷是以字节而非 pdata 的形式到达。
//
// # The field-name trap
// # 字段名陷阱
//
// OTLP/JSON accepts both the protobuf field names and their lowerCamelCase
// forms: trace_id and traceId, string_value and stringValue, both legal, both
// emitted by real SDKs depending on the encoder. Handling only one of them
// produces a walker that silently visits nothing on half the traffic and
// reports success — the exact shape of failure this whole system exists to
// avoid, arrived at through a JSON naming convention.
// OTLP/JSON 同时接受 protobuf 字段名与其 lowerCamelCase 形式：
// trace_id 与 traceId、string_value 与 stringValue 都合法，
// 真实 SDK 会依编码器不同而各自输出。只处理其中一种，
// 得到的遍历器会在一半流量上静默地什么都不访问，然后报告成功——
// 正是本系统要避免的那种故障形态，只不过这次是经由一个 JSON 命名约定抵达的。

// OTLPWalker walks an OTLP/JSON payload decoded into map[string]any.
// 遍历一份已解码为 map[string]any 的 OTLP/JSON 载荷。
type OTLPWalker struct {
	doc map[string]any
}

// NewOTLPWalker builds a walker over a decoded OTLP/JSON document.
// 基于已解码的 OTLP/JSON 文档构造遍历器。
func NewOTLPWalker(doc map[string]any) *OTLPWalker {
	return &OTLPWalker{doc: doc}
}

// RedactOTLPJSON redacts a raw OTLP/JSON payload and returns the rewritten
// bytes.
// 脱敏原始 OTLP/JSON 载荷并返回改写后的字节。
func RedactOTLPJSON(ctx context.Context, f *Firewall, tenant anonymize.Tenant, payload []byte) (
	[]byte, Stats, error) {
	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, Stats{}, fmt.Errorf("解析 OTLP/JSON 失败 / parsing OTLP/JSON: %w", err)
	}
	stats, err := f.Redact(ctx, tenant, NewOTLPWalker(doc))
	if err != nil {
		return nil, Stats{}, err
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, Stats{}, fmt.Errorf("序列化 OTLP/JSON 失败 / marshalling OTLP/JSON: %w", err)
	}
	return out, stats, nil
}

// Walk implements Walker.
//
// Trace IDs, span IDs, parent span IDs, trace state, timestamps and status
// codes are never visited. Rewriting them redacts nothing — they are opaque
// identifiers, not text a human wrote — and it severs every trace they belong
// to, so the leak stays and the observability goes.
// 从不访问 trace ID、span ID、parent span ID、trace state、时间戳与状态码。
// 改写它们脱不掉任何东西——它们是不透明标识，不是人写的文本——
// 却会打断它们所属的每一条链路：泄露还在，可观测性没了。
func (w *OTLPWalker) Walk(fn func(Field) (string, bool)) error {
	// Traces
	for _, rs := range list(w.doc, "resourceSpans", "resource_spans") {
		res := obj(rs, "resource")
		walkAttributes(res, fn, KindAttribute)

		for _, ss := range list(rs, "scopeSpans", "scope_spans", "instrumentationLibrarySpans") {
			walkAttributes(obj(ss, "scope"), fn, KindAttribute)

			for _, span := range list(ss, "spans") {
				walkStringField(span, "name", fn, KindSpanName, "")
				walkAttributes(span, fn, KindAttribute)

				// status.message is a formatted string built from live values.
				// status.message 是用运行时值拼出来的格式化字符串。
				if st := obj(span, "status"); st != nil {
					walkStringField(st, "message", fn, KindAttribute, "status.message")
				}

				for _, ev := range list(span, "events") {
					walkStringField(ev, "name", fn, KindEvent, "event.name")
					walkAttributes(ev, fn, KindEvent)
				}
				// Link attributes travel with the span and are scanned like any
				// other attribute; the link's own trace/span ids are not.
				// 链接属性随 span 一起流转，与其他属性一样扫描；
				// 链接自身的 trace/span id 不扫。
				for _, ln := range list(span, "links") {
					walkAttributes(ln, fn, KindAttribute)
				}
			}
		}
	}

	// Logs
	for _, rl := range list(w.doc, "resourceLogs", "resource_logs") {
		walkAttributes(obj(rl, "resource"), fn, KindAttribute)

		for _, sl := range list(rl, "scopeLogs", "scope_logs", "instrumentationLibraryLogs") {
			walkAttributes(obj(sl, "scope"), fn, KindAttribute)

			for _, rec := range list(sl, "logRecords", "log_records") {
				// The body is the free-text field, and the one most likely to
				// hold a raw prompt.
				// 正文是自由文本字段，也是最可能装着原始提示词的那个。
				if body := obj(rec, "body"); body != nil {
					walkAnyValue(body, fn, KindBody, "body")
				}
				walkAttributes(rec, fn, KindAttribute)
			}
		}
	}

	// Metrics
	for _, rm := range list(w.doc, "resourceMetrics", "resource_metrics") {
		walkAttributes(obj(rm, "resource"), fn, KindMetricLabel)

		for _, sm := range list(rm, "scopeMetrics", "scope_metrics", "instrumentationLibraryMetrics") {
			walkAttributes(obj(sm, "scope"), fn, KindMetricLabel)

			for _, metric := range list(sm, "metrics") {
				// The metric name is author-written and constant per call site,
				// so it is not user data. Its data-point attributes are.
				// 指标名由作者书写、在每个调用点上是常量，因此不是用户数据。
				// 它的数据点属性才是。
				for _, kind := range []string{
					"gauge", "sum", "histogram", "exponentialHistogram",
					"exponential_histogram", "summary",
				} {
					agg := obj(metric, kind)
					if agg == nil {
						continue
					}
					for _, dp := range list(agg, "dataPoints", "data_points") {
						walkAttributes(dp, fn, KindMetricLabel)
						for _, ex := range list(dp, "exemplars") {
							walkAttributes(ex, fn, KindMetricLabel)
						}
					}
				}
			}
		}
	}
	return nil
}

// walkAttributes visits an OTLP attribute list in place.
// 就地访问一个 OTLP 属性列表。
func walkAttributes(container map[string]any, fn func(Field) (string, bool), kind FieldKind) {
	if container == nil {
		return
	}
	for _, attr := range list(container, "attributes") {
		key, _ := attr["key"].(string)
		if v := obj(attr, "value"); v != nil {
			walkAnyValue(v, fn, kind, key)
		}
	}
}

// walkAnyValue visits an OTLP AnyValue, recursing through arrays and kvlists.
// 访问一个 OTLP AnyValue，并递归穿过数组与键值列表。
//
// Nested values are where structured logging puts the interesting fields: a
// single "http.request" attribute is routinely a kvlist holding headers, a
// body and a user object. A walker that only looks at stringValue would report
// a clean scan on exactly the payloads worth scanning.
// 嵌套值正是结构化日志放置有价值字段的地方：
// 一个 "http.request" 属性通常是一个装着请求头、请求体和用户对象的键值列表。
// 只看 stringValue 的遍历器，会在恰恰最值得扫描的那些载荷上报告「干净」。
func walkAnyValue(value map[string]any, fn func(Field) (string, bool), kind FieldKind, key string) {
	for _, name := range []string{"stringValue", "string_value"} {
		if s, ok := value[name].(string); ok {
			if next, changed := fn(Field{Kind: kind, Key: key, Value: s}); changed {
				value[name] = next
			}
			return
		}
	}

	for _, name := range []string{"arrayValue", "array_value"} {
		if arr := obj(value, name); arr != nil {
			for _, item := range list(arr, "values") {
				walkAnyValue(item, fn, kind, key)
			}
			return
		}
	}

	for _, name := range []string{"kvlistValue", "kvlist_value"} {
		if kv := obj(value, name); kv != nil {
			for _, entry := range list(kv, "values") {
				nested, _ := entry["key"].(string)
				if v := obj(entry, "value"); v != nil {
					walkAnyValue(v, fn, kind, joinKey(key, nested))
				}
			}
			return
		}
	}

	// bytesValue is deliberately not walked: it is not text, and a redacted
	// rewrite would corrupt whatever it encodes.
	// bytesValue 刻意不遍历：它不是文本，改写会破坏它编码的东西。
}

// walkStringField visits one plain string field on an object.
// 访问对象上的一个普通字符串字段。
func walkStringField(o map[string]any, name string, fn func(Field) (string, bool),
	kind FieldKind, key string) {
	if o == nil {
		return
	}
	s, ok := o[name].(string)
	if !ok || s == "" {
		return
	}
	if next, changed := fn(Field{Kind: kind, Key: key, Value: s}); changed {
		o[name] = next
	}
}

// joinKey renders a nested attribute path.
// 渲染嵌套属性路径。
func joinKey(parent, child string) string {
	if parent == "" {
		return child
	}
	if child == "" {
		return parent
	}
	return parent + "." + child
}

// obj returns a nested object under any of the given names.
// 取出给定名称之一下的嵌套对象。
func obj(m map[string]any, names ...string) map[string]any {
	if m == nil {
		return nil
	}
	for _, name := range names {
		if v, ok := m[name].(map[string]any); ok {
			return v
		}
	}
	return nil
}

// list returns a slice of objects under any of the given names.
// 取出给定名称之一下的对象切片。
func list(m map[string]any, names ...string) []map[string]any {
	if m == nil {
		return nil
	}
	for _, name := range names {
		raw, ok := m[name].([]any)
		if !ok {
			continue
		}
		out := make([]map[string]any, 0, len(raw))
		for _, item := range raw {
			if o, ok := item.(map[string]any); ok {
				out = append(out, o)
			}
		}
		return out
	}
	return nil
}
