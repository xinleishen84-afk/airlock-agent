package piiredactionprocessor

import (
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/xinleishen84-afk/airlock-agent/pii/telemetry"
)

// # pdata adapters
// # pdata 适配层
//
// These translate the collector's data model into the firewall's Walker
// interface. They are the only files in this repository that know pdata exists,
// which is why they live in a separate module: pdata pulls in a large
// dependency tree, and a library that redacts PII should not force it on a
// caller who only wants to scan their own JSON.
// 它们把 collector 的数据模型翻译成防火墙的 Walker 接口。
// 它们是本仓库中唯一知道 pdata 存在的文件，这也是它们独立成模块的原因：
// pdata 会带进一棵庞大的依赖树，而一个做 PII 脱敏的库，
// 不该把它强加给只想扫自己那份 JSON 的调用方。

// traceWalker exposes one ResourceSpans' redactable text.
// 暴露单个 ResourceSpans 中可脱敏的文本。
//
// # Resource-scoped, and walked in place
// # 以资源为单位，且就地遍历
//
// Per-resource rather than per-batch so the tenant can differ between resources
// in one batch: a shared collector receives batches from many services, and one
// tenant for the whole batch would hash one tenant's values under another
// tenant's key.
// 以资源而非批次为单位，是为了让同一批次内不同资源可以属于不同租户：
// 共享 collector 会收到来自多个服务的批次，
// 而整批共用一个租户会让一个租户的值用另一个租户的密钥去哈希。
//
// In place, because pdata's MoveTo/CopyTo produce an independent copy. An
// earlier version of this file isolated each resource that way; it compiled,
// ran, reported the fields it had redacted — and forwarded the original batch
// untouched. Every setter below must land on the batch the collector goes on to
// export.
// 就地遍历，是因为 pdata 的 MoveTo/CopyTo 会产出一份独立副本。
// 本文件先前的一版正是那样隔离每个资源的：它能编译、能运行、
// 还会报告自己脱敏了多少字段——然后原样转发了原批次。
// 下面每一个 setter 都必须落在 collector 接下来要导出的那个批次上。
type traceWalker struct{ rs ptrace.ResourceSpans }

// Walk implements telemetry.Walker.
//
// TraceID, SpanID and ParentSpanID are not visited. They are opaque
// identifiers, not text a human wrote: rewriting them redacts nothing and
// severs every trace they belong to, so the leak stays and the observability
// goes.
// 不访问 TraceID、SpanID 与 ParentSpanID。它们是不透明标识、不是人写的文本：
// 改写它们脱不掉任何东西，却会打断它们所属的每一条链路——
// 泄露还在，可观测性没了。
func (w traceWalker) Walk(fn func(telemetry.Field) (string, bool)) error {
	{
		rs := w.rs
		walkMap(rs.Resource().Attributes(), fn, telemetry.KindAttribute, "")

		sss := rs.ScopeSpans()
		for j := range sss.Len() {
			ss := sss.At(j)
			walkMap(ss.Scope().Attributes(), fn, telemetry.KindAttribute, "")

			spans := ss.Spans()
			for k := range spans.Len() {
				span := spans.At(k)

				// A span name is routinely a URL path, and URL paths carry
				// customer identifiers more often than any attribute does.
				// span 名经常是 URL 路径，而 URL 路径携带客户标识的频率
				// 高过任何属性。
				if next, changed := fn(telemetry.Field{
					Kind: telemetry.KindSpanName, Value: span.Name(),
				}); changed {
					span.SetName(next)
				}

				walkMap(span.Attributes(), fn, telemetry.KindAttribute, "")

				// status.message is a formatted string built from live values.
				// status.message 是用运行时值拼出来的格式化字符串。
				st := span.Status()
				if next, changed := fn(telemetry.Field{
					Kind: telemetry.KindAttribute, Key: "status.message", Value: st.Message(),
				}); changed {
					st.SetMessage(next)
				}

				events := span.Events()
				for e := range events.Len() {
					ev := events.At(e)
					if next, changed := fn(telemetry.Field{
						Kind: telemetry.KindEvent, Key: "event.name", Value: ev.Name(),
					}); changed {
						ev.SetName(next)
					}
					// exception.message and exception.stacktrace live here, and
					// an exception message is built from live variables — the
					// richest PII source in a trace.
					// exception.message 与 exception.stacktrace 就在这里，
					// 而异常消息是用运行时变量拼出来的——一条链路里最富含 PII 的地方。
					walkMap(ev.Attributes(), fn, telemetry.KindEvent, "")
				}

				links := span.Links()
				for l := range links.Len() {
					walkMap(links.At(l).Attributes(), fn, telemetry.KindAttribute, "")
				}
			}
		}
	}
	return nil
}

// logWalker exposes one ResourceLogs' redactable text, in place.
// 就地暴露单个 ResourceLogs 中可脱敏的文本。
type logWalker struct{ rl plog.ResourceLogs }

// Walk implements telemetry.Walker.
func (w logWalker) Walk(fn func(telemetry.Field) (string, bool)) error {
	{
		rl := w.rl
		walkMap(rl.Resource().Attributes(), fn, telemetry.KindAttribute, "")

		sls := rl.ScopeLogs()
		for j := range sls.Len() {
			sl := sls.At(j)
			walkMap(sl.Scope().Attributes(), fn, telemetry.KindAttribute, "")

			recs := sl.LogRecords()
			for k := range recs.Len() {
				rec := recs.At(k)
				// The body is the free-text field, and the one most likely to
				// hold a raw prompt.
				// 正文是自由文本字段，也是最可能装着原始提示词的那个。
				walkValue(rec.Body(), fn, telemetry.KindBody, "body")
				walkMap(rec.Attributes(), fn, telemetry.KindAttribute, "")
			}
		}
	}
	return nil
}

// metricWalker exposes one ResourceMetrics' redactable labels, in place.
// 就地暴露单个 ResourceMetrics 中可脱敏的标签。
type metricWalker struct{ rm pmetric.ResourceMetrics }

// Walk implements telemetry.Walker.
//
// Only data-point attributes are visited. A metric's name and description are
// written by whoever instrumented the code and are constant per call site, so
// they are not user data; the labels are.
// 只访问数据点属性。指标的名称与描述由写埋点的人书写、在每个调用点上是常量，
// 因此不是用户数据；标签才是。
func (w metricWalker) Walk(fn func(telemetry.Field) (string, bool)) error {
	{
		rm := w.rm
		walkMap(rm.Resource().Attributes(), fn, telemetry.KindMetricLabel, "")

		sms := rm.ScopeMetrics()
		for j := range sms.Len() {
			sm := sms.At(j)
			walkMap(sm.Scope().Attributes(), fn, telemetry.KindMetricLabel, "")

			metrics := sm.Metrics()
			for k := range metrics.Len() {
				walkMetricPoints(metrics.At(k), fn)
			}
		}
	}
	return nil
}

// walkMetricPoints visits every data point's attributes regardless of type.
// 无论指标类型，访问每个数据点的属性。
//
// All six aggregations are handled explicitly. A switch that forgets one leaves
// that metric type's labels forwarded verbatim, and nothing reports it.
// 六种聚合全部显式处理。漏掉任何一种，都会让那个指标类型的标签原样转发，
// 而且没有任何东西会报告这件事。
func walkMetricPoints(m pmetric.Metric, fn func(telemetry.Field) (string, bool)) {
	switch m.Type() {
	case pmetric.MetricTypeGauge:
		dps := m.Gauge().DataPoints()
		for i := range dps.Len() {
			walkNumberPoint(dps.At(i), fn)
		}
	case pmetric.MetricTypeSum:
		dps := m.Sum().DataPoints()
		for i := range dps.Len() {
			walkNumberPoint(dps.At(i), fn)
		}
	case pmetric.MetricTypeHistogram:
		dps := m.Histogram().DataPoints()
		for i := range dps.Len() {
			dp := dps.At(i)
			walkMap(dp.Attributes(), fn, telemetry.KindMetricLabel, "")
			walkExemplars(dp.Exemplars(), fn)
		}
	case pmetric.MetricTypeExponentialHistogram:
		dps := m.ExponentialHistogram().DataPoints()
		for i := range dps.Len() {
			dp := dps.At(i)
			walkMap(dp.Attributes(), fn, telemetry.KindMetricLabel, "")
			walkExemplars(dp.Exemplars(), fn)
		}
	case pmetric.MetricTypeSummary:
		dps := m.Summary().DataPoints()
		for i := range dps.Len() {
			walkMap(dps.At(i).Attributes(), fn, telemetry.KindMetricLabel, "")
		}
	case pmetric.MetricTypeEmpty:
	}
}

// walkNumberPoint visits a numeric data point.
// 访问一个数值型数据点。
func walkNumberPoint(dp pmetric.NumberDataPoint, fn func(telemetry.Field) (string, bool)) {
	walkMap(dp.Attributes(), fn, telemetry.KindMetricLabel, "")
	walkExemplars(dp.Exemplars(), fn)
}

// walkExemplars visits exemplar attributes.
// 访问 exemplar 的属性。
//
// Exemplars are the bridge from a metric back to a trace, and they carry
// filtered attributes of their own — a path by which a value redacted in the
// trace reappears attached to the metric.
// exemplar 是从指标回到链路的桥梁，且自带一份过滤后的属性——
// 一条「在链路里被脱敏掉的值，又挂在指标上重新出现」的路径。
func walkExemplars(exs pmetric.ExemplarSlice, fn func(telemetry.Field) (string, bool)) {
	for i := range exs.Len() {
		walkMap(exs.At(i).FilteredAttributes(), fn, telemetry.KindMetricLabel, "")
	}
}

// walkMap visits every string value in an attribute map, recursing through
// nested maps and slices.
// 访问属性表中的每一个字符串值，并递归穿过嵌套的表与切片。
func walkMap(m pcommon.Map, fn func(telemetry.Field) (string, bool),
	kind telemetry.FieldKind, prefix string) {
	m.Range(func(k string, v pcommon.Value) bool {
		walkValue(v, fn, kind, joinKey(prefix, k))
		return true
	})
}

// walkValue visits one attribute value.
// 访问一个属性值。
//
// Nested values are where structured logging puts the interesting fields: a
// single "http.request" attribute is routinely a map holding headers, a body
// and a user object. A walker that only looks at the top level would report a
// clean scan on exactly the payloads worth scanning.
// 嵌套值正是结构化日志放置有价值字段的地方：
// 一个 "http.request" 属性通常是一个装着请求头、请求体和用户对象的表。
// 只看顶层的遍历器，会在恰恰最值得扫描的那些载荷上报告「干净」。
func walkValue(v pcommon.Value, fn func(telemetry.Field) (string, bool),
	kind telemetry.FieldKind, key string) {
	switch v.Type() {
	case pcommon.ValueTypeStr:
		if next, changed := fn(telemetry.Field{Kind: kind, Key: key, Value: v.Str()}); changed {
			v.SetStr(next)
		}
	case pcommon.ValueTypeMap:
		walkMap(v.Map(), fn, kind, key)
	case pcommon.ValueTypeSlice:
		s := v.Slice()
		for i := range s.Len() {
			walkValue(s.At(i), fn, kind, key)
		}
	default:
		// Numbers, booleans and byte slices are not text a human wrote, and a
		// redacted rewrite would corrupt what they encode.
		// 数字、布尔与字节串不是人写的文本，改写会破坏它们编码的东西。
	}
}

// joinKey renders a nested attribute path.
// 渲染嵌套属性路径。
func joinKey(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}
