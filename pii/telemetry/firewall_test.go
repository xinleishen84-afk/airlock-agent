package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
)

const testTenant anonymize.Tenant = "acme"

func testDetector(t *testing.T) detect.Detector {
	t.Helper()
	gaz, err := detect.NewGazetteerDetector(map[detect.EntityType][]string{
		detect.TypeName: {"张伟", "李娜"},
	}, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	return detect.NewCompositeDetector(
		[]detect.Detector{packs.MustNewRegistry([]string{"GEN", "CN"}), gaz}, 0)
}

func hashFlow(t *testing.T) anonymize.Flow {
	t.Helper()
	ring, err := anonymize.NewKeyring([]byte("0123456789abcdef-0123456789abcdef"), nil)
	if err != nil {
		t.Fatal(err)
	}
	h, err := anonymize.NewHash(ring, 8)
	if err != nil {
		t.Fatal(err)
	}
	return anonymize.Flow{Name: "telemetry", Default: h}
}

func newFirewall(t *testing.T) *Firewall {
	t.Helper()
	f, err := New(testDetector(t), hashFlow(t), Policy{})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// ---------------------------------------------------------------------------
// 构造期拒绝 / Construction-time refusals
// ---------------------------------------------------------------------------

// 遥测链路用 mask 会让会话保险库随流量增长，且指标基数炸弹原样存活。
// mask on a telemetry flow grows the vault with traffic and leaves the metric
// cardinality bomb intact.
func TestTelemetryRefusesMaskOperator(t *testing.T) {
	_, err := New(testDetector(t),
		anonymize.Flow{Name: "telemetry", Default: anonymize.NewMask()}, Policy{})
	if err == nil {
		t.Fatal("遥测链路用 mask 应被拒绝")
	}
	if !strings.Contains(err.Error(), "hash") {
		t.Fatalf("报错应给出替代方案：%v", err)
	}
	t.Logf("按预期拒绝：%v", err)

	// 单个类型上的 mask 同样要拒绝
	_, err = New(testDetector(t), anonymize.Flow{
		Name: "telemetry", Default: anonymize.NewDrop(),
		ByType: map[detect.EntityType]anonymize.Strategy{
			detect.TypeName: anonymize.NewMask(),
		},
	}, Policy{})
	if err == nil {
		t.Fatal("单个类型上的 mask 同样应被拒绝")
	}
}

// 遥测是单向的，声明 restores 只会让配置读起来像存在一条并不存在的回程。
// Telemetry is one-way; declaring restores describes a return path that does
// not exist.
func TestTelemetryRefusesRestoringFlow(t *testing.T) {
	flow := hashFlow(t)
	flow.Restores = true
	if _, err := New(testDetector(t), flow, Policy{}); err == nil {
		t.Fatal("声明 restores 的遥测链路应被拒绝")
	}
}

// ---------------------------------------------------------------------------
// OTLP 遍历 / OTLP walking
// ---------------------------------------------------------------------------

// 一份真实形态的 trace：PII 藏在 span 名、属性、异常事件和状态消息里。
// A realistic trace with PII in the span name, attributes, exception event and
// status message.
const traceJSON = `{
  "resourceSpans": [{
    "resource": {"attributes": [
      {"key": "service.name", "value": {"stringValue": "checkout"}},
      {"key": "deployment.owner", "value": {"stringValue": "张伟 <zhang.wei@example.com>"}}
    ]},
    "scopeSpans": [{
      "spans": [{
        "traceId": "5b8aa5a2d2c872e8321cf37308d69df2",
        "spanId": "051581bf3cb55c13",
        "parentSpanId": "eee19b7ec3c1b174",
        "name": "GET /api/users/13812345678/orders",
        "attributes": [
          {"key": "http.status_code", "value": {"intValue": 500}},
          {"key": "http.url", "value": {"stringValue": "https://x.io/u?phone=13812345678"}},
          {"key": "enduser.id", "value": {"stringValue": "zhang.wei@example.com"}},
          {"key": "db.statement", "value": {"stringValue": "SELECT * FROM u WHERE id='11010519491231002X'"}}
        ],
        "status": {"code": 2, "message": "支付失败：卡号 4111 1111 1111 1111 被拒"},
        "events": [{
          "name": "exception",
          "attributes": [
            {"key": "exception.type", "value": {"stringValue": "ValidationError"}},
            {"key": "exception.message", "value": {"stringValue": "无效手机号 13812345678 (用户 李娜)"}}
          ]
        }]
      }]
    }]
  }]
}`

func TestTraceRedaction(t *testing.T) {
	f := newFirewall(t)
	out, stats, err := RedactOTLPJSON(t.Context(), f, testTenant, []byte(traceJSON))
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)

	// 每一处 PII 都不得残留
	for _, leaked := range []string{
		"13812345678", "zhang.wei@example.com", "11010519491231002X",
		"4111 1111 1111 1111", "李娜", "张伟",
	} {
		if strings.Contains(text, leaked) {
			t.Errorf("遥测中残留了 %q", leaked)
		}
	}

	// 链路标识必须原样保留，否则脱敏掉的是可观测性而不是 PII
	for _, keep := range []string{
		"5b8aa5a2d2c872e8321cf37308d69df2", "051581bf3cb55c13", "eee19b7ec3c1b174",
		"checkout", "ValidationError",
	} {
		if !strings.Contains(text, keep) {
			t.Errorf("不该被改写的 %q 丢失了", keep)
		}
	}

	t.Logf("扫描 %d 个字段，改写 %d 个，实体 %v",
		stats.FieldsScanned, stats.FieldsRedacted, stats.EntityCounts)
	if stats.FieldsRedacted < 5 {
		t.Errorf("改写字段数偏少：%d", stats.FieldsRedacted)
	}

	var probe map[string]any
	if err := json.Unmarshal(out, &probe); err != nil {
		t.Fatalf("输出不是合法 JSON：%v", err)
	}
}

// snake_case 与 camelCase 都是合法 OTLP/JSON，只认一种会在一半流量上静默失效。
// Both spellings are legal OTLP/JSON; handling one silently no-ops on half the
// traffic.
func TestSnakeCaseFieldNamesAreWalked(t *testing.T) {
	const snake = `{
      "resource_spans": [{
        "scope_spans": [{
          "spans": [{
            "name": "GET /u/13812345678",
            "attributes": [
              {"key": "enduser.id", "value": {"string_value": "zhang.wei@example.com"}}
            ]
          }]
        }]
      }]
    }`
	f := newFirewall(t)
	out, stats, err := RedactOTLPJSON(t.Context(), f, testTenant, []byte(snake))
	if err != nil {
		t.Fatal(err)
	}
	if stats.FieldsRedacted == 0 {
		t.Fatal("snake_case 载荷上一个字段都没改写")
	}
	if strings.Contains(string(out), "zhang.wei@example.com") ||
		strings.Contains(string(out), "13812345678") {
		t.Fatalf("snake_case 载荷未被脱敏：%s", out)
	}
	t.Logf("改写 %d 个字段", stats.FieldsRedacted)
}

// 结构化日志把有价值的字段放在嵌套值里，只看 stringValue 会在这些载荷上报告干净。
// Structured logging nests the interesting fields; a stringValue-only walker
// reports a clean scan on exactly those payloads.
func TestNestedAnyValuesAreWalked(t *testing.T) {
	const nested = `{
      "resourceLogs": [{
        "scopeLogs": [{
          "logRecords": [{
            "body": {"stringValue": "用户提交：手机 13812345678"},
            "attributes": [
              {"key": "http.request", "value": {"kvlistValue": {"values": [
                {"key": "headers", "value": {"kvlistValue": {"values": [
                  {"key": "x-user", "value": {"stringValue": "zhang.wei@example.com"}}
                ]}}},
                {"key": "tags", "value": {"arrayValue": {"values": [
                  {"stringValue": "vip"},
                  {"stringValue": "身份证 11010519491231002X"}
                ]}}}
              ]}}}
            ]
          }]
        }]
      }]
    }`
	f := newFirewall(t)
	out, stats, err := RedactOTLPJSON(t.Context(), f, testTenant, []byte(nested))
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"13812345678", "zhang.wei@example.com", "11010519491231002X"} {
		if strings.Contains(string(out), leaked) {
			t.Errorf("嵌套值里残留了 %q：%s", leaked, out)
		}
	}
	if !strings.Contains(string(out), "vip") {
		t.Error("非 PII 的数组项不应被改写")
	}
	t.Logf("改写 %d 个字段", stats.FieldsRedacted)
}

// 指标标签是基数所在。同一个手机号必须映射到同一个摘要，否则聚合就没了。
// Metric labels are where cardinality lives: the same phone must map to the
// same digest or aggregation is lost.
func TestMetricLabelsAreBoundedAndStable(t *testing.T) {
	const metrics = `{
      "resourceMetrics": [{
        "scopeMetrics": [{
          "metrics": [{
            "name": "orders.total",
            "sum": {"dataPoints": [
              {"attributes": [{"key": "user", "value": {"stringValue": "13812345678"}}]},
              {"attributes": [{"key": "user", "value": {"stringValue": "13812345678"}}]},
              {"attributes": [{"key": "user", "value": {"stringValue": "13900001111"}}]}
            ]}
          }]
        }]
      }]
    }`
	f := newFirewall(t)
	out, _, err := RedactOTLPJSON(t.Context(), f, testTenant, []byte(metrics))
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if strings.Contains(text, "13812345678") {
		t.Fatalf("指标标签未脱敏：%s", text)
	}
	if !strings.Contains(text, "orders.total") {
		t.Error("指标名不应被改写")
	}

	digests := extractDigests(text)
	if len(digests) != 3 {
		t.Fatalf("应得到 3 个标签值，实际 %d：%v", len(digests), digests)
	}
	if digests[0] != digests[1] {
		t.Errorf("同一个手机号应得到同一摘要，否则时间序列会分裂：%v", digests)
	}
	if digests[0] == digests[2] {
		t.Errorf("不同手机号不应塌缩成同一摘要：%v", digests)
	}
	t.Logf("标签摘要：%v", digests)
}

func extractDigests(text string) []string {
	var out []string
	for rest := text; ; {
		i := strings.Index(rest, "[hash:")
		if i < 0 {
			return out
		}
		j := strings.Index(rest[i:], "]")
		if j < 0 {
			return out
		}
		out = append(out, rest[i:i+j+1])
		rest = rest[i+j+1:]
	}
}

// collector 会重试，因此脱敏必须幂等：重跑一遍不得再次改写。
// The collector retries, so redaction must be idempotent.
func TestRedactionIsIdempotent(t *testing.T) {
	f := newFirewall(t)
	once, _, err := RedactOTLPJSON(t.Context(), f, testTenant, []byte(traceJSON))
	if err != nil {
		t.Fatal(err)
	}
	twice, stats, err := RedactOTLPJSON(t.Context(), f, testTenant, once)
	if err != nil {
		t.Fatal(err)
	}
	if stats.FieldsRedacted != 0 {
		t.Errorf("第二遍不应再改写任何字段，实际 %d", stats.FieldsRedacted)
	}
	if string(once) != string(twice) {
		t.Error("两次脱敏结果不一致，重试会产生不同的载荷")
	}
}

// 超长值被截断而非跳过：跳过等于把整段原样转发。
// Oversized values are truncated, not skipped: skipping forwards the whole
// thing unredacted.
func TestOversizedValueIsTruncatedNotSkipped(t *testing.T) {
	f, err := New(testDetector(t), hashFlow(t), Policy{MaxValueBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	huge := strings.Repeat("填充", 200) + " 手机 13812345678"
	payload, _ := json.Marshal(map[string]any{
		"resourceLogs": []any{map[string]any{
			"scopeLogs": []any{map[string]any{
				"logRecords": []any{map[string]any{
					"body": map[string]any{"stringValue": huge},
				}},
			}},
		}},
	})

	out, stats, err := RedactOTLPJSON(t.Context(), f, testTenant, payload)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Truncated != 1 {
		t.Errorf("应记录 1 次截断，实际 %d", stats.Truncated)
	}
	if strings.Contains(string(out), "13812345678") {
		t.Error("截断后的尾部把 PII 带了出去")
	}
	var probe map[string]any
	if err := json.Unmarshal(out, &probe); err != nil {
		t.Fatalf("截断产生了非法 UTF-8/JSON：%v", err)
	}
}

// 跳过清单只为吞吐存在，绝不能把携带客户数据的属性扫进去。
// The skip list exists for throughput and must not sweep in the attributes
// that carry customer data.
func TestSkipListExcludesDataCarryingKeys(t *testing.T) {
	skip := DefaultSkipKeys()
	for _, key := range []string{
		"http.url", "http.target", "db.statement", "http.request.body",
		"enduser.id", "messaging.destination", "exception.message",
	} {
		if skip[key] {
			t.Errorf("%q 携带客户数据，不该出现在跳过清单里", key)
		}
	}
	if !skip["http.status_code"] {
		t.Error("状态码这类枚举值应在跳过清单里")
	}
}

// 检测器故障必须让调用方丢弃载荷，而不是原样转发。
// A detector failure must make the caller drop the payload, not forward it.
func TestDetectorFailureBlocksTheSpan(t *testing.T) {
	f, err := New(brokenDetector{}, hashFlow(t), Policy{})
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := RedactOTLPJSON(t.Context(), f, testTenant, []byte(traceJSON))
	if err == nil {
		t.Fatal("检测器故障应返回错误")
	}
	if out != nil {
		t.Fatal("故障时不应返回可转发的载荷")
	}
	t.Logf("按预期阻断：%v", err)
}

type brokenDetector struct{}

func (brokenDetector) Name() string                      { return "broken" }
func (brokenDetector) CoveredTypes() []detect.EntityType { return nil }
func (brokenDetector) Detect(string) ([]detect.Entity, error) {
	return nil, errBroken{}
}

type errBroken struct{}

func (errBroken) Error() string { return "检测器不可用 / detector unavailable" }

// 每个 span 都要过这一层，因此它的耗时必须实测。
// Every span pays this, so the cost must be measured rather than asserted.
func BenchmarkTraceRedaction(b *testing.B) {
	gaz, _ := detect.NewGazetteerDetector(map[detect.EntityType][]string{
		detect.TypeName: {"张伟", "李娜"},
	}, false, 2)
	det := detect.NewCompositeDetector(
		[]detect.Detector{packs.MustNewRegistry([]string{"GEN", "CN"}), gaz}, 0)

	ring, _ := anonymize.NewKeyring([]byte("0123456789abcdef-0123456789abcdef"), nil)
	h, _ := anonymize.NewHash(ring, 8)
	f, err := New(det, anonymize.Flow{Name: "telemetry", Default: h}, Policy{})
	if err != nil {
		b.Fatal(err)
	}

	payload := []byte(traceJSON)
	ctx := b.Context()
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		if _, _, err := RedactOTLPJSON(ctx, f, testTenant, payload); err != nil {
			b.Fatal(err)
		}
	}
}

var _ = time.Second
