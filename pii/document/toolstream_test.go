package document

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// toolStreamFixture 造一个登记好占位符的复原器。
func toolStreamFixture(t *testing.T, names ...string) *StreamRestorer {
	t.Helper()
	gaz, err := detect.NewGazetteerDetector(
		map[detect.EntityType][]string{detect.TypeName: names}, false, 2)
	if err != nil {
		t.Fatalf("构造名册: %v", err)
	}
	r := anonymize.NewRedactor(detect.NewCompositeDetector([]detect.Detector{gaz}, 0), true)
	reg := anonymize.NewVaultRegistry(time.Hour, 10)
	vault, err := reg.Get(docSessionRef("s"))
	if err != nil {
		t.Fatalf("取保险库: %v", err)
	}
	for _, n := range names {
		if _, err := r.Redact(t.Context(), "联系"+n, docScope(vault)); err != nil {
			t.Fatalf("登记占位符: %v", err)
		}
	}
	return NewStreamRestorer(r, anonymize.StrategyScope{Tenant: docTenant, Vault: vault})
}

// only 断言只返回一帧并取出它。屏障放行时会多返回一帧，
// 用 frames 直接取全部。
func only(t *testing.T, fs [][]byte) []byte {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("期望恰好一帧，实得 %d 帧", len(fs))
	}
	return fs[0]
}

// frameArgs 取出某个工具调用的入参片段。
func frameArgs(t *testing.T, raw []byte, call int) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("输出帧非法 JSON: %s (%v)", raw, err)
	}
	v := dig(t, doc, "choices", 0, "delta", "tool_calls", call, "function", "arguments")
	s, _ := v.(string)
	return s
}

// TestToolArgsWithheldUntilBarrierReleases 证明工具入参在屏障放行前不外泄，
// 放行时一次性给出完整且合法的 JSON。
// Proves tool arguments are withheld until the barrier releases, then emitted
// complete and as valid JSON.
//
// # 屏障解决的是正确性，不是泄露
// # The barrier is a correctness control, not a leak control
//
// 攒着不发并不会让工具「拿不到 PII」——放行时照样给真值。它消灭的是
// 「在半截 JSON 文本上做替换」这一整类故障。逐帧复原时实测三种，全部静默：
//
//   - 真值含引号 -> {"who":"李"小"娜"}，下游工具解析器罢工
//   - 占位符跨帧劈开 -> 两半落进不同缓冲，工具收到字面量 "ME_0"
//   - 流末尾残留 -> 被当作 delta.content 发给用户，工具收到截断的 JSON
//
// Buffering does not keep PII from the tool — the real value is handed over on
// release all the same. What it removes is the class of failures caused by
// substituting text inside half a JSON document.
func TestToolArgsWithheldUntilBarrierReleases(t *testing.T) {
	restorer := toolStreamFixture(t, `李"小"娜`) // 真值含引号：文本替换必然毁掉 JSON

	// 正文帧，末尾留下会被滞留缓冲压住的占位符前缀
	body := only(t, restorer.Frame(t.Context(),
		[]byte(`{"choices":[{"index":0,"delta":{"content":"稍等 ANONYMIZED_NA"}}]}`)))
	if !json.Valid(body) {
		t.Fatalf("正文帧非法 JSON: %s", body)
	}

	// 同一帧里既有正文（补完上一帧被切断的占位符）又有入参分片——
	// 两股流共用缓冲时，这一帧就是它们互相污染的现场。
	// 屏障放行前不得吐出任何入参内容。
	f := only(t, restorer.Frame(t.Context(),
		[]byte(`{"choices":[{"index":0,"delta":{"content":"ME_0 好的",`+
			`"tool_calls":[{"index":0,"id":"call_1",`+
			`"function":{"name":"lookup","arguments":"{\"who\":\"ANONYMIZED_NAME_0"}}]}}]}`)))
	if got := frameArgs(t, f, 0); got != "" {
		t.Errorf("屏障放行前吐出了入参片段: %q", got)
	}
	var bodyProbe map[string]any
	_ = json.Unmarshal(f, &bodyProbe)
	if c := dig(t, bodyProbe, "choices", 0, "delta", "content"); c != `李"小"娜 好的` {
		t.Errorf("正文流被工具入参污染或未复原: %v", c)
	}

	// finish_reason 到达 -> 放行，补发一帧
	frames := restorer.Frame(t.Context(),
		[]byte(`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,`+
			`"function":{"arguments":"\"}"}}]},"finish_reason":"tool_calls"}]}`))
	if len(frames) != 2 {
		t.Fatalf("期望原帧＋放行帧共 2 帧，实得 %d", len(frames))
	}
	args := frameArgs(t, frames[1], 0)

	var parsed map[string]any
	if err := json.Unmarshal([]byte(args), &parsed); err != nil {
		t.Fatalf("放行的入参不是合法 JSON: %s (%v)——下游工具解析器会罢工", args, err)
	}
	if parsed["who"] != `李"小"娜` {
		t.Errorf("入参未复原为真值: %v", parsed["who"])
	}

	// 放行帧必须带回 index/id/name，客户端靠它们把调用归位
	var probe map[string]any
	_ = json.Unmarshal(frames[1], &probe)
	call := dig(t, probe, "choices", 0, "delta", "tool_calls", 0)
	cm, _ := call.(map[string]any)
	if cm["id"] != "call_1" {
		t.Errorf("放行帧丢了 tool call id: %v", cm["id"])
	}
	if fn, ok := cm["function"].(map[string]any); !ok || fn["name"] != "lookup" {
		t.Errorf("放行帧丢了函数名: %v", cm["function"])
	}

	tail, err := restorer.Flush(t.Context())
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if strings.Contains(tail, `"who"`) || strings.Contains(tail, "ANONYMIZED") {
		t.Errorf("工具入参或占位符残留漏进了正文增量帧: %q", tail)
	}
}

// TestParallelToolCallsKeepSeparateBuffers 证明并行工具调用各攒各的。
// Proves parallel tool calls accumulate independently.
//
// agent 一帧里发多个工具调用是常态，且后续 delta 只携带发生变化的那个
// index——「第 1 个调用」在某帧里可能是数组第 0 个元素。按数组位置分流
// 会让两股入参错位：实测占位符的两半被分进不同缓冲，永远拼不回来，
// 工具收到字面量 "ME_0"。身份必须取协议的 index 字段。
//
// Agents routinely emit several tool calls, and later deltas carry only the
// changed index — so "call 1" can be array element 0 in a given frame. Keying
// by array position misaligns the streams: measured, a placeholder's two halves
// landed in different buffers and the tool received the literal "ME_0".
func TestParallelToolCallsKeepSeparateBuffers(t *testing.T) {
	restorer := toolStreamFixture(t, "李小娜")

	restorer.Frame(t.Context(), []byte(`{"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"arguments":"{\"city\":\"beijing\"}"}},`+
		`{"index":1,"function":{"arguments":"{\"who\":\"ANONYMIZED_NA"}}]}}]}`))

	// 后续帧只带第 1 个调用的尾巴——数组位置是 0，协议 index 是 1
	frames := restorer.Frame(t.Context(), []byte(`{"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":1,"function":{"arguments":"ME_0\"}"}}]},"finish_reason":"tool_calls"}]}`))
	if len(frames) != 2 {
		t.Fatalf("期望放行帧，实得 %d 帧", len(frames))
	}

	var probe map[string]any
	if err := json.Unmarshal(frames[1], &probe); err != nil {
		t.Fatalf("放行帧非法 JSON: %s", frames[1])
	}
	calls, _ := dig(t, probe, "choices", 0, "delta", "tool_calls").([]any)
	if len(calls) != 2 {
		t.Fatalf("期望放行 2 个调用，实得 %d", len(calls))
	}
	got := map[float64]string{}
	for _, c := range calls {
		cm := c.(map[string]any)
		fn := cm["function"].(map[string]any)
		got[cm["index"].(float64)] = fn["arguments"].(string)
	}
	if got[0] != `{"city":"beijing"}` {
		t.Errorf("调用 0 的入参被污染: %q", got[0])
	}
	var p1 map[string]any
	if err := json.Unmarshal([]byte(got[1]), &p1); err != nil {
		t.Fatalf("调用 1 的入参非法 JSON: %s", got[1])
	}
	if p1["who"] != "李小娜" {
		t.Errorf("跨帧切分的占位符未复原: %v——工具会收到字面量占位符", p1["who"])
	}
}

// TestToolCallsReleasedWhenStreamEndsAbruptly 证明上游没吐 finish_reason
// 就结束时，屏障里的工具调用仍会发出。
// Proves buffered tool calls are still emitted when the stream ends without a
// finish_reason.
//
// 截断与断连是常态。屏障吞掉未放行的调用会让客户端永远等一个不会到来的
// 工具调用——比发出半截入参更糟，因为前者没有超时之外的任何信号。
//
// Truncation and disconnects are routine. Swallowing an unreleased call leaves
// the client waiting forever, which is worse than emitting a truncated payload:
// the client gets no signal at all beyond its own timeout.
func TestToolCallsReleasedWhenStreamEndsAbruptly(t *testing.T) {
	restorer := toolStreamFixture(t, "李小娜")
	restorer.Frame(t.Context(), []byte(`{"choices":[{"index":0,"delta":{"tool_calls":[`+
		`{"index":0,"function":{"arguments":"{\"who\":\"ANONYMIZED_NAME_0\"}"}}]}}]}`))

	frame := restorer.FlushToolCalls(t.Context())
	if frame == nil {
		t.Fatal("流突然结束时屏障吞掉了工具调用——客户端会永远等下去")
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(frameArgs(t, frame, 0)), &parsed); err != nil {
		t.Fatalf("补发的入参非法 JSON: %v", err)
	}
	if parsed["who"] != "李小娜" {
		t.Errorf("补发的入参未复原: %v", parsed["who"])
	}
}
