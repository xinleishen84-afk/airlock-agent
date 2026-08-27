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

// TestToolArgStreamNotContaminatedByBody 证明正文流不会污染工具入参流。
// Proves the message-body stream cannot contaminate the tool-argument stream.
//
// # 这条测试对应一次真实事故，且只有 agent 流量能触发
// # A real incident, reachable only by agent traffic
//
// 滞留缓冲曾按「帧内第几个可复原字段」做键。纯聊天流式里每帧只有
// delta.content，永远是第 0 个，这个键工作得很好。但 agent 流式各帧
// 携带的字段集合是变的：某帧只有 delta.content，下一帧只有
// delta.tool_calls[0].function.arguments，两者都是第 0 个，共用了缓冲。
//
// 实测三重后果，且三处都不报错：
//   - 正文压住的占位符前缀被拼到工具入参前面
//   - 整段入参被判为疑似占位符继续滞留，下游工具收到空参数
//   - 入参 JSON 随 Flush 作为正文增量帧吐给了用户
//
// The hold-back buffer was keyed by ordinal position within the frame. In plain
// chat streaming every frame carries only delta.content, always position zero,
// and the key works. Agent frames carry varying field subsets, so the body and
// a tool call's arguments were each position zero and shared one buffer.
//
// Measured, all three silent: the body's held-back prefix was prepended to the
// arguments; the whole argument was then held as a suspected placeholder so the
// tool received empty arguments; and the argument JSON was emitted to the user
// as a content delta on Flush.
func TestToolArgStreamNotContaminatedByBody(t *testing.T) {
	restorer := toolStreamFixture(t, "李小娜")

	// 正文末尾故意留下会被滞留缓冲压住的占位符前缀
	body := restorer.Frame(t.Context(),
		[]byte(`{"choices":[{"delta":{"content":"稍等，我查一下 ANONYMIZED_NA"}}]}`))
	if !json.Valid(body) {
		t.Fatalf("正文帧非法 JSON: %s", body)
	}

	args := restorer.Frame(t.Context(),
		[]byte(`{"choices":[{"delta":{"tool_calls":[{"index":0,`+
			`"function":{"arguments":"{\"q\":\"beijing\"}"}}]}}]}`))
	if got := frameArgs(t, args, 0); got != `{"q":"beijing"}` {
		t.Errorf("工具入参被正文流污染：want %q, got %q——"+
			"下游工具会收到错误或空的参数", `{"q":"beijing"}`, got)
	}

	tail, err := restorer.Flush(t.Context())
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if strings.Contains(tail, `"q"`) {
		t.Errorf("工具入参泄漏进了正文增量帧：%q——用户会看到本该发给工具的 JSON", tail)
	}
}

// TestParallelToolCallsKeepSeparateBuffers 证明并行工具调用各用各的滞留缓冲。
// Proves parallel tool calls keep separate hold-back buffers.
//
// agent 一帧里发多个工具调用是常态。若它们共用缓冲，A 调用压住的占位符
// 前半截会被拼进 B 调用的入参——两个工具都收到错的参数，且都不报错。
// 结构路径把数组下标包含在内，tool_calls.0 与 tool_calls.1 因此天然分开。
//
// Agents routinely emit several tool calls in one frame. Sharing a buffer would
// splice call A's held-back placeholder half into call B's arguments — both
// tools get wrong input, neither errors. Structural paths include the array
// index, so tool_calls.0 and tool_calls.1 separate naturally.
func TestParallelToolCallsKeepSeparateBuffers(t *testing.T) {
	restorer := toolStreamFixture(t, "李小娜")

	// 首帧两个调用都在，且第 1 个的入参在占位符中间被切断
	f1 := restorer.Frame(t.Context(), []byte(`{"choices":[{"delta":{"tool_calls":[`+
		`{"index":0,"function":{"arguments":"{\"city\":\"beijing\"}"}},`+
		`{"index":1,"function":{"arguments":"{\"who\":\"ANONYMIZED_NA"}}]}}]}`))
	if got := frameArgs(t, f1, 0); got != `{"city":"beijing"}` {
		t.Errorf("并行调用互相污染：调用 0 的入参 want %q, got %q",
			`{"city":"beijing"}`, got)
	}

	// 后续帧只带第 1 个调用的尾巴——OpenAI 流式的常见形状，
	// 每个 delta 只携带发生变化的那个 index。
	// 按序号做键时这一帧的唯一字段会落到「帧内第 0 个」，
	// 也就是调用 0 的缓冲上，两股流就此错位。
	f2 := restorer.Frame(t.Context(), []byte(`{"choices":[{"delta":{"tool_calls":[`+
		`{"index":1,"function":{"arguments":"ME_0\"}"}}]}}]}`))

	var assembled strings.Builder
	assembled.WriteString(frameArgs(t, f1, 1))
	assembled.WriteString(frameArgs(t, f2, 0))
	tail, err := restorer.Flush(t.Context())
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	assembled.WriteString(tail)
	if !strings.Contains(assembled.String(), "李小娜") {
		t.Errorf("工具入参里跨帧切分的占位符未复原，拼接结果: %q——"+
			"工具会收到字面量占位符而不是真值", assembled.String())
	}
}
