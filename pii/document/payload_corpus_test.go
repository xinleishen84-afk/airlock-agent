package document

import (
	"encoding/json"
	"strings"
	"testing"
)

// payloadShape 是一种真实存在的请求/响应载荷形态。
type payloadShape struct {
	name string
	json string
}

// requestShapes 枚举本网关声称能处理的全部请求形态。
// Every request shape this gateway claims to handle.
//
// # 为什么必须是一份可枚举的语料，而不是逐条路径的单测
// # Why an enumerable corpus rather than per-rule unit tests
//
// 严格白名单对**污染**是安全的：没列到的字段物理上不会被访问，协议骨架
// 因此不可能被脱敏结果破坏。但它对**泄露**是失效开放的：没列到的字段
// 同样不会被脱敏，不报错、不告警，看起来和「这段文本里没有 PII」一样。
// 两个失效方向相反，而白名单的设计文档只讲了前一个。
//
// 实测代价：这张表原本七条，覆盖 OpenAI Chat Completions。而同一张表里
// 有两条标着「Anthropic 风格」，也就是那个形态是声称支持的——它的
// tool_use / tool_result 内容块却一条都不在表里。结果是工具的**输出**
// （agent 循环里就是数据库查出来的整行客户记录）原样发给了模型。
// 同批漏掉的还有旧版 function_call、Responses API、embeddings、
// 顶层 prompt、Anthropic 的 system 块数组。
//
// 逐条路径写单测只能证明「已列出的路径有效」，永远证明不了「该列的都列了」。
// 因此把形态本身做成语料：新增一种支持的形态，就在这里加一行。
//
// A strict allowlist is safe against corruption — unlisted fields are never
// touched, so redaction can never break the protocol skeleton. It fails open
// for leakage — unlisted fields are never redacted either, with no error and no
// warning, indistinguishable from "this text held no PII". The two failure
// directions are opposite and the design only ever documented the first.
//
// Measured cost: seven rules covering OpenAI Chat Completions, in a table two of
// whose entries were labelled "Anthropic style" — yet neither Anthropic content
// block was listed, so tool output (a row of customer records, in an agent loop)
// went to the model verbatim.
//
// Per-rule unit tests can only show that listed paths work; they can never show
// that everything that should be listed is. So the shapes themselves are the
// corpus: supporting a new one means adding a line here.
var requestShapes = []payloadShape{
	{"OpenAI 消息正文（字符串）", `{"messages":[{"role":"user","content":"SECRET"}]}`},
	{"OpenAI 消息正文（内容块）", `{"messages":[{"role":"user","content":[{"type":"text","text":"SECRET"}]}]}`},
	{"OpenAI 工具入参", `{"messages":[{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"k\":\"SECRET\"}"}}]}]}`},
	{"OpenAI 工具返回消息", `{"messages":[{"role":"tool","tool_call_id":"c1","content":"SECRET"}]}`},
	{"OpenAI 旧版 function_call", `{"messages":[{"role":"assistant","function_call":{"name":"f","arguments":"{\"k\":\"SECRET\"}"}}]}`},
	{"OpenAI 工具描述", `{"tools":[{"type":"function","function":{"name":"f","description":"例如 SECRET"}}]}`},
	{"OpenAI 工具参数 schema 描述", `{"tools":[{"function":{"name":"f","parameters":{"properties":{"a":{"description":"如 SECRET"}}}}}]}`},
	{"OpenAI 顶层 prompt", `{"prompt":"SECRET"}`},
	{"Responses API 输入块", `{"input":[{"role":"user","content":[{"type":"input_text","text":"SECRET"}]}]}`},
	{"embeddings 输入（字符串）", `{"input":"SECRET","model":"m"}`},
	{"embeddings 输入（数组）", `{"input":["SECRET"],"model":"m"}`},
	{"Anthropic 系统提示词（字符串）", `{"system":"SECRET"}`},
	{"Anthropic 系统提示词（块数组）", `{"system":[{"type":"text","text":"SECRET"}]}`},
	{"Anthropic 工具描述", `{"tools":[{"name":"f","description":"例如 SECRET"}]}`},
	{"Anthropic tool_use 入参", `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"tu1","name":"f","input":{"k":"SECRET"}}]}]}`},
	{"Anthropic tool_result（字符串）", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu1","content":"SECRET"}]}]}`},
	{"Anthropic tool_result（块数组）", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu1","content":[{"type":"text","text":"SECRET"}]}]}]}`},
}

// responseShapes 枚举全部响应形态。漏掉一种的后果不是泄露而是占位符
// 还原不回来——用户直接在答案里看到 ANONYMIZED_NAME_0。
//
// Missing a response shape does not leak; it leaves placeholders unrestored, so
// the user reads ANONYMIZED_NAME_0 in the answer.
//
// 流式工具入参（OpenAI 的 delta.tool_calls[].function.arguments、Anthropic 的
// delta.partial_json）刻意不在这里：它们是不完整的 JSON 分片，由
// StreamRestorer 的屏障处理，见 toolstream_test.go。
var responseShapes = []payloadShape{
	{"OpenAI 流式正文", `{"choices":[{"delta":{"content":"SECRET"}}]}`},
	{"OpenAI 流式思考过程", `{"choices":[{"delta":{"reasoning_content":"SECRET"}}]}`},
	{"OpenAI 非流式正文", `{"choices":[{"message":{"content":"SECRET"}}]}`},
	{"OpenAI 非流式工具入参", `{"choices":[{"message":{"tool_calls":[{"function":{"arguments":"{\"k\":\"SECRET\"}"}}]}}]}`},
	{"OpenAI 旧版非流式 function_call", `{"choices":[{"message":{"function_call":{"arguments":"{\"k\":\"SECRET\"}"}}}]}`},
	{"Responses API 输出块", `{"output":[{"content":[{"type":"output_text","text":"SECRET"}]}]}`},
	{"Anthropic 流式正文", `{"delta":{"text":"SECRET"}}`},
	{"Anthropic content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":"SECRET"}}`},
	{"Anthropic 非流式正文块", `{"content":[{"type":"text","text":"SECRET"}]}`},
	{"Anthropic 非流式 tool_use 入参", `{"content":[{"type":"tool_use","name":"f","input":{"k":"SECRET"}}]}`},
}

// TestEveryRequestShapeIsSanitized 保证每一种声称支持的请求形态都被脱敏。
func TestEveryRequestShapeIsSanitized(t *testing.T) {
	for _, sh := range requestShapes {
		t.Run(sh.name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal([]byte(sh.json), &doc); err != nil {
				t.Fatalf("语料非法 JSON: %v", err)
			}
			if err := SanitizeDocument(doc, markAll); err != nil {
				t.Fatalf("清洗失败: %v", err)
			}
			out, err := MarshalPreserving(doc)
			if err != nil {
				t.Fatalf("序列化失败: %v", err)
			}
			if strings.Contains(string(out), "SECRET") {
				t.Errorf("该形态未被脱敏，PII 会原样发给模型：\n%s", out)
			}
		})
	}
}

// TestEveryResponseShapeIsRestored 保证每一种响应形态都能复原占位符。
func TestEveryResponseShapeIsRestored(t *testing.T) {
	for _, sh := range responseShapes {
		t.Run(sh.name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal([]byte(sh.json), &doc); err != nil {
				t.Fatalf("语料非法 JSON: %v", err)
			}
			err := RestoreDocument(doc, func(_, s string) (string, error) {
				return strings.ReplaceAll(s, "SECRET", "真值"), nil
			})
			if err != nil {
				t.Fatalf("复原失败: %v", err)
			}
			out, _ := MarshalPreserving(doc)
			if strings.Contains(string(out), "SECRET") {
				t.Errorf("该形态未被复原，用户会在答案里看到占位符：\n%s", out)
			}
		})
	}
}

// TestSkeletonSurvivesEveryRequestShape 保证脱敏不会破坏协议骨架。
// Proves sanitization never damages the protocol skeleton.
//
// 白名单的另一半承诺：id、名称、类型、参数键这些字段被脱敏之后，
// 工具结果配不上调用、模型认不出参数名，链路会以难以归因的方式坏掉。
func TestSkeletonSurvivesEveryRequestShape(t *testing.T) {
	// 每种形态里必须原样保留的协议骨架片段
	skeleton := []string{`"role"`, `"type"`, `"name"`, `"tool_call_id"`,
		`"tool_use_id"`, `"id"`, `"model"`}
	for _, sh := range requestShapes {
		t.Run(sh.name, func(t *testing.T) {
			var doc map[string]any
			json.Unmarshal([]byte(sh.json), &doc)
			if err := SanitizeDocument(doc, markAll); err != nil {
				t.Fatalf("清洗失败: %v", err)
			}
			out, _ := MarshalPreserving(doc)
			for _, k := range skeleton {
				if strings.Contains(sh.json, k) && !strings.Contains(string(out), k) {
					t.Errorf("协议骨架字段 %s 被脱敏破坏：\n%s", k, out)
				}
			}
			// 值也要在：工具名、id 这些是骨架内容而非自然语言
			for _, v := range []string{`"c1"`, `"tu1"`, `"f"`, `"m"`} {
				if strings.Contains(sh.json, v) && !strings.Contains(string(out), v) {
					t.Errorf("协议骨架取值 %s 被脱敏破坏：\n%s", v, out)
				}
			}
		})
	}
}
