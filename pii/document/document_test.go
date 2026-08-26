package document

import (
	"encoding/json"
	"strings"
	"testing"
)

// markAll 是最坏情况的净化函数：把任何非空文本整体替换为占位符。
//
// 用它模拟 NER 的概率性输出「大杀四方」的极端情形。凡是被送进净化的
// 字段都会变成占位符，因此测试只需断言协议骨架字段**没变**，
// 就能证明它们物理上没被触碰。
func markAll(s string) (string, error) {
	if s == "" {
		return s, nil
	}
	return "REDACTED", nil
}

// sanitizeJSON 对一段 JSON 执行定向清洗并返回结果文档。
func sanitizeJSON(t *testing.T, raw string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if err := SanitizeDocument(doc, markAll); err != nil {
		t.Fatalf("清洗失败: %v", err)
	}
	return doc
}

// dig 按路径取值，便于断言。
func dig(t *testing.T, doc any, path ...any) any {
	t.Helper()
	cur := doc
	for _, p := range path {
		switch key := p.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				t.Fatalf("路径 %v 处不是对象，实际 %T", path, cur)
			}
			cur = m[key]
		case int:
			a, ok := cur.([]any)
			if !ok || key >= len(a) {
				t.Fatalf("路径 %v 处不是数组或越界", path)
			}
			cur = a[key]
		}
	}
	return cur
}

// TestProtocolSkeletonUntouched 是本文件的核心断言：
// 即便净化函数把一切都替换掉，协议骨架字段必须原封不动。
//
// 这些字段一旦被污染，请求协议直接破损：role 变占位符则消息角色丢失，
// function.name 变占位符则模型再也调不到该工具，
// tool_call_id 变占位符则工具结果配不上调用。
func TestProtocolSkeletonUntouched(t *testing.T) {
	doc := sanitizeJSON(t, `{
		"model": "gpt-oss-120b",
		"stream": true,
		"temperature": 0.2,
		"stop": ["<|end|>", "STOP"],
		"user": "acct-12345",
		"response_format": {"type": "json_schema", "json_schema": {"name": "Order"}},
		"messages": [
			{"role": "system", "content": "你是助手"},
			{"role": "user", "content": "联系张伟"},
			{"role": "assistant", "content": null, "tool_calls": [
				{"id": "call_abc", "type": "function",
				 "function": {"name": "query_order", "arguments": "{\"customer\":\"张伟\"}"}}
			]},
			{"role": "tool", "tool_call_id": "call_abc", "content": "查询结果"}
		]
	}`)

	// Top-level protocol fields. / 顶层协议字段
	if doc["model"] != "gpt-oss-120b" {
		t.Errorf("model 被污染: %v", doc["model"])
	}
	if doc["stream"] != true {
		t.Errorf("stream 被污染: %v", doc["stream"])
	}
	if doc["user"] != "acct-12345" {
		t.Errorf("user 标识符被污染: %v", doc["user"])
	}
	// stop 序列被改写会直接改变模型的截断行为
	stops := doc["stop"].([]any)
	if stops[0] != "<|end|>" || stops[1] != "STOP" {
		t.Errorf("stop 序列被污染: %v", stops)
	}
	if dig(t, doc, "response_format", "type") != "json_schema" {
		t.Errorf("response_format.type 被污染")
	}
	if dig(t, doc, "response_format", "json_schema", "name") != "Order" {
		t.Errorf("json_schema.name 被污染")
	}

	// Message-level protocol fields. / 消息级协议字段
	for i, wantRole := range []string{"system", "user", "assistant", "tool"} {
		if got := dig(t, doc, "messages", i, "role"); got != wantRole {
			t.Errorf("messages[%d].role 被污染: %v", i, got)
		}
	}
	tc := dig(t, doc, "messages", 2, "tool_calls", 0)
	if dig(t, tc, "id") != "call_abc" {
		t.Errorf("tool_call.id 被污染: %v", dig(t, tc, "id"))
	}
	if dig(t, tc, "type") != "function" {
		t.Errorf("tool_call.type 被污染")
	}
	if dig(t, tc, "function", "name") != "query_order" {
		t.Errorf("function.name 被污染——模型将再也调不到该工具")
	}
	if dig(t, doc, "messages", 3, "tool_call_id") != "call_abc" {
		t.Errorf("tool_call_id 被污染——工具结果将配不上调用")
	}
}

// TestContentIsSanitized 校验真正的自然语言区域确实被净化了。
// 骨架不被碰的前提下，内容必须被碰——否则脱敏就形同虚设。
func TestContentIsSanitized(t *testing.T) {
	doc := sanitizeJSON(t, `{
		"system": "顶层系统提示词",
		"messages": [
			{"role": "user", "content": "联系张伟"},
			{"role": "user", "content": [
				{"type": "text", "text": "看这张图里的张伟"},
				{"type": "image_url", "image_url": {"url": "https://example.com/a.png"}}
			]}
		]
	}`)

	if doc["system"] != "REDACTED" {
		t.Errorf("顶层 system 未被净化: %v", doc["system"])
	}
	if got := dig(t, doc, "messages", 0, "content"); got != "REDACTED" {
		t.Errorf("消息正文未被净化: %v", got)
	}
	// 多模态：只碰 text，不碰 image_url
	if got := dig(t, doc, "messages", 1, "content", 0, "text"); got != "REDACTED" {
		t.Errorf("内容块 text 未被净化: %v", got)
	}
	if got := dig(t, doc, "messages", 1, "content", 0, "type"); got != "text" {
		t.Errorf("内容块 type 被污染: %v", got)
	}
	if got := dig(t, doc, "messages", 1, "content", 1, "image_url", "url"); got != "https://example.com/a.png" {
		t.Errorf("image_url 被污染: %v", got)
	}
}

// TestToolSchemaEnumPreserved 锁定「JSON Schema 被脱敏导致工具约束失效」这个回归。
//
// 早期实现递归净化 tools 下的所有字符串，enum 值（如 ["北京","上海"]）
// 会被当成地名脱敏，模型收到的枚举变成占位符，工具参数约束直接失效。
func TestToolSchemaEnumPreserved(t *testing.T) {
	doc := sanitizeJSON(t, `{
		"tools": [{
			"type": "function",
			"function": {
				"name": "query_weather",
				"description": "按城市查天气，如：查张伟所在城市",
				"parameters": {
					"type": "object",
					"properties": {
						"city": {
							"type": "string",
							"enum": ["北京", "上海", "深圳"],
							"description": "城市名，例如张伟常驻的北京"
						},
						"unit": {"type": "string", "enum": ["c", "f"]}
					},
					"required": ["city"],
					"additionalProperties": false
				}
			}
		}]
	}`)

	fn := dig(t, doc, "tools", 0, "function")
	if dig(t, fn, "name") != "query_weather" {
		t.Errorf("工具名被污染: %v", dig(t, fn, "name"))
	}
	// Descriptions are natural language and must be sanitized.
	// 描述属于自然语言，应被净化
	if dig(t, fn, "description") != "REDACTED" {
		t.Errorf("工具描述未被净化——里面常写着含 PII 的示例")
	}

	params := dig(t, fn, "parameters")
	if dig(t, params, "type") != "object" {
		t.Errorf("schema type 被污染")
	}
	// Enum values are protocol constraints and must never be sanitized.
	// 枚举值是协议约束，绝不能被净化
	cityEnum := dig(t, params, "properties", "city", "enum").([]any)
	if cityEnum[0] != "北京" || cityEnum[1] != "上海" || cityEnum[2] != "深圳" {
		t.Errorf("枚举值被污染，工具参数约束已失效: %v", cityEnum)
	}
	if dig(t, params, "properties", "city", "type") != "string" {
		t.Errorf("属性 type 被污染")
	}
	// 但 schema 内的 description 是自然语言，应被净化
	if dig(t, params, "properties", "city", "description") != "REDACTED" {
		t.Errorf("schema 内的 description 未被净化")
	}
	required := dig(t, params, "required").([]any)
	if required[0] != "city" {
		t.Errorf("required 数组被污染——那是属性名，属于协议骨架: %v", required)
	}
}

// TestToolArgumentsKeysPreserved 校验工具入参只净化值不碰键。
//
// arguments 是模型生成的 JSON 字符串，其中的值是从用户输入提取的自然语言，
// 但键是 schema 定义的参数名——脱敏后本地工具就认不出这个参数了。
func TestToolArgumentsKeysPreserved(t *testing.T) {
	doc := sanitizeJSON(t, `{
		"messages": [{
			"role": "assistant",
			"tool_calls": [{
				"id": "c1", "type": "function",
				"function": {
					"name": "create_ticket",
					"arguments": "{\"customer_name\":\"张伟\",\"phone\":\"13812345678\",\"priority\":3,\"tags\":[\"投诉\",\"紧急\"]}"
				}
			}]
		}]
	}`)

	raw := dig(t, doc, "messages", 0, "tool_calls", 0, "function", "arguments").(string)
	var args map[string]any
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		t.Fatalf("净化后的 arguments 不再是合法 JSON: %v（原始 %q）", err, raw)
	}

	for _, key := range []string{"customer_name", "phone", "priority", "tags"} {
		if _, ok := args[key]; !ok {
			t.Errorf("参数名 %q 丢失——本地工具将认不出这个参数。实际键: %v", key, keysOf(args))
		}
	}
	if args["customer_name"] != "REDACTED" || args["phone"] != "REDACTED" {
		t.Errorf("参数值未被净化: %v", args)
	}
	// Non-string values are untouched. / 非字符串值不受影响
	if args["priority"] != float64(3) {
		t.Errorf("数值型参数被改动: %v", args["priority"])
	}
	tags := args["tags"].([]any)
	if tags[0] != "REDACTED" || tags[1] != "REDACTED" {
		t.Errorf("数组内的字符串值应被净化: %v", tags)
	}
}

// TestMalformedToolArgumentsPassThrough 校验非法 JSON 的入参原样透传。
// 模型偶尔生成非法 JSON，此时不该让整个请求失败。
func TestMalformedToolArgumentsPassThrough(t *testing.T) {
	doc := sanitizeJSON(t, `{
		"messages": [{"role":"assistant","tool_calls":[
			{"id":"c1","type":"function","function":{"name":"f","arguments":"{broken json"}}]}]
	}`)
	got := dig(t, doc, "messages", 0, "tool_calls", 0, "function", "arguments")
	if got != "{broken json" {
		t.Errorf("非法 JSON 应原样透传，实际 %v", got)
	}
}

// TestUnknownFieldsUntouched 校验网关不认识的字段完全不被访问。
//
// 这是白名单相对黑名单的核心优势：上游新增任何字符串参数，
// 黑名单实现会把它送进 NER（可能污染），白名单实现根本不会碰它。
func TestUnknownFieldsUntouched(t *testing.T) {
	doc := sanitizeJSON(t, `{
		"model": "m",
		"messages": [{"role":"user","content":"正文"}],
		"future_param": "某个网关还不认识的枚举值",
		"nested_future": {"mode": "strict", "labels": ["a","b"]},
		"speculative_config": {"draft_model": "llama-3.2-1b", "num_tokens": 5}
	}`)

	if doc["future_param"] != "某个网关还不认识的枚举值" {
		t.Errorf("未知字段被污染: %v", doc["future_param"])
	}
	if dig(t, doc, "nested_future", "mode") != "strict" {
		t.Errorf("未知嵌套字段被污染")
	}
	if dig(t, doc, "speculative_config", "draft_model") != "llama-3.2-1b" {
		t.Errorf("未知配置被污染——上游新特性会因此失效")
	}
	// while known natural-language regions are still sanitized
	// 而已知的自然语言区域仍被正常净化
	if dig(t, doc, "messages", 0, "content") != "REDACTED" {
		t.Errorf("已知内容区域未被净化")
	}
}

// TestNoOpOnUnexpectedShapes 校验形态不符时安静跳过而非报错。
// 请求体形态多样，一条规则不匹配是常态。
func TestNoOpOnUnexpectedShapes(t *testing.T) {
	cases := []string{
		`{"messages": "不是数组"}`,
		`{"messages": [42, null, "字符串"]}`,
		`{"tools": {"不是":"数组"}}`,
		`{"system": 123}`,
		`{}`,
	}
	for _, raw := range cases {
		var doc map[string]any
		json.Unmarshal([]byte(raw), &doc)
		if err := SanitizeDocument(doc, markAll); err != nil {
			t.Errorf("形态 %s 不应报错: %v", raw, err)
		}
	}
}

// TestTransformErrorPropagates 校验净化函数报错会上抛。
// fail-closed 依赖这条链路：检测器故障必须能阻断请求。
func TestTransformErrorPropagates(t *testing.T) {
	var doc map[string]any
	json.Unmarshal([]byte(`{"messages":[{"role":"user","content":"x"}]}`), &doc)

	err := SanitizeDocument(doc, func(string) (string, error) {
		return "", errBoom
	})
	if err == nil {
		t.Fatal("净化失败必须上抛，否则 fail-closed 失效")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("错误信息应保留根因: %v", err)
	}
}

// errBoom 是测试用错误。
var errBoom = &sanitizeTestError{}

// sanitizeTestError 是测试用错误类型。
type sanitizeTestError struct{}

func (*sanitizeTestError) Error() string { return "boom" }

// keysOf 返回 map 的键列表，用于断言失败时的诊断输出。
func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
