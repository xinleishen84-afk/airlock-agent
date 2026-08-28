package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestToolCallRoundTripThroughGateway 端到端验证：带 PII 的工具调用穿过整条网关。
// End-to-end: a tool call carrying PII traverses the whole gateway.
//
// # 这条路径此前从未跑过
// # This path had never been exercised
//
// 单测覆盖过文档层，假上游却只吐 delta.content，于是「请求脱敏 -> 上游
// 看到占位符 -> 响应里工具入参带回占位符 -> 屏障攒齐 -> 复原成真值交给
// 客户端」这条链在 agent 形态下一次都没跑通过。三个 bug 就藏在这里。
//
// 本测试同时钉住三件事：
//   - 上游只应看到占位符，看不到真实姓名
//   - 客户端拿到的工具入参必须是合法 JSON 且是真值
//   - 入参不得以任何形式出现在 delta.content 里
//
// Unit tests covered the document layer, but the fake upstream only ever
// emitted delta.content, so the chain — redact request, upstream sees
// placeholders, tool arguments come back holding one, barrier assembles,
// restore to the real value for the client — had never run in agent shape.
// Three bugs lived here.
func TestToolCallRoundTripThroughGateway(t *testing.T) {
	var seenByUpstream string
	up := newUpstream(t, upstreamOpts{
		onRequest: func(_ *http.Request, body []byte) { seenByUpstream = string(body) },
		chunks: []string{
			`{"choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
			// 入参里带回占位符，且在占位符中间切断——最难的形状
			`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1",` +
				`"function":{"name":"lookup","arguments":"{\"who\":\"ANONYMIZED_NA"}}]}}]}`,
			`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,` +
				`"function":{"arguments":"ME_0\"}"}}]},"finish_reason":"tool_calls"}]}`,
		},
	})
	defer up.Close()

	h := newTestHandler(t, up.URL, true, true)
	rec := doRequest(t, h,
		`{"stream":true,"messages":[{"role":"user","content":"帮我查张伟的档案"}]}`,
		map[string]string{"X-Session-ID": "s-tool"})

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d，响应: %s", rec.Code, rec.Body.String())
	}

	// 1. 上游不得看到真名
	if strings.Contains(seenByUpstream, "张伟") {
		t.Errorf("真实姓名泄漏给了上游: %s", seenByUpstream)
	}
	if !strings.Contains(seenByUpstream, "ANONYMIZED_NAME_0") {
		t.Fatalf("上游没有收到占位符，脱敏未生效: %s", seenByUpstream)
	}

	// 2. 客户端拿到的入参必须是合法 JSON 且已复原
	body := rec.Body.String()
	var args string
	for _, line := range strings.Split(body, "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var doc map[string]any
		if json.Unmarshal([]byte(data), &doc) != nil {
			continue
		}
		choices, _ := doc["choices"].([]any)
		for _, c := range choices {
			cm, _ := c.(map[string]any)
			delta, _ := cm["delta"].(map[string]any)
			calls, _ := delta["tool_calls"].([]any)
			for _, call := range calls {
				fn, _ := call.(map[string]any)["function"].(map[string]any)
				if a, _ := fn["arguments"].(string); a != "" {
					args += a
				}
			}
		}
	}
	if args == "" {
		t.Fatalf("客户端一个字节的工具入参都没收到——工具将永远等下去。响应:\n%s", body)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(args), &parsed); err != nil {
		t.Fatalf("客户端收到的工具入参不是合法 JSON: %q (%v)", args, err)
	}
	if parsed["who"] != "张伟" {
		t.Errorf("工具入参未复原为真值: %v——工具会拿着占位符去查库", parsed["who"])
	}

	// 3. 入参不得混进用户可见正文
	for _, line := range strings.Split(body, "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var doc map[string]any
		if json.Unmarshal([]byte(data), &doc) != nil {
			continue
		}
		choices, _ := doc["choices"].([]any)
		for _, c := range choices {
			cm, _ := c.(map[string]any)
			delta, _ := cm["delta"].(map[string]any)
			if content, _ := delta["content"].(string); strings.Contains(content, `"who"`) {
				t.Errorf("工具入参漏进了用户可见正文: %q", content)
			}
		}
	}
}
