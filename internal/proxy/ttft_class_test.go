package proxy

import (
	"testing"
	"time"
)

// TestToolCallStreamDoesNotPolluteTTFT 证明工具调用轮不会混进 TTFT 均值。
// Proves a tool-call turn does not land in the TTFT average.
//
// TTFT 的含义是「用户多久看到第一个字」。工具调用帧里没有任何用户能看到
// 的东西——客户端要等整个调用拼完才能动作。两类混进同一个均值会得到
// 双峰分布的中点：既不描述对话轮，也不描述工具调用轮，还不能用来定容量。
//
// 分开计而不是丢弃：到首个工具调用帧的延迟本身是 agent 编排的指标，
// 有人要看，只是不能和前者相加。
//
// TTFT means "how long until the user sees the first character"; a tool-call
// frame shows the user nothing. Averaging both yields a bimodal metric whose
// mean describes neither. They are counted separately rather than dropped —
// time-to-first-tool-call is a real orchestration metric, just not the same one.
func TestToolCallStreamDoesNotPolluteTTFT(t *testing.T) {
	up := newUpstream(t, upstreamOpts{
		chunks: []string{
			`{"choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
			`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,` +
				`"function":{"name":"lookup","arguments":"{}"}}]}}]}`,
		},
		firstDelay: 20 * time.Millisecond,
	})
	defer up.Close()

	h := newTestHandler(t, up.URL, true, false)
	doRequest(t, h, `{"stream":true,"messages":[]}`, nil)

	if n := h.Stats().TTFTCount.Load(); n != 0 {
		t.Errorf("纯工具调用轮被计入了 TTFT（%d 次）——会把用户感知延迟的均值抬歪", n)
	}
	if n := h.Stats().ToolCallTTFTCount.Load(); n != 1 {
		t.Errorf("应记录 1 次工具调用延迟，实际 %d", n)
	}
}

// TestUnknownFrameShapeStillRecordsTTFT 证明认不出的帧形状不会让指标消失。
// Proves an unrecognized frame shape does not make the metric vanish.
//
// 分类依赖认得出 choices[].delta。换个上游协议（Anthropic 的
// content_block_delta、自研网关的变体）就一律落到 FrameOther，两个计数器
// 都不涨，/metrics 上 TTFT 静默归零——看起来像「没有流量」而不是
// 「认不出形状」。这正是这套系统里反复出现的那类故障：
// 声称存在的能力静默缺席。
//
// Classification depends on recognizing choices[].delta. Against a different
// upstream protocol every frame falls through, neither counter moves, and TTFT
// silently reads zero — looking like "no traffic" rather than "unknown shape".
func TestUnknownFrameShapeStillRecordsTTFT(t *testing.T) {
	up := newUpstream(t, upstreamOpts{
		// 既不是 OpenAI 也不是 Anthropic 的形状
		chunks:     []string{`{"payload":{"token":"a"}}`},
		firstDelay: 20 * time.Millisecond,
	})
	defer up.Close()

	h := newTestHandler(t, up.URL, true, false)
	doRequest(t, h, `{"stream":true,"messages":[]}`, nil)

	if n := h.Stats().TTFTCount.Load(); n != 1 {
		t.Fatalf("形状认不出时 TTFT 应按首帧兜底记一次，实际 %d 次——"+
			"指标会从监控上静默消失", n)
	}
	if ttft := h.Stats().AvgTTFT(); ttft < 15*time.Millisecond {
		t.Errorf("兜底 TTFT 数值异常: %v", ttft)
	}
}
