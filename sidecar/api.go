// Package sidecar exposes the PII redaction engine as a standalone HTTP
// service.
// 把 PII 脱敏引擎暴露为独立的 HTTP 服务。
//
// # Why HTTP rather than Envoy's ext_proc gRPC
// # 为什么是 HTTP 而不是 Envoy 的 ext_proc gRPC
//
// ext_proc only works for the Envoy family (including Higress). An HTTP endpoint
// works for everyone: APISIX serverless plugins, Kong plugins, Nginx njs, even a
// fully in-house gateway can wire it up in a few dozen lines.
// ext_proc 只有 Envoy 系（含 Higress）能用。而 HTTP 接口谁都能调：
// APISIX 的 serverless 插件、Kong 的 plugin、Nginx 的 njs、
// 乃至完全自研的网关，都能在几十行内接上。
//
// Adoption cost drives adoption rate — a component usable only by Envoy users
// locks out most of its potential audience. A thin Envoy-side adapter translates
// ext_proc into these HTTP calls; both sides share one engine.
// 采纳门槛决定采纳率——只有 Envoy 用户能用的组件天然把大半使用者挡在门外。
// Envoy 侧另有一个薄适配层把 ext_proc 翻译成这套 HTTP 调用，两边共用同一引擎。
//
// # Why not a library
// # 为什么不是库
//
// A library requires the gateway itself to be written in Go. As a sidecar, a
// Java gateway, C++ Envoy and Lua APISIX all use the same binary.
// 库要求网关本身是 Go 写的。做成 sidecar 后，Java 网关、
// C++ 的 Envoy、Lua 的 APISIX 都能用同一个二进制。
package sidecar

// RedactRequest is a redaction request.
// 是脱敏请求。
type RedactRequest struct {
	// SessionID 决定占位符映射的复用范围。同一会话的多轮对话必须
	// 传同一个 ID，否则模型会在轮次之间失去实体一致性。
	SessionID string `json:"session_id"`

	// Payload 是待脱敏的完整请求体（OpenAI 兼容格式）。
	// 服务端按结构化 AST 白名单定向清洗，只碰自然语言区域。
	Payload map[string]any `json:"payload"`

	// Text 是单段文本模式。与 Payload 二选一——
	// 网关若只想脱敏某个字段，用这个更直接。
	Text string `json:"text,omitempty"`

	// Destination 指定数据流向，决定使用哪一组脱敏算子。
	//
	// 同一份请求体发往公有云模型、分析数仓和冷归档，需要的算子并不相同：
	// 模型要指代一致的占位符，数仓要可关联的假名，归档要字节消失。
	// 未配置矩阵时留空即可，此时一律使用占位符遮罩。
	//
	// Destination selects which operators apply. The same body bound for a
	// public-cloud model, an analytics warehouse and a cold archive needs
	// different ones. Leave empty when no matrix is configured; placeholder
	// masking is then used throughout.
	Destination string `json:"destination,omitempty"`
}

// RedactResponse is a redaction result.
// 是脱敏结果。
type RedactResponse struct {
	// Payload 是脱敏后的请求体，可直接转发给上游
	Payload map[string]any `json:"payload,omitempty"`
	Text    string         `json:"text,omitempty"`

	// EntityCounts 是本次脱敏的实体类型计数。
	// 只给计数不给值——审计日志会长期归档，一旦写进真实值就是永久泄露。
	EntityCounts map[string]int `json:"entity_counts"`

	// StrategyCounts 是各脱敏算子的使用次数。
	//
	// 审计要回答的是「这条链路上有几个值被哈希、几个被切除」，
	// 而这在两次配置改动之间恰恰是唯一会变的数字——只看实体计数看不出来。
	// Audit needs "how many values were hashed and how many dropped": across a
	// configuration change that is the only number that moves.
	StrategyCounts map[string]int `json:"strategy_counts,omitempty"`

	// Blocked 为 true 表示按 fail-closed 阻断了请求。
	// 网关收到后应向调用方返回错误，绝不能放行原始载荷。
	Blocked bool   `json:"blocked"`
	Reason  string `json:"reason,omitempty"`
}

// RestoreRequest is a restoration request.
// 是复原请求。
type RestoreRequest struct {
	SessionID string         `json:"session_id"`
	Payload   map[string]any `json:"payload,omitempty"`
	Text      string         `json:"text,omitempty"`
	// Streaming 为 true 时按流式分片处理：占位符可能横跨两个分片，
	// 服务端会滞留不完整的尾部直到下一片到来。
	Streaming bool `json:"streaming,omitempty"`
	// Final 标记流的最后一片，触发滞留缓冲的吐出
	Final bool `json:"final,omitempty"`
}

// RestoreResponse is a restoration result.
// 是复原结果。
type RestoreResponse struct {
	Payload map[string]any `json:"payload,omitempty"`
	// ReleasedToolCalls 是工具调用屏障放行时补出的那一帧。
	//
	// 工具入参不逐帧复原——分片攒齐后才按结构还原一次，否则会在半截
	// JSON 文本上做替换（真值含引号即产出非法 JSON）。因此一个入参分片
	// 请求可能返回两份载荷：本帧（入参已被抹空）与放行帧。
	// 调用方必须把它也发给下游，否则工具永远等不到参数。
	//
	// The frame emitted when the tool-call barrier releases. Tool arguments are
	// not restored per frame: fragments are assembled and restored once
	// structurally, because substituting inside half a JSON document produces
	// invalid JSON as soon as a real value contains a quote. One fragment
	// request can therefore return two payloads — this frame (arguments
	// blanked) and the release frame. Callers must forward both, or the tool
	// never receives its arguments.
	ReleasedToolCalls map[string]any `json:"released_tool_calls,omitempty"`
	Text              string         `json:"text,omitempty"`
	// Restored 是成功还原的占位符数量
	Restored int `json:"restored"`
	// Phantom 是模型凭空捏造、无法还原的占位符。
	// 非空说明模型在编造实体引用，值得告警。
	Phantom []string `json:"phantom,omitempty"`
}

// SessionRequest explicitly ends a session.
// 用于显式结束会话。
type SessionRequest struct {
	SessionID string `json:"session_id"`
}

// EraseResponse reports what a tenant erasure actually removed.
// 报告一次租户擦除实际移除了什么。
type EraseResponse struct {
	Tenant string `json:"tenant"`
	// SessionsErased 是被清除的会话映射数量。
	SessionsErased int `json:"sessions_erased"`
	// TokensErased 是被清除的令牌数量。
	//
	// 两个计数都给出来，是因为擦除要拿得出证据。
	// 一次因租户串写错而匹配到零条的擦除，与一次真正成功的擦除，
	// 在没有计数时看起来完全一样。
	// Both counts are reported because erasure has to be evidenced: without
	// them, an erasure that matched nothing looks like one that worked.
	TokensErased int `json:"tokens_erased"`
}

// ErrorResponse is an error response.
// 是错误响应。
type ErrorResponse struct {
	Error string `json:"error"`
	// FailClosed 为 true 表示这是安全阻断而非服务故障。
	// 网关据此区分「该重试」与「该拒绝」——重试一个 fail-closed
	// 只会反复失败，而把安全阻断当成故障降级则会放行 PII。
	FailClosed bool `json:"fail_closed,omitempty"`
}

// StatsResponse holds runtime statistics.
// 是运行统计。
type StatsResponse struct {
	ActiveSessions int              `json:"active_sessions"`
	RedactCalls    int64            `json:"redact_calls"`
	RestoreCalls   int64            `json:"restore_calls"`
	BlockedCalls   int64            `json:"blocked_calls"`
	EntityCounts   map[string]int64 `json:"entity_counts"`
	// CoverageGaps 是检测器未覆盖的实体类型。
	// 非空意味着这几类 PII 会完全裸奔——必须在监控里可见。
	CoverageGaps []string `json:"coverage_gaps,omitempty"`
	// NERCacheHitRate 反映 NER 缓存效果。偏低说明文本变化频繁，
	// NER 的延迟成本会直接压在 TTFT 上。
	NERCacheHitRate float64 `json:"ner_cache_hit_rate,omitempty"`

	// RedactionMatrix 是当前生效的脱敏策略矩阵。
	//
	// 从运行中的进程产出，而不是从某个人以为已经部署了的配置文件产出——
	// 这两者不一致，正是审计要查的那种事。
	// Produced from the live process, not from the config file someone
	// believes is deployed: the gap between those two is what audit looks for.
	RedactionMatrix string `json:"redaction_matrix,omitempty"`
}
