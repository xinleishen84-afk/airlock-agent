// Package identity 解析工作负载身份并在调用链上传播。
//
// 网关的分流依据不是「这次请求内容像什么」，而是「这次请求来自谁、要干什么」。
// 身份从 HTTP 头部解析，随后放入 context 透传——中间隔着多少层与路由
// 无关的处理器都不影响，最终选路时依然拿得到原始身份。
package identity

import (
	"context"
	"net/http"
	"strconv"
	"strings"
)

// 身份头部约定。HTTP 头名大小写不敏感，统一按规范化形式比较。
const (
	HeaderApp      = "X-Workload-App"      // 调用方应用标识，如 toolbench-agent
	HeaderTask     = "X-Workload-Task"     // 任务类型，如 planning / extraction
	HeaderTier     = "X-Workload-Tier"     // 显式指定梯队，优先级最高
	HeaderTenant   = "X-Workload-Tenant"   // 租户，用于配额隔离
	HeaderPriority = "X-Workload-Priority" // 业务优先级 0-9，越大越高
	HeaderTrace    = "X-Request-Id"        // 链路追踪 ID
	HeaderSession  = "X-Session-Id"        // 会话 ID，决定脱敏映射的复用范围

	attrPrefix = "X-Workload-Attr-" // 自定义匹配维度的头部前缀
)

// TaskKind 是任务类型，自动定级的主要依据。
type TaskKind string

const (
	// 高价值：复杂推理与规划
	TaskPlanning          TaskKind = "planning"
	TaskReasoning         TaskKind = "reasoning"
	TaskCodeGeneration    TaskKind = "code_generation"
	TaskToolOrchestration TaskKind = "tool_orchestration"

	// 背景批量：结构化、高频、可预测
	TaskExtraction     TaskKind = "extraction"
	TaskClassification TaskKind = "classification"
	TaskSummarization  TaskKind = "summarization"
	TaskTranslation    TaskKind = "translation"
	TaskRerank         TaskKind = "rerank"
	TaskEmbeddingPrep  TaskKind = "embedding_prep"

	TaskUnknown TaskKind = "unknown"
)

// knownTasks 是合法任务类型集合，用于安全解析。
var knownTasks = map[TaskKind]bool{
	TaskPlanning: true, TaskReasoning: true, TaskCodeGeneration: true,
	TaskToolOrchestration: true, TaskExtraction: true, TaskClassification: true,
	TaskSummarization: true, TaskTranslation: true, TaskRerank: true,
	TaskEmbeddingPrep: true, TaskUnknown: true,
}

// ParseTask 把头部字符串安全映射为任务类型，未知值降级为 unknown 而非报错。
func ParseTask(v string) TaskKind {
	t := TaskKind(strings.ToLower(strings.TrimSpace(v)))
	if knownTasks[t] {
		return t
	}
	return TaskUnknown
}

// Identity 是一次请求的调用方身份。构造后不再修改，可安全跨 goroutine 共享。
type Identity struct {
	App        string
	Task       TaskKind
	TierHint   int // 0 表示未指定
	Tenant     string
	Priority   int // 0-9
	TraceID    string
	SessionID  string
	Attributes map[string]string
}

// Anonymous 是未声明身份时的兜底，按最低价值处理。
var Anonymous = Identity{App: "unknown", Task: TaskUnknown, Tenant: "default", Priority: 5}

// FromHeaders 从 HTTP 头部解析身份。缺失字段取默认值，非法值降级而非报错——
// 网关不应因为一个畸形头部就拒绝服务。
func FromHeaders(h http.Header) Identity {
	id := Identity{
		App:       firstNonEmpty(h.Get(HeaderApp), "unknown"),
		Task:      ParseTask(h.Get(HeaderTask)),
		Tenant:    firstNonEmpty(h.Get(HeaderTenant), "default"),
		Priority:  5,
		TraceID:   h.Get(HeaderTrace),
		SessionID: h.Get(HeaderSession),
	}

	// 同时接受 "1" 与 "tier1" 两种写法
	if raw := strings.TrimSpace(h.Get(HeaderTier)); raw != "" {
		cleaned := strings.TrimPrefix(strings.ToLower(raw), "tier")
		if n, err := strconv.Atoi(strings.TrimSpace(cleaned)); err == nil {
			id.TierHint = n
		}
	}

	if raw := strings.TrimSpace(h.Get(HeaderPriority)); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			id.Priority = clamp(n, 0, 9)
		}
	}

	// 以 X-Workload-Attr- 前缀的头部作为自定义匹配维度
	for name, values := range h {
		if len(values) == 0 {
			continue
		}
		if key, ok := strings.CutPrefix(http.CanonicalHeaderKey(name), attrPrefix); ok {
			if id.Attributes == nil {
				id.Attributes = map[string]string{}
			}
			id.Attributes[strings.ToLower(key)] = values[0]
		}
	}
	return id
}

// ToHeaders 反向序列化为头部，用于向下游服务透传身份。
func (i Identity) ToHeaders(h http.Header) {
	h.Set(HeaderApp, i.App)
	h.Set(HeaderTask, string(i.Task))
	h.Set(HeaderTenant, i.Tenant)
	h.Set(HeaderPriority, strconv.Itoa(i.Priority))
	if i.TierHint > 0 {
		h.Set(HeaderTier, strconv.Itoa(i.TierHint))
	}
	if i.TraceID != "" {
		h.Set(HeaderTrace, i.TraceID)
	}
	for k, v := range i.Attributes {
		h.Set(attrPrefix+k, v)
	}
}

// String 返回日志友好的紧凑表示。
func (i Identity) String() string {
	return i.App + "/" + string(i.Task) + "@" + i.Tenant + "(p" + strconv.Itoa(i.Priority) + ")"
}

// RateLimitSubject 返回限流主体标识。按「租户+应用」隔离配额：
// 只按租户会让一个失控的批量作业拖垮同租户的交互式请求。
func (i Identity) RateLimitSubject() string {
	return i.Tenant + "/" + i.App
}

// ---------------------------------------------------------------------------
// Context 传播
// ---------------------------------------------------------------------------

// ctxKey 是 context 键的私有类型，避免与其他包冲突。
type ctxKey struct{}

// NewContext 把身份放入 context。
func NewContext(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext 从 context 取出身份；未绑定时返回匿名身份。
func FromContext(ctx context.Context) Identity {
	if id, ok := ctx.Value(ctxKey{}).(Identity); ok {
		return id
	}
	return Anonymous
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// clamp 把整数收敛到 [lo, hi] 区间。
func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
