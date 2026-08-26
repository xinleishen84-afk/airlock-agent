package identity

import (
	"context"
	"net/http"
	"testing"
)

// TestFromHeadersCaseInsensitive 校验头名大小写不敏感，自定义属性按前缀收集。
func TestFromHeadersCaseInsensitive(t *testing.T) {
	h := http.Header{}
	h.Set("x-workload-app", "toolbench-agent")
	h.Set("X-WORKLOAD-TASK", "extraction")
	h.Set("X-Workload-Priority", "3")
	h.Set("x-workload-attr-region", "cn-north")

	id := FromHeaders(h)
	if id.App != "toolbench-agent" || id.Task != TaskExtraction || id.Priority != 3 {
		t.Errorf("解析错误: %+v", id)
	}
	if id.Attributes["region"] != "cn-north" {
		t.Errorf("自定义属性未收集: %v", id.Attributes)
	}
}

// TestMalformedHeadersDegrade 校验畸形头部降级而非报错——
// 网关不应因为一个坏头部就拒绝服务。
func TestMalformedHeadersDegrade(t *testing.T) {
	h := http.Header{}
	h.Set("X-Workload-Tier", "不是数字")
	h.Set("X-Workload-Priority", "abc")
	h.Set("X-Workload-Task", "未知任务")

	id := FromHeaders(h)
	if id.TierHint != 0 || id.Priority != 5 || id.Task != TaskUnknown {
		t.Errorf("畸形头部应降级为默认值: %+v", id)
	}
}

// TestTierHeaderAcceptsBothForms 校验同时接受 "1" 与 "tier1"。
func TestTierHeaderAcceptsBothForms(t *testing.T) {
	for _, raw := range []string{"1", "tier1", "Tier1", " TIER1 "} {
		h := http.Header{}
		h.Set("X-Workload-Tier", raw)
		if got := FromHeaders(h).TierHint; got != 1 {
			t.Errorf("%q 应解析为 1，实际 %d", raw, got)
		}
	}
}

// TestPriorityClamped 校验优先级越界时收敛到 0-9。
func TestPriorityClamped(t *testing.T) {
	for raw, want := range map[string]int{"99": 9, "-5": 0, "7": 7} {
		h := http.Header{}
		h.Set("X-Workload-Priority", raw)
		if got := FromHeaders(h).Priority; got != want {
			t.Errorf("%q 应收敛为 %d，实际 %d", raw, want, got)
		}
	}
}

// TestRoundTripHeaders 校验身份可反向序列化透传给下游。
func TestRoundTripHeaders(t *testing.T) {
	original := Identity{
		App: "planner-agent", Task: TaskPlanning, Tenant: "acme",
		Priority: 8, TierHint: 1, TraceID: "req-1",
		Attributes: map[string]string{"region": "eu"},
	}
	h := http.Header{}
	original.ToHeaders(h)
	got := FromHeaders(h)

	if got.App != original.App || got.Task != original.Task ||
		got.Tenant != original.Tenant || got.Priority != original.Priority ||
		got.TierHint != original.TierHint || got.Attributes["region"] != "eu" {
		t.Errorf("往返不一致:\n  得到 %+v\n  期望 %+v", got, original)
	}
}

// TestContextPropagation 校验身份在 context 上的传播与兜底。
func TestContextPropagation(t *testing.T) {
	ctx := context.Background()
	if FromContext(ctx).App != "unknown" {
		t.Error("未绑定时应返回匿名身份")
	}
	id := Identity{App: "planner-agent", Task: TaskPlanning}
	if got := FromContext(NewContext(ctx, id)); got.App != "planner-agent" {
		t.Errorf("context 传播失败: %+v", got)
	}
}

// TestRateLimitSubjectIsolation 校验限流主体按「租户+应用」隔离。
// 只按租户会让一个失控的批量作业拖垮同租户的交互式请求。
func TestRateLimitSubjectIsolation(t *testing.T) {
	batch := Identity{Tenant: "acme", App: "toolbench-agent"}
	chat := Identity{Tenant: "acme", App: "support-bot"}
	if batch.RateLimitSubject() == chat.RateLimitSubject() {
		t.Error("同租户不同应用应有独立限流主体")
	}
}
