package sidecar

import (
	"bytes"
	"encoding/json"
	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
)

// newTestServer 构造一个带名册检测器的 sidecar。
func newTestServer(t *testing.T, failClosed bool, detector detect.Detector) *httptest.Server {
	t.Helper()
	if detector == nil {
		gaz, err := detect.NewGazetteerDetector(map[detect.EntityType][]string{
			detect.TypeName: {"张伟", "李娜"},
			detect.TypeOrg:  {"星辰科技"},
		}, false, 2)
		if err != nil {
			t.Fatal(err)
		}
		detector = detect.NewCompositeDetector(
			[]detect.Detector{packs.MustNewRegistry([]string{"GEN", "CN", "US"}), gaz}, 0)
	}
	srv, err := New(Options{
		Detector: detector, FailClosed: failClosed,
		SessionTTL: time.Hour, MaxSessions: 100,
		TenantResolver: mustStaticResolver(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// post 发起一次调用并解析响应，返回状态码。
func post(t *testing.T, url string, req, out any) int {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && err != io.EOF {
			t.Fatalf("解析响应失败: %v", err)
		}
	}
	return resp.StatusCode
}

// TestRedactRestoreRoundTrip 校验完整往返。
func TestRedactRestoreRoundTrip(t *testing.T) {
	ts := newTestServer(t, true, nil)

	var red RedactResponse
	code := post(t, ts.URL+"/v1/redact", RedactRequest{
		SessionID: "s1",
		Payload: map[string]any{
			"model": "gpt-4o",
			"messages": []any{map[string]any{
				"role": "user", "content": "联系张伟，手机 13812345678",
			}},
		},
	}, &red)
	if code != http.StatusOK || red.Blocked {
		t.Fatalf("脱敏失败：code=%d blocked=%v reason=%s", code, red.Blocked, red.Reason)
	}

	raw, _ := json.Marshal(red.Payload)
	for _, secret := range []string{"张伟", "13812345678"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("真实 PII %q 未被脱敏：%s", secret, raw)
		}
	}
	if red.EntityCounts["NAME"] != 1 || red.EntityCounts["PHONE"] != 1 {
		t.Errorf("实体计数错误：%v", red.EntityCounts)
	}

	var res RestoreResponse
	post(t, ts.URL+"/v1/restore", RestoreRequest{
		SessionID: "s1",
		Payload: map[string]any{"choices": []any{map[string]any{
			"delta": map[string]any{"content": "已通知 ANONYMIZED_NAME_0，拨打 ANONYMIZED_PHONE_0"},
		}}},
	}, &res)
	out, _ := json.Marshal(res.Payload)
	if !strings.Contains(string(out), "张伟") || !strings.Contains(string(out), "13812345678") {
		t.Errorf("复原失败：%s", out)
	}
	if res.Restored != 2 {
		t.Errorf("应还原 2 个占位符，实际 %d", res.Restored)
	}
}

// everythingIsPII 把任意非空文本整体判为人名，模拟 NER 的最坏情况。
type everythingIsPII struct{}

func (everythingIsPII) Name() string { return "worst_case" }
func (everythingIsPII) CoveredTypes() []detect.EntityType {
	return []detect.EntityType{detect.TypeName, detect.TypeAddress, detect.TypeOrg}
}
func (everythingIsPII) Detect(text string) ([]detect.Entity, error) {
	if text == "" {
		return nil, nil
	}
	return []detect.Entity{{Type: detect.TypeName, Value: text, Start: 0, End: len(text),
		Confidence: 0.99, Detector: "worst_case"}}, nil
}

// TestProtocolSkeletonSurvives 校验协议骨架不被污染。
//
// 这是本组件相对同类方案的核心差异：递归净化所有字符串会把
// role / 工具名 / schema enum 一起换掉，请求协议直接破损。
func TestProtocolSkeletonSurvives(t *testing.T) {
	ts := newTestServer(t, true, detect.NewCompositeDetector(
		[]detect.Detector{everythingIsPII{}}, 0))

	var red RedactResponse
	post(t, ts.URL+"/v1/redact", RedactRequest{
		SessionID: "s1",
		Payload: map[string]any{
			"model":    "gpt-4o",
			"stop":     []any{"<|end|>"},
			"messages": []any{map[string]any{"role": "user", "content": "正文"}},
			"tools": []any{map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        "query_order",
					"description": "查单",
					"parameters": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"city": map[string]any{"type": "string", "enum": []any{"北京", "上海"}},
						},
						"required": []any{"city"},
					},
				},
			}},
		},
	}, &red)

	p := red.Payload
	if p == nil {
		t.Fatalf("未返回载荷：blocked=%v reason=%s", red.Blocked, red.Reason)
	}
	if p["model"] != "gpt-4o" {
		t.Errorf("model 被污染：%v", p["model"])
	}
	if stop := p["stop"].([]any); stop[0] != "<|end|>" {
		t.Errorf("stop 序列被污染：%v", stop)
	}
	msg := p["messages"].([]any)[0].(map[string]any)
	if msg["role"] != "user" {
		t.Errorf("role 被污染：%v", msg["role"])
	}
	if msg["content"] == "正文" {
		t.Error("正文应被净化")
	}
	fn := p["tools"].([]any)[0].(map[string]any)["function"].(map[string]any)
	if fn["name"] != "query_order" {
		t.Errorf("工具名被污染，模型将再也调不到该工具：%v", fn["name"])
	}
	params := fn["parameters"].(map[string]any)
	enum := params["properties"].(map[string]any)["city"].(map[string]any)["enum"].([]any)
	if enum[0] != "北京" || enum[1] != "上海" {
		t.Errorf("schema enum 被污染，工具参数约束失效：%v", enum)
	}
	if params["required"].([]any)[0] != "city" {
		t.Errorf("required 被污染：%v", params["required"])
	}
}

// TestSessionIsolation 校验会话之间互不可见。
func TestSessionIsolation(t *testing.T) {
	ts := newTestServer(t, true, nil)
	post(t, ts.URL+"/v1/redact", RedactRequest{SessionID: "a", Text: "联系张伟"}, &RedactResponse{})

	var res RestoreResponse
	post(t, ts.URL+"/v1/restore", RestoreRequest{
		SessionID: "b", Text: "ANONYMIZED_NAME_0 是谁",
	}, &res)
	if strings.Contains(res.Text, "张伟") {
		t.Error("会话 b 不应能解出会话 a 的实体")
	}
	if len(res.Phantom) == 0 {
		t.Error("跨会话的占位符应被记为捏造")
	}
}

// TestEndSessionPurges 校验结束会话后映射被清除。
func TestEndSessionPurges(t *testing.T) {
	ts := newTestServer(t, true, nil)
	post(t, ts.URL+"/v1/redact", RedactRequest{SessionID: "s", Text: "张伟"}, &RedactResponse{})

	if code := post(t, ts.URL+"/v1/session/end", SessionRequest{SessionID: "s"}, nil); code != http.StatusNoContent {
		t.Errorf("结束会话应返回 204，实际 %d", code)
	}
	var res RestoreResponse
	post(t, ts.URL+"/v1/restore", RestoreRequest{SessionID: "s", Text: "ANONYMIZED_NAME_0"}, &res)
	if res.Restored != 0 {
		t.Error("清除后不应还能复原")
	}
}

// brokenDetector 是永远失败的检测器。
type brokenDetector struct{}

func (brokenDetector) Name() string                           { return "broken" }
func (brokenDetector) CoveredTypes() []detect.EntityType      { return nil }
func (brokenDetector) Detect(string) ([]detect.Entity, error) { return nil, errBroken }

// sidecarTestError 是测试用错误类型。
type sidecarTestError struct{}

// Error 实现 error。
func (*sidecarTestError) Error() string { return "检测器不可用" }

// errBroken 是测试用错误。
var errBroken = &sidecarTestError{}

// TestFailClosedReturns200WithBlocked 校验 fail-closed 的响应形态。
//
// 用 200 + blocked=true 而非 5xx：这不是服务故障而是安全策略生效。
// 返回 5xx 会让网关按「上游故障」重试或降级——而降级的方向
// 往往是放行，恰好与安全意图相反。
func TestFailClosedReturns200WithBlocked(t *testing.T) {
	ts := newTestServer(t, true, detect.NewCompositeDetector(
		[]detect.Detector{brokenDetector{}}, 0))

	var red RedactResponse
	code := post(t, ts.URL+"/v1/redact", RedactRequest{
		SessionID: "s",
		Payload:   map[string]any{"messages": []any{map[string]any{"role": "user", "content": "张伟"}}},
	}, &red)

	if code != http.StatusOK {
		t.Errorf("安全阻断应返回 200，实际 %d——5xx 会诱导网关按故障降级放行", code)
	}
	if !red.Blocked {
		t.Error("检测器故障时应返回 blocked=true")
	}
	if red.Payload != nil {
		t.Error("阻断时不应返回任何载荷——网关可能会误转发")
	}
}

// TestMissingSessionIDRejected 校验缺 session_id 被拒。
// 没有它就无法在响应侧复原，脱敏会变成不可逆的单向破坏。
func TestMissingSessionIDRejected(t *testing.T) {
	ts := newTestServer(t, true, nil)
	if code := post(t, ts.URL+"/v1/redact", RedactRequest{Text: "张伟"}, nil); code != http.StatusBadRequest {
		t.Errorf("缺 session_id 应返回 400，实际 %d", code)
	}
}

// TestStatsExposeNoValues 校验统计端点不泄露真实值。
//
// /stats 会被监控系统抓取并长期保留。一旦写进真实值，
// 就等于把 PII 复制到了另一套系统里——泄露一次就是永久泄露。
func TestStatsExposeNoValues(t *testing.T) {
	ts := newTestServer(t, true, nil)
	post(t, ts.URL+"/v1/redact", RedactRequest{
		SessionID: "s", Text: "张伟的手机 13812345678",
	}, &RedactResponse{})

	resp, err := http.Get(ts.URL + "/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	dump := string(body)

	for _, secret := range []string{"张伟", "13812345678"} {
		if strings.Contains(dump, secret) {
			t.Errorf("统计端点泄露了真实值 %q：%s", secret, dump)
		}
	}
	if !strings.Contains(dump, "entity_counts") {
		t.Errorf("统计应含实体计数：%s", dump)
	}
}

// TestCoverageGapExposed 校验覆盖缺口在 /stats 可见。
//
// 正则检测不出人名。只装正则就上线，姓名类 PII 完全裸奔——
// 这个事实必须能被监控系统看见，而不是只在启动日志里出现一次。
func TestCoverageGapExposed(t *testing.T) {
	ts := newTestServer(t, true, detect.NewCompositeDetector(
		[]detect.Detector{packs.MustNewRegistry([]string{"GEN", "CN", "US"})}, 0))

	resp, err := http.Get(ts.URL + "/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var stats StatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	if len(stats.CoverageGaps) == 0 {
		t.Error("仅有正则检测器时应报告覆盖缺口——否则运维不知道姓名在裸奔")
	}
}

// 配了矩阵之后，缺 destination 必须拒绝，不能静默回退。
// With a matrix configured, a missing destination must be rejected.
func TestDestinationRequiredWhenMatrixConfigured(t *testing.T) {
	m := anonymize.NewMatrix()
	m.MustAdd(anonymize.Flow{
		Name: "public_llm", Default: anonymize.NewMask(), Restores: true,
	})
	m.MustAdd(anonymize.Flow{Name: "archive", Default: anonymize.NewDrop()})

	ts := newMatrixTestServer(t, m)

	t.Run("缺 destination", func(t *testing.T) {
		code, body := ts.post(t, "/v1/redact", `{"session_id":"s1","text":"手机 13812345678"}`)
		if code != http.StatusBadRequest {
			t.Fatalf("应返回 400，实际 %d：%s", code, body)
		}
		if !strings.Contains(body, "destination") {
			t.Fatalf("报错应提示 destination：%s", body)
		}
	})

	t.Run("未知 destination", func(t *testing.T) {
		code, body := ts.post(t, "/v1/redact",
			`{"session_id":"s1","destination":"nowhere","text":"手机 13812345678"}`)
		if code != http.StatusBadRequest {
			t.Fatalf("应返回 400，实际 %d：%s", code, body)
		}
	})

	t.Run("按流向选算子", func(t *testing.T) {
		_, masked := ts.post(t, "/v1/redact",
			`{"session_id":"s1","destination":"public_llm","text":"手机 13812345678"}`)
		if !strings.Contains(masked, "ANONYMIZED_PHONE_0") {
			t.Fatalf("public_llm 应走占位符：%s", masked)
		}
		_, dropped := ts.post(t, "/v1/redact",
			`{"session_id":"s1","destination":"archive","text":"手机 13812345678"}`)
		if strings.Contains(dropped, "ANONYMIZED") || strings.Contains(dropped, "13812345678") {
			t.Fatalf("archive 应切除：%s", dropped)
		}
		if !strings.Contains(dropped, `"drop":1`) {
			t.Fatalf("响应应带算子计数：%s", dropped)
		}
	})
}

// 没配矩阵时指定 destination 必须拒绝，不能静默忽略。
// Without a matrix, naming a destination must be rejected, not ignored.
//
// 静默忽略会让调用方以为归档链路的切除策略生效了，
// 实际上数据带着占位符原样发了出去 —— 占位符在归档场景里就是泄露。
// Silently ignoring it lets the caller believe the archive drop policy took
// effect while placeholders shipped instead — which in an archive is a leak.
func TestDestinationRejectedWithoutMatrix(t *testing.T) {
	ts := newMatrixTestServer(t, nil)
	code, body := ts.post(t, "/v1/redact",
		`{"session_id":"s1","destination":"archive","text":"手机 13812345678"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("应返回 400，实际 %d：%s", code, body)
	}
	t.Logf("按预期拒绝：%s", body)
}

// matrixTestServer 是带策略矩阵的测试服务器。
type matrixTestServer struct{ url string }

func newMatrixTestServer(t *testing.T, m *anonymize.Matrix) matrixTestServer {
	t.Helper()
	srv, err := New(Options{
		Detector:       packs.MustNewRegistry([]string{"GEN", "CN"}),
		FailClosed:     true,
		SessionTTL:     time.Hour,
		MaxSessions:    100,
		Matrix:         m,
		TokenStore:     anonymize.NewMemoryTokenStore(time.Hour),
		TenantResolver: mustStaticResolver(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return matrixTestServer{url: ts.URL}
}

func (m matrixTestServer) post(t *testing.T, path, body string) (int, string) {
	t.Helper()
	resp, err := http.Post(m.url+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// mustStaticResolver 供既有单租户用例使用。
// 这些用例测的不是隔离，因此显式声明「单租户」而不是把隔离关掉。
func mustStaticResolver(t *testing.T) TenantResolver {
	t.Helper()
	r, err := NewStaticTenantResolver("test")
	if err != nil {
		t.Fatal(err)
	}
	return r
}
