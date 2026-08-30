package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/xinleishen84-afk/airlock-agent/test/integration/chaos"
	"strings"
	"testing"
	"time"
)

// inspectSnapshot 拉取管理快照。
func inspectSnapshot(t *testing.T, addr string) map[string]any {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/v1/admin/inspect")
	if err != nil {
		t.Fatalf("拉取管理快照: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("解析管理快照: %v", err)
	}
	return doc
}

// TestAdminSnapshotIsPopulated 证明管理快照里的元数据真的被装配层填了。
// Proves the admin snapshot's metadata is actually populated by the assembly.
//
// # 库层测试再绿也证明不了这一点
// # No amount of green library tests can show this
//
// pii/audit 包齐备、测试全绿，sidecar.Options 有 Auditor / Fingerprinter /
// RosterSizes / RecognizerCatalog 四个字段——而 cmd/airlock-agent 的 main
// 一个都没赋值。实测真实二进制：/v1/admin/inspect 报 sink="none"、emitted=0，
// recognizers 与 jurisdictions 都是 null，而 README 的能力清单里写着
// 「不带原文的安全审计」。
//
// 同一个文件里的 Evidence 字段注释记着一模一样的事故：「验证器在测试里一直
// 接着，在真实二进制里从来没接上」。同类错误在同一处犯了两次，因为单元测试
// 各自装配自己那一份，装配层漏了什么它们全都发现不了。只有真跑二进制、
// 对着它自陈的能力拨测才能发现。
//
// The audit package was complete and green and Options had all four fields
// while main assigned none of them: the real binary reported sink="none" with
// zero events, a null recognizer catalog and null jurisdictions, while the
// README listed auditing as a capability. Unit tests each assemble their own
// wiring, so whatever the real assembly omits is invisible to all of them.
func TestAdminSnapshotIsPopulated(t *testing.T) {
	addr := binaryUnderTest(t, "airlock-agent",
		"--jurisdictions", "GEN,CN", "--single-tenant", "acme",
		"--session-consistency", "single-replica")

	snap := inspectSnapshot(t, addr)
	detection, _ := snap["detection"].(map[string]any)
	if detection == nil {
		t.Fatal("快照里没有 detection 段")
	}

	juris, _ := detection["jurisdictions"].([]any)
	if len(juris) == 0 {
		t.Error("快照里的 jurisdictions 为空——装配层没把国家包传进来，" +
			"运维无法核对「我以为装了的包在不在」")
	}

	recs, _ := detection["recognizers"].([]any)
	if len(recs) == 0 {
		t.Fatal("快照里的 recognizers 为空——识别器清单没被装配层填充。" +
			"「装了哪些包」与「这些包实际产出哪些识别器」是两件事：" +
			"包能注册、二进制能启动、请求能处理，而某个识别器从来匹配不到任何东西")
	}
	for i, r := range recs {
		rm, _ := r.(map[string]any)
		if s, _ := rm["name"].(string); s == "" {
			t.Errorf("第 %d 条识别器没有名字", i)
		}
		// entity_type 此前声明了却从未被赋值，快照里一直是空串
		if s, _ := rm["entity_type"].(string); s == "" {
			t.Errorf("识别器 %v 的 entity_type 为空——该字段声明了却没被赋值，"+
				"快照因此说不出每条识别器管的是哪类实体", rm["name"])
		}
	}
}

// TestAuditTrailOffIsAnnounced 证明不接审计轨迹时二进制会明确说出来。
// Proves a binary with no audit sink says so out loud.
//
// 不发审计事件是合法选择，但不能是「以为发了其实没发」。这一整块能力此前
// 在库里齐备、在二进制里一行都没接，而启动日志对此只字不提——运维看到的是
// 一个正常启动、正常处理请求的进程。
//
// Emitting nothing is a legitimate choice; believing you emit when you do not
// is not. The capability was previously absent with no startup log saying so.
func TestAuditTrailOffIsAnnounced(t *testing.T) {
	addr := binaryUnderTest(t, "airlock-agent",
		"--jurisdictions", "GEN,CN", "--single-tenant", "acme",
		"--session-consistency", "single-replica")

	snap := inspectSnapshot(t, addr)
	au, _ := snap["audit"].(map[string]any)
	if au == nil {
		t.Fatal("快照里没有 audit 段")
	}
	if sink, _ := au["sink"].(string); sink != "none" {
		t.Errorf("未配置 --audit-sink 时 sink 应为 none，实际 %q", sink)
	}
}

// TestAuditTrailEmitsWithoutPlaintext 证明接通后真的发事件，且事件里没有原文。
// Proves the trail emits once wired, and carries no plaintext.
//
// 审计事件的价值全在「能拿出证据」与「证据本身不是新的泄露渠道」这两点上。
// 会话标识常常就是用户邮箱——事件里必须是带密钥的摘要，不能是原值。
// 一个记下「脱敏了什么」的网关，是把 PII 搬了个地方而不是移除了它。
//
// The trail is worth having only if it is evidence and is not itself a leak.
// Session identifiers are often email addresses.
func TestAuditTrailEmitsWithoutPlaintext(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")
	// 32 字节下限由密钥环校验：派生密钥的强度不会超过根密钥
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("k", 48)), 0o600); err != nil {
		t.Fatal(err)
	}
	trailPath := filepath.Join(dir, "audit.jsonl")

	addr := binaryUnderTest(t, "airlock-agent",
		"--jurisdictions", "GEN,CN", "--single-tenant", "acme",
		"--session-consistency", "single-replica",
		"--audit-sink", trailPath, "--audit-key-file", keyPath)

	// 会话标识刻意用邮箱：它必须以摘要形式出现，不能原样落进轨迹
	const session = "zhangwei@acme.com"
	const secret = "13800138000"
	body := `{"session_id":"` + session + `","text":"手机 ` + secret + `"}`
	resp, err := http.Post("http://"+addr+"/v1/redact", "application/json",
		strings.NewReader(body))
	if err != nil {
		t.Fatalf("发起脱敏请求: %v", err)
	}
	_ = resp.Body.Close()

	raw, err := os.ReadFile(trailPath)
	if err != nil {
		t.Fatalf("读取审计轨迹（接通后应当有文件）: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("审计轨迹是空的——sink 接上了却没有事件落地")
	}
	trail := string(raw)
	for _, plain := range []string{secret, session} {
		if strings.Contains(trail, plain) {
			t.Errorf("审计轨迹里出现了原文 %q——事件本身成了泄露渠道", plain)
		}
	}

	var ev map[string]any
	if err := json.Unmarshal([]byte(strings.SplitN(trail, "\n", 2)[0]), &ev); err != nil {
		t.Fatalf("审计事件不是合法 JSON: %v", err)
	}
	if fp, _ := ev["session_fingerprint"].(string); fp == "" {
		t.Error("审计事件缺少 session_fingerprint——会话无法被追溯，证据链断了")
	}
	if _, ok := ev["entities"]; !ok {
		t.Error("审计事件缺少 entities 计数——拿不出「脱敏了多少」的证据")
	}
}

// TestAuditSinkWithoutKeyIsRefused 证明配了 sink 却没给密钥时启动即失败。
// Proves a sink without a key refuses to start.
//
// 无密钥的摘要可被穷举回原标识，而会话标识常常就是用户邮箱。此时「降级为
// 不发指纹」或「降级为记原文」都比启动失败更糟：前者让审计失去追溯能力，
// 后者让审计本身成为泄露渠道。
func TestAuditSinkWithoutKeyIsRefused(t *testing.T) {
	cmd := CommandNamed(t, "airlock-agent")
	bin := cmd.Build(t)
	out, err := runBinaryExpectingFailure(t, bin,
		"--addr", "127.0.0.1:0",
		"--jurisdictions", "GEN,CN", "--single-tenant", "acme",
		"--session-consistency", "single-replica",
		"--audit-sink", "stderr")
	if err == nil {
		t.Fatal("配了 --audit-sink 却没有 --audit-key-file 时应当启动失败")
	}
	if !strings.Contains(out, "audit-key-file") {
		t.Errorf("失败信息应指明缺少 --audit-key-file，实际：\n%s", out)
	}
}

// runBinaryExpectingFailure 启动二进制并期待它自行退出，返回它的输出。
// Runs a binary expecting it to exit on its own, returning its output.
//
// 用 cmd.Run 而不是 Start + Process.Wait：Stdout/Stderr 是 *bytes.Buffer 时
// os/exec 走管道加拷贝协程，只有 cmd.Wait 会 join 它们，绕过去读到的缓冲区
// 是「拷了多少算多少」且有数据竞争。这个坑在本仓库里踩过一次——被测进程
// 因缺必填配置启动即退出，测试报「未就绪」而日志转储是空的。
//
// cmd.Run rather than Start plus Process.Wait: with a *bytes.Buffer sink,
// os/exec copies through goroutines that only Wait joins. Bypassing them once
// produced an empty log dump at exactly the moment it was needed.
func runBinaryExpectingFailure(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// TestGatewayEmitsAuditTrail 证明网关这条脱敏路径也发审计事件。
// Proves the gateway's redaction path emits audit events too.
//
// # 网关是第三条脱敏路径
// # The gateway is a third redaction path
//
// 它不走 sidecar 包，自己在 internal/proxy 里做 redactBody / RestoreBody。
// 两个 sidecar 二进制接上审计之后，这条路径仍然一条事件都不发——而它照常在
// 真实流量上脱敏，PII 该换的都换了，只是没有任何记录。审计缺席不会有症状：
// 请求成功、脱敏生效、日志正常，唯独拿不出「这次请求处理了什么」的证据。
//
// 这条用例只能在二进制层写。库层测试会自己构造 Deps 并把 Auditor 填上，
// 于是测的是「补完接线之后的行为」——真实二进制漏没漏，它一无所知。
//
// It does not go through the sidecar package. With both sidecars wired, this
// path still emitted nothing while redacting real traffic: requests succeed,
// redaction works, logs look normal, and no evidence of what was processed
// exists. This can only be tested at the binary level — a library test supplies
// its own Deps with an Auditor and therefore measures wiring it added itself.
func TestGatewayEmitsAuditTrail(t *testing.T) {
	up := chaos.Start(chaos.DefaultConfig())
	defer up.Close()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("k", 48)), 0o600); err != nil {
		t.Fatal(err)
	}
	trailPath := filepath.Join(dir, "audit.jsonl")

	// 必须 always_redact：默认配置里上游是 self_hosted，脱敏按设计跳过
	// （自建后端在企业边界内），不脱敏自然也就没有审计事件——那样这条用例
	// 会因为前提不成立而绿，而不是因为接线正确而绿。
	//
	// always_redact is required: the default fixture's upstream is self_hosted,
	// so redaction is skipped by design and no event would be emitted — the
	// test would pass on a false premise rather than on correct wiring.
	gw := startGateway(t, writeAuditConfig(t, up.BaseURL()),
		"-audit-sink", trailPath, "-audit-key-file", keyPath)
	gw.waitReady(t, 20*time.Second)

	const session = "zhangwei@acme.com"
	const secret = "13800138000"
	req, err := http.NewRequest(http.MethodPost,
		gw.URL+"/v1/chat/completions",
		strings.NewReader(`{"stream":true,"messages":[{"role":"user","content":"联系`+secret+`"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Id", session)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求网关: %v\n网关日志：\n%s", err, gw.Logs())
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	raw, err := os.ReadFile(trailPath)
	if err != nil || len(raw) == 0 {
		t.Fatalf("网关没有产生审计轨迹——脱敏照常发生，但没有任何记录。"+
			"err=%v\n网关日志：\n%s", err, gw.Logs())
	}
	trail := string(raw)
	for _, plain := range []string{secret, session} {
		if strings.Contains(trail, plain) {
			t.Errorf("审计轨迹里出现了原文 %q——事件本身成了泄露渠道", plain)
		}
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(strings.SplitN(trail, "\n", 2)[0]), &ev); err != nil {
		t.Fatalf("审计事件不是合法 JSON: %v", err)
	}
	if fp, _ := ev["session_fingerprint"].(string); fp == "" {
		t.Error("事件缺少 session_fingerprint——会话无法被追溯")
	}
	ents, _ := ev["entities"].(map[string]any)
	if len(ents) == 0 {
		t.Error("事件里 entities 为空——脱敏发生了却没记下处理了什么")
	}
}

// writeAuditConfig 写一份会真正触发脱敏的网关配置。
func writeAuditConfig(t *testing.T, upstreamURL string) string {
	t.Helper()
	dir := t.TempDir()
	secretDir := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(secretDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "vendor-key"),
		[]byte("sk-audit-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`
secrets_mount_path: %s
targets:
  - name: audit-upstream
    tier: 2
    base_url: %s
    model: fixture
    self_hosted: true
rate_limit:
  tokens_per_window: 100000000
  window: 1m
pii:
  jurisdictions: [GEN, CN]
  session_consistency: single-replica
  fail_closed: true
  always_redact: true
gpu:
  kv_elevated: 0.75
  kv_critical: 0.90
  prefix_affinity: true
  probe_interval: 500ms
`, secretDir, upstreamURL)
	path := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
