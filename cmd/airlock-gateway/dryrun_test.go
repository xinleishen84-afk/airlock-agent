package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// baseYAML 是一份完整可用的配置模板，各用例在其上注入单点缺陷。
//
// 用 YAML 文本而非结构体：测试要验证的正是**解析层**，
// 从结构体序列化出来的配置永远是合法的，测不出拼写错误这类问题。
const baseYAML = `
secrets_mount_path: __SECRETS__
session_ttl: 1h
targets:
  - name: t1
    tier: 1
    base_url: http://127.0.0.1:19001/v1
    model: premium
    weight: 100
    credential_key: vendor-key
    input_price_per_mtok: 5.0
    output_price_per_mtok: 25.0
  - name: t2
    tier: 2
    base_url: http://127.0.0.1:19002/v1
    model: gpt-oss-120b
    weight: 100
    self_hosted: true
rules:
  - name: batch
    target_tier: 2
    priority: 10
    match_apps: ["toolbench-agent"]
rate_limit:
  tokens_per_window: 1000000
  window: 1m
pii:
  jurisdictions: [GEN, CN]
  fail_closed: true
  name_roster: ["张伟"]
  org_roster: ["星辰科技"]
  ner:
    endpoint: http://127.0.0.1:19100/v1/detect
gpu:
  kv_elevated: 0.75
  kv_critical: 0.90
  prefix_affinity: true
  affinity_load_factor: 1.25
`

// writeScenario 把配置与密钥写进临时目录，返回配置路径。
// mutate 直接改 YAML 文本，以便注入拼写错误这类只有解析层能发现的问题。
func writeScenario(t *testing.T, mutate func(string) string, secrets map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	secretDir := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(secretDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for k, v := range secrets {
		if err := os.WriteFile(filepath.Join(secretDir, k), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	body := strings.Replace(baseYAML, "__SECRETS__", secretDir, 1)
	if mutate != nil {
		body = mutate(body)
	}
	path := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// run 执行自检并返回报告。
func run(t *testing.T, path string) *Report {
	t.Helper()
	return RunDryRun(DryRunOptions{ConfigPath: path, CgroupRoot: t.TempDir()})
}

// find 取出指定检查项的结果。
func find(t *testing.T, rep *Report, name string) CheckResult {
	t.Helper()
	for _, r := range rep.Results {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("报告中不存在检查项 %q，实际项：%v", name, names(rep))
	return CheckResult{}
}

// assertFailsWith 断言自检失败，且报告中能找到指定线索。
//
// 不钉死具体检查项：校验可能在解析阶段完成，也可能在装配阶段完成，
// 两者都是正确的拦截。测试该关心的是「拦住了没有」与「原因说清楚了没有」，
// 而不是「在第几步拦住的」——后者会让每次内部重构都误伤一批用例。
func assertFailsWith(t *testing.T, rep *Report, clue string) {
	t.Helper()
	if !rep.Failed() {
		t.Fatalf("配置应被拒绝，实际全部通过。报告项：%v", names(rep))
	}
	for _, r := range rep.Results {
		if r.Status == StatusFail && strings.Contains(r.Detail, clue) {
			return
		}
	}
	var details []string
	for _, r := range rep.Results {
		if r.Status == StatusFail {
			details = append(details, r.Name+": "+r.Detail)
		}
	}
	t.Errorf("报错中应含线索 %q，实际失败项：\n  %s", clue, strings.Join(details, "\n  "))
}

// names 列出报告中的全部检查项名。
func names(rep *Report) []string {
	out := make([]string, 0, len(rep.Results))
	for _, r := range rep.Results {
		out = append(out, r.Name)
	}
	return out
}

// TestHealthyConfigPasses 校验完整配置全部通过且退出码为 0。
func TestHealthyConfigPasses(t *testing.T) {
	path := writeScenario(t, nil, map[string]string{"vendor-key": "sk-ENTERPRISE"})
	rep := run(t, path)

	if rep.Failed() {
		for _, r := range rep.Results {
			if r.Status == StatusFail {
				t.Errorf("健康配置不应失败：%s — %s", r.Name, r.Detail)
			}
		}
	}
	if exitCodeFor(rep) != 0 {
		t.Errorf("健康配置的退出码应为 0，实际 %d", exitCodeFor(rep))
	}
}

// TestTypoInConfigKeyBlocksDeploy 校验拼错的配置键会挂红。
//
// 这是 dry-run 最直接的价值：拼错的键若被静默忽略，
// 「我明明配了限流」会变成生产上最难查的一类事故。
func TestTypoInConfigKeyBlocksDeploy(t *testing.T) {
	path := writeScenario(t, func(y string) string {
		return strings.Replace(y, "tokens_per_window:", "token_per_window:", 1) // 少个 s
	}, map[string]string{"vendor-key": "sk-X"})

	rep := run(t, path)
	if !rep.Failed() {
		t.Fatal("拼错的配置键必须让自检失败，否则会被静默忽略")
	}
	if got := find(t, rep, "配置解析"); got.Status != StatusFail {
		t.Errorf("应在配置解析阶段就被拒绝，实际 %s", got.Status)
	}
	if !strings.Contains(find(t, rep, "配置解析").Detail, "token_per_window") {
		t.Errorf("错误信息应指出具体是哪个键：%s", find(t, rep, "配置解析").Detail)
	}
}

// TestMissingSecretBlocksDeploy 校验密钥缺失会挂红。
//
// 零信任下凭证读不到就必须阻断请求。这类故障应该在部署前发现，
// 而不是在第一个线上请求上。
func TestMissingSecretBlocksDeploy(t *testing.T) {
	path := writeScenario(t, nil, map[string]string{}) // 不写任何密钥
	assertFailsWith(t, run(t, path), "密钥")
}

// TestEmptySecretBlocksDeploy 校验空密钥文件会挂红。
// 挂载存在但内容为空是很常见的一种半配置状态。
func TestEmptySecretBlocksDeploy(t *testing.T) {
	path := writeScenario(t, nil, map[string]string{"vendor-key": "   \n"})
	rep := run(t, path)
	assertFailsWith(t, rep, "为空")
}

// TestDuplicateBackendNameBlocksDeploy 校验后端名重复会挂红。
func TestDuplicateBackendNameBlocksDeploy(t *testing.T) {
	path := writeScenario(t, func(y string) string {
		return strings.Replace(y, "  - name: t2", "  - name: t1", 1)
	}, map[string]string{"vendor-key": "sk-X"})

	assertFailsWith(t, run(t, path), "重复")
}

// TestRuleReferencingUnknownBackendBlocksDeploy 校验规则引用不存在的后端会挂红。
func TestRuleReferencingUnknownBackendBlocksDeploy(t *testing.T) {
	path := writeScenario(t, func(y string) string {
		return strings.Replace(y, "    priority: 10",
			"    priority: 10\n    prefer_targets: [\"不存在的后端\"]", 1)
	}, map[string]string{"vendor-key": "sk-X"})

	assertFailsWith(t, run(t, path), "不存在的后端")
}

// TestInvalidGlobBlocksDeploy 校验非法 glob 模式会挂红。
// 若不在装配期编译，非法模式会在运行时静默失配——规则形同虚设。
func TestInvalidGlobBlocksDeploy(t *testing.T) {
	path := writeScenario(t, func(y string) string {
		return strings.Replace(y, `["toolbench-agent"]`, `["[未闭合"]`, 1)
	}, map[string]string{"vendor-key": "sk-X"})

	assertFailsWith(t, run(t, path), "glob")
}

// TestInvertedKVThresholdsBlockDeploy 校验 KV 阈值倒置会挂红。
func TestInvertedKVThresholdsBlockDeploy(t *testing.T) {
	path := writeScenario(t, func(y string) string {
		return strings.NewReplacer(
			"kv_elevated: 0.75", "kv_elevated: 0.95",
			"kv_critical: 0.90", "kv_critical: 0.70").Replace(y)
	}, map[string]string{"vendor-key": "sk-X"})

	assertFailsWith(t, run(t, path), "kv_critical")
}

// TestPIICoverageGapWarns 校验 PII 覆盖缺口只告警不阻断。
//
// 缺口是配置选择而非配置错误——有的部署确实只需要正则覆盖。
// 但必须让运维在部署前看见，而不是等出事才知道。
func TestPIICoverageGapWarns(t *testing.T) {
	path := writeScenario(t, func(y string) string {
		return strings.NewReplacer(
			`  name_roster: ["张伟"]`, "",
			`  org_roster: ["星辰科技"]`, "",
			"  ner:\n    endpoint: http://127.0.0.1:19100/v1/detect", "").Replace(y)
	}, map[string]string{"vendor-key": "sk-X"})

	rep := run(t, path)
	got := find(t, rep, "PII 检测器装配")
	if got.Status != StatusWarn {
		t.Errorf("覆盖缺口应告警而非阻断，实际 %s", got.Status)
	}
	if !strings.Contains(got.Detail, "裸奔") {
		t.Errorf("告警应说清后果：%s", got.Detail)
	}
	if rep.Failed() {
		t.Error("仅有覆盖缺口时不应阻断部署")
	}
}

// TestPrefixAffinityDisabledWarns 校验关闭前缀亲和会告警。
func TestPrefixAffinityDisabledWarns(t *testing.T) {
	path := writeScenario(t, func(y string) string {
		return strings.Replace(y, "prefix_affinity: true", "prefix_affinity: false", 1)
	}, map[string]string{"vendor-key": "sk-X"})

	got := find(t, run(t, path), "前缀亲和环")
	if got.Status != StatusWarn {
		t.Errorf("关闭前缀亲和应告警，实际 %s", got.Status)
	}
}

// TestMissingConfigFileSkipsDownstream 校验配置文件不存在时下游检查标记为 SKIP。
// 不应产生一堆无意义的连锁失败，那会淹没真正的根因。
func TestMissingConfigFileSkipsDownstream(t *testing.T) {
	rep := RunDryRun(DryRunOptions{ConfigPath: "/nonexistent/gateway.json"})
	if find(t, rep, "配置解析").Status != StatusFail {
		t.Error("配置文件不存在应失败")
	}
	skipped := 0
	for _, r := range rep.Results {
		if r.Status == StatusSkip {
			skipped++
		}
	}
	if skipped < 5 {
		t.Errorf("下游检查应标记为 SKIP 而非连锁失败，实际仅 %d 项", skipped)
	}
}

// TestSanitizerSelfCheckDetectsBreakage 校验脱敏自检本身有效。
//
// 这一项守的是「一次错误合并让脱敏静默失效」——请求照常通过，
// PII 直接出境，没有任何报错。自检必须能在启动时拦住它。
func TestSanitizerSelfCheckDetectsBreakage(t *testing.T) {
	// 正常情况下应通过
	path := writeScenario(t, nil, map[string]string{"vendor-key": "sk-X"})
	if find(t, run(t, path), "AST 脱敏路径自检").Status != StatusPass {
		t.Fatal("正常配置下脱敏自检应通过")
	}

	// 直接验证核对函数能识别被破坏的结果
	var doc map[string]any
	json.Unmarshal([]byte(canonicalRequest), &doc)
	// 只净化正文，故意漏掉工具描述——模拟规则被误删
	msgs := doc["messages"].([]any)
	msgs[0].(map[string]any)["content"] = "REDACTED"
	if verifySanitized(doc) == "" {
		t.Error("漏净化工具描述时，自检应报错——否则脱敏失效无人察觉")
	}
}

// TestReportJSONOutput 校验 JSON 报告可被 CI 解析。
func TestReportJSONOutput(t *testing.T) {
	path := writeScenario(t, nil, map[string]string{"vendor-key": "sk-X"})
	rep := run(t, path)

	var buf strings.Builder
	if err := rep.WriteJSON(&buf); err != nil {
		t.Fatalf("JSON 输出失败: %v", err)
	}
	var parsed struct {
		OK      bool `json:"ok"`
		Results []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &parsed); err != nil {
		t.Fatalf("报告不是合法 JSON: %v", err)
	}
	if len(parsed.Results) < 10 {
		t.Errorf("报告项过少：%d", len(parsed.Results))
	}
	if parsed.OK != !rep.Failed() {
		t.Error("JSON 的 ok 字段与报告结论不一致")
	}
}

// TestSecretsNeverAppearInReport 校验报告中绝不出现凭证明文。
// 报告会进 CI 日志并长期归档，泄露一次就是永久泄露。
func TestSecretsNeverAppearInReport(t *testing.T) {
	const secret = "sk-SUPER-SECRET-VALUE-9f3a"
	path := writeScenario(t, nil, map[string]string{"vendor-key": secret})
	rep := run(t, path)

	var buf strings.Builder
	rep.WriteText(&buf)
	rep.WriteJSON(&buf)
	if strings.Contains(buf.String(), secret) {
		t.Error("凭证明文出现在自检报告中——CI 日志会长期归档，这是永久泄露")
	}
}

// TestDryRunStartsNoListener 校验 dry-run 不占用端口、不留后台协程。
//
// 若 dry-run 真的起了监听或探测协程，CI 里并行跑多个用例会互相抢端口，
// 表现为随机失败——这类问题极难定位。
func TestDryRunStartsNoListener(t *testing.T) {
	path := writeScenario(t, nil, map[string]string{"vendor-key": "sk-X"})

	before := runtimeGoroutines()
	run(t, path)
	// 给可能泄漏的协程一点退出时间
	time.Sleep(100 * time.Millisecond)
	after := runtimeGoroutines()

	// 允许少量波动（测试框架自身的协程），但不应显著增长
	if after > before+3 {
		t.Errorf("dry-run 泄漏了后台协程：%d -> %d", before, after)
	}
}

// runtimeGoroutines 返回当前协程数。
func runtimeGoroutines() int { return runtime.NumGoroutine() }
