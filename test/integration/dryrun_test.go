package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeConfig 生成一份指向给定上游的网关配置。
func writeConfig(t *testing.T, upstreamURL, nerURL string, mutate func(map[string]any)) string {
	t.Helper()
	dir := t.TempDir()
	secretDir := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(secretDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "vendor-api-key"),
		[]byte("sk-integration-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := map[string]any{
		"secrets_mount_path": secretDir,
		"session_ttl":        int64(time.Hour),
		"targets": []any{map[string]any{
			"name": "upstream", "tier": 2, "base_url": upstreamURL,
			"model": "fake", "weight": 100, "self_hosted": false,
			"credential_key": "vendor-api-key",
		}},
		"rate_limit": map[string]any{
			"tokens_per_window": 10_000_000, "window": int64(time.Minute),
		},
		"pii": map[string]any{
			"fail_closed": true,
			"name_roster": []any{"张伟"},
			"org_roster":  []any{"星辰科技"},
		},
		"gpu": map[string]any{
			"kv_elevated": 0.75, "kv_critical": 0.90,
			"prefix_affinity": true, "affinity_load_factor": 1.25,
			"probe_interval": int64(300 * time.Millisecond),
		},
	}
	if nerURL != "" {
		cfg["pii"].(map[string]any)["ner"] = map[string]any{
			"endpoint": nerURL, "timeout": int64(time.Second),
		}
	}
	if mutate != nil {
		mutate(cfg)
	}

	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestDryRunAgainstRealUpstream 验证装配层能连上真实容器里的上游。
//
// 这是单元测试覆盖不到的部分：配置里的 base_url 推导出的 /metrics 路径
// 是否正确、真实网络栈上的握手是否成功、指标格式是否符合解析预期。
// 这三样任何一个错了，网关都能正常启动，只是显存保护静默失效。
func TestDryRunAgainstRealUpstream(t *testing.T) {
	requireDocker(t)
	ctx := context.Background()

	up := startUpstream(t, ctx, nil)
	bin := buildGateway(t)
	cfg := writeConfig(t, up.BaseURL, "", nil)

	code, out := DryRun(t, bin, cfg, true)
	if code != 0 {
		t.Fatalf("对真实上游的自检应通过，退出码 %d：\n%s", code, out)
	}
	if !strings.Contains(out, "上游连通性") || !strings.Contains(out, "PASS") {
		t.Errorf("报告应包含上游连通性检查：\n%s", out)
	}
}

// TestDryRunDetectsUnreachableUpstream 验证上游不可达时自检挂红。
//
// 用真实容器验证的意义：容器停掉后是真实的 TCP 连接被拒，
// 而不是被打桩函数返回的假错误。
func TestDryRunDetectsUnreachableUpstream(t *testing.T) {
	requireDocker(t)
	ctx := context.Background()

	up := startUpstream(t, ctx, nil)
	bin := buildGateway(t)
	cfg := writeConfig(t, up.BaseURL, "", nil)

	// 先确认通得过
	if code, out := DryRun(t, bin, cfg, true); code != 0 {
		t.Fatalf("容器运行时自检应通过：\n%s", out)
	}

	// 停掉容器，制造真实的连接失败
	if err := up.Container.Stop(ctx, nil); err != nil {
		t.Fatalf("停止容器失败: %v", err)
	}

	code, out := DryRun(t, bin, cfg, true)
	if code == 0 {
		t.Errorf("上游不可达时自检必须挂红：\n%s", out)
	}
	if !strings.Contains(out, "上游连通性") {
		t.Errorf("报告应指明是连通性问题：\n%s", out)
	}
}

// TestDryRunWithoutProbeIgnoresUnreachableUpstream 验证不带 --probe 时
// 网络不可达不影响装配判定。
//
// CI 环境通常触达不到生产后端，把网络可达性当作装配失败会让流水线
// 在完全正确的配置上误报红——那样的红灯很快就没人看了。
func TestDryRunWithoutProbeIgnoresUnreachableUpstream(t *testing.T) {
	requireDocker(t)
	bin := buildGateway(t)
	// 指向一个确定不存在的地址
	cfg := writeConfig(t, "http://127.0.0.1:1/v1", "", nil)

	code, out := DryRun(t, bin, cfg, false)
	if code != 0 {
		t.Errorf("不带 --probe 时不应因网络不可达而失败：\n%s", out)
	}
	if !strings.Contains(out, "SKIP") {
		t.Errorf("上游连通性应标记为 SKIP：\n%s", out)
	}
}

// TestDryRunCatchesBrokenConfigAgainstRealTopology 验证真实拓扑下
// 配置缺陷依然被拦住——装配检查不因外部依赖健康而放松。
func TestDryRunCatchesBrokenConfigAgainstRealTopology(t *testing.T) {
	requireDocker(t)
	ctx := context.Background()

	up := startUpstream(t, ctx, nil)
	bin := buildGateway(t)

	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"配置键拼错", func(c map[string]any) {
			rl := c["rate_limit"].(map[string]any)
			rl["token_per_window"] = rl["tokens_per_window"]
			delete(rl, "tokens_per_window")
		}},
		{"密钥路径错误", func(c map[string]any) {
			c["secrets_mount_path"] = "/definitely/not/here"
		}},
		{"KV 阈值倒置", func(c map[string]any) {
			g := c["gpu"].(map[string]any)
			g["kv_elevated"], g["kv_critical"] = 0.95, 0.70
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := writeConfig(t, up.BaseURL, "", tc.mutate)
			code, out := DryRun(t, bin, cfg, true)
			if code == 0 {
				t.Errorf("%s 应让自检挂红：\n%s", tc.name, out)
			}
		})
	}
}
