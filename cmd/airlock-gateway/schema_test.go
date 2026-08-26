package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xinleishen84-afk/airlock-agent/internal/config"
)

// TestCRDInSyncWithCode 校验仓库里的 CRD 与代码生成结果一致。
//
// 手写或手工同步的 CRD 会和 Go 结构体漂移，两个方向都很难察觉：
//
//	加字段忘了同步 → APIServer 拒绝一个完全合法的配置
//	删字段忘了同步 → APIServer 放行一个网关不认识的字段
//
// 本用例让漂移在 CI 就被拦下。修法：`go run ./cmd/airlock-gateway --print-crd > configs/airlockconfig-crd.yaml`
func TestCRDInSyncWithCode(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "airlockconfig-crd.yaml")
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 CRD 失败（是否忘了生成？）：%v", err)
	}
	generated, err := config.GenerateCRD(config.DefaultCRDOptions())
	if err != nil {
		t.Fatalf("生成 CRD 失败: %v", err)
	}
	if string(onDisk) != string(generated) {
		t.Errorf("configs/airlockconfig-crd.yaml 与代码不一致。\n" +
			"schema 已漂移，APIServer 侧的拦截会与网关实际接受的字段对不上。\n" +
			"修法：go run ./cmd/airlock-gateway --print-crd > configs/airlockconfig-crd.yaml")
	}
}

// TestShippedConfigPassesDryRun 校验仓库里的示例配置能通过自检。
//
// 示例配置是使用者的第一印象。它自己都过不了自检，
// 说明配置格式已经变了而示例没跟上。
func TestShippedConfigPassesDryRun(t *testing.T) {
	secretDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(secretDir, "vendor-api-key"),
		[]byte("sk-test-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "configs", "gateway.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// 把密钥路径指向临时目录，其余保持原样
	patched := filepath.Join(t.TempDir(), "gateway.yaml")
	body := string(raw)
	body = replaceSecretsPath(body, secretDir)
	if err := os.WriteFile(patched, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	rep := RunDryRun(DryRunOptions{ConfigPath: patched, CgroupRoot: t.TempDir()})
	if rep.Failed() {
		for _, r := range rep.Results {
			if r.Status == StatusFail {
				t.Errorf("示例配置未通过自检：%s — %s", r.Name, r.Detail)
			}
		}
	}
}

// replaceSecretsPath 替换配置里的密钥挂载路径。
func replaceSecretsPath(body, dir string) string {
	out := ""
	for _, line := range splitLines(body) {
		if len(line) > 20 && line[:19] == "secrets_mount_path:" {
			out += "secrets_mount_path: " + dir + "\n"
			continue
		}
		out += line + "\n"
	}
	return out
}

// splitLines 按行切分，不保留行尾换行。
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
