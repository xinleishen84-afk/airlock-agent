// Package integration 是网关的真实拓扑集成测试。
//
// # No-Mock 原则
//
// 这里不打桩任何 IO。测试在 Docker 沙箱里拉起真实的上游端点与 NER 服务，
// 网关二进制以真实进程运行，全程走真实 TCP。被验证的是完整的装配与
// 网络路径——连接池、SSE 解析、超时、失效转移——而不是被替换掉的接口。
//
// 单元测试里的 httptest.NewServer 已经是真实 HTTP 服务，但它与被测代码
// 同进程、同调度器。容器化拓扑多验证了三件事：跨进程的配置装配、
// 真实的网络栈行为（含 DNS、连接复用、TCP 断连），以及镜像本身可构建。
//
// # 环境要求
//
// 需要可用的 Docker（或兼容运行时）。无 Docker 时全部用例 SKIP，
// 而不是失败——本地开发不该被强制要求装 Docker。
package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// dockerSocketCandidates 是常见的容器运行时套接字位置。
//
// 必须先自己探测，不能直接调 testcontainers.NewDockerProvider()——
// 后者在找不到 Docker 时会**panic**（内部走 MustExtractDockerHost），
// 而不是返回 error。让本地开发者一跑测试就看到 panic 栈，
// 结果就是没人再跑集成测试了。
func dockerSocketCandidates() []string {
	home, _ := os.UserHomeDir()
	return []string{
		"/var/run/docker.sock",
		filepath.Join(home, ".docker/run/docker.sock"),     // Docker Desktop (macOS)
		filepath.Join(home, ".colima/default/docker.sock"), // Colima
		filepath.Join(home, ".rd/docker.sock"),             // Rancher Desktop
		filepath.Join(home, ".local/share/containers/podman/machine/podman.sock"),
	}
}

// dockerAvailable 判断是否存在可用的容器运行时。
func dockerAvailable() bool {
	if host := os.Getenv("DOCKER_HOST"); host != "" {
		return true
	}
	if host := os.Getenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE"); host != "" {
		return true
	}
	for _, path := range dockerSocketCandidates() {
		if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return true
		}
	}
	return false
}

// requireDocker 在无容器运行时时跳过用例。
//
// 跳过而非失败是刻意的：本地开发不该被强制要求装 Docker。
// CI 里通过设置 REQUIRE_INTEGRATION=1 把跳过变成失败，
// 确保集成测试不会因为环境问题被悄悄绕过。
func requireDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("SKIP_INTEGRATION") != "" {
		t.Skip("SKIP_INTEGRATION 已设置")
	}

	fail := os.Getenv("REQUIRE_INTEGRATION") != ""
	bail := func(format string, args ...any) {
		if fail {
			t.Fatalf("REQUIRE_INTEGRATION 已设置但环境不可用："+format, args...)
		}
		t.Skipf(format, args...)
	}

	if !dockerAvailable() {
		bail("未发现容器运行时（DOCKER_HOST 未设置且无已知套接字），跳过真实拓扑测试")
		return
	}

	// 套接字存在不等于运行时健康，仍需探活。
	// testcontainers 在若干路径上会 panic，此处统一收敛为跳过。
	var provider *testcontainers.DockerProvider
	err := func() (err error) {
		defer func() {
			if v := recover(); v != nil {
				err = fmt.Errorf("容器运行时初始化 panic: %v", v)
			}
		}()
		provider, err = testcontainers.NewDockerProvider()
		return err
	}()
	if err != nil {
		bail("容器运行时不可用: %v", err)
		return
	}
	defer provider.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := provider.Health(ctx); err != nil {
		bail("容器运行时不健康: %v", err)
	}
}

// Upstream 是一个运行中的假 vLLM 容器。
type Upstream struct {
	Container testcontainers.Container
	BaseURL   string // 形如 http://127.0.0.1:32768/v1
	rootURL   string
}

// startUpstream 构建并启动一个假 vLLM 容器。
//
// 直接从源码构建镜像而非拉现成镜像：这样 Dockerfile 本身也进了
// CI 的验证范围——一个构建不出来的镜像应该在这里就暴露。
func startUpstream(t *testing.T, ctx context.Context, env map[string]string) *Upstream {
	t.Helper()
	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    filepath.Join(".", "fakevllm"),
			Dockerfile: "Dockerfile",
			KeepImage:  true, // 复用镜像，避免每个用例重新构建
		},
		ExposedPorts: []string{"8000/tcp"},
		Env:          env,
		WaitingFor: wait.ForHTTP("/metrics").
			WithPort("8000/tcp").
			WithStartupTimeout(90 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	if err != nil {
		t.Fatalf("启动上游容器失败: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := c.MappedPort(ctx, "8000/tcp")
	if err != nil {
		t.Fatal(err)
	}
	root := fmt.Sprintf("http://%s:%s", host, port.Port())
	return &Upstream{Container: c, BaseURL: root + "/v1", rootURL: root}
}

// SetKV 调整容器内的 KV 缓存占用（千分数）。
func (u *Upstream) SetKV(t *testing.T, permille int) {
	t.Helper()
	u.control(t, fmt.Sprintf("/_control/kv?permille=%d", permille))
}

// FailNext 让接下来 n 个请求返回 5xx。
func (u *Upstream) FailNext(t *testing.T, n int) {
	t.Helper()
	u.control(t, fmt.Sprintf("/_control/fail?n=%d", n))
}

// LastBody 返回容器最近收到的请求体。
func (u *Upstream) LastBody(t *testing.T) string {
	t.Helper()
	return u.control(t, "/_control/last-body")
}

// control 调用容器的测试控制面。
func (u *Upstream) control(t *testing.T, path string) string {
	t.Helper()
	resp, err := http.Get(u.rootURL + path)
	if err != nil {
		t.Fatalf("调用容器控制面失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// Gateway 是一个运行中的网关进程。
type Gateway struct {
	Addr    string
	cmd     *exec.Cmd
	logPath string
}

// buildGateway 编译网关二进制。
//
// 每次测试都真实编译一遍：编译失败本身就是需要在集成阶段暴露的问题。
func buildGateway(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gateway")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/airlock-gateway")
	cmd.Dir = "../.."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("编译网关失败: %v\n%s", err, out)
	}
	return bin
}

// DryRun 以自检模式运行网关，返回退出码与输出。
func DryRun(t *testing.T, bin, configPath string, probe bool) (int, string) {
	t.Helper()
	args := []string{"--dry-run", "-config", configPath}
	if probe {
		args = append(args, "--probe")
	}
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()

	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("执行 dry-run 失败: %v", err)
	}
	return code, string(out)
}
