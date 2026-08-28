package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/test/integration/chaos"
)

// gatewayProcess 是以真实子进程运行的网关。
//
// 必须是真实进程而不是同进程的 httptest：优雅停机的入口是 SIGTERM，
// 同进程测试只能手工调用内部函数，验不到信号处理、也验不到进程退出。
type gatewayProcess struct {
	URL     string
	cmd     *exec.Cmd
	logPath string
	t       *testing.T
}

// startGateway 编译并以子进程启动网关。
func startGateway(t *testing.T, cfgPath string, args ...string) *gatewayProcess {
	t.Helper()
	bin := buildGateway(t)

	port := freePort(t)
	logPath := filepath.Join(t.TempDir(), "gateway.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}

	full := append([]string{"-config", cfgPath, "-addr", fmt.Sprintf("127.0.0.1:%d", port)}, args...)
	cmd := exec.Command(bin, full...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	// 独立进程组：避免测试框架的信号影响到它，也便于精确投递 SIGTERM
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动网关失败: %v", err)
	}

	gw := &gatewayProcess{
		URL: fmt.Sprintf("http://127.0.0.1:%d", port),
		cmd: cmd, logPath: logPath, t: t,
	}
	t.Cleanup(func() {
		_ = logFile.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			// 必须是 cmd.Wait 而不是 cmd.Process.Wait：Stdout/Stderr 是
			// *bytes.Buffer 时 os/exec 走管道 + 拷贝协程，只有 cmd.Wait 会
			// join 它们。绕过去读到的缓冲区是「拷了多少算多少」，且有数据竞争。
			// 实测：被测进程因缺必填配置启动即退出，测试报「未在 N 秒内就绪」，
			// 而紧跟其后的日志转储是空的——唯一能解释原因的那段，恰好丢了。
			//
			// Must be cmd.Wait: with a *bytes.Buffer sink, os/exec copies through
			// goroutines that only cmd.Wait joins. Measured: a process exiting for
			// missing required config reported "not ready" with an empty log dump.
			_ = cmd.Wait()
		}
	})

	gw.waitReady(t, 15*time.Second)
	return gw
}

// waitReady 等待健康检查通过。
func (g *gatewayProcess) waitReady(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(g.URL + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if g.cmd.ProcessState != nil {
			t.Fatalf("网关进程已退出。日志：\n%s", g.Logs())
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("网关未在 %v 内就绪。日志：\n%s", timeout, g.Logs())
}

// SIGTERM 向网关投递终止信号。
func (g *gatewayProcess) SIGTERM() error { return g.cmd.Process.Signal(syscall.SIGTERM) }

// Wait 等待进程退出。
func (g *gatewayProcess) Wait(timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- g.cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("进程未在 %v 内退出", timeout)
	}
}

// Logs 返回网关日志。
func (g *gatewayProcess) Logs() string {
	data, _ := os.ReadFile(g.logPath)
	return string(data)
}

// freePort 取一个空闲端口。
func freePort(t *testing.T) int {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// streamResult 是一次流式请求的结果。
type streamResult struct {
	Tokens   []string
	GotDone  bool
	Err      error
	Duration time.Duration
}

// startStream 发起一条流式请求，在后台接收。
func startStream(gatewayURL string) (<-chan streamResult, error) {
	body := `{"model":"chaos","stream":true,"max_tokens":500,` +
		`"messages":[{"role":"user","content":"生成一段长文本"}]}`
	req, err := http.NewRequest(http.MethodPost, gatewayURL+"/v1/chat/completions",
		strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Workload-App", "toolbench-agent")
	req.Header.Set("X-Workload-Priority", "5")

	// 不设整体超时：长流本就该跑很久，超时会掐断我们要观察的对象
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("流式请求返回 %d", resp.StatusCode)
	}

	out := make(chan streamResult, 1)
	go func() {
		defer resp.Body.Close()
		start := time.Now()
		res := streamResult{}
		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				res.Err = err
				break
			}
			payload, ok := strings.CutPrefix(strings.TrimSpace(line), "data: ")
			if !ok {
				continue
			}
			if payload == "[DONE]" {
				res.GotDone = true
				break
			}
			var frame struct {
				Choices []struct {
					Delta struct {
						Content string `json:"content"`
					} `json:"delta"`
				} `json:"choices"`
			}
			if json.Unmarshal([]byte(payload), &frame) == nil &&
				len(frame.Choices) > 0 && frame.Choices[0].Delta.Content != "" {
				res.Tokens = append(res.Tokens, frame.Choices[0].Delta.Content)
			}
		}
		res.Duration = time.Since(start)
		out <- res
	}()
	return out, nil
}

// writeChaosConfig 生成指向混沌上游的网关配置。
func writeChaosConfig(t *testing.T, upstreamURL string) string {
	t.Helper()
	dir := t.TempDir()
	secretDir := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(secretDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "vendor-key"),
		[]byte("sk-chaos-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := fmt.Sprintf(`
secrets_mount_path: %s
targets:
  - name: chaos-upstream
    tier: 2
    base_url: %s
    model: chaos
    self_hosted: true
rate_limit:
  tokens_per_window: 100000000
  window: 1m
pii:
  jurisdictions: [GEN, CN]
  session_consistency: single-replica
  fail_closed: true
  name_roster: ["张伟"]
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

// ---------------------------------------------------------------------------
// 硬化后的优雅停机测试
// ---------------------------------------------------------------------------

// TestGracefulShutdownTrajectory 是三条硬化措施的合体验收。
//
//	措施一  发信号前强行核验 in_flight >= 1，为 0 则宣告测试无效
//	措施二  用混沌慢流制造宽阔且确定的 SIGTERM 轰炸窗口
//	措施三  验证完整的收敛轨迹，而非只看 abandoned=0 这个终态
//
// 这三条共同封死了「静默通过」：没有在途流时测试会响亮地失败，
// 而不是报一个毫无意义的绿。
func TestGracefulShutdownTrajectory(t *testing.T) {
	cfg := chaos.DefaultConfig()
	up := chaos.Start(cfg)
	defer up.Close()
	t.Logf("混沌上游就绪：%.1f token/s × %d = 轰炸窗口 %v",
		cfg.TokensPerSecond, cfg.TotalTokens, cfg.Window())

	gw := startGateway(t, writeChaosConfig(t, up.BaseURL()),
		"--drain-period", "2s", "--grace-period", "20s", "--log-level", "info")

	// ---- 起一条慢流 ----
	stream, err := startStream(gw.URL)
	if err != nil {
		t.Fatalf("发起流式请求失败: %v", err)
	}

	// ---- 措施一：硬断言在途流存在 ----
	//
	// 这是整个测试的有效性前提。检测不到在途流就直接判定本次运行无效，
	// 绝不允许它以 abandoned=0 静默通过。
	pre := MustHaveInFlight(t, gw.URL, 1, 10*time.Second)
	t.Logf("信号前核验通过：%s", pre)
	if pre.PhaseID != phaseServing {
		t.Fatalf("信号前阶段应为 serving，实际 %s", phaseName(pre.PhaseID))
	}

	// ---- 措施三：开始采样轨迹 ----
	var wg sync.WaitGroup
	var traj *Trajectory
	wg.Add(1)
	go func() {
		defer wg.Done()
		traj = SampleUntilDown(gw.URL, 100*time.Millisecond, 40*time.Second)
	}()

	// 让轨迹先记录若干个 serving 阶段的样本
	time.Sleep(600 * time.Millisecond)

	// ---- 投递 SIGTERM ----
	t.Log("投递 SIGTERM（此时流正在吐字）")
	if err := gw.SIGTERM(); err != nil {
		t.Fatalf("发送信号失败: %v", err)
	}

	// ---- 排空阶段：新请求应仍被接受 ----
	//
	// 此刻 LB 大概率还没摘掉本实例，拒绝会制造本可避免的错误。
	// 用非流式探测：慢流探测一超时就会在上游留下 truncated 记录，
	// 把测试自身的产物混进被测对象的统计里。
	drainStatus := probeOnce(t, gw.URL, false)
	if drainStatus != http.StatusOK {
		t.Errorf("排空阶段新请求应被正常服务，实际 HTTP %d——"+
			"过早拒绝会在 LB 摘除生效前制造本可避免的错误", drainStatus)
	}

	// ---- 等待进入收敛阶段 ----
	waitForPhase(t, gw.URL, phaseClosing, 10*time.Second)

	// ---- 收敛阶段持续打新请求，制造被拒计数 ----
	//
	// 轨迹验证要求「拒绝计数上涨」。不主动打请求的话，
	// 停机期间恰好没有新流量，这条断言就永远验证不到。
	// 此阶段的请求在网关侧就被 503 挡下，不会抵达上游。
	probeStop := make(chan struct{})
	var probeRejected int
	var probeMu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-probeStop:
				return
			case <-time.After(300 * time.Millisecond):
				if probeOnce(t, gw.URL, false) == http.StatusServiceUnavailable {
					probeMu.Lock()
					probeRejected++
					probeMu.Unlock()
				}
			}
		}
	}()

	// ---- 存量流必须完整吐完 ----
	var res streamResult
	select {
	case res = <-stream:
	case <-time.After(40 * time.Second):
		t.Fatal("存量流未在预期时间内结束")
	}
	close(probeStop)
	probeMu.Lock()
	rejectedCount := probeRejected
	probeMu.Unlock()
	if rejectedCount == 0 {
		t.Error("收敛阶段的探测请求全部未被拒绝——「拒绝新入站」未被证明发生")
	}

	if !res.GotDone {
		t.Errorf("存量流未收到 [DONE]，说明被强制中断。已收 %d/%d 个 token，err=%v",
			len(res.Tokens), cfg.TotalTokens, res.Err)
	}
	if len(res.Tokens) != cfg.TotalTokens {
		t.Errorf("存量流应完整吐出 %d 个 token，实际 %d 个：%v",
			cfg.TotalTokens, len(res.Tokens), res.Tokens)
	}

	// ---- 进程应自行退出 ----
	exited := gw.Wait(30*time.Second) == nil
	if !exited {
		t.Error("网关未自行退出")
	}
	wg.Wait()

	// ---- 措施三：验证收敛轨迹 ----
	t.Logf("停机轨迹（%d 个采样）：\n%s", len(traj.Samples), traj.Dump())
	traj.AssertConvergence(t, ConvergenceEvidence{
		StreamCompleted:   res.GotDone && len(res.Tokens) == cfg.TotalTokens,
		UpstreamTruncated: up.Truncated(),
		GatewayExited:     exited,
	})

	// ---- 与上游视角对账 ----
	//
	// 上游看到的 truncated 与网关侧的 abandoned 应当吻合。
	// 两边对不上说明有一侧的统计漏了——那会让运维依据错误的数字调窗口。
	// 上游不应看到任何被截断的流：主流完整收尾，排空期的探测是非流式的，
	// 收敛期的探测在网关侧就被挡下、根本没抵达上游。
	// 两边对不上说明有一侧的统计漏了——运维会据此调错窗口。
	if up.Truncated() != 0 {
		t.Errorf("上游观察到 %d 条被截断的流，与「优雅停机」矛盾", up.Truncated())
	}
	// 1 条主流 + 1 次排空期非流式探测
	if up.Completed() != 2 {
		t.Errorf("上游应看到 2 条完整响应（主流 + 排空期探测），实际 %d", up.Completed())
	}

	if !strings.Contains(gw.Logs(), "全部在途流已优雅收尾") {
		t.Errorf("日志中未见优雅收尾记录：\n%s", gw.Logs())
	}
}

// TestShutdownWithoutInFlightIsDeclaredInvalid 验证硬化措施一本身有效。
//
// 这是「测试的测试」：故意在没有在途流时核验，MustHaveInFlight
// 必须响亮地失败。若它能通过，说明措施一形同虚设，
// 真正的停机测试又会退回到静默通过的老路。
func TestShutdownWithoutInFlightIsDeclaredInvalid(t *testing.T) {
	up := chaos.Start(chaos.DefaultConfig())
	defer up.Close()
	gw := startGateway(t, writeChaosConfig(t, up.BaseURL()), "--log-level", "error")

	// 不发起任何流，直接核验——应当失败
	fake := &testing.T{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { recover() }() // t.Fatalf 在非测试 goroutine 里会 panic
		MustHaveInFlight(fake, gw.URL, 1, 1500*time.Millisecond)
	}()
	<-done

	if !fake.Failed() {
		t.Error("无在途流时 MustHaveInFlight 必须判定测试无效——" +
			"否则停机测试会退回到 abandoned=0 静默通过的老路")
	}
}

// probeOnce 发起一次探测请求，返回 HTTP 状态码。
//
// streaming=false 时走非流式路径：上游立刻返回完整 JSON，
// 不会在上游留下截断记录，因此可以安全地用于排空阶段的探测。
func probeOnce(t *testing.T, gatewayURL string, streaming bool) int {
	t.Helper()
	body := fmt.Sprintf(`{"model":"chaos","stream":%t,"max_tokens":16,`+
		`"messages":[{"role":"user","content":"探测"}]}`, streaming)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(gatewayURL+"/v1/chat/completions",
		"application/json", strings.NewReader(body))
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// waitForPhase 等待网关进入指定阶段。
func waitForPhase(t *testing.T, gatewayURL string, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last Metrics
	for time.Now().Before(deadline) {
		m, err := scrapeMetrics(gatewayURL)
		if err == nil {
			last = m
			if m.PhaseID >= want {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("网关未在 %v 内进入 %s 阶段（最后观察到 %s）",
		timeout, phaseName(want), last)
}
