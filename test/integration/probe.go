package integration

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Metrics 是网关 /metrics 端点的一次采样。
type Metrics struct {
	At               time.Time
	PhaseID          int
	InFlight         int64
	Streaming        int64
	ShutdownRejected int64
	Requests         int64
	Rejected         int64
}

// 阶段编号，与 internal/lifecycle.Phase 对应。
const (
	phaseServing  = 0
	phaseDraining = 1
	phaseClosing  = 2
	phaseStopped  = 3
)

// phaseName 返回阶段名。
func phaseName(id int) string {
	switch id {
	case phaseServing:
		return "serving"
	case phaseDraining:
		return "draining"
	case phaseClosing:
		return "closing"
	case phaseStopped:
		return "stopped"
	}
	return "unknown"
}

// String 返回可读表示，用于断言失败时输出轨迹。
func (m Metrics) String() string {
	return fmt.Sprintf("phase=%-8s in_flight=%d streaming=%d shutdown_rejected=%d",
		phaseName(m.PhaseID), m.InFlight, m.Streaming, m.ShutdownRejected)
}

// scrapeClient 复用连接。每次采样新建连接会在 200ms 间隔下
// 制造大量 TIME_WAIT，本身就可能成为采样失败的原因。
var scrapeClient = &http.Client{
	Timeout: 2 * time.Second,
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	},
}

// scrapeMetrics 拉取一次指标。
func scrapeMetrics(url string) (Metrics, error) {
	m := Metrics{At: time.Now()}
	client := scrapeClient
	resp, err := client.Get(url + "/metrics")
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return m, fmt.Errorf("指标端点返回 %d", resp.StatusCode)
	}

	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		name, value, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			continue
		}
		switch name {
		case "gateway_phase_id":
			m.PhaseID = int(n)
		case "gateway_in_flight":
			m.InFlight = n
		case "gateway_streaming":
			m.Streaming = n
		case "gateway_shutdown_rejected_total":
			m.ShutdownRejected = n
		case "gateway_requests_total":
			m.Requests = n
		case "gateway_rejected_total":
			m.Rejected = n
		}
	}
	return m, sc.Err()
}

// MustHaveInFlight 是硬化措施一：在途流断言限制。
//
// 停机测试最危险的失败模式不是「测出问题」，而是**静默通过**：
// 若 SIGTERM 到达时根本没有在途流，abandoned 必然为 0，
// 测试报绿，却什么都没验证。我第一次实测就是这样过的。
//
// 因此在发信号前必须强行核验并发流指标。检测到 in_flight == 0 时
// 直接宣告本次测试无效并中止——绝不允许它静默通过。
func MustHaveInFlight(t *testing.T, gatewayURL string, want int64, timeout time.Duration) Metrics {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var last Metrics
	var lastErr error
	for time.Now().Before(deadline) {
		m, err := scrapeMetrics(gatewayURL)
		if err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		last = m
		if m.Streaming >= want {
			return m
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("测试无效：等待 %v 后在途流仍未达到 %d 条（最后一次采样 %s，err=%v）。\n"+
		"  在没有在途流的情况下发送 SIGTERM，abandoned 必然为 0——\n"+
		"  测试会静默通过却什么都没验证。本次运行判定为无效，而非通过。",
		timeout, want, last, lastErr)
	return Metrics{}
}

// Trajectory 是停机期间的指标轨迹。
type Trajectory struct {
	Samples []Metrics
	// StopReason 记录采样为何终止。
	// 不记录的话，一条过早结束的轨迹看起来就像「网关提前退出了」，
	// 而真实原因可能只是一次瞬时的连接错误——两者的处置完全不同。
	StopReason string
}

// SampleUntilDown 持续采样直到网关不可达（进程退出）或超时。
//
// 硬化措施三的基础：不看「结果好不好」，而是看「收敛过程对不对」。
// 一个合格的优雅停机，其轨迹必须呈现完整形态；
// 只看终态的 abandoned=0 无法区分「优雅收敛」与「压根没有流」。
func SampleUntilDown(gatewayURL string, interval, timeout time.Duration) *Trajectory {
	tr := &Trajectory{}
	deadline := time.Now().Add(timeout)

	// 允许少量瞬时失败：网关在阶段切换时可能短暂拒绝新连接，
	// 一次失败就终止采样会把轨迹截断在最关键的位置上。
	// 连续多次失败才判定为「进程已退出」。
	const tolerated = 3
	consecutiveErrors := 0

	for time.Now().Before(deadline) {
		m, err := scrapeMetrics(gatewayURL)
		if err != nil {
			consecutiveErrors++
			if consecutiveErrors >= tolerated {
				tr.StopReason = fmt.Sprintf("连续 %d 次采样失败，判定进程已退出：%v",
					consecutiveErrors, err)
				return tr
			}
			time.Sleep(interval)
			continue
		}
		consecutiveErrors = 0
		tr.Samples = append(tr.Samples, m)
		time.Sleep(interval)
	}
	tr.StopReason = "采样超时"
	return tr
}

// Dump 输出完整轨迹，供断言失败时诊断。
func (tr *Trajectory) Dump() string {
	if len(tr.Samples) == 0 {
		return "  （无采样，终止原因：" + tr.StopReason + "）"
	}
	base := tr.Samples[0].At
	var b strings.Builder
	for _, m := range tr.Samples {
		fmt.Fprintf(&b, "  +%6.2fs  %s\n", m.At.Sub(base).Seconds(), m)
	}
	fmt.Fprintf(&b, "  终止原因：%s\n", tr.StopReason)
	return b.String()
}

// ConvergenceEvidence 是轨迹之外的佐证事实。
//
// 「在途流归零」这件事无法可靠地从轨迹里读出：流一结束网关就进入
// 阶段三关闭监听，归零与退出之间只有几毫秒，采样器必然采不到那个 0。
// 因此归零由客户端与上游的实证来证明，轨迹只负责证明**过程形态**。
type ConvergenceEvidence struct {
	// StreamCompleted 表示存量流完整收到了 [DONE]
	StreamCompleted bool
	// UpstreamTruncated 是上游观察到的被截断流数
	UpstreamTruncated int64
	// GatewayExited 表示网关进程自行退出（而非被强杀）
	GatewayExited bool
}

// AssertConvergence 是硬化措施三：排空轨迹验证。
//
// 合格的优雅停机必须完整呈现以下形态，缺一不可：
//
//  1. 信号前确有在途流                        —— 否则整个测试无意义
//  2. 阶段单调推进 serving→draining→closing    —— 顺序错了会导致 connection refused
//  3. 拒绝计数在收敛阶段上涨                    —— 证明「拒绝新入站」真的发生了
//  4. 达到峰值后在途流单调不增                  —— 证明停机期间不再接受新流
//  5. 存量流完整收尾（由 evidence 佐证）        —— 证明是自然收敛而非被掐断
//
// 只验证终态（abandoned=0）无法区分「优雅收敛」与「压根没有流」。
func (tr *Trajectory) AssertConvergence(t *testing.T, ev ConvergenceEvidence) {
	t.Helper()
	if len(tr.Samples) < 3 {
		t.Fatalf("轨迹采样过少（%d 个），无法验证收敛过程：\n%s",
			len(tr.Samples), tr.Dump())
	}

	// --- 1. 信号前确有在途流 ---
	peakStreaming := int64(0)
	for _, m := range tr.Samples {
		if m.Streaming > peakStreaming {
			peakStreaming = m.Streaming
		}
	}
	if peakStreaming == 0 {
		t.Fatalf("测试无效：整条轨迹中从未观察到在途流。\n"+
			"  停机逻辑没有被真正触发，abandoned=0 不能证明任何事。\n%s", tr.Dump())
	}

	// --- 2. 阶段单调推进 ---
	seen := map[int]bool{}
	prevPhase := -1
	for _, m := range tr.Samples {
		if m.PhaseID < prevPhase {
			t.Errorf("阶段发生回退（%s -> %s），LB 可能被重新导入流量：\n%s",
				phaseName(prevPhase), phaseName(m.PhaseID), tr.Dump())
		}
		prevPhase = m.PhaseID
		seen[m.PhaseID] = true
	}
	for _, want := range []int{phaseServing, phaseDraining, phaseClosing} {
		if !seen[want] {
			t.Errorf("轨迹中缺少 %s 阶段——三阶段停机未完整执行：\n%s",
				phaseName(want), tr.Dump())
		}
	}

	// --- 3. 收敛阶段拒绝计数上涨 ---
	var rejectedAtClosingStart, rejectedFinal int64 = -1, 0
	for _, m := range tr.Samples {
		if m.PhaseID >= phaseClosing && rejectedAtClosingStart < 0 {
			rejectedAtClosingStart = m.ShutdownRejected
		}
		rejectedFinal = m.ShutdownRejected
	}
	if rejectedAtClosingStart >= 0 && rejectedFinal <= rejectedAtClosingStart {
		t.Errorf("收敛阶段拒绝计数未上涨（%d -> %d）——"+
			"「拒绝新入站」这一步没有被证明发生过：\n%s",
			rejectedAtClosingStart, rejectedFinal, tr.Dump())
	}

	// --- 4. 达到峰值后在途流单调不增 ---
	peaked := false
	prevStreaming := int64(-1)
	for _, m := range tr.Samples {
		if m.Streaming == peakStreaming {
			peaked = true
		}
		if peaked && prevStreaming >= 0 && m.Streaming > prevStreaming {
			t.Errorf("达到峰值后在途流回升（%d -> %d）——"+
				"停机期间不应再接受新流：\n%s", prevStreaming, m.Streaming, tr.Dump())
		}
		if peaked {
			prevStreaming = m.Streaming
		}
	}

	// --- 5. 归零由实证佐证 ---
	//
	// 不断言「最后一个样本为 0」：流结束到进程退出只隔几毫秒，
	// 采样器采不到那个 0 是常态而非异常。硬要断言只会制造随机失败，
	// 而随机失败的测试很快就会被人加上 -skip。
	final := tr.Samples[len(tr.Samples)-1]
	if final.Streaming > 0 {
		if !ev.StreamCompleted {
			t.Errorf("轨迹结束时仍有 %d 条在途流，且存量流未收到 [DONE]——"+
				"存量流被强制中断：\n%s", final.Streaming, tr.Dump())
		}
		if ev.UpstreamTruncated > 0 {
			t.Errorf("轨迹结束时仍有 %d 条在途流，且上游观察到 %d 条截断：\n%s",
				final.Streaming, ev.UpstreamTruncated, tr.Dump())
		}
		if !ev.GatewayExited {
			t.Errorf("轨迹结束时仍有 %d 条在途流，且网关未自行退出：\n%s",
				final.Streaming, tr.Dump())
		}
	}
}
