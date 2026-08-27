package nerclient

import (
	"os"
	"testing"
	"time"
)

// UDS 与 TCP 的延迟差 —— 「把依赖负担转嫁给 K8s」的代价就在这个数字上。
// The latency difference: what "push the dependency burden onto K8s" costs.
//
// 独立 Deployment 可以单独水平扩缩容，代价是流量要重新走完整的 TCP 协议栈，
// 还要多一跳 Service 转发。两者不能兼得，而这一点应当在选型时就知道，
// 不是上线后才发现。
//
// A separate Deployment scales independently; the traffic goes back through
// the full TCP stack plus a Service hop. You cannot have both, and that should
// be known at selection time.
func TestTransportLatencyComparison(t *testing.T) {
	const tcpAddr = "127.0.0.1:19500"

	if _, err := os.Stat(testSocket); err != nil {
		t.Skip("需要 UDS 服务端")
	}

	uds, err := New(t.Context(), Options{SocketPath: testSocket, Timeout: 5 * time.Second})
	if err != nil {
		t.Skipf("UDS 连接失败：%v", err)
	}
	defer uds.Close()

	tcp, err := New(t.Context(), Options{Address: tcpAddr, Timeout: 5 * time.Second})
	if err != nil {
		t.Skipf("TCP 连接失败（需要 --listen %s 的服务端）：%v", tcpAddr, err)
	}
	defer tcp.Close()

	const text = "张三目前住在杭州，并且在阿里巴巴工作。"

	measure := func(c *Client) (rt, infer time.Duration, p99 time.Duration) {
		for range 20 {
			_, _ = c.raw(t.Context(), text)
		}
		const runs = 200
		samples := make([]time.Duration, 0, runs)
		var totalRT, totalInfer time.Duration
		for range runs {
			start := time.Now()
			resp, err := c.raw(t.Context(), text)
			d := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			samples = append(samples, d)
			totalRT += d
			totalInfer += time.Duration(resp.GetInferenceMicros()) * time.Microsecond
		}
		sortDurations(samples)
		return totalRT / runs, totalInfer / runs, samples[runs*99/100]
	}

	udsRT, udsInfer, udsP99 := measure(uds)
	tcpRT, tcpInfer, tcpP99 := measure(tcp)

	udsIPC := udsRT - udsInfer
	tcpIPC := tcpRT - tcpInfer

	t.Logf("%-28s %10s %10s %10s", "", "往返", "其中推理", "净 IPC")
	t.Logf("%-28s %10v %10v %10v", uds.Transport(),
		udsRT.Round(time.Microsecond), udsInfer.Round(time.Microsecond),
		udsIPC.Round(time.Microsecond))
	t.Logf("%-28s %10v %10v %10v", tcp.Transport(),
		tcpRT.Round(time.Microsecond), tcpInfer.Round(time.Microsecond),
		tcpIPC.Round(time.Microsecond))
	t.Logf("")
	t.Logf("净 IPC 差 %v（TCP 是 UDS 的 %.1f 倍）",
		(tcpIPC - udsIPC).Round(time.Microsecond),
		float64(tcpIPC)/float64(udsIPC))
	t.Logf("P99：UDS %v，TCP %v", udsP99.Round(time.Microsecond), tcpP99.Round(time.Microsecond))
	t.Logf("注意：本机 TCP 走的是 loopback，没有真实网络与 Service 转发那一跳；" +
		"K8s 里独立 Deployment 的实际差距会更大")
}
