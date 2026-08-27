package nerclient

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

const testSocket = "/tmp/airlock-ner-test.sock"

func liveClient(t *testing.T) *Client {
	t.Helper()
	if _, err := os.Stat(testSocket); err != nil {
		t.Skipf("需要运行中的 Python NER 服务：python -m pii.service.ner_server --socket %s",
			testSocket)
	}
	c, err := New(t.Context(), Options{SocketPath: testSocket, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("连接失败：%v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// 端到端：Go 拿到的偏移必须能在 Go 的字节串上切出正确的值。
// End to end: the offsets Go receives must slice correctly in Go's bytes.
//
// 这是整套架构里最容易出错的一处。Python 说「张三」在 [0,2)，Go 里它在
// [0,6)——中间的映射错一位，脱敏就洗错字节，且报文变成非法 UTF-8。
func TestOffsetsAlignAcrossLanguages(t *testing.T) {
	c := liveClient(t)

	cases := []string{
		"张三目前住在杭州，并且在阿里巴巴工作。",
		"你好张三",       // 实体不在开头，前面有中文
		"abc张三def",   // 中英混排
		"张三\n李娜\t王强", // 含控制字符
		"客户🙂张三的手机是13812345678",             // 含四字节 emoji
		strings.Repeat("填", 500) + "张三来过。", // 实体在很靠后的位置
	}

	for _, text := range cases {
		t.Run(text[:min(12, len(text))], func(t *testing.T) {
			got, err := c.DetectContext(t.Context(), text)
			if err != nil {
				t.Fatalf("检测失败：%v", err)
			}
			for _, e := range got {
				// 用 Go 的字节偏移切原文，必须等于实体值
				if sliced := text[e.Start:e.End]; sliced != e.Value {
					t.Errorf("偏移错位：text[%d:%d]=%q，实体值=%q",
						e.Start, e.End, sliced, e.Value)
				}
				// 切出来的必须是合法 UTF-8
				if !utf8Valid(e.Value) {
					t.Errorf("切出的值不是合法 UTF-8：%q", e.Value)
				}
			}
			t.Logf("%-28q → %v", truncate(text, 24), names(got))
		})
	}
}

// emoji 是四字节字符，最容易暴露「按字符 vs 按字节」的差异。
// A four-byte emoji is the clearest way to expose char-vs-byte confusion.
func TestFourByteRuneAlignment(t *testing.T) {
	c := liveClient(t)
	const text = "🙂🙂🙂张三住在杭州"

	got, err := c.DetectContext(t.Context(), text)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Skip("模型未在此文本上检出实体")
	}
	for _, e := range got {
		if text[e.Start:e.End] != e.Value {
			t.Fatalf("四字节字符前的实体偏移错位：text[%d:%d]=%q，值=%q",
				e.Start, e.End, text[e.Start:e.End], e.Value)
		}
	}
	t.Logf("三个 emoji（12 字节 / 3 字符）之后：%v", names(got))
}

// 服务不可用必须与「没找到实体」严格区分。
// An unavailable service must be distinguishable from "nothing found".
func TestUnavailableIsNotEmptyResult(t *testing.T) {
	_, err := New(t.Context(), Options{
		SocketPath: "/tmp/definitely-not-a-socket-" + t.Name(),
		Timeout:    time.Second,
	})
	if err == nil {
		t.Fatal("连接不存在的 socket 应报错")
	}
	if !strings.Contains(err.Error(), "ner_server") {
		t.Errorf("报错应给出启动指引：%v", err)
	}
	t.Logf("按预期拒绝：%v", err)
}

// 覆盖类型取自服务端自报，不是本地写死。
// Covered types come from the server, not a local constant.
func TestCoveredTypesComeFromServer(t *testing.T) {
	c := liveClient(t)
	covered := c.CoveredTypes()
	if len(covered) == 0 {
		t.Fatal("服务端应自报支持的类型")
	}
	t.Logf("后端 %s 自报覆盖：%v", c.Model(), covered)

	want := map[detect.EntityType]bool{
		detect.TypeName: false, detect.TypeAddress: false, detect.TypeOrg: false,
	}
	for _, ty := range covered {
		if _, ok := want[ty]; ok {
			want[ty] = true
		}
	}
	for ty, found := range want {
		if !found {
			t.Logf("  注意：后端不产出 %s —— 这一类将完全裸奔", ty)
		}
	}
}

// 单次调用的往返延迟 —— UDS 的价值就在这个数字上。
// Round-trip latency: the number that justifies the Unix socket.
func TestRoundTripLatency(t *testing.T) {
	c := liveClient(t)
	const text = "张三目前住在杭州，并且在阿里巴巴工作。"

	for range 20 {
		if _, err := c.DetectContext(t.Context(), text); err != nil {
			t.Fatal(err)
		}
	}

	const runs = 200
	samples := make([]time.Duration, 0, runs)
	for range runs {
		start := time.Now()
		if _, err := c.DetectContext(t.Context(), text); err != nil {
			t.Fatal(err)
		}
		samples = append(samples, time.Since(start))
	}
	sortDurations(samples)

	p50 := samples[len(samples)/2]
	p99 := samples[len(samples)*99/100]
	t.Logf("UDS 往返 + 推理：P50 %v  P99 %v（目标：单次 IPC < 1ms）",
		p50.Round(time.Microsecond), p99.Round(time.Microsecond))
}

func names(es []detect.Entity) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Value+"/"+string(e.Type))
	}
	return out
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == 0xFFFD && len(s) > 0 {
			return false
		}
	}
	return true
}

func sortDurations(d []time.Duration) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && d[j] < d[j-1]; j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}

// 把 IPC 往返与模型推理分开量。
// Separate the IPC round trip from model inference.
//
// 「UDS 把单次 IPC 压到 1ms 以内」这句话说的是传输，不是推理。两者混在一起
// 报，会让一个慢模型看起来像一个慢传输——而这两件事的解法完全不同：
// 前者换模型或加进程，后者换传输方式。契约里的 inference_micros 就是为了
// 让这一刀切得下去。
//
// "UDS keeps one IPC under 1ms" is a claim about transport, not inference.
// Reported together, a slow model looks like slow transport — and the remedies
// differ entirely. The contract's inference_micros exists to separate them.
func TestLatencyBreakdown(t *testing.T) {
	c := liveClient(t)

	for _, tc := range []struct {
		name string
		text string
	}{
		{"短文本 18 字", "张三目前住在杭州，并且在阿里巴巴工作。"},
		{"空实体短文本", "本季度产品迭代包括搜索排序优化。"},
		{"长文本 2KB", strings.Repeat("客户张三住在杭州的阿里巴巴附近。", 40)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for range 20 {
				_, _ = c.raw(t.Context(), tc.text)
			}

			const runs = 100
			var totalRT, totalInfer time.Duration
			rts := make([]time.Duration, 0, runs)
			for range runs {
				start := time.Now()
				resp, err := c.raw(t.Context(), tc.text)
				rt := time.Since(start)
				if err != nil {
					t.Fatal(err)
				}
				rts = append(rts, rt)
				totalRT += rt
				totalInfer += time.Duration(resp.GetInferenceMicros()) * time.Microsecond
			}
			sortDurations(rts)

			avgRT := totalRT / runs
			avgInfer := totalInfer / runs
			ipc := avgRT - avgInfer
			t.Logf("%-14s 文本 %5d 字节  往返 %8v  其中推理 %8v  IPC %8v  P99 %v",
				tc.name, len(tc.text), avgRT.Round(time.Microsecond),
				avgInfer.Round(time.Microsecond), ipc.Round(time.Microsecond),
				rts[runs*99/100].Round(time.Microsecond))

			if ipc > time.Millisecond {
				t.Logf("  注意：IPC %v 超过 1ms 目标", ipc.Round(time.Microsecond))
			}
		})
	}
}
