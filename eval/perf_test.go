package eval

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
)

// buildPrompt returns a document of roughly the requested byte size.
// 返回大致为指定字节数的文档。
//
// 中英混排、含代码块与 JSON —— 真实提示词就是这个样子，
// 而纯 ASCII 语料量出来的吞吐量会偏高：正则在多字节字符上要多走一些路。
// Mixed CJK/ASCII with code and JSON, because that is what a real prompt looks
// like; a pure-ASCII corpus measures higher than production ever will.
func buildPrompt(targetBytes int) string {
	block := "以下是本季度的客户工单摘要，请生成一份处理建议。\n" +
		"工单 A：客户反馈无法登录，联系电话 13812345678，邮箱 zhang.wei@example.com。\n" +
		"工单 B：退款申请，卡号 4111 1111 1111 1111，身份证 11010519491231002X。\n" +
		"排查脚本：\n```go\nfunc retry(n int) error { for i := 0; i < n; i++ { _ = i }; return nil }\n```\n" +
		`配置片段：{"timeout":"30s","retries":3,"endpoint":"https://api.example.com/v1"}` + "\n" +
		"备注：本次涉及订单 20240131000012345，处理时限 48 小时。\n\n"

	var b strings.Builder
	b.Grow(targetBytes + len(block))
	for b.Len() < targetBytes {
		b.WriteString(block)
	}
	return b.String()
}

// percentile returns the p-th percentile of a sorted duration slice.
// 返回已排序时长切片的第 p 百分位。
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

// 端到端延迟：检测 + 脱敏，按百分位报。
// End-to-end latency: detect plus redact, reported by percentile.
//
// 报 P99 而不是平均值：网关是每个请求都要过的组件，
// 而用户感知的是最慢的那批请求，不是平均的那个。
// P99 rather than a mean: the gateway sits on every request, and users
// experience the slow tail, not the average.
func TestLatencyPercentiles(t *testing.T) {
	for _, mode := range []struct {
		name string
		det  func(testing.TB) detect.Detector
	}{
		{"全量扫描", rosterDetector},
		{"并行分块扫描", scanningDetector},
	} {
		t.Run(mode.name, func(t *testing.T) { latencyRun(t, mode.det(t)) })
	}
}

func latencyRun(t *testing.T, d detect.Detector) {
	r := anonymize.NewRedactorWith(d, true)
	scope := anonymize.StrategyScope{
		Tenant: "acme",
		Vault:  evalVault(t),
	}

	sizes := []struct {
		name  string
		bytes int
	}{
		{"典型提示词 2KB", 2 << 10},
		{"长提示词 32KB", 32 << 10},
		{"128k token ≈ 384KB", 384 << 10},
	}

	for _, size := range sizes {
		text := buildPrompt(size.bytes)
		latencyFor(t, r, scope, size.name+"（PII 密集）", text)
	}
	// PII 稀疏才是真实提示词的形态：一份 128k token 的文档里通常只有
	// 几处标识，而不是每 130 字节一处。密集形态量的是上界，不是常态。
	// Sparse is what a real prompt looks like; the dense shape measures an
	// upper bound, not the common case.
	latencyFor(t, r, scope, "128k token（PII 稀疏）", sparseWithPII(384<<10))
}

func latencyFor(t *testing.T, r *anonymize.Redactor, scope anonymize.StrategyScope,
	name, text string) {
	const runs = 120
	{

		// 预热：首次调用会分配缓冲，把它算进 P99 是在量 GC 不是量算法
		for range 10 {
			if _, err := r.RedactTo(t.Context(), text, scope, maskFlow()); err != nil {
				t.Fatal(err)
			}
		}

		samples := make([]time.Duration, 0, runs)
		for range runs {
			start := time.Now()
			if _, err := r.RedactTo(t.Context(), text, scope, maskFlow()); err != nil {
				t.Fatal(err)
			}
			samples = append(samples, time.Since(start))
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })

		p50 := percentile(samples, 0.50)
		p95 := percentile(samples, 0.95)
		p99 := percentile(samples, 0.99)
		verdict := "达标"
		if p99 > 20*time.Millisecond {
			verdict = "未达标"
		}
		t.Logf("%-26s %7d 字节  P50 %8v  P95 %8v  P99 %8v  （目标 ≤20ms：%s）",
			name, len(text), p50.Round(time.Microsecond),
			p95.Round(time.Microsecond), p99.Round(time.Microsecond), verdict)
	}
}

// scanningDetector 是并行分块扫描 + 名册的生产形态。
func scanningDetector(t testing.TB) detect.Detector {
	t.Helper()
	reg := packs.MustNewRegistry([]string{"GEN", "CN", "US", "IT", "DE", "ES"})
	sc, err := detect.NewChunkedScanner(reg, detect.DefaultChunkSize, detect.DefaultMargin, 0)
	if err != nil {
		t.Fatal(err)
	}
	gaz, err := detect.NewGazetteerDetector(map[detect.EntityType][]string{
		detect.TypeName: {"张伟", "李娜"},
		detect.TypeOrg:  {"星辰科技"},
	}, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	return detect.NewCompositeDetector([]detect.Detector{sc, gaz}, 0)
}

// 吞吐量：单核与多核分别报。
// Throughput, reported for one core and for all of them.
//
// 单核数字才是「一个请求要等多久」的依据；多核数字是「一台机器能扛多少」的依据。
// 把后者当成前者报，是性能页上最常见的那种误导。
// The single-core number is what one request waits for; the multi-core number
// is what one machine sustains. Reporting the second as the first is the most
// common way a performance page misleads.
func TestThroughput(t *testing.T) {
	d := rosterDetector(t)
	text := buildPrompt(384 << 10)
	size := float64(len(text))

	// 单核
	const runs = 30
	start := time.Now()
	for range runs {
		if _, err := d.Detect(text); err != nil {
			t.Fatal(err)
		}
	}
	singleMBps := size * runs / time.Since(start).Seconds() / (1 << 20)

	// 多核：网关的实际形态是并发处理多个请求
	workers := runtime.GOMAXPROCS(0)
	var wg sync.WaitGroup
	start = time.Now()
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range runs {
				if _, err := d.Detect(text); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	multiMBps := size * float64(runs*workers) / time.Since(start).Seconds() / (1 << 20)

	t.Logf("文档 %d 字节（约 128k token）", len(text))
	t.Logf("  单核吞吐  %6.1f MB/s   （目标 ≥50MB/s：%s）", singleMBps, verdictAt(singleMBps, 50))
	t.Logf("  %d 核吞吐 %6.1f MB/s   （目标 ≥50MB/s：%s）", workers, multiMBps, verdictAt(multiMBps, 50))
}

func verdictAt(got, want float64) string {
	if got >= want {
		return "达标"
	}
	return "未达标"
}

// 分层扫描：快速层单独的吞吐量。
// The fast tier's throughput on its own.
func TestFastTierThroughput(t *testing.T) {
	reg := regexOnly(t)
	text := buildPrompt(384 << 10)
	size := float64(len(text))

	const runs = 30
	start := time.Now()
	for range runs {
		if _, err := reg.Detect(text); err != nil {
			t.Fatal(err)
		}
	}
	mbps := size * runs / time.Since(start).Seconds() / (1 << 20)
	t.Logf("仅正则+校验位层：%6.1f MB/s（目标 ≥50MB/s：%s）", mbps, verdictAt(mbps, 50))
}

// evalVault 构造一个评测用的会话保险库。
func evalVault(t testing.TB) *anonymize.SessionVault {
	t.Helper()
	reg := anonymize.NewVaultRegistry(time.Hour, 10)
	v, err := reg.Get(anonymize.SessionRef{Tenant: "acme", Session: "eval"})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// maskFlow 是评测用的占位符链路。
func maskFlow() anonymize.Flow {
	return anonymize.Flow{Name: "eval", Default: anonymize.NewMask(), Restores: true}
}

// regexOnly 只装正则与校验位层，不含名册。
func regexOnly(t *testing.T) detect.Detector {
	t.Helper()
	return packsRegistry(t)
}

var _ = fmt.Sprintf

// P99 ≤20ms 的实际适用范围在哪里断掉。
// Where the P99 ≤20ms target actually stops holding.
//
// 报一个「达标/未达标」的判断没有用；有用的是那条线的位置。
// A verdict is not useful; the location of the line is.
func TestLatencyCrossover(t *testing.T) {
	d := scanningDetector(t)
	r := anonymize.NewRedactorWith(d, true)
	scope := anonymize.StrategyScope{Tenant: "acme", Vault: evalVault(t)}

	for _, kb := range []int{8, 16, 32, 64, 96, 128, 192, 256, 384} {
		text := sparseWithPII(kb << 10)
		const runs = 60
		for range 5 {
			if _, err := r.RedactTo(t.Context(), text, scope, maskFlow()); err != nil {
				t.Fatal(err)
			}
		}
		samples := make([]time.Duration, 0, runs)
		for range runs {
			start := time.Now()
			if _, err := r.RedactTo(t.Context(), text, scope, maskFlow()); err != nil {
				t.Fatal(err)
			}
			samples = append(samples, time.Since(start))
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		p99 := percentile(samples, 0.99)
		mark := "✓"
		if p99 > 20*time.Millisecond {
			mark = "✗"
		}
		t.Logf("  %s %4d KB（约 %3dk token）  P99 %8v", mark, kb, kb*1024/3/1000, p99.Round(time.Microsecond))
	}
}

// 并发压力下的单请求延迟 —— 并行扫描在这里帮不上忙。
// Single-request latency under concurrent load, where parallel scanning does
// not help.
//
// 并行分块把一份长文档摊到多个核上，这在机器空闲时降低单请求延迟。
// 机器一旦被并发请求占满，那些核本来就在忙，摊不出去了——
// 于是延迟退回串行的那个数。把空闲时的数字当作生产延迟报，
// 是性能页上最常见的那种误导。
//
// Parallel chunking spreads one long document across cores, which lowers
// latency on an idle machine. Once concurrent requests saturate those cores
// there is nothing to spread onto, and latency reverts to the serial number.
func TestLatencyUnderConcurrency(t *testing.T) {
	d := scanningDetector(t)
	r := anonymize.NewRedactorWith(d, true)
	text := sparseWithPII(32 << 10)

	for _, concurrency := range []int{1, 4, 16, 64} {
		var wg sync.WaitGroup
		samples := make([][]time.Duration, concurrency)
		const perWorker = 30

		start := time.Now()
		for w := range concurrency {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				scope := anonymize.StrategyScope{Tenant: "acme", Vault: evalVault(t)}
				local := make([]time.Duration, 0, perWorker)
				for range perWorker {
					s := time.Now()
					if _, err := r.RedactTo(t.Context(), text, scope, maskFlow()); err != nil {
						t.Error(err)
						return
					}
					local = append(local, time.Since(s))
				}
				samples[w] = local
			}(w)
		}
		wg.Wait()
		elapsed := time.Since(start)

		var all []time.Duration
		for _, s := range samples {
			all = append(all, s...)
		}
		sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
		mbps := float64(len(text)) * float64(len(all)) / elapsed.Seconds() / (1 << 20)
		t.Logf("  并发 %2d：P50 %8v  P99 %8v  总吞吐 %6.1f MB/s",
			concurrency, percentile(all, 0.50).Round(time.Microsecond),
			percentile(all, 0.99).Round(time.Microsecond), mbps)
	}
}
