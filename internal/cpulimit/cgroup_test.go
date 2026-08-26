package cpulimit

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// writeCgroupV2 在临时目录里伪造一个 cgroup v2 层次。
func writeCgroupV2(t *testing.T, cpuMax string, cpuStat string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cpu.max"), []byte(cpuMax), 0o644); err != nil {
		t.Fatal(err)
	}
	if cpuStat != "" {
		if err := os.WriteFile(filepath.Join(root, "cpu.stat"), []byte(cpuStat), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// writeCgroupV1 在临时目录里伪造一个 cgroup v1 层次。
func writeCgroupV1(t *testing.T, quota, period string, cpuStat string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "cpu")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("cpu.cfs_quota_us", quota)
	write("cpu.cfs_period_us", period)
	if cpuStat != "" {
		write("cpu.stat", cpuStat)
	}
	return root
}

// atomicWrite 原子地覆写文件，避免读者看到截断中的中间状态。
func atomicWrite(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// TestPartialReadRejected 校验部分写入的读数被丢弃而非算出错误增量。
// 假的限流告警比没有告警更糟——它会把排查引向错误方向。
func TestPartialReadRejected(t *testing.T) {
	prev := ThrottleStats{NrPeriods: 100, NrThrottled: 10, ThrottledMicros: 1000}
	cases := []struct {
		desc    string
		current ThrottleStats
		want    bool
	}{
		{"正常递增", ThrottleStats{NrPeriods: 200, NrThrottled: 20, ThrottledMicros: 2000}, true},
		{"读到空文件", ThrottleStats{}, false},
		{"周期数倒退", ThrottleStats{NrPeriods: 50, NrThrottled: 10, ThrottledMicros: 1000}, false},
		{"限流数倒退", ThrottleStats{NrPeriods: 200, NrThrottled: 5, ThrottledMicros: 2000}, false},
	}
	for _, c := range cases {
		if got := plausible(c.current, prev, true); got != c.want {
			t.Errorf("%s: plausible=%v，期望 %v", c.desc, got, c.want)
		}
	}
	// 无基线时，只要不是零值就接受
	if !plausible(ThrottleStats{NrPeriods: 1}, ThrottleStats{}, false) {
		t.Error("首次采样应接受任何非零读数")
	}
}

// TestDetectQuotaV2 校验 cgroup v2 配额解析。
func TestDetectQuotaV2(t *testing.T) {
	cases := []struct {
		cpuMax    string
		wantLimit bool
		wantCPUs  float64
	}{
		{"800000 100000\n", true, 8},   // K8s cpu limit: 8
		{"150000 100000\n", true, 1.5}, // 非整数配额——Go 默认会向上取整到 2
		{"100000 100000\n", true, 1},   // cpu: 1，Go 默认仍会给 2
		{"max 100000\n", false, 0},     // 未设限
		{"50000 100000\n", true, 0.5},  // 低于 1 核
	}
	for _, c := range cases {
		root := writeCgroupV2(t, c.cpuMax, "")
		q, err := DetectQuota(root)
		if err != nil {
			t.Fatalf("解析 %q 失败: %v", c.cpuMax, err)
		}
		if q.Version != VersionV2 {
			t.Errorf("%q 应识别为 v2，实际 %v", c.cpuMax, q.Version)
		}
		if q.Limited != c.wantLimit {
			t.Errorf("%q 限额标志错误: %v", c.cpuMax, q.Limited)
		}
		if c.wantLimit && q.CPUs() != c.wantCPUs {
			t.Errorf("%q 应为 %.2f 核，实际 %.2f", c.cpuMax, c.wantCPUs, q.CPUs())
		}
	}
}

// TestDetectQuotaV1 校验 cgroup v1 配额解析。
func TestDetectQuotaV1(t *testing.T) {
	root := writeCgroupV1(t, "800000\n", "100000\n", "")
	q, err := DetectQuota(root)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if q.Version != VersionV1 || !q.Limited || q.CPUs() != 8 {
		t.Errorf("v1 解析错误: %+v", q)
	}

	// quota 为 -1 表示不限
	unlimited := writeCgroupV1(t, "-1\n", "100000\n", "")
	q2, _ := DetectQuota(unlimited)
	if q2.Limited {
		t.Errorf("-1 应表示不限，实际 %+v", q2)
	}
}

// TestDetectQuotaNoCgroup 校验裸机运行不报错——这是合法场景。
func TestDetectQuotaNoCgroup(t *testing.T) {
	q, err := DetectQuota(t.TempDir())
	if err != nil {
		t.Fatalf("无 cgroup 不应报错: %v", err)
	}
	if q.Version != VersionNone || q.Limited {
		t.Errorf("应识别为无限额: %+v", q)
	}
}

// TestDetectQuotaMalformed 校验畸形文件被识别为错误而非静默当成不限。
// 静默降级为「不限」会让并发度按宿主核数开——正是要防的那个陷阱。
func TestDetectQuotaMalformed(t *testing.T) {
	for _, bad := range []string{"garbage\n", "800000\n", "800000 0\n", "800000 abc\n"} {
		root := writeCgroupV2(t, bad, "")
		if _, err := DetectQuota(root); err == nil {
			t.Errorf("畸形 cpu.max %q 应报错而非静默放行", bad)
		}
	}
}

// TestRecommendRoundDownForLatency 校验延迟优先策略向下取整。
//
// 这是本包相对 Go 默认行为的核心差异：Go 对 1.5 核向上取整到 2，
// 满负载时两线程会在 75ms 内烧完 150ms 配额，余下 25ms 被冻结。
func TestRecommendRoundDownForLatency(t *testing.T) {
	q := Quota{Version: VersionV2, Limited: true, QuotaMicros: 150000, PeriodMicros: 100000}

	down := Recommend(q, RoundDown)
	if down.Recommended != 1 {
		t.Errorf("延迟优先应向下取整为 1，实际 %d", down.Recommended)
	}
	up := Recommend(q, RoundUp)
	if up.Recommended != 2 {
		t.Errorf("吞吐优先应向上取整为 2，实际 %d", up.Recommended)
	}
}

// TestRecommendDetectsOversubscription 校验超配检测。
func TestRecommendDetectsOversubscription(t *testing.T) {
	// 模拟宿主 64 核、容器限 8 核的经典场景
	old := runtime.GOMAXPROCS(16)
	defer runtime.GOMAXPROCS(old)

	q := Quota{Version: VersionV2, Limited: true, QuotaMicros: 800000, PeriodMicros: 100000}
	rec := Recommend(q, RoundDown)
	if !rec.Oversubscribed {
		t.Error("GOMAXPROCS=16 超过 8 核配额，应判定为超配")
	}
	if rec.Recommended != 8 {
		t.Errorf("应建议 8，实际 %d", rec.Recommended)
	}
}

// TestRecommendSubCoreQuota 校验低于 1 核的配额仍给 1 个 P。
func TestRecommendSubCoreQuota(t *testing.T) {
	q := Quota{Version: VersionV2, Limited: true, QuotaMicros: 50000, PeriodMicros: 100000}
	rec := Recommend(q, RoundDown)
	if rec.Recommended != 1 {
		t.Errorf("低于 1 核仍需至少 1 个 P，实际 %d", rec.Recommended)
	}
	if !rec.Oversubscribed {
		t.Error("0.5 核配额下 GOMAXPROCS>=1 必然超配，应告警")
	}
}

// TestRecommendNoQuotaKeepsDefault 校验无配额时不改动运行时默认。
func TestRecommendNoQuotaKeepsDefault(t *testing.T) {
	rec := Recommend(Quota{Version: VersionNone}, RoundDown)
	if rec.Recommended != runtime.GOMAXPROCS(0) || rec.Oversubscribed {
		t.Errorf("无配额时应保持默认: %+v", rec)
	}
}

// TestReadThrottleStatsV2 校验 cgroup v2 限流统计解析。
func TestReadThrottleStatsV2(t *testing.T) {
	root := writeCgroupV2(t, "800000 100000\n",
		"usage_usec 123456\nnr_periods 1000\nnr_throttled 250\nthrottled_usec 5000000\n")
	s, err := ReadThrottleStats(root, VersionV2)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if s.NrPeriods != 1000 || s.NrThrottled != 250 || s.ThrottledMicros != 5000000 {
		t.Errorf("解析错误: %+v", s)
	}
	if r := s.ThrottleRatio(); r != 0.25 {
		t.Errorf("限流比例应为 0.25，实际 %f", r)
	}
}

// TestReadThrottleStatsV1NanosecondConversion 校验 v1 的纳秒换算。
// v1 用 throttled_time（纳秒），v2 用 throttled_usec（微秒），
// 混用会让统计差 1000 倍。
func TestReadThrottleStatsV1NanosecondConversion(t *testing.T) {
	root := writeCgroupV1(t, "800000\n", "100000\n",
		"nr_periods 100\nnr_throttled 10\nthrottled_time 5000000000\n")
	s, err := ReadThrottleStats(root, VersionV1)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if s.ThrottledMicros != 5_000_000 {
		t.Errorf("纳秒应换算为微秒 5000000，实际 %d", s.ThrottledMicros)
	}
}

// TestMonitorReportsThrottling 校验监视器能发现限流并回调告警。
func TestMonitorReportsThrottling(t *testing.T) {
	root := writeCgroupV2(t, "800000 100000\n",
		"nr_periods 100\nnr_throttled 0\nthrottled_usec 0\n")

	m := NewMonitor(root, VersionV2, 10*time.Millisecond)
	fired := make(chan float64, 1)
	m.OnThrottle = func(w ThrottleStats, ratio float64) {
		select {
		case fired <- ratio:
		default:
		}
	}

	stop := m.Start(context.Background())
	defer stop()

	// 模拟限流发生：原子改写 cpu.stat。
	// 必须用 rename 而非直接覆写——覆写会先截断文件，监视器若正好读到
	// 那一瞬的空文件，基线就废了。内核对 cgroup 文件的更新本身是原子的。
	time.Sleep(20 * time.Millisecond)
	atomicWrite(t, filepath.Join(root, "cpu.stat"),
		"nr_periods 200\nnr_throttled 50\nthrottled_usec 1000000\n")

	select {
	case ratio := <-fired:
		// 窗口增量：100 个周期里 50 个被限流
		if ratio != 0.5 {
			t.Errorf("窗口限流比例应为 0.5，实际 %f", ratio)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("限流发生后监视器未回调")
	}

	if !m.Throttling() {
		t.Error("Throttling() 应返回 true")
	}
}

// TestMonitorBaselineAvoidsFalseAlarm 校验首次采样取基线，
// 不把容器启动至今的累计值误当成窗口增量。
func TestMonitorBaselineAvoidsFalseAlarm(t *testing.T) {
	root := writeCgroupV2(t, "800000 100000\n",
		"nr_periods 100000\nnr_throttled 9999\nthrottled_usec 1000000\n")

	m := NewMonitor(root, VersionV2, 10*time.Millisecond)
	fired := make(chan struct{}, 1)
	m.OnThrottle = func(ThrottleStats, float64) {
		select {
		case fired <- struct{}{}:
		default:
		}
	}
	stop := m.Start(context.Background())
	defer stop()

	select {
	case <-fired:
		t.Error("统计值未变化时不应告警——历史累计值不是当前窗口增量")
	case <-time.After(60 * time.Millisecond):
	}
}

// TestMonitorNoCgroupDegradesSilently 校验无 cgroup 时静默降级。
func TestMonitorNoCgroupDegradesSilently(t *testing.T) {
	m := NewMonitor(t.TempDir(), VersionNone, time.Millisecond)
	stop := m.Start(context.Background())
	stop()
	if m.Throttling() {
		t.Error("无 cgroup 时不应报告限流")
	}
}
