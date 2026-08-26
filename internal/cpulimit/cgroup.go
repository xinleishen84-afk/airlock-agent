// Package cpulimit 处理容器 CPU 配额与 CFS 限流（throttling）。
//
// # CFS 限流陷阱
//
// 高性能代理默认按**宿主机物理核数**开工作线程（Envoy 在 64 核机器上开 64 个），
// 但容器只被授予 8 核配额。线程数远超配额时，Linux CFS 调度器会在每个周期
// （默认 100ms）用尽配额后**冻结整个 cgroup 直到下个周期**，造成头部阻塞，
// 延迟从毫秒暴涨到数秒。Envoy 的工业解法是硬绑 `--concurrency 8`。
//
// # Go 的现状与残留缺口
//
// Go 1.25 起，运行时**已原生读取 cgroup quota** 来决定 GOMAXPROCS，
// Envoy 需要显式 --concurrency 的那一半 Go 自己做了。但默认策略有两处
// 对延迟敏感场景不利：
//
//  1. 「限额非整数时向上取整」——cpu:1.5 得到 GOMAXPROCS=2。两个线程满跑
//     会在 100ms 周期内 75ms 烧完 150ms 配额，余下 25ms 被冻结。
//     吞吐最优，延迟最差。
//  2. 「绝不设成小于 2」——cpu:1 的 sidecar 拿到 GOMAXPROCS=2，稳定超配。
//
// 更关键的是：**自动模式不会告诉你是否正在被 throttle**。没有这个信号，
// 生产上的延迟尖刺无从归因。本包因此提供三件事：
//
//	Detect  —— 读出真实配额，与当前 GOMAXPROCS 比对并告警
//	Apply   —— 按延迟优先策略（向下取整）显式设定，可选
//	Monitor —— 持续读 cpu.stat，把限流比例暴露成可观测指标
package cpulimit

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// DefaultCgroupRoot 是 cgroup 文件系统的标准挂载点。
const DefaultCgroupRoot = "/sys/fs/cgroup"

// CgroupVersion 标识 cgroup 版本。
type CgroupVersion int

const (
	VersionNone CgroupVersion = iota // 未检测到 cgroup CPU 限额
	VersionV1
	VersionV2
)

// String 返回版本名。
func (v CgroupVersion) String() string {
	switch v {
	case VersionV1:
		return "cgroup v1"
	case VersionV2:
		return "cgroup v2"
	default:
		return "none"
	}
}

// Quota 描述容器的 CPU 配额。
type Quota struct {
	Version CgroupVersion
	// Limited 为 false 表示未设配额（宿主机运行或 cpu.max=max）
	Limited bool
	// QuotaMicros 是每个周期可用的 CPU 微秒数
	QuotaMicros int64
	// PeriodMicros 是 CFS 周期长度，默认 100000（100ms）
	PeriodMicros int64
}

// CPUs 返回等效 CPU 核数（可能是小数，如 1.5）。
func (q Quota) CPUs() float64 {
	if !q.Limited || q.PeriodMicros <= 0 {
		return 0
	}
	return float64(q.QuotaMicros) / float64(q.PeriodMicros)
}

// String 返回可读描述。
func (q Quota) String() string {
	if !q.Limited {
		return fmt.Sprintf("%s: 未设 CPU 配额", q.Version)
	}
	return fmt.Sprintf("%s: %.2f 核（quota=%dus period=%dus）",
		q.Version, q.CPUs(), q.QuotaMicros, q.PeriodMicros)
}

// DetectQuota 从 cgroup 文件系统读取 CPU 配额。
// root 为空时使用标准挂载点。未检测到限额不是错误——裸机运行是合法场景。
func DetectQuota(root string) (Quota, error) {
	if root == "" {
		root = DefaultCgroupRoot
	}

	// 优先尝试 cgroup v2：现代发行版与 K8s 1.25+ 的默认
	if q, ok, err := readV2(root); err != nil {
		return Quota{}, err
	} else if ok {
		return q, nil
	}

	if q, ok, err := readV1(root); err != nil {
		return Quota{}, err
	} else if ok {
		return q, nil
	}

	return Quota{Version: VersionNone}, nil
}

// readV2 读取 cgroup v2 的 cpu.max。格式："<quota> <period>"，quota 为 "max" 表示不限。
func readV2(root string) (Quota, bool, error) {
	data, err := os.ReadFile(filepath.Join(root, "cpu.max"))
	if err != nil {
		if os.IsNotExist(err) {
			return Quota{}, false, nil
		}
		return Quota{}, false, fmt.Errorf("读取 cpu.max 失败: %w", err)
	}

	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return Quota{}, false, fmt.Errorf("cpu.max 格式异常: %q", strings.TrimSpace(string(data)))
	}

	period, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || period <= 0 {
		return Quota{}, false, fmt.Errorf("cpu.max 周期值非法: %q", fields[1])
	}
	if fields[0] == "max" {
		return Quota{Version: VersionV2, Limited: false, PeriodMicros: period}, true, nil
	}
	quota, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return Quota{}, false, fmt.Errorf("cpu.max 配额值非法: %q", fields[0])
	}
	return Quota{Version: VersionV2, Limited: quota > 0, QuotaMicros: quota, PeriodMicros: period}, true, nil
}

// readV1 读取 cgroup v1 的 cpu.cfs_quota_us / cpu.cfs_period_us。quota 为 -1 表示不限。
func readV1(root string) (Quota, bool, error) {
	base := filepath.Join(root, "cpu")
	quotaRaw, err := readInt64File(filepath.Join(base, "cpu.cfs_quota_us"))
	if err != nil {
		if os.IsNotExist(err) {
			return Quota{}, false, nil
		}
		return Quota{}, false, err
	}
	periodRaw, err := readInt64File(filepath.Join(base, "cpu.cfs_period_us"))
	if err != nil {
		return Quota{}, false, err
	}
	if periodRaw <= 0 {
		return Quota{}, false, fmt.Errorf("cpu.cfs_period_us 非法: %d", periodRaw)
	}
	return Quota{
		Version: VersionV1, Limited: quotaRaw > 0,
		QuotaMicros: quotaRaw, PeriodMicros: periodRaw,
	}, true, nil
}

// readInt64File 读取只含一个整数的文件。
func readInt64File(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// 并发度策略
// ---------------------------------------------------------------------------

// RoundingMode 是配额非整数时的取整策略。
type RoundingMode int

const (
	// RoundDown 向下取整（延迟优先）。1.5 核 -> 1 个 P。
	// 牺牲一点吞吐换取「绝不触发 CFS 冻结」，是网关这类延迟敏感组件的正确取舍。
	RoundDown RoundingMode = iota
	// RoundUp 向上取整（吞吐优先），与 Go 运行时默认一致。
	// 1.5 核 -> 2 个 P，满负载时会周期性被冻结。
	RoundUp
)

// Recommendation 是并发度建议。
type Recommendation struct {
	Quota             Quota
	CurrentGOMAXPROCS int
	Recommended       int
	// Oversubscribed 为 true 表示当前 GOMAXPROCS 超过配额，
	// 满负载时必然触发 CFS 限流。
	Oversubscribed bool
	Reason         string
}

// Recommend 根据配额计算建议的 GOMAXPROCS，并判断当前设置是否超配。
func Recommend(q Quota, mode RoundingMode) Recommendation {
	current := runtime.GOMAXPROCS(0)
	rec := Recommendation{Quota: q, CurrentGOMAXPROCS: current, Recommended: current}

	if !q.Limited {
		rec.Reason = "未设 CPU 配额，保持运行时默认"
		return rec
	}

	cpus := q.CPUs()
	var n int
	if mode == RoundUp {
		n = int(math.Ceil(cpus))
	} else {
		n = int(math.Floor(cpus))
	}
	if n < 1 {
		// 配额低于 1 核时仍需至少 1 个 P，否则程序无法运行。
		// 这种配置下 CFS 限流不可避免，只能靠告警让运维察觉。
		n = 1
	}

	rec.Recommended = n
	// 关键判据：GOMAXPROCS 超过等效核数即为超配。
	// Go 默认「向上取整」和「不小于 2」两条规则都会制造这种情况。
	rec.Oversubscribed = float64(current) > cpus
	if rec.Oversubscribed {
		rec.Reason = fmt.Sprintf(
			"GOMAXPROCS=%d 超过配额 %.2f 核，满负载时将触发 CFS 冻结（建议 %d）",
			current, cpus, n)
	} else {
		rec.Reason = fmt.Sprintf("GOMAXPROCS=%d 与配额 %.2f 核匹配", current, cpus)
	}
	return rec
}

// Apply 按建议显式设定 GOMAXPROCS，返回生效前后的值。
//
// 注意：显式调用 runtime.GOMAXPROCS 会**关闭 Go 1.25+ 的自动跟随更新**。
// 若容器 CPU 限额可能在运行期变更（VPA 垂直伸缩），应改用 Detect + 告警，
// 让运行时继续自动跟随，而不是在这里钉死。
func Apply(rec Recommendation) (before, after int) {
	if rec.Recommended <= 0 || rec.Recommended == rec.CurrentGOMAXPROCS {
		return rec.CurrentGOMAXPROCS, rec.CurrentGOMAXPROCS
	}
	before = runtime.GOMAXPROCS(rec.Recommended)
	return before, runtime.GOMAXPROCS(0)
}

// ---------------------------------------------------------------------------
// 限流观测
// ---------------------------------------------------------------------------

// ThrottleStats 是 CFS 限流统计。
//
// 这是诊断「延迟尖刺」的唯一直接证据：GOMAXPROCS 配得对不对是推断，
// nr_throttled 在涨才是事实。
type ThrottleStats struct {
	// NrPeriods 是已经历的 CFS 周期数
	NrPeriods int64
	// NrThrottled 是其中发生限流的周期数
	NrThrottled int64
	// ThrottledMicros 是累计被冻结的微秒数
	ThrottledMicros int64
}

// ThrottleRatio 返回被限流周期占比。持续大于 0 即说明并发度超配。
func (s ThrottleStats) ThrottleRatio() float64 {
	if s.NrPeriods == 0 {
		return 0
	}
	return float64(s.NrThrottled) / float64(s.NrPeriods)
}

// Sub 返回两次采样之间的增量，用于计算区间内的限流率。
func (s ThrottleStats) Sub(prev ThrottleStats) ThrottleStats {
	return ThrottleStats{
		NrPeriods:       s.NrPeriods - prev.NrPeriods,
		NrThrottled:     s.NrThrottled - prev.NrThrottled,
		ThrottledMicros: s.ThrottledMicros - prev.ThrottledMicros,
	}
}

// ReadThrottleStats 读取 CFS 限流统计。
func ReadThrottleStats(root string, version CgroupVersion) (ThrottleStats, error) {
	if root == "" {
		root = DefaultCgroupRoot
	}
	var path string
	switch version {
	case VersionV2:
		path = filepath.Join(root, "cpu.stat")
	case VersionV1:
		path = filepath.Join(root, "cpu", "cpu.stat")
	default:
		return ThrottleStats{}, fmt.Errorf("未检测到 cgroup，无限流统计可读")
	}

	f, err := os.Open(path)
	if err != nil {
		return ThrottleStats{}, fmt.Errorf("打开 %s 失败: %w", path, err)
	}
	defer f.Close()

	var stats ThrottleStats
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "nr_periods":
			stats.NrPeriods = v
		case "nr_throttled":
			stats.NrThrottled = v
		case "throttled_usec": // cgroup v2：微秒
			stats.ThrottledMicros = v
		case "throttled_time": // cgroup v1：纳秒，需换算
			stats.ThrottledMicros = v / 1000
		}
	}
	if err := scanner.Err(); err != nil {
		return ThrottleStats{}, fmt.Errorf("读取 %s 失败: %w", path, err)
	}
	return stats, nil
}
