package cpulimit

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Monitor 持续采样 CFS 限流统计，把「是否正在被冻结」变成可观测指标。
//
// 这是 CFS 陷阱防线里最重要的一环：GOMAXPROCS 配得对不对只是推断，
// nr_throttled 持续上涨才是事实。没有这个信号，生产上的延迟尖刺
// 只能靠猜——而这正是该问题极难定位的原因。
type Monitor struct {
	root     string
	version  CgroupVersion
	interval time.Duration

	mu      sync.RWMutex
	last    ThrottleStats
	window  ThrottleStats // 最近一个采样窗口的增量
	sampled bool

	// throttling 用原子量暴露，供热路径无锁读取——
	// 代理层可据此在被限流时降级（如拒绝新连接）而不必加锁。
	throttling atomic.Bool

	// OnThrottle 在检测到限流时回调，用于打日志或上报告警。
	// 回调在采样协程中同步执行，实现应保持轻量。
	OnThrottle func(window ThrottleStats, ratio float64)
}

// NewMonitor 创建限流监视器。interval 为采样间隔，建议 10~30 秒——
// 太密会浪费 CPU（这本身就是我们在省的东西），太疏会错过短促尖刺。
func NewMonitor(root string, version CgroupVersion, interval time.Duration) *Monitor {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &Monitor{root: root, version: version, interval: interval}
}

// Start 启动采样协程，返回停止函数。
func (m *Monitor) Start(ctx context.Context) (stop func()) {
	if m.version == VersionNone {
		return func() {} // 无 cgroup 可读，静默降级
	}

	// 先取一次基线，否则首个窗口会把容器启动至今的累计值当成窗口增量
	if s, err := ReadThrottleStats(m.root, m.version); err == nil {
		m.mu.Lock()
		m.last = s
		m.sampled = true
		m.mu.Unlock()
	}

	inner, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.sample()
			case <-inner.Done():
				return
			}
		}
	}()
	return cancel
}

// plausible 判断一次读数是否可信。
//
// cpu.stat 的计数器是单调递增的。读到 0 周期、或比上次更小的值，
// 只可能是读到了部分写入的文件（或 cgroup 被重建）。
// 拿这种读数算增量会得出完全错误的限流率——而限流率正是我们要
// 据以告警的指标，一个假告警比没有告警更糟。
func plausible(current, prev ThrottleStats, hadPrev bool) bool {
	if current.NrPeriods <= 0 {
		return false
	}
	if !hadPrev {
		return true
	}
	return current.NrPeriods >= prev.NrPeriods &&
		current.NrThrottled >= prev.NrThrottled &&
		current.ThrottledMicros >= prev.ThrottledMicros
}

// sample 采样一次并更新窗口增量。
func (m *Monitor) sample() {
	current, err := ReadThrottleStats(m.root, m.version)
	if err != nil {
		return // 读取失败不应影响主流程，静默跳过等下一轮
	}

	m.mu.Lock()
	prev, had := m.last, m.sampled
	if !plausible(current, prev, had) {
		// 读数不可信：丢弃本次采样，保留上次基线等下一轮
		m.mu.Unlock()
		return
	}
	m.last = current
	m.sampled = true
	if !had {
		m.mu.Unlock()
		return
	}
	window := current.Sub(prev)
	m.window = window
	m.mu.Unlock()

	ratio := window.ThrottleRatio()
	m.throttling.Store(window.NrThrottled > 0)
	if window.NrThrottled > 0 && m.OnThrottle != nil {
		m.OnThrottle(window, ratio)
	}
}

// Throttling 返回最近一个窗口内是否发生过限流。热路径可无锁调用。
func (m *Monitor) Throttling() bool { return m.throttling.Load() }

// Window 返回最近一个采样窗口的限流增量。
func (m *Monitor) Window() ThrottleStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.window
}

// Total 返回容器启动至今的累计限流统计。
func (m *Monitor) Total() ThrottleStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.last
}
