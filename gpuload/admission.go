package gpuload

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Pressure is a backend's memory-pressure level.
// 是后端的显存压力等级。
type Pressure int

const (
	// PressureNormal：KV 充裕，全量放行
	PressureNormal Pressure = iota
	// PressureElevated：KV 吃紧，开始拒绝低优先级请求。
	// 这一档存在的意义是「保住高价值流量」——等到 Critical 才动手，
	// 队列里已经全是低价值请求，高优先级请求照样排在后面。
	PressureElevated
	// PressureCritical：濒临 OOM 或已在抢占，只放行最高优先级
	PressureCritical
	// PressureUnknown：探测失效。按保守档处理，不能当成正常。
	PressureUnknown
)

// String 返回压力等级名。
func (p Pressure) String() string {
	switch p {
	case PressureNormal:
		return "normal"
	case PressureElevated:
		return "elevated"
	case PressureCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Thresholds are the pressure-tier thresholds.
// 是压力分档阈值。
type Thresholds struct {
	// KVElevated / KVCritical 是 KV 缓存占用比例阈值。
	//
	// 不设成 0.95 之类的贴边值：从「网关放行」到「请求真正占住 KV」
	// 有数百毫秒延迟，等读数到 95% 再刹车，那批在途请求已经把它推过 100%。
	// 阈值必须为这段控制延迟留出余量。
	KVElevated float64
	KVCritical float64

	// WaitingElevated / WaitingCritical 是等待队列长度阈值。
	// 队列堆积比 KV 占用更早出现，是更灵敏的先行指标。
	WaitingElevated int
	WaitingCritical int

	// PreemptionWindow 内出现任何抢占即直接判定 Critical。
	// 抢占意味着 KV 已经不够用，后端在反复换出重算——
	// 此时任何新请求都是在加剧活锁。
	PreemptionWindow time.Duration

	// StaleAfter 超过此时长未更新的快照视为失效
	StaleAfter time.Duration
}

// DefaultThresholds 返回经验默认值。
func DefaultThresholds() Thresholds {
	return Thresholds{
		KVElevated:       0.75,
		KVCritical:       0.90,
		WaitingElevated:  8,
		WaitingCritical:  32,
		PreemptionWindow: 30 * time.Second,
		StaleAfter:       15 * time.Second,
	}
}

// Decision is the outcome of one admission check.
// 是一次准入判定的结果。
type Decision struct {
	Admit    bool
	Pressure Pressure
	// Reason 用于日志与 429 响应体，让调用方知道为什么被拒
	Reason string
	// RetryAfter 是建议的重试等待时间。
	// 按压力等级给不同值——Critical 时给长一点，避免客户端立刻重试
	// 把刚腾出的 KV 又填满（重试风暴是 OOM 的常见二次诱因）。
	RetryAfter time.Duration
}

// State tracks one backend's load and pressure verdict.
// 跟踪单个后端的负载状态与压力判定。
type State struct {
	name       string
	thresholds Thresholds

	mu             sync.RWMutex
	snapshot       Snapshot
	updatedAt      time.Time
	lastPreemption float64
	preemptedAt    time.Time

	// pressure 用原子量暴露，供热路径无锁读取
	pressure atomic.Int32
}

// NewState 创建后端负载状态。
func NewState(name string, th Thresholds) *State {
	s := &State{name: name, thresholds: th}
	// 初始状态为 Unknown 而非 Normal：探测还没跑过，
	// 此时按「正常」放行等于闭眼开车
	s.pressure.Store(int32(PressureUnknown))
	return s
}

// Name 返回后端名。
func (s *State) Name() string { return s.name }

// Update 写入一次采样并重算压力等级。
func (s *State) Update(snap Snapshot) {
	s.mu.Lock()
	prevPreemptions := s.lastPreemption
	hadPrev := !s.updatedAt.IsZero()

	s.snapshot = snap
	s.updatedAt = time.Now()
	if snap.Valid {
		// 抢占计数增长即记录时间戳。这是唯一「一票否决」的信号。
		if hadPrev && snap.Preemptions > prevPreemptions {
			s.preemptedAt = time.Now()
		}
		s.lastPreemption = snap.Preemptions
	}
	p := s.computeLocked()
	s.mu.Unlock()

	s.pressure.Store(int32(p))
}

// computeLocked 计算当前压力等级（调用方需已持锁）。
func (s *State) computeLocked() Pressure {
	if !s.snapshot.Valid {
		return PressureUnknown
	}
	if time.Since(s.updatedAt) > s.thresholds.StaleAfter {
		// 快照过期：探测可能已挂，不能拿旧数据当依据
		return PressureUnknown
	}

	// 抢占是一票否决：它意味着 KV 已经不够用，后端在反复换出重算
	if !s.preemptedAt.IsZero() && time.Since(s.preemptedAt) < s.thresholds.PreemptionWindow {
		return PressureCritical
	}

	snap := s.snapshot
	if snap.KVCacheUsage >= s.thresholds.KVCritical ||
		snap.Waiting >= s.thresholds.WaitingCritical {
		return PressureCritical
	}
	if snap.KVCacheUsage >= s.thresholds.KVElevated ||
		snap.Waiting >= s.thresholds.WaitingElevated {
		return PressureElevated
	}
	return PressureNormal
}

// Pressure 返回当前压力等级。热路径可无锁调用。
func (s *State) Pressure() Pressure { return Pressure(s.pressure.Load()) }

// Snapshot 返回最近一次采样。
func (s *State) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot
}

// Admit decides whether a request may proceed.
// 判定一个请求能否放行。
//
// priority is the caller's business priority 0-9 (from x-workload-priority).
// The core idea of tiered shedding: **sacrifice low-value traffic before the GPU
// deadlocks**. Cutting everything off only once it is fully saturated is too
// late — by then the queue is already full of low-priority requests, and
// high-value ones still sit behind them. Degradation must be gradual and ordered
// by value.
// priority 是调用方的业务优先级 0-9。分档拒绝的核心思想：
// **在 GPU 死锁之前，先牺牲低价值流量**。等到打满再一刀切，
// 队列里已经全是低优先级请求，高价值请求照样排在后面——
// 降级必须是渐进的、按价值排序的。
func (s *State) Admit(priority int) Decision {
	p := s.Pressure()
	snap := s.Snapshot()

	switch p {
	case PressureNormal:
		return Decision{Admit: true, Pressure: p}

	case PressureElevated:
		// 只放行中等以上优先级。批量作业（通常 priority<=3）先被挡掉
		if priority >= 4 {
			return Decision{Admit: true, Pressure: p}
		}
		return Decision{
			Pressure: p, RetryAfter: 2 * time.Second,
			Reason: fmt.Sprintf(
				"后端 %s 显存吃紧（KV %.0f%%，排队 %d），低优先级请求已降级",
				s.name, snap.KVCacheUsage*100, snap.Waiting),
		}

	case PressureCritical:
		// 只放行最高优先级。这是保命档
		if priority >= 8 {
			return Decision{Admit: true, Pressure: p}
		}
		return Decision{
			Pressure: p, RetryAfter: 10 * time.Second,
			Reason: fmt.Sprintf(
				"后端 %s 显存濒临耗尽（KV %.0f%%，排队 %d），仅放行紧急请求",
				s.name, snap.KVCacheUsage*100, snap.Waiting),
		}

	default: // PressureUnknown
		// 探测失效时保守放行中等以上优先级：
		// 完全拒绝会让探测故障升级成服务故障，
		// 完全放行则失去保护。取折中并大声告警。
		if priority >= 4 {
			return Decision{Admit: true, Pressure: p}
		}
		return Decision{
			Pressure: p, RetryAfter: 5 * time.Second,
			Reason: fmt.Sprintf("后端 %s 负载探测失效，保守拒绝低优先级请求", s.name),
		}
	}
}

// Registry manages every backend's load state.
// 管理所有后端的负载状态。
type Registry struct {
	mu     sync.RWMutex
	states map[string]*State
}

// NewRegistry 创建注册表。
func NewRegistry() *Registry {
	return &Registry{states: map[string]*State{}}
}

// Register 登记一个后端。
func (r *Registry) Register(name string, th Thresholds) *State {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st, ok := r.states[name]; ok {
		return st
	}
	st := NewState(name, th)
	r.states[name] = st
	return st
}

// Get 取出后端状态，不存在时返回 nil。
func (r *Registry) Get(name string) *State {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.states[name]
}

// All 返回全部后端状态。
func (r *Registry) All() []*State {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*State, 0, len(r.states))
	for _, st := range r.states {
		out = append(out, st)
	}
	return out
}
