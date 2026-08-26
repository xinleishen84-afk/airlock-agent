package lifecycle

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// ShutdownOptions 控制三阶段停机的时间窗口。
type ShutdownOptions struct {
	// DrainPeriod 是阶段一时长：健康检查已翻 503，但仍照常服务。
	//
	// 这段时间是给 K8s/LB 摘除 endpoint 用的，取值应大于
	// (readinessProbe.periodSeconds × failureThreshold) + kube-proxy 同步延迟。
	// 设得太短，摘除还没生效就开始拒绝请求，客户端会看到本可避免的 503。
	DrainPeriod time.Duration

	// GracePeriod 是阶段二上限：等待在途 SSE 流自然结束。
	//
	// 大模型单次生成绝大多数在 15 秒内结束，15~30s 能让 95% 以上
	// 正在吐字的连接完整收尾。设得过长会拖慢滚动更新，
	// 且 K8s 的 terminationGracePeriodSeconds 到点会直接 SIGKILL——
	// 本值加上 DrainPeriod 必须小于它，否则阶段三根本没机会执行。
	GracePeriod time.Duration

	// ForceTimeout 是阶段三上限：持久化状态并物理关闭
	ForceTimeout time.Duration

	// PollInterval 是等待期间打印进度日志的间隔。
	// 停机过程若毫无输出，运维无法判断是在正常收敛还是卡死了。
	PollInterval time.Duration
}

// DefaultShutdownOptions 返回经验默认值。
//
// 三段之和 20s，需小于 K8s 的 terminationGracePeriodSeconds（默认 30s）。
// 部署时若调大了 GracePeriod，务必同步调大 terminationGracePeriodSeconds。
func DefaultShutdownOptions() ShutdownOptions {
	return ShutdownOptions{
		DrainPeriod:  5 * time.Second,
		GracePeriod:  15 * time.Second,
		ForceTimeout: 5 * time.Second,
		PollInterval: 2 * time.Second,
	}
}

// Validate 校验时间窗口配置。
func (o ShutdownOptions) Validate() error {
	if o.DrainPeriod < 0 || o.GracePeriod < 0 || o.ForceTimeout < 0 {
		return errors.New("停机时间窗口不能为负")
	}
	if o.GracePeriod == 0 {
		return errors.New("宽限期为 0 等于暴力掐断所有在途流")
	}
	return nil
}

// Total 返回三阶段总时长，用于与 K8s 的 terminationGracePeriodSeconds 比对。
func (o ShutdownOptions) Total() time.Duration {
	return o.DrainPeriod + o.GracePeriod + o.ForceTimeout
}

// Shutdowner 编排三阶段优雅停机。
type Shutdowner struct {
	State   *State
	Tracker *Tracker
	Server  *http.Server
	Store   Store
	Logger  *slog.Logger
	Options ShutdownOptions

	// Collect 在阶段三被调用，产出待持久化的快照。
	// 为 nil 时跳过持久化。
	Collect func() *Snapshot

	// OnPhase 在阶段切换时回调，供指标上报。
	OnPhase func(Phase)
}

// Result 是停机结果，供退出码与日志使用。
type Result struct {
	// Graceful 为 true 表示所有在途流都自然收尾
	Graceful bool
	// Abandoned 是被强制中断的在途请求数
	Abandoned int64
	// StateSaved 表示状态是否成功持久化
	StateSaved bool
	Duration   time.Duration
}

// Run 执行三阶段停机。
func (s *Shutdowner) Run(ctx context.Context) Result {
	start := time.Now()
	log := s.Logger
	if log == nil {
		log = slog.Default()
	}
	res := Result{Graceful: true}

	// ---------- 阶段一：排空 ----------
	//
	// 只翻健康检查，**不关监听、不拒请求**。此刻 LB 大概率还没摘掉本实例，
	// 拒绝会制造本可避免的错误；而关监听更糟——客户端拿到的是
	// connection refused，既没有 Retry-After 也不触发上游重试策略。
	s.advance(PhaseDraining, log)
	log.Info("停机阶段一：排空新流量",
		"healthz", "503",
		"drain_period", s.Options.DrainPeriod,
		"in_flight", s.Tracker.InFlight(),
		"说明", "保持监听并照常服务，等待 K8s/LB 摘除本实例")

	if !sleepCtx(ctx, s.Options.DrainPeriod) {
		log.Warn("排空期被中断，直接进入收敛阶段")
	}

	// ---------- 阶段二：收敛在途流 ----------
	//
	// 此时才开始拒绝新请求——返回干净的 503 + Retry-After，
	// 而不是让连接被拒。已在途的 SSE 流继续吐字直到自然结束。
	s.advance(PhaseClosing, log)
	inFlight, streaming := s.Tracker.InFlight(), s.Tracker.Streaming()
	log.Info("停机阶段二：等待在途流收敛",
		"in_flight", inFlight, "streaming", streaming,
		"grace_period", s.Options.GracePeriod)

	if inFlight > 0 {
		s.waitWithProgress(ctx, log)
	}

	if remaining := s.Tracker.InFlight(); remaining > 0 {
		res.Graceful = false
		res.Abandoned = remaining
		log.Warn("宽限期已尽，仍有在途连接将被强制中断",
			"abandoned", remaining,
			"streaming", s.Tracker.Streaming(),
			"建议", "若该数字持续偏高，说明 grace_period 短于典型生成时长")
	} else {
		log.Info("全部在途流已优雅收尾")
	}

	// ---------- 阶段三：持久化并退出 ----------
	s.advance(PhaseStopped, log)
	res.StateSaved = s.persist(log)

	closeCtx, cancel := context.WithTimeout(context.Background(), s.Options.ForceTimeout)
	defer cancel()
	if s.Server != nil {
		if err := s.Server.Shutdown(closeCtx); err != nil {
			log.Warn("关闭监听超时，强制退出", "err", err)
		}
	}

	res.Duration = time.Since(start)
	log.Info("停机完成",
		"graceful", res.Graceful, "abandoned", res.Abandoned,
		"state_saved", res.StateSaved, "duration", res.Duration)
	return res
}

// waitWithProgress 等待在途归零，期间定期打印进度。
//
// 停机若毫无输出，运维无法区分「正在正常收敛」与「卡死了」——
// 那会导致有人手动去 kill，把本来能优雅收尾的流全砍掉。
func (s *Shutdowner) waitWithProgress(ctx context.Context, log *slog.Logger) {
	deadline := time.Now().Add(s.Options.GracePeriod)
	interval := s.Options.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		wait := interval
		if remaining < wait {
			wait = remaining
		}
		if s.Tracker.WaitZero(ctx, wait) {
			return
		}
		log.Info("等待在途流收敛中",
			"in_flight", s.Tracker.InFlight(),
			"streaming", s.Tracker.Streaming(),
			"remaining", remaining.Round(time.Second))
	}
}

// persist 持久化网关状态。
func (s *Shutdowner) persist(log *slog.Logger) bool {
	if s.Store == nil || s.Collect == nil {
		return false
	}
	snap := s.Collect()
	if snap == nil {
		return false
	}
	if err := s.Store.Save(snap); err != nil {
		// 持久化失败不阻止退出，但必须大声报出来：
		// 下次启动会以为预算是零，可能多花一整个周期的额度
		log.Error("状态持久化失败，重启后预算与限流窗口将从零开始",
			"store", s.Store.Name(), "err", err)
		return false
	}
	log.Info("网关状态已持久化",
		"store", s.Store.Name(),
		"budgets", len(snap.BudgetSpent),
		"subjects", len(snap.RateLimitUsed),
		"注意", "PII 脱敏映射不在其中，且从类型层面禁止导出")
	return true
}

// advance 推进阶段并触发回调。
func (s *Shutdowner) advance(p Phase, log *slog.Logger) {
	if s.State.Advance(p) && s.OnPhase != nil {
		s.OnPhase(p)
	}
}

// sleepCtx 可被上下文取消的休眠。返回 false 表示被取消。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// HealthHandler 返回健康检查处理器。
//
// 排空阶段起返回 503。这是整个停机流程的起点，也是唯一能让
// K8s 主动摘除本实例的信号——没有它，摘除只能等 Pod 真正消失，
// 那段窗口里的请求全部失败。
func HealthHandler(state *State) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		phase := state.Phase()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Gateway-Phase", phase.String())

		if state.Healthy() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("draining: " + phase.String() + "\n"))
	}
}
