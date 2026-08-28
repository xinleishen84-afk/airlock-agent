// Command airlock-gateway 是企业级 AI 统一网关。
//
// 职责（第 ① 层）：极速拦截 Prompt、PII 双向脱敏、零信任凭证注入、
// 会话安全审计、Token 滑窗限流，全链路 SSE 流式推流。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/gpuload"
	"github.com/xinleishen84-afk/airlock-agent/internal/affinity"
	"github.com/xinleishen84-afk/airlock-agent/internal/cpulimit"
	"github.com/xinleishen84-afk/airlock-agent/internal/credential"
	"github.com/xinleishen84-afk/airlock-agent/internal/lifecycle"
	"github.com/xinleishen84-afk/airlock-agent/internal/proxy"
	"github.com/xinleishen84-afk/airlock-agent/internal/ratelimit"
	"github.com/xinleishen84-afk/airlock-agent/internal/routing"
	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/document"
)

// 命令行参数。
var (
	addr        = flag.String("addr", ":8080", "监听地址")
	configPath  = flag.String("config", "configs/gateway.yaml", "配置文件路径")
	cgroupRoot  = flag.String("cgroup-root", cpulimit.DefaultCgroupRoot, "cgroup 挂载点")
	concurrency = flag.Int("concurrency", 0,
		"工作线程并发度（GOMAXPROCS）。0 表示按 CPU 配额自动推导。\n"+
			"对应 Envoy 的 --concurrency：显式对齐容器 CPU limit 以避免 CFS 限流")
	latencyFirst = flag.Bool("latency-first", true,
		"CPU 配额非整数时向下取整。牺牲少量吞吐换取绝不触发 CFS 冻结")
	logLevel = flag.String("log-level", "info", "日志级别 debug|info|warn|error")

	// 配置自检（参照 nginx -t / apisix test）。走完 100% 装配流程但不启动监听，
	// CI/CD 在部署前强制跑一次，装配失败则流水线挂红。
	dryRun = flag.Bool("dry-run", false,
		"配置自检：走完全部装配流程但不启动监听。失败时退出码为 1，供 CI 拦截")
	dryRunProbe = flag.Bool("probe", false,
		"配合 --dry-run：额外对上游与 NER 服务做真实网络拨测。\n"+
			"默认关闭——CI 通常触达不到生产后端，把网络可达性当作装配失败会误报红")
	dryRunJSON = flag.Bool("json", false,
		"配合 --dry-run：以 JSON 输出报告，供 CI 解析归档")
	probeTimeout = flag.Duration("probe-timeout", 3*time.Second, "网络拨测超时")

	// Schema 导出。CRD 部署到 K8s 后，拼错的键会在 kubectl apply 阶段
	// 被 APIServer 直接拒绝——比进程启动时 fail-fast 更靠前，代价也更小
	printCRD = flag.Bool("print-crd", false,
		"输出 Kubernetes CRD（含 OpenAPI v3 Schema），用于在 APIServer 侧拦截非法配置")
	printSchema = flag.Bool("print-schema", false, "输出配置的 OpenAPI v3 Schema")

	// 三阶段停机窗口。三者之和必须小于 K8s 的
	// terminationGracePeriodSeconds，否则阶段三来不及执行就被 SIGKILL
	drainPeriod = flag.Duration("drain-period", 5*time.Second,
		"停机阶段一：healthz 翻 503 后仍照常服务的时长，\n"+
			"用于等待 K8s/LB 摘除本实例。应大于 readinessProbe 的失败检测时间")
	gracePeriod = flag.Duration("grace-period", 15*time.Second,
		"停机阶段二：等待在途 SSE 流自然结束的上限。\n"+
			"大模型单次生成多在 15s 内完成，该值决定多少比例的流能完整收尾")
	forceTimeout = flag.Duration("force-timeout", 5*time.Second,
		"停机阶段三：持久化状态并关闭监听的上限")
	statePath = flag.String("state-file", "",
		"网关计量状态的持久化路径（预算已花费、限流窗口用量）。\n"+
			"留空则不持久化——重启后预算与配额从零开始。\n"+
			"注意：PII 脱敏映射永不落盘，且从类型层面禁止导出")
)

func main() {
	flag.Parse()

	if *printCRD || *printSchema {
		printSchemaAndExit(*printCRD)
	}

	// Dry-run 必须在任何副作用之前分流：不改 GOMAXPROCS、不起协程、不监听端口
	if *dryRun {
		runDryRunAndExit(DryRunOptions{
			ConfigPath:   *configPath,
			CgroupRoot:   *cgroupRoot,
			Probe:        *dryRunProbe,
			ProbeTimeout: *probeTimeout,
		}, *dryRunJSON)
	}

	logger := newLogger(*logLevel)
	slog.SetDefault(logger)

	// --- CFS 限流防线：必须在起任何 goroutine 之前完成 ---
	monitor := setupCPULimits(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if monitor != nil {
		defer monitor.Start(ctx)()
	}

	// 生命周期状态必须在起监听之前建好：健康检查处理器要引用它
	lifeState := lifecycle.NewState()
	tracker := lifecycle.NewTracker()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		logger.Error("加载配置失败", "path", *configPath, "err", err)
		os.Exit(1)
	}

	shutdownOpts := lifecycle.ShutdownOptions{
		DrainPeriod:  *drainPeriod,
		GracePeriod:  *gracePeriod,
		ForceTimeout: *forceTimeout,
		PollInterval: 2 * time.Second,
	}
	if err := shutdownOpts.Validate(); err != nil {
		logger.Error("停机参数非法", "err", err)
		os.Exit(1)
	}

	var store lifecycle.Store = lifecycle.NopStore{}
	if *statePath != "" {
		store = lifecycle.NewFileStore(*statePath)
	}

	handler, runtimeState, cleanup, err := buildHandler(ctx, cfg, logger, lifeState, tracker)
	if err != nil {
		logger.Error("装配网关失败", "err", err)
		os.Exit(1)
	}
	defer cleanup()

	server := &http.Server{
		Addr:    *addr,
		Handler: withRecovery(mux(handler, lifeState, tracker), logger),

		// ReadHeaderTimeout 防慢速攻击，是唯一能安全设置的读超时
		ReadHeaderTimeout: 10 * time.Second,
		// **WriteTimeout 必须为 0**。任何非零值都会掐断长流——
		// 表现为「短对话正常、长回答总在固定秒数处断掉」，
		// 是 SSE 服务最常见也最难查的线上事故。
		// 流的生命周期由请求 context 与客户端断连控制。
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
		ErrorLog:     slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	restoreState(store, cfg, runtimeState, logger)

	go func() {
		logger.Info("网关启动", "addr", *addr,
			"gomaxprocs", runtime.GOMAXPROCS(0),
			"shutdown_budget", shutdownOpts.Total(),
			"state_store", store.Name())
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("监听失败", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	stop() // 解除信号捕获：第二次 SIGTERM 应能立刻强杀，
	// 否则运维在停机卡住时按 Ctrl-C 会毫无反应

	shutdowner := &lifecycle.Shutdowner{
		State:   lifeState,
		Tracker: tracker,
		Server:  server,
		Store:   store,
		Logger:  logger,
		Options: shutdownOpts,
		Collect: func() *lifecycle.Snapshot {
			return collectSnapshot(cfg, runtimeState)
		},
	}
	res := shutdowner.Run(context.Background())

	// 被强制中断的连接数是评估停机窗口是否合理的唯一依据，
	// 用非零退出码让 CI/运维平台能感知到
	if !res.Graceful {
		logger.Warn("停机未能完全优雅，考虑调大 --grace-period",
			"abandoned", res.Abandoned)
	}
}

// setupCPULimits 处理 CFS 限流陷阱：检测配额、校正并发度、启动限流观测。
//
// 背景：高性能代理默认按宿主机物理核数开工作线程（64 核机器开 64 个），
// 但容器只被授予 8 核配额。CFS 调度器在每个周期用尽配额后会冻结整个
// cgroup 直到下个周期，造成头部阻塞，延迟从毫秒暴涨到数秒。
//
// Go 1.25+ 已原生按 cgroup quota 推导 GOMAXPROCS，但默认策略是
// 「非整数向上取整」且「不小于 2」，两者在延迟敏感场景都会制造超配。
func setupCPULimits(logger *slog.Logger) *cpulimit.Monitor {
	quota, err := cpulimit.DetectQuota(*cgroupRoot)
	if err != nil {
		// 探测失败不能静默当成「不限」——那正好会让并发度按宿主核数开，
		// 撞进我们要防的陷阱。此处必须显式告警。
		logger.Warn("CPU 配额探测失败，无法校正并发度，存在 CFS 限流风险", "err", err)
		return nil
	}
	logger.Info("CPU 配额", "detail", quota.String())

	// 显式指定优先于自动推导，对应 Envoy 的 --concurrency
	if *concurrency > 0 {
		before := runtime.GOMAXPROCS(*concurrency)
		logger.Info("并发度已显式绑定", "before", before, "after", *concurrency)
		if quota.Limited && float64(*concurrency) > quota.CPUs() {
			logger.Warn("显式并发度超过 CPU 配额，满负载时将触发 CFS 冻结",
				"concurrency", *concurrency, "quota_cpus", quota.CPUs())
		}
	} else {
		mode := cpulimit.RoundUp
		if *latencyFirst {
			mode = cpulimit.RoundDown
		}
		rec := cpulimit.Recommend(quota, mode)
		if rec.Oversubscribed {
			logger.Warn("检测到并发度超配（CFS 限流陷阱）", "detail", rec.Reason)
			before, after := cpulimit.Apply(rec)
			logger.Info("并发度已校正", "before", before, "after", after)
		} else {
			logger.Info("并发度检查通过", "detail", rec.Reason)
		}
	}

	if quota.Version == cpulimit.VersionNone {
		return nil
	}

	// 限流观测：GOMAXPROCS 配得对不对只是推断，nr_throttled 在涨才是事实。
	// 没有这个信号，生产上的延迟尖刺无从归因。
	m := cpulimit.NewMonitor(*cgroupRoot, quota.Version, 15*time.Second)
	m.OnThrottle = func(w cpulimit.ThrottleStats, ratio float64) {
		logger.Warn("检测到 CFS 限流——延迟正在受损",
			"throttled_periods", w.NrThrottled,
			"total_periods", w.NrPeriods,
			"ratio", fmt.Sprintf("%.1f%%", ratio*100),
			"throttled_ms", w.ThrottledMicros/1000,
			"hint", "降低 GOMAXPROCS 或提高容器 CPU limit")
	}
	return m
}

// buildHandler 装配代理处理器及其全部依赖。
func buildHandler(
	ctx context.Context, cfg *Config, logger *slog.Logger,
	lifeState *lifecycle.State, tracker *lifecycle.Tracker,
) (*proxy.Handler, *runtimeComponents, func(), error) {
	policy, err := buildPolicy(cfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("构造路由策略: %w", err)
	}
	logger.Info("路由策略已加载\n" + policy.Describe())

	breakers := map[string]*routing.Breaker{}
	creds := map[string]*credential.BackendPolicy{}
	for _, t := range cfg.Targets {
		breakers[t.Name] = routing.NewBreaker(t.Name,
			cfg.Breaker.FailureThreshold, cfg.Breaker.RecoveryTimeout.Std())

		if t.CredentialKey == "" {
			continue // 内网后端可不配凭证
		}
		cp := buildCredentialPolicy(cfg, t)
		// 启动期校验：配置错误应该让进程起不来，而不是在生产流量上暴露
		if err := cp.Validate(); err != nil {
			return nil, nil, nil, fmt.Errorf("后端 %s 的凭证策略: %w", t.Name, err)
		}
		creds[t.Name] = cp
	}

	detector, err := buildDetector(cfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("构造 PII 检测器: %w", err)
	}
	// 把「哪些字段会被 NER 触碰」打进启动日志，让它成为可审计的显式清单。
	// 其余字段——包括网关不认识的新参数——在物理上不会被访问。
	logger.Info("PII 定向清洗白名单（仅以下路径会被送进检测器）",
		"regions", document.SanitizeRuleDescriptions())

	if cfg.PII.NER.Endpoint != "" {
		logger.Info("外部 NER 已接入", "endpoint", cfg.PII.NER.Endpoint,
			"fail_open", cfg.PII.NER.FailOpen)
	}
	if comp, ok := detector.(detect.GapReporter); ok {
		if missing := comp.Missing(); len(missing) > 0 {
			// 正则检测不出人名——这是最危险的静默配置，必须显式告警
			logger.Warn("PII 检测存在覆盖缺口，这几类实体将完全裸奔",
				"missing", missing,
				"hint", "配置 gazetteer 名册或接入本地 NER 模型服务")
		}
	}

	// GPU 显存压力探测：让网关直接理解 KV 缓存负载，而不只是 QPS
	gpuReg := gpuload.NewRegistry()
	probeTargets := make([]gpuload.Target, 0, len(cfg.Targets))
	for _, t := range cfg.Targets {
		gpuReg.Register(t.Name, toThresholds(cfg.GPU))
		probeTargets = append(probeTargets, gpuload.Target{
			Name: t.Name, MetricsURL: gpuload.MetricsURLFor(t.BaseURL),
		})
	}
	probe := gpuload.NewProbe(gpuReg, probeTargets, cfg.GPU.ProbeInterval.Std(), logger)
	stopProbe := probe.Start(ctx)

	// 前缀亲和路由：同前缀请求钉到同一副本，让 vLLM 的 prefix caching 生效
	var ring *affinity.Ring
	if cfg.GPU.PrefixAffinity {
		names := make([]string, 0, len(cfg.Targets))
		for _, t := range cfg.Targets {
			names = append(names, t.Name)
		}
		ring = affinity.NewRing(names, cfg.GPU.AffinityLoadFactor)
		logger.Info("前缀亲和路由已启用",
			"replicas", len(names), "load_factor", cfg.GPU.AffinityLoadFactor)
	} else {
		logger.Warn("前缀亲和路由未启用",
			"影响", "同前缀请求将被打散，vLLM prefix caching 命中率降至 1/副本数")
	}

	limiter := ratelimit.NewLimiter(toLimits(cfg.RateLimit.LimitConfig))
	for subject, l := range cfg.RateLimit.PerSubject {
		limiter.SetLimits(subject, toLimits(l))
	}
	stopLimiterJanitor := limiter.StartJanitor(30 * time.Second)

	vaults := anonymize.NewVaultRegistry(cfg.SessionTTL.Std(), cfg.MaxSessions)
	stopVaultJanitor := vaults.StartJanitor(time.Minute)

	handler := proxy.NewHandler(proxy.Deps{
		Policy:       policy,
		Breakers:     breakers,
		Creds:        creds,
		Limiter:      limiter,
		Redactor:     anonymize.NewRedactor(detector, cfg.PII.FailClosed),
		Vaults:       vaults,
		Client:       proxy.NewClient(toTransportConfig(cfg.Upstream)),
		Logger:       logger,
		GPULoad:      gpuReg,
		Affinity:     ring,
		Lifecycle:    lifeState,
		Tracker:      tracker,
		AlwaysRedact: cfg.PII.AlwaysRedact,
	})

	cleanup := func() {
		stopProbe()
		stopLimiterJanitor()
		stopVaultJanitor()
		// 进程退出前清空全部脱敏映射——不留任何真实值在内存里。
		// 这一步必须在状态持久化**之后**执行，但两者操作的是完全不同的数据：
		// 快照里只有计量数字，映射从类型层面就无法进入快照。
		vaults.PurgeAll()
	}
	return handler, &runtimeComponents{policy: policy, limiter: limiter}, cleanup, nil
}

// runtimeComponents 持有需要在停机时导出状态的组件。
type runtimeComponents struct {
	policy  *routing.Policy
	limiter *ratelimit.Limiter
}

// mux 组装路由。
func mux(h *proxy.Handler, state *lifecycle.State, tracker *lifecycle.Tracker) http.Handler {
	m := http.NewServeMux()
	m.Handle("POST /v1/chat/completions", h)
	// 健康检查由生命周期状态驱动：收到 SIGTERM 后立刻翻 503，
	// 触发 K8s 摘除本实例。这是整个停机流程的起点。
	m.HandleFunc("GET /healthz", lifecycle.HealthHandler(state))
	// 存活探针与就绪探针分开：livenessProbe 只关心进程是否卡死，
	// 停机期间返回 200 避免被 K8s 提前 SIGKILL；
	// readinessProbe 打 /healthz，停机时立刻摘流量。
	m.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("alive\n"))
	})
	m.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		s := h.Stats()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "gateway_requests_total %d\n", s.Requests.Load())
		fmt.Fprintf(w, "gateway_streamed_total %d\n", s.Streamed.Load())
		fmt.Fprintf(w, "gateway_rejected_total %d\n", s.Rejected.Load())
		fmt.Fprintf(w, "gateway_upstream_5xx_total %d\n", s.Upstream5xx.Load())
		fmt.Fprintf(w, "gateway_client_abort_total %d\n", s.ClientAbort.Load())
		fmt.Fprintf(w, "gateway_pii_leak_blocked_total %d\n", s.LeakBlocked.Load())
		fmt.Fprintf(w, "gateway_ttft_avg_ms %d\n", s.AvgTTFT().Milliseconds())
		// 工具调用轮单独一条：与上面那条混在一起会让 TTFT 变成双峰均值
		fmt.Fprintf(w, "gateway_toolcall_ttft_avg_ms %d\n",
			s.AvgToolCallTTFT().Milliseconds())
		fmt.Fprintf(w, "gateway_gpu_shed_total %d\n", s.GPUShed.Load())
		fmt.Fprintf(w, "gateway_prefix_pinned_total %d\n", s.PrefixPinned.Load())
		fmt.Fprintf(w, "gateway_gomaxprocs %d\n", runtime.GOMAXPROCS(0))
		fmt.Fprintf(w, "gateway_in_flight %d\n", tracker.InFlight())
		fmt.Fprintf(w, "gateway_streaming %d\n", tracker.Streaming())
		fmt.Fprintf(w, "gateway_shutdown_rejected_total %d\n", s.ShutdownRejected.Load())
		fmt.Fprintf(w, "gateway_failover_total %d\n", s.Failover.Load())
		// 阶段既给标签形式（便于告警规则）也给数值形式（便于轨迹断言）：
		// 停机测试需要验证阶段单调推进，用数值比解析标签可靠得多
		fmt.Fprintf(w, "gateway_phase{phase=\"%s\"} 1\n", state.Phase())
		fmt.Fprintf(w, "gateway_phase_id %d\n", int(state.Phase()))
	})
	return m
}

// withRecovery 兜住 panic，避免单个请求打崩整个进程。
//
// 网关承载着所有在途流，一次 panic 会同时切断成千上万条连接——
// 恢复的代价远小于让它崩掉。
func withRecovery(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				logger.Error("请求处理 panic", "panic", v, "path", r.URL.Path)
				// 响应可能已开始写出，此时再 WriteHeader 会 warn，
				// 但连接终止本身已经足够传达失败
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// newLogger 构造结构化日志器。
func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

// collectSnapshot 采集需要跨重启保留的计量状态。
//
// 只采集两类：预算已花费、限流窗口用量。判据是「丢失会造成实际损失」——
// 预算丢了是钱（$500 的月度上限，重启后忘记已花 $480，会再花一个 $500）；
// 限流窗口丢了是保护失效（滚动更新后每个新实例都发放全新配额，
// Agent 的相关性突发会直接打满 GPU）。
//
// **PII 脱敏映射不在其中**。它存的是「占位符 -> 真实姓名/手机/身份证」，
// 落盘就等于把脱敏网关变成 PII 数据库。Snapshot 的结构体里没有任何
// 字段能装下它，SessionVault 本身也从类型层面禁止序列化。
func collectSnapshot(cfg *Config, rt *runtimeComponents) *lifecycle.Snapshot {
	if rt == nil {
		return nil
	}
	snap := &lifecycle.Snapshot{
		BudgetSpent:   map[string]float64{},
		RateLimitUsed: map[string]int64{},
	}

	for tierKey := range cfg.Budgets {
		var tier int
		if _, err := fmt.Sscanf(tierKey, "%d", &tier); err != nil {
			continue
		}
		if b := rt.policy.BudgetOf(routing.Tier(tier)); b != nil {
			snap.BudgetSpent[tierKey] = b.Spent()
		}
	}

	for subject := range cfg.RateLimit.PerSubject {
		used, _, _ := rt.limiter.Snapshot(subject)
		if used > 0 {
			snap.RateLimitUsed[subject] = used
		}
	}
	return snap
}

// restoreState 从快照恢复计量状态。
//
// 恢复失败一律降级为「从零开始」并告警，而不是拒绝启动：
// 一个损坏的快照文件不该让整个网关起不来。但必须大声报出来——
// 静默从零开始意味着预算保护在这个周期内完全失效。
func restoreState(store lifecycle.Store, cfg *Config, rt *runtimeComponents, logger *slog.Logger) {
	snap, err := store.Load()
	if err != nil {
		logger.Warn("加载状态快照失败，预算与限流窗口将从零开始",
			"store", store.Name(), "err", err)
		return
	}
	if snap == nil {
		return // 首次启动，正常情况
	}

	// 快照过旧则丢弃：限流窗口通常只有几分钟，
	// 拿一小时前的用量去恢复毫无意义，还会误伤正常流量
	if snap.Age() > time.Hour {
		logger.Info("状态快照过旧，已忽略", "age", snap.Age().Round(time.Second))
		return
	}

	restored := 0
	for tierKey, spent := range snap.BudgetSpent {
		var tier int
		if _, err := fmt.Sscanf(tierKey, "%d", &tier); err != nil {
			continue
		}
		if b := rt.policy.BudgetOf(routing.Tier(tier)); b != nil {
			b.Record(spent)
			restored++
		}
	}
	logger.Info("已从快照恢复计量状态",
		"age", snap.Age().Round(time.Second),
		"budgets", restored,
		"saved_at", snap.SavedAt.Format(time.RFC3339))
}
