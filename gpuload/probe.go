package gpuload

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Target 是一个待探测的后端。
type Target struct {
	Name string
	// MetricsURL 是后端的 Prometheus 端点，通常为 <base_url>/metrics
	MetricsURL string
}

// Probe periodically scrapes each backend's GPU load metrics.
// 周期性拉取各后端的 GPU 负载指标。
//
// Probing uses a **separate HTTP client** from business traffic: the business
// client is tuned for long streams and has no overall timeout, while probing
// must fail fast. Otherwise one stuck backend hangs the probe goroutine and the
// pressure data goes stale without anyone noticing — the most dangerous state.
// 探测与业务请求走**独立的 HTTP 客户端**：业务客户端为长流优化关了整体超时；
// 探测必须快速失败，否则一个卡住的后端会让探测协程悬挂，
// 压力数据变陈旧却不自知——那正是最危险的状态。
type Probe struct {
	registry *Registry
	targets  []Target
	interval time.Duration
	client   *http.Client
	logger   *slog.Logger

	mu       sync.Mutex
	failures map[string]int
}

// NewProbe 创建负载探针。
func NewProbe(reg *Registry, targets []Target, interval time.Duration, logger *slog.Logger) *Probe {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Probe{
		registry: reg,
		targets:  targets,
		interval: interval,
		logger:   logger,
		failures: map[string]int{},
		client: &http.Client{
			// 探测必须快速失败：超时应远小于探测间隔，
			// 否则慢后端会让探测协程堆积
			Timeout: 1500 * time.Millisecond,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: len(targets) + 1,
				IdleConnTimeout:     60 * time.Second,
				DisableCompression:  true,
			},
		},
	}
}

// Start 启动探测协程，返回停止函数。
func (p *Probe) Start(ctx context.Context) (stop func()) {
	inner, cancel := context.WithCancel(ctx)

	// 立刻探一次，避免启动后的头几秒处于 Unknown 状态导致误拒
	p.sweep(inner)

	go func() {
		ticker := time.NewTicker(p.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p.sweep(inner)
			case <-inner.Done():
				return
			}
		}
	}()
	return cancel
}

// sweep probes every backend concurrently.
// 并发探测所有后端。
//
// Concurrent rather than serial: with serial probing, one slow backend among N
// makes every backend after it go stale too.
// 并发而非串行：串行探测下，N 个后端里有一个慢，
// 后面所有后端的数据都会跟着变陈旧。
func (p *Probe) sweep(ctx context.Context) {
	var wg sync.WaitGroup
	for _, t := range p.targets {
		wg.Add(1)
		go func(t Target) {
			defer wg.Done()
			p.probeOne(ctx, t)
		}(t)
	}
	wg.Wait()
}

// probeOne 探测单个后端。
func (p *Probe) probeOne(ctx context.Context, t Target) {
	st := p.registry.Get(t.Name)
	if st == nil {
		return
	}

	snap, err := p.fetch(ctx, t.MetricsURL)
	if err != nil {
		p.mu.Lock()
		p.failures[t.Name]++
		n := p.failures[t.Name]
		p.mu.Unlock()

		// 只在第一次与每 30 次失败时打日志，避免后端长期宕机时刷屏
		if n == 1 || n%30 == 0 {
			p.logger.Warn("GPU 负载探测失败", "backend", t.Name, "consecutive", n, "err", err)
		}
		// 写入无效快照，让状态转为 Unknown——
		// 沉默地沿用旧数据比报告未知更危险
		st.Update(Snapshot{})
		return
	}

	p.mu.Lock()
	if p.failures[t.Name] > 0 {
		p.logger.Info("GPU 负载探测恢复", "backend", t.Name)
		p.failures[t.Name] = 0
	}
	p.mu.Unlock()

	before := st.Pressure()
	st.Update(snap)
	if after := st.Pressure(); after != before {
		level := p.logger.Info
		if after == PressureCritical {
			level = p.logger.Warn
		}
		level("GPU 压力等级变化", "backend", t.Name,
			"from", before.String(), "to", after.String(), "detail", snap.String())
	}
}

// fetch 拉取并解析一个后端的指标。
func (p *Probe) fetch(ctx context.Context, url string) (Snapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Snapshot{}, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return Snapshot{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// 排空并丢弃响应体，让连接能被复用
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return Snapshot{}, fmt.Errorf("指标端点返回 %d", resp.StatusCode)
	}
	// 限制读取上限：指标端点异常时可能返回超大响应
	return ParsePrometheus(io.LimitReader(resp.Body, 8<<20))
}

// MetricsURLFor 从后端 base_url 推导指标端点。
//
// vLLM 的 /metrics 挂在服务根路径，而 base_url 通常带 /v1 后缀，
// 需要剥掉——这个细节不处理会导致所有探测 404，且表现为
// 「压力永远 Unknown」，很难一眼看出原因。
func MetricsURLFor(baseURL string) string {
	u := strings.TrimSuffix(baseURL, "/")
	u = strings.TrimSuffix(u, "/v1")
	return u + "/metrics"
}
