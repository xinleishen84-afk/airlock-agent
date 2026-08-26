// Package gpuload lets the gateway reason about GPU memory load and KV cache
// pressure directly.
// 让网关直接理解 GPU 显存负载与 KV 缓存压力。
//
// # Why QPS is not enough
// # 为什么 QPS 不够
//
// Traditional gateways throttle on QPS or connection count, but the real
// constraint on LLM inference is **KV cache memory**:
// 传统网关按 QPS 或连接数限流，但 LLM 推理的真实约束是 **KV 缓存显存**：
//
//	KV ≈ (generated + prompt tokens) × layers × heads × head_dim × 2 × precision
//
// A 100K-token prompt with 1 output token and a 1K-token prompt with 100K output
// tokens have identical QPS and wildly different memory pressure. A QPS-only
// gateway keeps admitting traffic while the GPU is already near OOM.
// 一个 10 万 token 的 prompt 配 1 个输出，和 1 千 token 配 10 万输出，
// QPS 完全相同，显存压力却天差地别。只看 QPS 的网关会在 GPU 濒临 OOM 时继续放行。
//
// # Correlated bursts
// # 相关性突发
//
// The dangerous traffic shape is not steady high load but **many autonomous
// agents firing at once**: a coding agent emits dozens of concurrent requests
// from a single planning step, and their arrival times are highly correlated.
// The smoothing assumptions of queueing theory break down here — the burst fills
// the KV cache outright, vLLM starts preempting and swapping out, in-flight
// requests are recomputed repeatedly, and the backend livelocks. The gateway has
// to shed the excess at the **edge**.
// 最危险的流量形态不是均匀高负载，而是**多个自动 Agent 同时爆发**：
// coding agent 一次规划就并发发出几十个请求，到达时间高度相关。
// 排队论的平滑假设在此失效——瞬时并发会直接打满 KV，vLLM 开始抢占换出，
// 在途请求被反复重算，整个后端进入活锁。网关必须在**边缘**挡掉多余请求。
package gpuload

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// vLLM 暴露的关键指标名。
//
// 只取这几个：KV 缓存占用是显存压力的直接信号，等待队列长度是
// 排队恶化的先行指标，前缀缓存命中率用于验证亲和路由是否真的生效。
const (
	metricRunning       = "vllm:num_requests_running"
	metricWaiting       = "vllm:num_requests_waiting"
	metricKVCacheUsage  = "vllm:gpu_cache_usage_perc"
	metricPrefixHits    = "vllm:prefix_cache_hits_total"
	metricPrefixQueries = "vllm:prefix_cache_queries_total"
	metricPreemptions   = "vllm:num_preemptions_total"
)

// Snapshot is one sample of GPU load.
// 是一次 GPU 负载采样。
type Snapshot struct {
	// Running 是正在解码的请求数
	Running int
	// Waiting 是排队等待的请求数。这是恶化的先行指标——
	// KV 占用还没满时，等待队列已经开始堆积。
	Waiting int
	// KVCacheUsage 是 KV 缓存显存占用比例，0..1。
	// 这是最直接的 OOM 距离指标。
	KVCacheUsage float64
	// PrefixHits / PrefixQueries 用于计算前缀缓存命中率。
	// 命中率持续偏低说明亲和路由失效，prefill 开销白白翻倍。
	PrefixHits    float64
	PrefixQueries float64
	// Preemptions 是累计抢占次数。它一旦开始增长，
	// 就说明 KV 已经不够用，后端在反复换出重算——必须立刻降压。
	Preemptions float64

	// Valid 为 false 表示本次采样失败，调用方应沿用上一次或按保守值处理
	Valid bool
}

// PrefixHitRate 返回前缀缓存命中率。无查询时返回 0。
func (s Snapshot) PrefixHitRate() float64 {
	if s.PrefixQueries <= 0 {
		return 0
	}
	return s.PrefixHits / s.PrefixQueries
}

// QueueDepth 返回总在途请求数。
func (s Snapshot) QueueDepth() int { return s.Running + s.Waiting }

// String 返回可读描述。
func (s Snapshot) String() string {
	if !s.Valid {
		return "GPU 负载：采样无效"
	}
	return fmt.Sprintf("running=%d waiting=%d kv=%.1f%% prefix_hit=%.1f%%",
		s.Running, s.Waiting, s.KVCacheUsage*100, s.PrefixHitRate()*100)
}

// ParsePrometheus extracts the needed metrics from Prometheus text format.
// 从 Prometheus 文本格式中抽取所需指标。
//
// Deliberately avoids the Prometheus client library: the gateway is a security
// component and every dependency is attack surface, while we need exactly six
// scalars. Parsing allocates nothing beyond the result, because this runs
// frequently.
// 刻意不引入 prometheus 客户端库：网关是安全组件，依赖越少攻击面越小，
// 而我们只需要六个标量。整个解析零分配（除结果本身），因为这会被高频调用。
func ParsePrometheus(r io.Reader) (Snapshot, error) {
	var s Snapshot
	scanner := bufio.NewScanner(r)
	// vLLM 的 label 可能很长（含模型全名），放大行缓冲
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)

	found := 0
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue // 跳过 HELP / TYPE 注释
		}

		name, value, ok := splitMetric(line)
		if !ok {
			continue
		}

		switch name {
		case metricRunning:
			s.Running = int(value)
			found++
		case metricWaiting:
			s.Waiting = int(value)
			found++
		case metricKVCacheUsage:
			s.KVCacheUsage = value
			found++
		case metricPrefixHits:
			s.PrefixHits = value
		case metricPrefixQueries:
			s.PrefixQueries = value
		case metricPreemptions:
			s.Preemptions = value
		}
	}
	if err := scanner.Err(); err != nil {
		return Snapshot{}, fmt.Errorf("读取指标失败: %w", err)
	}
	// 三个核心指标必须齐全，否则准入判断会基于残缺数据——
	// 那比没有数据更危险，因为它看起来是有效的
	if found < 3 {
		return Snapshot{}, fmt.Errorf("指标不完整：仅解析到 %d/3 个核心指标", found)
	}
	s.Valid = true
	return s, nil
}

// splitMetric 从一行 Prometheus 文本中解出指标名与值。
//
// 处理两种形态：
//
//	vllm:num_requests_running 3.0
//	vllm:num_requests_running{model_name="gpt-oss-120b"} 3.0
func splitMetric(line string) (name string, value float64, ok bool) {
	// 从右往左找最后一个空格：label 值里可能含空格，但值本身不会
	sp := strings.LastIndexByte(line, ' ')
	if sp <= 0 {
		return "", 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(line[sp+1:]), 64)
	if err != nil {
		return "", 0, false
	}

	name = line[:sp]
	// 剥掉 label 部分
	if brace := strings.IndexByte(name, '{'); brace >= 0 {
		name = name[:brace]
	}
	return strings.TrimSpace(name), v, true
}
