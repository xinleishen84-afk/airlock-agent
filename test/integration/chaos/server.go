// Package chaos 提供用于混沌测试的慢流上游。
//
// # 为什么需要专门的慢流端点
//
// 优雅停机测试的成败取决于一件事：**SIGTERM 到达时必须真的有流在途**。
// 用正常速度的上游（几十毫秒吐完）测停机，信号到达时流早已结束，
// 测试会以 abandoned=0 静默通过——而它什么都没验证。
//
// 本包刻意把推流间隔拉长（如每秒 2 个 token，持续 10 秒），
// 制造一个宽阔且时长确定的「轰炸窗口」，让停机逻辑能被稳定抓取。
//
// 这不是「把测试调慢」，而是把一个**时序竞态**转化为**确定性场景**：
// 窗口足够宽，信号落在窗口内就不再依赖运气。
package chaos

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"
)

// Config 描述慢流的形状。
type Config struct {
	// TokensPerSecond 是推流速率。设为 2 意味着每 500ms 吐一个 token。
	TokensPerSecond float64
	// TotalTokens 是单次生成的 token 总数。
	// 它与速率共同决定轰炸窗口宽度：TotalTokens/TokensPerSecond 秒。
	TotalTokens int
	// FirstTokenDelay 模拟 prefill 阶段的等待
	FirstTokenDelay time.Duration
	// KVUsage 是 /metrics 报告的显存占用，用于同时测试显存降级
	KVUsage float64
}

// DefaultConfig 返回一个 10 秒宽的轰炸窗口。
//
// 10 秒的取值依据：K8s 默认 terminationGracePeriodSeconds 是 30s，
// 网关三阶段总预算 20s。窗口设 10s 能确保信号无论落在哪一秒，
// 都还有足够的剩余 token 用来验证「停机期间流仍在吐字」。
func DefaultConfig() Config {
	return Config{
		TokensPerSecond: 2,
		TotalTokens:     20,
		FirstTokenDelay: 100 * time.Millisecond,
		KVUsage:         0.30,
	}
}

// Window 返回轰炸窗口宽度。
func (c Config) Window() time.Duration {
	if c.TokensPerSecond <= 0 {
		return 0
	}
	return time.Duration(float64(c.TotalTokens)/c.TokensPerSecond*float64(time.Second)) +
		c.FirstTokenDelay
}

// Server 是混沌慢流上游。
type Server struct {
	*httptest.Server
	cfg Config

	requests  atomic.Int64
	completed atomic.Int64
	truncated atomic.Int64

	// lastBody 记录最近一次收到的请求体。验收测试据此断言
	// 「哪些内容真的越过了企业边界」——这是脱敏与协议完整性
	// 唯一可信的观测点，网关自己的日志不算数。
	lastBody atomic.Value
}

// Start 启动慢流服务器。
func Start(cfg Config) *Server {
	if cfg.TokensPerSecond <= 0 {
		cfg.TokensPerSecond = 2
	}
	if cfg.TotalTokens <= 0 {
		cfg.TotalTokens = 20
	}
	s := &Server{cfg: cfg}
	s.lastBody.Store("")

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/v1/chat/completions", s.handleChat)
	s.Server = httptest.NewServer(mux)
	return s
}

// BaseURL 返回网关配置里该用的 base_url。
func (s *Server) BaseURL() string { return s.URL + "/v1" }

// Requests 返回收到的请求数。
func (s *Server) Requests() int64 { return s.requests.Load() }

// Completed 返回完整吐完的流数。
func (s *Server) Completed() int64 { return s.completed.Load() }

// Truncated 返回被客户端提前断开的流数。
//
// 这个计数是从**上游视角**看到的截断。网关侧的 abandoned 计数
// 与它应当吻合——两边对不上说明有一侧的统计漏了。
func (s *Server) Truncated() int64 { return s.truncated.Load() }

// wantsStreamBody 判断请求体是否要求流式响应。
func wantsStreamBody(body []byte) bool {
	var probe struct {
		Stream *bool `json:"stream"`
	}
	if json.Unmarshal(body, &probe) != nil || probe.Stream == nil {
		return true // 默认按流式处理
	}
	return *probe.Stream
}

// LastBody 返回最近一次收到的请求体。
func (s *Server) LastBody() string { return s.lastBody.Load().(string) }

// handleMetrics 输出 vLLM 风格指标。
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, `vllm:num_requests_running{model_name="chaos"} %d.0
vllm:num_requests_waiting{model_name="chaos"} 0.0
vllm:gpu_cache_usage_perc{model_name="chaos"} %f
vllm:prefix_cache_queries_total{model_name="chaos"} 100.0
vllm:prefix_cache_hits_total{model_name="chaos"} 90.0
vllm:num_preemptions_total{model_name="chaos"} 0.0
`, s.requests.Load()-s.completed.Load()-s.truncated.Load(), s.cfg.KVUsage)
}

// handleChat 以刻意拉长的间隔推送 SSE。
//
// stream=false 时立刻返回完整 JSON。测试需要一种「不产生截断」的探测手段：
// 用慢流去探测，客户端一超时就会在上游留下一条 truncated 记录，
// 把测试自身的产物混进被测对象的统计里。
func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)

	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	s.lastBody.Store(string(body))

	if !wantsStreamBody(body) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"content":"quick"}}],`+
			`"usage":{"prompt_tokens":10,"completion_tokens":1}}`)
		s.completed.Add(1)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	rc := http.NewResponseController(w)
	rc.Flush()

	interval := time.Duration(float64(time.Second) / s.cfg.TokensPerSecond)
	if s.cfg.FirstTokenDelay > 0 {
		select {
		case <-time.After(s.cfg.FirstTokenDelay):
		case <-r.Context().Done():
			s.truncated.Add(1)
			return
		}
	}

	for i := 1; i <= s.cfg.TotalTokens; i++ {
		payload, _ := json.Marshal(map[string]any{
			"choices": []any{map[string]any{
				"delta": map[string]any{"content": fmt.Sprintf("tok%02d", i)},
			}},
		})
		if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
			s.truncated.Add(1)
			return
		}
		if err := rc.Flush(); err != nil {
			s.truncated.Add(1)
			return
		}

		select {
		case <-time.After(interval):
		case <-r.Context().Done():
			// 客户端（网关）断开——这正是暴力掐断的表现，
			// 计入 truncated 供测试与网关侧的 abandoned 对账
			s.truncated.Add(1)
			return
		}
	}

	fmt.Fprint(w, `data: {"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":`+
		fmt.Sprint(s.cfg.TotalTokens)+`}}`+"\n\n")
	fmt.Fprint(w, "data: [DONE]\n\n")
	rc.Flush()
	s.completed.Add(1)
}
