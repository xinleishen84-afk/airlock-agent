// Command fakevllm 是一个容器化的假 vLLM 端点，供集成测试使用。
//
// 它不是 mock：它是一个真实的 HTTP 服务，跑在真实容器里，
// 通过真实 TCP 与网关通信。被测的是网关的完整网络路径——
// 连接池、SSE 解析、超时、背压——而不是被打桩替换掉的接口。
//
// 它模拟的只是「模型推理」这一件事本身（真实 vLLM 需要 GPU）。
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	kvUsage    atomic.Uint64 // 存 KV 占用的千分数，便于原子操作
	requests   atomic.Int64
	lastBody   atomic.Value
	failNext   atomic.Int64 // 大于 0 时对接下来 N 个请求返回 5xx
	tokenDelay time.Duration
)

func main() {
	port := envOr("PORT", "8000")
	tokenDelay = envDuration("TOKEN_DELAY", 30*time.Millisecond)
	kvUsage.Store(uint64(envInt("KV_PERMILLE", 300)))
	lastBody.Store("")

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/v1/chat/completions", handleChat)
	// 测试控制面：让集成测试能在运行中改变后端行为
	mux.HandleFunc("/_control/kv", handleSetKV)
	mux.HandleFunc("/_control/fail", handleSetFail)
	mux.HandleFunc("/_control/last-body", handleLastBody)
	mux.HandleFunc("/_control/stats", handleStats)

	log.Printf("fakevllm 监听 :%s（token 间隔 %v）", port, tokenDelay)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}

// handleMetrics 输出 vLLM 风格的 Prometheus 指标。
func handleMetrics(w http.ResponseWriter, _ *http.Request) {
	kv := float64(kvUsage.Load()) / 1000.0
	fmt.Fprintf(w, `# HELP vllm:num_requests_running Number of running requests.
# TYPE vllm:num_requests_running gauge
vllm:num_requests_running{model_name="fake"} 4.0
vllm:num_requests_waiting{model_name="fake"} 1.0
vllm:gpu_cache_usage_perc{model_name="fake"} %f
vllm:prefix_cache_queries_total{model_name="fake"} 1000.0
vllm:prefix_cache_hits_total{model_name="fake"} 850.0
vllm:num_preemptions_total{model_name="fake"} 0.0
`, kv)
}

// handleChat 以 SSE 逐 token 返回，模拟真实的流式推理。
func handleChat(w http.ResponseWriter, r *http.Request) {
	requests.Add(1)

	var sb strings.Builder
	body := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}
	sb.Write(body)
	lastBody.Store(sb.String())

	if failNext.Load() > 0 {
		failNext.Add(-1)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":{"message":"injected failure"}}`)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	rc := http.NewResponseController(w)
	rc.Flush()

	// 回声式生成：把请求里出现的占位符原样吐回，
	// 用于验证网关的复原链路
	tokens := []string{"已", "处理"}
	if strings.Contains(sb.String(), "ANONYMIZED_NAME_0") {
		tokens = []string{"已通知 ", "ANONYMIZED_NA", "ME_0", " 完成"}
	}
	for _, t := range tokens {
		payload, _ := json.Marshal(map[string]any{
			"choices": []any{map[string]any{"delta": map[string]any{"content": t}}},
		})
		fmt.Fprintf(w, "data: %s\n\n", payload)
		rc.Flush()
		time.Sleep(tokenDelay)
	}
	fmt.Fprint(w, `data: {"choices":[],"usage":{"prompt_tokens":42,"completion_tokens":8}}`+"\n\n")
	fmt.Fprint(w, "data: [DONE]\n\n")
	rc.Flush()
}

// handleSetKV 调整 KV 缓存占用，用于测试显存降级。
func handleSetKV(w http.ResponseWriter, r *http.Request) {
	v, _ := strconv.Atoi(r.URL.Query().Get("permille"))
	kvUsage.Store(uint64(v))
	fmt.Fprintf(w, "kv=%d‰\n", v)
}

// handleSetFail 让接下来 N 个请求返回 5xx，用于测试失效转移。
func handleSetFail(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	failNext.Store(int64(n))
	fmt.Fprintf(w, "fail_next=%d\n", n)
}

// handleLastBody 返回最近一次收到的请求体，用于验证脱敏结果。
func handleLastBody(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, lastBody.Load().(string))
}

// handleStats 返回累计请求数。
func handleStats(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, `{"requests":%d}`, requests.Load())
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(key)); err == nil {
		return v
	}
	return def
}
