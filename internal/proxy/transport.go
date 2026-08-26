package proxy

import (
	"net"
	"net/http"
	"time"
)

// TransportConfig 是上游连接的调优参数。
type TransportConfig struct {
	// MaxIdleConnsPerHost 决定到单个上游的连接复用池大小。
	// 默认值 2 对 LLM 网关远远不够——每条 SSE 流独占一个连接，
	// 池太小会导致大量连接反复三次握手，TTFT 直接多出一个 RTT。
	MaxIdleConnsPerHost int
	// ResponseHeaderTimeout 限制「发出请求到收到响应头」的时间。
	// 这是唯一能安全设置的上游超时——绝不能设 Transport 级别的整体超时，
	// 那会掐断正常的长流。
	ResponseHeaderTimeout time.Duration
	DialTimeout           time.Duration
	IdleConnTimeout       time.Duration
	// ForceHTTP2 为 false 时优先 HTTP/1.1。
	// HTTP/2 的流控窗口在超长 SSE 流上可能引入额外的 WINDOW_UPDATE 往返，
	// 除非上游明确受益，否则 HTTP/1.1 的流式行为更可预测。
	ForceHTTP2 bool
}

// DefaultTransportConfig 返回面向 SSE 场景调优过的默认值。
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		MaxIdleConnsPerHost:   256,
		ResponseHeaderTimeout: 60 * time.Second,
		DialTimeout:           5 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ForceHTTP2:            false,
	}
}

// NewTransport 构造面向流式场景的 http.Transport。
//
// 最关键的一行是 DisableCompression。若上游把 SSE 流 gzip 了，
// 压缩器会攒够一个 block 才输出，token 就不再是「涓涓细流」而是
// 一坨一坨地到达——TTFT 从毫秒退化到秒级。这是 SSE 代理最经典的坑，
// 而且极难定位：功能完全正常，只是慢。
func NewTransport(cfg TransportConfig) *http.Transport {
	if cfg.MaxIdleConnsPerHost <= 0 {
		cfg.MaxIdleConnsPerHost = 256
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if cfg.IdleConnTimeout <= 0 {
		cfg.IdleConnTimeout = 90 * time.Second
	}

	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout: cfg.DialTimeout,
			// KeepAlive 让空闲连接保持活性，避免中间设备静默回收后
			// 下一次请求撞上一个死连接（表现为随机的首包超时）
			KeepAlive: 30 * time.Second,
		}).DialContext,

		// 流式场景的核心开关：绝不压缩
		DisableCompression: true,

		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		MaxIdleConns:          cfg.MaxIdleConnsPerHost * 4,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     cfg.ForceHTTP2,

		// 写缓冲调小：SSE 请求体通常只有几 KB，大缓冲纯属浪费内存。
		// 读缓冲保持较大值以容纳突发的 chunk 批量到达。
		WriteBufferSize: 8 << 10,
		ReadBufferSize:  32 << 10,
	}
}

// NewClient 构造上游 HTTP 客户端。
//
// **刻意不设 Timeout 字段**：http.Client.Timeout 覆盖从发起请求到
// 读完响应体的全过程，对长流式响应意味着必然被掐断。
// 流的生命周期应由请求 context 控制，而非客户端级超时。
func NewClient(cfg TransportConfig) *http.Client {
	return &http.Client{
		Transport: NewTransport(cfg),
		// 网关不应跟随重定向：上游的 3xx 可能把凭证带到非预期的域
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
