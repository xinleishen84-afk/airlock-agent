// Package nerclient 是 Go 网关到 Python NER 服务的 gRPC 客户端。
//
// The gRPC client from the Go gateway to the Python NER service.
//
// # 为什么独立成模块
// # Why a separate module
//
// gRPC 与 protobuf 会带进一棵庞大的依赖树。主模块的卖点之一是只有一个外部
// 依赖——一个做 PII 脱敏的库，不该把 gRPC 强加给只想扫自己那段文本的调用方。
// 与 otelprocessor 同理。
//
// gRPC and protobuf pull in a large dependency tree. The main module's single
// external dependency is a property worth keeping.
package nerclient

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	piiv1 "github.com/xinleishen84-afk/airlock-agent/nerclient/genproto/piiv1"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// Options configures the client.
// 配置客户端。
type Options struct {
	// SocketPath 是 Python 服务监听的 Unix domain socket。
	SocketPath string

	// Timeout 是单次调用的超时。
	//
	// NER 在 TTFT 关键路径上：这段延迟会叠加到每一个走到第三层的请求上。
	// 超时设得太长，等于让一个卡住的推理进程拖慢整个网关。
	//
	// NER sits on the TTFT path: this latency adds to every request that
	// reaches the third layer. Too long a timeout lets one stuck inference
	// process slow the whole gateway.
	Timeout time.Duration

	// FailOpen 决定服务不可用时放行还是阻断。
	//
	// 默认 false（阻断）。放行意味着「检测不出来就当没有」，
	// 而第三层负责的恰恰是姓名、地址、机构——正则一个都找不到的那些。
	// NER 挂掉时放行，等于在这几类上完全裸奔，且不报错。
	//
	// Defaults to false. Failing open means "if we cannot detect it, assume it
	// is not there", and this layer covers exactly what regexes cannot find.
	FailOpen bool

	// Types 限定要识别的实体类型。留空表示全部。
	Types []detect.EntityType

	// MaxTextBytes 限制单次送入的文本大小。
	//
	// 模型的耗时随输入长度增长，而 gRPC 默认的消息上限是 4MB。
	// 超长文本应当在调用方切分，而不是在这里被默默截断——截断掉的那部分
	// 既没有被检测，也没有留下痕迹。
	//
	// Model cost grows with input length. Oversized text should be split by
	// the caller, not silently truncated here: a truncated tail is neither
	// scanned nor recorded.
	MaxTextBytes int
}

// Client talks to the Python NER service.
// 与 Python NER 服务通信。
type Client struct {
	conn   *grpc.ClientConn
	stub   piiv1.NERServiceClient
	opts   Options
	model  string
	covers []detect.EntityType
}

// New dials the socket and confirms the model is loaded.
// 连接 socket 并确认模型已加载。
//
// 启动期就做一次 Health：模型加载失败时，Analyze 也会失败，但那时候第一个
// 真实请求已经进来了，而网关已经对外声称自己就绪。
//
// Health is called at startup: a failed model load makes Analyze fail too, but
// by then the first real request has arrived and the gateway has already
// reported itself ready.
func New(ctx context.Context, opts Options) (*Client, error) {
	if opts.SocketPath == "" {
		return nil, fmt.Errorf("必须指定 socket 路径 / socket path is required")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 300 * time.Millisecond
	}
	if opts.MaxTextBytes <= 0 {
		opts.MaxTextBytes = 1 << 20
	}

	if info, err := os.Stat(opts.SocketPath); err != nil {
		return nil, fmt.Errorf(
			"socket %s 不可用：%w\n"+
				"请先启动 Python 侧：python -m pii.service.ner_server --socket %s",
			opts.SocketPath, err, opts.SocketPath)
	} else if info.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf(
			"路径 %s 存在但不是 socket / path exists but is not a socket",
			opts.SocketPath)
	}

	conn, err := grpc.NewClient(
		"unix:"+opts.SocketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", strings.TrimPrefix(addr, "unix:"))
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("连接 NER 服务失败 / dialing NER service: %w", err)
	}

	c := &Client{conn: conn, stub: piiv1.NewNERServiceClient(conn), opts: opts}

	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	health, err := c.stub.Health(healthCtx, &piiv1.HealthRequest{})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("NER 服务健康检查失败 / health check failed: %w", err)
	}
	if !health.GetReady() {
		_ = conn.Close()
		return nil, fmt.Errorf("NER 服务未就绪：%s / not ready", health.GetDetail())
	}

	c.model = health.GetModel()
	seen := map[detect.EntityType]bool{}
	for _, t := range health.GetSupportedTypes() {
		local, err := mapWireType(t)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("健康检查返回了无法映射的类型：%w", err)
		}
		if !seen[local] {
			seen[local] = true
			c.covers = append(c.covers, local)
		}
	}
	sort.Slice(c.covers, func(i, j int) bool { return c.covers[i] < c.covers[j] })
	return c, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Model returns the backend identifier reported by the service.
// 返回服务端自报的后端标识。
func (c *Client) Model() string { return c.model }

// Name implements detect.Detector.
func (c *Client) Name() string { return "ner:" + c.model }

// CoveredTypes implements detect.Detector.
//
// 取自服务端 Health 自报的类型，而不是本地写死。写死会让「服务端换了个
// 不产出 ORGANIZATION 的模型」这件事在覆盖度自检里看不出来。
//
// Taken from the server's Health rather than hard-coded locally: hard-coding
// would hide a server-side model swap from the coverage check.
func (c *Client) CoveredTypes() []detect.EntityType {
	return append([]detect.EntityType(nil), c.covers...)
}

// Detect implements detect.Detector.
func (c *Client) Detect(text string) ([]detect.Entity, error) {
	return c.DetectContext(context.Background(), text)
}

// DetectContext runs one analysis.
// 执行一次识别。
func (c *Client) DetectContext(ctx context.Context, text string) ([]detect.Entity, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	if len(text) > c.opts.MaxTextBytes {
		return nil, fmt.Errorf(
			"文本 %d 字节超过上限 %d——请在调用方切分，"+
				"在这里截断会让截掉的那部分既没被检测也没留下痕迹 / text too large",
			len(text), c.opts.MaxTextBytes)
	}

	types := wireTypesFor(c.opts.Types)

	callCtx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	resp, err := c.stub.Analyze(callCtx, &piiv1.AnalyzeRequest{
		Text: text, Language: "zh", EntityTypes: types,
	})
	if err != nil {
		if c.opts.FailOpen {
			// fail-open 是显式选择，必须留下痕迹供审计追责。
			// A fail-open is an explicit choice and must leave a trace.
			return nil, fmt.Errorf(
				"%w（已按 fail-open 放行，姓名/地址/机构本次完全未检测）: %v",
				ErrNERUnavailable, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrNERUnavailable, err)
	}

	return c.convert(text, resp)
}

// raw performs one Analyze call without conversion, for latency measurement.
// 执行一次不做转换的 Analyze，供延迟测量使用。
func (c *Client) raw(ctx context.Context, text string) (*piiv1.AnalyzeResponse, error) {
	callCtx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	return c.stub.Analyze(callCtx, &piiv1.AnalyzeRequest{Text: text, Language: "zh"})
}

// convert maps character offsets to byte offsets and verifies each one.
// 把字符偏移映射为字节偏移，并逐条验证。
func (c *Client) convert(text string, resp *piiv1.AnalyzeResponse) ([]detect.Entity, error) {
	entities := resp.GetEntities()
	if len(entities) == 0 {
		return nil, nil
	}

	idx := newOffsetIndex(text)
	out := make([]detect.Entity, 0, len(entities))

	for _, e := range entities {
		startByte, endByte, err := idx.toBytes(int(e.GetStart()), int(e.GetEnd()), e.GetText())
		if err != nil {
			// 一处映射失败就整体失败，不做「跳过这一条」。
			//
			// 映射对不上说明两端看到的不是同一份文本，那么这一批里其他实体的
			// 偏移同样不可信。跳过坏的那条、留下其余的，等于拿一批可能全都
			// 错位的区间去脱敏。
			//
			// One bad mapping fails the batch rather than skipping the entity:
			// a mismatch means the two sides disagree about the text, so every
			// other offset in the batch is equally suspect.
			return nil, fmt.Errorf("%w: %v", ErrOffsetMismatch, err)
		}

		localType, err := mapWireType(e.GetEntityType())
		if err != nil {
			return nil, err
		}
		out = append(out, detect.Entity{
			Type:       localType,
			Value:      text[startByte:endByte],
			Start:      startByte,
			End:        endByte,
			Confidence: float64(e.GetScore()),
			Detector:   c.Name(),
		})
	}
	return out, nil
}
