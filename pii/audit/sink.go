package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Sink delivers audit events.
// 投递审计事件。
type Sink interface {
	// Name identifies the sink in startup logs and in the admin snapshot, so an
	// operator can see where the audit trail is actually going.
	// 在启动日志与管理快照中标识本 sink，使运维能看清审计轨迹实际去了哪。
	Name() string

	// Emit delivers one event.
	// 投递一条事件。
	Emit(ctx context.Context, e Event) error

	// Close flushes and releases resources.
	// 冲刷并释放资源。
	Close() error
}

// ---------------------------------------------------------------------------
// WriterSink / 写入器
// ---------------------------------------------------------------------------

// WriterSink writes newline-delimited JSON.
// 写出以换行分隔的 JSON。
//
// The right sink for a container: stdout is already collected, shipped and
// retained by the platform, so this inherits the delivery guarantees the
// platform already provides rather than inventing weaker ones.
// 容器场景下最合适的 sink：stdout 本来就由平台收集、转运、留存，
// 因此它继承了平台已有的投递保证，而不是自己发明一套更弱的。
type WriterSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriterSink builds a sink over a writer.
// 基于写入器构造 sink。
func NewWriterSink(w io.Writer) *WriterSink { return &WriterSink{w: w} }

// Name implements Sink.
func (s *WriterSink) Name() string { return "writer" }

// Emit implements Sink.
func (s *WriterSink) Emit(_ context.Context, e Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("序列化审计事件失败 / marshalling audit event: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("写出审计事件失败 / writing audit event: %w", err)
	}
	return nil
}

// Close implements Sink.
func (s *WriterSink) Close() error { return nil }

// ---------------------------------------------------------------------------
// HTTPSink / SIEM 投递
// ---------------------------------------------------------------------------

// HTTPSink posts events to a SIEM endpoint.
// 把事件 POST 到 SIEM 端点。
//
// # Buffered, and what that costs
// # 带缓冲，以及它的代价
//
// Delivery happens off the request path: a SIEM that is slow must not make the
// gateway slow, or an observability outage becomes a latency incident on every
// request the gateway serves.
// 投递发生在请求路径之外：一个慢的 SIEM 不该让网关变慢，
// 否则一次可观测性故障会变成网关每一个请求上的延迟事故。
//
// The cost is that a full buffer drops events, and a dropped audit event is an
// accountability gap — the one record that would have shown what happened is
// the one that was not written. So drops are counted and surfaced, and an
// operator who cannot accept them should put a durable queue between the
// gateway and the SIEM rather than reaching for a bigger buffer.
// 代价是缓冲满了会丢事件，而丢掉的审计事件就是一个问责缺口——
// 本来能说明发生了什么的那一条，恰恰是没写下来的那一条。
// 因此丢弃会被计数并暴露出来；无法接受丢弃的运维，
// 应当在网关与 SIEM 之间放一个持久队列，而不是去调大缓冲。
type HTTPSink struct {
	endpoint string
	client   *http.Client
	headers  map[string]string

	queue   chan Event
	wg      sync.WaitGroup
	closing chan struct{}
	once    sync.Once

	dropped   atomic.Int64
	delivered atomic.Int64
	failed    atomic.Int64
}

// HTTPSinkOptions configures the SIEM sink.
// 配置 SIEM sink。
type HTTPSinkOptions struct {
	Endpoint string
	// Headers carries authentication (for example Splunk's Authorization
	// header). Supplied by the caller from a secret mount, never from the
	// config file that describes the pipeline.
	// 携带认证信息（例如 Splunk 的 Authorization 头）。
	// 由调用方从密钥挂载点提供，绝不来自描述管线的那个配置文件。
	Headers    map[string]string
	BufferSize int
	Timeout    time.Duration
	BatchSize  int
	// FlushInterval bounds how long an event waits in the buffer.
	//
	// 审计事件的价值随时间衰减：一条要到下一批才发出的告警，
	// 在事故响应里等于没有。
	// An audit event's value decays: an alert that ships with the next batch is
	// not an alert during an incident.
	FlushInterval time.Duration
}

// NewHTTPSink builds a SIEM sink.
// 构造 SIEM sink。
func NewHTTPSink(opts HTTPSinkOptions) (*HTTPSink, error) {
	if opts.Endpoint == "" {
		return nil, fmt.Errorf("SIEM 端点不能为空 / SIEM endpoint is required")
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = 4096
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 64
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 2 * time.Second
	}

	s := &HTTPSink{
		endpoint: opts.Endpoint,
		client:   &http.Client{Timeout: opts.Timeout},
		headers:  opts.Headers,
		queue:    make(chan Event, opts.BufferSize),
		closing:  make(chan struct{}),
	}
	s.wg.Add(1)
	go s.run(opts.BatchSize, opts.FlushInterval)
	return s, nil
}

// Name implements Sink.
func (s *HTTPSink) Name() string { return "http:" + s.endpoint }

// Emit implements Sink.
//
// Non-blocking by construction. A blocking send here would couple request
// latency to SIEM availability, which is the failure this sink's buffer exists
// to prevent.
// 构造上就是非阻塞的。在这里阻塞会把请求延迟与 SIEM 可用性绑在一起，
// 而这正是本 sink 的缓冲要防的那种故障。
func (s *HTTPSink) Emit(_ context.Context, e Event) error {
	select {
	case s.queue <- e:
		return nil
	default:
		s.dropped.Add(1)
		return fmt.Errorf("审计事件缓冲已满，本条已丢弃（累计 %d 条）—— "+
			"丢掉的审计事件是一个问责缺口 / audit buffer full, event dropped",
			s.dropped.Load())
	}
}

// Close implements Sink.
func (s *HTTPSink) Close() error {
	s.once.Do(func() {
		close(s.closing)
		s.wg.Wait()
	})
	return nil
}

// Stats reports delivery counters for the admin snapshot.
// 为管理快照报告投递计数。
func (s *HTTPSink) Stats() (delivered, dropped, failed int64) {
	return s.delivered.Load(), s.dropped.Load(), s.failed.Load()
}

// run batches and delivers events.
// 成批投递事件。
func (s *HTTPSink) run(batchSize int, flushInterval time.Duration) {
	defer s.wg.Done()

	batch := make([]Event, 0, batchSize)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.deliver(batch)
		batch = batch[:0]
	}

	for {
		select {
		case e := <-s.queue:
			batch = append(batch, e)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.closing:
			// 停机时把队列排空再走：留在缓冲里的审计事件，
			// 是这个进程最后做过的事情的唯一记录。
			// Drain on shutdown: the events still in the buffer are the only
			// record of the last thing this process did.
			for {
				select {
				case e := <-s.queue:
					batch = append(batch, e)
					if len(batch) >= batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

// deliver posts one batch.
// 投递一个批次。
func (s *HTTPSink) deliver(batch []Event) {
	body, err := json.Marshal(batch)
	if err != nil {
		s.failed.Add(int64(len(batch)))
		return
	}
	req, err := http.NewRequest(http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		s.failed.Add(int64(len(batch)))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.failed.Add(int64(len(batch)))
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 300 {
		s.failed.Add(int64(len(batch)))
		return
	}
	s.delivered.Add(int64(len(batch)))
}

// ---------------------------------------------------------------------------
// MultiSink / NopSink
// ---------------------------------------------------------------------------

// MultiSink fans an event out to several sinks.
// 把事件扇出到多个 sink。
//
// One sink's failure does not stop the others: a SIEM outage must not also cost
// the local record, which is often the only one an incident responder can reach
// while the SIEM is down.
// 一个 sink 失败不影响其他：SIEM 故障不该连本地记录也一起赔进去，
// 而在 SIEM 挂着的时候，本地记录往往是事故响应者唯一够得到的那份。
type MultiSink struct{ sinks []Sink }

// NewMultiSink builds a fan-out sink.
// 构造扇出 sink。
func NewMultiSink(sinks ...Sink) *MultiSink { return &MultiSink{sinks: sinks} }

// Name implements Sink.
func (m *MultiSink) Name() string {
	names := make([]string, 0, len(m.sinks))
	for _, s := range m.sinks {
		names = append(names, s.Name())
	}
	return "multi(" + joinComma(names) + ")"
}

// Emit implements Sink.
func (m *MultiSink) Emit(ctx context.Context, e Event) error {
	var firstErr error
	for _, s := range m.sinks {
		if err := s.Emit(ctx, e); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close implements Sink.
func (m *MultiSink) Close() error {
	var firstErr error
	for _, s := range m.sinks {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// NopSink discards events.
// 丢弃事件。
//
// For tests and for deployments that have deliberately decided not to keep a
// security audit trail. It is a named type so that decision is visible in the
// admin snapshot rather than being indistinguishable from a misconfiguration.
// 供测试，以及那些刻意决定不保留安全审计轨迹的部署使用。
// 它是一个具名类型，使这个决定在管理快照中可见，
// 而不是与一次配置失误无法区分。
type NopSink struct{}

// Name implements Sink.
func (NopSink) Name() string { return "none" }

// Emit implements Sink.
func (NopSink) Emit(context.Context, Event) error { return nil }

// Close implements Sink.
func (NopSink) Close() error { return nil }

// joinComma joins names without importing strings for one call.
// 拼接名称，避免为一次调用引入 strings。
func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}
