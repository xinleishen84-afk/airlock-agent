package sidecar

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/document"
)

// Options configures the sidecar.
// 是 sidecar 的配置。
type Options struct {
	// Detector 是 PII 检测器。必填。
	Detector detect.Detector
	// FailClosed 为 true 时，检测器故障会返回阻断而非放行原文。
	// 这是脱敏组件唯一安全的默认值——网关收到 Blocked 后
	// 必须拒绝请求，绝不能把原始载荷发出去。
	FailClosed bool
	// SessionTTL 是脱敏映射的存活时长
	SessionTTL time.Duration
	// MaxSessions 是活跃会话上限，防止内存无限增长
	MaxSessions int
	// MaxBodyBytes 限制单次请求体大小
	MaxBodyBytes int64

	// Matrix 是脱敏策略矩阵。为 nil 时一律使用占位符遮罩。
	//
	// 配置了矩阵之后，请求必须带 destination：一个既配了矩阵、
	// 又允许不指定流向的服务，会在调用方漏传字段时静默回退到
	// 某条默认策略，把数据按为别处写的规则发出去。
	//
	// When a matrix is configured, requests must name a destination. A service
	// that allows both would silently fall back to some default policy when a
	// caller forgets the field, shipping data under rules written for
	// somewhere else.
	Matrix *anonymize.Matrix

	// TokenStore 支撑 tokenize 算子的复原。矩阵里用到 tokenize 时必填。
	// Backs restoration for the tokenize operator; required when it is used.
	TokenStore anonymize.TokenStore

	Logger *slog.Logger
}

// Server is the PII redaction sidecar.
// 是 PII 脱敏 sidecar。
type Server struct {
	opts     Options
	redactor *anonymize.Redactor
	vaults   *anonymize.VaultRegistry
	logger   *slog.Logger

	// 流式复原器按会话保存。SSE 分片里的占位符可能横跨两片，
	// 必须让同一会话的连续调用共用同一个滞留缓冲。
	streamMu    sync.Mutex
	streamers   map[string]*streamEntry
	stopJanitor func()

	redactCalls  atomic.Int64
	restoreCalls atomic.Int64
	blockedCalls atomic.Int64
	entityMu     sync.Mutex
	entityCounts map[string]int64
}

// streamEntry 是一个会话的流式复原器及其最后活跃时间。
type streamEntry struct {
	restorer *document.StreamRestorer
	lastUsed time.Time
}

// New creates the sidecar service.
// 创建 sidecar 服务。
func New(opts Options) (*Server, error) {
	if opts.Detector == nil {
		return nil, errors.New("必须提供 PII 检测器")
	}
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = time.Hour
	}
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = 100_000
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 32 << 20
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	s := &Server{
		opts: opts,
		redactor: anonymize.NewRedactorWith(opts.Detector, opts.FailClosed,
			anonymize.WithTokenStore(opts.TokenStore)),
		vaults:       anonymize.NewVaultRegistry(opts.SessionTTL, opts.MaxSessions),
		logger:       opts.Logger,
		streamers:    map[string]*streamEntry{},
		entityCounts: map[string]int64{},
	}
	s.stopJanitor = s.vaults.StartJanitor(time.Minute)
	go s.reapStreamers()
	return s, nil
}

// Close stops background tasks and clears every redaction mapping.
// 停止后台任务并清空全部脱敏映射。
func (s *Server) Close() {
	if s.stopJanitor != nil {
		s.stopJanitor()
	}
	// 退出前清空——不留任何真实值在内存里
	s.vaults.PurgeAll()
}

// Handler returns the HTTP routes.
// 返回 HTTP 路由。
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /v1/redact", s.handleRedact)
	m.HandleFunc("POST /v1/restore", s.handleRestore)
	m.HandleFunc("POST /v1/session/end", s.handleEndSession)
	m.HandleFunc("GET /healthz", s.handleHealth)
	m.HandleFunc("GET /stats", s.handleStats)
	return m
}

// resolveFlow 把请求里的 destination 解析为脱敏策略。
//
// 三种情形各有其唯一安全的处理：
//   - 未配矩阵、也未指定流向：一律占位符遮罩，即本服务原有的行为
//   - 配了矩阵却没指定流向：拒绝。回退到某条默认策略等于把数据按
//     为别处写的规则发出去，而调用方不会知道
//   - 指定了未知流向：拒绝，并列出已配置的流向
//
// resolveFlow turns the request's destination into a policy. Falling back to
// some default when a matrix is configured would ship data under rules written
// for somewhere else, with the caller none the wiser.
func (s *Server) resolveFlow(w http.ResponseWriter, dest string) (anonymize.Flow, bool) {
	if s.opts.Matrix == nil {
		if dest != "" {
			s.fail(w, http.StatusBadRequest,
				"请求指定了 destination="+dest+"，但本服务未配置脱敏策略矩阵——"+
					"按指定流向处理是做不到的，静默忽略又会让调用方以为生效了", false)
			return anonymize.Flow{}, false
		}
		return anonymize.DefaultMaskFlow(), true
	}

	if dest == "" {
		s.fail(w, http.StatusBadRequest,
			"已配置脱敏策略矩阵，请求必须指定 destination。已配置："+
				strings.Join(s.opts.Matrix.Destinations(), ", "), false)
		return anonymize.Flow{}, false
	}

	flow, err := s.opts.Matrix.Flow(anonymize.Destination(dest))
	if err != nil {
		s.fail(w, http.StatusBadRequest, err.Error(), false)
		return anonymize.Flow{}, false
	}
	return flow, true
}

// handleRedact applies structured, AST-directed sanitization to an outbound
// payload.
// 对出站载荷执行结构化 AST 定向清洗。
func (s *Server) handleRedact(w http.ResponseWriter, r *http.Request) {
	s.redactCalls.Add(1)

	var req RedactRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.SessionID == "" {
		s.fail(w, http.StatusBadRequest, "缺少 session_id——"+
			"没有它就无法在响应侧复原，脱敏将成为单向操作", false)
		return
	}

	vault, err := s.vaults.Get(req.SessionID)
	if err != nil {
		s.fail(w, http.StatusServiceUnavailable, err.Error(), false)
		return
	}

	flow, ok := s.resolveFlow(w, req.Destination)
	if !ok {
		return
	}

	counts := map[string]int{}
	stratCounts := map[string]int{}
	transform := func(text string) (string, error) {
		res, err := s.redactor.RedactTo(text, vault, flow)
		if err != nil {
			return "", err
		}
		for typ, n := range res.TypeCounts {
			counts[typ] += n
		}
		for name, n := range res.StrategyCounts {
			stratCounts[name] += n
		}
		return res.Text, nil
	}

	resp := RedactResponse{EntityCounts: counts, StrategyCounts: stratCounts}
	switch {
	case req.Payload != nil:
		// 深拷贝后再改，避免把调用方传来的结构改坏
		doc := deepCopyMap(req.Payload)
		if err := document.SanitizeDocument(doc, transform); err != nil {
			s.blocked(w, err)
			return
		}
		// 纵深防御：清洗后断言载荷中不含任何已登记的真实值
		if leaked := s.scanLeak(doc, vault); len(leaked) > 0 {
			s.blockedCalls.Add(1)
			s.logger.Error("出站终检发现未脱敏 PII", "types", leaked, "session", req.SessionID)
			s.writeJSON(w, http.StatusOK, RedactResponse{
				Blocked: true,
				Reason:  fmt.Sprintf("终检发现未脱敏的 PII 类型：%v", leaked),
			})
			return
		}
		resp.Payload = doc
	case req.Text != "":
		out, err := transform(req.Text)
		if err != nil {
			s.blocked(w, err)
			return
		}
		resp.Text = out
	default:
		s.fail(w, http.StatusBadRequest, "payload 与 text 必须提供其一", false)
		return
	}

	s.recordEntities(counts)
	s.writeJSON(w, http.StatusOK, resp)
}

// handleRestore applies targeted restoration to an inbound payload.
// 对入站载荷执行定向复原。
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	s.restoreCalls.Add(1)

	var req RestoreRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.SessionID == "" {
		s.fail(w, http.StatusBadRequest, "缺少 session_id", false)
		return
	}

	vault, err := s.vaults.Get(req.SessionID)
	if err != nil {
		s.fail(w, http.StatusServiceUnavailable, err.Error(), false)
		return
	}

	// 流式分片：占位符可能横跨两片，必须复用同一个滞留缓冲
	if req.Streaming {
		s.handleStreamRestore(w, req, vault)
		return
	}

	var resp RestoreResponse
	switch {
	case req.Payload != nil:
		doc := deepCopyMap(req.Payload)
		restored := 0
		var phantom []string
		err := document.RestoreDocument(doc, func(text string) (string, error) {
			res := s.redactor.Unredact(text, vault)
			restored += res.Restored
			phantom = append(phantom, res.Phantom...)
			return res.Text, nil
		})
		if err != nil {
			s.fail(w, http.StatusInternalServerError, err.Error(), false)
			return
		}
		resp = RestoreResponse{Payload: doc, Restored: restored, Phantom: phantom}
	case req.Text != "":
		res := s.redactor.Unredact(req.Text, vault)
		resp = RestoreResponse{Text: res.Text, Restored: res.Restored, Phantom: res.Phantom}
	default:
		s.fail(w, http.StatusBadRequest, "payload 与 text 必须提供其一", false)
		return
	}

	if len(resp.Phantom) > 0 {
		s.logger.Warn("响应含模型捏造的占位符",
			"session", req.SessionID, "count", len(resp.Phantom))
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleStreamRestore restores a streaming chunk.
// 处理流式分片的复原。
func (s *Server) handleStreamRestore(w http.ResponseWriter, req RestoreRequest, vault *anonymize.SessionVault) {
	s.streamMu.Lock()
	entry, ok := s.streamers[req.SessionID]
	if !ok {
		entry = &streamEntry{restorer: document.NewStreamRestorer(s.redactor, vault)}
		s.streamers[req.SessionID] = entry
	}
	entry.lastUsed = time.Now()
	restorer := entry.restorer
	s.streamMu.Unlock()

	var resp RestoreResponse
	if req.Payload != nil {
		raw, err := document.MarshalPreserving(req.Payload)
		if err != nil {
			s.fail(w, http.StatusBadRequest, "序列化分片失败", false)
			return
		}
		out := restorer.Frame(raw)
		var doc map[string]any
		if json.Unmarshal(out, &doc) == nil {
			resp.Payload = doc
		}
	} else {
		// 纯文本分片：Frame 期望 JSON，此处退回逐段复原
		res := s.redactor.Unredact(req.Text, vault)
		resp.Text = res.Text
		resp.Restored = res.Restored
		resp.Phantom = res.Phantom
	}

	if req.Final {
		if tail := restorer.Flush(); tail != "" {
			resp.Text += tail
		}
		resp.Phantom = append(resp.Phantom, restorer.Phantom()...)
		s.streamMu.Lock()
		delete(s.streamers, req.SessionID)
		s.streamMu.Unlock()
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// handleEndSession explicitly ends a session and clears its mapping.
// 显式结束会话并清除映射。
//
// Gateways should call this when a conversation ends. Skipping it does not leak
// (the TTL is a backstop) but the mapping lingers longer — and for PII, shorter
// is always better.
// 网关应在会话终止时调用。不调也不会泄露（有 TTL 兜底），
// 但映射会多驻留一段时间——对 PII 而言越短越好。
func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	var req SessionRequest
	if !s.decode(w, r, &req) {
		return
	}
	s.vaults.Drop(req.SessionID)
	s.streamMu.Lock()
	delete(s.streamers, req.SessionID)
	s.streamMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// handleHealth 是健康检查。
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// handleStats 返回运行统计。
func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	s.entityMu.Lock()
	counts := make(map[string]int64, len(s.entityCounts))
	for k, v := range s.entityCounts {
		counts[k] = v
	}
	s.entityMu.Unlock()

	resp := StatsResponse{
		ActiveSessions: s.vaults.ActiveSessions(),
		RedactCalls:    s.redactCalls.Load(),
		RestoreCalls:   s.restoreCalls.Load(),
		BlockedCalls:   s.blockedCalls.Load(),
		EntityCounts:   counts,
	}
	if s.opts.Matrix != nil {
		resp.RedactionMatrix = s.opts.Matrix.Describe()
	}
	if comp, ok := s.opts.Detector.(*detect.CompositeDetector); ok {
		for _, t := range comp.Missing() {
			resp.CoverageGaps = append(resp.CoverageGaps, string(t))
		}
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

// decode 解析请求体。
func (s *Server) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, s.opts.MaxBodyBytes))
	if err := dec.Decode(v); err != nil {
		s.fail(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error(), false)
		return false
	}
	return true
}

// blocked returns a fail-closed block response.
// 返回 fail-closed 阻断响应。
//
// Uses 200 rather than 5xx: this is not a service failure but a security policy
// taking effect. A 5xx invites the gateway to retry or degrade as if upstream
// were broken — and degradation usually means letting traffic through, exactly
// the opposite of the security intent.
// 用 200 而非 5xx：这不是服务故障，而是安全策略生效。
// 返回 5xx 会让网关按「上游故障」重试或降级——
// 而降级的方向往往是放行，恰好与安全意图相反。
func (s *Server) blocked(w http.ResponseWriter, err error) {
	s.blockedCalls.Add(1)
	if s.opts.FailClosed {
		s.logger.Error("PII 检测失败，已阻断（fail-closed）", "err", err)
		s.writeJSON(w, http.StatusOK, RedactResponse{
			Blocked: true,
			Reason:  "PII 检测失败，按 fail-closed 阻断：" + err.Error(),
		})
		return
	}
	s.logger.Error("PII 检测失败，已放行原文（fail-open，存在泄露风险）", "err", err)
	s.fail(w, http.StatusInternalServerError, err.Error(), false)
}

// fail 返回错误响应。
func (s *Server) fail(w http.ResponseWriter, code int, msg string, failClosed bool) {
	s.writeJSON(w, code, ErrorResponse{Error: msg, FailClosed: failClosed})
}

// writeJSON 写出 JSON 响应，不做 HTML 转义。
func (s *Server) writeJSON(w http.ResponseWriter, code int, v any) {
	body, err := document.MarshalPreserving(v)
	if err != nil {
		http.Error(w, "序列化响应失败", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// scanLeak asserts the sanitized document holds none of the registered real
// values.
// 断言清洗后的文档中不含任何已登记的真实值。
func (s *Server) scanLeak(doc map[string]any, vault *anonymize.SessionVault) []string {
	raw, err := document.MarshalPreserving(doc)
	if err != nil {
		return nil
	}
	return vault.ScanLeak(string(raw))
}

// recordEntities accumulates entity counts — types and totals only, never
// values.
// 累计实体计数。只记类型与数量，绝不记值。
func (s *Server) recordEntities(counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	s.entityMu.Lock()
	defer s.entityMu.Unlock()
	for typ, n := range counts {
		s.entityCounts[typ] += int64(n)
	}
}

// reapStreamers reclaims stream restorers that have been idle too long.
// 回收长时间未使用的流式复原器。
//
// A client that drops the stream never sends Final, so without reaping the
// hold-back buffer lives forever — and that buffer may hold half a placeholder,
// which maps to a real piece of PII.
// 客户端断流时不会发 Final，不回收的话滞留缓冲会永久驻留——
// 而缓冲里可能压着半个占位符，对应着一条真实 PII。
func (s *Server) reapStreamers() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-5 * time.Minute)
		s.streamMu.Lock()
		for id, e := range s.streamers {
			if e.lastUsed.Before(cutoff) {
				delete(s.streamers, id)
			}
		}
		s.streamMu.Unlock()
	}
}

// deepCopyMap deep-copies a JSON structure so the caller's object is not
// mutated.
// 深拷贝 JSON 结构，避免改坏调用方传入的对象。
func deepCopyMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = deepCopyValue(v)
	}
	return out
}

// deepCopyValue 深拷贝任意 JSON 值。
func deepCopyValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return deepCopyMap(val)
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = deepCopyValue(item)
		}
		return out
	default:
		return v
	}
}
