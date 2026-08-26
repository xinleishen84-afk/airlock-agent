// Package ratelimit 实现 Token 滑动窗口限流。
//
// Token 限流与请求限流有本质差别：**放行请求的那一刻，无法知道它会消耗多少
// token**。输出 token 要等流式推完才知道。因此本实现采用「预留—回填」三段式：
//
//  1. 准入（Reserve）——按 max_tokens 预扣配额。宁可保守：预扣多了后面回补，
//     预扣少了会超卖。
//  2. 回填（Commit）——流正常结束，按 usage 实际值把多预扣的部分退还。
//  3. 释放（Release）——流中断或超时，整笔预留作废。若没有这一步，
//     一次客户端断连就会永久占住一份配额，窗口会被慢慢"漏干"。
//
// 窗口实现为分桶滑动窗口：把窗口切成 N 个时间桶，过期桶直接丢弃。
// 相比精确的时间戳队列，内存是 O(桶数) 而非 O(请求数)——
// 网关是每连接热路径，不能让限流器本身成为内存瓶颈。
package ratelimit

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrQuotaExceeded 表示配额不足，请求应被拒绝（HTTP 429）。
var ErrQuotaExceeded = errors.New("token 配额不足")

// ErrUnknownReservation 表示提交或释放了一个不存在的预留。
var ErrUnknownReservation = errors.New("预留不存在或已结算")

// defaultBuckets 是窗口的默认分桶数。桶越多精度越高、内存越大。
const defaultBuckets = 60

// Limits 描述一个限流主体的配额上限。
type Limits struct {
	// TokensPerWindow 是窗口内的 token 总配额，0 表示不限
	TokensPerWindow int64
	// Window 是滑动窗口长度
	Window time.Duration
	// MaxConcurrent 是并发在途请求数上限，0 表示不限。
	// 单独设这一项是因为：token 配额充足时，仍可能因过多并发流打爆 GPU 队列。
	MaxConcurrent int
	// ReservationTTL 是预留的最长存活时间。超时未结算的预留会被自动释放，
	// 防止客户端断连导致配额永久泄漏。
	ReservationTTL time.Duration
}

// normalized 返回补齐默认值后的副本。
func (l Limits) normalized() Limits {
	if l.Window <= 0 {
		l.Window = time.Minute
	}
	if l.ReservationTTL <= 0 {
		// 默认给足一次长输出的时间；过短会误杀正常的长流
		l.ReservationTTL = 10 * time.Minute
	}
	return l
}

// Reservation 是一次准入产生的预留凭据。
type Reservation struct {
	ID       string
	Subject  string
	Reserved int64 // 预扣的 token 数
	IssuedAt time.Time

	// 预扣落在哪个时间桶。退还必须打回原桶——若打到当前桶，
	// 而原桶仍在窗口内，负数会被钳零，退款静默丢失，配额被慢慢漏干。
	bucketSlot  int
	bucketStart int64
}

// Usage 是一次调用的实际消耗，用于回填。
type Usage struct {
	InputTokens  int64
	OutputTokens int64
}

// Total 返回实际消耗的总 token 数。
func (u Usage) Total() int64 { return u.InputTokens + u.OutputTokens }

// bucket 是滑动窗口中的一个时间桶。
type bucket struct {
	startUnixNano int64
	tokens        int64
}

// subjectState 是单个限流主体的窗口状态。
type subjectState struct {
	buckets      []bucket
	inflight     int
	reservations map[string]*Reservation
}

// Limiter 是 Token 滑窗限流器，按主体（租户 / 应用 / API Key）隔离配额。
type Limiter struct {
	mu       sync.Mutex
	limits   map[string]Limits
	fallback Limits
	states   map[string]*subjectState
	buckets  int
	now      func() time.Time // 可注入，便于测试
	seq      uint64
}

// NewLimiter 创建限流器。fallback 是未单独配置主体时使用的默认配额。
func NewLimiter(fallback Limits) *Limiter {
	return &Limiter{
		limits:   make(map[string]Limits),
		fallback: fallback.normalized(),
		states:   make(map[string]*subjectState),
		buckets:  defaultBuckets,
		now:      time.Now,
	}
}

// SetLimits 为某个主体设置独立配额（多租户差异化限流）。
func (l *Limiter) SetLimits(subject string, limits Limits) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.limits[subject] = limits.normalized()
}

// limitsFor 取得某主体生效的配额。
func (l *Limiter) limitsFor(subject string) Limits {
	if lim, ok := l.limits[subject]; ok {
		return lim
	}
	return l.fallback
}

// stateFor 取得（或惰性创建）某主体的窗口状态。
func (l *Limiter) stateFor(subject string) *subjectState {
	st, ok := l.states[subject]
	if !ok {
		st = &subjectState{
			buckets:      make([]bucket, l.buckets),
			reservations: make(map[string]*Reservation),
		}
		l.states[subject] = st
	}
	return st
}

// bucketSpan 返回单个时间桶的跨度。
func (l *Limiter) bucketSpan(lim Limits) time.Duration {
	return lim.Window / time.Duration(l.buckets)
}

// currentUsage 汇总窗口内仍有效的 token 消耗，顺带丢弃过期桶。
func (l *Limiter) currentUsage(st *subjectState, lim Limits, now time.Time) int64 {
	cutoff := now.Add(-lim.Window).UnixNano()
	var total int64
	for i := range st.buckets {
		if st.buckets[i].startUnixNano <= cutoff {
			// 过期桶直接清零，无需搬移——这是分桶实现的核心收益
			st.buckets[i] = bucket{}
			continue
		}
		total += st.buckets[i].tokens
	}
	return total
}

// charge 把 tokens 记入当前时间桶，返回落点，供后续精确退还。
func (l *Limiter) charge(st *subjectState, lim Limits, now time.Time, tokens int64) (slot int, start int64) {
	span := l.bucketSpan(lim)
	slot = int((now.UnixNano() / int64(span)) % int64(l.buckets))
	start = now.Truncate(span).UnixNano()

	b := &st.buckets[slot]
	if b.startUnixNano != start {
		// 桶已轮转到新的时间片，重置后再累加
		*b = bucket{startUnixNano: start}
	}
	b.tokens += tokens
	return slot, start
}

// refund 把 tokens 从原始扣费所在的桶中扣回。
//
// 若该桶已轮转（原始扣费已随窗口滑出统计），说明配额早已自然释放，
// 无需也不应再退——否则会凭空多出一份额度。
func (l *Limiter) refund(st *subjectState, slot int, start int64, tokens int64) {
	if slot < 0 || slot >= len(st.buckets) {
		return
	}
	b := &st.buckets[slot]
	if b.startUnixNano != start {
		return // 原桶已过期轮转，无需退还
	}
	b.tokens -= tokens
	if b.tokens < 0 {
		b.tokens = 0
	}
}

// sweepExpiredLocked 释放超时未结算的预留。
//
// 这一步不可省：客户端断连时不会有人调用 Commit/Release，
// 没有清扫的话配额会被慢慢漏干，最终整个主体永久 429。
func (l *Limiter) sweepExpiredLocked(st *subjectState, lim Limits, now time.Time) {
	for id, r := range st.reservations {
		if now.Sub(r.IssuedAt) < lim.ReservationTTL {
			continue
		}
		delete(st.reservations, id)
		st.inflight--
		if st.inflight < 0 {
			st.inflight = 0
		}
		l.refund(st, r.bucketSlot, r.bucketStart, r.Reserved)
	}
}

// Reserve 执行准入判定并预扣配额。
//
// maxTokens 应传请求声明的 max_tokens——这是该请求可能消耗的上界。
// 预扣上界而非估计值，是为了保证「已放行的请求即使全部跑满也不会超卖」。
func (l *Limiter) Reserve(subject string, maxTokens int64, promptTokens int64) (*Reservation, error) {
	if maxTokens < 0 || promptTokens < 0 {
		return nil, fmt.Errorf("token 数不能为负: max=%d prompt=%d", maxTokens, promptTokens)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	lim := l.limitsFor(subject)
	st := l.stateFor(subject)
	now := l.now()
	l.sweepExpiredLocked(st, lim, now)

	if lim.MaxConcurrent > 0 && st.inflight >= lim.MaxConcurrent {
		return nil, fmt.Errorf("%w: 并发在途请求已达上限 %d", ErrQuotaExceeded, lim.MaxConcurrent)
	}

	// 预扣 = 输入 token（已确定）+ 输出上界（max_tokens）
	reserve := promptTokens + maxTokens
	if lim.TokensPerWindow > 0 {
		used := l.currentUsage(st, lim, now)
		if used+reserve > lim.TokensPerWindow {
			return nil, fmt.Errorf("%w: 窗口内已用 %d + 本次预扣 %d 超过上限 %d",
				ErrQuotaExceeded, used, reserve, lim.TokensPerWindow)
		}
	}

	l.seq++
	r := &Reservation{
		ID:       fmt.Sprintf("%s#%d", subject, l.seq),
		Subject:  subject,
		Reserved: reserve,
		IssuedAt: now,
	}
	r.bucketSlot, r.bucketStart = l.charge(st, lim, now, reserve)
	st.reservations[r.ID] = r
	st.inflight++
	return r, nil
}

// Commit 在流正常结束后按实际用量回填，退还多预扣的部分。
func (l *Limiter) Commit(r *Reservation, actual Usage) error {
	if r == nil {
		return ErrUnknownReservation
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	lim := l.limitsFor(r.Subject)
	st, ok := l.states[r.Subject]
	if !ok {
		return ErrUnknownReservation
	}
	if _, ok := st.reservations[r.ID]; !ok {
		return ErrUnknownReservation
	}
	delete(st.reservations, r.ID)
	st.inflight--
	if st.inflight < 0 {
		st.inflight = 0
	}

	// 两步结算：先把预扣从原桶退掉，再把实际用量记入当前桶。
	// 不能简单地把差额记到当前桶——原桶与当前桶可能不是同一个，
	// 那样会同时留下一笔未退的预扣和一笔错误的负值。
	l.refund(st, r.bucketSlot, r.bucketStart, r.Reserved)
	l.charge(st, lim, l.now(), actual.Total())
	return nil
}

// Release 在流中断时作废整笔预留。
func (l *Limiter) Release(r *Reservation) error {
	if r == nil {
		return ErrUnknownReservation
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	st, ok := l.states[r.Subject]
	if !ok {
		return ErrUnknownReservation
	}
	if _, ok := st.reservations[r.ID]; !ok {
		return ErrUnknownReservation
	}
	delete(st.reservations, r.ID)
	st.inflight--
	if st.inflight < 0 {
		st.inflight = 0
	}
	l.refund(st, r.bucketSlot, r.bucketStart, r.Reserved)
	return nil
}

// Snapshot 返回某主体当前的窗口用量与在途数，供监控与调试。
func (l *Limiter) Snapshot(subject string) (used int64, inflight int, limit int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim := l.limitsFor(subject)
	st, ok := l.states[subject]
	if !ok {
		return 0, 0, lim.TokensPerWindow
	}
	return l.currentUsage(st, lim, l.now()), st.inflight, lim.TokensPerWindow
}

// StartJanitor 启动后台协程，定期清扫超时预留。
// 仅靠 Reserve 时的惰性清扫不够：一个长期无新请求的主体，
// 其泄漏的预留会一直挂着。
func (l *Limiter) StartJanitor(interval time.Duration) (stop func()) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				l.mu.Lock()
				now := l.now()
				for subject, st := range l.states {
					l.sweepExpiredLocked(st, l.limitsFor(subject), now)
				}
				l.mu.Unlock()
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}
