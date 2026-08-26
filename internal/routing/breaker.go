package routing

import (
	"sync"
	"time"
)

// BreakerState 是熔断器状态。
type BreakerState int

const (
	StateClosed   BreakerState = iota // 正常放行
	StateOpen                         // 直接拒绝，不再打无谓的请求
	StateHalfOpen                     // 试探性放行少量请求
)

// String 返回状态名。
func (s BreakerState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half_open"
	}
	return "unknown"
}

// Breaker 是单个后端的熔断器。
//
// 只有「瞬时故障」才计入熔断（限流、5xx、网络）。参数非法这类确定性错误
// 不计——那是调用方的问题，熔断后端于事无补，只会误伤健康节点。
type Breaker struct {
	name             string
	failureThreshold int
	recoveryTimeout  time.Duration
	halfOpenMaxCalls int

	mu            sync.Mutex
	state         BreakerState
	consecutive   int
	openedAt      time.Time
	halfOpenCalls int
	now           func() time.Time // 可注入，便于测试
}

// NewBreaker 创建熔断器。
func NewBreaker(name string, failureThreshold int, recoveryTimeout time.Duration) *Breaker {
	if failureThreshold <= 0 {
		failureThreshold = 5
	}
	if recoveryTimeout <= 0 {
		recoveryTimeout = 30 * time.Second
	}
	return &Breaker{
		name: name, failureThreshold: failureThreshold,
		recoveryTimeout: recoveryTimeout, halfOpenMaxCalls: 2,
		now: time.Now,
	}
}

// refreshLocked 检查冷却是否到期（调用方需已持锁）。
func (b *Breaker) refreshLocked() {
	if b.state == StateOpen && b.now().Sub(b.openedAt) >= b.recoveryTimeout {
		b.state = StateHalfOpen
		b.halfOpenCalls = 0
	}
}

// State 返回当前状态；冷却期满时自动迁移到半开。
func (b *Breaker) State() BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refreshLocked()
	return b.state
}

// Allow 判断是否放行本次请求。半开状态下按配额限量试探。
func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refreshLocked()

	switch b.state {
	case StateClosed:
		return true
	case StateOpen:
		return false
	default: // StateHalfOpen
		if b.halfOpenCalls < b.halfOpenMaxCalls {
			b.halfOpenCalls++
			return true
		}
		return false
	}
}

// RecordSuccess 记录一次成功，清零失败计数并在半开态下恢复正常。
func (b *Breaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = StateClosed
	b.consecutive = 0
	b.halfOpenCalls = 0
}

// RecordFailure 记录一次瞬时故障；半开态下一次失败即退回熔断。
func (b *Breaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consecutive++
	if b.state == StateHalfOpen || b.consecutive >= b.failureThreshold {
		b.state = StateOpen
		b.openedAt = b.now()
		b.halfOpenCalls = 0
	}
}

// Reset 手动复位（运维干预后使用）。
func (b *Breaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = StateClosed
	b.consecutive = 0
	b.halfOpenCalls = 0
}

// Name 返回熔断器标识。
func (b *Breaker) Name() string { return b.name }
