package lifecycle

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Tracker 跟踪在途请求，用于判断何时可以安全退出。
//
// 与裸 sync.WaitGroup 的差别在于两点：
//
//  1. 能读出当前在途数——停机日志需要它，否则运维只能盲等
//  2. 区分「流式」与「非流式」——非流式请求通常几百毫秒内结束，
//     真正需要等的是 SSE 流。分开计数才能在日志里说清楚
//     「还在等 3 条流」而不是「还有 3 个请求」
type Tracker struct {
	wg sync.WaitGroup

	total     atomic.Int64
	streaming atomic.Int64

	// 用于在归零时唤醒等待者。WaitGroup 无法带超时地等待，
	// 而停机必须有硬上限——不能因为一条卡住的流永远不退出。
	mu     sync.Mutex
	zeroCh chan struct{}
}

// NewTracker 创建跟踪器。
func NewTracker() *Tracker {
	return &Tracker{zeroCh: make(chan struct{})}
}

// Done 是请求结束时必须调用的回调。
type Done func()

// Enter 登记一个在途请求，返回结束回调。
//
// 必须用 defer 调用返回值。漏掉任何一条路径都会让停机永远等不到归零，
// 最终只能靠超时强杀——那正是我们想避免的。
func (t *Tracker) Enter(streaming bool) Done {
	t.wg.Add(1)
	t.total.Add(1)
	if streaming {
		t.streaming.Add(1)
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			if streaming {
				t.streaming.Add(-1)
			}
			remaining := t.total.Add(-1)
			t.wg.Done()
			if remaining == 0 {
				t.signalZero()
			}
		})
	}
}

// signalZero 在在途数归零时唤醒等待者。
func (t *Tracker) signalZero() {
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case <-t.zeroCh:
		// 已关闭，说明之前就归零过
	default:
		close(t.zeroCh)
	}
}

// resetZero 重新武装归零通道，供多次等待使用。
func (t *Tracker) resetZero() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.zeroCh = make(chan struct{})
}

// InFlight 返回当前在途请求总数。
func (t *Tracker) InFlight() int64 { return t.total.Load() }

// Streaming 返回当前活跃的 SSE 流数。
func (t *Tracker) Streaming() int64 { return t.streaming.Load() }

// WaitZero 等待在途数归零，或直到超时/上下文取消。
//
// 返回 true 表示已优雅归零，false 表示超时——此时调用方应记录
// 有多少连接将被强制中断，这个数字是评估停机窗口是否合理的唯一依据。
func (t *Tracker) WaitZero(ctx context.Context, timeout time.Duration) bool {
	if t.InFlight() == 0 {
		return true
	}
	t.resetZero()
	// 重置后再查一次：重置期间可能刚好归零，
	// 漏掉这次检查会白等一整个超时窗口
	if t.InFlight() == 0 {
		return true
	}

	t.mu.Lock()
	ch := t.zeroCh
	t.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ch:
		return true
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
}
