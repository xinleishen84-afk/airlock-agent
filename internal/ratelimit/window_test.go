package ratelimit

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// newTestLimiter 构造一个可控时钟的限流器。
func newTestLimiter(lim Limits) (*Limiter, func(time.Duration)) {
	l := NewLimiter(lim)
	clock := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return clock }
	return l, func(d time.Duration) { clock = clock.Add(d) }
}

// TestReserveWithinQuota 校验配额内正常放行。
func TestReserveWithinQuota(t *testing.T) {
	l, _ := newTestLimiter(Limits{TokensPerWindow: 1000, Window: time.Minute})
	if _, err := l.Reserve("tenant-a", 400, 100); err != nil {
		t.Fatalf("配额内应放行: %v", err)
	}
	used, inflight, limit := l.Snapshot("tenant-a")
	if used != 500 || inflight != 1 || limit != 1000 {
		t.Errorf("快照不符: used=%d inflight=%d limit=%d", used, inflight, limit)
	}
}

// TestReserveBlocksOverQuota 校验超配额被拒。
// 关键点：拒绝依据是「预扣上界」而非「已实际消耗」——
// 否则已放行但未完成的请求跑满时会超卖。
func TestReserveBlocksOverQuota(t *testing.T) {
	l, _ := newTestLimiter(Limits{TokensPerWindow: 1000, Window: time.Minute})
	if _, err := l.Reserve("t", 800, 100); err != nil {
		t.Fatalf("首次应放行: %v", err)
	}
	_, err := l.Reserve("t", 200, 100)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("超配额应返回 ErrQuotaExceeded，得到 %v", err)
	}
}

// TestCommitRefundsOverReservation 校验回填退还多预扣的部分。
// 这是 token 限流的核心：按 max_tokens 预扣，按实际 usage 结算。
func TestCommitRefundsOverReservation(t *testing.T) {
	l, _ := newTestLimiter(Limits{TokensPerWindow: 10000, Window: time.Minute})
	r, err := l.Reserve("t", 4000, 100) // 预扣 4100
	if err != nil {
		t.Fatalf("预留失败: %v", err)
	}
	if used, _, _ := l.Snapshot("t"); used != 4100 {
		t.Fatalf("预扣后应为 4100，实际 %d", used)
	}

	// 实际只用了 100 输入 + 250 输出
	if err := l.Commit(r, Usage{InputTokens: 100, OutputTokens: 250}); err != nil {
		t.Fatalf("回填失败: %v", err)
	}
	used, inflight, _ := l.Snapshot("t")
	if used != 350 {
		t.Errorf("回填后应为 350，实际 %d", used)
	}
	if inflight != 0 {
		t.Errorf("回填后在途数应归零，实际 %d", inflight)
	}
}

// TestCommitHandlesOverrun 校验实际用量超过预扣时如实计入。
func TestCommitHandlesOverrun(t *testing.T) {
	l, _ := newTestLimiter(Limits{TokensPerWindow: 10000, Window: time.Minute})
	r, _ := l.Reserve("t", 100, 100) // 预扣 200
	// 模型无视 max_tokens 的极端情况
	l.Commit(r, Usage{InputTokens: 100, OutputTokens: 500})
	if used, _, _ := l.Snapshot("t"); used != 600 {
		t.Errorf("超额应如实计入 600，实际 %d", used)
	}
}

// TestReleaseFreesQuota 校验流中断时整笔预留作废。
func TestReleaseFreesQuota(t *testing.T) {
	l, _ := newTestLimiter(Limits{TokensPerWindow: 1000, Window: time.Minute})
	r, _ := l.Reserve("t", 900, 50)
	if err := l.Release(r); err != nil {
		t.Fatalf("释放失败: %v", err)
	}
	if used, inflight, _ := l.Snapshot("t"); used != 0 || inflight != 0 {
		t.Errorf("释放后应清零，实际 used=%d inflight=%d", used, inflight)
	}
	// 释放后配额应可再次使用
	if _, err := l.Reserve("t", 900, 50); err != nil {
		t.Errorf("释放后应能再次预留: %v", err)
	}
}

// TestDoubleSettleRejected 校验重复结算被拒，防止配额被凭空退还。
func TestDoubleSettleRejected(t *testing.T) {
	l, _ := newTestLimiter(Limits{TokensPerWindow: 1000, Window: time.Minute})
	r, _ := l.Reserve("t", 100, 100)
	l.Commit(r, Usage{OutputTokens: 50})
	if err := l.Commit(r, Usage{OutputTokens: 50}); !errors.Is(err, ErrUnknownReservation) {
		t.Errorf("重复 Commit 应被拒，得到 %v", err)
	}
	if err := l.Release(r); !errors.Is(err, ErrUnknownReservation) {
		t.Errorf("已结算的预留不应可释放，得到 %v", err)
	}
}

// TestLeakedReservationSwept 校验客户端断连导致的预留泄漏会被清扫。
// 若没有这一步，配额会被慢慢漏干，最终整个主体永久 429。
func TestLeakedReservationSwept(t *testing.T) {
	l, advance := newTestLimiter(Limits{
		TokensPerWindow: 1000, Window: time.Hour, ReservationTTL: time.Minute,
	})
	l.Reserve("t", 900, 50) // 拿到预留后「客户端断连」，永不结算
	if used, _, _ := l.Snapshot("t"); used != 950 {
		t.Fatalf("预扣应为 950，实际 %d", used)
	}

	advance(2 * time.Minute)
	// 下一次 Reserve 触发惰性清扫，泄漏的预留应被释放
	if _, err := l.Reserve("t", 900, 50); err != nil {
		t.Errorf("泄漏预留清扫后应能再次预留: %v", err)
	}
}

// TestWindowSlides 校验窗口滑动后旧用量退出统计。
func TestWindowSlides(t *testing.T) {
	l, advance := newTestLimiter(Limits{TokensPerWindow: 1000, Window: time.Minute})
	r, _ := l.Reserve("t", 800, 100)
	l.Commit(r, Usage{InputTokens: 100, OutputTokens: 800})
	if used, _, _ := l.Snapshot("t"); used != 900 {
		t.Fatalf("窗口内应为 900，实际 %d", used)
	}

	advance(2 * time.Minute) // 超过窗口长度
	if used, _, _ := l.Snapshot("t"); used != 0 {
		t.Errorf("窗口滑过后应清零，实际 %d", used)
	}
	if _, err := l.Reserve("t", 900, 50); err != nil {
		t.Errorf("窗口滑过后应能再次预留: %v", err)
	}
}

// TestMaxConcurrent 校验并发在途上限独立生效。
// token 配额充足时仍可能因过多并发流打爆 GPU 队列，故需单独限制。
func TestMaxConcurrent(t *testing.T) {
	l, _ := newTestLimiter(Limits{TokensPerWindow: 1_000_000, Window: time.Minute, MaxConcurrent: 2})
	r1, _ := l.Reserve("t", 10, 10)
	l.Reserve("t", 10, 10)
	if _, err := l.Reserve("t", 10, 10); !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("并发超限应被拒，得到 %v", err)
	}
	l.Commit(r1, Usage{OutputTokens: 5})
	if _, err := l.Reserve("t", 10, 10); err != nil {
		t.Errorf("释放一个在途后应可再次预留: %v", err)
	}
}

// TestPerSubjectIsolation 校验多租户配额互相隔离。
func TestPerSubjectIsolation(t *testing.T) {
	l, _ := newTestLimiter(Limits{TokensPerWindow: 100, Window: time.Minute})
	l.SetLimits("vip", Limits{TokensPerWindow: 10000, Window: time.Minute})

	if _, err := l.Reserve("normal", 200, 0); !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("普通租户应被限，得到 %v", err)
	}
	if _, err := l.Reserve("vip", 200, 0); err != nil {
		t.Errorf("VIP 租户应放行: %v", err)
	}
}

// TestUnlimitedQuota 校验配额为 0 表示不限。
func TestUnlimitedQuota(t *testing.T) {
	l, _ := newTestLimiter(Limits{TokensPerWindow: 0, Window: time.Minute})
	for i := 0; i < 100; i++ {
		if _, err := l.Reserve("t", 100000, 0); err != nil {
			t.Fatalf("不限配额时不应被拒: %v", err)
		}
	}
}

// TestConcurrentReserveCommit 校验并发准入与结算的正确性。
func TestConcurrentReserveCommit(t *testing.T) {
	l := NewLimiter(Limits{TokensPerWindow: 1_000_000, Window: time.Minute})

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				r, err := l.Reserve("shared", 100, 10)
				if err != nil {
					continue
				}
				l.Commit(r, Usage{InputTokens: 10, OutputTokens: 20})
			}
		}()
	}
	wg.Wait()

	_, inflight, _ := l.Snapshot("shared")
	if inflight != 0 {
		t.Errorf("全部结算后在途数应归零，实际 %d", inflight)
	}
}

// TestNegativeInputRejected 校验非法输入被拒。
func TestNegativeInputRejected(t *testing.T) {
	l, _ := newTestLimiter(Limits{TokensPerWindow: 1000, Window: time.Minute})
	if _, err := l.Reserve("t", -1, 0); err == nil {
		t.Error("负数 token 应被拒")
	}
}
