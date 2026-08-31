package anonymize

import (
	"context"
	"sync"
	"testing"
	"time"
)

func newTestCacheStore(t *testing.T, c Cache, ttl time.Duration) *CacheTokenStore {
	t.Helper()
	s, err := NewCacheTokenStore(c, ttl, "airlock:")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var atomicityKey = TokenKey{Tenant: "acme", Namespace: "phone"}

// TestIssuedTokenAlwaysResolves 是这个存储最要紧的不变量：
// Issue 成功返回的令牌，一定解析得回原值。
// The store's central invariant: a token Issue returns must resolve.
//
// # 两键写撕裂后，坏的不是失败的那一次调用
// # A torn two-key write does not damage the call that failed
//
// Issue 要写两条记录：正向「值摘要 → 令牌」与反向「令牌 → 值」。缓存是分布式的，
// 两次写之间可以断。
//
// 曾经是先写正向。反向写失败时 Issue 报错——看起来安全，但正向那条留下了。
// 下一次同一个值进来走快路径直接命中，**成功返回**那个令牌，而它没有反向记录。
// 实测：令牌进入出站载荷，模型带回来后 Resolve 返回 ok=false，被当成模型捏造
// 的幻影，真值永远还不回去。且每一次针对该值的调用都返回同一个坏令牌，
// 直到 TTL 到期。
//
// Forward-first left the forward entry behind when the reverse write failed, so
// the next call for that value hit the fast path and succeeded with a token
// nothing could resolve — for every call until the TTL expired.
func TestIssuedTokenAlwaysResolves(t *testing.T) {
	ctx := context.Background()
	const value = "13800138000"

	for _, tc := range []struct {
		name    string
		failNth int // 第 N 次 SetNX 起失败；0 表示不失败
	}{
		{"正常路径", 0},
		{"第一次写就失败", 1},
		{"第二次写失败（撕裂）", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newFakeCache()
			s := newTestCacheStore(t, c, time.Hour)

			c.failSetNXFrom = tc.failNth
			_, firstErr := s.Issue(ctx, atomicityKey, value)
			if tc.failNth > 0 && firstErr == nil {
				t.Fatal("写失败时 Issue 必须报错，不能悄悄返回")
			}

			// 缓存恢复。这一步是关键：故障期间留下的状态，会不会毒害之后的调用。
			c.failSetNXFrom = 0

			tok, err := s.Issue(ctx, atomicityKey, value)
			if err != nil {
				t.Fatalf("缓存恢复后 Issue 仍失败: %v", err)
			}
			got, ok, err := s.Resolve(ctx, atomicityKey, tok)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatalf("Issue 返回的令牌 %s 解析不出来——它会进入出站载荷，"+
					"模型带回来后被当成幻影，真值永远还不回去", tok)
			}
			if got != value {
				t.Fatalf("解析出错误的值: %q，期望 %q", got, value)
			}
		})
	}
}

// TestTornWriteLeavesNoForwardEntry 证明撕裂后不会留下「指向空处」的正向记录。
// Proves a torn write never leaves a forward entry pointing at nothing.
//
// 这是上一条不变量成立的原因。正向记录是快路径的入口，它一旦存在就会被
// 无条件采信；反向记录没人指向时只是垃圾，到期自己消失。两者的失效代价
// 差得很远，所以顺序不是风格问题。
//
// The forward entry is the fast path's entry point and is trusted
// unconditionally once present; an unreferenced reverse entry is merely
// garbage. Their failure costs differ enough that the ordering is not a matter
// of taste.
func TestTornWriteLeavesNoForwardEntry(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	s := newTestCacheStore(t, c, time.Hour)

	c.failSetNXFrom = 2 // 反向写成功，正向写失败
	if _, err := s.Issue(ctx, atomicityKey, "13800138000"); err == nil {
		t.Fatal("正向写失败时 Issue 应当报错")
	}

	if fwd := c.keysWith(":v:"); len(fwd) != 0 {
		t.Errorf("撕裂后残留了正向记录 %v——下一次调用会走快路径命中它，"+
			"返回一个没有反向记录、谁也还原不了的令牌", fwd)
	}
	if rev := c.keysWith(":t:"); len(rev) != 1 {
		t.Errorf("期望恰好一条无人指向的反向记录（无害垃圾，到期消失），实得 %v", rev)
	}
}

// TestReverseOutlivesForward 证明反向映射比正向活得久。
// Proves the reverse mapping outlives the forward one.
//
// 只调换写入顺序不够。两次写差着几毫秒，同样的 TTL 意味着先写的先过期——
// 反向先写就先过期，于是在正向过期之前会有一段时间，快路径返回的令牌已经
// 还原不了了。这正是原来那个顺序碰巧避开的边，换顺序时必须补上。
//
// 余量不按 TTL 比例放大：反向记录里存的是明文原值，余量有多长 PII 就多留多久。
//
// Swapping the order alone is not enough: with equal TTLs the earlier write
// expires earlier, so the reverse would lapse while the forward still answers.
// The margin is a constant, not a fraction: the reverse holds plaintext.
func TestReverseOutlivesForward(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	const ttl = time.Hour
	s := newTestCacheStore(t, c, ttl)

	if _, err := s.Issue(ctx, atomicityKey, "13800138000"); err != nil {
		t.Fatal(err)
	}

	fwd := c.keysWith(":v:")
	rev := c.keysWith(":t:")
	if len(fwd) != 1 || len(rev) != 1 {
		t.Fatalf("期望各一条记录，实得正向 %v 反向 %v", fwd, rev)
	}
	fttl, _ := c.ttlOf(fwd[0])
	rttl, _ := c.ttlOf(rev[0])
	if !(rttl > fttl) {
		t.Errorf("反向 TTL %v 不大于正向 %v——正向会比反向后过期，"+
			"那段时间里快路径返回的令牌已经还原不了了", rttl, fttl)
	}
	if fttl != ttl {
		t.Errorf("正向 TTL 应为配置值 %v，实得 %v", ttl, fttl)
	}
}

// TestNoExpiryNeedsNoMargin 确认 ttl=0（永不过期）时余量不生效。
// ttl=0 时两边都不过期，正向不可能比反向后过期，加余量只会让代码说谎。
func TestNoExpiryNeedsNoMargin(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	s := newTestCacheStore(t, c, 0)

	if _, err := s.Issue(ctx, atomicityKey, "13800138000"); err != nil {
		t.Fatal(err)
	}
	for _, k := range append(c.keysWith(":v:"), c.keysWith(":t:")...) {
		if d, _ := c.ttlOf(k); d != 0 {
			t.Errorf("键 %s 的 TTL 是 %v，ttl=0 时应当为 0（永不过期）", k, d)
		}
	}
}

// TestConcurrentIssueConvergesAndResolves 证明并发签发收敛到一个令牌，
// 且那个令牌可还原。
// Proves concurrent issues converge on one token that resolves.
//
// 竞争失败的一方会留下一条无人指向的反向记录。那是有意的取舍：用一条会
// 自己过期的垃圾，换「Issue 返回的令牌一定可还原」。
func TestConcurrentIssueConvergesAndResolves(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	s := newTestCacheStore(t, c, time.Hour)
	const value = "13800138000"

	const n = 16
	tokens := make([]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := s.Issue(ctx, atomicityKey, value)
			if err != nil {
				t.Errorf("并发 Issue 失败: %v", err)
				return
			}
			tokens[i] = tok
		}()
	}
	wg.Wait()

	for i, tok := range tokens {
		if tok != tokens[0] {
			t.Fatalf("并发签发没有收敛：第 %d 个是 %s，第 0 个是 %s", i, tok, tokens[0])
		}
	}
	got, ok, err := s.Resolve(ctx, atomicityKey, tokens[0])
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got != value {
		t.Errorf("收敛后的令牌解析失败: ok=%v got=%q", ok, got)
	}
}
