package anonymize

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

var atomicityKey = TokenKey{Tenant: "acme", Namespace: "phone"}

func newTestCacheStore(t *testing.T, c Cache, ttl time.Duration) *CacheTokenStore {
	t.Helper()
	s, err := NewCacheTokenStore(c, testKeyring(t), ttl, "airlock:")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestIssueWritesExactlyOneKey 证明签发只落一个键。
// Proves issuing writes exactly one key.
//
// # 不变量二：不允许观察到 forward 存在而 reverse 不存在
// # Invariant 2: a forward mapping must never be observable without its reverse
//
// 这一条不是靠写入顺序或 TTL 余量满足的，是靠**没有第二个键**满足的。
// 原来的设计写两个键：正向「值摘要 → 令牌」与反向「令牌 → 原值」。两个键
// 意味着两次写，而缓存是分布式的——两次写之间可以断、可以崩、可以被各自
// 驱逐。无论怎么排序、怎么调 TTL，都只是把能观察到撕裂的窗口挪小：
// 调换顺序换掉的是写失败那条边，TTL 余量换掉的是过期那条边，而缓存在
// maxmemory 压力下独立驱逐任一键这条边，两者都盖不住。
//
// 令牌改为从原值确定性派生之后，正向索引整个不需要了——同一个值算出同一个
// 令牌这件事由函数保证，不需要存储去记。于是只剩一个键、一次写。
//
// The invariant holds because there is no second key, not because of ordering
// or TTL margins. Two keys mean two writes, and no ordering closes the edge
// where a cache independently evicts either one under memory pressure.
func TestIssueWritesExactlyOneKey(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	s := newTestCacheStore(t, c, time.Hour)

	if _, err := s.Issue(ctx, atomicityKey, "13800138000"); err != nil {
		t.Fatal(err)
	}
	if n := c.setN; n != 1 {
		t.Errorf("签发写了 %d 次，应当只写 1 次——多于一次就存在可撕裂的中间态", n)
	}
	if fwd := c.keysWith(":v:"); len(fwd) != 0 {
		t.Errorf("仍然存在正向索引键 %v——它是撕裂的来源，应当已被消除", fwd)
	}
	if rev := c.keysWith(":t:"); len(rev) != 1 {
		t.Errorf("期望恰好一个「令牌 → 原值」键，实得 %v", rev)
	}
}

// TestIssuedTokenAlwaysResolves 是不变量一：返回的令牌必须立即可还原。
// Invariant 1: a token Issue returns must resolve immediately.
//
// 写失败必须让 Issue 报错，而且**不能留下会毒害后续调用的状态**。原来的
// 两键设计正是败在后半句：反向写失败时 Issue 报错，看起来安全，但正向那条
// 留下了，下一次同一个值走快路径直接命中、成功返回一个没有反向记录的令牌。
// 坏的不是失败的那一次调用，是之后每一次，直到 TTL 到期。
//
// A failed write must error and must not leave state that poisons later calls
// — which is exactly where the two-key design failed.
func TestIssuedTokenAlwaysResolves(t *testing.T) {
	ctx := context.Background()
	const value = "13800138000"

	for _, tc := range []struct {
		name    string
		failNth int
	}{
		{"正常路径", 0},
		{"写入失败", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newFakeCache()
			s := newTestCacheStore(t, c, time.Hour)

			c.failWriteFrom = tc.failNth
			if _, err := s.Issue(ctx, atomicityKey, value); tc.failNth > 0 && err == nil {
				t.Fatal("写失败时 Issue 必须报错，不能悄悄返回一个没落地的令牌")
			}
			c.failWriteFrom = 0

			tok, err := s.Issue(ctx, atomicityKey, value)
			if err != nil {
				t.Fatalf("缓存恢复后 Issue 仍失败: %v", err)
			}
			got, ok, err := s.Resolve(ctx, atomicityKey, tok)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Fatalf("Issue 返回的令牌 %s 还原不出来——它会进入出站载荷，"+
					"模型带回来后被当成幻影，真值永远还不回去", tok)
			}
			if got != value {
				t.Fatalf("还原出错误的值: %q，期望 %q", got, value)
			}
		})
	}
}

// TestConcurrentIssueLinearizes 是不变量三：并发签发线性化到同一个令牌。
// Invariant 3: concurrent issues linearize to one token.
//
// 派生式令牌让这一条从「竞争出一个赢家」变成「由构造方式直接达成一致」：
// 并发的各方算出的本来就是同一个令牌，SetNX 只决定谁真正落盘，而落盘的
// 内容对所有人都一样。因此不存在「赢家的令牌与败者手里的不一致」这种状态，
// 也不需要败者回头去读赢家写了什么。
//
// Derivation turns this from racing for a winner into agreeing by
// construction: every caller computes the same token, and SetNX only decides
// who physically writes it.
func TestConcurrentIssueLinearizes(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	s := newTestCacheStore(t, c, time.Hour)
	const value = "13800138000"

	const n = 32
	tokens := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tokens[i], errs[i] = s.Issue(ctx, atomicityKey, value)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("并发第 %d 次签发失败: %v", i, err)
		}
		if tokens[i] != tokens[0] {
			t.Fatalf("并发签发未线性化：第 %d 个是 %s，第 0 个是 %s",
				i, tokens[i], tokens[0])
		}
	}
	got, ok, err := s.Resolve(ctx, atomicityKey, tokens[0])
	if err != nil || !ok || got != value {
		t.Errorf("线性化后的令牌还原失败: ok=%v got=%q err=%v", ok, got, err)
	}
}

// TestReplicasAgreeWithoutSharedProcessState 是不变量五：跨副本一致性
// 不依赖进程内 mutex。
// Invariant 5: cross-replica consistency must not rely on an in-process mutex.
//
// 用两个互不相识的 CacheTokenStore 实例模拟两个副本——它们只共享缓存，
// 不共享任何 Go 层面的状态。一致性必须来自派生函数本身，而不是来自
// 「碰巧在同一个进程里」。
//
// 这一条用单进程内的 mutex 是测不出来的：mutex 在单实例测试里永远是绿的，
// 而它在第二个副本上一点用都没有。
//
// Two stores that share only the cache stand in for two replicas. An
// in-process mutex would pass every single-instance test while doing nothing
// on the second replica.
func TestReplicasAgreeWithoutSharedProcessState(t *testing.T) {
	ctx := context.Background()
	shared := newFakeCache()
	replicaA := newTestCacheStore(t, shared, time.Hour)
	replicaB := newTestCacheStore(t, shared, time.Hour)
	const value = "13800138000"

	tokA, err := replicaA.Issue(ctx, atomicityKey, value)
	if err != nil {
		t.Fatal(err)
	}
	tokB, err := replicaB.Issue(ctx, atomicityKey, value)
	if err != nil {
		t.Fatal(err)
	}
	if tokA != tokB {
		t.Fatalf("两个副本对同一个值签发了不同令牌：A=%s B=%s——"+
			"同一会话的同一个值会在下游被当成两个不同的实体", tokA, tokB)
	}

	// A 签发的令牌必须能被 B 还原，反之亦然
	for name, pair := range map[string]struct {
		by   *CacheTokenStore
		tok  string
		from string
	}{
		"B 还原 A 签发的": {replicaB, tokA, "A"},
		"A 还原 B 签发的": {replicaA, tokB, "B"},
	} {
		got, ok, err := pair.by.Resolve(ctx, atomicityKey, pair.tok)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !ok || got != value {
			t.Errorf("%s：副本 %s 签发的令牌在另一个副本上还原失败 ok=%v got=%q",
				name, pair.from, ok, got)
		}
	}
}

// TestCrashBetweenCallsLeavesNoBrokenState 是不变量四：崩溃与超时之后
// 不变量仍成立。
// Invariant 4: the invariants survive a crash or timeout.
//
// 单键写只有两种结果：写之前崩——什么都没有；写之后崩——记录是完整的。
// 超时的含义不明（写可能已经落地），但下一次调用算出的是同一个令牌，
// SetNX 要么写入、要么发现它已在，两条路都收敛到同一个可还原的令牌。
//
// 用「新建一个 store 实例」模拟进程重启：新实例不带任何进程内状态，
// 它对同一个值算出的令牌必须与崩溃前一致。
//
// A single write either happened or did not. A timeout is ambiguous, but the
// next call derives the same token and SetNX either stores it or finds it
// present. A fresh store instance stands in for a restarted process.
func TestCrashBetweenCallsLeavesNoBrokenState(t *testing.T) {
	ctx := context.Background()
	shared := newFakeCache()
	const value = "13800138000"

	before := newTestCacheStore(t, shared, time.Hour)
	tokBefore, err := before.Issue(ctx, atomicityKey, value)
	if err != nil {
		t.Fatal(err)
	}

	// 进程重启：全新实例，无任何进程内状态
	after := newTestCacheStore(t, shared, time.Hour)
	tokAfter, err := after.Issue(ctx, atomicityKey, value)
	if err != nil {
		t.Fatalf("重启后签发失败: %v", err)
	}
	if tokAfter != tokBefore {
		t.Errorf("重启前后令牌不一致: %s vs %s", tokBefore, tokAfter)
	}
	got, ok, err := after.Resolve(ctx, atomicityKey, tokBefore)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got != value {
		t.Errorf("重启后还原崩溃前签发的令牌失败 ok=%v got=%q", ok, got)
	}
}

// TestMismatchedKeyringFailsLoudly 证明同一前缀下混用密钥环会响亮地失败。
// Proves two keyrings under one prefix fail loudly.
//
// 派生式令牌的代价：令牌与密钥绑定。两套不同的密钥环写进同一个缓存前缀是
// 配置错误，而它的症状本来会是「一个租户的令牌解析出另一份数据」——
// 一次跨租户的数据串线，且没有任何错误。因此 Issue 在发现已有键映射到
// 不同的值时必须报错，而不是沉默返回。
//
// The cost of derived tokens: they are bound to a key. Two keyrings under one
// prefix is a misconfiguration whose symptom would otherwise be one tenant's
// token resolving to another's data, silently.
func TestMismatchedKeyringFailsLoudly(t *testing.T) {
	ctx := context.Background()
	shared := newFakeCache()
	s := newTestCacheStore(t, shared, time.Hour)

	tok, err := s.Issue(ctx, atomicityKey, "13800138000")
	if err != nil {
		t.Fatal(err)
	}
	// 手工把该令牌的记录改成另一个值，模拟「另一套密钥环恰好算出同一个令牌」
	shared.mu.Lock()
	for k := range shared.data {
		if strings.HasSuffix(k, tok) {
			shared.data[k] = "13900139000"
		}
	}
	shared.mu.Unlock()

	if _, err := s.Issue(ctx, atomicityKey, "13800138000"); err == nil {
		t.Error("已有键映射到不同的值时必须报错——沉默返回会让一个租户的" +
			"令牌解析出另一份数据")
	} else if !errors.Is(err, ErrTokenStore) {
		t.Errorf("错误应当归到 ErrTokenStore: %v", err)
	}
}
