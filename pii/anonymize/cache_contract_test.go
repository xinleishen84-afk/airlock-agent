package anonymize

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"
)

// CacheConformance 是 Cache 契约的一致性测试，任何实现都应当能跑通。
// A conformance suite any Cache implementation should pass.
//
// # 为什么契约要有可执行的形式
// # Why the contract needs an executable form
//
// FindOrCreate 的原子性写在接口注释里，而注释拦不住一个「先 Get 再 Set」的
// 实现——它在单线程测试里表现得完全正确，只在并发下偶尔多创建一次。
// 这一套用例把注释里那几句话变成会红的断言：实现者接进来跑一遍，
// 就知道自己有没有真的满足契约，而不是自以为满足。
//
// 传 factory 而不是实例：每个用例要一个干净的存储，共用一个会让先跑的用例
// 留下的键影响后跑的。
//
// Atomicity stated in a doc comment does not stop a check-then-set
// implementation, which looks correct single-threaded and only occasionally
// over-creates under concurrency. These cases turn those sentences into
// assertions that fail.
func CacheConformance(t *testing.T, factory func() Cache) {
	t.Helper()

	t.Run("创建时返回自己写入的值", func(t *testing.T) {
		c := factory()
		got, created, err := c.FindOrCreate(context.Background(), "k", "v", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if !created {
			t.Error("键不存在时 created 应为 true")
		}
		if got != "v" {
			t.Errorf("应返回刚写入的值，实得 %q", got)
		}
	})

	t.Run("已存在时返回已有的值而非入参", func(t *testing.T) {
		c := factory()
		ctx := context.Background()
		if _, _, err := c.FindOrCreate(ctx, "k", "first", time.Hour); err != nil {
			t.Fatal(err)
		}
		got, created, err := c.FindOrCreate(ctx, "k", "second", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if created {
			t.Error("键已存在时 created 应为 false")
		}
		if got != "first" {
			t.Errorf("应返回已有的值 first，实得 %q——"+
				"返回入参会让后写者以为自己的值是权威的，"+
				"两个副本因此对同一个键持有不同的认知", got)
		}
	})

	t.Run("并发下恰好一个创建者", func(t *testing.T) {
		// 重复多轮，而不是一轮开很多协程。
		//
		// 第一版只跑一轮 64 协程，结果连一个故意写坏的 check-then-set 实现都
		// 抓不住：协程是循环里逐个起的，第一个走完「查—间隙—建」时后面的还
		// 没被调度，于是谁都没落进那个间隙。窗口窄的时候，并发度救不了，
		// 重复才行——每一轮都是一次新的调度赌局，只要有一轮翻车就算抓住。
		//
		// 用屏障让本轮的协程尽量同时到达检查点，再把轮数拉起来。
		//
		// Repeating rounds rather than one wide round: the first version could
		// not catch even a deliberately broken check-then-set cache, because
		// goroutines started in a loop do not reach the check together — the
		// first finished before the last was spawned. A narrow window is not
		// exposed by concurrency but by repetition; each round is a fresh
		// scheduling draw and one bad round is enough.
		const rounds = 200
		const n = 16
		for round := range rounds {
			c := factory()
			ctx := context.Background()
			barrier := make(chan struct{})
			var wg sync.WaitGroup
			results := make([]string, n)
			createdFlags := make([]bool, n)
			for i := range n {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-barrier
					got, created, err := c.FindOrCreate(ctx, "k", "v", time.Hour)
					if err != nil {
						t.Errorf("并发调用失败: %v", err)
						return
					}
					results[i], createdFlags[i] = got, created
				}()
			}
			close(barrier)
			wg.Wait()

			creators := 0
			for i := range n {
				if createdFlags[i] {
					creators++
				}
				if results[i] != "v" {
					t.Fatalf("第 %d 轮：第 %d 个调用拿到 %q，期望 v", round, i, results[i])
				}
			}
			if creators != 1 {
				t.Fatalf("第 %d 轮：%d 个并发调用产生了 %d 个创建者，应恰好 1 个——"+
					"多于一个说明「查」与「建」之间存在可观察的间隙，"+
					"那正是 check-then-set 实现的特征", round, n, creators)
			}
		}
	})

	t.Run("读到已有键不得续期", func(t *testing.T) {
		c := factory()
		ctx := context.Background()
		probe, ok := c.(interface {
			ttlOf(string) (time.Duration, bool)
		})
		if !ok {
			t.Skip("该实现不支持 TTL 探查，跳过")
		}
		if _, _, err := c.FindOrCreate(ctx, "k", "v", time.Hour); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.FindOrCreate(ctx, "k", "v", 100*time.Hour); err != nil {
			t.Fatal(err)
		}
		d, _ := probe.ttlOf("k")
		if d != time.Hour {
			t.Errorf("键已存在时 TTL 被改成了 %v，应保持创建时的 1h——"+
				"续期会让一条被反复读到的映射永不过期，而 TTL 正是 PII 的保留期", d)
		}
	})
}

// TestFakeCacheConformance 让测试替身自己先过一遍契约。
//
// 替身不合契约，用它写出来的所有用例就都在测一个不存在的世界——
// 而那正是「测试全绿、真实实现出问题」最常见的来源。
func TestFakeCacheConformance(t *testing.T) {
	CacheConformance(t, func() Cache { return newFakeCache() })
}

// TokenStoreConformance 是 TokenStore 契约的一致性套件。
// A conformance suite for the TokenStore contract.
//
// # 为什么不给每个后端各写一套
// # Why not a separate suite per backend
//
// 各写一套的结果是各测各的：Cache 那套测了并发收敛，SQL 那套测了租户隔离，
// 两边都绿，而没人知道 SQL 的并发收敛与 Cache 的租户隔离有没有被验过。
// 契约是一份，用例就该是一份——后端接进来跑，不通过就是不满足契约，
// 而不是「这个后端的测试是这样写的」。
//
// Per-backend suites end up testing different things: both green, with nobody
// knowing whether SQL's convergence or the cache's isolation was ever checked.
// One contract deserves one suite.
func TokenStoreConformance(t *testing.T, name string, factory func() TokenStore) {
	t.Helper()
	ctx := context.Background()
	const value = "13800138000"
	key := TokenKey{Tenant: "acme", Namespace: "phone"}

	t.Run(name+"/签发后立即可还原", func(t *testing.T) {
		s := factory()
		tok, err := s.Issue(ctx, key, value)
		if err != nil {
			t.Fatal(err)
		}
		got, ok, err := s.Resolve(ctx, key, tok)
		if err != nil || !ok || got != value {
			t.Errorf("Issue 返回的令牌无法立即还原 ok=%v got=%q err=%v", ok, got, err)
		}
	})

	t.Run(name+"/并发签发收敛到同一个令牌", func(t *testing.T) {
		s := factory()
		const n = 100
		tokens := make([]string, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tok, err := s.Issue(ctx, key, value)
				if err != nil {
					t.Errorf("并发签发失败: %v", err)
					return
				}
				tokens[i] = tok
			}()
		}
		wg.Wait()
		for i := 1; i < n; i++ {
			if tokens[i] != tokens[0] {
				t.Fatalf("第 %d 个令牌 %s 与第 0 个 %s 不同——并发未收敛",
					i, tokens[i], tokens[0])
			}
		}
	})

	t.Run(name+"/提交后超时重试得到同一个令牌", func(t *testing.T) {
		// 模拟「服务端已提交、客户端超时」：第一次调用成功但调用方当作失败，
		// 随后重试。重试必须落到同一个令牌，而不是再造一个。
		//
		// Models a commit the client never saw: the retry must land on the same
		// token rather than minting a second one.
		s := factory()
		first, err := s.Issue(ctx, key, value)
		if err != nil {
			t.Fatal(err)
		}
		retry, err := s.Issue(ctx, key, value)
		if err != nil {
			t.Fatalf("重试失败: %v", err)
		}
		if retry != first {
			t.Errorf("超时重试得到了不同的令牌 %s vs %s——"+
				"同一个值因此在下游被当成两个不同的实体", retry, first)
		}
	})

	t.Run(name+"/租户之间绝对隔离", func(t *testing.T) {
		s := factory()
		a := TokenKey{Tenant: "acme", Namespace: "phone"}
		b := TokenKey{Tenant: "globex", Namespace: "phone"}
		tokA, err := s.Issue(ctx, a, value)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := s.Resolve(ctx, b, tokA); ok {
			t.Error("租户 B 用租户 A 的令牌还原成功——这是一次跨租户明文泄露")
		}
	})

	t.Run(name+"/命名空间之间绝对隔离", func(t *testing.T) {
		s := factory()
		a := TokenKey{Tenant: "acme", Namespace: "phone"}
		b := TokenKey{Tenant: "acme", Namespace: "name"}
		tokA, err := s.Issue(ctx, a, value)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := s.Resolve(ctx, b, tokA); ok {
			t.Error("另一个命名空间用该令牌还原成功——类别边界没有生效")
		}
	})

	t.Run(name+"/未知令牌确定性地返回未找到", func(t *testing.T) {
		s := factory()
		got, ok, err := s.Resolve(ctx, key, "ffffffffffffffffffffffffffffffff")
		if err != nil {
			t.Errorf("未知令牌应返回 (false, nil) 而不是错误: %v", err)
		}
		if ok || got != "" {
			t.Errorf("未知令牌不该解出任何东西 ok=%v got=%q", ok, got)
		}
	})

	t.Run(name+"/擦除后不再可还原", func(t *testing.T) {
		s := factory()
		tok, err := s.Issue(ctx, key, value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Clear(ctx, key.Tenant); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := s.Resolve(ctx, key, tok); ok {
			t.Error("擦除之后令牌仍能还原——GDPR 第 17 条的擦除没有真正生效")
		}
	})
}

// TestCacheTokenStoreConformance 让缓存后端过一遍 TokenStore 契约。
func TestCacheTokenStoreConformance(t *testing.T) {
	TokenStoreConformance(t, "cache", func() TokenStore {
		s, err := NewCacheTokenStore(newFakeCache(), testKeyring(t), time.Hour, "conf:")
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

// TestMemoryTokenStoreConformance 让内存后端过同一份契约。
func TestMemoryTokenStoreConformance(t *testing.T) {
	TokenStoreConformance(t, "memory", func() TokenStore {
		return NewMemoryTokenStore(time.Hour)
	})
}

// TestIssueNeverReturnsUnresolvableToken 是不变量 A 在故障注入下的版本。
// Invariant A under fault injection.
//
// # 只测 happy path 证明不了这条不变量
// # The happy path cannot prove this invariant
//
// 「Issue 返回的令牌立即可 Resolve」在一切正常时当然成立。它真正要挡的是
// 故障之后的状态：写失败之后留下的东西，会不会让**下一次**调用返回一个
// 还原不了的令牌。旧的两键设计正是败在这里——失败的那次调用报了错，
// 而它留下的半条映射毒害了之后每一次调用，直到 TTL 到期。
//
// The invariant holds trivially when nothing fails. What it must guard is the
// state left behind by a failure: whether the *next* call returns a token that
// cannot be resolved. The old two-key design failed exactly there.
func TestIssueNeverReturnsUnresolvableToken(t *testing.T) {
	ctx := context.Background()
	key := TokenKey{Tenant: "acme", Namespace: "phone"}
	const value = "13800138000"

	for _, failFrom := range []int{1, 2, 3} {
		t.Run("第"+strconv.Itoa(failFrom)+"次写起失败", func(t *testing.T) {
			c := newFakeCache()
			s, err := NewCacheTokenStore(c, testKeyring(t), time.Hour, "fi:")
			if err != nil {
				t.Fatal(err)
			}

			c.failWriteFrom = failFrom
			// 故障期间反复调用，每一次要么报错，要么返回一个立即可还原的令牌。
			// 不允许出现第三种结果。
			for range 5 {
				tok, err := s.Issue(ctx, key, value)
				if err != nil {
					continue
				}
				got, ok, rerr := s.Resolve(ctx, key, tok)
				if rerr != nil || !ok || got != value {
					t.Fatalf("Issue 成功返回了令牌 %s，但它还原不出来 "+
						"ok=%v got=%q err=%v——故障期间产生了一个坏令牌",
						tok, ok, got, rerr)
				}
			}

			// 故障恢复后必须能正常工作，而不是被故障期间留下的状态毒害
			c.failWriteFrom = 0
			tok, err := s.Issue(ctx, key, value)
			if err != nil {
				t.Fatalf("故障恢复后仍失败: %v", err)
			}
			got, ok, err := s.Resolve(ctx, key, tok)
			if err != nil || !ok || got != value {
				t.Errorf("恢复后签发的令牌还原失败 ok=%v got=%q err=%v", ok, got, err)
			}
		})
	}
}

// TestSQLTokenStoreConformance 让 SQL 后端过同一份 TokenStore 契约。
//
// 接进来之后立刻发现了一个真缺陷：SELECT 与 INSERT 之间有间隙，两个副本
// 会同时落空、同时插入，而 UNIQUE 约束拒绝后到的那个——原来的代码把这个
// 拒绝当成写入故障抛出，真库语义下 32 次并发有 4 次直接失败。
//
// 它此前不被发现，是因为假 DB 用一把全局锁把 SELECT 与 INSERT 串起来，
// 比真数据库更原子，冲突从未发生。替身现在真的执行唯一约束。
//
// Wiring SQL into the shared suite immediately surfaced a real defect that the
// old double hid by being more atomic than a database.
func TestSQLTokenStoreConformance(t *testing.T) {
	TokenStoreConformance(t, "sql", func() TokenStore {
		s, err := NewSQLTokenStore(newFakeDB(), testKeyring(t), "tokens", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}
