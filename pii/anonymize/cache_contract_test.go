package anonymize

import (
	"context"
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
