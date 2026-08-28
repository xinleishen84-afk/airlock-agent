package eval

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/preset"
	"github.com/xinleishen84-afk/airlock-agent/pii/verify"
)

// # Core 模式能覆盖多少
// # What Core mode actually covers
//
// 「Core 解决 85% 的场景」这类说法，不量出来就只是一句话。这里量的是：
// 纯 Go、零额外依赖、单二进制的配置下，语料里的实体有多大比例被检出。
//
// "Core covers 85%" is a sentence until it is measured. This measures what
// fraction of the corpus a pure-Go, zero-extra-dependency binary catches.
//
// 分母分开报：结构化标识与非结构化实体的性质完全不同，混在一起平均，
// 会把「结构化几乎全中」和「人名地址全靠模型」这两件事都藏起来。
//
// The denominators are reported separately: averaging structured identifiers
// with unstructured entities hides both that the former are nearly all caught
// and that the latter depend entirely on the model.

// coreDetector 走 preset 的标准装配 —— 与二进制完全同一份。
//
// 手工搭一份是这个文件原来的做法，而它与二进制搭的那份不一样：
// 这里装了复姓识别、二进制没装。于是这里量出来的数字描述的是一个
// 二进制产不出的配置，而我把它写进了报告和 README。
//
// This used to hand-build an assembly that differed from the binary's, so the
// numbers here described a configuration the binary could not produce.
func coreDetector(t testing.TB, roster map[detect.EntityType][]string) detect.Detector {
	t.Helper()
	opts := preset.DefaultCoreOptions([]string{"GEN", "CN", "US", "IT", "DE", "ES"})
	opts.Roster = roster
	d, _, err := preset.Core(opts)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// coreStack 返回检测器与证据链，供需要完整 Core 行为的用例使用。
func coreStack(t testing.TB, roster map[detect.EntityType][]string) (
	detect.Detector, *verify.EvidenceValidator) {
	t.Helper()
	opts := preset.DefaultCoreOptions([]string{"GEN", "CN", "US", "IT", "DE", "ES"})
	opts.Roster = roster
	d, v, err := preset.Core(opts)
	if err != nil {
		t.Fatal(err)
	}
	return d, v
}

// Core 模式的覆盖率，按实体性质分开报。
// Core mode's coverage, split by the nature of the entity.
func TestCoreModeCoverage(t *testing.T) {
	d := coreDetector(t, map[detect.EntityType][]string{
		detect.TypeName: {"张伟", "李娜"},
		detect.TypeOrg:  {"星辰科技 有限公司"},
	})

	type group struct {
		name    string
		samples []Sample
	}
	groups := []group{
		{"结构化标识（含凭据、欧洲国家包）", Positives()},
		{"非结构化（名册外姓名/地址/机构）", UnknownNames()},
	}

	totalHit, totalGold := 0, 0
	for _, g := range groups {
		res, err := Score(d, g.samples)
		if err != nil {
			t.Fatal(err)
		}
		gold := res.TruePositives + res.FalseNegatives + res.PartialMatches + res.TypeMismatches
		t.Logf("%-32s %2d/%2d = %5.1f%%", g.name, res.TruePositives, gold,
			float64(res.TruePositives)/float64(gold)*100)
		totalHit += res.TruePositives
		totalGold += gold
	}
	t.Logf("%-32s %2d/%2d = %5.1f%%   ← Core 模式的总覆盖",
		"合计", totalHit, totalGold, float64(totalHit)/float64(totalGold)*100)

	// 误报同样要报：覆盖率高而误报也高，不是好交易。
	neg, err := Score(d, Negatives())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%-32s 反例 %d 篇，误报 %d 处", "对抗性反例", len(Negatives()), neg.FalsePositives)
}

// Core 模式的吞吐量与内存 —— 单二进制、无跨进程调用的实际数字。
// Core mode's throughput and memory: the numbers for one binary, no IPC.
func TestCoreModeThroughputAndMemory(t *testing.T) {
	skipPerfUnderRace(t)
	d := coreDetector(t, map[detect.EntityType][]string{
		detect.TypeName: {"张伟", "李娜"},
	})

	// 典型提示词大小的请求
	const text = "请联系张伟，手机 13812345678，邮箱 zhang.wei@example.com，" +
		"身份证 11010519491231002X，公司在杭州。"

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	for range 1000 {
		if _, err := d.Detect(text); err != nil {
			t.Fatal(err)
		}
	}

	workers := runtime.GOMAXPROCS(0)
	const perWorker = 20000
	var wg sync.WaitGroup
	start := time.Now()
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perWorker {
				if _, err := d.Detect(text); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	runtime.ReadMemStats(&after)
	qps := float64(workers*perWorker) / elapsed.Seconds()

	t.Logf("请求体 %d 字节，%d 核并发", len(text), workers)
	t.Logf("  吞吐 %.0f req/s（%.1fk QPS）", qps, qps/1000)
	t.Logf("  单请求平均 %v", elapsed/time.Duration(workers*perWorker))
	t.Logf("  堆增量 %.1f MB（%d 次请求期间）",
		float64(after.HeapAlloc-before.HeapAlloc)/(1<<20), workers*perWorker)
	t.Logf("  常驻堆 %.1f MB", float64(after.HeapAlloc)/(1<<20))
}

// Core 与 Advanced 各自解决什么 —— 逐条列出来，而不是给一个百分比。
// What each mode solves, itemized rather than averaged into one percentage.
func TestModeCapabilityMatrix(t *testing.T) {
	d := coreDetector(t, map[detect.EntityType][]string{
		detect.TypeName: {"张伟"},
	})

	cases := []struct {
		text string
		want string
		note string
	}{
		{"身份证 11010519491231002X", "11010519491231002X", "校验位"},
		{"卡号 4111111111111111", "4111111111111111", "Luhn + IIN"},
		{"手机 13812345678", "13812345678", "正则"},
		{"邮箱 a.b@example.com", "a.b@example.com", "正则"},
		{"统一代码 91110108MA01ABCD71", "91110108MA01ABCD71", "GB 32100"},
		{"Codice Fiscale MRTMTT25D09F205Z", "MRTMTT25D09F205Z", "CIN 校验"},
		{"Steuer-ID 86095742719", "86095742719", "ISO 7064 + 结构规则"},
		{"密钥 sk-abcdefghij1234567890", "sk-abcdefghij1234567890", "正则"},
		{"请联系张伟", "张伟", "静态名册"},
		{"经办人欧阳志远已签字", "欧阳志远", "复姓表 + AC 自动机"},
		{"请联系周慧敏确认", "周慧敏", "需要 NER"},
		{"寄往上海市浦东新区世纪大道100号", "上海市浦东新区世纪大道100号", "需要 NER"},
		{"供应商是临安远景机械制造有限公司", "临安远景机械制造有限公司", "需要 NER"},
		{"Contact Margaret Okonkwo", "Margaret Okonkwo", "需要 NER（英文模型）"},
	}

	core, advanced := 0, 0
	for _, c := range cases {
		found, err := d.Detect(c.text)
		if err != nil {
			t.Fatal(err)
		}
		hit := false
		for _, e := range found {
			if e.Value == c.want {
				hit = true
			}
		}
		mark := "✗ 需要 Advanced"
		if hit {
			mark = "✓ Core"
			core++
		} else {
			advanced++
		}
		t.Logf("  %-10s %-28q %s", mark, c.want, c.note)
	}
	t.Logf("\nCore 覆盖 %d/%d，其余 %d 项需要 Advanced 模式",
		core, len(cases), advanced)
}

var _ = fmt.Sprintf
var _ = strings.TrimSpace
