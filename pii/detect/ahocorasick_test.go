package detect

import (
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestAhoCorasickBasics(t *testing.T) {
	ac, err := NewAhoCorasick([]string{"张伟", "李娜", "星辰科技"})
	if err != nil {
		t.Fatal(err)
	}
	text := "请联系张伟或李娜，合同方是星辰科技。"
	got := ac.FindAll(text)

	if len(got) != 3 {
		t.Fatalf("应命中 3 处，实际 %d：%v", len(got), got)
	}
	for _, m := range got {
		if text[m.Start:m.End] != ac.Pattern(m.Pattern) {
			t.Errorf("偏移与模式不符：text[%d:%d]=%q，模式=%q",
				m.Start, m.End, text[m.Start:m.End], ac.Pattern(m.Pattern))
		}
	}
}

// 嵌套词条：短的不得被长的静默吞掉。
// A shorter term must not be silently swallowed by a longer one.
//
// 名册的语义是「凡在册的一律标记」。漏掉任何一条都违背它存在的理由，
// 而这种漏掉不会报错——它只是少了一个实体。
func TestNestedPatternsBothReported(t *testing.T) {
	ac, err := NewAhoCorasick([]string{"北京市海淀区", "海淀区", "北京"})
	if err != nil {
		t.Fatal(err)
	}
	got := ac.FindAll("寄往北京市海淀区中关村。")

	found := map[string]bool{}
	for _, m := range got {
		found[ac.Pattern(m.Pattern)] = true
	}
	for _, want := range []string{"北京市海淀区", "海淀区", "北京"} {
		if !found[want] {
			t.Errorf("嵌套词条 %q 未被报出：%v", want, found)
		}
	}
}

// 按字节匹配不得在 UTF-8 字符中间命中。
// A byte-level match must never begin mid-rune.
//
// 这是「按字节建 Trie」这个决定的正确性前提。UTF-8 的自同步性保证了它，
// 但保证是要被检验的：一旦这条不成立，脱敏切出来的就是半个汉字，
// 而载荷会变成非法 UTF-8。
//
// This is the correctness premise of a byte-keyed trie. UTF-8's
// self-synchronization guarantees it, but a guarantee has to be checked: if it
// failed, redaction would slice half a character and the payload would become
// invalid UTF-8.
func TestNoMatchStartsMidRune(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 7))

	// 用共享字节的 CJK 词条做对抗：CJK 统一表意文字都在 E4–E9 开头
	patterns := []string{"京", "北京", "东京", "南京", "京都", "北", "东"}
	ac, err := NewAhoCorasick(patterns)
	if err != nil {
		t.Fatal(err)
	}

	// 随机拼 CJK 文本
	pool := []rune("北东南西京都市区县村镇张王李赵刘陈杨黄周吴")
	for trial := range 2000 {
		n := 5 + rng.IntN(40)
		var b strings.Builder
		for range n {
			b.WriteRune(pool[rng.IntN(len(pool))])
		}
		text := b.String()

		for _, m := range ac.FindAll(text) {
			// 命中的起点与终点都必须是字符边界
			if !utf8Start(text[m.Start]) {
				t.Fatalf("trial %d：命中起点 %d 落在字符中间，文本 %q", trial, m.Start, text)
			}
			if m.End < len(text) && !utf8Start(text[m.End]) {
				t.Fatalf("trial %d：命中终点 %d 落在字符中间，文本 %q", trial, m.End, text)
			}
			// 且切出来的必须正好是模式
			if text[m.Start:m.End] != ac.Pattern(m.Pattern) {
				t.Fatalf("trial %d：切片 %q 不等于模式 %q",
					trial, text[m.Start:m.End], ac.Pattern(m.Pattern))
			}
		}
	}
	t.Log("2000 组随机 CJK 文本上，无一处命中落在字符中间")
}

// 与朴素扫描逐字对齐 —— 自动机不是「更快但不太一样」。
// Byte-identical to a naive scan: the automaton is not "faster but different".
func TestMatchesNaiveScan(t *testing.T) {
	rng := rand.New(rand.NewPCG(11, 13))
	pool := []rune("张王李赵北京上海科技有限公司abc")

	for trial := range 500 {
		// 随机词典
		nPat := 2 + rng.IntN(8)
		seen := map[string]bool{}
		var patterns []string
		for len(patterns) < nPat {
			l := 1 + rng.IntN(4)
			var b strings.Builder
			for range l {
				b.WriteRune(pool[rng.IntN(len(pool))])
			}
			if p := b.String(); !seen[p] {
				seen[p] = true
				patterns = append(patterns, p)
			}
		}

		var tb strings.Builder
		for range 5 + rng.IntN(30) {
			tb.WriteRune(pool[rng.IntN(len(pool))])
		}
		text := tb.String()

		ac, err := NewAhoCorasick(patterns)
		if err != nil {
			t.Fatal(err)
		}
		got := ac.FindAll(text)

		// 朴素：对每个模式逐位置 strings.Index
		type key struct{ s, e, p int }
		want := map[key]bool{}
		for pi, p := range patterns {
			for off := 0; ; {
				idx := strings.Index(text[off:], p)
				if idx < 0 {
					break
				}
				abs := off + idx
				want[key{abs, abs + len(p), pi}] = true
				off = abs + 1
			}
		}

		if len(got) != len(want) {
			t.Fatalf("trial %d：命中数不符 自动机 %d vs 朴素 %d\n词典 %v\n文本 %q",
				trial, len(got), len(want), patterns, text)
		}
		for _, m := range got {
			if !want[key{m.Start, m.End, m.Pattern}] {
				t.Fatalf("trial %d：自动机多报了 %+v", trial, m)
			}
		}
	}
	t.Log("500 组随机词典 × 随机文本上，自动机与朴素扫描结果完全一致")
}

func TestAhoCorasickRejections(t *testing.T) {
	if _, err := NewAhoCorasick(nil); err == nil {
		t.Error("空模式集应被拒绝")
	}
	if _, err := NewAhoCorasick([]string{"张伟", ""}); err == nil {
		t.Error("空串模式应被拒绝——它会在每个位置命中")
	}
	if _, err := NewAhoCorasick([]string{"张伟", "张伟"}); err == nil {
		t.Error("重复模式应被拒绝——多半说明主数据合并有问题")
	}
}

// 耗时必须与词典大小无关，这正是换掉正则大并集的理由。
// Cost must be independent of dictionary size — the reason for the change.
func TestScalesIndependentlyOfDictionarySize(t *testing.T) {
	text := strings.Repeat("客户张伟与李娜于北京签署合同，供应商为星辰科技有限公司。", 200)

	var prev time.Duration
	for _, size := range []int{100, 1000, 10000, 50000} {
		patterns := make([]string, 0, size)
		seen := map[string]bool{"张伟": true, "李娜": true, "星辰科技有限公司": true}
		patterns = append(patterns, "张伟", "李娜", "星辰科技有限公司")
		for i := 0; len(patterns) < size; i++ {
			p := fmt.Sprintf("员工%06d号", i)
			if !seen[p] {
				seen[p] = true
				patterns = append(patterns, p)
			}
		}

		ac, err := NewAhoCorasick(patterns)
		if err != nil {
			t.Fatal(err)
		}

		const runs = 20
		start := time.Now()
		var n int
		for range runs {
			n = len(ac.FindAll(text))
		}
		elapsed := time.Since(start) / runs

		t.Logf("  词典 %6d 条（%7d 节点）  扫描 %8v  命中 %d",
			size, ac.Size(), elapsed.Round(time.Microsecond), n)

		if prev > 0 && elapsed > prev*3 {
			t.Errorf("词典从上一档增大后耗时涨了 3 倍以上（%v → %v），"+
				"这说明扫描代价没有与词典大小解耦", prev, elapsed)
		}
		prev = elapsed
	}
}

// 与它取代的正则大并集正面对比，找出交叉点在哪。
// Head-to-head with the regex alternation it replaced, to locate the crossover.
//
// 报「快了多少倍」而不说规模是没有意义的：小词典上正则更快，
// 交叉点的位置才是选型依据。
// "N times faster" without a size is meaningless: the regex wins on small
// dictionaries, and where the crossover sits is what decides the choice.
func TestCrossoverAgainstRegexAlternation(t *testing.T) {
	text := strings.Repeat(
		"客户张伟与李娜于北京签署合同，供应商为星辰科技有限公司，"+
			"联系人手机 13812345678，发票寄往上海市浦东新区。", 60)

	t.Logf("文本 %d 字节", len(text))
	t.Logf("  %8s  %12s  %12s  %s", "词典", "正则大并集", "Aho-Corasick", "")

	for _, size := range []int{100, 1000, 5000, 20000, 100000} {
		patterns := buildRoster(size)

		re, err := compileAlternation(patterns)
		if err != nil {
			t.Logf("  %8d  %12s  —— 正则在这个规模上已经编译不了", size, "编译失败")
			continue
		}
		ac, err := NewAhoCorasick(patterns)
		if err != nil {
			t.Fatal(err)
		}

		const runs = 20
		start := time.Now()
		for range runs {
			_ = re.FindAllStringIndex(text, -1)
		}
		reTime := time.Since(start) / runs

		start = time.Now()
		for range runs {
			_ = ac.FindAll(text)
		}
		acTime := time.Since(start) / runs

		verdict := "自动机更快"
		ratio := float64(reTime) / float64(acTime)
		if ratio < 1 {
			verdict = "正则更快"
			ratio = 1 / ratio
		}
		t.Logf("  %8d  %12v  %12v  %s %.1f×",
			size, reTime.Round(time.Microsecond), acTime.Round(time.Microsecond),
			verdict, ratio)
	}
}

func buildRoster(size int) []string {
	patterns := []string{"张伟", "李娜", "星辰科技有限公司"}
	seen := map[string]bool{"张伟": true, "李娜": true, "星辰科技有限公司": true}
	for i := 0; len(patterns) < size; i++ {
		p := fmt.Sprintf("员工%06d号", i)
		if !seen[p] {
			seen[p] = true
			patterns = append(patterns, p)
		}
	}
	return patterns
}

func compileAlternation(patterns []string) (*regexp.Regexp, error) {
	quoted := make([]string, len(patterns))
	for i, p := range patterns {
		quoted[i] = regexp.QuoteMeta(p)
	}
	return regexp.Compile(strings.Join(quoted, "|"))
}

// 构建耗时与内存也要量：名册在启动时编译，十万条编译半分钟是不可接受的。
// Build cost matters too: the roster compiles at startup.
func TestBuildCost(t *testing.T) {
	for _, size := range []int{1000, 10000, 100000} {
		patterns := buildRoster(size)

		start := time.Now()
		ac, err := NewAhoCorasick(patterns)
		if err != nil {
			t.Fatal(err)
		}
		acBuild := time.Since(start)

		start = time.Now()
		_, reErr := compileAlternation(patterns)
		reBuild := time.Since(start)

		reNote := reBuild.Round(time.Millisecond).String()
		if reErr != nil {
			reNote = "编译失败"
		}
		t.Logf("  词典 %6d 条  自动机构建 %8v（%d 节点）  正则编译 %8v",
			size, acBuild.Round(time.Millisecond), ac.Size(), reNote)
	}
}
