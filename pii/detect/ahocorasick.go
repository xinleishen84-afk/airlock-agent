package detect

import (
	"fmt"
	"sort"
)

// # Aho-Corasick 多模式匹配
// # Aho-Corasick multi-pattern matching
//
// 名册匹配原本走的是「把所有词条拼成一个正则大并集」。它能工作，但代价随
// 词典大小增长：一万条员工姓名意味着一万个分支的 NFA，而 RE2 模拟它的每字节
// 成本是随状态数上升的。企业主数据动辄十万条，那条路走不到底。
//
// Roster matching used to be one big regex alternation. It works, but its cost
// grows with the dictionary: ten thousand employee names is a ten-thousand-way
// NFA, and RE2's per-byte cost rises with the state count. Enterprise master
// data runs to six figures, and that path does not get there.
//
// Aho-Corasick 把全部词条编进一棵带失败指针的 Trie，一遍扫描同时匹配所有模式，
// 时间是 O(文本长度 + 命中数)，**与词典大小无关**。
//
// Aho-Corasick compiles every term into a trie with failure links and matches
// all patterns in one pass: O(len(text) + matches), independent of dictionary
// size.
//
// # 为什么按字节而不按 rune
// # Why bytes rather than runes
//
// 按 rune 建 Trie 需要为每个节点维护一张稀疏的 rune→子节点映射，中文的 rune
// 取值范围极大，这张表要么退化成 map（每步一次哈希），要么占用巨量内存。
// 按字节则每个节点最多 256 个分支，可以用数组，一步一次索引。
//
// UTF-8 的自同步性让这件事是安全的：合法 UTF-8 里，任何非字符边界的位置
// 一定是延续字节（0x80–0xBF），而任何合法 UTF-8 模式的首字节要么是 ASCII
// （< 0x80）要么是前导字节（≥ 0xC0）——两者都不可能是延续字节。因此按字节
// 匹配**不可能**在字符中间命中。有一条用例用对抗性 CJK 输入钉住这一点。
//
// A rune-keyed trie needs a sparse rune→child map per node; the CJK range is
// huge, so that map degenerates into a hash lookup per step or eats enormous
// memory. Byte-keyed nodes have at most 256 children and index an array.
//
// UTF-8's self-synchronization makes this safe: in valid UTF-8, any position
// that is not a rune boundary is a continuation byte (0x80–0xBF), and the first
// byte of any valid UTF-8 pattern is either ASCII (< 0x80) or a lead byte
// (>= 0xC0). Neither can be a continuation byte, so a byte-level match cannot
// begin mid-rune. A test pins this with adversarial CJK input.

// acNode is one trie node.
// 是 Trie 的一个节点。
type acNode struct {
	// children 用 map 而非 [256]int32 数组。
	//
	// 中文词典的 Trie 极其稀疏：每个节点实际只有个位数的出边，而数组要为
	// 每个节点固定占 1KB。十万词条的 Trie 有几十万节点，数组版本要几百 MB，
	// map 版本几十 MB。这里换的是内存，不是时间——热路径上的每步查找
	// 仍然是一次哈希，而 Go 的小 map 查找足够快。
	//
	// A map rather than [256]int32: a Chinese dictionary trie is extremely
	// sparse — single-digit out-edges per node — while an array costs a fixed
	// 1KB per node. This trades memory, not asymptotic time.
	children map[byte]int32

	// fail 是失败指针：当前节点匹配不下去时跳到的最长真后缀节点。
	// The failure link: the longest proper suffix that is also a prefix.
	fail int32

	// output 是在本节点结束的模式下标，-1 表示没有。
	// Index of the pattern ending here, or -1.
	output int32

	// suffixLink 指向下一个「也在此处结束」的较短模式。
	//
	// 「北京市海淀区」与「海淀区」同时在词典里时，走到前者的终点也必须能
	// 报出后者。没有这条链，短模式会被长模式静默吞掉——而名册的用途恰恰
	// 是「凡在册的一律标记」，漏掉任何一条都违背它存在的理由。
	//
	// Points to the next shorter pattern also ending here. Without it a short
	// term is silently swallowed by a longer one — and a roster exists
	// precisely to guarantee that everything in it is flagged.
	suffixLink int32
}

// AhoCorasick is a compiled multi-pattern matcher.
// 是编译后的多模式匹配器。
type AhoCorasick struct {
	nodes    []acNode
	patterns []string

	// root 是根节点的稠密跳转表。
	//
	// 根节点是绝大多数字节的落点：任何不处在匹配中途的位置都要在这里查一次。
	// 用 map 做这一步，等于给文本的每个字节付一次哈希——实测在小词典上，
	// 这让自动机比它要取代的正则还慢（5831ns vs 2160ns）。
	// 稠密表把根节点的查找变成一次数组索引，代价是固定的 1KB。
	//
	// 只有根节点这样做：更深的节点稀疏且访问次数少几个数量级，
	// 给它们每个配 1KB 会让十万词条的自动机吃掉几百 MB。
	//
	// The root is where nearly every byte lands: any position not mid-match
	// looks up here. Using a map for that step costs one hash per byte of
	// text — measured, it made the automaton slower than the regex it
	// replaced. A dense table makes it one array index, for a fixed 1KB.
	// Only the root: deeper nodes are sparse and hit orders of magnitude less
	// often, and 1KB each would cost hundreds of MB at scale.
	root [256]int32
}

// ACMatch is one occurrence.
// 是一次命中。
type ACMatch struct {
	Start, End int
	// Pattern is the index into the pattern slice given at build time.
	// 是构建时传入的模式切片下标。
	Pattern int
}

// NewAhoCorasick compiles the patterns into an automaton.
// 把模式集编译成自动机。
//
// 重复模式会被拒绝而不是静默去重：名册通常由多份主数据合并而来，
// 重复往往说明合并逻辑有问题，而静默去重会让这个问题一直藏着。
//
// Duplicate patterns are rejected rather than silently deduplicated: a roster
// is usually merged from several master-data sources, and a duplicate usually
// means the merge is wrong.
func NewAhoCorasick(patterns []string) (*AhoCorasick, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("模式集不能为空 / no patterns given")
	}

	ac := &AhoCorasick{
		nodes:    make([]acNode, 1, len(patterns)*4),
		patterns: append([]string(nil), patterns...),
	}
	ac.nodes[0] = acNode{children: map[byte]int32{}, fail: 0, output: -1, suffixLink: -1}

	seen := make(map[string]int, len(patterns))
	for i, p := range patterns {
		if p == "" {
			return nil, fmt.Errorf("模式 %d 为空串——空模式会在每个位置命中 / empty pattern at %d", i, i)
		}
		if prev, dup := seen[p]; dup {
			return nil, fmt.Errorf("模式 %q 重复出现在下标 %d 与 %d / duplicate pattern", p, prev, i)
		}
		seen[p] = i
		ac.insert(p, int32(i))
	}

	ac.buildLinks()

	for b := range 256 {
		if child, ok := ac.nodes[0].children[byte(b)]; ok {
			ac.root[b] = child
		}
	}
	return ac, nil
}

// insert adds one pattern to the trie.
// 把一个模式插入 Trie。
func (ac *AhoCorasick) insert(pattern string, index int32) {
	cur := int32(0)
	for i := 0; i < len(pattern); i++ {
		b := pattern[i]
		next, ok := ac.nodes[cur].children[b]
		if !ok {
			ac.nodes = append(ac.nodes, acNode{
				children: map[byte]int32{}, fail: 0, output: -1, suffixLink: -1,
			})
			next = int32(len(ac.nodes) - 1)
			ac.nodes[cur].children[b] = next
		}
		cur = next
	}
	ac.nodes[cur].output = index
}

// buildLinks computes failure and suffix links by breadth-first traversal.
// 用广度优先遍历计算失败指针与后缀链。
func (ac *AhoCorasick) buildLinks() {
	queue := make([]int32, 0, len(ac.nodes))

	// 深度 1 的节点失败指针一律指向根
	for _, child := range ac.nodes[0].children {
		ac.nodes[child].fail = 0
		queue = append(queue, child)
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		for b, child := range ac.nodes[cur].children {
			// 沿失败链上溯，找到第一个有 b 出边的祖先
			f := ac.nodes[cur].fail
			for {
				if next, ok := ac.nodes[f].children[b]; ok {
					ac.nodes[child].fail = next
					break
				}
				if f == 0 {
					ac.nodes[child].fail = 0
					break
				}
				f = ac.nodes[f].fail
			}

			// 后缀链：失败指针处若本身是一个模式终点，就串上；
			// 否则继承它的后缀链。
			failNode := ac.nodes[child].fail
			if ac.nodes[failNode].output >= 0 {
				ac.nodes[child].suffixLink = failNode
			} else {
				ac.nodes[child].suffixLink = ac.nodes[failNode].suffixLink
			}

			queue = append(queue, child)
		}
	}
}

// FindAll returns every occurrence of every pattern, including overlaps.
// 返回所有模式的所有出现，含重叠。
//
// 不在这里做「最长优先」的取舍。名册的语义是「凡在册的一律标记」，
// 而哪个该赢是调用方的策略——ResolveOverlaps 已经承担了这件事，
// 在这里再做一次会让两处规则不一致，且只在词典含嵌套词条时显形。
//
// No longest-wins resolution here. A roster means "flag everything listed",
// and which one wins is the caller's policy — ResolveOverlaps already owns
// that, and duplicating it would let the two rules diverge, visibly only when
// the dictionary contains nested terms.
func (ac *AhoCorasick) FindAll(text string) []ACMatch {
	var out []ACMatch
	cur := int32(0)

	for i := 0; i < len(text); i++ {
		b := text[i]

		// 快路径：不处在匹配中途时直接查稠密根表。
		// 这是绝大多数字节走的分支。
		// Fast path for the overwhelming majority of bytes.
		if cur == 0 {
			cur = ac.root[b]
			if cur == 0 {
				continue
			}
		} else {
			for {
				if next, ok := ac.nodes[cur].children[b]; ok {
					cur = next
					break
				}
				if cur == 0 {
					cur = ac.root[b]
					break
				}
				cur = ac.nodes[cur].fail
			}
		}

		// 本节点及其后缀链上的每一个模式终点都是一次命中
		for n := cur; n >= 0; {
			if idx := ac.nodes[n].output; idx >= 0 {
				length := len(ac.patterns[idx])
				out = append(out, ACMatch{Start: i + 1 - length, End: i + 1, Pattern: int(idx)})
			}
			n = ac.nodes[n].suffixLink
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		return out[i].End < out[j].End
	})
	return out
}

// Pattern returns the pattern at an index.
// 返回下标处的模式。
func (ac *AhoCorasick) Pattern(i int) string { return ac.patterns[i] }

// Size reports the automaton's node count, for capacity planning.
// 报告自动机的节点数，供容量评估使用。
func (ac *AhoCorasick) Size() int { return len(ac.nodes) }
