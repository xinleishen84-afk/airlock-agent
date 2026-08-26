package detect

import (
	"fmt"
	"runtime"
	"sync"
)

// # Scanning a long document
// # 扫描长文档
//
// A registry runs every recognizer over the whole input, so the cost is the
// number of recognizers times the document size. That is fine for a 2KB prompt
// and it is not fine for a 128k-token one: twenty-two full passes over 384KB is
// eight megabytes of scanning for a document that usually contains a handful of
// identifiers, or none.
// 注册中心让每个识别器扫一遍完整输入，因此代价是「识别器数量 × 文档大小」。
// 对 2KB 的提示词这没问题，对 128k token 的就有问题了：
// 二十二遍扫过 384KB，等于为一份通常只含少数几个标识、甚至一个都没有的文档
// 扫描了八兆字节。
//
// # What did not work
// # 试过但不成立的做法
//
// The first attempt was a gate: compile the union of every recognizer's regex
// and skip any chunk the union does not match. It is sound — each recognizer's
// pattern is one of the union's alternatives, so a chunk the union misses
// cannot contain a match — and it was measured to be slower than no gate at
// all. RE2 simulates an alternation of twenty-two non-trivial patterns as one
// large automaton, and that automaton costs more per byte than running the
// twenty-two smaller ones in sequence.
// 第一次尝试是做门控：把所有识别器正则编译成并集，
// 并集不命中的分块整块跳过。这个做法是成立的——每个识别器的模式
// 都是并集的一个分支，并集扫不到的分块里不可能有匹配——
// 但实测比不加门控还慢。RE2 把二十二个非平凡模式的并集模拟成一个大自动机，
// 而这个自动机每字节的代价高过依次跑那二十二个小的。
//
// 记在这里，是因为「合并成一个正则」听上去总是像个优化。
// Recorded here because "combine them into one regex" always sounds like an
// optimization.
//
// # What does work
// # 成立的做法
//
// Chunks are independent, so they are scanned in parallel. This is the one
// axis with real headroom: the per-byte cost is what it is, and the only way to
// move a 384KB document faster is to use more than one core on it. Latency for
// a single long document drops by roughly the core count, which is what the
// tail-latency target actually needs.
// 分块之间彼此独立，因此并行扫描。这是唯一还有真实余量的维度：
// 每字节的代价就是那么多，而让一份 384KB 文档走得更快的唯一办法，
// 是在它身上用不止一个核。单份长文档的延迟大致按核数下降——
// 这正是尾延迟目标真正需要的东西。
//
// # Chunk boundaries
// # 分块边界
//
// An identifier can straddle a boundary. Chunks therefore overlap by a margin
// wider than the longest thing any recognizer can match, and entities found
// twice in the overlap are deduplicated by absolute offset. Without the margin
// the scanner would lose exactly the identifiers that happen to land on a
// boundary — a failure whose rate depends on chunk size and which no test that
// uses short inputs would ever see.
// 一个标识可能跨在边界上。因此分块之间重叠一段比「任何识别器可能匹配到的
// 最长内容」还宽的余量，并按绝对偏移对重叠区里被找到两次的实体去重。
// 没有这段余量，扫描器会恰好丢掉那些落在边界上的标识——
// 一种发生率取决于分块大小、而且任何用短输入的测试都永远看不到的故障。
type ChunkedScanner struct {
	registry *Registry

	chunkSize int
	margin    int
	// workers bounds the parallelism. Zero means GOMAXPROCS.
	// 限制并行度。0 表示使用 GOMAXPROCS。
	workers int
}

// DefaultChunkSize is the scanning window.
// 是扫描窗口大小。
//
// Large enough that the per-chunk overhead is negligible, small enough that a
// single identifier-bearing region does not force a full-cost scan of the whole
// document.
// 大到让每块的固定开销可以忽略，小到不会因为一处含标识的区域
// 就让整份文档按满代价扫描。
const DefaultChunkSize = 16 << 10

// DefaultMargin is the overlap between chunks.
// 是分块之间的重叠余量。
//
// Wider than the longest match any built-in recognizer can produce. A grouped
// card number with separators is the longest at 24 bytes; a generous margin
// costs a little duplicate scanning and buys immunity to the boundary case.
// 比任何内置识别器可能产生的最长匹配都宽。带分隔符的分组卡号最长 24 字节；
// 余量给得宽裕一点，代价是少量重复扫描，换来的是对边界情形免疫。
const DefaultMargin = 512

// NewChunkedScanner builds a gated scanner over a registry.
// 基于注册中心构造带门控的扫描器。
func NewChunkedScanner(reg *Registry, chunkSize, margin, workers int) (*ChunkedScanner, error) {
	if reg == nil {
		return nil, fmt.Errorf("扫描器需要注册中心 / scanner requires a registry")
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if margin <= 0 {
		margin = DefaultMargin
	}
	if margin >= chunkSize {
		return nil, fmt.Errorf(
			"重叠余量 %d 不得大于等于分块大小 %d / margin must be smaller than chunk size",
			margin, chunkSize)
	}

	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	return &ChunkedScanner{
		registry: reg, chunkSize: chunkSize, margin: margin, workers: workers,
	}, nil
}

// Name implements Detector.
func (s *ChunkedScanner) Name() string { return "chunked-scanner" }

// CoveredTypes implements Detector.
func (s *ChunkedScanner) CoveredTypes() []EntityType { return s.registry.CoveredTypes() }

// Detect implements Detector.
func (s *ChunkedScanner) Detect(text string) ([]Entity, error) {
	// 短文档直接走原路径：分块与调度的固定开销大于它能省下的
	// Short documents take the direct path: chunking and scheduling cost more
	// than they save.
	if len(text) <= s.chunkSize {
		return s.registry.Detect(text)
	}

	bounds := s.chunks(text)
	results := make([][]Entity, len(bounds))
	errs := make([]error, len(bounds))

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.workers)
	for i, b := range bounds {
		wg.Add(1)
		go func(i int, b [2]int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ents, err := s.registry.Detect(text[b[0]:b[1]])
			if err != nil {
				errs[i] = err
				return
			}
			// 偏移换算回全文绝对位置：分块内的偏移对调用方毫无意义，
			// 而一个忘了换算的实现会脱敏错的字节，且短输入的测试永远看不到。
			// Offsets are translated back to absolute: a chunk-relative offset
			// is meaningless to the caller, and an implementation that forgets
			// redacts the wrong bytes.
			for j := range ents {
				ents[j].Start += b[0]
				ents[j].End += b[0]
			}
			results[i] = ents
		}(i, b)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	var found []Entity
	seen := make(map[entityKey]bool)
	for _, ents := range results {
		for _, e := range ents {
			key := entityKey{start: e.Start, end: e.End, typ: e.Type, detector: e.Detector}
			if seen[key] {
				continue
			}
			seen[key] = true
			found = append(found, e)
		}
	}

	// 分块内部各自消解过重叠，但跨块没有——重叠区里同一处文本可能被两个
	// 分块以不同方式消解。这里再消解一次。
	// Overlaps were resolved inside each chunk but not across them.
	return ResolveOverlaps(found), nil
}

// chunks returns the byte ranges to scan, overlapping by the margin.
// 返回要扫描的字节区间，彼此重叠一段余量。
func (s *ChunkedScanner) chunks(text string) [][2]int {
	var out [][2]int
	for start := 0; start < len(text); start += s.chunkSize {
		end := start + s.chunkSize + s.margin
		if end > len(text) {
			end = len(text)
		}
		// 分块边界必须落在字符边界上，否则会把一个多字节字符切开，
		// 让正则在两半上都匹配不到本该匹配的东西。
		// Chunk edges must fall on rune boundaries.
		a, b := alignLeft(text, start), alignLeft(text, end)
		if a < b {
			out = append(out, [2]int{a, b})
		}
	}
	return out
}

// entityKey identifies one detection for deduplication.
// 标识一次检出，用于去重。
type entityKey struct {
	start, end int
	typ        EntityType
	detector   string
}

// alignLeft moves an offset back to the nearest rune boundary.
// 把偏移左移到最近的字符边界。
func alignLeft(s string, i int) int {
	if i >= len(s) {
		return len(s)
	}
	for i > 0 && !utf8Start(s[i]) {
		i--
	}
	return i
}
