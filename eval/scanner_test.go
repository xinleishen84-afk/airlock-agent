package eval

import (
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
)

func scannerAndRegistry(t testing.TB) (*detect.ChunkedScanner, *detect.Registry) {
	t.Helper()
	reg := packs.MustNewRegistry([]string{"GEN", "CN", "US", "IT", "DE", "ES"})
	sc, err := detect.NewChunkedScanner(reg, detect.DefaultChunkSize, detect.DefaultMargin, 0)
	if err != nil {
		t.Fatal(err)
	}
	return sc, reg
}

// 分块扫描的结果必须与全量扫描逐字相同。
// Chunked results must be byte-identical to a full scan.
//
// 一个会静默丢匹配的扫描器，比慢的扫描器糟糕得多：慢是看得见的，
// 丢是看不见的。
// A scanner that quietly loses matches is far worse than a slow one: slow is
// visible, lost is not.
func TestChunkedMatchesFullScan(t *testing.T) {
	sc, reg := scannerAndRegistry(t)

	docs := map[string]string{
		"PII 密集":   buildPrompt(384 << 10),
		"PII 稀疏":   sparseWithPII(384 << 10),
		"无 PII":    sparseDoc(384 << 10),
		"刚过分块阈值":   buildPrompt(detect.DefaultChunkSize + 100),
		"恰好等于分块大小": buildPrompt(detect.DefaultChunkSize),
		"两倍分块":     buildPrompt(2 * detect.DefaultChunkSize),
	}
	for name, doc := range docs {
		want, err := reg.Detect(doc)
		if err != nil {
			t.Fatal(err)
		}
		got, err := sc.Detect(doc)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) {
			t.Errorf("%s：实体数不符 分块 %d vs 全量 %d", name, len(got), len(want))
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s：第 %d 项不符\n分块 %+v\n全量 %+v", name, i, got[i], want[i])
			}
		}
	}
	t.Logf("%d 种文档形态上，分块扫描与全量扫描输出逐字相同", len(docs))
}

// 边界情形：标识刚好跨在分块边界上。
// The boundary case: an identifier straddling a chunk edge.
//
// 没有重叠余量时，这类标识会被恰好丢掉——而发生率取决于分块大小，
// 任何用短输入的测试都永远看不到。
// Without the overlap margin these are lost, at a rate that depends on chunk
// size and that no short-input test would ever see.
func TestIdentifierStraddlingChunkBoundary(t *testing.T) {
	sc, reg := scannerAndRegistry(t)
	const pii = "13812345678"

	missed := 0
	// 把手机号逐字节挪过边界
	for offset := -20; offset <= 20; offset++ {
		pos := detect.DefaultChunkSize + offset
		if pos < 0 {
			continue
		}
		var b strings.Builder
		b.WriteString(strings.Repeat("填", pos/3))
		for b.Len() < pos {
			b.WriteByte('x')
		}
		b.WriteString("联系 " + pii + " 处理")
		b.WriteString(strings.Repeat("尾", 2000))
		doc := b.String()

		got, err := sc.Detect(doc)
		if err != nil {
			t.Fatal(err)
		}
		want, err := reg.Detect(doc)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) {
			missed++
			t.Errorf("偏移 %+d：分块 %d 个实体，全量 %d 个", offset, len(got), len(want))
		}
	}
	t.Logf("手机号跨边界的 41 个位置全部检出（漏检 %d）", missed)
}

// 并行分块的实际收益。
// The measured gain from parallel chunking.
func TestParallelScanGain(t *testing.T) {
	skipPerfUnderRace(t)
	sc, reg := scannerAndRegistry(t)

	for _, c := range []struct{ name, text string }{
		{"PII 密集", buildPrompt(384 << 10)},
		{"PII 稀疏（真实提示词形态）", sparseWithPII(384 << 10)},
		{"无 PII", sparseDoc(384 << 10)},
	} {
		const runs = 20
		start := time.Now()
		for range runs {
			if _, err := reg.Detect(c.text); err != nil {
				t.Fatal(err)
			}
		}
		full := time.Since(start) / runs

		start = time.Now()
		for range runs {
			if _, err := sc.Detect(c.text); err != nil {
				t.Fatal(err)
			}
		}
		chunked := time.Since(start) / runs

		mb := float64(len(c.text)) / (1 << 20)
		t.Logf("%-24s 全量 %8v (%5.1f MB/s)   并行分块 %8v (%6.1f MB/s)   提速 %.1f×",
			c.name, full.Round(time.Microsecond), mb/full.Seconds(),
			chunked.Round(time.Microsecond), mb/chunked.Seconds(),
			float64(full)/float64(chunked))
	}
}

func sparseDoc(size int) string {
	block := "本季度产品迭代包括：搜索排序优化、批量导出、以及看板加载性能改进。\n" +
		"```go\nfunc apply(x int) int { return x * 2 }\n```\n" +
		`{"feature":"export","enabled":true,"rollout":"gradual"}` + "\n\n"
	var b strings.Builder
	for b.Len() < size {
		b.WriteString(block)
	}
	return b.String()
}

func sparseWithPII(size int) string {
	doc := sparseDoc(size)
	cut := len(doc) * 95 / 100
	for cut > 0 && doc[cut]&0xC0 == 0x80 {
		cut--
	}
	return doc[:cut] +
		"\n联系人 手机 13812345678，邮箱 zhang.wei@example.com，身份证 11010519491231002X\n" +
		doc[cut:]
}
