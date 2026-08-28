package eval

import (
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
	"github.com/xinleishen84-afk/airlock-agent/pii/verify"
)

// # 完整流水线评测
// # Full-pipeline evaluation
//
// 上一轮评测里，姓名/地址/机构这三类的召回率是 0%。之后加了名册（Aho-Corasick）、
// 复姓识别与证据链验证。这一组量的是：那 0% 现在变成了多少，代价是什么。
//
// The previous round measured 0% recall for names, addresses and organizations.
// A roster, surname recognition and evidence-chain validation were added since.
// This measures what the 0% became, and what it cost.

// pipelineConfig 描述一种装配方式。
type pipelineConfig struct {
	name     string
	roster   map[detect.EntityType][]string
	surnames bool
	single   bool
	evidence bool
}

func buildPipeline(t testing.TB, cfg pipelineConfig) (detect.Detector, *verify.EvidenceValidator) {
	t.Helper()

	detectors := []detect.Detector{
		packs.MustNewRegistry([]string{"GEN", "CN", "US", "IT", "DE", "ES"}),
	}
	if len(cfg.roster) > 0 {
		gaz, err := detect.NewGazetteerDetector(cfg.roster, false, 2)
		if err != nil {
			t.Fatal(err)
		}
		detectors = append(detectors, gaz)
	}
	if cfg.surnames {
		opts := detect.DefaultSurnameOptions()
		opts.IncludeSingle = cfg.single
		sr, err := detect.NewSurnameRecognizer(opts)
		if err != nil {
			t.Fatal(err)
		}
		reg := detect.NewRegistry()
		if err := reg.Register(sr); err != nil {
			t.Fatal(err)
		}
		detectors = append(detectors, reg)
	}

	var v *verify.EvidenceValidator
	if cfg.evidence {
		var err error
		v, err = verify.NewDefaultEvidenceValidator()
		if err != nil {
			t.Fatal(err)
		}
	}
	return detect.NewCompositeDetector(detectors, 0), v
}

// runPipeline 跑检测 + 可选的证据链，返回最终留下的实体。
func runPipeline(t testing.TB, d detect.Detector, v *verify.EvidenceValidator,
	text string) []detect.Entity {
	t.Helper()

	found, err := d.Detect(text)
	if err != nil {
		t.Fatal(err)
	}
	if v == nil {
		return found
	}

	kept := make([]detect.Entity, 0, len(found))
	for _, d := range v.ValidateAll(text, found) {
		kept = append(kept, d.Entity)
	}
	return kept
}

// 那 0% 现在是多少 —— 分档报，因为不同装配的代价完全不同。
// What the 0% became, reported per configuration: the costs differ sharply.
func TestUnknownNameRecallAcrossConfigurations(t *testing.T) {
	// 名册里只放一个人，用来单独看名册这条路的效果
	roster := map[detect.EntityType][]string{
		detect.TypeName: {"周慧敏"},
	}

	configs := []pipelineConfig{
		{name: "① 仅正则+校验位（上一轮的基线）"},
		{name: "② + 名册（Aho-Corasick）", roster: roster},
		{name: "③ + 复姓识别", roster: roster, surnames: true},
		{name: "④ + 单姓识别", roster: roster, surnames: true, single: true},
		{name: "⑤ + 证据链验证", roster: roster, surnames: true, single: true, evidence: true},
	}

	samples := UnknownNames()
	for _, cfg := range configs {
		d, v := buildPipeline(t, cfg)

		hit, miss := 0, 0
		var missed []string
		for _, s := range samples {
			found := runPipeline(t, d, v, s.Text)
			for _, g := range s.Gold {
				gv := s.Text[g.Start:g.End]
				ok := false
				for _, e := range found {
					if e.Start == g.Start && e.End == g.End && e.Type == g.Type {
						ok = true
					}
				}
				if ok {
					hit++
				} else {
					miss++
					missed = append(missed, gv)
				}
			}
		}
		total := hit + miss
		t.Logf("%-28s 命中 %d/%d = %5.1f%%   漏 %v",
			cfg.name, hit, total, float64(hit)/float64(total)*100, missed)
	}
}

// 收益要和代价一起报：复姓与单姓识别会带来多少误报。
// Gains reported with costs: what the surname recognizers add in false
// positives.
func TestSurnameFalsePositiveCost(t *testing.T) {
	configs := []pipelineConfig{
		{name: "① 仅正则+校验位"},
		{name: "③ + 复姓识别", surnames: true},
		{name: "④ + 单姓识别", surnames: true, single: true},
		{name: "⑤ + 证据链验证", surnames: true, single: true, evidence: true},
	}

	// 对抗性反例：这些文本里一个 PII 都没有
	negatives := Negatives()
	// 再补一批「像人名但不是」的中文
	extra := []Sample{
		clean("prose_1", "散文", "王者荣耀的新赛季已经开启。"),
		clean("prose_2", "散文", "李子和杨梅都是夏季水果。"),
		clean("prose_3", "散文", "陈述事实比争辩更有力。"),
		clean("prose_4", "散文", "黄河与长江是中国的两条大河。"),
		clean("prose_5", "散文", "马上就到，请稍等。"),
		clean("prose_6", "散文", "方法论上讲这属于归纳。"),
		clean("prose_7", "散文", "石油价格本周下跌。"),
		clean("prose_8", "散文", "常见的白色噪音有助睡眠。"),
	}
	negatives = append(negatives, extra...)

	for _, cfg := range configs {
		d, v := buildPipeline(t, cfg)

		fp := 0
		var examples []string
		for _, s := range negatives {
			for _, e := range runPipeline(t, d, v, s.Text) {
				fp++
				if len(examples) < 6 {
					examples = append(examples, e.Value+"["+string(e.Type)+"/"+e.Detector+"]")
				}
			}
		}
		t.Logf("%-28s 反例 %d 篇，误报 %d 处   例：%v",
			cfg.name, len(negatives), fp, examples)
	}
}

// 名册的规模不该影响延迟 —— 这是换掉正则大并集的理由。
// Roster size must not affect latency.
func TestRosterScaleImpactOnPipeline(t *testing.T) {
	skipPerfUnderRace(t)
	text := buildPrompt(32 << 10)

	for _, size := range []int{0, 1000, 50000} {
		roster := map[detect.EntityType][]string{}
		if size > 0 {
			names := make([]string, 0, size)
			for i := range size {
				names = append(names, "员工"+itoa(i)+"号")
			}
			roster[detect.TypeName] = names
		}
		d, _ := buildPipeline(t, pipelineConfig{roster: roster, surnames: true})

		const runs = 30
		for range 3 {
			_, _ = d.Detect(text)
		}
		start := time.Now()
		for range runs {
			if _, err := d.Detect(text); err != nil {
				t.Fatal(err)
			}
		}
		elapsed := time.Since(start) / runs
		t.Logf("  名册 %6d 条  32KB 文档检测 %8v", size, elapsed.Round(time.Microsecond))
	}
}

// 证据链加在热路径上要花多少时间。
// What the evidence chain costs on the hot path.
func TestEvidenceChainOverhead(t *testing.T) {
	skipPerfUnderRace(t)
	text := buildPrompt(32 << 10)

	for _, cfg := range []pipelineConfig{
		{name: "无证据链", surnames: true, single: true},
		{name: "有证据链", surnames: true, single: true, evidence: true},
	} {
		d, v := buildPipeline(t, cfg)

		const runs = 30
		for range 3 {
			_ = runPipeline(t, d, v, text)
		}
		start := time.Now()
		var n int
		for range runs {
			n = len(runPipeline(t, d, v, text))
		}
		elapsed := time.Since(start) / runs
		t.Logf("  %-8s 32KB 文档 %8v   留下 %d 个实体", cfg.name, elapsed.Round(time.Microsecond), n)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "000000"
	}
	var b [6]byte
	for i := 5; i >= 0; i-- {
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[:])
}

var _ = strings.TrimSpace
