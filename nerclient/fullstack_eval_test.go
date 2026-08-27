package nerclient

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/eval"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
	"github.com/xinleishen84-afk/airlock-agent/pii/verify"
)

// # 完整栈评测
// # Full-stack evaluation
//
// 前几轮评测里，Go 侧与 Python 侧是分开量的：Go 侧对姓名/地址/机构是 40%，
// Python NER 单独是 82.8%。两个数字都不代表接起来之后是什么样——
// 级联会挡掉一部分调用，证据链会否决一部分判定，边界拉伸会改一部分结果。
//
// Earlier rounds measured the two sides separately: 40% on the Go side, 82.8%
// for the Python NER alone. Neither predicts the wired-up behaviour: the
// cascade withholds some calls, the evidence chain rejects some verdicts, and
// boundary expansion rewrites some spans.

type stackConfig struct {
	name     string
	roster   bool
	surnames bool
	model    bool
	evidence bool
}

func buildStack(t *testing.T, cfg stackConfig) (detect.Detector, *verify.EvidenceValidator, *detect.CascadeStats) {
	t.Helper()

	detectors := []detect.Detector{packs.MustNewRegistry([]string{"GEN", "CN", "US", "IT", "DE", "ES"})}
	if cfg.roster {
		gaz, err := detect.NewGazetteerDetector(
			map[detect.EntityType][]string{detect.TypeName: {"周慧敏"}}, false, 2)
		if err != nil {
			t.Fatal(err)
		}
		detectors = append(detectors, gaz)
	}
	if cfg.surnames {
		sr, err := detect.NewSurnameRecognizer(detect.DefaultSurnameOptions())
		if err != nil {
			t.Fatal(err)
		}
		reg := detect.NewRegistry()
		if err := reg.Register(sr); err != nil {
			t.Fatal(err)
		}
		detectors = append(detectors, reg)
	}
	fast := detect.NewCompositeDetector(detectors, 0)

	stats := &detect.CascadeStats{}
	var d detect.Detector = fast
	if cfg.model {
		c, err := detect.NewCascade(fast, liveClient(t))
		if err != nil {
			t.Fatal(err)
		}
		// 不设语言闸：服务端已按文字系统路由，中文段走中文模型、
		// 拉丁段走英文模型。此时再设闸，会把拉丁文整段挡在门外——
		// 而那正是刚刚接上模型的那一类。
		//
		// No script gate: the server now routes by script. A gate here would
		// block Latin text entirely — the very class that just got a model.
		c.OnStats = func(s detect.CascadeStats) {
			stats.ModelCalls += s.ModelCalls
			stats.ModelSkipped += s.ModelSkipped
			stats.ModelDiscarded += s.ModelDiscarded
		}
		d = c
	}

	var v *verify.EvidenceValidator
	if cfg.evidence {
		var err error
		if v, err = verify.NewDefaultEvidenceValidator(); err != nil {
			t.Fatal(err)
		}
	}
	return d, v, stats
}

func runStack(t *testing.T, d detect.Detector, v *verify.EvidenceValidator, text string) []detect.Entity {
	t.Helper()
	found, err := d.Detect(text)
	if err != nil {
		t.Fatalf("检测失败 %q: %v", truncate(text, 20), err)
	}
	if v == nil {
		return found
	}
	out := make([]detect.Entity, 0, len(found))
	for _, dec := range v.ValidateAll(text, found) {
		out = append(out, dec.Entity)
	}
	return out
}

// score 逐 span 打分：位置与类型都要对。
func score(t *testing.T, d detect.Detector, v *verify.EvidenceValidator,
	samples []eval.Sample) (hit, miss, spurious, partial int, missed, extra []string) {
	t.Helper()

	for _, s := range samples {
		found := runStack(t, d, v, s.Text)
		usedPred := make([]bool, len(found))
		usedGold := make([]bool, len(s.Gold))

		for gi, g := range s.Gold {
			for pi, p := range found {
				if usedPred[pi] || usedGold[gi] {
					continue
				}
				if p.Start == g.Start && p.End == g.End && p.Type == g.Type {
					usedGold[gi], usedPred[pi] = true, true
					hit++
				}
			}
		}
		// 重叠但边界不符：单独计，因为它既不是干净的命中也不是干净的漏
		for gi, g := range s.Gold {
			if usedGold[gi] {
				continue
			}
			for pi, p := range found {
				if usedPred[pi] {
					continue
				}
				if p.Start < g.End && g.Start < p.End {
					usedGold[gi], usedPred[pi] = true, true
					partial++
					missed = append(missed, "~"+s.Text[g.Start:g.End]+"→"+p.Value)
				}
			}
		}
		for gi, used := range usedGold {
			if !used {
				miss++
				missed = append(missed, s.Text[s.Gold[gi].Start:s.Gold[gi].End])
			}
		}
		for pi, used := range usedPred {
			if !used {
				spurious++
				extra = append(extra, found[pi].Value+"/"+string(found[pi].Type))
			}
		}
	}
	return
}

// 姓名/地址/机构：从 0% 到接起来之后的多少。
// The class that was 0%, measured with everything wired.
func TestFullStackRecall(t *testing.T) {
	configs := []stackConfig{
		{name: "① 正则+校验位"},
		{name: "② +名册", roster: true},
		{name: "③ +复姓", roster: true, surnames: true},
		{name: "④ +NER（三层级联）", roster: true, surnames: true, model: true},
		{name: "⑤ +证据链", roster: true, surnames: true, model: true, evidence: true},
	}

	samples := eval.UnknownNames()
	total := 0
	for _, s := range samples {
		total += len(s.Gold)
	}

	for _, cfg := range configs {
		d, v, _ := buildStack(t, cfg)
		hit, miss, spur, partial, missed, _ := score(t, d, v, samples)
		t.Logf("%-20s 命中 %d/%d = %5.1f%%  边界不符 %d  漏 %d  多报 %d",
			cfg.name, hit, total, float64(hit)/float64(total)*100, partial, miss, spur)
		if len(missed) > 0 {
			t.Logf("%-20s   未精确命中：%v", "", missed)
		}
	}
}

// 对抗性反例上的误报 —— 收益必须和代价一起报。
// False positives on adversarial negatives.
func TestFullStackPrecision(t *testing.T) {
	configs := []stackConfig{
		{name: "① 正则+校验位"},
		{name: "④ +NER（三层级联）", roster: true, surnames: true, model: true},
		{name: "⑤ +证据链", roster: true, surnames: true, model: true, evidence: true},
	}

	negatives := eval.Negatives()
	for _, cfg := range configs {
		d, v, stats := buildStack(t, cfg)
		_, _, spur, _, _, extra := score(t, d, v, negatives)
		if len(extra) > 6 {
			extra = extra[:6]
		}
		t.Logf("%-20s 反例 %d 篇  误报 %d 处  例：%v",
			cfg.name, len(negatives), spur, extra)
		if cfg.model {
			t.Logf("%-20s   模型调用 %d 次，跳过 %d 次，丢弃重叠判定 %d 条",
				"", stats.ModelCalls, stats.ModelSkipped, stats.ModelDiscarded)
		}
	}
}

// 结构化标识不能因为加了后两层而退化。
// The structured identifiers must not regress from the added layers.
func TestFullStackDoesNotRegressStructured(t *testing.T) {
	d, v, _ := buildStack(t, stackConfig{roster: true, surnames: true, model: true, evidence: true})

	samples := eval.Positives()
	total := 0
	for _, s := range samples {
		total += len(s.Gold)
	}
	hit, miss, spur, partial, missed, extra := score(t, d, v, samples)

	t.Logf("结构化正例：命中 %d/%d = %.1f%%  边界不符 %d  漏 %d  多报 %d",
		hit, total, float64(hit)/float64(total)*100, partial, miss, spur)
	if len(missed) > 0 {
		t.Logf("  未精确命中：%v", missed)
	}
	if len(extra) > 0 {
		// 多报与漏检不是一回事，代价方向相反：
		//   漏检 = 该脱敏的没脱 = 泄露，不可接受
		//   多报 = 不该脱的脱了 = 效用损失，可接受但要看得见
		//
		// 这里的多报全部来自第三层对非英语拉丁文的判定（德语 Steuer、
		// 西班牙语 registrado），以及一个语料没标注但确实是机构的
		// WhatsApp。它们是按文字系统路由的固有代价：拉丁文≠英文，
		// 而德语、西班牙语送进英文模型同样是分布外。
		//
		// 真正的解法是按语言而非按文字系统路由——契约里的 language 字段
		// 支持这件事，缺的是一个语言识别器和对应语种的模型。
		//
		// Over-redaction and under-redaction are not the same failure:
		// a miss is a leak, an extra is a utility loss. These extras come from
		// the third layer judging non-English Latin text (German Steuer,
		// Spanish registrado), which is the inherent cost of routing by script:
		// Latin is not English. Routing by actual language is what the
		// contract's language field is for; what is missing is a language
		// identifier and models for those languages.
		t.Logf("  多报（过度脱敏，非泄露）：%v", extra)
	}
	if hit < total {
		t.Errorf("加了第二、三层之后结构化标识出现漏检——" +
			"前两层的结论不该被后面的层改动。漏检是泄露，与多报不同")
	}
}

// 完整栈的端到端延迟分位。
// End-to-end latency percentiles for the full stack.
func TestFullStackLatency(t *testing.T) {
	d, v, stats := buildStack(t, stackConfig{roster: true, surnames: true, model: true, evidence: true})

	cases := []struct{ name, text string }{
		{"纯结构化（无散文）", "13812345678 4111111111111111 a.b@example.com"},
		{"典型提示词", "请联系张伟，手机 13812345678，住上海市浦东新区世纪大道100号。"},
		{"无 PII 散文", "本季度产品迭代包括搜索排序优化、批量导出与看板加载性能改进。"},
	}

	for _, tc := range cases {
		for range 10 {
			_ = runStack(t, d, v, tc.text)
		}
		before := *stats

		const runs = 100
		samples := make([]time.Duration, 0, runs)
		for range runs {
			start := time.Now()
			_ = runStack(t, d, v, tc.text)
			samples = append(samples, time.Since(start))
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })

		calls := stats.ModelCalls - before.ModelCalls
		t.Logf("%-16s P50 %8v  P99 %8v   %d/%d 次调用了模型",
			tc.name, samples[runs/2].Round(time.Microsecond),
			samples[runs*99/100].Round(time.Microsecond), calls, runs)
	}
}

var _ = strings.TrimSpace
