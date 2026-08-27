package eval

import (
	"testing"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
)

// rosterDetector 是「正则 + 企业名册」的生产形态，不含 NER。
// The production shape without NER: regexes plus an enterprise roster.
func rosterDetector(t testing.TB) detect.Detector {
	t.Helper()
	gaz, err := detect.NewGazetteerDetector(map[detect.EntityType][]string{
		detect.TypeName: {"张伟", "李娜"},
		detect.TypeOrg:  {"星辰科技 有限公司"}, // 名册存注册全名，与语料标注一致
	}, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	reg := packs.MustNewRegistry([]string{"GEN", "CN", "US", "IT", "DE", "ES"})
	return detect.NewCompositeDetector([]detect.Detector{reg, gaz}, 0)
}

// 语料是量具，量任何东西之前先校准它。
// The corpus is a measuring instrument; calibrate before measuring.
func TestCorpusIsWellFormed(t *testing.T) {
	for _, set := range [][]Sample{Positives(), UnknownNames(), Negatives()} {
		if err := Validate(set); err != nil {
			t.Fatal(err)
		}
	}
	pos, neg := len(Positives()), len(Negatives())
	golds := 0
	for _, s := range Positives() {
		golds += len(s.Gold)
	}
	t.Logf("正例 %d 篇 / %d 处标注，反例 %d 篇，名册外样本 %d 篇",
		pos, golds, neg, len(UnknownNames()))
}

// 召回率：结构化标识 vs 无字面特征的实体，必须分开报。
// Recall, reported separately for structured identifiers and for the entity
// classes that have no lexical signature.
func TestRecall(t *testing.T) {
	d := rosterDetector(t)

	res, err := Score(d, Positives())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res.Report("召回率评估 —— 正例语料"))
	for _, m := range res.Misses {
		t.Logf("  ✗ %s", m)
	}
	t.Logf("总召回率 %.2f%%（目标 ≥ 99.5%%）", res.Recall()*100)

	unknown, err := Score(d, UnknownNames())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(unknown.Report("召回率评估 —— 名册外的姓名/地址/机构"))
	t.Logf("名册外召回率 %.2f%% —— 这一类没有字面特征，正则找不到，"+
		"不接 NER 模型时接近零", unknown.Recall()*100)
}

// 精确率：反例全部由对抗性文本构成，没有一条是为了通过而写的。
// Precision, measured against adversarial text: nothing here was written to
// pass.
func TestPrecision(t *testing.T) {
	d := rosterDetector(t)
	res, err := Score(d, Negatives())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res.Report("精确率评估 —— 对抗性反例语料"))
	for _, s := range res.Spurious {
		t.Logf("  ✗ %s", s)
	}
	total := 0
	for _, s := range Negatives() {
		total += len(s.Text)
	}
	t.Logf("反例共 %d 字节，误报 %d 处（目标：精确率 ≥ 98%%）",
		total, res.FalsePositives)
}

// 正例与反例合并后的整体精确率 —— 这才是生产语料的形态。
// Combined precision, which is the shape a production corpus actually has.
func TestCombinedPrecisionAndRecall(t *testing.T) {
	d := rosterDetector(t)
	all := append(append([]Sample{}, Positives()...), Negatives()...)
	res, err := Score(d, all)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res.Report("综合评估 —— 正例 + 对抗性反例"))
	t.Logf("召回 %.2f%%（目标 ≥ 99.5%%）  精确 %.2f%%（目标 ≥ 98%%）  F1 %.4f",
		res.Recall()*100, res.Precision()*100, res.F1())
}

// packsRegistry 返回全部国家包组成的注册中心。
func packsRegistry(t testing.TB) detect.Detector {
	t.Helper()
	return packs.MustNewRegistry([]string{"GEN", "CN", "US", "IT", "DE", "ES"})
}
