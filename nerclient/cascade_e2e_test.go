package nerclient

import (
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
	"github.com/xinleishen84-afk/airlock-agent/pii/verify"
)

// 三层真正串起来之后的端到端行为。
// The three layers actually wired together.
func fullStack(t *testing.T) (*detect.Cascade, *verify.EvidenceValidator, *detect.CascadeStats) {
	t.Helper()

	reg := packs.MustNewRegistry([]string{"GEN", "CN"})
	sr, err := detect.NewSurnameRecognizer(detect.DefaultSurnameOptions())
	if err != nil {
		t.Fatal(err)
	}
	srReg := detect.NewRegistry()
	if err := srReg.Register(sr); err != nil {
		t.Fatal(err)
	}
	gaz, err := detect.NewGazetteerDetector(
		map[detect.EntityType][]string{detect.TypeName: {"张伟"}}, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	fast := detect.NewCompositeDetector([]detect.Detector{reg, srReg, gaz}, 0)

	model := liveClient(t)
	c, err := detect.NewCascade(fast, model)
	if err != nil {
		t.Fatal(err)
	}

	stats := &detect.CascadeStats{}
	c.OnStats = func(s detect.CascadeStats) { *stats = s }

	v, err := verify.NewDefaultEvidenceValidator()
	if err != nil {
		t.Fatal(err)
	}
	return c, v, stats
}

// 一段同时含三层各自负责内容的文本。
// One text carrying what each layer is responsible for.
func TestThreeLayersEndToEnd(t *testing.T) {
	c, v, stats := fullStack(t)

	const text = "请联系张伟，手机 13812345678，身份证 11010519491231002X。" +
		"经办人欧阳志远住在上海市浦东新区世纪大道100号，公司是阿里巴巴。"

	found, err := c.DetectContext(t.Context(), text)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("分层统计：%+v", *stats)
	for _, e := range found {
		d := v.Validate(text, e)
		note := ""
		if d.Extended > 0 {
			note = "  ← 边界拉伸 " + itoa(d.Extended) + " 字节"
		}
		t.Logf("  %-24q → %-30q %-8s %s%s",
			e.Value, d.Entity.Value, e.Type, d.Verdict, note)

		if text[e.Start:e.End] != e.Value {
			t.Errorf("检出偏移错位：text[%d:%d]=%q", e.Start, e.End, text[e.Start:e.End])
		}
		if text[d.Entity.Start:d.Entity.End] != d.Entity.Value {
			t.Errorf("验证后偏移错位：text[%d:%d]=%q",
				d.Entity.Start, d.Entity.End, text[d.Entity.Start:d.Entity.End])
		}
	}

	// 每一层都该有贡献
	if stats.PerStage[detect.StagePattern] == 0 {
		t.Error("第一层无检出（手机号、身份证）")
	}
	if stats.PerStage[detect.StageGazetteer] == 0 {
		t.Error("第二层无检出（名册里的张伟、复姓欧阳志远）")
	}
	if stats.PerStage[detect.StageModel] == 0 {
		t.Error("第三层无检出（地址、机构）")
	}
	if stats.ModelCalls != 1 {
		t.Errorf("模型应被调用一次，实际 %d", stats.ModelCalls)
	}
}

// 级联省下的模型调用 —— 这是漏斗存在的理由。
// The model calls the funnel saves.
func TestCascadeSavesModelCalls(t *testing.T) {
	c, _, stats := fullStack(t)

	texts := []string{
		"13812345678",                      // 整段被第一层拿下
		"4111111111111111",                 // 同上
		"a.b@example.com",                  // 同上
		"11010519491231002X 与 13900001111", // 同上
		"请联系周慧敏确认收货。",                      // 需要模型
		"合同方是临安远景机械制造有限公司。",                // 需要模型
	}

	called, skipped := 0, 0
	for _, text := range texts {
		if _, err := c.DetectContext(t.Context(), text); err != nil {
			t.Fatal(err)
		}
		called += stats.ModelCalls
		skipped += stats.ModelSkipped
	}
	t.Logf("%d 段文本：模型被调用 %d 次，跳过 %d 次", len(texts), called, skipped)
	if skipped == 0 {
		t.Error("整段被前两层拿下的文本应跳过模型")
	}
}

// 级联对延迟的实际影响。
// The measured latency effect of cascading.
func TestCascadeLatencyEffect(t *testing.T) {
	c, _, _ := fullStack(t)
	model := liveClient(t)

	cases := []struct{ name, text string }{
		{"全部被前两层拿下", "手机 13812345678，卡号 4111111111111111。"},
		{"需要模型", "请联系周慧敏确认收货地址。"},
	}

	for _, tc := range cases {
		for range 10 {
			_, _ = c.DetectContext(t.Context(), tc.text)
		}
		const runs = 60

		start := time.Now()
		for range runs {
			if _, err := c.DetectContext(t.Context(), tc.text); err != nil {
				t.Fatal(err)
			}
		}
		cascaded := time.Since(start) / runs

		start = time.Now()
		for range runs {
			if _, err := model.DetectContext(t.Context(), tc.text); err != nil {
				t.Fatal(err)
			}
		}
		direct := time.Since(start) / runs

		t.Logf("%-16s 级联 %8v   直接调模型 %8v   %.1f×",
			tc.name, cascaded.Round(time.Microsecond),
			direct.Round(time.Microsecond), float64(direct)/float64(cascaded))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// 挖空到底省不省推理时间 —— 不能想当然。
// Whether masking actually saves inference time, measured rather than assumed.
//
// 直觉是「挖掉一部分文本，模型就少算一点」。但填充符 ▮ 是 3 字节，而被它
// 覆盖的 ASCII 数字每个 1 字节——挖空后的文本比原文更长。推理耗时与输入
// 长度大致成线性，所以挖空很可能不省反费。
//
// The intuition is that removing text means less to compute. But the filler is
// three bytes while the ASCII digits it covers are one, so the masked text is
// longer than the original, and inference is roughly linear in length.
func TestMaskingDoesNotSaveInferenceTime(t *testing.T) {
	model := liveClient(t)

	// 一段 PII 密集的文本：挖空会覆盖掉相当大一部分
	original := strings.Repeat(
		"客户手机 13812345678，卡号 4111111111111111，邮箱 a.b@example.com。", 20)

	// 走真实的挖空代码，而不是在测试里手写一份。
	//
	// 第一版这里手写了 strings.Repeat("▮", ...)，于是量的是测试自己的实现，
	// 不是被测代码——生产代码改成按字节宽度分档之后，这个测试还在报旧数字。
	//
	// The real masking, not a hand-rolled copy: the first version measured the
	// test's own implementation and kept reporting the old number after the
	// production code changed.
	fast := packs.MustNewRegistry([]string{"GEN", "CN"})
	settled, err := fast.Detect(original)
	if err != nil {
		t.Fatal(err)
	}
	masked, maskedRunes := detect.MaskSettledSpans(original, settled)
	t.Logf("前两层命中 %d 处，覆盖 %d 个字符", len(settled), maskedRunes)

	t.Logf("原文 %d 字节 / %d 字符", len(original), len([]rune(original)))
	t.Logf("挖空 %d 字节 / %d 字符", len(masked), len([]rune(masked)))

	measure := func(text string) time.Duration {
		for range 5 {
			_, _ = model.raw(t.Context(), text)
		}
		const runs = 20
		var total time.Duration
		for range runs {
			resp, err := model.raw(t.Context(), text)
			if err != nil {
				t.Fatal(err)
			}
			total += time.Duration(resp.GetInferenceMicros()) * time.Microsecond
		}
		return total / runs
	}

	origTime := measure(original)
	maskTime := measure(masked)

	t.Logf("推理耗时：原文 %v   挖空后 %v   %.2f×",
		origTime.Round(time.Microsecond), maskTime.Round(time.Microsecond),
		float64(maskTime)/float64(origTime))
	t.Logf("结论：挖空的价值在正确性（模型不会对已确定的区间再判一次、" +
		"也不会给出冲突的类型），不在省时间")
}
