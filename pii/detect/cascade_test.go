package detect

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
)

// recordingModel 记录第三层实际收到了什么。
type recordingModel struct {
	seen     []string
	entities []Entity
	err      error
}

func (m *recordingModel) Name() string { return "ner:fake" }
func (m *recordingModel) CoveredTypes() []EntityType {
	return []EntityType{TypeName, TypeAddress, TypeOrg}
}
func (m *recordingModel) Detect(text string) ([]Entity, error) {
	m.seen = append(m.seen, text)
	if m.err != nil {
		return nil, m.err
	}
	return m.entities, nil
}

func fastLayers(t *testing.T) Detector {
	t.Helper()
	reg := newBaselineRegistry(t)
	gaz, err := NewGazetteerDetector(map[EntityType][]string{TypeName: {"张伟"}}, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	return NewCompositeDetector([]Detector{reg, gaz}, 0)
}

// 前两层命中的区间必须从第三层的输入里消失。
// Spans matched by the first two layers must vanish from the third's input.
func TestSettledSpansAreMaskedBeforeModel(t *testing.T) {
	model := &recordingModel{}
	c, err := NewCascade(fastLayers(t), model)
	if err != nil {
		t.Fatal(err)
	}
	c.MaskSettled = true // 挖空是可选的，默认走「重叠即丢弃」

	const text = "请联系张伟，手机 13812345678，邮箱 a.b@example.com。"
	if _, err := c.Detect(text); err != nil {
		t.Fatal(err)
	}

	if len(model.seen) != 1 {
		t.Fatalf("模型应被调用一次，实际 %d", len(model.seen))
	}
	got := model.seen[0]
	for _, settled := range []string{"13812345678", "a.b@example.com", "张伟"} {
		if strings.Contains(got, settled) {
			t.Errorf("已确定的 %q 仍出现在模型输入里：%q", settled, got)
		}
	}
	t.Logf("模型收到：%q", got)
}

// 挖空必须保持字符数不变 —— 偏移一一对应正是靠这一点。
// Masking must preserve the rune count: the offset correspondence rests on it.
func TestMaskingPreservesRuneCount(t *testing.T) {
	model := &recordingModel{}
	c, _ := NewCascade(fastLayers(t), model)
	c.MaskSettled = true

	texts := []string{
		"请联系张伟，手机 13812345678。",
		"卡号 4111111111111111 与身份证 11010519491231002X。",
		"混排 abc 13812345678 def 张伟 ghi。",
		"🙂张伟🙂13812345678🙂",
	}
	for _, text := range texts {
		model.seen = nil
		if _, err := c.Detect(text); err != nil {
			t.Fatal(err)
		}
		if len(model.seen) == 0 {
			continue
		}
		masked := model.seen[0]
		if a, b := utf8.RuneCountInString(text), utf8.RuneCountInString(masked); a != b {
			t.Errorf("字符数变了：原文 %d，挖空后 %d\n原文 %q\n挖空 %q", a, b, text, masked)
		}
		// 字节数同样必须不变。第一版统一用 3 字节的 ▮，字符数保住了、
		// 字节数没有，于是挖空后的输入凭空变长、推理慢了 2 倍。
		//
		// Byte length too: the first version used one three-byte filler for
		// every rune, inflating the input and doubling inference time.
		if len(text) != len(masked) {
			t.Errorf("字节数变了：原文 %d，挖空后 %d——"+
				"填充符必须与被覆盖的字符等宽\n原文 %q\n挖空 %q",
				len(text), len(masked), text, masked)
		}
	}
	t.Logf("%d 段文本挖空后字符数均不变", len(texts))
}

// 挖空必须保住上下文 —— 切段会让证据链失去依据。
// Masking must preserve context: splitting would strip the evidence chain.
func TestMaskingPreservesSurroundingContext(t *testing.T) {
	model := &recordingModel{}
	c, _ := NewCascade(fastLayers(t), model)
	c.MaskSettled = true

	const text = "请联系张伟，手机 13812345678，他是项目经理。"
	if _, err := c.Detect(text); err != nil {
		t.Fatal(err)
	}
	got := model.seen[0]

	// 「项目经理」是右侧证据，必须还在
	if !strings.Contains(got, "项目经理") {
		t.Errorf("右侧上下文丢失：%q", got)
	}
	if !strings.Contains(got, "请联系") {
		t.Errorf("左侧上下文丢失：%q", got)
	}
}

// 模型返回的偏移必须在原文上成立。
// Offsets from the model must hold in the original text.
func TestModelOffsetsMapBackToOriginal(t *testing.T) {
	const text = "请联系周慧敏，手机 13812345678。"
	// 模型在挖空后的文本上认出「周慧敏」，位置与原文相同
	start := strings.Index(text, "周慧敏")
	model := &recordingModel{entities: []Entity{{
		Type: TypeName, Value: "周慧敏", Start: start, End: start + len("周慧敏"),
		Confidence: 0.85, Detector: "ner:fake",
	}}}

	c, _ := NewCascade(fastLayers(t), model)
	got, err := c.Detect(text)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, e := range got {
		if e.Type == TypeName && e.Value == "周慧敏" {
			found = true
			if text[e.Start:e.End] != "周慧敏" {
				t.Errorf("偏移在原文上不成立：text[%d:%d]=%q", e.Start, e.End, text[e.Start:e.End])
			}
		}
	}
	if !found {
		t.Errorf("模型检出的实体未出现在结果里：%v", got)
	}
}

// 触发判据必须是必要条件 —— 只跳过结构上不可能含实体的文本。
// The trigger must be a necessary condition.
func TestNERTriggerOnlySkipsImpossibleText(t *testing.T) {
	skip := []string{"", " ", "1", "。", "  \n\t ", "123456", "!!!???", "＋－×÷"}
	send := []string{
		"张三",
		"ab",
		"func retry(n int) error", // 代码里也可能有人名，不能跳
		"// 联系人：张伟",               // 注释里的人名，最容易被忽略的泄露点
		"▮▮▮▮▮ 是项目经理",
		// 十六进制字面量含字母，因此会被送进模型。这是刻意的：判据只跳过
		// 「结构上不可能含实体」的文本，不做「看起来像代码就跳过」那种判断——
		// 那种判断会连注释里的人名一起跳掉。多花几毫秒可以接受，
		// 静默漏掉整段文本不行。
		//
		// A hex literal contains letters and is therefore sent: the trigger
		// never skips "things that look like code", which would skip names in
		// comments too.
		"0xFF 0x00", // 挖空后仍有上下文
	}

	for _, text := range skip {
		if ok, _ := DefaultNERTrigger(text); ok {
			t.Errorf("%q 结构上不可能含实体，不应送进模型", text)
		}
	}
	for _, text := range send {
		if ok, reason := DefaultNERTrigger(text); !ok {
			t.Errorf("%q 应送进模型，实际被跳过：%s", text, reason)
		}
	}
}

// 全部被前两层拿下时，模型不该被唤醒。
// The model must not wake when the first two layers took everything.
func TestModelSkippedWhenNothingRemains(t *testing.T) {
	model := &recordingModel{}
	c, _ := NewCascade(fastLayers(t), model)

	var stats CascadeStats
	c.OnStats = func(s CascadeStats) { stats = s }

	if _, err := c.Detect("13812345678"); err != nil {
		t.Fatal(err)
	}
	if len(model.seen) != 0 {
		t.Errorf("整段都被前两层拿下，模型不应被调用，实际收到 %q", model.seen)
	}
	if stats.ModelSkipped != 1 {
		t.Errorf("应记录一次跳过，实际 %+v", stats)
	}
	t.Logf("分层统计：%+v", stats)
}

// 分层计数是这套架构唯一能被检验的地方。
// Per-layer counts are the only place this architecture can be checked.
func TestStatsAttributeEachLayer(t *testing.T) {
	start := len("请联系")
	model := &recordingModel{entities: []Entity{{
		Type: TypeAddress, Value: "杭州", Start: 0, End: 6, Confidence: 0.8, Detector: "ner:fake",
	}}}
	_ = start

	c, _ := NewCascade(fastLayers(t), model)
	var stats CascadeStats
	c.OnStats = func(s CascadeStats) { stats = s }

	const text = "杭州的张伟，手机 13812345678。"
	if _, err := c.Detect(text); err != nil {
		t.Fatal(err)
	}

	if stats.PerStage[StagePattern] == 0 {
		t.Error("第一层应有检出（手机号）")
	}
	if stats.PerStage[StageGazetteer] == 0 {
		t.Error("第二层应有检出（名册里的张伟）")
	}
	if stats.PerStage[StageModel] == 0 {
		t.Error("第三层应有检出")
	}
	if stats.ModelCalls != 1 {
		t.Errorf("模型应被调用一次，实际 %d", stats.ModelCalls)
	}
	t.Logf("分层统计：%+v", stats)
}

// 第三层故障必须上抛，不能当作「没找到」。
// A third-layer failure must propagate, not read as "nothing found".
func TestModelFailurePropagates(t *testing.T) {
	model := &recordingModel{err: errModelDown{}}
	c, _ := NewCascade(fastLayers(t), model)

	if _, err := c.Detect("请联系周慧敏确认。"); err == nil {
		t.Fatal("模型故障应上抛——静默当作没找到会让这一类完全裸奔")
	}
}

type errModelDown struct{}

func (errModelDown) Error() string { return "模型不可用 / model unavailable" }

// 没有第三层时级联退化为前两层，而不是报错。
// Without a third layer the cascade degrades to the first two.
func TestCascadeWithoutModel(t *testing.T) {
	c, err := NewCascade(fastLayers(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Detect("手机 13812345678")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Error("前两层仍应工作")
	}
}

func TestCascadeRequiresFastLayer(t *testing.T) {
	if _, err := NewCascade(nil, &recordingModel{}); err == nil {
		t.Error("缺少前两层应被拒绝")
	}
}

var _ = context.Background

// 默认路径：模型看到原文，但与已确定区间重叠的判定被丢弃。
// The default path: the model sees the original, and verdicts overlapping a
// settled span are discarded.
//
// 这条路与挖空的正确性相同，代价却小得多——实测挖空会让 PII 密集文本的
// 推理慢 3.15 倍，因为一长串填充符对中文分词器是病态输入。
func TestOverlappingModelVerdictsAreDiscarded(t *testing.T) {
	const text = "请联系张伟，手机 13812345678。"
	phoneStart := strings.Index(text, "13812345678")

	// 模型对已确定的手机号给出一个冲突的判定
	model := &recordingModel{entities: []Entity{{
		Type: TypeName, Value: "13812345678",
		Start: phoneStart, End: phoneStart + len("13812345678"),
		Confidence: 0.9, Detector: "ner:fake",
	}}}

	c, _ := NewCascade(fastLayers(t), model)
	var stats CascadeStats
	c.OnStats = func(s CascadeStats) { stats = s }

	got, err := c.Detect(text)
	if err != nil {
		t.Fatal(err)
	}

	// 模型确实看到了原文
	if !strings.Contains(model.seen[0], "13812345678") {
		t.Error("默认路径下模型应看到原文")
	}
	// 但它的冲突判定被丢弃了
	if stats.ModelDiscarded != 1 {
		t.Errorf("应丢弃 1 条重叠判定，实际 %+v", stats)
	}
	for _, e := range got {
		if e.Start == phoneStart && e.Type == TypeName {
			t.Errorf("模型把已确定的手机号判成人名，不该留下：%+v", e)
		}
	}
	// 校验位给出的结论必须留下
	found := false
	for _, e := range got {
		if e.Type == TypePhone && e.Value == "13812345678" {
			found = true
		}
	}
	if !found {
		t.Errorf("校验位确定的手机号丢失了：%v", got)
	}
}

// 挖空与不挖空必须得到同样的最终结论。
// Masking and not masking must reach the same conclusion.
func TestMaskedAndUnmaskedAgree(t *testing.T) {
	const text = "请联系周慧敏，手机 13812345678，住上海市浦东新区。"
	nameStart := strings.Index(text, "周慧敏")
	modelEntity := Entity{
		Type: TypeName, Value: "周慧敏",
		Start: nameStart, End: nameStart + len("周慧敏"),
		Confidence: 0.85, Detector: "ner:fake",
	}

	results := map[bool][]Entity{}
	for _, mask := range []bool{false, true} {
		c, _ := NewCascade(fastLayers(t), &recordingModel{entities: []Entity{modelEntity}})
		c.MaskSettled = mask
		got, err := c.Detect(text)
		if err != nil {
			t.Fatalf("MaskSettled=%v: %v", mask, err)
		}
		results[mask] = got
	}

	if len(results[false]) != len(results[true]) {
		t.Fatalf("两条路结论不同：不挖空 %d 个，挖空 %d 个", len(results[false]), len(results[true]))
	}
	for i := range results[false] {
		if results[false][i] != results[true][i] {
			t.Errorf("第 %d 项不同：\n不挖空 %+v\n挖空   %+v", i, results[false][i], results[true][i])
		}
	}
	t.Logf("两条路得到相同的 %d 个实体", len(results[false]))
}
