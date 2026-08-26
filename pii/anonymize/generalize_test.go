package anonymize

import (
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

func testOntology() *Ontology {
	return &Ontology{Terms: map[string]string{
		"外科医生":    "医生",
		"心内科医生":   "医生",
		"surgeon": "physician",
		"上海市浦东新区": "上海市",
	}}
}

func TestGeneralizeDates(t *testing.T) {
	cases := []struct {
		in          string
		granularity dateGranularity
		want        string
	}{
		{"1995-10-24", GranularityDecade, "1990s"},
		{"1995-10-24", GranularityYear, "1995"},
		{"1995/10/24", GranularityDecade, "1990s"},
		{"1995年10月24日", GranularityDecade, "1990s"},
		{"2003-01-02", GranularityDecade, "2000s"},
		{"1995", GranularityDecade, "1990s"},
	}
	for _, c := range cases {
		g, err := NewGeneralize(testOntology(), c.granularity, NewDrop())
		if err != nil {
			t.Fatal(err)
		}
		got, err := g.Apply(t.Context(), testScope(), ent(detect.TypeIDCard, c.in))
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("Generalize(%q, %s) = %q, want %q", c.in, c.granularity, got, c.want)
		}
	}
}

func TestGeneralizeOntologyTerms(t *testing.T) {
	g, err := NewGeneralize(testOntology(), GranularityDecade, NewDrop())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"外科医生":    "医生",
		"上海市浦东新区": "上海市",
		"Surgeon": "physician", // 大小写不敏感
	}
	for in, want := range cases {
		got, err := g.Apply(t.Context(), testScope(), ent(detect.TypeOrg, in))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("Generalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// 词表未覆盖的值必须走兜底算子，绝不能原样通过。
// A value the ontology does not cover must take the fallback, never pass
// through.
//
// 词表里没有的词，恰恰是没人预料到的那个值 —— 一个「查不到就放过」的
// 泛化器，泄露的正是最不该泄露的那些。
// A term missing from the table is precisely the value nobody anticipated: a
// generalizer that passes unknowns through leaks exactly the wrong ones.
func TestGeneralizeFallsBackForUnknownTerms(t *testing.T) {
	g, err := NewGeneralize(testOntology(), GranularityDecade, NewCharMask('*', 0))
	if err != nil {
		t.Fatal(err)
	}
	got, err := g.Apply(t.Context(), testScope(), ent(detect.TypeOrg, "某个词表里没有的罕见职业"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "罕见职业") {
		t.Fatalf("词表未覆盖的值原样通过了：%q", got)
	}
	t.Logf("未覆盖的值走了兜底算子：%q", got)
}

func TestGeneralizeRequiresFallback(t *testing.T) {
	if _, err := NewGeneralize(testOntology(), GranularityDecade, nil); err == nil {
		t.Fatal("缺少兜底算子应被拒绝")
	}
	if _, err := NewGeneralize(testOntology(), "century", NewDrop()); err == nil {
		t.Fatal("未知粒度应被拒绝")
	}
}

func TestLoadOntology(t *testing.T) {
	good := `
terms:
  外科医生: 医生
  心内科医生: 医生
`
	o, err := LoadOntology(strings.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := o.lookup("外科医生"); h != "医生" {
		t.Fatalf("解析结果不符：%v", o.Terms)
	}

	bad := []struct{ name, src string }{
		{"空表", "terms: {}"},
		{"上位词为空", "terms:\n  外科医生: \"\""},
		{"泛化到自身", "terms:\n  医生: 医生"},
		{"未知字段", "terms:\n  医生: 人\nontology_version: 3"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if _, err := LoadOntology(strings.NewReader(c.src)); err == nil {
				t.Fatal("应加载失败")
			}
		})
	}
}

// 医疗病历共享的完整链路：日期泛化、职业泛化、其余走遮罩。
// The medical-record sharing flow end to end.
func TestMedicalRecordFlow(t *testing.T) {
	g, err := NewGeneralize(testOntology(), GranularityDecade, NewCharMask('*', 0))
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatrix().MustAdd(Flow{
		Name: "research_export", Default: NewDrop(),
		ByType: map[detect.EntityType]Strategy{
			detect.TypeIDCard: g,
			detect.TypeOrg:    g,
		},
	})
	flow, _ := m.Flow("research_export")

	// 直接验证算子层，避免依赖检测器对这些自由文本的切分
	// Exercised at the operator level: the detector's segmentation of free
	// text is a separate concern.
	for _, c := range []struct {
		typ      detect.EntityType
		in, want string
	}{
		{detect.TypeIDCard, "1995-10-24", "1990s"},
		{detect.TypeOrg, "外科医生", "医生"},
	} {
		got, err := flow.Strategy(c.typ).Apply(t.Context(), testScope(), ent(c.typ, c.in))
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%s: %q -> %q, want %q", c.typ, c.in, got, c.want)
		}
	}

	// 没被显式覆盖的类型走默认算子（切除），不会原样漏出
	// A type without an override takes the default (drop), never passes through
	got, err := flow.Strategy(detect.TypePhone).Apply(t.Context(), testScope(), ent(detect.TypePhone, "13812345678"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("未覆盖类型应走默认切除，实际 %q", got)
	}
}

// 令牌被 SSE 帧边界切开时，前半截不能发给终端用户。
// A token split across SSE frames must not have its first half emitted.
func TestStreamHoldsBackSplitToken(t *testing.T) {
	store := NewMemoryTokenStore(time.Hour)
	tk, _ := NewTokenize(store)
	r := newStrategyTestRedactor(t, store)
	vault := newSessionVault("s", time.Hour)

	full, err := tk.Apply(t.Context(), testScope(), ent(detect.TypeEmail, "a.b@example.com"))
	if err != nil {
		t.Fatal(err)
	}

	// 在令牌中间切开
	cut := len(full) / 2
	su := NewStreamUnredactor(r, sessScope(vault))

	var out strings.Builder
	out.WriteString(su.FeedT(t, "已发送到 "+full[:cut]))
	emitted := out.String()
	if strings.Contains(emitted, "[tok:") {
		t.Fatalf("半个令牌被发了出去：%q", emitted)
	}
	out.WriteString(su.FeedT(t, full[cut:]+"，请查收"))
	out.WriteString(su.FlushT(t))

	if !strings.Contains(out.String(), "a.b@example.com") {
		t.Fatalf("跨帧令牌应被完整还原：%q", out.String())
	}
}
