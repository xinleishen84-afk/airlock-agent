package detect

import (
	"strings"
	"testing"
)

// TestContextBoostsConfidence verifies context words actually change the score.
// 校验上下文词真的会改变置信度。
//
// This is the whole point of context: the same 16-digit run means different
// things next to "卡号" and next to "订单号". Without the boost the recognizer
// cannot tell them apart, and every order number becomes a false positive.
// 这正是上下文的意义：同样 16 位数字，旁边是「卡号」和是「订单号」
// 含义完全不同。没有加权，识别器分不出来，每个订单号都是误报。
func TestContextBoostsConfidence(t *testing.T) {
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}

	withCtx, err := reg.Detect("客户的银行卡号是 4111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	withoutCtx, err := reg.Detect("参考编号 4111111111111111")
	if err != nil {
		t.Fatal(err)
	}

	card := func(list []Entity) (Entity, bool) {
		for _, e := range list {
			if e.Type == TypeBankCard {
				return e, true
			}
		}
		return Entity{}, false
	}
	a, okA := card(withCtx)
	b, okB := card(withoutCtx)
	if !okA || !okB {
		t.Fatalf("两种语境都应检出卡号：with=%v without=%v", withCtx, withoutCtx)
	}
	if a.Confidence <= b.Confidence {
		t.Errorf("有上下文时置信度应更高：%.2f vs %.2f", a.Confidence, b.Confidence)
	}
}

// TestContextWindowRespectsRuneBoundaries verifies the context window never
// splits a multi-byte character.
// 校验上下文窗口不会切开多字节字符。
//
// A window edge landing mid-rune would corrupt the substring search — and only
// for non-ASCII text, so an English-only test suite would never catch it.
// 窗口边缘落在字符中间会破坏子串查找——而且只对非 ASCII 文本出错，
// 纯英文的测试永远发现不了。
func TestContextWindowRespectsRuneBoundaries(t *testing.T) {
	rec, err := NewPatternRecognizer("t", TypeBankCard, `[0-9]{16}`, 0.5,
		WithContext(0.4, "卡号"), WithContextWindow(5))
	if err != nil {
		t.Fatal(err)
	}
	// The window edge deliberately lands inside a multi-byte character.
	// 窗口边缘刻意落在多字节字符内部。
	for _, text := range []string{
		"卡号4111111111111111",
		"银行卡号 4111111111111111",
		"这是一段较长的中文前缀卡号4111111111111111",
	} {
		if _, err := rec.Recognize(text); err != nil {
			t.Errorf("文本 %q 触发错误: %v", text, err)
		}
	}
}

// TestCustomRecognizerRegistration verifies a deployment can add its own entity
// type without patching this library.
// 校验部署方无需改本库源码即可加入自己的实体类型。
//
// If the only way to add a recognizer is to fork, adopters end up maintaining a
// fork — and a forked security component stops receiving upstream fixes.
// 如果加识别器的唯一途径是 fork，采纳方最终会维护一个 fork——
// 而被 fork 的安全组件从此收不到上游修复。
func TestCustomRecognizerRegistration(t *testing.T) {
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}

	// An internal employee ID format nobody upstream could anticipate.
	// 一种上游无从预料的内部工号格式。
	custom, err := NewPatternRecognizer(
		"acme_employee_id", TypeAccount, `EMP-[0-9]{6}`, 0.95,
		WithContext(contextBoost, "工号", "employee"))
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(custom); err != nil {
		t.Fatal(err)
	}

	got, err := reg.Detect("请核对工号 EMP-123456 的权限")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range got {
		if e.Type == TypeAccount && e.Value == "EMP-123456" {
			found = true
			if e.Confidence <= 0.95 {
				t.Errorf("上下文应提升置信度，实际 %.2f", e.Confidence)
			}
		}
	}
	if !found {
		t.Errorf("自定义识别器未生效：%v", got)
	}
}

// TestDuplicateRegistrationRejected verifies a name clash is an error, not a
// silent overwrite.
// 校验重名是错误而非静默覆盖。
//
// A silently replaced recognizer means an entity type stops being detected with
// no signal at all.
// 被静默替换的识别器意味着某类实体从此不再被检出，且毫无征兆。
func TestDuplicateRegistrationRejected(t *testing.T) {
	reg := NewRegistry()
	rec, _ := NewPatternRecognizer("dup", TypeEmail, `x`, 0.5)
	if err := reg.Register(rec); err != nil {
		t.Fatal(err)
	}
	other, _ := NewPatternRecognizer("dup", TypePhone, `y`, 0.5)
	if err := reg.Register(other); err == nil {
		t.Error("重名注册必须报错——静默覆盖会让一类实体不再被检出")
	}
}

// TestRemoveDisablesRecognizer verifies a built-in can be turned off.
// 校验内置识别器可以被关闭。
func TestRemoveDisablesRecognizer(t *testing.T) {
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	before, _ := reg.Detect("服务器地址 192.168.1.100")
	hasIP := func(list []Entity) bool {
		for _, e := range list {
			if e.Type == TypeIP {
				return true
			}
		}
		return false
	}
	if !hasIP(before) {
		t.Fatal("默认应检出 IP")
	}
	if !reg.Remove("ipv4") {
		t.Fatal("移除应成功")
	}
	after, _ := reg.Detect("服务器地址 192.168.1.100")
	if hasIP(after) {
		t.Error("移除后不应再检出 IP")
	}
}

// TestDisabledTypesAtConstruction verifies types can be disabled up front.
// 校验可在构造时关闭指定类型。
func TestDisabledTypesAtConstruction(t *testing.T) {
	reg, err := NewDefaultRegistry(TypeIP)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range reg.Names() {
		if strings.Contains(name, "ipv4") {
			t.Errorf("IP 已被禁用，不应注册 %s", name)
		}
	}
}

// TestRecognizerFailurePropagates verifies one failure is not silently dropped.
// 校验单个识别器故障不会被静默丢弃。
func TestRecognizerFailurePropagates(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(failingRecognizer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Detect("任意文本"); err == nil {
		t.Error("识别器故障必须上抛——静默削弱防护比请求失败更糟")
	}
}

// failingRecognizer always fails.
// 永远失败的识别器。
type failingRecognizer struct{}

// Name returns the identifier. / 返回标识。
func (failingRecognizer) Name() string { return "failing" }

// EntityType returns the produced type. / 返回产出类型。
func (failingRecognizer) EntityType() EntityType { return TypeName }

// Recognize always fails. / 总是失败。
func (failingRecognizer) Recognize(string) ([]Entity, error) { return nil, errFailing }

// errFailing is a test error. / 测试用错误。
var errFailing = &recognizerErr{}

// recognizerErr is a test error type. / 测试用错误类型。
type recognizerErr struct{}

// Error implements error. / 实现 error。
func (*recognizerErr) Error() string { return "识别器不可用 / recognizer unavailable" }

// TestOffsetsAreAccurateFromRegistry verifies offsets survive the registry path.
// 校验经过注册中心后偏移量仍然精确。
func TestOffsetsAreAccurateFromRegistry(t *testing.T) {
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	text := "客户张三的手机是 13812345678，邮箱 a@b.com"
	got, err := reg.Detect(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("应检出实体")
	}
	for _, e := range got {
		if e.Start < 0 || e.End > len(text) || text[e.Start:e.End] != e.Value {
			t.Errorf("偏移不准：text[%d:%d]=%q，Value=%q",
				e.Start, e.End, text[e.Start:e.End], e.Value)
		}
	}
}
