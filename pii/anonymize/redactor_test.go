package anonymize

import (
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
	"strings"
	"testing"
	"time"
)

// 测试数据：校验位合法的构造值（非真实身份）。
// Test fixtures: constructed values with valid check digits (not real identities).
const (
	validID   = "110101199003078515"
	validCard = "4111111111111111"
)

// newTestRedactor 构造与 Python 参考实现同配置的脱敏器与会话。
func newTestRedactor(t *testing.T) (*Redactor, *SessionVault) {
	t.Helper()
	gaz, err := detect.NewGazetteerDetector(map[detect.EntityType][]string{
		detect.TypeName: {"张伟", "李娜"},
	}, false, 2)
	if err != nil {
		t.Fatalf("构造名册失败: %v", err)
	}
	d := detect.NewCompositeDetector([]detect.Detector{packs.MustNewRegistry([]string{"GEN", "CN", "US"}), gaz}, 0)
	return NewRedactor(d, true), newSessionVault("s1", time.Hour)
}

// TestRoundTrip 校验脱敏—复原往返后回到原文。
func TestRoundTrip(t *testing.T) {
	r, v := newTestRedactor(t)
	original := "张伟的手机是 13812345678，身份证 " + validID
	res, err := r.Redact(t.Context(), original, sessScope(v))
	if err != nil {
		t.Fatalf("脱敏失败: %v", err)
	}
	for _, secret := range []string{"张伟", "13812345678", validID} {
		if strings.Contains(res.Text, secret) {
			t.Errorf("脱敏后仍含真实值 %q: %s", secret, res.Text)
		}
	}
	if got := unredactT(t, r, res.Text, sessScope(v)).Text; got != original {
		t.Errorf("往返不一致:\n  得到 %q\n  期望 %q", got, original)
	}
}

// TestWhitespacePreserved 锁定 Python 版实测踩到的空白吞噬 bug。
// 若占位符正则被改成「可选包裹符 + \s*」，前导空格会被吃掉，本用例会失败。
func TestWhitespacePreserved(t *testing.T) {
	r, v := newTestRedactor(t)
	original := "李娜 13900001111 张伟 13812345678"
	res, _ := r.Redact(t.Context(), original, sessScope(v))
	if got := unredactT(t, r, res.Text, sessScope(v)).Text; got != original {
		t.Errorf("空白丢失:\n  得到 %q\n  期望 %q", got, original)
	}
}

// TestCrossTurnConsistency 校验跨轮次同一实体占位符稳定。
func TestCrossTurnConsistency(t *testing.T) {
	r, v := newTestRedactor(t)
	first, _ := r.Redact(t.Context(), "张伟来了", sessScope(v))
	second, _ := r.Redact(t.Context(), "张伟又来了", sessScope(v))
	if !strings.Contains(first.Text, "ANONYMIZED_NAME_0") ||
		!strings.Contains(second.Text, "ANONYMIZED_NAME_0") {
		t.Errorf("跨轮次占位符不稳定: %q / %q", first.Text, second.Text)
	}
}

// TestDistinctPlaceholderPerType 校验同名的人和公司拿到不同占位符。
func TestDistinctPlaceholderPerType(t *testing.T) {
	v := newSessionVault("s", time.Hour)
	asName := v.PlaceholderFor(detect.Entity{Type: detect.TypeName, Value: "星辰"})
	asOrg := v.PlaceholderFor(detect.Entity{Type: detect.TypeOrg, Value: "星辰"})
	if asName == asOrg {
		t.Errorf("同名不同类型必须拿到不同占位符，均为 %q", asName)
	}
}

// TestUnredactToleratesRewriting 校验模型改写占位符后仍能复原。
func TestUnredactToleratesRewriting(t *testing.T) {
	r, v := newTestRedactor(t)
	r.Redact(t.Context(), "张伟", sessScope(v))
	for _, variant := range []string{
		"ANONYMIZED_NAME_0", "anonymized_name_0",
		"`ANONYMIZED_NAME_0`", "[ANONYMIZED_NAME_0]", "【ANONYMIZED_NAME_0】",
	} {
		got := unredactT(t, r, "你好 "+variant, sessScope(v)).Text
		if !strings.Contains(got, "张伟") {
			t.Errorf("变体 %q 未能复原，得到 %q", variant, got)
		}
	}
}

// TestPhantomPlaceholderNotGuessed 校验模型捏造的占位符原样保留并记录。
func TestPhantomPlaceholderNotGuessed(t *testing.T) {
	r, v := newTestRedactor(t)
	r.Redact(t.Context(), "张伟", sessScope(v))
	res := unredactT(t, r, "联系 ANONYMIZED_NAME_77", sessScope(v))
	if !strings.Contains(res.Text, "ANONYMIZED_NAME_77") {
		t.Errorf("捏造的占位符应原样保留: %q", res.Text)
	}
	if len(res.Phantom) != 1 {
		t.Errorf("应记录 1 个捏造占位符，实际 %v", res.Phantom)
	}
}

// TestFailClosedBlocks 校验检测器故障时 fail-closed 阻断。
func TestFailClosedBlocks(t *testing.T) {
	r := NewRedactor(detect.NewCompositeDetector([]detect.Detector{brokenDetector{}}, 0), true)
	v := newSessionVault("s", time.Hour)
	if _, err := r.Redact(t.Context(), "张伟 13812345678", sessScope(v)); err == nil {
		t.Fatal("检测器故障时必须阻断")
	}
}

// TestFailOpenPassesThroughWithError 校验 fail-open 放行但仍返回错误供审计。
func TestFailOpenPassesThroughWithError(t *testing.T) {
	r := NewRedactor(detect.NewCompositeDetector([]detect.Detector{brokenDetector{}}, 0), false)
	v := newSessionVault("s", time.Hour)
	res, err := r.Redact(t.Context(), "张伟", sessScope(v))
	if err == nil {
		t.Error("fail-open 也必须返回错误，否则无法审计追责")
	}
	if res.Text != "张伟" {
		t.Errorf("fail-open 应放行原文，得到 %q", res.Text)
	}
}

// TestScanLeakDetectsResidual 校验终检能发现脱敏后残留的真实值。
func TestScanLeakDetectsResidual(t *testing.T) {
	r, v := newTestRedactor(t)
	r.Redact(t.Context(), "张伟", sessScope(v))
	if got := v.ScanLeak("正常文本"); len(got) != 0 {
		t.Errorf("无泄露时应返回空，得到 %v", got)
	}
	if got := v.ScanLeak("这里还有张伟"); len(got) != 1 || got[0] != "NAME" {
		t.Errorf("应检出 NAME 泄露，得到 %v", got)
	}
}

// TestAuditCountsHideValues 校验审计视图只暴露计数。
func TestAuditCountsHideValues(t *testing.T) {
	r, v := newTestRedactor(t)
	r.Redact(t.Context(), "张伟 13812345678", sessScope(v))
	counts := v.AuditCounts()
	if counts["NAME"] != 1 || counts["PHONE"] != 1 {
		t.Errorf("计数不符: %v", counts)
	}
}

// TestPurgeClearsMapping 校验清除后无法再复原。
func TestPurgeClearsMapping(t *testing.T) {
	v := newSessionVault("s", time.Hour)
	p := v.PlaceholderFor(detect.Entity{Type: detect.TypeName, Value: "张伟"})
	v.Purge()
	if _, ok := v.Resolve(p); ok {
		t.Error("清除后不应还能解出真实值")
	}
}

// ---------------------------------------------------------------------------
// Streaming restoration / 流式复原
// ---------------------------------------------------------------------------

// TestStreamUnredactHandlesSplitPlaceholder 校验被切分的占位符能正确复原。
// 这是流式脱敏的核心难点：占位符可能横跨两个 SSE 分片。
func TestStreamUnredactHandlesSplitPlaceholder(t *testing.T) {
	r, v := newTestRedactor(t)
	r.Redact(t.Context(), "张伟", sessScope(v)) // 登记 ANONYMIZED_NAME_0

	cases := [][]string{
		{"你好 ANONYMIZED_NAME_0 再见"},             // complete in one chunk / 单片完整
		{"你好 ANONYMIZED_NA", "ME_0 再见"},         // split in the middle / 中间切开
		{"你好 ANONYM", "IZED_", "NAME_", "0 再见"}, // split into four / 切成四片
		{"你好 ", "A", "N", "O", "N", "Y", "M", "I", "Z", "E", "D", "_", "N", "A", "M", "E", "_", "0", " 再见"},
	}
	for i, chunks := range cases {
		s := NewStreamUnredactor(r, sessScope(v))
		var out strings.Builder
		for _, c := range chunks {
			out.WriteString(s.FeedT(t, c))
		}
		out.WriteString(s.FlushT(t))
		if got := out.String(); got != "你好 张伟 再见" {
			t.Errorf("用例 %d 复原错误: %q", i, got)
		}
	}
}

// TestStreamNeverEmitsPartialPlaceholder 校验绝不把半个占位符吐给用户。
func TestStreamNeverEmitsPartialPlaceholder(t *testing.T) {
	r, v := newTestRedactor(t)
	r.Redact(t.Context(), "张伟", sessScope(v))

	s := NewStreamUnredactor(r, sessScope(v))
	emitted := s.FeedT(t, "前缀 ANONYMIZED_NA")
	if strings.Contains(emitted, "ANONYMIZED") {
		t.Errorf("半个占位符被吐出: %q", emitted)
	}
	rest := s.FeedT(t, "ME_0 后缀") + s.FlushT(t)
	if !strings.Contains(emitted+rest, "张伟") {
		t.Errorf("最终未复原: %q", emitted+rest)
	}
}

// TestVaultRegistryExpiry 校验 TTL 到期的会话被回收且映射清空。
func TestVaultRegistryExpiry(t *testing.T) {
	reg := NewVaultRegistry(10*time.Millisecond, 100)
	first, err := reg.Get(anonymize_SessionRef("s"))
	if err != nil {
		t.Fatalf("获取会话失败: %v", err)
	}
	p := first.PlaceholderFor(detect.Entity{Type: detect.TypeName, Value: "张伟"})

	time.Sleep(20 * time.Millisecond)
	second, _ := reg.Get(anonymize_SessionRef("s"))
	if second == first {
		t.Error("过期会话应被重建")
	}
	if _, ok := second.Resolve(p); ok {
		t.Error("过期会话的映射应已清空")
	}
}

// TestVaultRegistryConcurrent 校验分片注册表在并发下的正确性。
func TestVaultRegistryConcurrent(t *testing.T) {
	reg := NewVaultRegistry(time.Hour, 10000)
	r, _ := newTestRedactor(t)

	done := make(chan struct{})
	for i := 0; i < 32; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			sid := string(rune('a' + id%8))
			v, err := reg.Get(anonymize_SessionRef(sid))
			if err != nil {
				t.Errorf("并发获取失败: %v", err)
				return
			}
			for j := 0; j < 50; j++ {
				res, _ := r.Redact(t.Context(), "张伟 13812345678", sessScope(v))
				if strings.Contains(res.Text, "张伟") {
					t.Error("并发脱敏遗漏")
					return
				}
			}
		}(i)
	}
	for i := 0; i < 32; i++ {
		<-done
	}
}

// brokenDetector 是永远失败的检测器，用于验证 fail-closed。
// brokenDetector always fails; used to verify fail-closed behaviour.
type brokenDetector struct{}

// Name 返回检测器标识。/ Name returns the detector id.
func (brokenDetector) Name() string { return "broken" }

// CoveredTypes 返回覆盖类型。/ CoveredTypes returns covered types.
func (brokenDetector) CoveredTypes() []detect.EntityType { return nil }

// Detect 总是失败。/ Detect always fails.
func (brokenDetector) Detect(string) ([]detect.Entity, error) { return nil, errBrokenDetector }

// errBrokenDetector 是测试用错误。/ errBrokenDetector is a test error.
var errBrokenDetector = &testErr{}

// testErr 是测试用错误类型。/ testErr is a test error type.
type testErr struct{}

// Error 实现 error。/ Error implements error.
func (*testErr) Error() string { return "检测器不可用 / detector unavailable" }
