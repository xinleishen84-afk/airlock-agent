package eval

import (
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/preset"
	"github.com/xinleishen84-afk/airlock-agent/pii/verify"
)

// 随机文本上的往返一致性：脱敏 → 复原 必须逐字回到原文。
func TestRoundTripFuzzProbe(t *testing.T) {
	det, v, err := preset.Core(preset.CoreOptions{
		Jurisdictions: []string{"GEN", "CN"},
		Roster: map[detect.EntityType][]string{
			detect.TypeName: {"张伟", "李娜"},
		},
		Surnames: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 与真实二进制一致：证据链包在检测器外面。
	//
	// 第一版直接把 preset.Core 的检测器交给 Redactor，3000 组里 699 组阻断——
	// 因为它刻意延后重叠消解，产出的是候选不是判决。这不是被测代码的 bug，
	// 是测试搭错了管线；而在加硬阻断之前，这 699 组会静默泄露半截 PII。
	//
	// Wired as the real binary does. The first version handed preset.Core's
	// detector straight to the Redactor: 699 of 3000 blocked, because it defers
	// overlap resolution by design. Not a bug in the code under test but a
	// wrongly assembled pipeline — and before the hard block, those 699 would
	// have leaked half a PII value each.
	r := anonymize.NewRedactorWith(verifyingWrapper{inner: det, validator: v}, true)

	rng := rand.New(rand.NewPCG(99, 7))
	fragments := []string{
		"请联系张伟", "手机 13812345678", "邮箱 a.b@example.com",
		"身份证 11010519491231002X", "卡号 4111111111111111",
		"经办人欧阳志远", "住上海市浦东新区", "统一代码 91110108MA01ABCD71",
		"，", "。", "\n", " ", "订单 20240131000012345",
		"func retry(n int) error", "🙂", "王者荣耀", "ST 段压低",
	}

	flow := anonymize.Flow{Name: "t", Default: anonymize.NewMask(), Restores: true}
	failures := 0

	for trial := range 3000 {
		n := 1 + rng.IntN(8)
		var b strings.Builder
		for range n {
			b.WriteString(fragments[rng.IntN(len(fragments))])
		}
		text := b.String()

		vault := anonymize.NewVaultRegistry(time.Hour, 10)
		vlt, _ := vault.Get(anonymize.SessionRef{Tenant: "acme", Session: "s"})
		scope := anonymize.StrategyScope{Tenant: "acme", Vault: vlt}

		res, err := r.RedactTo(t.Context(), text, scope, flow)
		if err != nil {
			failures++
			if failures <= 3 {
				t.Errorf("trial %d 脱敏失败：%v\n  文本 %q", trial, err, text)
			}
			continue
		}

		back, err := r.Unredact(t.Context(), res.Text, scope)
		if err != nil {
			t.Fatalf("trial %d 复原失败：%v", trial, err)
		}
		if back.Text != text {
			failures++
			if failures <= 5 {
				t.Errorf("trial %d 往返不一致：\n  原文 %q\n  脱敏 %q\n  复原 %q",
					trial, text, res.Text, back.Text)
			}
		}
	}
	if failures == 0 {
		t.Log("3000 组随机文本往返全部一致")
	} else {
		t.Logf("共 %d 组失败", failures)
	}
}

// verifyingWrapper 把证据链包在检测器外面，与 sidecar 的做法一致。
type verifyingWrapper struct {
	inner     detect.Detector
	validator *verify.EvidenceValidator
}

func (w verifyingWrapper) Name() string                      { return w.inner.Name() + "+evidence" }
func (w verifyingWrapper) CoveredTypes() []detect.EntityType { return w.inner.CoveredTypes() }
func (w verifyingWrapper) Detect(text string) ([]detect.Entity, error) {
	found, err := w.inner.Detect(text)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	out := make([]detect.Entity, 0, len(found))
	for _, d := range w.validator.ValidateAll(text, found) {
		out = append(out, d.Entity)
	}
	return out, nil
}
