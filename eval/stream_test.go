package eval

import (
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/preset"
)

// 流式复原在任意切分点下都必须与整体复原逐字相同。
// Streaming restoration must match whole-text restoration byte for byte, at
// any split point.
func TestStreamRestoreFuzzProbe(t *testing.T) {
	det, v, err := preset.Core(preset.CoreOptions{
		Jurisdictions: []string{"GEN", "CN"},
		Roster:        map[detect.EntityType][]string{detect.TypeName: {"张伟", "李娜"}},
		Surnames:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := anonymize.NewRedactorWith(verifyingWrapper{inner: det, validator: v}, true)
	flow := anonymize.Flow{Name: "t", Default: anonymize.NewMask(), Restores: true}

	rng := rand.New(rand.NewPCG(31, 41))
	fragments := []string{
		"已通知张伟", "手机是 13812345678", "邮箱 a.b@example.com",
		"，请查收。", "经办人欧阳志远", "身份证 11010519491231002X",
		"🙂", "\n", "住上海市浦东新区",
	}

	failures := 0
	for trial := range 1500 {
		var b strings.Builder
		for range 1 + rng.IntN(5) {
			b.WriteString(fragments[rng.IntN(len(fragments))])
		}
		original := b.String()

		vaults := anonymize.NewVaultRegistry(time.Hour, 10)
		vlt, _ := vaults.Get(anonymize.SessionRef{Tenant: "acme", Session: "s"})
		scope := anonymize.StrategyScope{Tenant: "acme", Vault: vlt}

		red, err := r.RedactTo(t.Context(), original, scope, flow)
		if err != nil {
			t.Fatalf("trial %d 脱敏失败：%v", trial, err)
		}

		// 整体复原作为基准
		whole, err := r.Unredact(t.Context(), red.Text, scope)
		if err != nil {
			t.Fatalf("trial %d 整体复原失败：%v", trial, err)
		}

		// 随机切成若干片走流式
		su := anonymize.NewStreamUnredactor(r, scope)
		var streamed strings.Builder
		rest := red.Text
		for len(rest) > 0 {
			n := 1 + rng.IntN(6)
			if n > len(rest) {
				n = len(rest)
			}
			out, err := su.Feed(t.Context(), rest[:n])
			if err != nil {
				t.Fatalf("trial %d 流式复原失败：%v", trial, err)
			}
			streamed.WriteString(out)
			rest = rest[n:]
		}
		tail, err := su.Flush(t.Context())
		if err != nil {
			t.Fatalf("trial %d 流式收尾失败：%v", trial, err)
		}
		streamed.WriteString(tail)

		if streamed.String() != whole.Text {
			failures++
			if failures <= 4 {
				t.Errorf("trial %d 流式与整体不一致：\n  原文 %q\n  脱敏 %q\n  整体 %q\n  流式 %q",
					trial, original, red.Text, whole.Text, streamed.String())
			}
		}
	}
	if failures == 0 {
		t.Log("1500 组随机切分下，流式与整体复原逐字相同")
	}
}

// 并发使用同一套检测器与验证器必须安全。
// The detector and validator must be safe under concurrent use.
func TestConcurrentPipelineProbe(t *testing.T) {
	det, v, err := preset.Core(preset.CoreOptions{
		Jurisdictions: []string{"GEN", "CN"},
		Roster:        map[detect.EntityType][]string{detect.TypeName: {"张伟"}},
		Surnames:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := anonymize.NewRedactorWith(verifyingWrapper{inner: det, validator: v}, true)
	flow := anonymize.Flow{Name: "t", Default: anonymize.NewMask(), Restores: true}
	vaults := anonymize.NewVaultRegistry(time.Hour, 1000)

	texts := []string{
		"请联系张伟，手机 13812345678。",
		"经办人欧阳志远，身份证 11010519491231002X。",
		"邮箱 a.b@example.com，卡号 4111111111111111。",
		"住上海市浦东新区世纪大道100号。",
	}

	var wg sync.WaitGroup
	for w := range 16 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range 200 {
				text := texts[(id+i)%len(texts)]
				vlt, err := vaults.Get(anonymize.SessionRef{
					Tenant: "acme", Session: string(rune('a' + id)),
				})
				if err != nil {
					t.Error(err)
					return
				}
				scope := anonymize.StrategyScope{Tenant: "acme", Vault: vlt}

				red, err := r.RedactTo(t.Context(), text, scope, flow)
				if err != nil {
					t.Errorf("worker %d 脱敏失败：%v", id, err)
					return
				}
				back, err := r.Unredact(t.Context(), red.Text, scope)
				if err != nil {
					t.Errorf("worker %d 复原失败：%v", id, err)
					return
				}
				if back.Text != text {
					t.Errorf("worker %d 往返不一致：\n  原文 %q\n  复原 %q", id, text, back.Text)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	t.Log("16 协程 × 200 次并发往返，全部一致")
}
