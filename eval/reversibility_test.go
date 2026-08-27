package eval

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/document"
)

// 还原准确率必须是 100%：99.9% 意味着每一千次对话里有一次，
// 终端用户收到的是另一个人的姓名。
// Reversibility must be 100%: 99.9% means one conversation in a thousand hands
// the end user somebody else's name.

func revRedactor(t testing.TB, roster map[detect.EntityType][]string) (*anonymize.Redactor, anonymize.StrategyScope) {
	t.Helper()
	gaz, err := detect.NewGazetteerDetector(roster, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	d := detect.NewCompositeDetector(
		[]detect.Detector{packsRegistry(t), gaz}, 0)
	r := anonymize.NewRedactorWith(d, true)
	return r, anonymize.StrategyScope{Tenant: "acme", Vault: evalVault(t)}
}

// 往返：脱敏 → 复原，必须逐字节回到原文。
// Round trip: redact then restore must return the exact original bytes.
func TestRoundTripExactness(t *testing.T) {
	// 刻意选难处理的值：引号、换行、JSON 元字符、CJK、emoji、零宽字符
	// Deliberately awkward values: quotes, newlines, JSON metacharacters, CJK,
	// emoji, zero-width characters.
	names := []string{
		`李"小"娜`, "张\\伟", "王<script>", "赵\n换行", "陈\ttab",
		"欧阳·修", "Ünicode Ström", "李娜👩‍💻", "孙​悟空", "钱{}[]()",
	}
	r, scope := revRedactor(t, map[detect.EntityType][]string{detect.TypeName: names})

	failures := 0
	for _, name := range names {
		for _, tmpl := range []string{
			"请联系 %s 处理此事。",
			"%s 的手机是 13812345678。",
			`{"owner":"%s","phone":"13812345678"}`,
			"多次出现：%s、%s、%s。",
		} {
			original := fmt.Sprintf(strings.ReplaceAll(tmpl, "%s", "%[1]s"), name)

			red, err := r.RedactTo(t.Context(), original, scope, maskFlow())
			if err != nil {
				t.Fatalf("脱敏失败 %q: %v", original, err)
			}
			if strings.Contains(red.Text, name) {
				t.Errorf("脱敏后仍含原值：%q -> %q", original, red.Text)
				failures++
				continue
			}
			back, err := r.Unredact(t.Context(), red.Text, scope)
			if err != nil {
				t.Fatalf("复原失败: %v", err)
			}
			if back.Text != original {
				t.Errorf("往返不等：\n原文 %q\n脱敏 %q\n复原 %q", original, red.Text, back.Text)
				failures++
			}
		}
	}
	t.Logf("%d 个高难度值 × 4 种上下文，往返失败 %d 次", len(names), failures)
}

// 幂等：重复脱敏、重复复原都不得改变结果。
// Idempotency: repeating either direction must not change the result.
func TestIdempotency(t *testing.T) {
	r, scope := revRedactor(t, map[detect.EntityType][]string{
		detect.TypeName: {"张伟", "李娜"},
	})
	const original = "张伟 的手机 13812345678，李娜 的邮箱 li.na@example.com。"

	once, err := r.RedactTo(t.Context(), original, scope, maskFlow())
	if err != nil {
		t.Fatal(err)
	}
	twice, err := r.RedactTo(t.Context(), once.Text, scope, maskFlow())
	if err != nil {
		t.Fatal(err)
	}
	if twice.Text != once.Text {
		t.Errorf("重复脱敏改变了结果：\n一次 %q\n两次 %q", once.Text, twice.Text)
	}
	if len(twice.Entities) != 0 {
		t.Errorf("对已脱敏文本的第二次脱敏不应再检出实体：%v", twice.Entities)
	}

	b1, _ := r.Unredact(t.Context(), once.Text, scope)
	b2, _ := r.Unredact(t.Context(), b1.Text, scope)
	if b1.Text != original {
		t.Errorf("复原不等于原文：%q", b1.Text)
	}
	if b2.Text != b1.Text {
		t.Errorf("重复复原改变了结果：%q vs %q", b1.Text, b2.Text)
	}
	t.Logf("脱敏与复原双向幂等")
}

// 错位替换：同一类型的多个不同值，必须各自还原到自己那一个。
// Misaligned substitution: several distinct values of one type must each
// restore to their own.
//
// 这是「还原准确率」真正要测的东西。往返回到原文，可能只是因为文本里
// 只有一个实体；有三个人名时，占位符编号错一位就会把甲的名字还给乙，
// 而结果仍然是一段通顺的中文。
// This is what reversibility actually has to measure. A round trip can succeed
// merely because there was one entity; with three names, an off-by-one in the
// placeholder numbering hands person A's name to person B and still produces a
// fluent sentence.
func TestNoMisalignedSubstitution(t *testing.T) {
	names := []string{"张伟", "李娜", "王强", "赵敏", "陈静"}
	r, scope := revRedactor(t, map[detect.EntityType][]string{detect.TypeName: names})

	rng := rand.New(rand.NewPCG(5, 9))
	failures := 0
	const trials = 500

	for range trials {
		// 随机排列、随机重复
		n := 2 + rng.IntN(8)
		var parts []string
		for range n {
			parts = append(parts, names[rng.IntN(len(names))])
		}
		original := "参会人：" + strings.Join(parts, "、") + "。请依次发言。"

		red, err := r.RedactTo(t.Context(), original, scope, maskFlow())
		if err != nil {
			t.Fatal(err)
		}
		back, err := r.Unredact(t.Context(), red.Text, scope)
		if err != nil {
			t.Fatal(err)
		}
		if back.Text != original {
			failures++
			if failures <= 3 {
				t.Errorf("错位：\n原文 %q\n脱敏 %q\n复原 %q", original, red.Text, back.Text)
			}
		}
	}
	t.Logf("%d 组随机人名排列（含重复），错位 %d 次 —— 还原准确率 %.4f%%",
		trials, failures, float64(trials-failures)/trials*100)
}

// 跨轮次一致性：同一个人在第 1 轮和第 N 轮必须是同一个占位符。
// Cross-turn consistency: the same person must keep one placeholder.
func TestCrossTurnConsistency(t *testing.T) {
	r, scope := revRedactor(t, map[detect.EntityType][]string{
		detect.TypeName: {"张伟", "李娜"},
	})
	seen := map[string]string{}
	for turn := range 20 {
		text := fmt.Sprintf("第 %d 轮：张伟 说要联系 李娜。", turn)
		red, err := r.RedactTo(t.Context(), text, scope, maskFlow())
		if err != nil {
			t.Fatal(err)
		}
		normalized := strings.Replace(red.Text, fmt.Sprintf("第 %d 轮", turn), "第 N 轮", 1)
		if prev, ok := seen["norm"]; ok && prev != normalized {
			t.Errorf("第 %d 轮占位符编号发生了漂移：\n%q\n%q", turn, prev, normalized)
		}
		seen["norm"] = normalized
		if turn == 0 {
			t.Logf("第 1 轮：%s", red.Text)
		}
		if turn == 19 {
			t.Logf("第 20 轮：%s", red.Text)
		}
	}
}

// 结构化往返走的是真实链路：请求侧清洗 → 模型 → 响应侧复原。
// The structured round trip follows the real path: sanitize the request, then
// restore the response.
//
// 请求路径与响应路径的白名单是两套，这是刻意的：请求里 messages[].content
// 是要脱敏的自然语言，而响应里对应的是 choices[].message.content。
// 拿一套去处理另一套，会安静地什么都不做——本用例最初就是这么写错的，
// 而它报出来的现象是「复原失败」，看上去像还原准确率的问题。
//
// The request and response allowlists are two different sets, deliberately.
// Applying one to the other silently does nothing — this test was first
// written that way, and the symptom looked like a reversibility failure.
func TestStructuredRoundTrip(t *testing.T) {
	r, scope := revRedactor(t, map[detect.EntityType][]string{
		detect.TypeName: {`李"小"娜`, "张伟"},
	})

	// --- 出站：清洗请求 ---
	request := map[string]any{
		"model": "gpt-4o",
		"messages": []any{
			map[string]any{"role": "system", "content": "你是客服助理。"},
			map[string]any{"role": "user", "content": `联系 李"小"娜，手机 13812345678`},
		},
		"tools": []any{
			map[string]any{"function": map[string]any{
				"name":        "lookup",
				"description": "例如：查询 张伟 的订单",
				"parameters": map[string]any{
					"type":       "object",
					"properties": map[string]any{"status": map[string]any{"enum": []any{"paid", "shipped"}}},
				},
			}},
		},
	}
	if err := document.SanitizeDocument(request, func(_, text string) (string, error) {
		res, err := r.RedactTo(t.Context(), text, scope, maskFlow())
		if err != nil {
			return "", err
		}
		return res.Text, nil
	}); err != nil {
		t.Fatal(err)
	}
	outbound, err := document.MarshalPreserving(request)
	if err != nil {
		t.Fatalf("脱敏后无法序列化 —— 载荷已被打坏：%v", err)
	}
	for _, leaked := range []string{`李\"小\"娜`, "13812345678", "张伟"} {
		if strings.Contains(string(outbound), leaked) {
			t.Errorf("出站载荷仍含原值 %q：%s", leaked, outbound)
		}
	}
	// enum 是工具约束，不是自然语言，绝不能被改写
	if !strings.Contains(string(outbound), `"paid"`) {
		t.Errorf("工具 enum 被改写了，模型的调用约束已损坏：%s", outbound)
	}

	// --- 入站：模型用占位符作答，响应侧复原 ---
	userMsg := request["messages"].([]any)[1].(map[string]any)["content"].(string)
	toolDesc := request["tools"].([]any)[0].(map[string]any)["function"].(map[string]any)["description"].(string)

	response := map[string]any{
		"choices": []any{
			map[string]any{"message": map[string]any{
				"role":    "assistant",
				"content": "好的，我会按「" + userMsg + "」处理，并参考「" + toolDesc + "」。",
			}},
		},
	}
	if err := document.RestoreDocument(response, func(_, text string) (string, error) {
		res, err := r.Unredact(t.Context(), text, scope)
		if err != nil {
			return "", err
		}
		return res.Text, nil
	}); err != nil {
		t.Fatal(err)
	}
	restored, err := document.MarshalPreserving(response)
	if err != nil {
		t.Fatalf("复原后无法序列化 —— 含引号的真实值把 JSON 打坏了：%v", err)
	}

	got := response["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["content"].(string)
	want := "好的，我会按「联系 李\"小\"娜，手机 13812345678」处理，并参考「例如：查询 张伟 的订单」。"
	if got != want {
		t.Errorf("响应复原不等：\n得到 %q\n期望 %q", got, want)
	}
	var probe map[string]any
	if err := json.Unmarshal(restored, &probe); err != nil {
		t.Fatalf("复原后不是合法 JSON：%v", err)
	}
	t.Logf("请求清洗 → 响应复原，含嵌套引号的真实值逐字回到原样，工具 enum 未被触碰")
}

// 流式复原：占位符被逐字节切开，拼回来必须与整体复原一致。
// Streaming restoration: a placeholder split byte by byte must reassemble.
func TestStreamingRestorationEquivalence(t *testing.T) {
	r, scope := revRedactor(t, map[detect.EntityType][]string{
		detect.TypeName: {"张伟", "李娜"},
	})
	const original = "张伟 与 李娜 将于明日核对 13812345678 的账单。"

	red, err := r.RedactTo(t.Context(), original, scope, maskFlow())
	if err != nil {
		t.Fatal(err)
	}
	whole, err := r.Unredact(t.Context(), red.Text, scope)
	if err != nil {
		t.Fatal(err)
	}

	// 逐字节喂：最坏情况的分片
	su := anonymize.NewStreamUnredactor(r, scope)
	var out strings.Builder
	for i := 0; i < len(red.Text); i++ {
		chunk, err := su.Feed(t.Context(), red.Text[i:i+1])
		if err != nil {
			t.Fatal(err)
		}
		out.WriteString(chunk)
	}
	tail, err := su.Flush(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	out.WriteString(tail)

	if out.String() != whole.Text {
		t.Errorf("流式与整体复原不一致：\n流式 %q\n整体 %q", out.String(), whole.Text)
	}
	if out.String() != original {
		t.Errorf("流式复原不等于原文：\n%q\n%q", out.String(), original)
	}
	t.Logf("逐字节切分下流式复原与整体复原一致")
}

var _ = time.Second
