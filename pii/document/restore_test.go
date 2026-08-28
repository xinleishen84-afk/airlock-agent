package document

import (
	"encoding/json"
	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"strings"
	"testing"
	"time"
)

// TestRestoreProtocolFieldsUntouched 验收：复原侧同样不碰协议骨架。
//
// 占位符本不该出现在 id / model / finish_reason 里，一旦出现说明上游有问题，
// 此时保留原样比擅自替换更安全——替换会掩盖问题并可能破坏协议。
func TestRestoreProtocolFieldsUntouched(t *testing.T) {
	var doc map[string]any
	raw := `{
		"id": "ANONYMIZED_NAME_0",
		"model": "ANONYMIZED_NAME_0",
		"choices": [{
			"index": 0,
			"finish_reason": "ANONYMIZED_NAME_0",
			"delta": {"role": "ANONYMIZED_NAME_0", "content": "你好 ANONYMIZED_NAME_0"}
		}]
	}`
	json.Unmarshal([]byte(raw), &doc)

	err := RestoreDocument(doc, func(_, s string) (string, error) {
		return strings.ReplaceAll(s, "ANONYMIZED_NAME_0", "张伟"), nil
	})
	if err != nil {
		t.Fatalf("复原失败: %v", err)
	}

	if doc["id"] != "ANONYMIZED_NAME_0" {
		t.Errorf("响应 id 被复原污染: %v", doc["id"])
	}
	if doc["model"] != "ANONYMIZED_NAME_0" {
		t.Errorf("model 被复原污染: %v", doc["model"])
	}
	choice := dig(t, doc, "choices", 0)
	if dig(t, choice, "finish_reason") != "ANONYMIZED_NAME_0" {
		t.Errorf("finish_reason 被复原污染")
	}
	if dig(t, choice, "delta", "role") != "ANONYMIZED_NAME_0" {
		t.Errorf("delta.role 被复原污染")
	}
	// 但正文必须被复原
	if dig(t, choice, "delta", "content") != "你好 张伟" {
		t.Errorf("正文未被复原: %v", dig(t, choice, "delta", "content"))
	}
}

// TestStreamRestoreHandlesSplitPlaceholder 验收：跨帧切分的占位符能正确复原，
// 且每一帧输出都是合法 JSON。
func TestStreamRestoreHandlesSplitPlaceholder(t *testing.T) {
	gaz, _ := detect.NewGazetteerDetector(map[detect.EntityType][]string{
		detect.TypeName: {`李"小"娜`},
	}, false, 2)
	r := anonymize.NewRedactor(detect.NewCompositeDetector([]detect.Detector{gaz}, 0), true)
	reg := anonymize.NewVaultRegistry(time.Hour, 10)
	vault, _ := reg.Get(docSessionRef("s"))
	if _, err := r.Redact(t.Context(), `联系李"小"娜`, docScope(vault)); err != nil { // 登记 ANONYMIZED_NAME_0
		t.Fatal(err)
	}

	restorer := NewStreamRestorer(r, anonymize.StrategyScope{Tenant: docTenant, Vault: vault})
	frames := []string{
		`{"choices":[{"delta":{"content":"已通知 ANONYMIZED_NA"}}]}`,
		`{"choices":[{"delta":{"content":"ME_0 处理"}}]}`,
	}

	var assembled strings.Builder
	for _, f := range frames {
		fs := restorer.Frame(t.Context(), []byte(f))
		if len(fs) != 1 {
			t.Fatalf("期望一帧，实得 %d", len(fs))
		}
		out := fs[0]
		var probe map[string]any
		if err := json.Unmarshal(out, &probe); err != nil {
			t.Fatalf("输出帧非法 JSON: %s (%v)", out, err)
		}
		if c := dig(t, probe, "choices", 0, "delta", "content"); c != nil {
			assembled.WriteString(c.(string))
		}
	}
	tail, err := restorer.Flush(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	assembled.WriteString(tail)

	if !strings.Contains(assembled.String(), `李"小"娜`) {
		t.Errorf("跨帧占位符未正确复原，拼接结果: %q", assembled.String())
	}
}

// docSessionRef 是测试用的会话引用构造。
const docTenant anonymize.Tenant = "acme"

func docSessionRef(session string) anonymize.SessionRef {
	return anonymize.SessionRef{Tenant: docTenant, Session: session}
}

func docScope(v *anonymize.SessionVault) anonymize.StrategyScope {
	return anonymize.StrategyScope{Tenant: docTenant, Vault: v}
}
