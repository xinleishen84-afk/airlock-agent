package eval

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/document"
	"github.com/xinleishen84-afk/airlock-agent/pii/preset"
)

// 协议完整性：白名单之外的字段一个字都不能被碰。
// Protocol integrity: nothing outside the allowlist may be touched.
//
// 这是本项目的头号卖点，但它此前只在旧检测器下验证过。复姓识别、
// 证据链的边界拉伸、机构名的逆向补全都会改动实体的 Start/End——
// 而那正是「碰到不该碰的字段」最可能发生的地方。
func TestDocumentIntegrityProbe(t *testing.T) {
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

	// 一份含 PII 的真实请求体，PII 同时出现在白名单内与白名单外
	const payload = `{
	  "model": "gpt-4o",
	  "user": "13812345678",
	  "messages": [
	    {"role": "user", "content": "请联系张伟，手机 13812345678"},
	    {"role": "assistant", "content": [{"type":"text","text":"经办人欧阳志远"},
	                                      {"type":"image_url","image_url":{"url":"https://x.io/13812345678.png"}}]}
	  ],
	  "tools": [{"type":"function","function":{
	      "name": "lookup_13812345678",
	      "description": "查询张伟的订单",
	      "parameters": {"type":"object","properties":{
	          "city": {"type":"string","enum":["杭州","上海"],"description":"客户所在城市，如张伟在杭州"}
	      }}
	  }}]
	}`

	var doc map[string]any
	if err := json.Unmarshal([]byte(payload), &doc); err != nil {
		t.Fatal(err)
	}

	vaults := anonymize.NewVaultRegistry(time.Hour, 10)
	vlt, _ := vaults.Get(anonymize.SessionRef{Tenant: "acme", Session: "s"})
	scope := anonymize.StrategyScope{Tenant: "acme", Vault: vlt}

	err = document.SanitizeDocument(doc, func(text string) (string, error) {
		res, err := r.RedactTo(t.Context(), text, scope, flow)
		if err != nil {
			return "", err
		}
		return res.Text, nil
	})
	if err != nil {
		t.Fatalf("清洗失败：%v", err)
	}

	out, err := document.MarshalPreserving(doc)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	t.Logf("清洗后：\n%s", got)

	// 白名单外的结构字段必须原封不动
	untouched := map[string]string{
		"模型名":       `"model":"gpt-4o"`,
		"消息角色 user": `"role":"user"`,
		"工具名":       `"name":"lookup_13812345678"`,
		"参数枚举值":     `"enum":["杭州","上海"]`,
		"多模态 image": `13812345678.png`,
		"参数类型":      `"type":"string"`,
	}
	for label, want := range untouched {
		if !strings.Contains(strings.ReplaceAll(got, " ", ""), strings.ReplaceAll(want, " ", "")) {
			t.Errorf("白名单外的%s被改动了，期望仍含 %s", label, want)
		}
	}

	// 白名单内的 PII 必须被脱敏
	if strings.Contains(got, `"content":"请联系张伟`) {
		t.Error("消息正文里的 PII 未被脱敏")
	}
	if !strings.Contains(got, "ANONYMIZED_") {
		t.Error("完全没有脱敏发生")
	}

	// top-level "user" 字段不在白名单里 —— 它应当原样保留
	if !strings.Contains(strings.ReplaceAll(got, " ", ""), `"user":"13812345678"`) {
		t.Error("top-level user 字段不在白名单里，不该被改动")
	}
}
