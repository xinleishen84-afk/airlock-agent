package config

import (
	"strings"
	"testing"
	"time"
)

// 一份最小可用配置，各用例在其上注入单点缺陷。
const baseYAML = `
secrets_mount_path: /tmp/secrets
targets:
  - name: t1
    tier: 1
    base_url: http://backend-a:8000/v1
    model: premium
    credential_key: vendor-key
    input_price_per_mtok: 5.0
    output_price_per_mtok: 25.0
  - name: t2
    tier: 2
    base_url: http://backend-b:8000/v1
    model: local
    self_hosted: true
rules:
  - name: batch
    target_tier: 2
    priority: 10
    match_apps: ["toolbench-agent"]
rate_limit:
  tokens_per_window: 1000000
  window: 1m
pii:
  fail_closed: true
  jurisdictions: [GEN, CN]
  session_consistency: single-replica
  name_roster: ["张伟"]
gpu:
  kv_elevated: 0.75
  kv_critical: 0.9
  prefix_affinity: true
`

// load 解析一段 YAML。
func load(t *testing.T, y string) (*Config, error) {
	t.Helper()
	return Decode(strings.NewReader(y), "test.yaml")
}

// mustLoad 解析并断言成功。
func mustLoad(t *testing.T, y string) *Config {
	t.Helper()
	c, err := load(t, y)
	if err != nil {
		t.Fatalf("配置应能解析：%v", err)
	}
	return c
}

// TestBaseConfigLoads 校验基准配置可解析。
func TestBaseConfigLoads(t *testing.T) {
	c := mustLoad(t, baseYAML)
	if len(c.Targets) != 2 || c.Targets[0].Name != "t1" {
		t.Errorf("后端解析错误: %+v", c.Targets)
	}
	if c.RateLimit.Window.Std() != time.Minute {
		t.Errorf("时长解析错误: %v", c.RateLimit.Window)
	}
}

// ---------------------------------------------------------------------------
// 第 1 层：未知字段
// ---------------------------------------------------------------------------

// TestUnknownFieldRejected 校验拼错的键被拒绝。
//
// 静默忽略会让「我明明配了限流」变成最难查的一类事故：
// 配置文件里白纸黑字写着配额，运行时却是无限制。
func TestUnknownFieldRejected(t *testing.T) {
	cases := map[string]string{
		"顶层":   strings.Replace(baseYAML, "targets:", "target:", 1),
		"嵌套":   strings.Replace(baseYAML, "tokens_per_window:", "token_per_window:", 1),
		"数组元素": strings.Replace(baseYAML, "    model: premium", "    modle: premium", 1),
	}
	for name, y := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, y)
			if err == nil {
				t.Fatal("拼错的键必须被拒绝，否则会被静默忽略")
			}
			if !strings.Contains(err.Error(), "拼写错误") {
				t.Errorf("报错应提示这是拼写错误：%v", err)
			}
		})
	}
}

// TestMultiDocumentRejected 校验多文档配置被拒。
// 从 K8s manifest 复制粘贴时很容易带上 ---，静默只取第一个会让后面的配置神秘失效。
func TestMultiDocumentRejected(t *testing.T) {
	if _, err := load(t, baseYAML+"\n---\nmax_sessions: 999\n"); err == nil {
		t.Error("多文档配置应被拒绝")
	}
}

// ---------------------------------------------------------------------------
// 第 2 层：枚举与时长
// ---------------------------------------------------------------------------

// TestMisspelledEntityTypeRejected 锁定那个静默泄露路径。
//
// NER 配置里把 NAME 拼成 NAEM：网关不再向 NER 申请人名识别，
// 姓名从此裸奔；而覆盖度自检因为看到了「NAEM」这个类型，
// 反而报告「无缺口」。没有任何报错、任何告警。
func TestMisspelledEntityTypeRejected(t *testing.T) {
	y := strings.Replace(baseYAML, `  name_roster: ["张伟"]`,
		"  name_roster: [\"张伟\"]\n"+
			"  ner:\n"+
			"    endpoint: http://ner:8000/v1/detect\n"+
			"    types: [\"NAEM\", \"ADDRESS\"]", 1)
	_, err := load(t, y)
	if err == nil {
		t.Fatal("拼错的实体类型必须被拒绝——否则该类型的 PII 会静默泄露")
	}
	if !strings.Contains(err.Error(), "NAEM") || !strings.Contains(err.Error(), "NAME") {
		t.Errorf("报错应指出错在哪并列出合法取值：%v", err)
	}
}

// TestMisspelledTaskRejected 校验拼错的任务类型被拒。
// 规则里的任务类型拼错会让规则永久失配——批量作业一路走到昂贵的 Tier1。
func TestMisspelledTaskRejected(t *testing.T) {
	y := strings.Replace(baseYAML,
		`    match_apps: ["toolbench-agent"]`,
		`    match_tasks: ["extration"]`, 1)
	_, err := load(t, y)
	if err == nil {
		t.Fatal("拼错的任务类型必须被拒绝——否则规则永久失配")
	}
	if !strings.Contains(err.Error(), "extraction") {
		t.Errorf("报错应列出正确拼写：%v", err)
	}
}

// TestDisabledTypeMisspellRejected 校验 disabled_types 的拼写错误被拒。
func TestDisabledTypeMisspellRejected(t *testing.T) {
	y := strings.Replace(baseYAML, `  name_roster: ["张伟"]`,
		"  disabled_types: [\"EMIAL\"]", 1)
	if _, err := load(t, y); err == nil {
		t.Error("拼错的 disabled_types 必须被拒绝")
	}
}

// TestBareNumberDurationRejected 校验裸数字时长被拒。
//
// 纳秒整数无法人工复核：60000000000 与 6000000000 差 10 倍，肉眼看不出。
// 而写 300 又有单位歧义——纳秒？毫秒？秒？
func TestBareNumberDurationRejected(t *testing.T) {
	y := strings.Replace(baseYAML, "  window: 1m", "  window: 60000000000", 1)
	_, err := load(t, y)
	if err == nil {
		t.Fatal("裸数字时长必须被拒绝")
	}
	msg := err.Error()
	if !strings.Contains(msg, "单位") && !strings.Contains(msg, "非法时长") {
		t.Errorf("报错应说明时长格式问题：%v", err)
	}
}

// TestInvalidDurationUnitRejected 校验非法单位被拒。
func TestInvalidDurationUnitRejected(t *testing.T) {
	for _, bad := range []string{"300mss", "5 seconds", "1x", "-3s"} {
		y := strings.Replace(baseYAML, "  window: 1m", "  window: "+bad, 1)
		if _, err := load(t, y); err == nil {
			t.Errorf("非法时长 %q 应被拒绝", bad)
		}
	}
}

// TestZeroDurationIndistinguishableFromUnset 记录一个已知的语义边界。
//
// 显式写 `window: 0s` 与「不写 window」在 Go 里都是零值，applyDefaults
// 无法区分，会一律补上默认值。对时长这类字段这不是问题——0 时长本来就
// 没有合理语义（0 秒窗口 = 除零）。但若将来有字段的 0 是有效取值，
// 必须改用指针或 sql.Null 式的包装类型来区分「未设置」与「设为零」。
func TestZeroDurationIndistinguishableFromUnset(t *testing.T) {
	y := strings.Replace(baseYAML, "  window: 1m", "  window: 0s", 1)
	c := mustLoad(t, y)
	if c.RateLimit.Window.Std() != time.Minute {
		t.Errorf("显式 0s 会被默认值覆盖（已知语义边界），实际 %v", c.RateLimit.Window)
	}
}

// TestValidDurationFormats 校验合法时长格式都被接受。
func TestValidDurationFormats(t *testing.T) {
	for raw, want := range map[string]time.Duration{
		"300ms": 300 * time.Millisecond,
		"5s":    5 * time.Second,
		"1h30m": 90 * time.Minute,
	} {
		y := strings.Replace(baseYAML, "  window: 1m", "  window: "+raw, 1)
		c, err := load(t, y)
		if err != nil {
			t.Errorf("%q 应被接受：%v", raw, err)
			continue
		}
		if c.RateLimit.Window.Std() != want {
			t.Errorf("%q 解析为 %v，期望 %v", raw, c.RateLimit.Window, want)
		}
	}
}

// TestTierOutOfRangeRejected 校验越界梯队被拒。
func TestTierOutOfRangeRejected(t *testing.T) {
	for _, bad := range []string{"0", "-1", "99"} {
		y := strings.Replace(baseYAML, "    tier: 1", "    tier: "+bad, 1)
		if _, err := load(t, y); err == nil {
			t.Errorf("梯队 %s 越界应被拒绝", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// 第 3 层：语义校验
// ---------------------------------------------------------------------------

// TestSemanticErrorsReportedTogether 校验一次报出全部语义问题。
// 运维希望一次改完，而不是修一个跑一次。
func TestSemanticErrorsReportedTogether(t *testing.T) {
	y := strings.NewReplacer(
		"  kv_elevated: 0.75", "  kv_elevated: 0.95",
		"  kv_critical: 0.9", "  kv_critical: 0.7",
		"    target_tier: 2", "    target_tier: 7",
	).Replace(baseYAML)

	_, err := load(t, y)
	if err == nil {
		t.Fatal("应报出语义错误")
	}
	msg := err.Error()
	for _, want := range []string{"kv_critical", "target_tier"} {
		if !strings.Contains(msg, want) {
			t.Errorf("应同时报出 %s 的问题：%v", want, msg)
		}
	}
	if !strings.Contains(msg, "共 2 处") {
		t.Errorf("应汇总问题数量：%v", msg)
	}
}

// TestSelfHostedWithPriceRejected 校验自建集群误登记单价被拒。
// 那会让 GPU 摊销成本被当成公有云支出，错误消耗 Tier1 预算。
func TestSelfHostedWithPriceRejected(t *testing.T) {
	y := strings.Replace(baseYAML,
		"    self_hosted: true",
		"    self_hosted: true\n    input_price_per_mtok: 2.0\n    output_price_per_mtok: 10.0", 1)
	_, err := load(t, y)
	if err == nil || !strings.Contains(err.Error(), "GPU 摊销") {
		t.Errorf("自建集群登记单价应被拒绝：%v", err)
	}
}

// TestHalfPriceRejected 校验只登记单边价格被拒（几乎总是漏配）。
func TestHalfPriceRejected(t *testing.T) {
	y := strings.Replace(baseYAML, "    output_price_per_mtok: 25.0", "", 1)
	if _, err := load(t, y); err == nil {
		t.Error("只登记输入单价应被拒绝——成本核算会只算一半")
	}
}

// TestCatchAllRuleRejected 校验无条件规则被拒。
// 一条什么都不匹配的规则会命中所有请求，把其后所有规则屏蔽掉。
func TestCatchAllRuleRejected(t *testing.T) {
	y := strings.Replace(baseYAML, `    match_apps: ["toolbench-agent"]`, "", 1)
	if _, err := load(t, y); err == nil {
		t.Error("无匹配条件的规则应被拒绝")
	}
}

// TestInvalidGlobRejected 校验非法 glob 被拒。
func TestInvalidGlobRejected(t *testing.T) {
	y := strings.Replace(baseYAML, `["toolbench-agent"]`, `["[未闭合"]`, 1)
	if _, err := load(t, y); err == nil {
		t.Error("非法 glob 应被拒绝——运行时会静默失配")
	}
}

// TestDuplicateNamesRejected 校验重名被拒。
func TestDuplicateNamesRejected(t *testing.T) {
	y := strings.Replace(baseYAML, "  - name: t2", "  - name: t1", 1)
	if _, err := load(t, y); err == nil {
		t.Error("后端重名应被拒绝——路由与熔断按名索引，会互相覆盖")
	}
}

// TestBadBaseURLRejected 校验非法 base_url 被拒。
func TestBadBaseURLRejected(t *testing.T) {
	for _, bad := range []string{"backend-a:8000", "ftp://x/v1", "http:///v1"} {
		y := strings.Replace(baseYAML, "http://backend-a:8000/v1", bad, 1)
		if _, err := load(t, y); err == nil {
			t.Errorf("非法 base_url %q 应被拒绝", bad)
		}
	}
}

// TestShortReservationTTLRejected 校验预留 TTL 过短被拒。
// 长流会在结算前被清扫，配额重复释放导致限流实际失效。
func TestShortReservationTTLRejected(t *testing.T) {
	y := strings.Replace(baseYAML, "  window: 1m", "  window: 1m\n  reservation_ttl: 1s", 1)
	if _, err := load(t, y); err == nil {
		t.Error("预留 TTL 远短于窗口应被拒绝")
	}
}

// ---------------------------------------------------------------------------
// 告警（不阻断）
// ---------------------------------------------------------------------------

// TestWarningsDoNotBlock 校验配置「选择」只告警不阻断。
func TestWarningsDoNotBlock(t *testing.T) {
	y := strings.NewReplacer(
		"  fail_closed: true", "  fail_closed: false",
		`  name_roster: ["张伟"]`, "",
		"  prefix_affinity: true", "  prefix_affinity: false",
	).Replace(baseYAML)

	c, err := load(t, y)
	if err != nil {
		t.Fatalf("这些是配置选择而非错误，不应阻断：%v", err)
	}
	warns := c.Warn()
	if len(warns) < 3 {
		t.Errorf("应产出多条告警，实际 %d 条：%v", len(warns), warns)
	}
	joined := ""
	for _, w := range warns {
		joined += w.Error()
	}
	for _, want := range []string{"泄露风险", "裸奔", "prefix caching"} {
		if !strings.Contains(joined, want) {
			t.Errorf("告警应说清后果，缺少 %q：%v", want, warns)
		}
	}
}

// ---------------------------------------------------------------------------
// Schema / CRD
// ---------------------------------------------------------------------------

// TestSchemaRejectsUnknownAtEveryLevel 校验每个对象层级都设了
// additionalProperties: false——这是 APIServer 侧拦截的关键。
func TestSchemaRejectsUnknownAtEveryLevel(t *testing.T) {
	var check func(path string, s *Schema)
	checked := 0
	check = func(path string, s *Schema) {
		if s.Type == "object" && len(s.Properties) > 0 {
			checked++
			if v, ok := s.AdditionalProperties.(bool); !ok || v {
				t.Errorf("%s 未设 additionalProperties: false，APIServer 会放行未知字段", path)
			}
		}
		for name, child := range s.Properties {
			check(path+"."+name, child)
		}
		if s.Items != nil {
			check(path+"[]", s.Items)
		}
	}
	check("spec", GenerateSchema())
	if checked < 8 {
		t.Errorf("检查到的对象层级过少（%d），schema 生成可能不完整", checked)
	}
}

// TestSchemaCarriesEnums 校验枚举约束进入了 schema。
// 没有它，kubectl apply 会放行 types: ["NAEM"]，拦截退回到进程启动时。
func TestSchemaCarriesEnums(t *testing.T) {
	s := GenerateSchema()
	ner := s.Properties["pii"].Properties["ner"]
	types := ner.Properties["types"]
	if types.Items == nil || len(types.Items.Enum) == 0 {
		t.Fatal("pii.ner.types 应带枚举约束")
	}
	found := false
	for _, e := range types.Items.Enum {
		if e == "NAME" {
			found = true
		}
	}
	if !found {
		t.Errorf("枚举应含 NAME：%v", types.Items.Enum)
	}
}

// TestSchemaCarriesDurationPattern 校验时长字段带格式约束。
func TestSchemaCarriesDurationPattern(t *testing.T) {
	s := GenerateSchema()
	w := s.Properties["rate_limit"].Properties["window"]
	if w.Type != "string" || w.Pattern == "" {
		t.Errorf("时长字段应是带 pattern 的 string：%+v", w)
	}
}

// TestInlineFieldsHoisted 校验内嵌结构体的字段被提升到父层。
// 若没提升，生成的 schema 会多出一层不存在的嵌套，APIServer 会拒绝合法配置。
func TestInlineFieldsHoisted(t *testing.T) {
	s := GenerateSchema()
	rl := s.Properties["rate_limit"]
	if _, ok := rl.Properties["tokens_per_window"]; !ok {
		t.Errorf("内嵌的 LimitConfig 字段未提升到 rate_limit 下：%v", rl.Properties)
	}
	if _, ok := rl.Properties["per_subject"]; !ok {
		t.Error("per_subject 丢失")
	}
}

// TestCRDGenerates 校验 CRD 可生成且结构完整。
func TestCRDGenerates(t *testing.T) {
	out, err := GenerateCRD(DefaultCRDOptions())
	if err != nil {
		t.Fatalf("生成 CRD 失败: %v", err)
	}
	body := string(out)
	for _, want := range []string{
		"apiextensions.k8s.io/v1", "CustomResourceDefinition",
		"AirlockConfig", "openAPIV3Schema", "additionalProperties: false",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("CRD 缺少 %q", want)
		}
	}
}

// 未选司法管辖区必须阻断启动。
// No jurisdiction selected must block startup.
//
// 这条用例存在的理由是：这种配置的失败形态是「一切正常，零 PII」。
// 它不会崩、不会报错、审计日志干干净净——直到监管机构来问。
// The failure mode of this configuration is "everything fine, zero PII":
// nothing crashes, nothing errors, the audit log is spotless — until a
// regulator asks.
func TestMissingJurisdictionBlocksStartup(t *testing.T) {
	y := strings.Replace(baseYAML, "  jurisdictions: [GEN, CN]\n", "", 1)
	if _, err := load(t, y); err == nil {
		t.Fatal("未指定国家包应阻断启动")
	} else if !strings.Contains(err.Error(), "pii.jurisdictions") {
		t.Fatalf("报错应指向 pii.jurisdictions，实际：%v", err)
	}
}

// 拼错的国家包代码同样必须阻断，而不是静默跳过。
// A misspelled pack code must block too, not be silently skipped.
func TestUnknownJurisdictionBlocksStartup(t *testing.T) {
	y := strings.Replace(baseYAML, "[GEN, CN]", "[GEN, GB]", 1)
	_, err := load(t, y)
	if err == nil {
		t.Fatal("未知国家包应阻断启动")
	}
	if !strings.Contains(err.Error(), `"GB"`) {
		t.Fatalf("报错应点名 GB，实际：%v", err)
	}
	t.Logf("按预期拒绝：%v", err)
}

// TestMissingSessionConsistencyRejected 校验会话一致性声明必填。
// Verifies the session-consistency declaration is required.
//
// 缺省不能选任何一边：猜「单副本」会让多副本部署静默串号，猜「有亲和」
// 会让单副本部署背上一个并不存在的承诺。这条约束此前只写在 README 里，
// 而出货的 deploy/core.yaml 是 replicas: 3——没人执行的注记不是控制措施。
//
// Neither value is safe as a default: assuming single-replica lets a
// multi-replica deployment silently cross-number sessions, and assuming
// affinity records a guarantee nobody made. The constraint used to live only in
// the README while the shipped manifest set replicas: 3.
func TestMissingSessionConsistencyRejected(t *testing.T) {
	y := strings.Replace(baseYAML, "  session_consistency: single-replica\n", "", 1)
	if y == baseYAML {
		t.Fatal("测试夹具里没有 session_consistency，前提不成立")
	}
	if _, err := load(t, y); err == nil {
		t.Fatal("未声明会话一致性应阻断启动")
	} else if !strings.Contains(err.Error(), "pii.session_consistency") {
		t.Fatalf("报错应指向 pii.session_consistency，实际：%v", err)
	}
}

// TestSessionConsistencyRejectsUnknownValue 校验拼错的取值不会被当成默认。
func TestSessionConsistencyRejectsUnknownValue(t *testing.T) {
	y := strings.Replace(baseYAML,
		"  session_consistency: single-replica",
		"  session_consistency: sticky", 1)
	if _, err := load(t, y); err == nil {
		t.Fatal("拼错的取值应被拒绝")
	} else if !strings.Contains(err.Error(), "sticky") {
		t.Fatalf("报错应回显拼错的取值，实际：%v", err)
	}
}
