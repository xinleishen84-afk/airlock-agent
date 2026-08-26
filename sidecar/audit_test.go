package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/audit"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
)

// 一组辨识度极高的 PII：任何一个出现在审计事件或管理快照里都是一次泄露。
// Deliberately distinctive PII: any of these appearing in an audit event or an
// admin snapshot is a leak.
var canaries = []string{
	"张伟", "李娜", "星辰科技",
	"zhang.wei@example.com", "13812345678",
	"11010519491231002X", "4111111111111111",
	"conv-zhang.wei@example.com", // 会话 ID 本身就是 PII 的情形
}

type recordingSink struct{ events []audit.Event }

func (r *recordingSink) Name() string { return "recording" }
func (r *recordingSink) Emit(_ interface{ Done() <-chan struct{} }, e audit.Event) error {
	r.events = append(r.events, e)
	return nil
}
func (r *recordingSink) Close() error { return nil }

func auditServer(t *testing.T) (*httptestServer, *recordingSink) {
	t.Helper()
	return nil, nil
}

type httptestServer struct{}

// 审计轨迹里绝不能出现原始 PII —— 包括会话 ID 本身就是 PII 的情形。
// The trail must contain no raw PII, including when the session id is itself
// PII.
func TestAuditTrailCarriesNoPII(t *testing.T) {
	sink := &captureSink{}
	ts := newAuditServer(t, sink)

	// 会话 ID 用邮箱：调用方拿手边有的东西当会话 ID，这是常态
	body := `{"session_id":"conv-zhang.wei@example.com","destination":"public_llm",` +
		`"text":"联系张伟，手机 13812345678，邮箱 zhang.wei@example.com，` +
		`身份证 11010519491231002X，卡号 4111111111111111，公司 星辰科技"}`
	code, resp := asTenant(t, ts, "acme", "/v1/redact", body)
	if code != 200 {
		t.Fatalf("脱敏失败 %d: %s", code, resp)
	}

	_, _ = asTenant(t, ts, "acme", "/v1/restore",
		`{"session_id":"conv-zhang.wei@example.com","text":"是 ANONYMIZED_NAME_0 吗"}`)
	_, _ = asTenant(t, ts, "acme", "/v1/tenant/erase", "")

	dump := sink.dump(t)
	t.Logf("审计轨迹（%d 条事件）：\n%s", len(sink.events), dump)

	if len(sink.events) < 3 {
		t.Fatalf("三次操作应产生至少 3 条事件，实际 %d", len(sink.events))
	}
	for _, canary := range canaries {
		if strings.Contains(dump, canary) {
			t.Errorf("审计轨迹里出现了 %q —— 二次日志泄露", canary)
		}
	}

	// 但宏观统计量必须在：审计轨迹要能证明发生了什么
	if !strings.Contains(dump, `"entities"`) {
		t.Error("事件应携带实体类型计数")
	}
	if !strings.Contains(dump, `"strategies"`) {
		t.Error("事件应携带算子计数")
	}
	if !strings.Contains(dump, `"recognizers"`) {
		t.Error("事件应携带识别器命中数")
	}
	if !strings.Contains(dump, `"session_fingerprint"`) {
		t.Error("事件应携带会话指纹")
	}
	if !strings.Contains(dump, `"action":"tenant_erase"`) {
		t.Error("擦除应产生审计事件")
	}
}

// 管理快照不得包含密钥、盐、映射记录、名册条目或租户名单。
// The admin snapshot must contain no keys, salts, mapping records, roster
// entries or tenant list.
func TestAdminSnapshotCarriesNoSecretsOrPII(t *testing.T) {
	sink := &captureSink{}
	ts := newAuditServer(t, sink)

	_, _ = asTenant(t, ts, "acme", "/v1/redact",
		`{"session_id":"s1","destination":"public_llm","text":"联系张伟，手机 13812345678"}`)

	code, body := getAs(t, ts, "acme", "/v1/admin/inspect")
	if code != 200 {
		t.Fatalf("快照失败 %d: %s", code, body)
	}
	t.Logf("快照：\n%s", indent(t, body))

	// 名册条目就是 PII —— 回显它等于导出 PII
	for _, canary := range canaries {
		if strings.Contains(body, canary) {
			t.Errorf("管理快照里出现了 %q", canary)
		}
	}
	// 密钥材料
	for _, secret := range []string{testRootKey, "hash_key", "salt", "keyring"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(secret)) {
			t.Errorf("管理快照里出现了密钥材料线索 %q", secret)
		}
	}
	// 令牌与占位符映射
	if strings.Contains(body, "ANONYMIZED_") || strings.Contains(body, "[tok:") {
		t.Errorf("管理快照里出现了映射记录：%s", body)
	}

	// 但运营需要的东西必须在
	var snap Snapshot
	if err := json.Unmarshal([]byte(body), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.SchemaVersion != SnapshotSchema {
		t.Errorf("schema 版本不符：%s", snap.SchemaVersion)
	}
	if len(snap.Detection.Jurisdictions) == 0 {
		t.Error("应列出已装配的国家包")
	}
	if len(snap.Detection.Recognizers) == 0 {
		t.Error("应列出识别器健康度")
	}
	if len(snap.Redaction.Destinations) == 0 {
		t.Error("应列出脱敏链路")
	}
	if snap.Detection.RosterSizes["NAME"] != 2 {
		t.Errorf("应报告名册条目数量而非条目本身：%v", snap.Detection.RosterSizes)
	}
	if snap.Isolation.ActiveTenants != 1 {
		t.Errorf("应报告活跃租户数量：%d", snap.Isolation.ActiveTenants)
	}
}

// 命中过的规则与从未命中的规则必须能分开。
// Rules that have fired must be distinguishable from those that never have.
//
// 一条写错的租户规则不报错，它只是安静地什么都不拦。
// 这一列存在，就是为了让「安静」变得可见。
// A wrong tenant rule does not error; it quietly catches nothing.
func TestRecognizerHealthShowsNeverFired(t *testing.T) {
	sink := &captureSink{}
	ts := newAuditServer(t, sink)

	_, _ = asTenant(t, ts, "acme", "/v1/redact",
		`{"session_id":"s1","destination":"public_llm","text":"手机 13812345678"}`)

	_, body := getAs(t, ts, "acme", "/v1/admin/inspect")
	var snap Snapshot
	if err := json.Unmarshal([]byte(body), &snap); err != nil {
		t.Fatal(err)
	}

	var fired, quiet []string
	for _, r := range snap.Detection.Recognizers {
		if r.NeverFired {
			quiet = append(quiet, r.Name)
		} else {
			fired = append(fired, r.Name+"×"+itoa(int(r.Hits)))
		}
	}
	if len(fired) == 0 {
		t.Fatal("应有识别器被记为已命中")
	}
	if len(quiet) == 0 {
		t.Fatal("应有识别器被记为从未命中")
	}
	t.Logf("已命中：%v", fired)
	t.Logf("从未命中（前 5）：%v", quiet[:min(5, len(quiet))])
}

// 快照结构体也要有结构性保证：任何能装下原值的新字段都必须先被论证。
// The snapshot needs the same structural guarantee as the audit event.
func TestSnapshotCarriesNoFreeText(t *testing.T) {
	allowed := map[string]string{
		"SchemaVersion": "常量",
		"Resolver":      "解析器实现名，取自封闭集合",
		"Sink":          "sink 实现名，取自封闭集合",
		"TokenStore":    "驱动种类名，不是内容",
		"Name":          "配置里的链路名 / 识别器名，均来自运维配置",
		"Type":          "实体类型枚举名",
		"Source":        "识别器来源，形如 pack:CN / tenant:acme-corp",
		"Default":       "算子名，取自封闭集合",
	}
	walkNoFreeText(t, reflect.TypeOf(Snapshot{}), allowed, "Snapshot")
}

// walkNoFreeText 递归检查结构体里的每个字符串字段是否被论证过。
func walkNoFreeText(t *testing.T, typ reflect.Type, allowed map[string]string, path string) {
	t.Helper()
	switch typ.Kind() {
	case reflect.Struct:
		if typ == reflect.TypeOf(time.Time{}) {
			return
		}
		for i := range typ.NumField() {
			f := typ.Field(i)
			walkNoFreeText(t, f.Type, allowed, path+"."+f.Name)
			if f.Type.Kind() == reflect.String {
				if _, ok := allowed[f.Name]; !ok {
					t.Errorf("%s.%s 是一个未经论证的字符串字段——"+
						"管理快照会被独立的控制台读取，"+
						"任何能装下原值的字段都是一次导出。"+
						"若确实不可能装下原值，请把理由写进 allowed。", path, f.Name)
				}
			}
		}
	case reflect.Slice, reflect.Ptr:
		walkNoFreeText(t, typ.Elem(), allowed, path+"[]")
	case reflect.Map:
		// map[string]int / map[string]string：键与值均来自内部词表，
		// 逐个在上面的 allowed 里论证过
		if typ.Elem().Kind() == reflect.String && typ.Key().Kind() == reflect.String {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// 装配 / Assembly
// ---------------------------------------------------------------------------

const testRootKey = "0123456789abcdef-0123456789abcdef"

func newAuditServer(t *testing.T, sink audit.Sink) *httptest.Server {
	t.Helper()

	roster := map[detect.EntityType][]string{
		detect.TypeName: {"张伟", "李娜"},
		detect.TypeOrg:  {"星辰科技"},
	}
	gaz, err := detect.NewGazetteerDetector(roster, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	reg := packs.MustNewRegistry([]string{"GEN", "CN"})
	detector := detect.NewCompositeDetector([]detect.Detector{reg, gaz}, 0)

	ring, err := anonymize.NewKeyring([]byte(testRootKey), nil)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := audit.NewFingerprinter(ring)
	if err != nil {
		t.Fatal(err)
	}

	store := anonymize.NewMemoryTokenStore(time.Hour)
	tk, err := anonymize.NewTokenize(store)
	if err != nil {
		t.Fatal(err)
	}
	m := anonymize.NewMatrix()
	m.MustAdd(anonymize.Flow{Name: "public_llm", Default: anonymize.NewMask(), Restores: true})
	m.MustAdd(anonymize.Flow{Name: "pseudonymous", Default: tk, Restores: true})

	resolver, err := NewHeaderTenantResolver(tenantHeader)
	if err != nil {
		t.Fatal(err)
	}

	catalog := make([]RecognizerInfo, 0, len(reg.Names()))
	for _, name := range reg.Names() {
		catalog = append(catalog, RecognizerInfo{Name: name, Source: "pack"})
	}

	srv, err := New(Options{
		Detector: detector, FailClosed: true,
		SessionTTL: time.Hour, MaxSessions: 100,
		Matrix: m, TokenStore: store, TenantResolver: resolver,
		Auditor:           audit.NewRecorder(sink, fp, nil),
		Fingerprinter:     fp,
		Jurisdictions:     []string{"GEN", "CN"},
		RosterSizes:       map[string]int{"NAME": 2, "ORG": 1},
		RecognizerCatalog: catalog,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func getAs(t *testing.T, ts *httptest.Server, tenant, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(tenantHeader, tenant)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

func indent(t *testing.T, raw string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(raw), "", "  "); err != nil {
		return raw
	}
	return buf.String()
}

type captureSink struct{ events []audit.Event }

func (c *captureSink) Name() string { return "capture" }
func (c *captureSink) Emit(_ context.Context, e audit.Event) error {
	c.events = append(c.events, e)
	return nil
}
func (c *captureSink) Close() error { return nil }

func (c *captureSink) dump(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, e := range c.events {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String()
}
