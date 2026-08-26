package sidecar

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
)

const tenantHeader = "X-Tenant-Id"

// tenantServer 是启用了租户隔离的测试服务器。
func tenantServer(t *testing.T) (*httptest.Server, *anonymize.MemoryTokenStore) {
	t.Helper()

	gaz, err := detect.NewGazetteerDetector(map[detect.EntityType][]string{
		detect.TypeName: {"张伟", "李娜"},
	}, false, 2)
	if err != nil {
		t.Fatal(err)
	}
	detector := detect.NewCompositeDetector(
		[]detect.Detector{packs.MustNewRegistry([]string{"GEN", "CN"}), gaz}, 0)

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
	srv, err := New(Options{
		Detector: detector, FailClosed: true,
		SessionTTL: time.Hour, MaxSessions: 100,
		Matrix: m, TokenStore: store, TenantResolver: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, store
}

func asTenant(t *testing.T, ts *httptest.Server, tenant, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if tenant != "" {
		req.Header.Set(tenantHeader, tenant)
	}
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

// 本文件存在的理由：这个漏洞曾经是活的。
// The reason this file exists: this hole was live.
//
// 在引入租户之前，会话保险库只以调用方提供的 session_id 作键。
// 租户 B 拿同一个 session_id 调 /v1/restore，会原样拿回租户 A 的
// 姓名和手机号明文——不是令牌、不是摘要，是值本身。
// 这比令牌库的越权更严重：令牌至少还要先有一个令牌。
//
// Before tenants existed, the vault was keyed by a caller-supplied session_id
// alone. Tenant B calling /v1/restore with the same id got tenant A's name and
// phone number back in plaintext — not a token, not a digest, the value.
func TestCrossTenantRestoreIsBlocked(t *testing.T) {
	ts, _ := tenantServer(t)

	code, redacted := asTenant(t, ts, "tenant-a", "/v1/redact",
		`{"session_id":"conv-42","destination":"public_llm","text":"联系张伟，手机 13812345678"}`)
	if code != http.StatusOK {
		t.Fatalf("租户 A 脱敏失败 %d: %s", code, redacted)
	}
	if !strings.Contains(redacted, "ANONYMIZED_NAME_0") {
		t.Fatalf("脱敏结果不符：%s", redacted)
	}

	// 租户 A 自己能还原
	_, own := asTenant(t, ts, "tenant-a", "/v1/restore",
		`{"session_id":"conv-42","text":"是 ANONYMIZED_NAME_0，号码 ANONYMIZED_PHONE_0"}`)
	if !strings.Contains(own, "张伟") || !strings.Contains(own, "13812345678") {
		t.Fatalf("租户 A 应能还原自己的数据：%s", own)
	}

	// 租户 B 用同一个 session_id：必须什么也拿不到
	_, other := asTenant(t, ts, "tenant-b", "/v1/restore",
		`{"session_id":"conv-42","text":"是 ANONYMIZED_NAME_0，号码 ANONYMIZED_PHONE_0"}`)
	if strings.Contains(other, "张伟") || strings.Contains(other, "13812345678") {
		t.Fatalf("越权：租户 B 拿到了租户 A 的 PII：%s", other)
	}
	if !strings.Contains(other, "ANONYMIZED_NAME_0") {
		t.Fatalf("无法解析的占位符应原样保留：%s", other)
	}
	t.Logf("租户 B 得到：%s", other)
}

// 令牌层的同一问题：拿到令牌串也不该跨租户解析。
// The same at the token layer: holding the token string must not be enough.
func TestCrossTenantTokenResolveIsBlocked(t *testing.T) {
	ts, _ := tenantServer(t)

	_, redacted := asTenant(t, ts, "tenant-a", "/v1/redact",
		`{"session_id":"s1","destination":"pseudonymous","text":"邮箱 a.b@example.com"}`)
	var out RedactResponse
	if err := json.Unmarshal([]byte(redacted), &out); err != nil {
		t.Fatal(err)
	}
	tok := out.Text[strings.Index(out.Text, "[tok:"):]
	t.Logf("租户 A 的令牌：%s", tok)

	_, own := asTenant(t, ts, "tenant-a", "/v1/restore",
		`{"session_id":"s1","text":"已发送到 `+tok+`"}`)
	if !strings.Contains(own, "a.b@example.com") {
		t.Fatalf("租户 A 应能解析自己的令牌：%s", own)
	}

	_, other := asTenant(t, ts, "tenant-b", "/v1/restore",
		`{"session_id":"s1","text":"已发送到 `+tok+`"}`)
	if strings.Contains(other, "a.b@example.com") {
		t.Fatalf("越权：租户 B 解析出了租户 A 的令牌：%s", other)
	}
	t.Logf("租户 B 得到：%s", other)
}

// 同一个值在两个租户下必须得到不同的令牌。
// The same value must get different tokens in different tenants.
func TestSameValueDifferentTokenPerTenant(t *testing.T) {
	ts, _ := tenantServer(t)

	const body = `{"session_id":"s","destination":"pseudonymous","text":"邮箱 a.b@example.com"}`
	_, a := asTenant(t, ts, "tenant-a", "/v1/redact", body)
	_, b := asTenant(t, ts, "tenant-b", "/v1/redact", body)

	tokA := a[strings.Index(a, "[tok:") : strings.Index(a, "]")+1]
	tokB := b[strings.Index(b, "[tok:") : strings.Index(b, "]")+1]
	if tokA == tokB {
		t.Fatalf("两个租户的同一个值不应共用令牌：%s", tokA)
	}
	t.Logf("A=%s  B=%s", tokA, tokB)
}

// 解析不出租户必须阻断，不能回退到默认租户。
// An unresolvable tenant must block, never fall back to a default.
func TestMissingTenantHeaderBlocks(t *testing.T) {
	ts, _ := tenantServer(t)
	code, body := asTenant(t, ts, "", "/v1/redact",
		`{"session_id":"s","destination":"public_llm","text":"手机 13812345678"}`)
	if code != http.StatusForbidden {
		t.Fatalf("缺租户头部应返回 403，实际 %d：%s", code, body)
	}
	t.Logf("按预期拒绝：%s", body)
}

// 非法租户标识必须拒绝：分隔字节会让一个租户构造出与另一个撞车的键。
// An invalid tenant must be rejected: the separator byte would let one tenant
// construct a key that collides with another's.
func TestInvalidTenantRejected(t *testing.T) {
	ts, _ := tenantServer(t)
	for _, bad := range []string{"tenant a", "-leading-dash", strings.Repeat("x", 65)} {
		code, body := asTenant(t, ts, bad, "/v1/redact",
			`{"session_id":"s","destination":"public_llm","text":"手机 13812345678"}`)
		if code != http.StatusForbidden {
			t.Errorf("非法租户 %q 应被拒绝，实际 %d：%s", bad, code, body)
		}
	}
}

// GDPR 第 17 条：擦除只清当前租户，且必须给出可作为证据的条数。
// Article 17: erase this tenant only, with counts that can serve as evidence.
func TestTenantEraseIsPreciseAndEvidenced(t *testing.T) {
	ts, store := tenantServer(t)

	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		_, _ = asTenant(t, ts, tenant, "/v1/redact",
			`{"session_id":"s1","destination":"pseudonymous","text":"邮箱 a.b@example.com"}`)
		_, _ = asTenant(t, ts, tenant, "/v1/redact",
			`{"session_id":"s2","destination":"public_llm","text":"联系张伟"}`)
	}
	if store.Size() != 2 {
		t.Fatalf("两个租户各自签发令牌后应有 2 条，实际 %d", store.Size())
	}

	code, body := asTenant(t, ts, "tenant-a", "/v1/tenant/erase", "")
	if code != http.StatusOK {
		t.Fatalf("擦除失败 %d：%s", code, body)
	}
	var res EraseResponse
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	t.Logf("擦除回执：%+v", res)

	if res.Tenant != "tenant-a" {
		t.Errorf("回执租户不符：%s", res.Tenant)
	}
	if res.SessionsErased != 2 {
		t.Errorf("应擦除 2 个会话映射，实际 %d", res.SessionsErased)
	}
	if res.TokensErased != 1 {
		t.Errorf("应擦除 1 个令牌，实际 %d", res.TokensErased)
	}

	// 租户 B 的数据必须毫发无损
	_, b := asTenant(t, ts, "tenant-b", "/v1/restore",
		`{"session_id":"s2","text":"是 ANONYMIZED_NAME_0"}`)
	if !strings.Contains(b, "张伟") {
		t.Fatalf("擦除污染了租户 B 的数据：%s", b)
	}
	if store.Size() != 1 {
		t.Errorf("租户 B 的令牌应仍在，库内 %d 条", store.Size())
	}

	// 租户 A 的数据必须真的没了
	_, a := asTenant(t, ts, "tenant-a", "/v1/restore",
		`{"session_id":"s2","text":"是 ANONYMIZED_NAME_0"}`)
	if strings.Contains(a, "张伟") {
		t.Fatalf("擦除后仍能还原出租户 A 的数据：%s", a)
	}
}

// 单租户部署必须显式声明，而不是靠「不配就没有隔离」。
// A single-tenant deployment must be declared, not defaulted into.
func TestTenantResolverIsRequired(t *testing.T) {
	_, err := New(Options{
		Detector:   packs.MustNewRegistry([]string{"GEN"}),
		SessionTTL: time.Hour, MaxSessions: 10,
	})
	if err == nil {
		t.Fatal("缺少租户解析器应拒绝启动")
	}
	if !strings.Contains(err.Error(), "TenantResolver") {
		t.Fatalf("报错应点名 TenantResolver：%v", err)
	}
	t.Logf("按预期拒绝：%v", err)
}
