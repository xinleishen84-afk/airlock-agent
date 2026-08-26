package credential

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sprint / sprintf 是 fmt 的薄封装，用于验证 Secret 在各种格式化路径下都不泄露。
func sprint(v any) string            { return fmt.Sprint(v) }
func sprintf(f string, v any) string { return fmt.Sprintf(f, v) }

// TestSecretNeverLeaksInFormatting 校验凭证不会被日志或格式化带出。
func TestSecretNeverLeaksInFormatting(t *testing.T) {
	s := Secret{value: "sk-super-secret-value", source: "test"}
	for _, rendered := range []string{
		s.String(),
		strings.TrimSpace(sprint(s)),
		sprintf("%v", s),
		sprintf("%s", s),
	} {
		if strings.Contains(rendered, "sk-super-secret-value") {
			t.Errorf("凭证明文泄露到格式化输出: %s", rendered)
		}
		if !strings.Contains(rendered, "fp=") {
			t.Errorf("格式化输出应含指纹: %s", rendered)
		}
	}
	if s.Reveal() != "sk-super-secret-value" {
		t.Error("Reveal 应返回明文")
	}
}

// TestCredentialHeaderClassification 校验凭证类头部识别。
func TestCredentialHeaderClassification(t *testing.T) {
	credentials := []string{
		"authorization", "X-API-Key", "x-vault-token", "my-service-apikey",
		"x-foo-secret", "proxy-authorization", "Cookie", "x-goog-api-key",
	}
	for _, n := range credentials {
		if !IsCredentialHeader(n) {
			t.Errorf("%q 应被识别为凭证头", n)
		}
	}
	safe := []string{"content-type", "x-request-id", "user-agent", "x-workload-app", "accept"}
	for _, n := range safe {
		if IsCredentialHeader(n) {
			t.Errorf("%q 不应被识别为凭证头", n)
		}
	}
}

// TestStripRemovesAllClientCredentials 校验客户端自携凭证一律剥离。
func TestStripRemovesAllClientCredentials(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer sk-DEV-LEAKED")
	h.Set("X-Api-Key", "stolen-key")
	h.Set("X-Goog-Api-Key", "another")
	h.Set("Cookie", "session=abc")
	h.Set("X-Custom-Token", "t")
	h.Set("X-Request-Id", "keep-me")
	h.Set("Content-Type", "application/json")

	res := Strip(h)
	if len(res.Stripped) != 5 {
		t.Errorf("应剥离 5 个凭证头，实际 %v", res.Stripped)
	}
	if h.Get("Authorization") != "" || h.Get("X-Api-Key") != "" {
		t.Error("凭证头未被删除")
	}
	if h.Get("X-Request-Id") != "keep-me" || h.Get("Content-Type") == "" {
		t.Error("非凭证头被误删")
	}
}

// TestApplyInjectsEnterpriseCredential 校验注入的是企业凭证。
func TestApplyInjectsEnterpriseCredential(t *testing.T) {
	p := &BackendPolicy{
		Name: "t1", Provider: NewStaticProvider(map[string]string{"k": "sk-ENTERPRISE"}),
		SecretKey: "k", Mode: InjectBearer,
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer sk-DEV-LEAKED")
	h.Set("X-Request-Id", "r1")

	strip, secret, err := p.Apply(h)
	if err != nil {
		t.Fatalf("注入失败: %v", err)
	}
	if h.Get("Authorization") != "Bearer sk-ENTERPRISE" {
		t.Errorf("应注入企业凭证，实际 %q", h.Get("Authorization"))
	}
	if len(strip.Stripped) != 1 {
		t.Errorf("应剥离 1 个头，实际 %v", strip.Stripped)
	}
	if secret.Fingerprint() == "" {
		t.Error("应返回可审计的指纹")
	}
	if h.Get("X-Request-Id") != "r1" {
		t.Error("非凭证头应保留")
	}
}

// TestInjectHeaderMode 校验自定义头注入模式。
func TestInjectHeaderMode(t *testing.T) {
	p := &BackendPolicy{
		Name: "t", Provider: NewStaticProvider(map[string]string{"k": "sk-X"}),
		SecretKey: "k", Mode: InjectHeader, HeaderName: "X-Api-Key",
	}
	h := http.Header{}
	if _, _, err := p.Apply(h); err != nil {
		t.Fatalf("注入失败: %v", err)
	}
	if h.Get("X-Api-Key") != "sk-X" {
		t.Errorf("应写入自定义头，实际 %q", h.Get("X-Api-Key"))
	}
	if h.Get("Authorization") != "" {
		t.Error("头部注入模式不应写 Authorization")
	}
}

// TestSecretFailureBlocksRequest 校验取不到凭证时阻断。
func TestSecretFailureBlocksRequest(t *testing.T) {
	p := &BackendPolicy{
		Name: "t", Provider: NewStaticProvider(map[string]string{}),
		SecretKey: "missing", Mode: InjectBearer,
	}
	if _, _, err := p.Apply(http.Header{}); !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("凭证缺失应阻断，得到 %v", err)
	}
}

// TestVerifyDetectsLeakedHeader 校验终检能发现绕过策略残留的凭证头。
func TestVerifyDetectsLeakedHeader(t *testing.T) {
	p := &BackendPolicy{
		Name: "t", Provider: NewStaticProvider(map[string]string{"k": "sk-X"}),
		SecretKey: "k", Mode: InjectBearer,
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer sk-X")
	h.Set("X-Api-Key", "sneaked-in") // 绕过 Strip 混进来的
	if err := p.Verify(h); !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("终检应拦下残留凭证头，得到 %v", err)
	}
}

// TestVerifyDetectsMissingInjection 校验声明注入但实际未注入会被发现。
func TestVerifyDetectsMissingInjection(t *testing.T) {
	p := &BackendPolicy{Name: "t", SecretKey: "k", Mode: InjectBearer,
		Provider: NewStaticProvider(map[string]string{"k": "v"})}
	if err := p.Verify(http.Header{}); !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("缺失注入应被终检发现，得到 %v", err)
	}
}

// TestFileProviderStripsNewline 校验 K8s 挂载文件的末尾换行被剥掉。
func TestFileProviderStripsNewline(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "key"), []byte("sk-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewFileProvider(dir).Fetch("key")
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if s.Reveal() != "sk-value" {
		t.Errorf("末尾换行未剥离: %q", s.Reveal())
	}
}

// TestFileProviderBlocksTraversal 校验密钥名不允许路径穿越。
func TestFileProviderBlocksTraversal(t *testing.T) {
	p := NewFileProvider(t.TempDir())
	for _, key := range []string{"../../etc/passwd", "sub/key", "..", ""} {
		if _, err := p.Fetch(key); !errors.Is(err, ErrSecretUnavailable) {
			t.Errorf("非法密钥名 %q 应被拒，得到 %v", key, err)
		}
	}
}

// TestCachingReducesUpstreamCalls 校验缓存命中期间不回源。
func TestCachingReducesUpstreamCalls(t *testing.T) {
	inner := &countingProvider{StaticProvider: NewStaticProvider(map[string]string{"k": "v"})}
	cached := NewCachingProvider(inner, time.Hour)
	for i := 0; i < 5; i++ {
		if _, err := cached.Fetch("k"); err != nil {
			t.Fatal(err)
		}
	}
	if inner.calls != 1 {
		t.Errorf("应只回源 1 次，实际 %d", inner.calls)
	}
	cached.Invalidate("")
	cached.Fetch("k")
	if inner.calls != 2 {
		t.Errorf("失效后应重新回源，实际 %d", inner.calls)
	}
}

// countingProvider 记录回源次数。
type countingProvider struct {
	*StaticProvider
	calls int
}

// Fetch 计数后回源。
func (p *countingProvider) Fetch(key string) (Secret, error) {
	p.calls++
	return p.StaticProvider.Fetch(key)
}

// TestValidateRejectsBadConfig 校验启动期配置校验。
func TestValidateRejectsBadConfig(t *testing.T) {
	sp := NewStaticProvider(map[string]string{"k": "v"})
	cases := []*BackendPolicy{
		{Name: "", SecretKey: "k", Provider: sp, Mode: InjectBearer},
		{Name: "n", SecretKey: "", Provider: sp, Mode: InjectBearer},
		{Name: "n", SecretKey: "k", Provider: nil, Mode: InjectBearer},
		{Name: "n", SecretKey: "k", Provider: sp, Mode: "bogus"},
		{Name: "n", SecretKey: "k", Provider: sp, Mode: InjectHeader}, // 缺 HeaderName
	}
	for i, c := range cases {
		if err := c.Validate(); err == nil {
			t.Errorf("用例 %d 应校验失败", i)
		}
	}
}
