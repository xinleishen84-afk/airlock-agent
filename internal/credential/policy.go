package credential

import (
	"fmt"
	"net/http"
	"strings"
)

// InjectMode 是凭证注入方式。
type InjectMode string

const (
	// InjectBearer 写入 Authorization: Bearer <secret>
	InjectBearer InjectMode = "bearer"
	// InjectHeader 写入自定义头（如 x-api-key: <secret>）
	InjectHeader InjectMode = "header"
)

// BackendPolicy 是单个后端的凭证注入策略。
//
// SecretKey 是密钥源里的逻辑名，不是凭证本身——因此策略对象可以安全地
// 写进配置文件、打进镜像、提交到代码仓库。
type BackendPolicy struct {
	Name          string
	Provider      Provider
	SecretKey     string
	Mode          InjectMode
	HeaderName    string            // Mode 为 InjectHeader 时使用
	StaticHeaders map[string]string // 除凭证外要附加的固定头（组织 ID、项目 ID 等）
}

// Validate 在启动期校验策略配置与密钥源可用性。
// 配置错误应该让进程起不来，而不是在生产流量上暴露。
func (p *BackendPolicy) Validate() error {
	if p.Name == "" || p.SecretKey == "" {
		return fmt.Errorf("%w: 策略名与密钥名不能为空", ErrPolicyViolation)
	}
	if p.Provider == nil {
		return fmt.Errorf("%w: 策略 %s 未配置密钥源", ErrPolicyViolation, p.Name)
	}
	switch p.Mode {
	case InjectBearer:
	case InjectHeader:
		if p.HeaderName == "" {
			return fmt.Errorf("%w: 策略 %s 声明头部注入但未指定头名", ErrPolicyViolation, p.Name)
		}
	default:
		return fmt.Errorf("%w: 策略 %s 的注入方式非法 %q", ErrPolicyViolation, p.Name, p.Mode)
	}
	if err := p.Provider.HealthCheck(); err != nil {
		return fmt.Errorf("%w: 策略 %s 的密钥源探活失败: %v", ErrPolicyViolation, p.Name, err)
	}
	return nil
}

// StripResult 记录一次剥离的结果。
type StripResult struct {
	// Stripped 是被剥离的头名列表。「客户端试图自携凭证」本身就是
	// 需要关注的信号，因此必须进审计。
	Stripped []string
}

// Strip 无条件删除入站请求中的一切凭证类头部。
//
// 就地修改 header：网关持有的是请求的独占副本，原地改比重建整个 Header
// 少一次分配——这是每请求热路径，分配次数直接影响 GC 压力。
func Strip(h http.Header) StripResult {
	var stripped []string
	for name := range h {
		if IsCredentialHeader(name) {
			stripped = append(stripped, name)
		}
	}
	for _, name := range stripped {
		h.Del(name)
	}
	return StripResult{Stripped: stripped}
}

// Inject 从密钥源热取真实凭证写入请求头。
//
// 必须在 Strip 之后调用。取不到凭证时返回错误而非降级放行——
// 宁可请求失败，也不能用空凭证或客户端凭证发出去。
func (p *BackendPolicy) Inject(h http.Header) (Secret, error) {
	secret, err := p.Provider.Fetch(p.SecretKey)
	if err != nil {
		return Secret{}, fmt.Errorf("%w: 策略 %s 无法获取凭证: %v", ErrPolicyViolation, p.Name, err)
	}

	switch p.Mode {
	case InjectBearer:
		h.Set("Authorization", "Bearer "+secret.Reveal())
	case InjectHeader:
		h.Set(p.HeaderName, secret.Reveal())
	}
	for k, v := range p.StaticHeaders {
		h.Set(k, v)
	}
	return secret, nil
}

// Verify 是出站请求的凭证终检。
//
// 在请求真正离开网关前做最后一道断言：确认没有任何非预期凭证残留。
// 这是纵深防御——即便上游逻辑配置出错，这里也能兜住。
func (p *BackendPolicy) Verify(h http.Header) error {
	expected := "authorization"
	if p.Mode == InjectHeader {
		expected = strings.ToLower(p.HeaderName)
	}

	var leaked []string
	found := false
	for name := range h {
		lowered := strings.ToLower(name)
		if !IsCredentialHeader(lowered) {
			continue
		}
		if lowered == expected {
			found = true
			continue
		}
		leaked = append(leaked, name)
	}
	if len(leaked) > 0 {
		return fmt.Errorf("%w: 出站请求含非预期凭证头 %v（策略 %s）",
			ErrPolicyViolation, leaked, p.Name)
	}
	if !found {
		return fmt.Errorf("%w: 策略 %s 声明注入 %s，但出站请求中不存在",
			ErrPolicyViolation, p.Name, expected)
	}
	return nil
}

// Apply 是完整的「剥离—注入—终检」流程，供代理层单点调用。
func (p *BackendPolicy) Apply(h http.Header) (StripResult, Secret, error) {
	strip := Strip(h)
	secret, err := p.Inject(h)
	if err != nil {
		return strip, Secret{}, err
	}
	if err := p.Verify(h); err != nil {
		return strip, Secret{}, err
	}
	return strip, secret, nil
}
