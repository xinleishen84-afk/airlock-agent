// Package credential 实现零信任凭证管理。
//
// 铁律：调用方一律不携带、也不允许知晓真实凭证。网关对每个出站请求执行两步：
//
//  1. 剥离（Strip）—— 无条件删除客户端自携的一切授权头。
//     不是「校验后放行」而是「一律丢弃」：客户端携带的凭证在零信任模型下
//     没有任何可信度，即便它恰好是对的，也可能是横向移动的产物。
//  2. 注入（Inject）—— 从密钥源热取真实凭证写入请求。
//
// 凭证只在构造请求的瞬间存在于内存，不落配置、不进日志、不回传调用方。
package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ErrSecretUnavailable 表示凭证获取失败。属于安全事件，绝不允许静默降级。
var ErrSecretUnavailable = errors.New("凭证不可用")

// ErrPolicyViolation 表示检测到凭证策略违规，请求必须中断。
var ErrPolicyViolation = errors.New("凭证策略违规")

// Secret 是密钥的安全包装。
//
// 真实值只能通过显式的 Reveal() 取出——把「泄露」变成一个需要主动调用的动作，
// 代码审查时可以直接 grep 出所有取用点。String() 永远只输出指纹，
// 杜绝凭证被日志、错误信息、%v 格式化意外带出。
type Secret struct {
	value     string
	source    string
	fetchedAt time.Time
	leaseTTL  time.Duration
}

// Reveal 取出明文。每一处调用都应经得起安全审查。
func (s Secret) Reveal() string { return s.value }

// Source 返回来源标识，用于审计。
func (s Secret) Source() string { return s.source }

// Fingerprint 返回凭证指纹：仅供审计比对，无法反推原值。
func (s Secret) Fingerprint() string {
	sum := sha256.Sum256([]byte(s.value))
	return hex.EncodeToString(sum[:])[:12]
}

// Expired 判断租约是否已过期。
func (s Secret) Expired() bool {
	return s.leaseTTL > 0 && time.Since(s.fetchedAt) >= s.leaseTTL
}

// String 返回脱敏表示。实现 fmt.Stringer，确保 %v / %s 都不会泄露明文。
func (s Secret) String() string {
	return fmt.Sprintf("<Secret source=%s fp=%s len=%d>", s.source, s.Fingerprint(), len(s.value))
}

// Provider 是密钥源抽象。
type Provider interface {
	Fetch(key string) (Secret, error)
	HealthCheck() error
	Name() string
}

// ---------------------------------------------------------------------------
// 挂载文件密钥源（Kubernetes Secrets 的标准消费方式）
// ---------------------------------------------------------------------------

// FileProvider 从挂载目录读取密钥。
//
// K8s 把 Secret 以 tmpfs 挂载到容器内（如 /var/run/secrets/llm/），
// 每个键是一个文件。相比环境变量，它支持热更新，且不会进入进程环境块
// （环境变量会出现在 /proc/<pid>/environ、容器 inspect 输出与崩溃转储中）。
type FileProvider struct {
	root string
}

// NewFileProvider 创建挂载文件密钥源。
func NewFileProvider(mountPath string) *FileProvider {
	return &FileProvider{root: mountPath}
}

// Name 返回密钥源标识。
func (p *FileProvider) Name() string { return "file" }

// Fetch 读取 <mount>/<key> 的内容作为凭证。
func (p *FileProvider) Fetch(key string) (Secret, error) {
	// 拒绝路径穿越：逻辑名不允许包含分隔符
	if strings.ContainsAny(key, `/\`) || key == "." || key == ".." || key == "" {
		return Secret{}, fmt.Errorf("%w: 非法的密钥名 %q", ErrSecretUnavailable, key)
	}
	data, err := os.ReadFile(filepath.Join(p.root, key))
	if err != nil {
		return Secret{}, fmt.Errorf("%w: 读取密钥文件失败: %v", ErrSecretUnavailable, err)
	}
	// 末尾换行是挂载文件的常见噪音，必须剥掉，否则鉴权头会带上 \n
	value := strings.TrimSpace(string(data))
	if value == "" {
		return Secret{}, fmt.Errorf("%w: 密钥文件为空: %s", ErrSecretUnavailable, key)
	}
	return Secret{value: value, source: "file:" + key, fetchedAt: time.Now()}, nil
}

// HealthCheck 检查挂载目录是否可访问。
func (p *FileProvider) HealthCheck() error {
	info, err := os.Stat(p.root)
	if err != nil {
		return fmt.Errorf("%w: 挂载目录不可访问: %v", ErrSecretUnavailable, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s 不是目录", ErrSecretUnavailable, p.root)
	}
	return nil
}

// ---------------------------------------------------------------------------
// 缓存装饰器
// ---------------------------------------------------------------------------

// CachingProvider 为任意密钥源加一层 TTL 缓存。
//
// 密钥源多为网络调用（Vault）或文件 IO，每次请求都回源会显著抬高延迟。
// 缓存过期或租约到期后自动重新拉取，实现无感轮转。
type CachingProvider struct {
	inner Provider
	ttl   time.Duration

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

// cacheEntry 是一条缓存记录。
type cacheEntry struct {
	secret   Secret
	cachedAt time.Time
}

// NewCachingProvider 包装一个密钥源。
func NewCachingProvider(inner Provider, ttl time.Duration) *CachingProvider {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &CachingProvider{inner: inner, ttl: ttl, cache: map[string]cacheEntry{}}
}

// Name 返回密钥源标识。
func (p *CachingProvider) Name() string { return p.inner.Name() }

// Fetch 命中且未过期则走缓存，否则回源并刷新。
func (p *CachingProvider) Fetch(key string) (Secret, error) {
	p.mu.RLock()
	e, ok := p.cache[key]
	p.mu.RUnlock()
	if ok && time.Since(e.cachedAt) < p.ttl && !e.secret.Expired() {
		return e.secret, nil
	}

	// 回源在锁外进行，避免阻塞其他键的读取
	secret, err := p.inner.Fetch(key)
	if err != nil {
		return Secret{}, err
	}
	p.mu.Lock()
	p.cache[key] = cacheEntry{secret: secret, cachedAt: time.Now()}
	p.mu.Unlock()
	return secret, nil
}

// Invalidate 手动失效缓存。key 为空时清空全部（凭证轮转后调用）。
func (p *CachingProvider) Invalidate(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if key == "" {
		clear(p.cache)
		return
	}
	delete(p.cache, key)
}

// HealthCheck 透传到内层密钥源。
func (p *CachingProvider) HealthCheck() error { return p.inner.HealthCheck() }

// ---------------------------------------------------------------------------
// 静态密钥源（仅供测试）
// ---------------------------------------------------------------------------

// StaticProvider 是内存密钥源，仅供单元测试与本地演示。
type StaticProvider struct {
	secrets map[string]string
}

// NewStaticProvider 从字典构造。刻意不做成生产可用。
func NewStaticProvider(secrets map[string]string) *StaticProvider {
	return &StaticProvider{secrets: secrets}
}

// Name 返回密钥源标识。
func (p *StaticProvider) Name() string { return "static" }

// Fetch 从内存字典取值。
func (p *StaticProvider) Fetch(key string) (Secret, error) {
	v, ok := p.secrets[key]
	if !ok {
		return Secret{}, fmt.Errorf("%w: 测试密钥源中不存在 %q", ErrSecretUnavailable, key)
	}
	return Secret{value: v, source: "static:" + key, fetchedAt: time.Now()}, nil
}

// HealthCheck 恒定成功。
func (p *StaticProvider) HealthCheck() error { return nil }

// ---------------------------------------------------------------------------
// 凭证头识别与剥离
// ---------------------------------------------------------------------------

// credentialHeaderPatterns 是必须无条件剥离的授权类头部模式。
// 覆盖各家命名习惯——漏掉一条就是一个凭证泄露通道。
var credentialHeaderPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^authorization$`),
	regexp.MustCompile(`^proxy-authorization$`),
	regexp.MustCompile(`^x-api-key$`),
	regexp.MustCompile(`^api-key$`),
	regexp.MustCompile(`^x-goog-api-key$`),
	regexp.MustCompile(`^x-vault-token$`),
	regexp.MustCompile(`^cookie$`),
	regexp.MustCompile(`^x-.*-(token|key|secret|credential)s?$`),
	regexp.MustCompile(`^.*[-_]?(apikey|api_key|access[-_]?token)$`),
}

// IsCredentialHeader 判断某个头部是否属于必须剥离的凭证类头部。
func IsCredentialHeader(name string) bool {
	lowered := strings.ToLower(strings.TrimSpace(name))
	for _, re := range credentialHeaderPatterns {
		if re.MatchString(lowered) {
			return true
		}
	}
	return false
}
