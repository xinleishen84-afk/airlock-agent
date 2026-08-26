package config

// Config 是网关的完整配置。
//
// 每个字段都带 yaml tag。KnownFields(true) 会拿实际的键名与这些 tag
// 逐一比对，对不上就报错——这是「拼错的键被静默忽略」的唯一防线。
//
// 注意所有 tag 都必须写全：漏写 tag 的字段，Go 会按字段名小写匹配，
// 造成配置文件里的键名与文档不一致，且没有任何提示。
type Config struct {
	SecretsMountPath string   `yaml:"secrets_mount_path"`
	SecretsCacheTTL  Duration `yaml:"secrets_cache_ttl"`
	SessionTTL       Duration `yaml:"session_ttl"`
	MaxSessions      int      `yaml:"max_sessions"`

	Targets   []TargetConfig     `yaml:"targets"`
	Rules     []RuleConfig       `yaml:"rules"`
	Budgets   map[string]float64 `yaml:"budgets"` // 梯队号 -> 美元硬上限
	Breaker   BreakerConfig      `yaml:"breaker"`
	RateLimit RateLimitConfig    `yaml:"rate_limit"`
	PII       PIIConfig          `yaml:"pii"`
	Upstream  UpstreamConfig     `yaml:"upstream"`
	GPU       GPUConfig          `yaml:"gpu"`
}

// TargetConfig 是一个后端的配置。
type TargetConfig struct {
	Name       string     `yaml:"name"`
	Tier       TierNumber `yaml:"tier"`
	BaseURL    string     `yaml:"base_url"`
	Model      string     `yaml:"model"`
	Weight     int        `yaml:"weight"`
	SelfHosted bool       `yaml:"self_hosted"`

	// 价格留空表示未登记。自建集群是 GPU 摊销成本，
	// 按 token 计价本身就不对，不该编造单价让预算核算失真。
	InputPricePerMTok  float64 `yaml:"input_price_per_mtok"`
	OutputPricePerMTok float64 `yaml:"output_price_per_mtok"`

	// CredentialKey 是密钥源里的逻辑名，不是凭证本身——
	// 因此本配置文件可以安全地提交到代码仓库
	CredentialKey string         `yaml:"credential_key"`
	InjectMode    InjectModeName `yaml:"inject_mode"`
	InjectHeader  string         `yaml:"inject_header"`
}

// RuleConfig 是一条路由规则的配置。
type RuleConfig struct {
	Name          string     `yaml:"name"`
	TargetTier    TierNumber `yaml:"target_tier"`
	MatchApps     []string   `yaml:"match_apps"`
	MatchTasks    []TaskName `yaml:"match_tasks"`
	MatchTenants  []string   `yaml:"match_tenants"`
	MinPriority   int        `yaml:"min_priority"`
	PreferTargets []string   `yaml:"prefer_targets"`
	Priority      int        `yaml:"priority"`
}

// BreakerConfig 是熔断器配置。
type BreakerConfig struct {
	FailureThreshold int      `yaml:"failure_threshold"`
	RecoveryTimeout  Duration `yaml:"recovery_timeout"`
}

// LimitConfig 是一组限流配额。
type LimitConfig struct {
	TokensPerWindow int64    `yaml:"tokens_per_window"`
	Window          Duration `yaml:"window"`
	MaxConcurrent   int      `yaml:"max_concurrent"`
	ReservationTTL  Duration `yaml:"reservation_ttl"`
}

// RateLimitConfig 是限流配置，支持按主体差异化。
//
// 内嵌结构体在 yaml 里必须用 `,inline`，否则 KnownFields 会把
// tokens_per_window 当成未知字段——这是内嵌与严格解析的经典冲突点。
type RateLimitConfig struct {
	LimitConfig `yaml:",inline"`
	PerSubject  map[string]LimitConfig `yaml:"per_subject"`
}

// PIIConfig 是脱敏配置。
type PIIConfig struct {
	// FailClosed 为 true 时，检测器故障会阻断请求而非放行原文。
	// 这是脱敏网关唯一安全的默认值。
	FailClosed bool `yaml:"fail_closed"`
	// AlwaysRedact 为 true 时连私有化后端也脱敏
	AlwaysRedact bool `yaml:"always_redact"`
	// NameRoster / OrgRoster 是企业主数据名册。
	// 正则检测不出人名——不配这个也不接 NER，姓名类 PII 会完全裸奔。
	NameRoster []string `yaml:"name_roster"`
	OrgRoster  []string `yaml:"org_roster"`
	// DisabledTypes 可关闭部分检测类型（如内网场景不必脱敏 IP）
	DisabledTypes []EntityTypeName `yaml:"disabled_types"`

	// Jurisdictions 是要加载的国家包代码（如 GEN、CN、DE）。
	// 必填且没有默认值：默认值只能选定某个本土市场，
	// 而无论选哪个，对写它的人都对、在别处都静默地错——
	// 扫意大利合同的部署会在从未被询问的情况下继承别人的假设，
	// 然后报告「零 PII」。
	//
	// Jurisdictions names the country packs to load. Required, with no default:
	// any default would pick a home market and be silently wrong everywhere
	// else.
	Jurisdictions []JurisdictionCode `yaml:"jurisdictions"`

	// TenantRulesDir 是租户自定义 YAML 规则目录（工号、资产编号、合同号等
	// 只有租户自己知道格式的标识）。留空表示不加载。
	//
	// TenantRulesDir points at custom YAML rule files for tenant-specific
	// identifiers. Empty means none are loaded.
	TenantRulesDir string `yaml:"tenant_rules_dir"`

	NER NERConfig `yaml:"ner"`
}

// NERConfig 是外部 NER 服务配置。
//
// 服务契约（语言无关，便于各家自行实现）：
//
//	POST <endpoint>
//	{"text": "...", "types": ["NAME","ADDRESS","ORG"]}
//	-> {"entities": [{"type":"NAME","value":"张伟","confidence":0.95}]}
//
// 刻意不要求返回偏移量：跨语言偏移约定不一致（Python 按字符、Go 按字节），
// 中文下会把文本切碎，且只在含中文时出错。由网关侧回原文定位更安全。
type NERConfig struct {
	// Endpoint 为空表示不启用外部 NER
	Endpoint string `yaml:"endpoint"`
	// Timeout 直接叠加在 TTFT 上，必须设紧
	Timeout Duration `yaml:"timeout"`
	// CacheTTL / CacheSize 控制检测结果缓存。
	// Agent 每轮携带相同的系统提示词，缓存命中率决定 NER 是否可用于生产。
	CacheTTL  Duration `yaml:"cache_ttl"`
	CacheSize int      `yaml:"cache_size"`
	// Types 限定识别类型，留空取 NAME/ADDRESS/ORG
	Types []EntityTypeName `yaml:"types"`
	// FailOpen 为 true 时服务不可用会放行原文（有泄露风险）
	FailOpen bool `yaml:"fail_open"`
	// FailureThreshold / Cooldown 是熔断参数。
	// 没有熔断，一次 NER 故障会让所有请求延迟 +timeout。
	FailureThreshold int      `yaml:"failure_threshold"`
	Cooldown         Duration `yaml:"cooldown"`
}

// UpstreamConfig 是上游连接配置。
type UpstreamConfig struct {
	MaxIdleConnsPerHost   int      `yaml:"max_idle_conns_per_host"`
	ResponseHeaderTimeout Duration `yaml:"response_header_timeout"`
	DialTimeout           Duration `yaml:"dial_timeout"`
	IdleConnTimeout       Duration `yaml:"idle_conn_timeout"`
}

// GPUConfig 是 GPU 显存保护与前缀亲和的配置。
type GPUConfig struct {
	// ProbeInterval 是负载探测间隔
	ProbeInterval Duration `yaml:"probe_interval"`
	// KVElevated / KVCritical 是 KV 缓存占用阈值。
	// 不要贴边设 0.95——从放行到真正占住 KV 有数百毫秒延迟，
	// 阈值必须为这段控制延迟留余量。
	KVElevated      float64 `yaml:"kv_elevated"`
	KVCritical      float64 `yaml:"kv_critical"`
	WaitingElevated int     `yaml:"waiting_elevated"`
	WaitingCritical int     `yaml:"waiting_critical"`
	// PrefixAffinity 开启前缀感知路由。关掉它，vLLM 的 prefix caching
	// 命中率会降到 1/副本数——后端开了缓存，收益被网关摧毁。
	PrefixAffinity bool `yaml:"prefix_affinity"`
	// AffinityLoadFactor 是有界负载倍数
	AffinityLoadFactor float64 `yaml:"affinity_load_factor"`
}
