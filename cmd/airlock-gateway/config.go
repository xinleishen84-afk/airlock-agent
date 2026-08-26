package main

import (
	"fmt"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/gpuload"
	"github.com/xinleishen84-afk/airlock-agent/internal/config"
	"github.com/xinleishen84-afk/airlock-agent/internal/credential"
	"github.com/xinleishen84-afk/airlock-agent/internal/identity"
	"github.com/xinleishen84-afk/airlock-agent/internal/proxy"
	"github.com/xinleishen84-afk/airlock-agent/internal/ratelimit"
	"github.com/xinleishen84-afk/airlock-agent/internal/routing"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
)

// identityTask 是任务类型的别名，避免 buildPolicy 里出现冗长的包路径。
type identityTask = identity.TaskKind

// Config 是配置类型的别名。定义在 internal/config，
// 以便 CRD 生成器与集成测试都能引用同一份事实来源。
type Config = config.Config

// loadConfig 严格加载配置（YAML 或 JSON，未知字段一律拒绝）。
func loadConfig(path string) (*Config, error) { return config.Load(path) }

// buildPolicy 由配置装配路由策略。
func buildPolicy(c *Config) (*routing.Policy, error) {
	targets := make([]*routing.Target, 0, len(c.Targets))
	for _, t := range c.Targets {
		targets = append(targets, &routing.Target{
			Name: t.Name, Tier: routing.Tier(t.Tier), BaseURL: t.BaseURL,
			Model: t.Model, Weight: t.Weight, Enabled: true,
			SelfHosted:         t.SelfHosted,
			InputPricePerMTok:  t.InputPricePerMTok,
			OutputPricePerMTok: t.OutputPricePerMTok,
			CredentialKey:      t.CredentialKey,
		})
	}

	rules := make([]*routing.Rule, 0, len(c.Rules))
	for _, r := range c.Rules {
		tasks := make([]identityTask, 0, len(r.MatchTasks))
		for _, t := range r.MatchTasks {
			tasks = append(tasks, t.Task())
		}
		rules = append(rules, &routing.Rule{
			Name: r.Name, TargetTier: routing.Tier(r.TargetTier),
			MatchApps: r.MatchApps, MatchTasks: tasks, MatchTenants: r.MatchTenants,
			MinPriority: r.MinPriority, PreferTargets: r.PreferTargets,
			Priority: r.Priority, Enabled: true,
		})
	}

	budgets := map[routing.Tier]*routing.Budget{}
	for tierStr, limit := range c.Budgets {
		var tier int
		if _, err := fmt.Sscanf(tierStr, "%d", &tier); err != nil {
			return nil, fmt.Errorf("预算配置的梯队键非法 %q", tierStr)
		}
		budgets[routing.Tier(tier)] = routing.NewBudget(limit)
	}

	return routing.NewPolicy(targets, rules, routing.Tier2Standard, nil, budgets)
}

// buildDetector 由配置装配 PII 检测器。
func buildDetector(c *Config) (detect.Detector, error) {
	disabled := make([]detect.EntityType, 0, len(c.PII.DisabledTypes))
	for _, t := range c.PII.DisabledTypes {
		disabled = append(disabled, t.PII())
	}
	// 只装配置显式点名的司法管辖区；校验层已保证列表非空且代码合法。
	// Only the jurisdictions the config names; validation already guarantees
	// the list is non-empty and every code is known.
	reg, err := packs.NewRegistry(jurisdictionCodes(c), disabled...)
	if err != nil {
		return nil, fmt.Errorf("装配国家包: %w", err)
	}
	if dir := c.PII.TenantRulesDir; dir != "" {
		if err := packs.LoadYAMLInto(reg, dir); err != nil {
			return nil, fmt.Errorf("装配租户规则: %w", err)
		}
	}
	detectors := []detect.Detector{reg}

	roster := map[detect.EntityType][]string{}
	if len(c.PII.NameRoster) > 0 {
		roster[detect.TypeName] = c.PII.NameRoster
	}
	if len(c.PII.OrgRoster) > 0 {
		roster[detect.TypeOrg] = c.PII.OrgRoster
	}
	if len(roster) > 0 {
		gaz, err := detect.NewGazetteerDetector(roster, false, 2)
		if err != nil {
			return nil, fmt.Errorf("构造名册检测器: %w", err)
		}
		detectors = append(detectors, gaz)
	}

	if c.PII.NER.Endpoint != "" {
		types := make([]detect.EntityType, 0, len(c.PII.NER.Types))
		for _, t := range c.PII.NER.Types {
			types = append(types, t.PII())
		}
		ner, err := detect.NewRemoteNERDetector(detect.RemoteNEROptions{
			Endpoint:         c.PII.NER.Endpoint,
			Timeout:          c.PII.NER.Timeout.Std(),
			CacheTTL:         c.PII.NER.CacheTTL.Std(),
			CacheSize:        c.PII.NER.CacheSize,
			Types:            types,
			FailOpen:         c.PII.NER.FailOpen,
			FailureThreshold: c.PII.NER.FailureThreshold,
			Cooldown:         c.PII.NER.Cooldown.Std(),
		})
		if err != nil {
			return nil, fmt.Errorf("构造 NER 检测器: %w", err)
		}
		detectors = append(detectors, ner)
	}

	return detect.NewCompositeDetector(detectors, 0), nil
}

// toLimits 把限流配置转成限流器参数。
func toLimits(l config.LimitConfig) ratelimit.Limits {
	return ratelimit.Limits{
		TokensPerWindow: l.TokensPerWindow,
		Window:          l.Window.Std(),
		MaxConcurrent:   l.MaxConcurrent,
		ReservationTTL:  l.ReservationTTL.Std(),
	}
}

// toThresholds 把 GPU 配置转成压力阈值。
func toThresholds(g config.GPUConfig) gpuload.Thresholds {
	th := gpuload.DefaultThresholds()
	if g.KVElevated > 0 {
		th.KVElevated = g.KVElevated
	}
	if g.KVCritical > 0 {
		th.KVCritical = g.KVCritical
	}
	if g.WaitingElevated > 0 {
		th.WaitingElevated = g.WaitingElevated
	}
	if g.WaitingCritical > 0 {
		th.WaitingCritical = g.WaitingCritical
	}
	return th
}

// toTransportConfig 把上游配置转成 transport 参数。
func toTransportConfig(c config.UpstreamConfig) proxy.TransportConfig {
	cfg := proxy.DefaultTransportConfig()
	if c.MaxIdleConnsPerHost > 0 {
		cfg.MaxIdleConnsPerHost = c.MaxIdleConnsPerHost
	}
	if c.ResponseHeaderTimeout > 0 {
		cfg.ResponseHeaderTimeout = c.ResponseHeaderTimeout.Std()
	}
	if c.DialTimeout > 0 {
		cfg.DialTimeout = c.DialTimeout.Std()
	}
	if c.IdleConnTimeout > 0 {
		cfg.IdleConnTimeout = c.IdleConnTimeout.Std()
	}
	return cfg
}

// buildCredentialPolicy 由后端配置装配凭证策略。
func buildCredentialPolicy(c *Config, t config.TargetConfig) *credential.BackendPolicy {
	return &credential.BackendPolicy{
		Name:       t.Name,
		SecretKey:  t.CredentialKey,
		Mode:       t.InjectMode.Mode(),
		HeaderName: t.InjectHeader,
		Provider: credential.NewCachingProvider(
			credential.NewFileProvider(c.SecretsMountPath), c.SecretsCacheTTL.Std()),
	}
}

// 确保 time 被引用（Duration 转换用到）
var _ = time.Second

// jurisdictionCodes 取出配置里的国家包代码。
// jurisdictionCodes extracts the pack codes from the config.
func jurisdictionCodes(c *Config) []string {
	out := make([]string, 0, len(c.PII.Jurisdictions))
	for _, j := range c.PII.Jurisdictions {
		out = append(out, j.Code())
	}
	return out
}
