package config

import (
	"fmt"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
)

// ValidationError 是一条配置校验错误。
//
// 带上配置路径（如 targets[1].base_url）而不是只给一句描述：
// 一份几百行的配置里，「base_url 非法」这种报错等于没报。
type ValidationError struct {
	Path   string
	Reason string
}

// Error 实现 error。
func (e ValidationError) Error() string { return e.Path + ": " + e.Reason }

// ValidationErrors 是校验错误集合。
//
// 一次报出全部问题而非遇到第一个就返回：运维希望一次改完，
// 而不是修一个跑一次、再暴露下一个。
type ValidationErrors []ValidationError

// Error 实现 error。
func (e ValidationErrors) Error() string {
	if len(e) == 1 {
		return "配置校验失败 — " + e[0].Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "配置校验失败，共 %d 处问题：", len(e))
	for _, item := range e {
		b.WriteString("\n  • " + item.Error())
	}
	return b.String()
}

// Warnings 是不阻断启动但必须让运维知晓的问题。
type Warnings []ValidationError

// Validate 执行语义校验。返回的错误里包含全部问题。
func (c *Config) Validate() error {
	var errs ValidationErrors
	add := func(p, format string, args ...any) {
		errs = append(errs, ValidationError{Path: p, Reason: fmt.Sprintf(format, args...)})
	}

	c.validateTargets(add)
	c.validateRules(add)
	c.validateBudgets(add)
	c.validateRateLimit(add)
	c.validateGPU(add)
	c.validatePII(add)

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// validateTargets 校验后端配置。
func (c *Config) validateTargets(add func(string, string, ...any)) {
	if len(c.Targets) == 0 {
		add("targets", "必须至少配置一个后端")
		return
	}

	seen := map[string]int{}
	for i, t := range c.Targets {
		p := fmt.Sprintf("targets[%d]", i)

		switch {
		case t.Name == "":
			add(p+".name", "后端名不能为空")
		default:
			if prev, dup := seen[t.Name]; dup {
				add(p+".name", "后端名 %q 与 targets[%d] 重复——路由与熔断都按名索引，重名会互相覆盖",
					t.Name, prev)
			}
			seen[t.Name] = i
		}

		if t.BaseURL == "" {
			add(p+".base_url", "不能为空")
		} else if u, err := url.Parse(t.BaseURL); err != nil {
			add(p+".base_url", "非法 URL: %v", err)
		} else if u.Scheme != "http" && u.Scheme != "https" {
			add(p+".base_url", "协议必须是 http 或 https，实际 %q", u.Scheme)
		} else if u.Host == "" {
			add(p+".base_url", "缺少主机名: %q", t.BaseURL)
		}

		if t.Tier == 0 {
			add(p+".tier", "必须指定梯队（1 为最高档）")
		}
		if t.Weight < 0 {
			add(p+".weight", "权重不能为负: %d", t.Weight)
		}

		// 自建集群若登记了单价，预算核算会把 GPU 摊销成本
		// 当成公有云支出，导致 Tier1 预算被错误消耗
		if t.SelfHosted && (t.InputPricePerMTok > 0 || t.OutputPricePerMTok > 0) {
			add(p, "self_hosted 后端不应登记 token 单价——"+
				"自建是 GPU 摊销成本，登记单价会让它错误消耗公有云预算")
		}
		// 只登记单边价格几乎总是漏配
		if (t.InputPricePerMTok > 0) != (t.OutputPricePerMTok > 0) {
			add(p, "输入与输出单价必须同时登记或同时留空，否则成本核算只算一半")
		}

		if t.InjectMode == "header" && t.InjectHeader == "" {
			add(p+".inject_header", "inject_mode 为 header 时必须指定头名")
		}
		if t.InjectMode != "" && t.CredentialKey == "" {
			add(p+".credential_key", "已指定 inject_mode 但未配置密钥名")
		}
	}
}

// validateRules 校验路由规则。
func (c *Config) validateRules(add func(string, string, ...any)) {
	targetNames := map[string]bool{}
	tiers := map[TierNumber]bool{}
	for _, t := range c.Targets {
		targetNames[t.Name] = true
		tiers[t.Tier] = true
	}

	seenName := map[string]int{}
	for i, r := range c.Rules {
		p := fmt.Sprintf("rules[%d]", i)

		if r.Name == "" {
			add(p+".name", "规则名不能为空——报错与审计都靠它定位")
		} else if prev, dup := seenName[r.Name]; dup {
			add(p+".name", "规则名 %q 与 rules[%d] 重复", r.Name, prev)
		} else {
			seenName[r.Name] = i
		}

		if r.TargetTier == 0 {
			add(p+".target_tier", "必须指定目标梯队")
		} else if !tiers[r.TargetTier] {
			// 指向一个没有任何后端的梯队，规则命中后会立刻降级——
			// 表现为「规则配了但不生效」
			add(p+".target_tier", "梯队 %d 下没有任何后端，命中该规则的请求会直接降级",
				int(r.TargetTier))
		}

		// glob 必须在装配期编译。非法模式在运行时是静默失配——
		// 规则形同虚设，且没有任何报错
		for j, pattern := range r.MatchApps {
			if _, err := path.Match(pattern, "probe"); err != nil {
				add(fmt.Sprintf("%s.match_apps[%d]", p, j),
					"非法 glob 模式 %q: %v——运行时会静默失配，规则形同虚设", pattern, err)
			}
		}

		for j, name := range r.PreferTargets {
			if !targetNames[name] {
				add(fmt.Sprintf("%s.prefer_targets[%d]", p, j),
					"引用了不存在的后端 %q", name)
			}
		}

		if r.MinPriority < 0 || r.MinPriority > 9 {
			add(p+".min_priority", "优先级须在 0~9 之间，实际 %d", r.MinPriority)
		}

		// 一条什么都不匹配的规则会命中所有请求，
		// 若它排在前面会把后面所有规则屏蔽掉
		if len(r.MatchApps) == 0 && len(r.MatchTasks) == 0 &&
			len(r.MatchTenants) == 0 && r.MinPriority == 0 {
			add(p, "规则未设置任何匹配条件，将命中全部请求并屏蔽其后所有规则")
		}
	}
}

// validateBudgets 校验梯队预算。
func (c *Config) validateBudgets(add func(string, string, ...any)) {
	tiers := map[TierNumber]bool{}
	for _, t := range c.Targets {
		tiers[t.Tier] = true
	}
	for key, limit := range c.Budgets {
		p := "budgets." + key
		n, err := strconv.Atoi(key)
		if err != nil {
			add(p, "预算的键必须是梯队编号（如 \"1\"），实际 %q", key)
			continue
		}
		if !tiers[TierNumber(n)] {
			add(p, "梯队 %d 下没有任何后端，该预算不会生效", n)
		}
		if limit <= 0 {
			add(p, "预算上限必须为正数，实际 %v", limit)
		}
	}
}

// validateRateLimit 校验限流配置。
func (c *Config) validateRateLimit(add func(string, string, ...any)) {
	check := func(p string, l LimitConfig) {
		if l.TokensPerWindow < 0 {
			add(p+".tokens_per_window", "不能为负: %d", l.TokensPerWindow)
		}
		if l.MaxConcurrent < 0 {
			add(p+".max_concurrent", "不能为负: %d", l.MaxConcurrent)
		}
		// 预留 TTL 短于窗口时，长流会在结算前被清扫，
		// 配额被重复释放，限流实际失效
		if l.ReservationTTL > 0 && l.Window > 0 && l.ReservationTTL < l.Window/10 {
			add(p+".reservation_ttl",
				"预留 TTL(%s) 远短于窗口(%s)——长流会在结算前被清扫，配额重复释放导致限流失效",
				l.ReservationTTL, l.Window)
		}
	}
	check("rate_limit", c.RateLimit.LimitConfig)

	subjects := make([]string, 0, len(c.RateLimit.PerSubject))
	for s := range c.RateLimit.PerSubject {
		subjects = append(subjects, s)
	}
	sort.Strings(subjects)
	for _, s := range subjects {
		check("rate_limit.per_subject."+s, c.RateLimit.PerSubject[s])
	}
}

// validateGPU 校验显存保护配置。
func (c *Config) validateGPU(add func(string, string, ...any)) {
	g := c.GPU
	for _, f := range []struct {
		p string
		v float64
	}{{"gpu.kv_elevated", g.KVElevated}, {"gpu.kv_critical", g.KVCritical}} {
		if f.v <= 0 || f.v > 1 {
			add(f.p, "KV 占用阈值须在 (0, 1] 之间，实际 %v", f.v)
		}
	}
	if g.KVCritical <= g.KVElevated {
		add("gpu.kv_critical", "必须大于 kv_elevated（%.2f <= %.2f）——"+
			"否则永远不会进入 elevated 档，分级降级失效", g.KVCritical, g.KVElevated)
	}
	if g.WaitingCritical > 0 && g.WaitingElevated > 0 && g.WaitingCritical <= g.WaitingElevated {
		add("gpu.waiting_critical", "必须大于 waiting_elevated（%d <= %d）",
			g.WaitingCritical, g.WaitingElevated)
	}
	if g.AffinityLoadFactor < 1 {
		add("gpu.affinity_load_factor", "必须 >= 1.0，实际 %v——小于 1 会让所有副本都被判为过载",
			g.AffinityLoadFactor)
	}
}

// validatePII 校验脱敏配置。
func (c *Config) validatePII(add func(string, string, ...any)) {
	if c.PII.NER.Endpoint != "" {
		if u, err := url.Parse(c.PII.NER.Endpoint); err != nil {
			add("pii.ner.endpoint", "非法 URL: %v", err)
		} else if u.Scheme != "http" && u.Scheme != "https" {
			add("pii.ner.endpoint", "协议必须是 http 或 https，实际 %q", u.Scheme)
		}
		// NER 在 TTFT 关键路径上，超时过长会让每个请求都变慢
		if c.PII.NER.Timeout > Duration(3e9) {
			add("pii.ner.timeout", "超时 %s 过长——NER 在 TTFT 关键路径上，"+
				"这段延迟会叠加到每个未命中缓存的请求", c.PII.NER.Timeout)
		}
	}
	if c.PII.NER.Endpoint == "" && len(c.PII.NER.Types) > 0 {
		add("pii.ner.types", "配置了识别类型但未设置 endpoint，NER 不会启用")
	}

	// 会话一致性必须显式声明。缺省不能选任何一边：
	// 猜「单副本」会让多副本部署静默串号，猜「有亲和」会让单副本部署
	// 背上一个并不存在的承诺。两种猜法都比报错更糟。
	if c.PII.SessionConsistency == "" {
		add("pii.session_consistency",
			"必填——占位符是副本本地的递增序号，多副本部署下同一会话的"+
				"同一个占位符会在不同副本上指向不同的真实值，用户会拿到"+
				"别人的数据且不报错。请声明 %s 之一",
			strings.Join(SessionConsistencyNames(), " 或 "))
	}

	// 未选司法管辖区 = 一条识别器都不装 = 扫描全过、报告干净。
	// 这必须是启动期硬错误，不能是警告。
	// No jurisdiction selected means no recognizers at all: everything scans
	// clean. That has to fail startup, not warn.
	if len(c.PII.Jurisdictions) == 0 {
		add("pii.jurisdictions", "必须显式指定至少一个国家包（可用：%v）——"+
			"一个都不装意味着任何文本都扫不出 PII，且看起来像「数据很干净」",
			strings.Join(packs.Available(), ", "))
	}
	// 代码本身的合法性已在解析期由 JurisdictionCode 拦下，这里只查重复。
	// Code validity is already enforced at parse time by JurisdictionCode.
	seen := map[JurisdictionCode]bool{}
	for i, code := range c.PII.Jurisdictions {
		if seen[code] {
			add(fmt.Sprintf("pii.jurisdictions[%d]", i), "国家包 %q 重复", code)
		}
		seen[code] = true
	}
}

// Warn 返回不阻断启动但需要运维知晓的问题。
//
// 与 Validate 分开：这些是配置**选择**而非配置**错误**。
// 有的部署确实只需要正则覆盖，不该阻止它启动——
// 但必须让人在部署前看见自己选了什么。
func (c *Config) Warn() Warnings {
	var out Warnings
	add := func(p, format string, args ...any) {
		out = append(out, ValidationError{Path: p, Reason: fmt.Sprintf(format, args...)})
	}

	if !c.PII.FailClosed {
		add("pii.fail_closed", "为 false——检测器故障时将放行原文，存在 PII 泄露风险")
	}
	if c.PII.NER.FailOpen {
		add("pii.ner.fail_open", "为 true——NER 不可用时将放行原文，存在 PII 泄露风险")
	}
	if c.PII.NER.Endpoint == "" && len(c.PII.NameRoster) == 0 {
		add("pii", "既未配置名册也未接入 NER——正则检测不出人名，姓名类 PII 将完全裸奔")
	}
	if !c.GPU.PrefixAffinity && len(c.Targets) > 1 {
		add("gpu.prefix_affinity", "未启用——同前缀请求会被打散，"+
			"vLLM prefix caching 命中率降至 1/%d", len(c.Targets))
	}
	if c.GPU.KVCritical > 0.95 {
		add("gpu.kv_critical", "%.2f 过于贴边——从放行到真正占住 KV 有数百毫秒延迟，"+
			"控制延迟内可能已被推过 100%%", c.GPU.KVCritical)
	}
	if c.RateLimit.TokensPerWindow == 0 {
		add("rate_limit.tokens_per_window", "未设 token 配额——突发流量下无保护")
	}
	hasCred := false
	for _, t := range c.Targets {
		if t.CredentialKey != "" {
			hasCred = true
		}
	}
	if !hasCred {
		add("targets", "无后端配置凭证——出站请求将不携带任何鉴权")
	}
	return out
}
