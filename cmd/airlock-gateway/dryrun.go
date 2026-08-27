package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/gpuload"
	"github.com/xinleishen84-afk/airlock-agent/internal/config"
	"github.com/xinleishen84-afk/airlock-agent/internal/cpulimit"
	"github.com/xinleishen84-afk/airlock-agent/internal/lifecycle"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/document"
	"go.yaml.in/yaml/v3"
)

// 配置自检与 Dry-Run。
//
// 参照 nginx -t / apisix test 的范式：走完 100% 的配置读取与装配流程，
// 但不启动监听。CI/CD 在部署前强制跑一次，装配失败则流水线挂红，
// 保证「带病」配置绝不上线。
//
// 与单元测试的分工：单元测试验证**组件逻辑**，dry-run 验证**装配结果**。
// 一个拼错的配置键、一个未注入的依赖、一个连不上的密钥源，
// 单元测试全都发现不了——它们只在真实装配时才暴露。

// CheckStatus 是单项检查的结果状态。
type CheckStatus string

const (
	StatusPass CheckStatus = "PASS"
	StatusFail CheckStatus = "FAIL"
	StatusWarn CheckStatus = "WARN" // 不阻断启动，但需要运维知晓
	StatusSkip CheckStatus = "SKIP" // 前置检查失败，或该项未启用
)

// CheckResult 是单项检查的结果。
type CheckResult struct {
	Name   string
	Status CheckStatus
	Detail string
}

// Report 是完整的自检报告。
type Report struct {
	Results []CheckResult
}

// add 追加一条结果。
func (r *Report) add(name string, status CheckStatus, format string, args ...any) {
	r.Results = append(r.Results, CheckResult{
		Name: name, Status: status, Detail: fmt.Sprintf(format, args...),
	})
}

// Failed 判断是否存在阻断性失败。
func (r *Report) Failed() bool {
	for _, res := range r.Results {
		if res.Status == StatusFail {
			return true
		}
	}
	return false
}

// Counts 统计各状态数量。
func (r *Report) Counts() map[CheckStatus]int {
	out := map[CheckStatus]int{}
	for _, res := range r.Results {
		out[res.Status]++
	}
	return out
}

// WriteText 输出人类可读的报告。
func (r *Report) WriteText(w io.Writer) {
	fmt.Fprintln(w, "网关配置自检（--dry-run）")
	fmt.Fprintln(w, strings.Repeat("─", 78))
	for _, res := range r.Results {
		marker := map[CheckStatus]string{
			StatusPass: "✓", StatusFail: "✗", StatusWarn: "!", StatusSkip: "-",
		}[res.Status]
		fmt.Fprintf(w, " %s %-4s %-26s %s\n", marker, res.Status, res.Name, res.Detail)
	}
	fmt.Fprintln(w, strings.Repeat("─", 78))

	c := r.Counts()
	fmt.Fprintf(w, " 通过 %d  失败 %d  告警 %d  跳过 %d\n",
		c[StatusPass], c[StatusFail], c[StatusWarn], c[StatusSkip])
	if r.Failed() {
		fmt.Fprintln(w, " 结论：装配失败，配置不可用于部署")
	} else {
		fmt.Fprintln(w, " 结论：装配通过，配置可用于部署")
	}
}

// WriteJSON 输出机器可读的报告，供 CI 解析归档。
func (r *Report) WriteJSON(w io.Writer) error {
	type jsonResult struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
	out := struct {
		OK      bool         `json:"ok"`
		Results []jsonResult `json:"results"`
	}{OK: !r.Failed()}
	for _, res := range r.Results {
		out.Results = append(out.Results, jsonResult{res.Name, string(res.Status), res.Detail})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// DryRunOptions 控制自检范围。
type DryRunOptions struct {
	ConfigPath string
	CgroupRoot string
	// Probe 为 true 时额外对上游与 NER 服务做网络拨测。
	// 默认关闭：CI 环境通常触达不到生产后端，把网络可达性
	// 当作装配失败会让流水线在正确的配置上误报红。
	Probe        bool
	ProbeTimeout time.Duration
}

// RunDryRun 执行完整自检。返回报告，不启动任何监听。
//
// 各检查项之间尽量独立执行：CI 希望一次看到**所有**问题，
// 而不是修一个跑一次、再暴露下一个。有依赖关系的项在前置失败时标记为 SKIP。
func RunDryRun(opts DryRunOptions) *Report {
	rep := &Report{}
	if opts.ProbeTimeout <= 0 {
		opts.ProbeTimeout = 3 * time.Second
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// --- 1. 配置解析 ---
	cfg, err := loadConfig(opts.ConfigPath)
	if err != nil {
		rep.add("配置解析", StatusFail, "%v", err)
		// 配置读不出来，后面全部无从谈起
		for _, name := range []string{
			"配置语义校验", "并发度与 CPU 配额", "路由策略装配", "PII 检测器装配",
			"AST 脱敏路径自检", "凭证策略与密钥握手", "限流器装配", "GPU 负载注册表",
			"前缀亲和环", "代理处理器装配",
		} {
			rep.add(name, StatusSkip, "配置解析失败，跳过")
		}
		return rep
	}
	rep.add("配置解析", StatusPass, "%s（未知字段已拒绝）", opts.ConfigPath)
	rep.add("配置语义校验", StatusPass, "后端 %d 个，规则 %d 条", len(cfg.Targets), len(cfg.Rules))

	// --- 2. 并发度与 CPU 配额 ---
	checkConcurrency(rep, cfg, opts)

	// --- 3. 路由策略装配（含 glob 编译、后端名唯一性、规则引用校验）---
	policy, err := buildPolicy(cfg)
	if err != nil {
		rep.add("路由策略装配", StatusFail, "%v", err)
	} else {
		tiers := map[int]int{}
		for _, t := range cfg.Targets {
			tiers[int(t.Tier)]++
		}
		rep.add("路由策略装配", StatusPass, "梯队分布 %v，降级链已就绪", tiers)
	}

	// --- 4. PII 检测器装配（正则与名册编译）---
	detector, err := buildDetector(cfg)
	if err != nil {
		rep.add("PII 检测器装配", StatusFail, "%v", err)
	} else if comp, ok := detector.(detect.GapReporter); ok {
		if missing := comp.Missing(); len(missing) > 0 {
			// 不阻断启动，但必须让运维知道自己漏了什么
			rep.add("PII 检测器装配", StatusWarn,
				"存在覆盖缺口 %v——这几类实体将完全裸奔，请配置名册或接入 NER", missing)
		} else {
			rep.add("PII 检测器装配", StatusPass, "覆盖类型 %d 种，无缺口", len(detector.CoveredTypes()))
		}
	} else {
		// 断言失败时如果什么都不加，这一项会从报告里整条消失——
		// 运维看到的是「没有这项检查」而不是「这项检查失败了」，
		// 而这正是覆盖缺口告警此前被包装层吞掉的方式。宁可吵，不可静默。
		//
		// Adding nothing here would delete the whole item from the report:
		// operators would see "no such check" rather than "check failed" —
		// exactly how a wrapper silently swallowed this warning before.
		rep.add("PII 检测器装配", StatusWarn,
			"检测器 %q 未实现 detect.GapReporter，无法判断覆盖缺口——"+
				"若它是包装层，请让它透传 Missing/CoveredTypes", detector.Name())
	}

	// --- 5. AST 脱敏路径自检 ---
	checkSanitizer(rep)

	// --- 6. 凭证策略装配与密钥源握手 ---
	checkCredentials(rep, cfg)

	// --- 7~9. 其余组件装配 ---
	checkRuntimeComponents(rep, cfg)

	// --- 10. 代理处理器装配 ---
	if policy != nil && detector != nil {
		handler, _, cleanup, err := buildHandler(context.Background(), cfg, logger, lifecycle.NewState(), lifecycle.NewTracker())
		if err != nil {
			rep.add("代理处理器装配", StatusFail, "%v", err)
		} else {
			cleanup() // 立刻回收，dry-run 不留后台协程
			_ = handler
			rep.add("代理处理器装配", StatusPass, "全部依赖已注入")
		}
	} else {
		rep.add("代理处理器装配", StatusSkip, "前置装配失败，跳过")
	}

	// --- 11. 网络拨测（可选）---
	if opts.Probe {
		checkConnectivity(rep, cfg, opts.ProbeTimeout)
	} else {
		rep.add("上游连通性", StatusSkip, "未启用 --probe")
		rep.add("NER 服务连通性", StatusSkip, "未启用 --probe")
	}

	return rep
}

// checkConcurrency 检查并发度是否与容器 CPU 配额匹配。
func checkConcurrency(rep *Report, cfg *Config, opts DryRunOptions) {
	quota, err := cpulimit.DetectQuota(opts.CgroupRoot)
	if err != nil {
		// 探测失败不能当成「不限」——那正好会让并发度按宿主核数开，
		// 撞进 CFS 限流陷阱
		rep.add("并发度与 CPU 配额", StatusWarn, "配额探测失败：%v", err)
		return
	}
	if !quota.Limited {
		rep.add("并发度与 CPU 配额", StatusPass,
			"未设配额（裸机或无限制），GOMAXPROCS=%d", runtime.GOMAXPROCS(0))
		return
	}
	rec := cpulimit.Recommend(quota, cpulimit.RoundDown)
	if rec.Oversubscribed {
		rep.add("并发度与 CPU 配额", StatusWarn, "%s", rec.Reason)
		return
	}
	rep.add("并发度与 CPU 配额", StatusPass, "%s", rec.Reason)
}

// canonicalRequest 是脱敏自检用的标准样本。
//
// 同时包含自然语言区域与协议骨架，用来验证 AST 定向清洗
// 「该碰的碰了、不该碰的没碰」。
const canonicalRequest = `{
  "model": "probe-model",
  "stop": ["<|end|>"],
  "messages": [
    {"role": "user", "content": "SELFCHECK_CONTENT"},
    {"role": "assistant", "tool_calls": [{"id": "call_probe", "type": "function",
      "function": {"name": "probe_tool", "arguments": "{\"k\":\"SELFCHECK_ARG\"}"}}]}
  ],
  "tools": [{"type": "function", "function": {
    "name": "probe_tool", "description": "SELFCHECK_DESC",
    "parameters": {"type": "object",
      "properties": {"k": {"type": "string", "enum": ["KEEP_A", "KEEP_B"]}},
      "required": ["k"]}}}]
}`

// checkSanitizer 对 AST 定向清洗做启动期自检。
//
// 这不是重复单元测试。单元测试跑的是当前代码，自检跑的是**当前二进制**：
// 一次错误的合并、一个被误删的规则，会让脱敏静默失效——
// 请求照常通过，PII 直接出境，没有任何报错。宁可在启动时拒绝服务。
func checkSanitizer(rep *Report) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(canonicalRequest), &doc); err != nil {
		rep.add("AST 脱敏路径自检", StatusFail, "标准样本损坏：%v", err)
		return
	}

	err := document.SanitizeDocument(doc, func(s string) (string, error) {
		return "REDACTED", nil
	})
	if err != nil {
		rep.add("AST 脱敏路径自检", StatusFail, "清洗执行失败：%v", err)
		return
	}

	// 按解码后的**结构**比对，而不是在序列化字节上做子串匹配。
	// 字节层面的比对会被键序、空白、以及编码器的转义策略干扰——
	// 这类误报会让运维怀疑自检本身，久而久之就没人看它了。
	if bad := verifySanitized(doc); bad != "" {
		rep.add("AST 脱敏路径自检", StatusFail, "%s", bad)
		return
	}
	rep.add("AST 脱敏路径自检", StatusPass,
		"%d 条路径，自然语言已净化且协议骨架完整", len(document.SanitizeRuleDescriptions()))
}

// verifySanitized 逐项核对清洗结果，返回空串表示通过。
func verifySanitized(doc map[string]any) string {
	get := func(path ...any) any {
		cur := any(doc)
		for _, p := range path {
			switch k := p.(type) {
			case string:
				m, ok := cur.(map[string]any)
				if !ok {
					return nil
				}
				cur = m[k]
			case int:
				a, ok := cur.([]any)
				if !ok || k >= len(a) {
					return nil
				}
				cur = a[k]
			}
		}
		return cur
	}

	// 自然语言区域必须已被净化
	natural := []struct {
		name string
		path []any
	}{
		{"消息正文", []any{"messages", 0, "content"}},
		{"工具描述", []any{"tools", 0, "function", "description"}},
	}
	for _, n := range natural {
		if v, _ := get(n.path...).(string); v != "REDACTED" {
			return fmt.Sprintf("%s 未被净化（实际 %q）——脱敏已静默失效，PII 会直接出境", n.name, v)
		}
	}
	// 工具入参是 JSON 套 JSON，值应被净化、键应保留
	rawArgs, _ := get("messages", 1, "tool_calls", 0, "function", "arguments").(string)
	var args map[string]any
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		return fmt.Sprintf("工具入参净化后不再是合法 JSON：%v", err)
	}
	if _, ok := args["k"]; !ok {
		return "工具入参的键名丢失——本地工具将认不出该参数"
	}
	if args["k"] != "REDACTED" {
		return fmt.Sprintf("工具入参的值未被净化（实际 %v）", args["k"])
	}

	// 协议骨架必须原封不动
	skeleton := []struct {
		name string
		path []any
		want any
	}{
		{"model", []any{"model"}, "probe-model"},
		{"stop 序列", []any{"stop", 0}, "<|end|>"},
		{"消息 role", []any{"messages", 0, "role"}, "user"},
		{"tool_call id", []any{"messages", 1, "tool_calls", 0, "id"}, "call_probe"},
		{"工具名", []any{"tools", 0, "function", "name"}, "probe_tool"},
		{"schema enum[0]", []any{"tools", 0, "function", "parameters", "properties", "k", "enum", 0}, "KEEP_A"},
		{"schema required[0]", []any{"tools", 0, "function", "parameters", "required", 0}, "k"},
	}
	for _, sk := range skeleton {
		if got := get(sk.path...); got != sk.want {
			return fmt.Sprintf("协议骨架 %s 被污染（期望 %v，实际 %v）——请求协议将破损",
				sk.name, sk.want, got)
		}
	}
	return ""
}

// checkCredentials 装配凭证策略并**真实读取**一次密钥。
//
// 只校验配置合法性不够：密钥挂载缺失、文件为空、权限不对，
// 这些只有真正读一次才知道。零信任下凭证读不到就必须阻断请求，
// 那样的故障应该在部署前发现，而不是在第一个线上请求上。
func checkCredentials(rep *Report, cfg *Config) {
	var configured, ok int
	var problems []string

	for _, t := range cfg.Targets {
		if t.CredentialKey == "" {
			continue // 内网后端可不配凭证
		}
		configured++
		cp := buildCredentialPolicy(cfg, t)
		if err := cp.Validate(); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", t.Name, err))
			continue
		}
		// 真实握手：把密钥读出来。只记指纹，绝不记明文。
		secret, err := cp.Provider.Fetch(t.CredentialKey)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: 密钥读取失败 %v", t.Name, err))
			continue
		}
		if secret.Reveal() == "" {
			problems = append(problems, fmt.Sprintf("%s: 密钥为空", t.Name))
			continue
		}
		ok++
	}

	switch {
	case configured == 0:
		rep.add("凭证策略与密钥握手", StatusWarn, "无后端配置凭证——出站请求将不携带任何鉴权")
	case len(problems) > 0:
		rep.add("凭证策略与密钥握手", StatusFail, "%s", strings.Join(problems, "；"))
	default:
		rep.add("凭证策略与密钥握手", StatusPass, "%d/%d 个后端密钥握手成功", ok, configured)
	}
}

// checkRuntimeComponents 装配限流器、GPU 负载表与前缀亲和环。
func checkRuntimeComponents(rep *Report, cfg *Config) {
	lim := toLimits(cfg.RateLimit.LimitConfig)
	if lim.TokensPerWindow == 0 {
		rep.add("限流器装配", StatusWarn, "未设 token 配额——突发流量下无保护")
	} else {
		rep.add("限流器装配", StatusPass, "窗口 %v 内 %d tokens，%d 个主体独立配额",
			lim.Window, lim.TokensPerWindow, len(cfg.RateLimit.PerSubject))
	}

	th := toThresholds(cfg.GPU)
	if th.KVCritical <= th.KVElevated {
		rep.add("GPU 负载注册表", StatusFail,
			"kv_critical(%.2f) 必须大于 kv_elevated(%.2f)", th.KVCritical, th.KVElevated)
	} else if th.KVCritical > 0.95 {
		// 从放行到真正占住 KV 有数百毫秒延迟，阈值贴边会来不及刹车
		rep.add("GPU 负载注册表", StatusWarn,
			"kv_critical=%.2f 过于贴边，控制延迟内可能已被推过 100%%", th.KVCritical)
	} else {
		rep.add("GPU 负载注册表", StatusPass,
			"阈值 elevated=%.2f critical=%.2f，探测间隔 %v",
			th.KVElevated, th.KVCritical, cfg.GPU.ProbeInterval)
	}

	if !cfg.GPU.PrefixAffinity {
		rep.add("前缀亲和环", StatusWarn,
			"未启用——同前缀请求将被打散，vLLM prefix caching 命中率降至 1/副本数")
	} else {
		rep.add("前缀亲和环", StatusPass,
			"%d 个副本，负载上限倍数 %.2f", len(cfg.Targets), cfg.GPU.AffinityLoadFactor)
	}
}

// checkConnectivity 对上游与 NER 服务做真实网络拨测。
func checkConnectivity(rep *Report, cfg *Config, timeout time.Duration) {
	client := &http.Client{Timeout: timeout}

	var okCount int
	var problems []string
	for _, t := range cfg.Targets {
		url := gpuload.MetricsURLFor(t.BaseURL)
		resp, err := client.Get(url)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", t.Name, err))
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			problems = append(problems, fmt.Sprintf("%s: 指标端点返回 %d", t.Name, resp.StatusCode))
			continue
		}
		okCount++
	}
	if len(problems) > 0 {
		rep.add("上游连通性", StatusFail, "%s", strings.Join(problems, "；"))
	} else {
		rep.add("上游连通性", StatusPass, "%d/%d 个后端指标端点可达", okCount, len(cfg.Targets))
	}

	if cfg.PII.NER.Endpoint == "" {
		rep.add("NER 服务连通性", StatusSkip, "未配置 NER 服务")
		return
	}
	resp, err := client.Post(cfg.PII.NER.Endpoint, "application/json",
		strings.NewReader(`{"text":"连通性探测","types":["NAME"]}`))
	if err != nil {
		rep.add("NER 服务连通性", StatusFail, "%v", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		rep.add("NER 服务连通性", StatusFail, "返回 %d", resp.StatusCode)
		return
	}
	// 不只看状态码：响应必须符合契约，否则运行期才发现格式不对
	var probe struct {
		Entities []map[string]any `json:"entities"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		rep.add("NER 服务连通性", StatusFail, "响应不符合契约（应含 entities 数组）：%v", err)
		return
	}
	rep.add("NER 服务连通性", StatusPass, "契约校验通过")
}

// exitCodeFor 返回 CI 用的退出码。
func exitCodeFor(rep *Report) int {
	if rep.Failed() {
		return 1
	}
	return 0
}

// runDryRunAndExit 执行自检、输出报告并按结果退出进程。
func runDryRunAndExit(opts DryRunOptions, jsonOut bool) {
	rep := RunDryRun(opts)
	if jsonOut {
		if err := rep.WriteJSON(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "输出报告失败:", err)
			os.Exit(2)
		}
	} else {
		rep.WriteText(os.Stdout)
	}
	os.Exit(exitCodeFor(rep))
}

// printSchemaAndExit 输出 CRD 或 Schema 后退出。
func printSchemaAndExit(asCRD bool) {
	var out []byte
	var err error
	if asCRD {
		out, err = config.GenerateCRD(config.DefaultCRDOptions())
	} else {
		out, err = yaml.Marshal(config.GenerateSchema())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "生成 schema 失败:", err)
		os.Exit(2)
	}
	os.Stdout.Write(out)
	os.Exit(0)
}
