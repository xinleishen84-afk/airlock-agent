// Command airlock-agent 是 PII 脱敏 sidecar。
//
// 它把结构化 AST 定向脱敏引擎暴露为 HTTP 服务，任何网关都能接：
// Envoy（经 ext_proc 适配）、APISIX（serverless 插件）、Kong（plugin）、
// Nginx（njs）、乃至完全自研的网关。
//
//	POST /v1/redact    出站脱敏
//	POST /v1/restore   入站复原
//	POST /v1/session/end
//	GET  /healthz  /stats
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/document"
	"github.com/xinleishen84-afk/airlock-agent/pii/preset"
	"github.com/xinleishen84-afk/airlock-agent/pii/verify"
	"github.com/xinleishen84-afk/airlock-agent/sidecar"
)

var (
	addr        = flag.String("addr", ":8888", "监听地址")
	nameRoster  = flag.String("name-roster", "", "姓名名册文件（每行一个词条）")
	orgRoster   = flag.String("org-roster", "", "机构名册文件")
	nerEndpoint = flag.String("ner", "", "外部 NER 服务地址。\n"+
		"不配的话，姓名/地址/机构名只能靠名册覆盖，名册之外的完全检测不到")
	nerTimeout = flag.Duration("ner-timeout", 300*time.Millisecond, "NER 调用超时")
	failClosed = flag.Bool("fail-closed", true,
		"检测器故障时阻断请求而非放行原文。这是脱敏组件唯一安全的默认值")
	sessionTTL   = flag.Duration("session-ttl", time.Hour, "脱敏映射存活时长")
	maxSessions  = flag.Int("max-sessions", 100_000, "活跃会话上限")
	disableTypes = flag.String("disable-types", "",
		"逗号分隔的检测类型黑名单（如内网场景可关掉 IP）")
	jurisdictions = flag.String("jurisdictions", "",
		"逗号分隔的国家包代码（如 GEN,CN）。必填——\n"+
			"一个都不装意味着任何文本都扫不出 PII，且看起来像「数据很干净」")
	tenantRules = flag.String("tenant-rules", "",
		"租户自定义 YAML 规则目录（工号、资产编号等企业内部标识）")
	surnames = flag.Bool("surnames", true,
		"启用复姓识别。零依赖、确定性——统计模型对复姓是系统性零召回")
	singleSurnames = flag.Bool("single-surnames", false,
		"启用单姓识别。实测在对抗性语料上召回零增益、误报十四处，因此默认关闭")
	matrixFile = flag.String("redaction-matrix", "",
		"脱敏策略矩阵配置。配置后请求必须带 destination 字段")
	auditSink    = flag.String("audit-sink", "", sidecar.AuditSinkFlagUsage)
	auditKeyFile = flag.String("audit-key-file", "", sidecar.AuditKeyFlagUsage)

	hashKeyFile = flag.String("hash-key-file", "",
		"HMAC 密钥文件（密钥卷挂载点）。矩阵里用到 hash 算子时必填。\n"+
			"密钥绝不能写进配置文件——与策略文件同行的密钥会随它的每一份副本流传")
	ontologyFile = flag.String("ontology", "",
		"本体词表 YAML。矩阵里用到 generalize 算子时必填")
	sessionConsistency = flag.String("session-consistency", "",
		sidecar.SessionConsistencyFlagUsage)

	tenantHeader = flag.String("tenant-header", "",
		"从该请求头解析租户（如 X-Tenant-Id）。\n"+
			"只有当调用方绕不过去的上游来设置它时才安全——服务网格、做认证的网关、\n"+
			"带 mTLS 的入口。在调用方能直连的端口上，这等于让他们自己挑租户")
	singleTenant = flag.String("single-tenant", "",
		"把所有请求归入该租户。确实是单租户部署时使用。\n"+
			"与 --tenant-header 二选一，且必须选一个：\n"+
			"缺少隔离时，任何拿到他人 session_id 的调用方都能取回对方的明文 PII")
	logLevel = flag.String("log-level", "info", "日志级别")
)

func main() {
	flag.Parse()

	logger := newLogger(*logLevel)
	slog.SetDefault(logger)

	detector, evidence, err := buildDetector(logger)
	if err != nil {
		logger.Error("构造检测器失败", "err", err)
		os.Exit(1)
	}

	if err := sidecar.ValidateSessionConsistency(*sessionConsistency); err != nil {
		logger.Error("会话一致性声明缺失或非法", "err", err)
		os.Exit(1)
	}
	logger.Info("会话一致性声明", "mode", *sessionConsistency)

	resolver, err := buildTenantResolver()
	if err != nil {
		logger.Error("构造租户解析器失败", "err", err)
		os.Exit(1)
	}
	logger.Info("租户隔离已生效", "resolver", resolver.Name())

	// 证据链在 Core 模式同样必要，而且理由就在上面那段复姓识别里。
	//
	// 复姓识别产出的是**候选**不是判决：复姓候选 0.70 分、单姓候选 0.45 分。
	// 证据链的 RejectUnverifiedBelow 把没有证据支撑的低分候选挡下——
	// 不接它，这些候选会原样进入脱敏管线，实测在对抗性语料上多出十四处误报。
	//
	// 也就是说：把复姓识别加进 Core 而不同时加证据链，是把召回换成了误报。
	//
	// The evidence chain is required in Core, and the reason is the surname
	// recognizer just above: it emits candidates, not verdicts. Without
	// verification they enter the pipeline verbatim — fourteen false positives
	// on the adversarial corpus. Adding surnames without the chain trades
	// recall for false positives.
	logger.Info("证据链已装配", "覆盖类型", evidence.Types())

	matrix, tokenStore, err := buildMatrix()
	if err != nil {
		logger.Error("构造脱敏策略矩阵失败", "err", err)
		os.Exit(1)
	}
	if matrix != nil {
		logger.Info("脱敏策略矩阵已生效", "流向", matrix.Destinations())
		fmt.Fprint(os.Stderr, matrix.Describe())
	}

	auditor, fingerprinter, err := sidecar.BuildAudit(*auditSink, *auditKeyFile, logger)
	if err != nil {
		logger.Error("构造审计轨迹失败", "err", err)
		os.Exit(1)
	}
	if auditor != nil {
		defer func() { _ = auditor.Close() }()
		logger.Info("GDPR 安全审计轨迹已接通", "sink", auditor.SinkName())
	} else {
		// 不发审计事件是合法选择，但不能是「以为发了其实没发」。
		// 这一整块能力此前在库里齐备、在二进制里一行都没接——
		// /v1/admin/inspect 报 sink=none、emitted=0，而 README 声称
		// 「不带原文的安全审计」。声称的能力静默缺席，只能靠说出来堵。
		logger.Warn("未接审计轨迹——不会产生任何 GDPR 审计事件",
			"补法", "--audit-sink=stderr|<文件>|<SIEM URL> 搭配 --audit-key-file")
	}

	srv, err := sidecar.New(sidecar.Options{
		Detector:          detector,
		Evidence:          evidence,
		Matrix:            matrix,
		TokenStore:        tokenStore,
		TenantResolver:    resolver,
		Auditor:           auditor,
		Fingerprinter:     fingerprinter,
		Jurisdictions:     splitCSV(*jurisdictions),
		RosterSizes:       rosterSizes,
		RecognizerCatalog: sidecar.CatalogFromJurisdictions(splitCSV(*jurisdictions)),
		FailClosed:        *failClosed,
		SessionTTL:        *sessionTTL,
		MaxSessions:       *maxSessions,
		Logger:            logger,
	})
	if err != nil {
		logger.Error("启动失败", "err", err)
		os.Exit(1)
	}
	defer srv.Close()

	if !*failClosed {
		logger.Warn("fail-closed 已关闭——检测器故障时将放行原文，存在 PII 泄露风险")
	}
	logger.Info("PII 脱敏 sidecar 启动",
		"addr", *addr,
		"fail_closed", *failClosed,
		"ner", firstNonEmpty(*nerEndpoint, "未配置"),
		"清洗白名单", document.SanitizeRuleDescriptions())

	server := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// 脱敏是短请求，可以设写超时；与网关的 SSE 长连接不同
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("监听失败", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("收到停机信号")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	logger.Info("已停止，脱敏映射已清空")
}

// buildDetector 按命令行参数组装检测器。
// buildDetector 按 Core 模式的标准装配构造检测器与证据链。
//
// 装配逻辑在 pii/preset 里，不在这里。
//
// 曾经它在这里，而评测在测试里手工搭了另一份。两份看起来一样，实际不一样：
// 评测那份装了复姓识别，这份没装。于是我拿评测的数字描述了这个二进制的
// 能力——报告「Core 覆盖 90.5%，复姓 欧阳志远 ✓」，而它对
// 「经办人欧阳志远」返回的是 {PHONE: 1}，一个字都没认出来。
//
// The assembly lives in pii/preset. It used to live here while the evaluation
// hand-built another; they looked identical and were not, so the measured
// numbers described a configuration this binary could not produce.
func buildDetector(logger *slog.Logger) (detect.Detector, *verify.EvidenceValidator, error) {
	roster := map[detect.EntityType][]string{}
	if names, err := readRoster(*nameRoster); err != nil {
		return nil, nil, err
	} else if len(names) > 0 {
		roster[detect.TypeName] = names
	}
	if orgs, err := readRoster(*orgRoster); err != nil {
		return nil, nil, err
	} else if len(orgs) > 0 {
		roster[detect.TypeOrg] = orgs
	}

	// 记下条数，不记条目。
	//
	// 姓名名册就是一份员工与客户姓名清单——它不是「碰巧含有 PII 的配置」，
	// 它本身就是 PII，只不过以配置形式加载。管理快照因此只报规模。
	//
	// Sizes, never entries: a name roster is a list of people. The admin
	// snapshot reports how many, never which.
	for typ, entries := range roster {
		rosterSizes[string(typ)] = len(entries)
	}

	var disabled []detect.EntityType
	for _, t := range splitCSV(*disableTypes) {
		disabled = append(disabled, detect.EntityType(strings.ToUpper(t)))
	}

	opts := preset.DefaultCoreOptions(splitCSV(*jurisdictions))
	opts.Roster = roster
	opts.DisabledTypes = disabled
	opts.Surnames = *surnames
	opts.SingleSurnames = *singleSurnames

	detector, validator, err := preset.Core(opts)
	if err != nil {
		return nil, nil, err
	}

	// Core 模式必须自陈它做不到什么。
	//
	// 一个只装了正则与名册的部署，与一个接了 NER 的部署，在日志上长得一样：
	// 都在正常处理请求、都在报告检出数。区别只在「姓名、地址、机构名
	// 有没有被检测」——而没被检测的那些不会出现在任何计数里。
	//
	// Without this, a regex-only deployment is indistinguishable in the logs
	// from one with NER: what is not scanned appears in no counter.
	logger.Info("运行在 Core 模式",
		"外部依赖", "无（单二进制，无跨进程调用）",
		"复姓识别", *surnames,
		"单姓识别", *singleSurnames,
		"实测覆盖率", "语料 90.5%（结构化 37/37，非结构化 1/5）")

	if comp, ok := detector.(detect.GapReporter); ok {
		if missing := comp.Missing(); len(missing) > 0 {
			logger.Warn("Core 模式检测不到这几类——它们没有字面特征，正则找不到",
				"类型", missing,
				"补法", "配 --name-roster/--org-roster 覆盖已知的，"+
					"或改用 airlock-agent-advanced 接 NER sidecar 覆盖未知的")
		}
	}
	return detector, validator, nil
}

// readRoster 从文件读取名册，每行一个词条。
func readRoster(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取名册 %s: %w", path, err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if term := strings.TrimSpace(line); term != "" && !strings.HasPrefix(term, "#") {
			out = append(out, term)
		}
	}
	return out, nil
}

// splitCSV 切分逗号分隔的列表。
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// newLogger 构造结构化日志器。
func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

// buildMatrix 装配脱敏策略矩阵。
//
// 密钥与词表由本函数从磁盘读取后交给矩阵，而不是由矩阵配置自己去读：
// 配置描述策略，进程提供材料。一份能自行拉取密钥的策略文件，
// 等于把密钥路径也变成了策略的一部分，任何能改配置的人都能改它指向哪。
//
// buildMatrix assembles the redaction matrix. The key and ontology are read
// here and handed in, rather than fetched by the matrix config itself: config
// describes policy, the process supplies material. A policy file that can
// fetch its own key makes the key path part of the policy, and anyone who can
// edit the policy can point it elsewhere.
func buildMatrix() (*anonymize.Matrix, anonymize.TokenStore, error) {
	if *matrixFile == "" {
		if *hashKeyFile != "" || *ontologyFile != "" {
			return nil, nil, fmt.Errorf(
				"配置了 --hash-key-file / --ontology 但没有 --redaction-matrix，" +
					"这些材料不会被任何算子使用")
		}
		return nil, nil, nil
	}

	deps := anonymize.MatrixDeps{TokenStore: anonymize.NewMemoryTokenStore(*sessionTTL)}

	if *hashKeyFile != "" {
		key, err := os.ReadFile(*hashKeyFile) //nolint:gosec // 路径由运维显式指定
		if err != nil {
			return nil, nil, fmt.Errorf("读取 HMAC 密钥失败: %w", err)
		}
		// 密钥文件常带尾部换行，原样使用会让同一把密钥因写入方式不同
		// 产生两组互不相容的摘要——跨系统关联就此断掉，且不会报错。
		// Key files usually carry a trailing newline; using it verbatim makes
		// one key produce two incompatible digest sets depending on how it was
		// written, silently breaking cross-system correlation.
		ring, err := anonymize.NewKeyring([]byte(strings.TrimSpace(string(key))), nil)
		if err != nil {
			return nil, nil, err
		}
		deps.Keyring = ring
	}

	if *ontologyFile != "" {
		o, err := anonymize.LoadOntologyFile(*ontologyFile)
		if err != nil {
			return nil, nil, err
		}
		deps.Ontology = o
	}

	m, err := anonymize.LoadMatrixFile(*matrixFile, deps)
	if err != nil {
		return nil, nil, err
	}
	return m, deps.TokenStore, nil
}

// buildTenantResolver 装配租户解析器。
//
// 两者必选其一，没有默认值。默认值只能是「所有人一个租户」，
// 而那意味着任何拿到他人 session_id 的调用方都能从 /v1/restore
// 取回对方的明文姓名和手机号——不是令牌，是值本身。
// 让「不做隔离」成为一个必须敲出来的命令行参数。
//
// One of the two is required, with no default. The only possible default is
// "everyone is one tenant", which means anyone holding another caller's
// session_id gets their name and phone number back in plaintext.
func buildTenantResolver() (sidecar.TenantResolver, error) {
	switch {
	case *tenantHeader != "" && *singleTenant != "":
		return nil, fmt.Errorf(
			"--tenant-header 与 --single-tenant 只能选一个——" +
				"同时配置时无法判断哪一个才是实际生效的隔离模型")

	case *tenantHeader != "":
		return sidecar.NewHeaderTenantResolver(*tenantHeader)

	case *singleTenant != "":
		return sidecar.NewStaticTenantResolver(anonymize.Tenant(*singleTenant))
	}
	return nil, fmt.Errorf(
		"必须指定 --tenant-header 或 --single-tenant：" +
			"缺少租户隔离时，会话保险库只以调用方提供的 session_id 作键，" +
			"任何拿到他人 session_id 的调用方都能取回对方的明文 PII")
}

// rosterSizes 记录各名册的条目数量，供管理快照展示。只记数量，绝不记条目。
var rosterSizes = map[string]int{}
