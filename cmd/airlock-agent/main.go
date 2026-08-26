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
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
	"github.com/xinleishen84-afk/airlock-agent/pii/document"
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
	matrixFile = flag.String("redaction-matrix", "",
		"脱敏策略矩阵配置。配置后请求必须带 destination 字段")
	hashKeyFile = flag.String("hash-key-file", "",
		"HMAC 密钥文件（密钥卷挂载点）。矩阵里用到 hash 算子时必填。\n"+
			"密钥绝不能写进配置文件——与策略文件同行的密钥会随它的每一份副本流传")
	ontologyFile = flag.String("ontology", "",
		"本体词表 YAML。矩阵里用到 generalize 算子时必填")
	logLevel = flag.String("log-level", "info", "日志级别")
)

func main() {
	flag.Parse()

	logger := newLogger(*logLevel)
	slog.SetDefault(logger)

	detector, err := buildDetector(logger)
	if err != nil {
		logger.Error("构造检测器失败", "err", err)
		os.Exit(1)
	}

	matrix, tokenStore, err := buildMatrix()
	if err != nil {
		logger.Error("构造脱敏策略矩阵失败", "err", err)
		os.Exit(1)
	}
	if matrix != nil {
		logger.Info("脱敏策略矩阵已生效", "流向", matrix.Destinations())
		fmt.Fprint(os.Stderr, matrix.Describe())
	}

	srv, err := sidecar.New(sidecar.Options{
		Detector:    detector,
		Matrix:      matrix,
		TokenStore:  tokenStore,
		FailClosed:  *failClosed,
		SessionTTL:  *sessionTTL,
		MaxSessions: *maxSessions,
		Logger:      logger,
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
func buildDetector(logger *slog.Logger) (detect.Detector, error) {
	var disabled []detect.EntityType
	for _, t := range splitCSV(*disableTypes) {
		disabled = append(disabled, detect.EntityType(strings.ToUpper(t)))
	}
	reg, err := packs.NewRegistry(splitCSV(*jurisdictions), disabled...)
	if err != nil {
		return nil, err
	}
	if *tenantRules != "" {
		if err := packs.LoadYAMLInto(reg, *tenantRules); err != nil {
			return nil, fmt.Errorf("装配租户规则: %w", err)
		}
	}
	logger.Info("已装配国家包",
		"jurisdictions", *jurisdictions, "识别器数", len(reg.Names()))
	detectors := []detect.Detector{reg}

	roster := map[detect.EntityType][]string{}
	if names, err := readRoster(*nameRoster); err != nil {
		return nil, err
	} else if len(names) > 0 {
		roster[detect.TypeName] = names
	}
	if orgs, err := readRoster(*orgRoster); err != nil {
		return nil, err
	} else if len(orgs) > 0 {
		roster[detect.TypeOrg] = orgs
	}
	if len(roster) > 0 {
		gaz, err := detect.NewGazetteerDetector(roster, false, 2)
		if err != nil {
			return nil, fmt.Errorf("构造名册检测器: %w", err)
		}
		detectors = append(detectors, gaz)
	}

	if *nerEndpoint != "" {
		ner, err := detect.NewRemoteNERDetector(detect.RemoteNEROptions{
			Endpoint: *nerEndpoint,
			Timeout:  *nerTimeout,
			FailOpen: !*failClosed,
		})
		if err != nil {
			return nil, fmt.Errorf("构造 NER 检测器: %w", err)
		}
		detectors = append(detectors, ner)
	}

	comp := detect.NewCompositeDetector(detectors, 0)
	if missing := comp.Missing(); len(missing) > 0 {
		// 正则检测不出人名——这是最危险的静默配置，必须显式告警
		logger.Warn("PII 检测存在覆盖缺口，这几类实体将完全裸奔",
			"missing", missing,
			"hint", "配置 --name-roster / --org-roster 或接入 --ner")
	}
	return comp, nil
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

	deps := anonymize.MatrixDeps{TokenStore: anonymize.NewMemoryTokenStore()}

	if *hashKeyFile != "" {
		key, err := os.ReadFile(*hashKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("读取 HMAC 密钥失败: %w", err)
		}
		// 密钥文件常带尾部换行，原样使用会让同一把密钥因写入方式不同
		// 产生两组互不相容的摘要——跨系统关联就此断掉，且不会报错。
		// Key files usually carry a trailing newline; using it verbatim makes
		// one key produce two incompatible digest sets depending on how it was
		// written, silently breaking cross-system correlation.
		deps.HashKey = []byte(strings.TrimSpace(string(key)))
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
