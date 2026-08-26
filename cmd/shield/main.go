// Command shield 是 PII 脱敏 sidecar。
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

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
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

	srv, err := sidecar.New(sidecar.Options{
		Detector:    detector,
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
	detectors := []detect.Detector{detect.NewRegexDetector(disabled...)}

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
