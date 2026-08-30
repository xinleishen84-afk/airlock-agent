// Command airlock-agent-advanced 是接了 NER sidecar 的 PII 脱敏 sidecar。
//
// The PII sidecar with the NER analyzer wired in.
//
// # 与 airlock-agent 的关系
// # Its relationship to airlock-agent
//
// 两个二进制，不是一个二进制的两种模式。这是刻意的：
//
// Two binaries, not two modes of one. Deliberately:
//
//	airlock-agent           1 个外部依赖，11MB，纯 Go，无跨进程调用
//	airlock-agent-advanced  8 个外部依赖（gRPC + protobuf），另需 Python sidecar
//
// 如果做成一个二进制加开关，那 gRPC 与 protobuf 的依赖树就会进到每一个
// 部署里——包括那些只想要 Core 的。而「零额外依赖」一旦不成立，它就再也
// 回不来了：依赖是加进去容易、拿出来难的东西。
//
// One binary with a flag would pull gRPC and protobuf into every deployment,
// including those that only want Core. Once "no extra dependencies" stops
// being true it does not come back: dependencies are easy to add and hard to
// remove.
//
// # 什么时候需要它
// # When it is needed
//
// 实测：Core 模式覆盖语料里 90.5% 的实体（结构化标识 37/37，
// 非结构化 1/5）。剩下的是姓名、地址、机构名——它们没有字面特征，
// 正则找不到，只能靠模型。
//
// Measured: Core covers 90.5% of the corpus — all structured identifiers and
// one in five unstructured entities. The rest are names, addresses and
// organizations, which have no lexical signature.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/nerclient"
	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/audit"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
	"github.com/xinleishen84-afk/airlock-agent/pii/verify"
	"github.com/xinleishen84-afk/airlock-agent/sidecar"
)

var (
	addr          = flag.String("addr", ":8888", "监听地址")
	jurisdictions = flag.String("jurisdictions", "", "逗号分隔的国家包代码（如 GEN,CN）。必填")
	tenantHeader  = flag.String("tenant-header", "", "从该请求头解析租户")
	singleTenant  = flag.String("single-tenant", "", "把所有请求归入该租户")

	nerSocket = flag.String("ner-socket", "",
		"NER sidecar 的 Unix domain socket（同 Pod 部署）。\n"+
			"实测 IPC 往返 ~110µs")
	nerAddress = flag.String("ner-address", "",
		"NER 分析器的 host:port（独立 Service 部署）。与 --ner-socket 二选一。\n"+
			"可单独水平扩缩容，代价是走完整 TCP 协议栈——实测净 IPC 是 UDS 的 1.4 倍，\n"+
			"而这还没算 K8s Service 转发那一跳")
	nerTimeout = flag.Duration("ner-timeout", 500*time.Millisecond,
		"NER 调用超时。它在 TTFT 关键路径上，每个走到第三层的请求都要付")
	nerFailOpen = flag.Bool("ner-fail-open", false,
		"NER 不可用时放行而非阻断。默认阻断——第三层负责的正是正则找不到的\n"+
			"那几类，放行等于在它们上完全裸奔")

	nameRoster    = flag.String("name-roster", "", "姓名名册文件（每行一个词条）")
	orgRoster     = flag.String("org-roster", "", "机构名册文件")
	surnames      = flag.Bool("surnames", true, "启用复姓识别")
	singleSurname = flag.Bool("single-surnames", false,
		"启用单姓识别。实测在对抗性语料上召回零增益、误报十四处，因此默认关闭")

	sessionTTL = flag.Duration("session-ttl", time.Hour, "脱敏映射存活时长")

	// Advanced 与 Core 持有同一种会话保险库，因此受同一条约束。
	// 校验实现在 sidecar 包里共用一份——分散在各个 main 里就会漂移成
	// 「有的进程管、有的不管」，本行缺失时部署清单传的这个 flag 会让
	// Advanced Pod 以「flag provided but not defined」崩溃循环。
	//
	// Advanced holds the same vault as Core and is under the same constraint.
	// The check is shared in the sidecar package; duplicating it per main is
	// what let this binary drift into not having the flag at all while the
	// manifest already passed it.
	sessionConsistency = flag.String("session-consistency", "",
		sidecar.SessionConsistencyFlagUsage)

	// 审计装配与 Core 共用 sidecar 包里的同一份实现，理由见那里的注释：
	// 安全相关的装配在两个 main 里各写一份就会漂移。
	auditSink    = flag.String("audit-sink", "", audit.SinkFlagUsage)
	auditKeyFile = flag.String("audit-key-file", "", audit.KeyFlagUsage)
	maxSessions  = flag.Int("max-sessions", 100_000, "活跃会话上限")
	logLevel     = flag.String("log-level", "info", "日志级别")
)

func main() {
	flag.Parse()

	logger := newLogger(*logLevel)
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("启动失败", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	if *nerSocket == "" && *nerAddress == "" {
		return fmt.Errorf(
			"必须指定 --ner-socket 或 --ner-address。\n" +
				"如果不需要 NER，请改用 airlock-agent（1 个外部依赖、11MB、" +
				"实测覆盖语料 90.5%%）——本二进制的存在理由就是接 NER")
	}

	// --- 第一、二层：进程内，与 Core 模式完全相同的装配 ---
	reg, err := packs.NewRegistry(splitCSV(*jurisdictions))
	if err != nil {
		return err
	}
	detectors := []detect.Detector{reg}

	roster := map[detect.EntityType][]string{}
	if names, err := readRoster(*nameRoster); err != nil {
		return err
	} else if len(names) > 0 {
		roster[detect.TypeName] = names
	}
	if orgs, err := readRoster(*orgRoster); err != nil {
		return err
	} else if len(orgs) > 0 {
		roster[detect.TypeOrg] = orgs
	}
	// 只记条数，绝不记条目：姓名名册本身就是 PII，只是以配置形式加载。
	// Sizes, never entries — a name roster is a list of people.
	rosterSizes := map[string]int{}
	for typ, entries := range roster {
		rosterSizes[string(typ)] = len(entries)
	}

	if len(roster) > 0 {
		gaz, err := detect.NewGazetteerDetector(roster, false, 2)
		if err != nil {
			return fmt.Errorf("构造名册检测器: %w", err)
		}
		detectors = append(detectors, gaz)
	}

	if *surnames {
		opts := detect.DefaultSurnameOptions()
		opts.IncludeSingle = *singleSurname
		sr, err := detect.NewSurnameRecognizer(opts)
		if err != nil {
			return err
		}
		srReg := detect.NewRegistry()
		if err := srReg.Register(sr); err != nil {
			return err
		}
		detectors = append(detectors, srReg)
	}

	fast := detect.NewCompositeDetector(detectors, 0)

	// --- 第三层：跨进程 ---
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := nerclient.New(ctx, nerclient.Options{
		SocketPath: *nerSocket,
		Address:    *nerAddress,
		Timeout:    *nerTimeout,
		FailOpen:   *nerFailOpen,
	})
	if err != nil {
		return fmt.Errorf("连接 NER 分析器失败: %w", err)
	}
	defer client.Close()

	cascade, err := detect.NewCascade(fast, client)
	if err != nil {
		return err
	}

	logger.Info("三层级联已装配",
		"第一二层", fmt.Sprintf("%d 个识别器", len(reg.Names())),
		"第三层", client.Model(),
		"传输", client.Transport(),
		"fail_open", *nerFailOpen)

	// --- 证据链 ---
	validator, err := verify.NewDefaultEvidenceValidator()
	if err != nil {
		return err
	}
	logger.Info("证据链已装配", "覆盖类型", validator.Types())

	if err := sidecar.ValidateSessionConsistency(*sessionConsistency); err != nil {
		logger.Error("会话一致性声明缺失或非法", "err", err)
		os.Exit(1)
	}
	logger.Info("会话一致性声明", "mode", *sessionConsistency)

	resolver, err := buildTenantResolver()
	if err != nil {
		return err
	}
	logger.Info("租户隔离已生效", "resolver", resolver.Name())

	auditor, fingerprinter, err := audit.Build(*auditSink, *auditKeyFile, logger)
	if err != nil {
		return err
	}
	if auditor != nil {
		defer func() { _ = auditor.Close() }()
		logger.Info("GDPR 安全审计轨迹已接通", "sink", auditor.SinkName())
	} else {
		logger.Warn("未接审计轨迹——不会产生任何 GDPR 审计事件",
			"补法", "--audit-sink=stderr|<文件>|<SIEM URL> 搭配 --audit-key-file")
	}

	srv, err := sidecar.New(sidecar.Options{
		Detector:          cascade,
		Evidence:          validator,
		FailClosed:        true,
		SessionTTL:        *sessionTTL,
		MaxSessions:       *maxSessions,
		TenantResolver:    resolver,
		Auditor:           auditor,
		Fingerprinter:     fingerprinter,
		Jurisdictions:     splitCSV(*jurisdictions),
		RosterSizes:       rosterSizes,
		RecognizerCatalog: sidecar.CatalogFromJurisdictions(splitCSV(*jurisdictions)),
		Logger:            logger,
	})
	if err != nil {
		return err
	}
	defer srv.Close()

	logger.Info("Advanced 模式已启动", "addr", *addr)
	return serveHTTP(srv, *addr, logger)
}

func buildTenantResolver() (sidecar.TenantResolver, error) {
	switch {
	case *tenantHeader != "" && *singleTenant != "":
		return nil, fmt.Errorf("--tenant-header 与 --single-tenant 只能选一个")
	case *tenantHeader != "":
		return sidecar.NewHeaderTenantResolver(*tenantHeader)
	case *singleTenant != "":
		return sidecar.NewStaticTenantResolver(anonymize.Tenant(*singleTenant))
	}
	return nil, fmt.Errorf(
		"必须指定 --tenant-header 或 --single-tenant：缺少租户隔离时，" +
			"任何拿到他人 session_id 的调用方都能取回对方的明文 PII")
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
