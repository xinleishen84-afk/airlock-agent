package piiredactionprocessor

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"
	"go.uber.org/zap"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
	"github.com/xinleishen84-afk/airlock-agent/pii/telemetry"
)

// typeStr is the component type used in collector configuration.
// 是 collector 配置中使用的组件类型名。
var typeStr = component.MustNewType("piiredaction")

// NewFactory returns the processor factory.
// 返回处理器工厂。
func NewFactory() processor.Factory {
	return processor.NewFactory(
		typeStr,
		createDefaultConfig,
		processor.WithTraces(createTraces, component.StabilityLevelBeta),
		processor.WithLogs(createLogs, component.StabilityLevelBeta),
		processor.WithMetrics(createMetrics, component.StabilityLevelBeta),
	)
}

// createDefaultConfig returns the default configuration.
// 返回默认配置。
//
// Jurisdictions and tenant are deliberately left empty so that Validate
// refuses to start rather than running with an assumption nobody made.
// jurisdictions 与 tenant 刻意留空，使 Validate 拒绝启动，
// 而不是带着一个没人做过的假设跑起来。
func createDefaultConfig() component.Config {
	return &Config{
		Strategy:      "hash",
		FailureMode:   FailureDrop,
		MaxValueBytes: 32 << 10,
		LogEvery:      time.Minute,
	}
}

// redactor holds the assembled firewall shared by all three signals.
// 持有三种信号共用的、已装配好的防火墙。
type redactor struct {
	firewall  *telemetry.Firewall
	cfg       *Config
	logger    *zap.Logger
	lastLogAt atomic.Int64
	dropped   atomic.Int64
}

// build assembles the firewall from configuration.
// 依配置装配防火墙。
func build(cfg *Config, logger *zap.Logger) (*redactor, error) {
	reg, err := packs.NewRegistry(cfg.Jurisdictions)
	if err != nil {
		return nil, err
	}

	var strategy anonymize.Strategy
	switch cfg.Strategy {
	case "drop":
		strategy = anonymize.NewDrop()
	case "hash":
		raw, err := os.ReadFile(cfg.HashKeyFile)
		if err != nil {
			return nil, fmt.Errorf("读取 HMAC 根密钥失败 / reading HMAC root key: %w", err)
		}
		// 密钥文件常带尾部换行，原样使用会让同一把密钥因写入方式不同产生
		// 两组互不相容的摘要——跨系统关联就此断掉，且不会报错。
		// Key files usually carry a trailing newline; using it verbatim makes
		// one key produce two incompatible digest sets.
		ring, err := anonymize.NewKeyring([]byte(strings.TrimSpace(string(raw))), nil)
		if err != nil {
			return nil, err
		}
		if strategy, err = anonymize.NewHash(ring, 8); err != nil {
			return nil, err
		}
	}

	policy := telemetry.Policy{MaxValueBytes: cfg.MaxValueBytes}
	if len(cfg.SkipKeys) > 0 {
		policy.SkipKeys = make(map[string]bool, len(cfg.SkipKeys))
		for _, k := range cfg.SkipKeys {
			policy.SkipKeys[k] = true
		}
	}

	fw, err := telemetry.New(reg, anonymize.Flow{Name: "telemetry", Default: strategy}, policy)
	if err != nil {
		return nil, err
	}

	logger.Info("PII 遥测防火墙已装配 / telemetry firewall assembled",
		zap.Strings("jurisdictions", cfg.Jurisdictions),
		zap.Int("recognizers", len(reg.Names())),
		zap.String("strategy", cfg.Strategy),
		zap.String("failure_mode", cfg.FailureMode))

	// 覆盖缺口必须在启动时喊出来：正则检不出人名，
	// 只装正则就上线时，姓名/地址/机构名会在遥测里完全裸奔。
	// Coverage gaps must be announced at startup: regexes cannot find names.
	if gaps := missingTypes(reg); len(gaps) > 0 {
		logger.Warn("PII 检测存在覆盖缺口，这几类实体将在遥测中完全裸奔 / coverage gaps",
			zap.Strings("missing", gaps))
	}

	return &redactor{firewall: fw, cfg: cfg, logger: logger}, nil
}

// missingTypes lists entity types no recognizer covers.
// 列出没有任何识别器覆盖的实体类型。
func missingTypes(reg *detect.Registry) []string {
	covered := map[detect.EntityType]bool{}
	for _, t := range reg.CoveredTypes() {
		covered[t] = true
	}
	var out []string
	for _, t := range []detect.EntityType{detect.TypeName, detect.TypeAddress, detect.TypeOrg} {
		if !covered[t] {
			out = append(out, string(t))
		}
	}
	return out
}

// tenantFor resolves the tenant for one batch.
// 解析一个批次的租户。
func (r *redactor) tenantFor(attrs pcommon.Map) (anonymize.Tenant, error) {
	if r.cfg.TenantAttribute != "" {
		if v, ok := attrs.Get(r.cfg.TenantAttribute); ok && v.Str() != "" {
			t := anonymize.Tenant(v.Str())
			if err := anonymize.ValidateTenant(t); err != nil {
				return "", err
			}
			return t, nil
		}
		if r.cfg.Tenant == "" {
			// 不回退到某个默认租户：那会把所有解析不出租户的批次合并进
			// 同一个隔离域，于是同一个手机号在其中得到相同摘要。
			// No fallback tenant: that would merge every unidentified batch
			// into one domain where the same phone gets the same digest.
			return "", fmt.Errorf(
				"资源属性 %s 缺失且未配置 tenant / missing %s and no tenant configured",
				r.cfg.TenantAttribute, r.cfg.TenantAttribute)
		}
	}
	return anonymize.Tenant(r.cfg.Tenant), nil
}

// fail applies the configured failure mode.
// 施加配置的故障处理方式。
func (r *redactor) fail(err error) error {
	r.dropped.Add(1)
	r.logThrottled(err)
	if r.cfg.FailureMode == FailureForward {
		return nil
	}
	return err
}

// logThrottled rate-limits the failure log.
// 对故障日志做频率限制。
//
// A failing detector fails on every span, and a log line per span turns one
// incident into a second one — the log backend falls over, taking the evidence
// of the first with it.
// 检测器一旦故障就会对每个 span 故障，而每个 span 一条日志会把一次事故
// 变成两次——日志后端被打垮，第一次事故的证据也一起没了。
func (r *redactor) logThrottled(err error) {
	if r.cfg.LogEvery <= 0 {
		r.logger.Error("遥测脱敏失败 / telemetry redaction failed", zap.Error(err))
		return
	}
	now := time.Now().UnixNano()
	last := r.lastLogAt.Load()
	if now-last < int64(r.cfg.LogEvery) {
		return
	}
	if !r.lastLogAt.CompareAndSwap(last, now) {
		return
	}
	r.logger.Error("遥测脱敏失败 / telemetry redaction failed",
		zap.Error(err),
		zap.Int64("dropped_total", r.dropped.Load()),
		zap.String("failure_mode", r.cfg.FailureMode))
}

func createTraces(_ context.Context, set processor.Settings, cfg component.Config,
	next consumer.Traces) (processor.Traces, error) {
	r, err := build(cfg.(*Config), set.Logger)
	if err != nil {
		return nil, err
	}
	return processorhelper.NewTraces(context.Background(), set, cfg, next,
		func(ctx context.Context, td ptrace.Traces) (ptrace.Traces, error) {
			rss := td.ResourceSpans()
			for i := range rss.Len() {
				tenant, err := r.tenantFor(rss.At(i).Resource().Attributes())
				if err != nil {
					return td, r.fail(err)
				}
				if _, err := r.firewall.Redact(ctx, tenant,
					traceWalker{rs: rss.At(i)}); err != nil {
					return td, r.fail(err)
				}
			}
			return td, nil
		},
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}))
}

func createLogs(_ context.Context, set processor.Settings, cfg component.Config,
	next consumer.Logs) (processor.Logs, error) {
	r, err := build(cfg.(*Config), set.Logger)
	if err != nil {
		return nil, err
	}
	return processorhelper.NewLogs(context.Background(), set, cfg, next,
		func(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
			rls := ld.ResourceLogs()
			for i := range rls.Len() {
				tenant, err := r.tenantFor(rls.At(i).Resource().Attributes())
				if err != nil {
					return ld, r.fail(err)
				}
				if _, err := r.firewall.Redact(ctx, tenant,
					logWalker{rl: rls.At(i)}); err != nil {
					return ld, r.fail(err)
				}
			}
			return ld, nil
		},
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}))
}

func createMetrics(_ context.Context, set processor.Settings, cfg component.Config,
	next consumer.Metrics) (processor.Metrics, error) {
	r, err := build(cfg.(*Config), set.Logger)
	if err != nil {
		return nil, err
	}
	return processorhelper.NewMetrics(context.Background(), set, cfg, next,
		func(ctx context.Context, md pmetric.Metrics) (pmetric.Metrics, error) {
			rms := md.ResourceMetrics()
			for i := range rms.Len() {
				tenant, err := r.tenantFor(rms.At(i).Resource().Attributes())
				if err != nil {
					return md, r.fail(err)
				}
				if _, err := r.firewall.Redact(ctx, tenant,
					metricWalker{rm: rms.At(i)}); err != nil {
					return md, r.fail(err)
				}
			}
			return md, nil
		},
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}))
}
