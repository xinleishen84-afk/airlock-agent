// Package piiredactionprocessor is an OpenTelemetry Collector processor that
// redacts PII from traces, logs and metrics in transit.
// 是一个在传输途中从链路追踪、日志与指标中脱敏 PII 的 OpenTelemetry
// Collector 处理器。
//
// # Where it belongs in the pipeline
// # 它在管线中的位置
//
// First. Ahead of batch, ahead of every exporter, ahead of anything that
// persists or forwards. A processor placed after batch still redacts, but the
// unredacted spans have already sat in a queue that a heap dump, a debug
// exporter or a crash log can read — and "we redact it eventually" is not a
// property anyone can testify to.
// 放在最前。在 batch 之前、在每一个 exporter 之前、在任何会持久化或转发的
// 组件之前。放在 batch 之后的处理器照样能脱敏，但未脱敏的 span 已经在一个
// 队列里待过，而堆转储、debug exporter 或崩溃日志都读得到它——
// 「我们最终会脱敏」不是任何人能作证的属性。
//
//	processors: [piiredaction, batch]     # 正确 / correct
//	processors: [batch, piiredaction]     # 已经晚了 / already too late
package piiredactionprocessor

import (
	"fmt"
	"time"

	"go.opentelemetry.io/collector/component"
)

// Config is the processor's configuration.
// 是处理器的配置。
type Config struct {
	// Jurisdictions names the country packs to load (GEN, CN, DE, ...).
	// 指定要加载的国家包（GEN、CN、DE……）。
	//
	// Required, with no default. A default would pick a home market and be
	// silently wrong everywhere else: scanning Italian traces with a US pack
	// reports zero PII, which reads as clean telemetry rather than as a
	// missing pack.
	// 必填且无默认值。默认值只能选定一个本土市场，在别处都静默地错：
	// 用美国包扫意大利链路会报告零 PII，
	// 这读起来像「遥测很干净」，而不是「装错了包」。
	Jurisdictions []string `mapstructure:"jurisdictions"`

	// Tenant is the isolation boundary used for hashing.
	// 是用于哈希的隔离边界。
	//
	// One collector instance usually serves one tenant. When it does not, the
	// tenant must come from a resource attribute — see TenantAttribute.
	// 一个 collector 实例通常服务一个租户。若非如此，
	// 租户必须来自资源属性——见 TenantAttribute。
	Tenant string `mapstructure:"tenant"`

	// TenantAttribute names a resource attribute carrying the tenant, for a
	// shared collector. It takes precedence over Tenant when present on a
	// batch.
	// 指定携带租户的资源属性名，供共享 collector 使用。
	// 批次上存在该属性时，它优先于 Tenant。
	TenantAttribute string `mapstructure:"tenant_attribute"`

	// Strategy is the redaction operator: hash or drop.
	// 是脱敏算子：hash 或 drop。
	//
	// mask is deliberately not offered. Placeholders are minted per distinct
	// value in a session vault, and telemetry has no session: every distinct
	// value would mint an entry nothing will ever resolve, so the vault grows
	// with traffic. On a metric label a per-value placeholder multiplies time
	// series exactly the way the raw value did, so the cardinality bomb
	// survives the redaction intact.
	// 刻意不提供 mask。占位符按不同值在会话保险库中铸造，而遥测没有会话：
	// 每个不同的值都会铸造一条永远不会有人去解析的记录，
	// 于是保险库随流量增长。放在指标标签上，逐值不同的占位符会像原值一样
	// 让时间序列成倍增长，于是基数炸弹原封不动地活过了这次脱敏。
	Strategy string `mapstructure:"strategy"`

	// HashKeyFile is the file holding the root HMAC key.
	// 是存放 HMAC 根密钥的文件。
	//
	// A path rather than the key itself: a collector configuration is mounted
	// as a ConfigMap, copied into container images and pasted into support
	// tickets. The key belongs in a secret volume that travels separately.
	// 用路径而非密钥本身：collector 配置会以 ConfigMap 挂载、
	// 被复制进容器镜像、被粘进工单。密钥属于一个单独流转的密钥卷。
	HashKeyFile string `mapstructure:"hash_key_file"`

	// SkipKeys replaces the default skip list when non-empty.
	// 非空时替换默认跳过清单。
	SkipKeys []string `mapstructure:"skip_keys"`

	// MaxValueBytes caps how much of one value is scanned. Zero uses the
	// default.
	// 限制单个值被扫描的字节数。0 表示使用默认值。
	MaxValueBytes int `mapstructure:"max_value_bytes"`

	// FailureMode is drop or forward.
	// 取值 drop 或 forward。
	//
	// drop is the default and the only defensible one for most deployments: a
	// lost span costs a gap in a dashboard, while a leaked one is copied into a
	// backend that retains it for a year and is readable by everyone with a
	// login. forward exists because a few deployments would rather lose the
	// guarantee than lose the telemetry, and that choice should be written in
	// the config rather than implied by a fallback.
	// drop 是默认值，也是多数部署下唯一站得住的选择：丢一个 span 的代价是
	// 看板上少一段，而漏一个 span 会被复制进一个留存一年、人人可读的后端。
	// forward 存在，是因为少数部署宁可失去这个保证也不愿失去遥测——
	// 而这个选择应当写在配置里，而不是由某个回退行为暗示。
	FailureMode string `mapstructure:"failure_mode"`

	// LogEvery throttles the failure log. Zero logs every failure.
	// 限制故障日志频率。0 表示每次都记。
	LogEvery time.Duration `mapstructure:"log_every"`
}

const (
	// FailureDrop discards a batch the firewall could not redact.
	FailureDrop = "drop"
	// FailureForward passes an unredacted batch downstream.
	FailureForward = "forward"
)

var _ component.Config = (*Config)(nil)

// Validate implements component.ConfigValidator.
// 实现 component.ConfigValidator。
//
// Every problem here is one that produces a running, quiet, wrong pipeline:
// no jurisdictions means nothing is ever detected, a missing key file means the
// processor cannot start rather than starting without hashing, and "mask" means
// a vault that grows until the collector dies.
// 这里的每一个问题都会产出一条「在跑、不出声、但是错的」管线：
// 没有司法管辖区意味着什么都检不出来；缺密钥文件必须让处理器起不来，
// 而不是不带哈希地起来；而 "mask" 意味着一个会一直长到 collector 死掉的保险库。
func (c *Config) Validate() error {
	if len(c.Jurisdictions) == 0 {
		return fmt.Errorf(
			"必须指定 jurisdictions——一个国家包都不装意味着任何遥测都扫不出 PII，" +
				"且看起来像「数据很干净」 / jurisdictions is required")
	}

	switch c.Strategy {
	case "hash":
		if c.HashKeyFile == "" {
			return fmt.Errorf(
				"strategy=hash 需要 hash_key_file——密钥必须来自密钥卷，" +
					"不能写在 collector 配置里 / hash requires hash_key_file")
		}
	case "drop":
		if c.HashKeyFile != "" {
			return fmt.Errorf(
				"strategy=drop 不使用 hash_key_file，配置它会让人以为哈希生效了 / " +
					"drop does not use hash_key_file")
		}
	case "mask":
		return fmt.Errorf(
			"遥测不支持 mask 算子：占位符按不同值在会话保险库中铸造，而遥测没有会话，" +
				"保险库会随流量增长；用在指标标签上还会让基数炸弹原样存活。" +
				"请改用 hash（保住聚合）或 drop / mask is not supported for telemetry")
	default:
		return fmt.Errorf("未知的 strategy %q，可用 hash|drop / unknown strategy %q",
			c.Strategy, c.Strategy)
	}

	switch c.FailureMode {
	case FailureDrop, FailureForward:
	default:
		return fmt.Errorf("未知的 failure_mode %q，可用 drop|forward / unknown failure_mode",
			c.FailureMode)
	}

	if c.Tenant == "" && c.TenantAttribute == "" {
		return fmt.Errorf(
			"必须指定 tenant 或 tenant_attribute——" +
				"缺少租户时，同一个手机号在每个租户下得到相同摘要，" +
				"两个租户比对导出即可确认共有客户 / tenant or tenant_attribute is required")
	}
	if c.MaxValueBytes < 0 {
		return fmt.Errorf("max_value_bytes 不能为负 / max_value_bytes must not be negative")
	}
	return nil
}
