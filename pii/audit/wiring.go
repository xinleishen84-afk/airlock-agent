package audit

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
)

// 装配代码放在 audit 包而不是任何一个 main 或 sidecar 包里。
//
// 三个二进制都要发审计事件，而其中的网关根本不是 sidecar——让它为了一个
// 构造函数依赖整个 sidecar 包，读起来是错的。更要紧的是上一次事故：
// 会话一致性校验只写进了 Core 的 main，Advanced 因此完全不受那条约束，
// 而部署清单已经在传那个 flag，Pod 以「flag provided but not defined」
// 崩溃循环。安全相关的装配一旦在多个入口各写一份，就会漂移成
// 「有的进程管、有的不管」。
//
// The assembly lives in the audit package rather than in any main or in
// sidecar: all three binaries emit audit events, and the gateway is not a
// sidecar. Duplicating a security-relevant assembly across entry points is what
// previously left one binary unconstrained while its manifest already passed
// the flag it never defined.

const (
	SinkFlagUsage = "GDPR 安全审计轨迹的去向：stderr、文件路径，或 http(s):// 的 SIEM 端点。\n" +
		"留空表示不发送任何审计事件——留空是合法选择，但必须是写下来的选择：\n" +
		"启动日志会明确说明轨迹是开还是关"
	KeyFlagUsage = "审计指纹的 HMAC 密钥文件。配了 --audit-sink 就必填。\n" +
		"会话标识常常就是用户邮箱，无密钥的摘要可被穷举回原值"
)

// Build 构造 GDPR 审计轨迹。sinkSpec 为空时返回 (nil, nil, nil)。
// Builds the GDPR audit trail; returns nils when --audit-sink is unset.
//
// # 这一整块能力此前在二进制里一行都没接
// # None of this was wired into the binary
//
// pii/audit 包齐备、测试全绿、sidecar.Options 有 Auditor 与 Fingerprinter
// 两个字段——而 main 里从未给它们赋值。实测真实二进制：
// /v1/admin/inspect 报 sink="none"、emitted=0，识别器清单与名册规模均为 null，
// 而 README 的能力清单里写着「不带原文的安全审计」。
//
// 同一个文件里的 Evidence 字段注释记着一模一样的事故：「验证器在测试里一直
// 接着，在真实二进制里从来没接上」。同一类错误在同一个文件里犯了两次，
// 因为库层的测试无论多绿都证明不了装配层接了它。
//
// The audit package was complete and green, Options had both fields, and main
// never assigned them: the real binary reported sink="none" with zero events
// while the README listed "auditing that carries no plaintext" as a capability.
// The Evidence field in this same file documents the identical incident. Library
// tests, however green, cannot show that the assembly wired them.
func Build(sinkSpec, keyFile string, logger *slog.Logger) (*Recorder, *Fingerprinter, error) {
	if sinkSpec == "" {
		return nil, nil, nil
	}

	// 指纹必须有密钥，这不是可选项：会话标识常常就是用户邮箱，
	// 无密钥摘要能被穷举回原值——那样审计事件本身成了 PII 泄露渠道。
	//
	// A keyless digest of a session identifier can be brute-forced back, and
	// session identifiers are often email addresses: the audit trail would
	// itself become the leak.
	if keyFile == "" {
		return nil, nil, fmt.Errorf(
			"配置了 --audit-sink 但没有 --audit-key-file：" +
				"审计事件里的会话标识必须是带密钥的摘要，" +
				"而会话标识常常就是用户邮箱，无密钥摘要可被穷举回原值")
	}
	key, err := os.ReadFile(keyFile) //nolint:gosec // 路径由运维显式指定
	if err != nil {
		return nil, nil, fmt.Errorf("读取审计密钥失败: %w", err)
	}
	ring, err := anonymize.NewKeyring([]byte(strings.TrimSpace(string(key))), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("构造审计密钥环: %w", err)
	}
	fp, err := NewFingerprinter(ring)
	if err != nil {
		return nil, nil, err
	}

	sink, err := buildAuditSink(sinkSpec)
	if err != nil {
		return nil, nil, err
	}
	// onError 只记错误类别，绝不记事件内容——事件里有指纹与计数，
	// 把它整条打进日志等于绕过了「审计不落原文」这条约束。
	rec := NewRecorder(sink, fp, func(err error) {
		logger.Error("审计事件发送失败", "err_class", err.Error())
	})
	return rec, fp, nil
}

// buildAuditSink 按 --audit-sink 的取值构造轨迹去向。
func buildAuditSink(spec string) (Sink, error) {
	switch {
	case spec == "stderr":
		return NewWriterSink(os.Stderr), nil
	case strings.HasPrefix(spec, "http://"), strings.HasPrefix(spec, "https://"):
		return NewHTTPSink(HTTPSinkOptions{Endpoint: spec})
	default:
		// 文件：追加打开。审计轨迹不能覆盖已有内容——
		// 重启把上一段轨迹截断掉，等于合规证据被自己抹了。
		f, err := os.OpenFile(spec, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("打开审计文件失败: %w", err)
		}
		return NewWriterSink(f), nil
	}
}
