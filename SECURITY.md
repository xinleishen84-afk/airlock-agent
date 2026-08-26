# Security Policy / 安全策略

## Reporting a vulnerability / 报告漏洞

**Do not open a public issue.** This project handles PII; a public report gives
attackers a window before a fix ships.
**请勿公开提交 issue。** 本项目处理 PII，公开报告会在修复发布前给攻击者留出窗口。

Report privately via GitHub Security Advisories:
请通过 GitHub Security Advisories 私下报告：
https://github.com/xinleishen84-afk/airlock-agent/security/advisories/new

Please include: affected version, reproduction steps, and impact assessment.
请附上：受影响版本、复现步骤、影响评估。

## What counts as a vulnerability here / 什么算本项目的漏洞

This project's threat model is specific. The following are vulnerabilities:
本项目的威胁模型很具体。以下情形属于漏洞：

- **PII crosses the boundary un-redacted.** Any input that produces an outbound
  payload still containing a value the detector should have caught.
  **PII 未脱敏就越过边界。** 任何能让出站载荷仍含应被检出值的输入。
- **Protocol corruption.** Any input causing `role`, `function.name`, a schema
  `enum`, or another skeleton field to be rewritten.
  **协议被污染。** 任何能让 role、function.name、schema enum 等骨架字段被改写的输入。
- **Mapping escapes memory.** Any path by which the placeholder-to-real-value
  mapping is serialized, logged, or persisted.
  **映射逃逸出内存。** 任何能让「占位符 → 真实值」映射被序列化、记录或持久化的路径。
- **Credential leakage.** Any path by which an injected credential appears in
  logs, error messages, metrics, or an outbound payload.
  **凭证泄露。** 任何能让注入的凭证出现在日志、错误信息、指标或出站载荷中的路径。
- **Fail-open under failure.** Any detector or NER failure that results in raw
  text being forwarded while `fail_closed` is enabled.
  **故障时放行。** 在 `fail_closed` 开启的情况下，检测器或 NER 故障却放行了原文。

The following are **not** vulnerabilities, though bug reports are welcome:
以下**不算**漏洞，但欢迎作为普通 bug 报告：

- Missed detections due to an unconfigured detector. Regexes cannot find personal
  names; without a gazetteer or NER this is documented behaviour, not a flaw.
  因未配置检测器导致的漏检。正则检测不出人名，未配名册或 NER 时这是文档记载的行为。
- False positives from a recognizer. Tune the confidence threshold or disable the
  recognizer.
  识别器误报。请调整置信度阈值或关闭该识别器。

## Supported versions / 支持的版本

Pre-1.0. Only the latest release receives fixes.
1.0 之前，仅最新发布版本接受修复。
