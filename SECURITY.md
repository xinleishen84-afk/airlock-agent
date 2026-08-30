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

## 验证你拿到的产物

签名没人验就等于没签。下面每一条都是可以直接粘贴执行的。

### 二进制

Release 里每个二进制都带 `.sig`（签名）与 `.pem`（证书）。签名是**无密钥**的
（Sigstore/Fulcio）：身份来自 GitHub Actions 的 OIDC token，没有需要保管、
轮转、泄漏后吊销的长期私钥。

```bash
cosign verify-blob \
  --certificate airlock-agent_linux_amd64.pem \
  --signature  airlock-agent_linux_amd64.sig \
  --certificate-identity-regexp 'https://github\.com/xinleishen84-afk/airlock-agent/\.github/workflows/release\.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  airlock-agent_linux_amd64
```

**`--certificate-identity-regexp` 不能省。** 省掉它，任何一个能让 Sigstore
签名的身份都会被接受——包括攻击者自己的仓库。签名回答的是「谁签的」，
不写清期望的身份，这个问题就等于没问。

### SLSA provenance

签名说「有人签了它」，provenance 说「它是这么来的」：哪个仓库、哪条
workflow、哪个提交。

```bash
gh attestation verify airlock-agent_linux_amd64 \
  --repo xinleishen84-afk/airlock-agent
```

### 容器镜像

```bash
cosign verify ghcr.io/xinleishen84-afk/airlock-analyzer:vX.Y.Z \
  --certificate-identity-regexp 'https://github\.com/xinleishen84-afk/airlock-agent/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### 自己复现一遍构建

产物是可复现的：同一个提交在任何机器上构建都产出相同字节。这让你不必
信任签名本身——你可以自己验证那份产物确实来自这份源码。

```bash
git checkout vX.Y.Z
./scripts/build.sh
shasum -a 256 -c dist/SHA256SUMS      # 与 Release 里的 SHA256SUMS 比对
```

可复现依赖三件事，都写在 `scripts/build.sh` 里：`-trimpath`（去掉构建机的
绝对路径）、`SOURCE_DATE_EPOCH` 取自最后一次提交而不是「现在」、
`CGO_ENABLED=0`（静态链接，与 libc 版本无关）。

> 这不是形式主义。这个仓库里曾经提交过一个 12MB 的编译产物，`strings`
> 出来带着构建机的家目录。当时 Dockerfile 是有 `-trimpath` 的——**参数写在
> 别处，就等于没写**。现在三个入口、两个模块、CI、release 与 Dockerfile
> 共用 `scripts/build.sh` 一份参数。

## SBOM

每个 Release 附带 SPDX 格式的 SBOM。它值得看，因为三个二进制的依赖面差得很远：

| | 外部依赖 |
|---|---|
| `airlock-agent`（Core） | 1 个（yaml） |
| `airlock-agent-advanced` | 8 个（gRPC + protobuf） |
| 分析器镜像 | spaCy 整棵依赖树 + 数百 MB 模型 |

## 模型是被锁住的

spaCy 模型不是 pip 依赖：`spacy download` 取「当前兼容的那一个」，版本随时间
漂移，没有校验，也不出现在任何 SBOM 的默认覆盖范围里。

对这个项目而言这不是小事——**模型就是检测器**。换一个版本，姓名、地址、
机构名的召回率会变，而没有任何东西会报错；README 里那个「非结构化 100%」
是拿某一个具体模型跑出来的。

`analyzer/models.lock` 锁住版本与 sha256，镜像构建时逐个校验，不符即中止。
CI 另有一步对着上游重新计算校验和——GitHub release 资产不可变，所以不一致
只有两种可能：锁写错了，或者上游资产被换了。

## 这套东西保证不了什么

- **签名不保证代码是对的。** 它只保证产物出自这条流水线、这份源码。
  这份源码本身没有经过任何外部安全审计。
- **provenance 不保证依赖是干净的。** 它证明构建过程，不证明构建输入。
- **可复现构建不保证没有后门。** 它保证「你能自己造出一模一样的东西」，
  至于那个东西里有什么，要靠读代码。

## Supported versions / 支持的版本

Pre-1.0. Only the latest release receives fixes.
1.0 之前，仅最新发布版本接受修复。
