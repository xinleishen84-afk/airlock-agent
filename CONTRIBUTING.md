# Contributing / 贡献指南

## Before you start / 开始之前

This is a security component. Two rules govern everything else:
这是一个安全组件。以下两条规则高于其他一切：

1. **Allowlist, never denylist.** New fields reachable by a detector must be
   added explicitly to `pii/document`'s rule table. A denylist means any field
   nobody anticipated gets touched.
   **只用白名单，绝不用黑名单。** 检测器能触及的新字段必须显式加进
   `pii/document` 的规则表。黑名单意味着任何没预料到的字段都会被触碰。
2. **Fail closed.** When detection cannot run, the request must be blocked, not
   forwarded. A degradation that lets traffic through is the opposite of the
   security intent.
   **失败时关闭。** 检测无法执行时必须阻断请求而非转发。
   放行式的降级与安全意图恰好相反。

## Development / 开发

```bash
go test ./... -race          # 必须全绿 / must be green
gofmt -l .                   # 必须无输出 / must print nothing
go vet ./...
go run ./cmd/airlock-gateway --dry-run -config configs/gateway.yaml
```

`-race` is not optional. This is a per-connection hot path; data races only
surface under load, and by then it is in production.
`-race` 不是可选项。这是每连接热路径，数据竞争只在压力下显形，而那时已在生产上。

## Adding a recognizer / 新增识别器

Prefer registering one from outside — that is what `detect.Registry` is for, and
it means you do not need to fork:
优先从外部注册——`detect.Registry` 就是为此存在的，你不需要 fork：

```go
rec, _ := detect.NewPatternRecognizer(
    "acme_contract", detect.TypeAccount, `CT-[0-9]{8}`, 0.9,
    detect.WithContext(0.15, "合同号", "contract"))
registry.Register(rec)
```

If a recognizer belongs upstream (a national ID format, a common credential
shape), add it to `pii/detect/predefined.go` **with**:
若某识别器确实该进上游（某国身份证格式、常见凭证形态），加进
`pii/detect/predefined.go`，**并且必须附带**：

- A check digit or structural validator where one exists. Without it, false
  positives bury the real alerts.
  有校验算法的必须实现。没有校验位，误报会淹没真正的告警。
- Context words. A bare 16-digit run is ambiguous; the words around it are not.
  上下文词。裸的 16 位数字有歧义，它周围的词没有。
- A test proving `text[Start:End] == Value`. An off-by-one offset shreds the
  document, and it only shows up on non-ASCII text.
  一个证明 `text[Start:End] == Value` 的测试。偏移量差一位会切碎文档，
  而且只在非 ASCII 文本上显形。

## Tests must be able to fail / 测试必须能失败

A test that passes when the feature is broken is worse than no test. For any
test asserting an absence (no leak, no corruption, graceful shutdown), first
verify the precondition actually held — for example, assert there really was an
in-flight stream before asserting none were dropped.
一个在功能损坏时仍然通过的测试比没有测试更糟。凡是断言「某事没发生」的测试
（没泄露、没污染、优雅停机），先验证前置条件真的成立——比如断言「没有连接被中断」
之前，先断言当时确实有在途连接。

## Comments / 注释

Public packages use bilingual comments, English first (pkg.go.dev takes the first
sentence as the summary), Chinese second.
公开包使用双语注释，英文在前（pkg.go.dev 取首句作摘要），中文在后。

Explain *why*, not *what*. `// increments the counter` is noise; the trade-off
that made the counter necessary is not.
解释**为什么**而非**是什么**。「递增计数器」是噪音，而「为什么需要这个计数器」不是。
