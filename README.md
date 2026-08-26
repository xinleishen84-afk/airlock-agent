# airlock-agent

**Bidirectional PII redaction for LLM gateways.**
**面向 LLM 网关的双向 PII 脱敏。**

> An *airlock* is the sealed chamber between two incompatible environments —
> everything passes through it on the way out, and through it again on the way
> back in. That is exactly what this does: sensitive data is redacted before it
> crosses your enterprise boundary, and restored when the model's answer returns.
>
> 气闸舱是两个不相容环境之间的密封通道——出去要过它，回来也要过它。
> 这正是本项目做的事：数据出企业边界前脱敏，模型回答返回时复原。

> **Not an agent framework.** The `-agent` suffix follows the `datadog-agent` /
> `consul-agent` convention: a resident process that works alongside your
> gateway. It does not build AI agents; it protects the traffic they generate.
>
> **不是 Agent 框架。** `-agent` 后缀取 `datadog-agent` / `consul-agent` 的惯例，
> 指常驻边车进程。它不用于构建 AI Agent，而是保护 Agent 产生的流量。

Plugs into the gateway you already run — Envoy, APISIX, Higress, Kong, or your
own. Not a replacement for it.
接入你现有的网关——Envoy、APISIX、Higress、Kong，或自研的。不是要替换它。

```
       enterprise boundary / 企业边界
                  │
  your gateway ───┤   airlock-agent   ├──→  cloud LLM
   业务网关       │   ① redact 脱敏   │      云端模型
                  │   ② restore 复原  │
  ←───────────────┤                   ├──────
                  │
```

---

## 解决什么问题

### 1. PII 脱敏：把整个请求体喂给 NER，协议会被打烂

LLM 请求体是多层嵌套的 JSON。NER 是**概率性**的，把整个 payload 当文本扫，
或者递归净化所有字符串值，迟早会出这种事：

```jsonc
{
  "messages": [{"role": "ANONYMIZED_NAME_0", ...}],   // 消息角色丢失
  "tools": [{"function": {
    "name": "ANONYMIZED_NAME_1",                       // 模型再也调不到这个工具
    "parameters": {"properties": {"city": {
      "enum": ["ANONYMIZED_NAME_2", "..."]             // 参数约束失效
    }}}
  }}]
}
```

更糟的是复原：占位符→真实值的映射依赖会话字典，协议一旦被污染，
不仅返回数据无法还原，请求本身已经破损，下游解析器直接罢工。

**本项目的做法是白名单，不是黑名单。** 只有 7 条显式声明的 JSON 路径
会被送进检测器，其余字段在遍历层面就不会被访问到：

```
system
messages[*].content
messages[*].content[*].text                    ← 多模态只碰 text，不碰 image_url
messages[*].tool_calls[*].function.arguments   ← 只净化值，不碰键（键是 schema 参数名）
tools[*].function.description
tools[*].description
tools[*].function.parameters.**.description    ← 只取 description，enum/type/属性名不碰
```

黑名单的问题在于默认方向错了：默认净化一切、例外才跳过，
意味着上游 API 新增任何字符串参数都会被 NER 触碰。安全组件必须默认拒绝。

### 2. GPU 感知：只看 QPS 的网关会在 KV 快满时继续放行

LLM 推理的真实约束是 **KV 缓存显存**，不是请求数。一个 10 万 token 的 prompt
配 1 个输出，和 1 千 token 配 10 万输出，QPS 完全相同，显存压力天差地别。

多个 Agent 同时爆发（coding agent 一次规划并发几十个请求）会瞬间打满 KV，
vLLM 开始抢占换出，在途请求被反复重算，整个后端进入活锁。

本项目按 vLLM 的实际指标做**分级降级**：

| KV 占用 | priority≤3 | priority 4~7 | priority≥8 |
|---|---|---|---|
| < 75% | 放行 | 放行 | 放行 |
| ≥ 75% | **429** | 放行 | 放行 |
| ≥ 90% 或检测到抢占 | 429 | **429** | 放行 |

在 GPU 死锁**之前**先牺牲低价值流量。等完全打满再一刀切，
队列里已经全是低优先级请求，高价值请求照样排在后面。

---

## 快速开始

### 作为 sidecar（任何语言的网关都能用）

```bash
docker run -p 8888:8888 \
  -v ./names.txt:/rosters/names.txt \
  ghcr.io/xinleishen84-afk/airlock-agent \
  --name-roster /rosters/names.txt \
  --ner http://ner-service:8000/v1/detect
```

出站脱敏：

```bash
curl -X POST localhost:8888/v1/redact -d '{
  "session_id": "conv-42",
  "payload": {"model":"gpt-4o","messages":[
    {"role":"user","content":"联系张伟，手机 13812345678"}]}
}'
```

```jsonc
{
  "payload": {"model":"gpt-4o","messages":[
    {"role":"user","content":"联系ANONYMIZED_NAME_0，手机 ANONYMIZED_PHONE_0"}]},
  "entity_counts": {"NAME":1,"PHONE":1},
  "blocked": false
}
```

入站复原（把模型回吐的占位符换回真实值）：

```bash
curl -X POST localhost:8888/v1/restore -d '{
  "session_id": "conv-42",
  "payload": {"choices":[{"delta":{"content":"已通知 ANONYMIZED_NAME_0"}}]}
}'
# -> {"payload":{"choices":[{"delta":{"content":"已通知 张伟"}}]},"restored":1}
```

### 作为 Go 库 / As a Go library

```go
import (
    "github.com/xinleishen84-afk/airlock-agent/pii/detect"
    "github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
    "github.com/xinleishen84-afk/airlock-agent/pii/document"
)

// 检测层：内置识别器 + 你自己的实体类型
// Detection: built-in recognizers plus your own entity types
reg, _ := detect.NewDefaultRegistry()
custom, _ := detect.NewPatternRecognizer(
    "employee_id", detect.TypeAccount, `EMP-[0-9]{6}`, 0.95,
    detect.WithContext(0.15, "工号", "employee"))
reg.Register(custom)

// 脱敏层：会话映射保证占位符跨轮次稳定
// Anonymization: the session vault keeps placeholders stable across turns
redactor := anonymize.NewRedactor(reg, true /* failClosed */)
vaults := anonymize.NewVaultRegistry(time.Hour, 100_000)
vault, _ := vaults.Get(sessionID)

// 结构化定向清洗：只碰白名单路径，协议骨架永不被访问
// Targeted sanitization: only allowlisted paths, skeleton never visited
err := document.SanitizeDocument(payload, func(text string) (string, error) {
    res, err := redactor.Redact(text, vault)
    return res.Text, err
})
```

三层可以单独使用。只想扫描审计不改数据的，只 import `detect` 即可。
The three layers are usable independently: import only `detect` if you want to
scan and audit without modifying anything.

---

## 设计决策

几个不那么显然、但踩过坑才定下来的选择。

**校验位不是可选项。** 身份证（GB 11643）、银行卡（Luhn）、统一社会信用代码
（GB 32100）全部做校验位验证。没有它，任意 18 位串都会被误报为信用代码 ——
误报会淹没真正的告警。

**服务契约里不含偏移量。** Python 的 `str` 索引按字符，Go 的字符串索引按字节，
中文一字 3 字节。直接采信对端偏移会把文本切碎，且**只在含中文时出错** ——
用英文测试完全正常，能一路带到生产。NER 服务只返回实体文本，由本端回原文定位。

**fail-closed 返回 200 + `blocked: true`，不返回 5xx。** 这不是服务故障而是
安全策略生效。返回 5xx 会让网关按「上游故障」重试或降级 ——
而降级的方向往往是放行，恰好与安全意图相反。

**脱敏映射永不落盘。** `SessionVault` 从类型层面禁止序列化（`__reduce__` 等价物
直接抛错）。它存的是「占位符 → 真实姓名/手机/身份证」，落盘就等于把脱敏组件
变成 PII 数据库 —— 一次备份泄露，整条防线全废。

**正则检测不出人名。** 人名没有稳定的字面特征。只装 `RegexDetector` 就上线，
姓名/地址/机构名会**完全裸奔**。`CompositeDetector` 在缺少这三类覆盖时会主动告警，
`/stats` 端点也会暴露 `coverage_gaps` —— 必须在监控里可见。

---

## 现状与边界

**已验证**

- 12 个 Go 包，`-race -count=2` 全绿
- 端到端验收：真实进程 + 真实故障转移 + 真实 PII，观测点在组件外部
- 协议完整性：用「把任何文本都判成人名」的最坏情况检测器验证骨架不被污染

**未验证**

- Testcontainers 集成用例（开发机无 Docker，代码写好但容器行为未实测）
- 生产规模压测

**尚未实现**

- Envoy `ext_proc` gRPC 适配层（HTTP 接口已可用，Envoy 侧需要一层薄翻译）
- 多副本部署的会话映射共享（当前映射在单实例内存中，需要会话亲和路由）

## 仓库结构

```
pii/          脱敏引擎（公开 API，零外部依赖）
gpuload/      GPU 显存感知准入（公开 API）
sidecar/      HTTP 服务实现
cmd/airlock-agent/   sidecar 二进制
cmd/airlock-gateway/  参考网关实现（完整的 AI 网关，用于演示扩展如何集成）
internal/     参考网关专用的内部包
```

`pii` 与 `gpuload` 是公开包，可以单独 import；其余是参考实现。

## License

Apache-2.0
