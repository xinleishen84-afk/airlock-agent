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
  --jurisdictions GEN,CN \
  --tenant-header X-Tenant-Id \
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

## 司法管辖区国家包 / Country packs

一张扁平的「敏感数据」字典，悄悄编码了编写者的假设。以美国为中心的引擎能找到
SSN 却漏掉意大利税号；以中国为中心的能找到身份证却漏掉德国税号。两者在各自本土
市场都没错，出了本土都没用 —— 而且**故障是静默的**：用美国包扫意大利文档会报告
零 PII，这读起来像「数据很干净」，而不是「装错了包」。

所以 `jurisdictions` 是必填项，没有默认值：

```yaml
pii:
  jurisdictions: [GEN, CN]   # 必填。装错、拼错、不装，都在启动期报错
  tenant_rules_dir: /etc/airlock/rules
```

| 包 | 覆盖 |
|---|---|
| `GEN` | 与国界无关的部分：邮箱、银行卡（Luhn）、IBAN（ISO 7064 mod-97）、国际电话、IPv4、API 密钥/JWT |
| `CN` | 身份证（GB 11643）、统一社会信用代码（GB 32100）、手机、固话、护照、车牌 |
| `US` | SSN |
| `IT` | Codice Fiscale（CIN 控制字符）、Partita IVA |
| `DE` | Steuer-ID（ISO 7064 MOD 11,10 + 数字重复结构规则）、USt-IdNr |
| `ES` | DNI / NIE（mod-23 校验字母，同一识别器覆盖两者） |

装包的代价是可量化的：装全部六个包相对只装 `GEN`，hot path 从 31.8µs 涨到
37.9µs（+19%），因为前置过滤器在正则之前就把绝大多数识别器挡掉了。构建全部包
一次 36µs，不构成启动负担。

### 租户 YAML 规则 / Tenant rule packs

国家包覆盖司法管辖区定义的标识；它们覆盖不了只有你自己知道格式的东西 ——
工号、资产编号、合同号。这些放在 YAML 里，不需要写代码：

```yaml
version: 1
tenant: example-corp
rules:
  - name: employee_id
    type: CUSTOM_EMPLOYEE_ID
    pattern: 'EMP-[0-9]{6}'
    score: 0.90
    boundary: alnum
    samples:
      match: ["EMP-004217"]
      no_match: ["EMP-4217", "emp-004217"]
```

**`samples` 是强制的**，这是这套规则引擎唯一能安全交给非工程师的前提。
YAML 规则的每一种故障模式都是静默的 —— 模式并不蕴含的前置过滤、拒绝一切
真实出现的边界类、拒绝租户自身格式的校验器 —— 三者都能干净地注册、报告成功，
同时从它们本该捕获的数据上扫过。加载器会在接受规则之前把样本喂进组装好的
识别器：`match` 必须恰好命中一次且覆盖整串，`no_match` 必须零命中。
**一条匹配不到任何东西的规则会加载失败，而不是保护失败。**

完整示例见 [`configs/tenant-rules/example.yaml`](configs/tenant-rules/example.yaml)，
该文件本身在 CI 中被加载验证。

---

## 脱敏策略矩阵 / Redaction strategy matrix

`[REDACTED]` 是对某一个问题的答案，而对大多数问题都是错的答案：需要统计去重
用户数的分析仓库用不了它；需要让「他」始终指向同一个人的模型用不了它；而必须
一个字节都不出去的 DLP 红线，也不会满足于一个仍然为这些字节留着位置的占位符。

**算子由数据的去向决定，不由数据本身决定。**

| 算子 | 输出 | 可逆 | 用在哪 |
|---|---|---|---|
| `mask` | `ANONYMIZED_NAME_0` | ✅ | 公有云大模型 —— 保语法完整与指代一致 |
| `tokenize` | `[tok:email:9df3a0c1]` | ✅ | 跨系统伪名化 —— 令牌在另一个系统里含义相同 |
| `hash` | `[hash:email:a4b2efc8]` | ❌ | 分析数仓 —— 可关联的假名，不需还原 |
| `char_mask` | `************1111` | ❌ | 展示层 —— 保留末四位是**刻意的泄露** |
| `drop` | `` | ❌ | DLP 红线归档 —— 字节必须消失 |
| `generalize` | `1995-10-24` → `1990s` | ❌ | 医疗/研究导出 —— 保住统计效用 |

```yaml
# configs/redaction-matrix.yaml
version: 1
flows:
  - name: public_llm
    restores: true          # 声明要复原响应
    default: mask
  - name: analytics
    default: hash
    by_type: {PHONE: drop}
  - name: archive
    default: drop
```

同一份请求体、四个去向，实测输出：

```
public_llm    客户手机 ANONYMIZED_PHONE_0，邮箱 ANONYMIZED_EMAIL_0     {mask:2}
pseudonymous  客户手机 [tok:phone:165d7009…]，邮箱 [tok:email:7c169fca…]  {tokenize:2}
analytics     客户手机 ，邮箱 [hash:email:2cbdec25]                      {drop:1, hash:1}
archive       客户手机 ，邮箱                                            {drop:2}
```

### 唯一要紧的不变量：可逆性

给一条要做响应复原的链路配上哈希，**运行时不会有任何报错**：请求带着哈希正常
出站，模型用哈希作答，网关把 `[hash:name:a4b2efc8]` 当成人名交给终端用户。
故障从头到尾都是静默的 —— 所以 `restores: true` 的链路在**加载期**就拒绝
不可逆算子：

```
flows[0]：声明 restores 却对 默认 / default 使用不可逆算子 "hash"——
这类配置不会报错，只会把脱敏后的符号当作原值交给终端用户
```

这个检查只看算子名字，不构建算子。理由是它必须在密钥没挂上时也能跑：否则
「缺 HMAC 密钥」的报错会盖住「策略本身不成立」，运维补上密钥，然后带着一条
静默损坏的链路上线。

### 几个不打折扣的说法

**哈希用 HMAC，不是「SHA-256 加盐」。** 中国大陆手机号总量 10^11，已知盐的
情况下一台笔记本几分钟就能穷举完 —— 与数据放在一起的盐，在数据泄露之后
一文不值，而数据泄露正是这套机制要应对的场景。密钥只存在于网关进程内，
从密钥卷读取（`--hash-key-file`），**绝不写进配置文件**。

**假名仍然是个人数据。** 一个稳定到可以做关联的假名，也就稳定到可以做画像。
在 GDPR 下它降低暴露面，但没有走出监管范围。

**令牌库是一个 PII 数据库。** `SessionVault` 拒绝序列化，正因为一张活得比会话
久的映射表就是 PII 数据库。令牌库是同一张表、刻意做成持久的 —— 这就是跨系统
可逆的代价。令牌化把秘密从载荷搬进了库，库因此继承原始数据的全部管控要求。

**泛化不是隐私保证。** 「1990 年代」加上一个罕见专科加上一座小城，仍然可能
恰好是一个人。k-匿名是整个**发布数据集**的属性，需要跨准标识符计算，
一个只看得见单条请求的网关无从计算。本算子诚实的说法是：它以保住分析效用的
方式降低精度。

**词表未覆盖的值走兜底算子，绝不原样通过。** 词表里没有的词，恰恰是没人预料到
的那个值 —— 「查不到就放过」的泛化器，泄露的正是最不该泄露的那些。

---

## 租户隔离与可逆令牌库 / Tenant isolation

每一个可逆构造都是一次查表：进去一个占位符或令牌，出来一个真实值。
**键里没有租户的查表，在构造上就是一个越权漏洞** —— 谁拿到那串不透明字符谁就
拿到值，而不透明字符是会流传的：流经日志、流经模型的回复、流经某人粘进工单的
那段文本。

所以租户是键的一部分，不是事后施加的过滤。过滤可能在某一个调用点被忘掉，键不会。

```
SessionRef{Tenant, Session}            会话保险库：占位符 → 真实值
TokenKey{Tenant, Namespace} + token    令牌库：令牌 → 真实值
```

隔离模型必须显式声明，二选一，没有默认值：

```bash
--tenant-header X-Tenant-Id   # 多租户：从上游盖的头部解析
--single-tenant acme          # 单租户：让「不做隔离」成为敲出来的参数
```

不配就不启动：

```
必须指定 --tenant-header 或 --single-tenant：缺少租户隔离时，
会话保险库只以调用方提供的 session_id 作键，
任何拿到他人 session_id 的调用方都能取回对方的明文 PII
```

### 三个驱动，同一套契约

| 驱动 | 用在哪 | TTL | 跨重启 |
|---|---|---|---|
| `MemoryTokenStore` | 开发、单进程 | ✅ | ❌ |
| `CacheTokenStore` | 多副本（Redis / DynamoDB / 任意 KV） | ✅ | ✅ |
| `SQLTokenStore` | 加密关系库 | ✅ | ✅ |

`Cache` 与 `SQLExecutor` 都是刻意收窄的接口，不含任何厂商类型 —— 签名里出现
`redis.Client`，会让本库的每个使用者都依赖那个客户端的版本。三个驱动跑**同一套
契约用例**，否则「开发用内存、生产换 Redis」这句话不成立。

`SQLTokenStore` 的表结构由代码给出，两件事必须做对：

```sql
PRIMARY KEY (tenant_id, namespace, token)          -- 不是「代理主键 + 租户列」
UNIQUE (tenant_id, namespace, value_digest)
value_cipher BLOB NOT NULL                          -- 不存明文
```

复合主键而非代理主键，是因为**这一类越权漏洞每一个都是一句忘掉的 WHERE**。
值用租户派生密钥 AES-GCM 加密、以自身 HMAC 摘要作查找键：存明文会把每个被令牌化
的值送进数据库的索引、备份、副本和查询日志 —— 而那正是买下令牌化本来要消除的
暴露面。租户参与 AAD，所以一行密文被挪到另一个租户名下时会**解不开**，而不是
干干净净地解密出来。

### 每租户密钥派生，而不是每租户一把密钥

`Keyring` 用 HKDF-SHA256 从单一根密钥派生子密钥。独立密钥意味着 N 份秘密要挂载、
轮转和审计，新增租户会变成一次密钥管理操作；派生只保留一份根密钥，轮转根密钥即
一次性轮转全部。

这对 `hash` 算子是**必需**的：哈希按设计确定性，没有租户级密钥时同一个手机号在
每个租户下摘要相同，两个租户比对数仓导出即可确认共有客户 —— 一次谁都没同意的
跨租户披露，用双方都以为已经假名化的数据做到。

```
tenant-a  [hash:email:561bdc89]
tenant-b  [hash:email:ed13e46e]      同一个邮箱
```

**令牌不需要盐。** 令牌是随机的，本就跨租户不可关联 —— 根本没有东西可加盐。
保护它们的是复合键。

### GDPR 第 17 条：精准擦除

```
POST /v1/tenant/erase       →  {"tenant":"tenant-a","sessions_erased":2,"tokens_erased":1}
```

擦除同时覆盖两处状态，漏掉任何一处都只做了一半：内存里活着的会话映射，和持久化的
令牌库。**回执里的条数不是便利功能** —— 第 17 条的擦除要拿得出证据，而「我们调了
这个接口」不算证据：一次因租户串写错而匹配到零条的擦除，与一次真正成功的擦除，
在没有计数时看起来完全一样。令牌库擦除失败时接口返回错误而非成功，因为一次
「部分擦除」被签字为完成，数据还在库里。

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

**正则检测不出人名。** 人名没有稳定的字面特征。只装正则识别器就上线，
姓名/地址/机构名会**完全裸奔**。`CompositeDetector` 在缺少这三类覆盖时会主动告警，
`/stats` 端点也会暴露 `coverage_gaps` —— 必须在监控里可见。

**识别器表只有一份。** 国家包是唯一的来源，网关、sidecar、配置校验层全部从它读。
这条规则是踩出来的：曾经同一张表存在三份副本（`RegexDetector`、`predefinedSpecs`、
packs），新增意大利/德国/西班牙识别器后，跑起来的二进制用的仍是老副本 ——
包装好了，业务上一个也没生效，且没有任何报错。

**这个越权漏洞曾经是活的。** 在引入租户之前，会话保险库只以调用方提供的
`session_id` 作键。租户 B 拿同一个 `session_id` 调 `/v1/restore`，会原样拿回
租户 A 的姓名和手机号**明文** —— 不是令牌、不是摘要，是值本身。这比令牌层的
越权更严重：令牌至少还要先有一个令牌。修复方式不是加一层检查，而是把租户放进键里。

**校验位函数不许夹带长度。** `LuhnValid` 一度写死了 12–19 位（卡号长度），
于是意大利 11 位增值税号的识别器注册成功、运行正常、**永不命中**。
长度属于「卡号」这个概念，不属于 Luhn 这个算法 —— 现在是
`LuhnValid` 与 `BankCardLuhnValid` 两个函数。

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
pii/detect/packs/    国家合规包 + 租户 YAML 规则加载器
gpuload/      GPU 显存感知准入（公开 API）
sidecar/      HTTP 服务实现
cmd/airlock-agent/   sidecar 二进制
cmd/airlock-gateway/  参考网关实现（完整的 AI 网关，用于演示扩展如何集成）
internal/     参考网关专用的内部包
```

`pii` 与 `gpuload` 是公开包，可以单独 import；其余是参考实现。

## License

Apache-2.0
