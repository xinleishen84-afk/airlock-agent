# airlock-agent

**LLM 网关的 PII 层：出站脱敏，入站复原，会话映射不落盘。**
**The PII layer for an LLM gateway: redact on the way out, restore on the way back.**

<sub>会话保险库从类型层面禁止序列化。跨会话可逆需要令牌库，而令牌库**是**持久化的
—— 那是一个 PII 数据库，代价见「脱敏策略矩阵」一节。<br>
The session vault refuses to serialize. Cross-session reversibility needs a token
store, and that store **is** persistent — it is a PII database.</sub>

> 气闸舱是两个不相容环境之间的密封通道——出去要过它，回来也要过它。
> 这正是本项目做的事：数据出企业边界前脱敏，模型回答返回时复原。
>
> An *airlock* is the sealed chamber between two incompatible environments.
> Everything passes through it on the way out, and through it again on the way back.

> **不是 Agent 框架。** `-agent` 后缀取 `datadog-agent` / `consul-agent` 的惯例，
> 指常驻边车进程。它不用于构建 AI Agent，而是保护 Agent 产生的流量。
>
> **Not an agent framework.** The suffix follows the `datadog-agent` convention:
> a resident process alongside your gateway.

> **不是通用 PII 库。** 如果你要扫数据库、扫文件、做批量去标识化，
> 用 [Presidio](https://github.com/microsoft/presidio)——它的生态、模型和社区都比这里成熟。
> 本项目只解决一件事：**LLM 请求/响应这条链路上**的 PII，
> 以及这条链路特有的问题（协议结构、流式帧、会话一致性、多租户可逆映射）。
>
> **Not a general-purpose PII library.** For scanning databases or files, use
> Presidio. This solves PII on the LLM request/response path specifically.

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

## 成熟度：先看这个

这是一份**没有生产使用者**的代码。在你评估它之前，请先读完这一节。

**做得到**

- 结构化标识（身份证、银行卡、统一社会信用代码、IBAN、税号、护照、车牌、API 密钥……）
- 协议安全的定向脱敏：不会打烂 OpenAI 请求体的工具调用约束
- 双向复原：含 SSE 流式帧被切开的情形
- 多租户隔离、GDPR 第 17 条精准擦除、不带原文的安全审计

**做不到**

- **Core 模式下人名、地址、机构名基本检不出**（除非在名册里）。
  这不是调参问题——人名没有字面特征。接上 Advanced 模式的 NER sidecar
  之后可解，代价是 622MB 内存与一次跨进程调用（实测 2.5ms/请求）。
- 出站侧**没有流式脱敏**（复原是流式的，脱敏要拿到完整载荷）
- 容器镜像与 K8s 清单已写好但**未在真实集群里跑过**——本机验证到进程级为止
- 多副本部署的会话映射共享。占位符（`PHONE_0`、`PHONE_1`……）是按本副本见过的
  文本顺序分配的递增序号，两个副本对同一会话会给出不同的编号。实测：同一会话下
  副本 A 把 `13800138000` 编成 `PHONE_0`、副本 B 把 `13900139000` 也编成
  `PHONE_0`，上游回一句引用 `PHONE_0` 的话，两边复原出不同的真实号码——
  用户拿到别人的数据，且不报错。客户端每轮重发完整历史时看不出来（分配顺序
  由文本确定），长会话一裁剪或摘要历史就复现，也就是**会话越长越容易出事**。

  现在这条约束是强制的而不是一句注记：`pii.session_consistency`
  （网关配置）与 `--session-consistency`（边车）必填，取值
  `single-replica` 或 `session-affinity`，缺失或拼错都启动即失败。
  出货清单默认单副本；扩容需要同时改副本数、改声明、并在入口按 session id
  做一致性哈希（`ClusterIP` 轮询与 `sessionAffinity: ClientIP` 都不算数）。
  根治办法是把序号换成会话内确定性派生的 ID，代价是占位符从 `NAME_0`
  变成哈希串，模型对短序号的推理质量更好——尚未采纳。
- Envoy `ext_proc` gRPC 适配层（HTTP 接口可用，Envoy 侧需一层薄翻译）

**验证到什么程度**

| | |
|---|---|
| 测试 | 429 个测试函数 / 13,672 行测试代码 / 覆盖率 73.7% / `-race` 全绿 |
| 依赖 | 主模块 1 个外部依赖（yaml） |
| 已实测 | 检测准确率、延迟分位、吞吐、还原准确率（见下节） |
| **未实测** | Testcontainers 用例（开发机无 Docker）、OTel 处理器未用 `ocb` 构建进真实 Collector、生产规模压测 |
| **零外部验证** | 没有任何人在生产里跑过它 |

---

## 两种模式:先拿 Core,需要时再唤醒 Sidecar

依赖是加进去容易、拿出来难的东西。所以这里是**两个二进制**,不是一个二进制加开关
—— 做成开关,gRPC 与 protobuf 的依赖树就会进到每一个部署里,包括那些只想要 Core 的。

| | **Core** | **Advanced** |
|---|---|---|
| 二进制 | `airlock-agent` · **11MB** | `airlock-agent-advanced` · 18MB |
| 外部依赖 | **1 个**(yaml) | 8 个(gRPC + protobuf) |
| 额外进程 | 无 | Python 分析器 sidecar |
| 额外内存 | **0** | 622MB(中英双模型) |
| 吞吐 | **254.8k QPS**(10 核) | 受模型限制,~400 req/s/副本 |
| 单请求 | **3.9µs** | 2.5ms(含一次跨进程调用) |
| 语料覆盖 | **90.5%** | 100% |

```bash
# Core:零额外依赖,单进程
airlock-agent --jurisdictions GEN,CN --tenant-header X-Tenant-Id \
              --name-roster ./names.txt

# Advanced:只有需要非结构化实体时才配
airlock-agent-advanced --jurisdictions GEN,CN --tenant-header X-Tenant-Id \
                       --ner-socket /var/run/airlock/ner.sock
```

### Core 覆盖什么、不覆盖什么(实测,逐条)

```
✓ Core   身份证 11010519491231002X          校验位 GB 11643
✓ Core   银行卡 4111111111111111            Luhn + ISO/IEC 7812 IIN
✓ Core   统一代码 91110108MA01ABCD71         GB 32100
✓ Core   Codice Fiscale MRTMTT25D09F205Z   CIN 控制字符
✓ Core   Steuer-ID 86095742719             ISO 7064 + 结构规则
✓ Core   手机/邮箱/密钥/护照/车牌              正则
✓ Core   张伟                               静态名册
✓ Core   欧阳志远                            复姓表 + AC 自动机
✗ 需要 Advanced   周慧敏                      名册外中文人名
✗ 需要 Advanced   上海市浦东新区世纪大道100号      非结构化地址
✗ 需要 Advanced   临安远景机械制造有限公司         非结构化机构名
✗ 需要 Advanced   Margaret Okonkwo          拉丁人名
```

**Core 模式在启动时自陈这件事**,不用翻文档:

```
[INFO] 运行在 Core 模式  实测覆盖率=语料 90.5%（结构化 37/37，非结构化 1/5）
[WARN] Core 模式检测不到这几类——它们没有字面特征，正则找不到
       类型=[NAME ADDRESS ORG]
       补法=配 --name-roster/--org-roster 覆盖已知的，
            或改用 airlock-agent-advanced 接 NER sidecar 覆盖未知的
```

一个只装了正则的部署,与一个接了 NER 的部署,**在日志上长得一样**——都在正常处理
请求、都在报告检出数。区别只在「姓名、地址、机构名有没有被检测」,而没被检测的
那些不会出现在任何计数里。所以这段自陈是能力声明,不是提示。

### Advanced 的三种部署形态

重型依赖封在 `Dockerfile.analyzer` 里,对 Go 网关彻底屏蔽。**痛苦没有消失,
只是从「每个用网关的人」转移到了「运维这一个镜像的人」。**

| 形态 | 清单 | 净 IPC | 换来什么 | 代价 |
|---|---|---|---|---|
| Core | `deploy/core.yaml` | — | 无依赖、无额外内存 | 非结构化实体检不出 |
| 同 Pod sidecar | `deploy/advanced-sidecar.yaml` | **110µs** | 最低延迟 | 每副本 +622MB,绑定扩缩容 |
| 独立 Service | `deploy/advanced-service.yaml` | 154µs | 独立水平扩缩容 | 延迟 1.4×,还要多一跳 Service 转发 |

**两者不能兼得。** 网关是 CPU 密集、分析器是内存密集,绑在一起意味着按其中一个
的需求去扩、另一个必然浪费;拆开则要把流量放回完整的 TCP 协议栈。这是一次二选一,
依据是「延迟敏感」还是「资源画像差异大」。

> **换成 TCP 时有一道闸会静默消失。** UDS 靠文件权限(0600)拦住同机其他用户;
> TCP 没有这个。而这个端口返回的是**「PII 在哪」**——`advanced-service.yaml`
> 里配了 NetworkPolicy 把它补回来,服务端启动时也会打一条 WARNING。

---

## 实测数字

全部由 `eval/` 下的评测框架跑出，可复现：`go test ./eval/ -v`

| 指标 | 目标 | 实测 | |
|---|---|---|---|
| 精确率（对抗性语料） | ≥ 98% | 24 篇对抗文本 **0 误报** | ✅ |
| 精确率（生成式，12000 条） | ≥ 98% | 误报 7 次，**0.058%** | ✅ |
| 召回率（结构化标识） | ≥ 99.5% | 37/37 = **100%** | ⚠️ 见下 |
| 召回率（名册外姓名/地址/机构） | ≥ 99.5% | **0%** | ❌ |
| P99 延迟（2KB 提示词） | ≤ 20ms | **277µs** | ✅ |
| P99 延迟（32KB） | ≤ 20ms | **3.8ms** | ✅ |
| P99 延迟（384KB ≈ 131k token） | ≤ 20ms | **14.9ms**（空闲机单请求） | ✅ |
| 吞吐（真实提示词形态，单请求） | ≥ 50MB/s | **69.0 MB/s** | ✅ |
| 吞吐（并发饱和，整机） | ≥ 50MB/s | **~40 MB/s** | ❌ |
| 还原准确率 | 100% | 500 组随机排列 **0 错位** | ✅ |
| 幂等性 | 是 | 脱敏、复原双向幂等 | ✅ |

**关于那个 100% 召回率：你不该采信它。** 正例语料是本项目作者写的，
识别器也是——量的是「模式能匹配它们本来就是为之而写的例子」。
**精确率那个数才是真的**，因为反例是对抗性写的：源代码、git 哈希、UUID、
订单号、毫秒时间戳、坐标、医学与法律术语，没有一条是为了通过而写的。

**关于并发下的吞吐：**并行分块降低的是**空闲机器上的单请求延迟**，
不是负载下的吞吐。核被并发请求占满之后就摊不出去了：

```
并发  1：P99   2.7ms   整机吞吐 12.1 MB/s
并发 16：P99  56.4ms   整机吞吐 39.8 MB/s
并发 64：P99 437.0ms   整机吞吐 38.7 MB/s
```

把空闲时的 69 MB/s 当作生产吞吐报，是性能页上最常见的那种误导。

---

## 为什么不是又一个 PII 库

四件事，是这条链路特有的，也是本项目存在的理由。

### 1. 把整个请求体喂给 NER，协议会被打烂

LLM 请求体是多层嵌套 JSON。NER 是**概率性**的，把整个 payload 当文本扫、
或递归净化所有字符串值，迟早会出这种事：

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

**本项目用白名单，不是黑名单。** 只有 7 条显式声明的 JSON 路径会被送进检测器，
其余字段在遍历层面就不会被访问到：

```
system
messages[*].content
messages[*].content[*].text                    ← 多模态只碰 text，不碰 image_url
messages[*].tool_calls[*].function.arguments   ← 只净化值，不碰键（键是 schema 参数名）
tools[*].function.description
tools[*].description
tools[*].function.parameters.**.description    ← 只取 description，enum/type/属性名不碰
```

黑名单的默认方向是错的：默认净化一切、例外才跳过，
意味着上游 API 新增任何字符串参数都会被 NER 触碰。安全组件必须默认拒绝。

### 2. 复原必须扛得住 SSE 帧边界

模型的回答是逐帧流式吐出来的，一个占位符会被切成两半：

```
帧 1: {"delta":{"content":"已通知 ANONYMIZED_NA"}}
帧 2: {"delta":{"content":"ME_0 处理"}}
```

滞留缓冲会压住不完整的尾部直到下一帧到来。**逐字节切分下，
流式复原与整体复原逐字相同**——有用例钉住这一点。

令牌化算子引入后这里出过一次真实故障：滞留只认 `ANONYMIZED_`，
于是被切开的 `[tok:email:9df3a0c1]` 前半截直接发给了终端用户。
注入回归验证过现在拦得住。

### 3. 租户在键里，不在 WHERE 子句里

每一个可逆构造都是一次查表：进去占位符或令牌，出来真实值。
**键里没有租户的查表，在构造上就是一个越权漏洞。**

这个洞在本项目里曾经是活的：会话保险库只以调用方提供的 `session_id` 作键，
而 `session_id` 是自由文本——租户 B 拿到租户 A 的 `session_id` 调
`/v1/restore`，原样拿回对方的**明文姓名和手机号**。不是令牌、不是摘要，是值本身。

修法不是加一层检查，是把租户放进键里：

```go
SessionRef{Tenant, Session}            // 会话保险库
TokenKey{Tenant, Namespace} + token    // 令牌库
PRIMARY KEY (tenant_id, namespace, token)   // SQL 驱动：复合主键，不是代理主键+租户列
```

过滤会在某一个调用点被忘掉，键不会。

### 4. 网关脱敏了模型看到的东西，管不到飞往 Datadog 的那份副本

同一段提示词还躺在 span 属性里。而遥测里的那份**更糟**：模型厂商有合同、
有留存策略，而可观测性后端对每一个有看板账号的人可读、留存一年。

```yaml
processors: [piiredaction, batch]     # 正确
processors: [batch, piiredaction]     # 已经晚了
```

放在 `batch` 之后照样能脱敏，但未脱敏的 span 已经在队列里待过，
而堆转储、debug exporter、崩溃日志都读得到它。

---

## 快速开始

### 作为 sidecar（任何语言的网关都能接）

> 还没有发布二进制或容器镜像。下面是从源码跑。
> No released binary or container image yet; this builds from source.

```bash
go build -o airlock ./cmd/airlock-agent

./airlock \
  --addr :8888 \
  --jurisdictions GEN,CN \
  --tenant-header X-Tenant-Id \
  --name-roster ./names.txt \
  --ner http://ner-service:8000/v1/detect   # 不配 --ner 时，姓名类召回率为 0
```

出站脱敏：

```bash
curl -X POST localhost:8888/v1/redact -H 'X-Tenant-Id: acme' -d '{
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
  "strategy_counts": {"mask":2},
  "blocked": false
}
```

入站复原（把模型回吐的占位符换回真实值）：

```bash
curl -X POST localhost:8888/v1/restore -H 'X-Tenant-Id: acme' -d '{
  "session_id": "conv-42",
  "payload": {"choices":[{"delta":{"content":"已通知 ANONYMIZED_NAME_0"}}]}
}'
# -> {"payload":{"choices":[{"delta":{"content":"已通知 张伟"}}]},"restored":1}
```

### 作为 Go 库

```go
import (
    "github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
    "github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
)

// 必须显式选择司法管辖区——没有默认值
reg, err := packs.NewRegistry([]string{"GEN", "CN"})
if err != nil {
    return err
}
redactor := anonymize.NewRedactorWith(reg, true /* fail-closed */)

// 会话保险库持有「占位符 → 真实值」，按租户+会话取
vaults := anonymize.NewVaultRegistry(time.Hour, 100_000)
vault, err := vaults.Get(anonymize.SessionRef{Tenant: "acme", Session: "conv-42"})
if err != nil {
    return err
}
scope := anonymize.StrategyScope{Tenant: "acme", Vault: vault}

// 出站
flow := anonymize.Flow{Name: "public_llm", Default: anonymize.NewMask(), Restores: true}
out, err := redactor.RedactTo(ctx, "联系张伟，手机 13812345678", scope, flow)
// out.Text == "联系张伟，手机 ANONYMIZED_PHONE_0"
//   （张伟需要名册或 NER 才能检出——见「成熟度」一节）

// 入站
back, err := redactor.Unredact(ctx, modelReply, scope)
```

---

## 能力细节

### 司法管辖区国家包

一张扁平的「敏感数据」字典，悄悄编码了编写者的假设。以美国为中心的引擎能找到
SSN 却漏掉意大利税号；以中国为中心的能找到身份证却漏掉德国税号。两者在各自本土
市场都没错，出了本土都没用——而且**故障是静默的**：用美国包扫意大利文档会报告
零 PII，这读起来像「数据很干净」，而不是「装错了包」。

所以 `jurisdictions` 是必填项，没有默认值。装错、拼错、不装，都在启动期报错。

| 包 | 覆盖 |
|---|---|
| `GEN` | 与国界无关：邮箱、银行卡（Luhn + ISO/IEC 7812 IIN）、IBAN、国际电话、IPv4、API 密钥/JWT |
| `CN` | 身份证（GB 11643）、统一社会信用代码（GB 32100）、手机、固话、护照、车牌 |
| `US` | SSN |
| `IT` | Codice Fiscale（CIN 控制字符）、Partita IVA |
| `DE` | Steuer-ID（ISO 7064 MOD 11,10 **+ 数字重复结构规则**） |
| `ES` | DNI / NIE（mod-23，同一识别器覆盖两者） |

德国那条值得单说：**只做校验位会放行十分之一的随机 11 位数字**——订单号、
时间戳都是 11 位数字。结构规则把这批全挡掉了（实测 2000/2000 校验位正确的
随机串全被拒绝）。

**租户 YAML 规则**（工号、资产编号、合同号）：`samples` 是强制的。
加载器在接受规则前把样本喂进组装好的识别器跑一遍——
**匹配不到任何东西的规则会加载失败，而不是保护失败。**

详见 [`configs/tenant-rules/example.yaml`](configs/tenant-rules/example.yaml)。

### 脱敏策略矩阵

`[REDACTED]` 是对某一个问题的答案，而对大多数问题都是错的答案：需要统计去重
用户数的分析仓库用不了它；需要让「他」始终指向同一个人的模型用不了它；
必须一个字节都不出去的 DLP 红线，也不会满足于一个仍为这些字节留着位置的占位符。

**算子由数据的去向决定，不由数据本身决定。**

| 算子 | 输出 | 可逆 | 用在哪 |
|---|---|---|---|
| `mask` | `ANONYMIZED_NAME_0` | ✅ | 公有云模型——保语法与指代一致 |
| `tokenize` | `[tok:email:9df3a0c1]` | ✅ | 跨系统伪名化 |
| `hash` | `[hash:email:a4b2efc8]` | ❌ | 分析数仓——可关联假名 |
| `char_mask` | `************1111` | ❌ | 展示层——保留末四位是**刻意的泄露** |
| `drop` | `` | ❌ | DLP 红线归档 |
| `generalize` | `1995-10-24` → `1990s` | ❌ | 医疗/研究导出 |

同一份请求体、四个去向，实测输出：

```
public_llm    客户手机 ANONYMIZED_PHONE_0，邮箱 ANONYMIZED_EMAIL_0     {mask:2}
pseudonymous  客户手机 [tok:phone:165d7009…]，邮箱 [tok:email:7c169fca…]  {tokenize:2}
analytics     客户手机 ，邮箱 [hash:email:2cbdec25]                      {drop:1, hash:1}
archive       客户手机 ，邮箱                                            {drop:2}
```

**唯一要紧的不变量是可逆性。** 给一条要复原响应的链路配上哈希，运行时不会有
任何报错：请求带哈希出站，模型用哈希作答，网关把 `[hash:name:a4b2efc8]`
当成人名交给终端用户。故障从头到尾静默——所以 `restores: true`
的链路在**加载期**就拒绝不可逆算子。

这个检查**只看算子名，不构建算子**：它必须在密钥没挂上时也能跑，
否则「缺 HMAC 密钥」会盖住「策略本身不成立」。

几个不打折扣的说法：

- **哈希用 HMAC，不是「SHA-256 加盐」。** 中国大陆手机号总量 10¹¹，
  已知盐一台笔记本几分钟穷举完。密钥从密钥卷读，绝不进配置文件。
- **假名仍然是个人数据。** 稳定到可以做关联，就稳定到可以做画像。GDPR 下它
  降低暴露面，但没有走出监管范围。
- **令牌库是一个 PII 数据库。** 这是跨系统可逆的代价，消不掉。
- **泛化不是隐私保证。** k-匿名是整个**发布数据集**的属性，网关算不了。

### 租户隔离与可逆令牌库

隔离模型必须显式声明，二选一，没有默认值——不配就不启动：

```bash
--tenant-header X-Tenant-Id   # 多租户
--single-tenant acme          # 单租户：让「不做隔离」成为敲出来的参数
```

| 令牌库驱动 | 用在哪 | TTL | 跨重启 |
|---|---|---|---|
| `MemoryTokenStore` | 开发、单进程 | ✅ | ❌ |
| `CacheTokenStore` | 多副本（Redis / DynamoDB / 任意 KV） | ✅ | ✅ |
| `SQLTokenStore` | 加密关系库 | ✅ | ✅ |

三个驱动跑**同一套契约用例**，否则「开发用内存、生产换 Redis」这句话不成立。
`Cache` 与 `SQLExecutor` 都不含厂商类型——签名里出现 `redis.Client`，
会让本库每个使用者都依赖那个客户端的版本。

`SQLTokenStore` 的值用租户派生密钥 AES-GCM 加密、以 HMAC 摘要作查找键，
租户参与 AAD——一行密文被挪到另一个租户名下会**解不开**。

**每租户密钥派生**（HKDF-SHA256）对 `hash` 算子是必需的：没有它，
同一个手机号在每个租户下摘要相同，两个租户比对数仓导出即可确认共有客户。

```
tenant-a  [hash:email:561bdc89]
tenant-b  [hash:email:ed13e46e]      同一个邮箱
```

**令牌不需要盐**——令牌是随机的，本就跨租户不可关联。保护它们的是复合键。

**GDPR 第 17 条：** `POST /v1/tenant/erase` 同时清会话映射与令牌库，
回执带条数——一次因租户串写错而匹配到零条的擦除，与一次真正成功的擦除，
在没有计数时看起来完全一样。

### 遥测防火墙

| 模块 | 依赖 | 用途 |
|---|---|---|
| `pii/telemetry` | 零外部依赖 | 防火墙 + OTLP/JSON 遍历器 |
| `otelprocessor/` | collector pdata | 真正的 Collector 处理器 |

覆盖 span 名（常是带客户 ID 的 URL 路径）、属性、`status.message`、
**span 事件**（异常消息是用运行时变量拼出来的，一条链路里最富含 PII 的地方）、
链接、日志正文与属性、资源属性、指标标签、exemplar、以及全部嵌套值。
`traceId`/`spanId` **从不改写**——改写脱不掉任何东西，却会打断整条链路。

**遥测不许用 mask**（构造期硬拒绝）：占位符按不同值在会话保险库中铸造，
而遥测没有会话——保险库会随流量增长；用在指标标签上还会让基数炸弹原样存活。

### 安全审计与管理面

审计事件只携带**计数、枚举与带密钥的指纹**：

```json
{"schema":"airlock.audit.v1","tenant":"acme","session_fingerprint":"1cbcf2a5ad1c089d",
 "action":"redact","outcome":"ok","destination":"public_llm",
 "entities":{"PHONE":1,"EMAIL":1,"ID_CARD":1},"strategies":{"mask":6},
 "recognizers":{"cn_mobile":1,"email":1,"gazetteer":2},"duration_micros":96}
```

**`session_id` 被指纹化，不被记录**——它是调用方自由文本，而调用方会拿
用户邮箱当会话 ID。原样记录会在一个没人把它归类为 PII 的字段上泄露 PII，
而这些请求的载荷本身脱敏得干干净净。

**错误只记类别，绝不记 `err.Error()`**——错误信息是写给排查的人看的，
所以它们会引用出问题的那个值。

这个保证是**结构性**的，不是靠人守规矩：有一条用例用反射遍历事件结构体，
遇到任何未经论证的字符串字段就失败。注入一个 `SampleText string` 会当场红：

```
Event.SampleText 是一个未经论证的字符串字段。
审计事件绝不能携带调用方可控的文本——它会被送进 SIEM、建索引、留存数年。
```

`GET /v1/admin/inspect` 给出策略矩阵、国家包装配、识别器健康度
（含**从未命中**的规则——一条写错的租户规则不报错，它只是安静地什么都不拦），
但不含密钥、盐、映射记录、名册条目或租户名单。**名册条目就是 PII**，
回显它等于导出 PII。

### GPU 显存感知准入

LLM 推理的真实约束是 **KV 缓存显存**，不是请求数。一个 10 万 token 的 prompt
配 1 个输出，和 1 千 token 配 10 万输出，QPS 完全相同，显存压力天差地别。

| KV 占用 | priority≤3 | priority 4~7 | priority≥8 |
|---|---|---|---|
| < 75% | 放行 | 放行 | 放行 |
| ≥ 75% | **429** | 放行 | 放行 |
| ≥ 90% 或检测到抢占 | 429 | **429** | 放行 |

在 GPU 死锁**之前**先牺牲低价值流量。等完全打满再一刀切，队列里已经全是低优先
级请求。

---

## 设计决策：踩过的坑

这一节记的都是**能编译、能运行、能报告成功，但业务上什么也没做**的故障。
它们是这个项目里最难抓的一类。

**识别器表只有一份。** 曾经同一张表存在三份副本（`RegexDetector`、
`predefinedSpecs`、packs），新增意大利/德国/西班牙识别器后，跑起来的二进制
用的仍是老副本——包装好了，业务上一个也没生效，且没有任何报错。

**校验位函数不许夹带长度。** `LuhnValid` 一度写死了 12–19 位（卡号长度），
于是意大利 11 位增值税号的识别器注册成功、运行正常、**永不命中**。
长度属于「卡号」这个概念，不属于 Luhn 这个算法。

**只做 Luhn 会放行十分之一的随机数字串**（单位校验位的理论值，实测 9.80%）。
加入 ISO/IEC 7812 的 IIN 前缀与各卡组织实际签发长度后降到 0.86%，
八个卡组织的公开测试卡号零漏检。

**IPv4 与四段式版本号字面完全相同。** `5.15.0.91` 既是合法地址也是内核版本号
——没有任何模式能分开，因为根本没有可分的东西。上下文对这一类被提升为
**必要条件**。代价写下来了：裸日志行里的地址会被漏掉。

**pdata 的 MoveTo/CopyTo 会产出独立副本。** OTel 处理器第一版用它隔离每个资源：
能编译、能运行、还会报告自己脱敏了多少字段——然后原样转发了原批次。

**`ResolveOverlaps` 曾是 O(n²)。** 3052 个实体上单次 8.8ms。改为「按起点切连通块
+ 块内原贪心」，3000 组随机输入上新旧输出逐字相同，6000 个实体上提速 285×。

**试过但不成立：把 22 个模式合并成一个并集正则做门控。** 逻辑上完全成立，
实测比不加还慢——RE2 把它模拟成一个大自动机，每字节代价高过依次跑那些小的。
记在这里，因为「合并成一个正则」听上去永远像个优化。

**服务契约里不含偏移量。** Python 的 `str` 索引按字符，Go 按字节，中文一字 3 字节。
直接采信对端偏移会把文本切碎，且**只在含中文时出错**——用英文测试完全正常。

**fail-closed 返回 200 + `blocked: true`，不返回 5xx。** 这不是服务故障而是安全
策略生效。返回 5xx 会让网关按「上游故障」重试或降级——而降级的方向往往是放行。

**脱敏映射永不落盘。** `SessionVault` 从类型层面禁止序列化。它存的是
「占位符 → 真实姓名/手机/身份证」，落盘就等于把脱敏组件变成 PII 数据库。

---

## 仓库结构

```
pii/detect/          检测：正则 + 校验位 + 名册 + 远程 NER + 分层 + 并行分块扫描
pii/detect/packs/    国家合规包 + 租户 YAML 规则加载器
pii/anonymize/       脱敏算子、策略矩阵、租户令牌库、会话保险库
pii/document/        AST 定向清洗白名单（协议完整性）
pii/verify/          双层验证：证据链验证器 + CAPID 上下文相关性
pii/audit/           GDPR 安全审计事件与 SIEM sink
pii/telemetry/       遥测防火墙（零外部依赖）
gpuload/             GPU 显存感知准入
sidecar/             HTTP 服务实现 + 租户解析 + 管理面快照
eval/                量化评测框架（语料、打分、延迟、吞吐、还原准确率）
cmd/airlock-agent/   sidecar 二进制 ← 主要交付物
otelprocessor/       OTel Collector 处理器（独立模块）
test/integration/    集成测试（独立模块，testcontainers）

cmd/airlock-gateway/ 演示用参考网关。不与 Envoy/APISIX 竞争，
internal/            只是为了让集成方式有一份可运行的示例。
```

`pii/*`、`gpuload`、`sidecar` 是公开包，可单独 import。

---

## License

Apache-2.0
