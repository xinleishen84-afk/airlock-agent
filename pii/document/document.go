package document

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"strconv"
	"strings"
)

// Package document applies redaction to LLM API payloads through a structural
// allowlist, so the protocol skeleton can never be corrupted.
// 通过结构化白名单对 LLM API 载荷执行脱敏，使协议骨架永不被污染。
//
// An LLM request body is deeply nested JSON. Feeding the whole payload to a
// probabilistic detector lets it rewrite `role`, `function.name` or a schema
// `enum` — and a request with a redacted role is simply broken. This package
// walks only the paths explicitly declared as natural-language regions; every
// other field is never visited.
// LLM 请求体是多层嵌套 JSON。把整个载荷交给概率性检测器，它会改写
// role、function.name 或 schema enum——而 role 被脱敏的请求就是坏的。
// 本包只遍历显式声明为自然语言区域的路径，其余字段根本不会被访问。
//
// 本文件实现「结构化 AST 定向清洗」。
//
// # Why the whole payload must not be fed to NER
// # 为什么不能把整个 Payload 喂给 NER
//
// An LLM API request body is a deeply nested JSON document. Treating it as raw
// text, or recursively sanitizing every string value, lets NER's
// **probabilistic output** corrupt the protocol skeleton:
// 大模型 API 的请求体是复杂的多嵌套 JSON。把它当作原始文本或递归地
// 净化所有字符串值，NER 的**概率性输出**会污染协议骨架：
//
//	role: "user"    -> ANONYMIZED_NAME_0   message role is lost / 消息角色丢失
//	function.name   -> ANONYMIZED_NAME_1   the tool becomes uncallable / 模型再也调不到该工具
//	parameters.enum -> ANONYMIZED_NAME_2   the argument constraint dies / 工具参数约束失效
//
// Restoration makes it worse: un-redaction depends on the session dictionary,
// so once the protocol is polluted, not only can the response not be restored —
// the request itself is already broken and downstream parsers give up.
// 更糟的是复原：un-redaction 依赖会话字典，协议一旦被污染，
// 不仅返回数据无法还原，请求本身就已破损，下游解析器直接罢工。
//
// # Allowlist, not denylist
// # 白名单，而不是黑名单
//
// An earlier implementation used a denylist (enumerate role/name/type and skip
// them). That shape is wrong: sanitize-everything-except means **any protocol
// field we failed to anticipate gets touched by NER**. One new string parameter
// upstream is one more path to a broken request.
// 早期实现用黑名单（列出 role/name/type 等骨架字段并跳过）。这个形状是错的：
// 默认净化一切、例外才跳过，意味着**任何未预料到的新协议字段都会被 NER 触碰**。
// OpenAI 新增一个字符串参数，网关就多一条破损路径。
//
// A security component must deny by default. Hence an explicit allowlist: only
// the paths in the table below reach NER; every other field is never even
// visited. Control over the protocol stays in deterministic code, out of reach
// of model predictions.
// 安全组件必须默认拒绝。这里改为显式白名单：只有下表列出的路径
// 会被送进 NER，其余字段在物理上根本不会被访问到。
// 协议控制权始终掌握在确定性的代码逻辑里，模型预测触碰不到。

// segKind is the kind of a path segment.
// 是路径段的类型。
type segKind uint8

const (
	segKey     segKind = iota // named field / 具名字段
	segIndex                  // any array index [*] / 数组任意下标
	segDeepAny                // 任意深度 **，仅用于 schema 内的 description
)

// segment is one step in a path.
// 是路径中的一段。
type segment struct {
	kind segKind
	name string
}

// valueKind describes how a target value should be sanitized.
// 描述目标值该如何净化。
type valueKind uint8

const (
	// kindText：普通自然语言字符串，直接净化
	kindText valueKind = iota
	// kindJSONString：值本身是一段 JSON 文本（工具调用参数）。
	// 必须先解析，只净化其中的**值**——它的键是 schema 定义的参数名，
	// 属于协议骨架，脱敏后模型与本地工具就对不上了。
	kindJSONString
	// kindJSONObject：值是一个已解析的 JSON 对象或数组（Anthropic 的
	// tool_use.input 就是这个形态，不是 JSON 字符串）。递归净化其中的值，
	// 键名同样属于协议骨架，不碰。
	//
	// kindJSONObject: the value is an already-parsed JSON object or array —
	// Anthropic's tool_use.input has this shape rather than a JSON string.
	// Values are sanitized recursively; keys are protocol skeleton and are not.
	kindJSONObject
)

// pathRule is one targeted-sanitization rule.
// 是一条定向清洗规则。
//
// Distinct from `rule` in detector.go, which is a regex matching rule. Naming
// both "rule" would suggest they are the same mechanism; they are not.
// 与 detector.go 里的 rule 不同：那个是正则匹配规则，
// 这个是 JSON 路径白名单——两者都叫 rule 会让人误以为是同一套机制。
type pathRule struct {
	path []segment
	kind valueKind
	desc string // for audit and docs / 供审计与文档
}

// sanitizeRules is the only set of paths NER and the regex detectors may touch.
// 是唯一允许被 NER/正则触碰的路径清单。
//
// This table *is* the definition of "unstructured natural-language region".
// Every addition must answer: is this field freely written by a human or a
// model? If it carries an enum, an identifier, a type name or a schema
// constraint, it does not belong here.
// 这张表就是「非结构化自然语言区域」的完整定义。新增条目必须能回答：
// 这个字段的内容是由人或模型自由撰写的吗？如果它承载的是枚举、标识符、
// 类型名或 schema 约束，就不属于这里。
var sanitizeRules = []pathRule{
	{
		path: seg("system"),
		kind: kindText,
		desc: "顶层系统提示词（Anthropic 风格）",
	},
	{
		path: seg("messages", "[*]", "content"),
		kind: kindText,
		desc: "消息正文（字符串形态）",
	},
	{
		path: seg("messages", "[*]", "content", "[*]", "text"),
		kind: kindText,
		desc: "消息正文（多模态内容块形态）——只碰 text，不碰 image_url 等",
	},
	{
		path: seg("messages", "[*]", "tool_calls", "[*]", "function", "arguments"),
		kind: kindJSONString,
		desc: "模型生成的工具入参（JSON 字符串），只净化值不碰键",
	},
	// --- 以下六条补的是「声称支持、实际漏过」的载荷形态 ---
	// --- The six shapes below were claimed as supported yet passed through ---
	//
	// 这张表原有七条，覆盖 OpenAI Chat Completions 的主干形态。但表里同时
	// 有 system 与 tools[*].description 两条标着「Anthropic 风格」，也就是
	// Anthropic 形态是声称支持的——而它的两种内容块（tool_use / tool_result）
	// 一条都不在表里。实测：整段工具返回结果原样发给了模型。
	//
	// 严格白名单对**污染**是安全的（没列到的字段物理上不会被访问），对
	// **泄露**却是失效开放的：没列到的字段同样不会被脱敏，而且不报错。
	// 两种失效方向相反，容易只记住前一种。
	//
	// The original seven rules covered OpenAI Chat Completions. Two of them are
	// labelled "Anthropic style", so that shape is claimed — yet neither of its
	// content blocks appeared here, and a whole tool result reached the model
	// verbatim. A strict allowlist is safe against corruption (unlisted fields
	// are never touched) but fails open for leakage (unlisted fields are never
	// redacted, silently). The two failure directions are opposite and it is
	// easy to remember only the first.
	{
		path: seg("messages", "[*]", "content", "[*]", "content"),
		kind: kindText,
		desc: "Anthropic tool_result 内容块（字符串形态）——" +
			"这是工具的**输出**，在 agent 循环里就是数据库查出来的整行记录",
	},
	{
		path: seg("messages", "[*]", "content", "[*]", "content", "[*]", "text"),
		kind: kindText,
		desc: "Anthropic tool_result 内容块（内容块数组形态）",
	},
	{
		path: seg("messages", "[*]", "content", "[*]", "input"),
		kind: kindJSONObject,
		desc: "Anthropic tool_use 入参对象——是已解析的对象而非 JSON 字符串",
	},
	{
		path: seg("messages", "[*]", "function_call", "arguments"),
		kind: kindJSONString,
		desc: "OpenAI 旧版 function_call 入参——已废弃但老客户端仍在发",
	},
	{
		path: seg("input", "[*]", "content", "[*]", "text"),
		kind: kindText,
		desc: "OpenAI Responses API 的输入内容块（input_text / output_text）",
	},
	{
		path: seg("prompt"),
		kind: kindText,
		desc: "旧版 completions 端点的顶层 prompt",
	},
	{
		path: seg("system", "[*]", "text"),
		kind: kindText,
		desc: "Anthropic 系统提示词（内容块数组形态）——" +
			"同一个 system 键既可以是字符串也可以是块数组，两条规则各管一种",
	},
	{
		path: seg("input"),
		kind: kindText,
		desc: "embeddings 端点的顶层 input（字符串形态）——" +
			"要嵌入的往往正是客户记录原文",
	},
	{
		path: seg("input", "[*]"),
		kind: kindText,
		desc: "embeddings 端点的顶层 input（字符串数组形态）；" +
			"若数组元素是 token id 整数则本规则不适用，自动跳过",
	},
	{
		path: seg("tools", "[*]", "function", "description"),
		kind: kindText,
		desc: "工具描述——开发者常在此写含 PII 的示例",
	},
	{
		path: seg("tools", "[*]", "description"),
		kind: kindText,
		desc: "工具描述（Anthropic 风格）",
	},
	{
		path: seg("tools", "[*]", "function", "parameters", "**", "description"),
		kind: kindText,
		desc: "工具参数 schema 中的字段描述——同样可能含示例 PII，" +
			"但**只取 description**，enum / type / 属性名一律不碰",
	},
}

// seg compiles a string path into a segment sequence.
// 把字符串形式的路径编译为段序列。
func seg(parts ...string) []segment {
	out := make([]segment, 0, len(parts))
	for _, p := range parts {
		switch p {
		case "[*]":
			out = append(out, segment{kind: segIndex})
		case "**":
			out = append(out, segment{kind: segDeepAny})
		default:
			out = append(out, segment{kind: segKey, name: p})
		}
	}
	return out
}

// textTransform sanitizes one span of natural language (redact or restore).
// 是对一段自然语言的净化函数（脱敏或复原）。
//
// key 是该段文本在文档里的结构路径（如
// choices.0.delta.tool_calls.0.function.arguments）。脱敏是逐段无状态的，
// 用不上它；但流式复原要为每股文本流维护独立的滞留缓冲，必须靠它把
// 「正文」与「第 N 个工具调用的入参」区分开——这两者在不同帧里可能
// 恰好都是帧内第一个可复原字段。
//
// key is the field's structural path within the document. Redaction is
// stateless per span and ignores it; streaming restoration needs it to keep a
// separate hold-back buffer per text stream, because the message body and the
// Nth tool call's arguments can each be the first restorable field in their
// own frame.
type textTransform func(key, text string) (string, error)

// SanitizeDocument applies targeted sanitization to a parsed request document.
// 对已解析的请求文档执行定向清洗。
//
// Only the paths in sanitizeRules are traversed. Everything else — including
// fields this gateway has never heard of — is never visited, and therefore
// cannot possibly be polluted.
// 只遍历 sanitizeRules 列出的路径。文档中其余部分——包括本网关
// 完全不认识的新字段——不会被访问，因此在物理上不可能被污染。
func SanitizeDocument(doc map[string]any, transform textTransform) error {
	for _, r := range sanitizeRules {
		if err := walk(doc, "", r.path, r.kind, transform); err != nil {
			return fmt.Errorf("清洗路径 %s 失败: %w", r.desc, err)
		}
	}
	return nil
}

// walk descends along a path and sanitizes at the leaf.
// 沿路径下行，到达叶子时执行净化。
//
// node is typed `any`: a type mismatch mid-path (e.g. content is an array while
// the rule expects a string) simply returns — that rule does not apply to this
// shape and another one covers it. Returning no error is deliberate: request
// bodies take many shapes, and a rule not matching is the norm, not a fault.
// node 用 any 而非具体类型：中途遇到类型不符（比如 content 是数组而规则
// 期望字符串）直接静默返回——那说明这条规则不适用于当前形态，
// 由另一条规则覆盖。不报错是刻意的：请求体形态多样，
// 一条规则不匹配是常态而非异常。
func walk(node any, key string, path []segment, kind valueKind, transform textTransform) error {
	if len(path) == 0 {
		return fmt.Errorf("内部错误：空路径")
	}

	current := path[0]
	rest := path[1:]

	switch current.kind {
	case segKey:
		obj, ok := node.(map[string]any)
		if !ok {
			return nil
		}
		child, exists := obj[current.name]
		if !exists {
			return nil
		}
		childKey := joinKey(key, current.name)
		if len(rest) == 0 {
			// 到达叶子：这是唯一会调用 transform 的地方
			newVal, err := applyTransform(child, childKey, kind, transform)
			if err != nil {
				return err
			}
			obj[current.name] = newVal
			return nil
		}
		return walk(child, childKey, rest, kind, transform)

	case segIndex:
		arr, ok := node.([]any)
		if !ok {
			return nil
		}
		for i, item := range arr {
			itemKey := joinKey(key, elementID(item, i))
			if len(rest) == 0 {
				newVal, err := applyTransform(item, itemKey, kind, transform)
				if err != nil {
					return err
				}
				arr[i] = newVal
				continue
			}
			if err := walk(item, itemKey, rest, kind, transform); err != nil {
				return err
			}
		}
		return nil

	case segDeepAny:
		// 任意深度下探，但**只在剩余路径匹配时才净化**。
		// 用于 JSON Schema 里任意嵌套层级的 description 字段。
		return walkDeep(node, key, rest, kind, transform)
	}
	return nil
}

// walkDeep matches the remaining path at arbitrary depth.
// 在任意深度上匹配剩余路径。
//
// Every level attempts to match rest while continuing to recurse, so both
// parameters.properties.city.description and
// parameters.properties.a.items.properties.b.description are reached.
// 每一层都尝试匹配 rest，同时继续向下递归。这样
// parameters.properties.city.description 与
// parameters.properties.a.items.properties.b.description 都能命中。
func walkDeep(node any, key string, rest []segment, kind valueKind, transform textTransform) error {
	switch n := node.(type) {
	case map[string]any:
		// Try to match at this level. / 在本层尝试匹配
		if err := walk(n, key, rest, kind, transform); err != nil {
			return err
		}
		// 继续下探。注意：不能对已匹配的键再下探，否则
		// description 里若恰好是个对象会被重复处理
		for k, v := range n {
			if len(rest) > 0 && rest[0].kind == segKey && rest[0].name == k {
				continue
			}
			if err := walkDeep(v, joinKey(key, k), rest, kind, transform); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range n {
			if err := walkDeep(item, joinKey(key, strconv.Itoa(i)), rest, kind, transform); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyTransform sanitizes according to the value kind.
// 按值类型执行净化。
func applyTransform(value any, key string, kind valueKind, transform textTransform) (any, error) {
	// kindJSONObject 的值本来就不是字符串，要在字符串断言之前处理
	if kind == kindJSONObject {
		switch value.(type) {
		case map[string]any, []any:
			return transformJSONValue(value, key, transform)
		}
		return value, nil
	}
	s, ok := value.(string)
	if !ok {
		return value, nil // type mismatch: rule does not apply / 类型不符，规则不适用
	}

	switch kind {
	case kindText:
		return transform(key, s)

	case kindJSONString:
		return transformJSONString(s, key, transform)
	}
	return value, nil
}

// transformJSONString handles the case where the value is itself JSON text.
// 处理「值本身是一段 JSON 文本」的情形。
//
// Tool-call arguments are a JSON string produced by the model, e.g.
// 工具调用参数是模型生成的 JSON 字符串，例如：
//
//	{"customer_name": "Zhang Wei", "city": "Beijing"}
//
// The **values** are natural language the model extracted from user input and
// must be sanitized. The **keys** are parameter names defined by the tool
// schema — protocol skeleton; redacting them makes the local tool unable to
// recognize the parameter. Hence values only.
// 其中的**值**是模型从用户输入里提取的，属于自然语言，必须净化；
// **键**是工具 schema 定义的参数名，属于协议骨架，脱敏后本地工具
// 就再也认不出这个参数了。因此只净化值。
//
// On parse failure the input is returned verbatim: models occasionally emit
// invalid JSON, and that should not fail the whole request — let upstream
// handle the format error.
// 解析失败时原样返回：模型偶尔会生成非法 JSON，此时不该整个请求失败，
// 由上游自行处理格式错误。
func transformJSONString(raw, key string, transform textTransform) (any, error) {
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return raw, nil
	}

	sanitized, err := transformJSONValue(parsed, key, transform)
	if err != nil {
		return nil, err
	}
	out, err := MarshalPreserving(sanitized)
	if err != nil {
		return nil, fmt.Errorf("重新序列化工具参数失败: %w", err)
	}
	return string(out), nil
}

// transformJSONValue recursively sanitizes JSON values, keeping every key.
// 递归净化 JSON 值，保留全部键名。
func transformJSONValue(value any, key string, transform textTransform) (any, error) {
	switch v := value.(type) {
	case string:
		return transform(key, v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			// 键名是 schema 定义的参数名，属于协议骨架，绝不净化
			r, err := transformJSONValue(item, joinKey(key, k), transform)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			r, err := transformJSONValue(item, joinKey(key, strconv.Itoa(i)), transform)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	default:
		return value, nil
	}
}

// SanitizeRuleDescriptions returns every rule's description, for startup logs
// and documentation. It turns "which fields does NER touch" into an auditable,
// explicit list.
// 返回全部规则的说明，供启动日志与文档。
// 把「哪些字段会被 NER 触碰」变成可审计的显式清单。
func SanitizeRuleDescriptions() []string {
	out := make([]string, 0, len(sanitizeRules))
	for _, r := range sanitizeRules {
		out = append(out, r.desc)
	}
	return out
}

// 本文件是 sanitize.go 的反向：对**响应**做结构化 AST 定向复原。
//
// # 为什么复原也必须走 AST
//
// 复原是把占位符换回真实值。早期实现直接在 SSE 帧的原始 JSON 文本上
// 做字符串替换——这与「把整个请求体喂给 NER」是同一类错误的反向版本：
// 在结构化 JSON 上做裸文本操作。
//
// 真实 PII 值含有 JSON 特殊字符时会直接产出非法 JSON：
//
//	姓名 李"小"娜  ->  {"content":"已通知 李"小"娜"}   ← 解析器罢工
//	地址含换行     ->  {"content":"北京市\n朝阳区"}     ← 字面换行截断字符串
//
// 而且这类值在真实数据里并不罕见（带引号的昵称、多行地址、含反斜杠的路径）。
// 解法是：解析 JSON -> 在结构上替换 -> 重新序列化（marshalPreserving），
// 转义交给标准库处理，从根上消除这种可能。

// responseRules is the allowlist of response paths eligible for restoration.
// 是响应中允许被复原的路径白名单。
//
// Same reasoning as the request side: touch only natural-language regions;
// never the protocol skeleton (id / model / finish_reason / tool_calls[].id /
// function.name). A placeholder should never appear in a skeleton field — if
// one does, something upstream is wrong, and leaving it alone is safer than
// substituting on our own initiative.
// 与请求侧同理：只碰自然语言区域，协议骨架（id / model / finish_reason /
// tool_calls[].id / function.name）绝不触碰。占位符本不该出现在骨架字段里，
// 一旦出现说明上游有问题，此时保留原样比擅自替换更安全。
var responseRules = []pathRule{
	{
		path: seg("choices", "[*]", "delta", "content"),
		kind: kindText,
		desc: "流式增量正文",
	},
	{
		path: seg("choices", "[*]", "delta", "reasoning_content"),
		kind: kindText,
		desc: "流式增量思考过程",
	},
	// 流式工具入参不在此表中——它由 StreamRestorer 的工具调用屏障独占处理。
	//
	// 曾经在这里，kind 是 kindText，即在半截 JSON 文本上做替换。实测真值
	// 含引号时直接产出 {"who":"李"小"娜"} 这种非法 JSON，下游工具解析器
	// 罢工。本文件另一处注释写着「绝不在原始 JSON 文本上做字符串替换」，
	// 这条规则恰恰在做那件事。攒齐整段再按结构复原，这一整类问题不复存在。
	//
	// Streaming tool arguments are absent here by design — the tool-call
	// barrier in StreamRestorer owns them. This rule used kindText, i.e. text
	// substitution on half a JSON document; a real value containing a quote
	// produced invalid JSON and broke the downstream tool's parser. Buffering
	// the whole argument and restoring it structurally removes the class.
	{
		path: seg("choices", "[*]", "message", "content"),
		kind: kindText,
		desc: "非流式响应正文",
	},
	{
		path: seg("choices", "[*]", "message", "reasoning_content"),
		kind: kindText,
		desc: "非流式思考过程",
	},
	{
		path: seg("choices", "[*]", "message", "tool_calls", "[*]", "function", "arguments"),
		kind: kindJSONString,
		desc: "非流式工具入参（完整 JSON），只复原值不碰键",
	},
	{
		path: seg("content", "[*]", "text"),
		kind: kindText,
		desc: "内容块正文（Anthropic 风格）",
	},
	{
		path: seg("delta", "text"),
		kind: kindText,
		desc: "流式增量正文（Anthropic 风格）",
	},
	{
		path: seg("content_block", "text"),
		kind: kindText,
		desc: "Anthropic content_block_start 里预置的首段正文",
	},
	{
		path: seg("content", "[*]", "input"),
		kind: kindJSONObject,
		desc: "Anthropic 非流式 tool_use 入参对象（已完整，可直接结构化复原）",
	},
	{
		path: seg("output", "[*]", "content", "[*]", "text"),
		kind: kindText,
		desc: "OpenAI Responses API 的输出内容块（output_text）",
	},
	{
		path: seg("choices", "[*]", "message", "function_call", "arguments"),
		kind: kindJSONString,
		desc: "OpenAI 旧版非流式 function_call 入参",
	},
	// Anthropic 的流式工具入参（delta.partial_json）刻意不在此表中：
	// 它和 OpenAI 的 delta.tool_calls[].function.arguments 一样是不完整的
	// JSON 分片，当普通规则处理就等于在半截 JSON 文本上做替换——真值含引号
	// 时直接产出非法 JSON。它由 StreamRestorer 的工具调用屏障处理。
	//
	// Anthropic's streaming tool arguments (delta.partial_json) are absent here
	// on purpose: like OpenAI's, they are incomplete JSON fragments, and a plain
	// rule would substitute inside half a document. The tool-call barrier owns
	// them.
}

// RestoreDocument applies targeted restoration to a parsed response document.
// 对已解析的响应文档执行定向复原。
func RestoreDocument(doc map[string]any, transform textTransform) error {
	for _, r := range responseRules {
		if err := walk(doc, "", r.path, r.kind, transform); err != nil {
			return err
		}
	}
	return nil
}

// StreamRestorer performs structured, per-frame restoration over an SSE stream.
// 对 SSE 流做逐帧的结构化复原。
//
// Two problems stack here:
// 需要解决两个叠加的问题：
//
//  1. Structural safety — substitution must happen on the parsed structure,
//     never on raw text.
//     结构安全——必须解析 JSON 后在结构上替换，不能做裸文本替换。
//  2. Cross-frame placeholders — one placeholder can be split across two frames
//     ("ANONYMIZED_NA" + "ME_0"), requiring a hold-back buffer.
//     跨帧占位符——一个占位符可能被切分到两个帧里，需要滞留缓冲。
//
// Each natural-language path keeps its own buffer: the message body and the
// tool arguments are independent text streams, and sharing one buffer would let
// them contaminate each other.
// 每条自然语言路径各自维护一个滞留缓冲：正文与工具入参是两股独立的
// 文本流，共用一个缓冲会让它们互相污染。
type StreamRestorer struct {
	redactor *anonymize.Redactor
	scope    anonymize.StrategyScope
	buffers  map[string]*anonymize.StreamUnredactor
	phantom  []string

	// 工具调用屏障：入参分片按 choice:index 攒着，放行时一次性复原
	toolArgs  map[string]*strings.Builder
	toolShape map[string]map[string]any // 保留 index/id/name 以便回填
	toolOrder []string                  // 放行顺序＝首次出现顺序
	// pendingFrames 存放已渲染但尚未取走的补发帧（Anthropic 形态各自成帧）
	pendingFrames [][]byte
}

// NewStreamRestorer creates a restorer for one stream.
// 为一条流创建复原器。
func NewStreamRestorer(r *anonymize.Redactor, scope anonymize.StrategyScope) *StreamRestorer {
	return &StreamRestorer{
		redactor:  r,
		scope:     scope,
		buffers:   make(map[string]*anonymize.StreamUnredactor, 2),
		toolArgs:  map[string]*strings.Builder{},
		toolShape: map[string]map[string]any{},
	}
}

// Frame restores one SSE data frame and returns the frames to emit, in order.
// 复原一个 SSE 数据帧，返回应当依次发出的帧。
//
// 返回切片而非单帧：工具调用屏障放行时会补发装着完整入参的帧。绝大多数
// 情况下返回恰好一帧。**当前帧永远是切片的最后一个**——补发帧在语义上
// 属于终止帧之前，因此排在它前面。调用方若要把原帧的 SSE event/id 带上，
// 应当认最后一个而不是第一个。
//
// Returns a slice because the barrier emits extra frames on release. The
// current frame is always the LAST element — released frames belong before the
// terminator that triggered them. Callers propagating the original SSE
// event/id must attach it to the last frame, not the first.
//
// A frame that does not parse as JSON is returned verbatim: upstream may emit
// non-JSON heartbeats or error text, and doing nothing is safer than guessing.
// 帧无法解析为 JSON 时原样返回：上游可能吐出非 JSON 的心跳或错误文本，
// 此时不做任何替换比猜测更安全。
func (s *StreamRestorer) Frame(ctx context.Context, data []byte) [][]byte {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return [][]byte{data}
	}

	// 工具调用先被屏障截走：入参分片只入缓冲，不参与逐帧复原。
	released := s.absorbToolCalls(doc)
	released = append(released, s.absorbAnthropicToolCalls(doc)...)

	// 用结构路径区分不同的文本流。
	//
	// 这里曾按「帧内第几个可复原字段」做键，理由是「同一位置在各帧间
	// 是同一股文本流」。那个前提对 agent 流量不成立：各帧携带的字段
	// 集合是变的——某帧只有 delta.content，下一帧只有
	// delta.tool_calls[0].function.arguments，两者都是帧内第 0 个字段，
	// 于是共用同一个滞留缓冲。
	//
	// This was keyed by ordinal position within the frame, on the premise that
	// the same position across frames is the same text stream. That premise
	// fails for agent traffic: frames carry different field subsets.
	err := RestoreDocument(doc, func(key, text string) (string, error) {
		buf, ok := s.buffers[key]
		if !ok {
			buf = anonymize.NewStreamUnredactor(s.redactor, s.scope)
			s.buffers[key] = buf
		}
		return buf.Feed(ctx, text)
	})
	if err != nil {
		return [][]byte{data}
	}

	out, err := MarshalPreserving(doc)
	if err != nil {
		// 序列化失败时退回原帧，绝不产出半截 JSON
		return [][]byte{data}
	}

	// 放行帧必须排在**当前帧之前**。
	//
	// 触发放行的那一帧正是终止帧（OpenAI 的 finish_reason、Anthropic 的
	// content_block_stop）。客户端看到终止信号就会把工具调用定型并派发，
	// 若参数帧排在它后面，派发时手里还是空参数，而那一帧要么被忽略、
	// 要么被当成协议错误。屏障攒下来的内容在语义上属于终止之前，
	// 发出的顺序也必须如此。
	//
	// The frame that triggers release is the terminator itself. A client
	// finalizes and dispatches the tool call on seeing it, so an arguments
	// frame arriving afterwards is either ignored or treated as a protocol
	// error. What the barrier held belongs before the terminator semantically,
	// and must be emitted there too.
	var frames [][]byte
	for {
		extra := s.renderReleased(ctx, released)
		if extra == nil {
			break
		}
		frames = append(frames, extra)
		released = nil // 后续轮次只取 pendingFrames 里的剩余帧
	}
	return append(frames, out)
}

// absorbToolCalls 把本帧里的工具入参分片吸进屏障缓冲，并从帧中抹去。
// Absorbs this frame's tool-argument fragments into the barrier and blanks them.
//
// # 为什么工具入参不能逐帧复原
// # Why tool arguments cannot be restored frame by frame
//
// 工具入参是给机器的结构化载荷，不是给人看的文本——逐帧吐出去没有任何
// 延迟收益，却要在半截 JSON 上做文本替换。实测三类故障，全部静默：
//
//   - 真值含引号时产出 {"who":"李"小"娜"}，下游工具解析器罢工
//   - 占位符跨帧劈开时两半落进不同缓冲，工具收到字面量 "ME_0"
//   - 流末尾残留被当作 delta.content 发给用户，同时工具收到截断的 JSON
//
// 攒齐整段再按结构复原一次，这三类同时消失：替换发生在解析后的值上，
// 占位符不可能被劈开，也不存在需要另找地方吐的残留。
//
// Tool arguments are a machine payload, not text a human reads — streaming them
// buys no latency and forces text substitution on half a JSON document. Three
// measured failure modes, all silent: a real value containing a quote produced
// invalid JSON; a placeholder split across frames landed in two buffers and the
// tool received the literal "ME_0"; end-of-stream residue was emitted to the
// user as content while the tool got truncated JSON. Assembling first and
// restoring once removes all three.
func (s *StreamRestorer) absorbToolCalls(doc map[string]any) []string {
	choices, ok := doc["choices"].([]any)
	if !ok {
		return nil
	}
	var release []string
	for ci, c := range choices {
		choice, ok := c.(map[string]any)
		if !ok {
			continue
		}
		choiceID := elementID(choice, ci)
		delta, _ := choice["delta"].(map[string]any)
		if delta != nil {
			if calls, ok := delta["tool_calls"].([]any); ok {
				for pos, raw := range calls {
					call, ok := raw.(map[string]any)
					if !ok {
						continue
					}
					fn, ok := call["function"].(map[string]any)
					if !ok {
						continue
					}
					frag, ok := fn["arguments"].(string)
					if !ok {
						continue
					}
					key := choiceID + ":" + elementID(call, pos)
					if s.toolArgs == nil {
						s.toolArgs = map[string]*strings.Builder{}
					}
					b, ok := s.toolArgs[key]
					if !ok {
						b = &strings.Builder{}
						s.toolArgs[key] = b
						s.toolOrder = append(s.toolOrder, key)
						s.toolShape[key] = call
					}
					b.WriteString(frag)
					// 分片从本帧抹去：屏障放行前不向下游吐任何入参
					fn["arguments"] = ""
				}
			}
		}
		// finish_reason 出现即为屏障放行点——该 choice 的工具调用已完整
		if fr, exists := choice["finish_reason"]; exists && fr != nil {
			for _, key := range s.toolOrder {
				if strings.HasPrefix(key, choiceID+":") {
					release = append(release, key)
				}
			}
		}
	}
	return release
}

// absorbAnthropicToolCalls 处理 Anthropic 形态的流式工具入参。
// Handles Anthropic-shaped streaming tool arguments.
//
// # 形状不同，问题完全相同
// # A different shape, the identical problem
//
// Anthropic 把工具入参切成 delta.partial_json 分片，用事件顶层的 index 标识
// 是第几个内容块，以 content_block_stop 收尾：
//
//	{"type":"content_block_start","index":1,"content_block":{"type":"tool_use",...}}
//	{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta",
//	 "partial_json":"{\"who\":"}}
//	{"type":"content_block_stop","index":1}
//
// 名字和层级都与 OpenAI 不同，但它同样是「不完整的 JSON 分片」。若当作普通
// 文本逐帧复原，真值含引号时照样产出非法 JSON——也就是刚在 OpenAI 那条路
// 上修掉的那个 bug 会原封不动地在这条路上重现一次。因此走同一道屏障。
//
// Anthropic splits tool arguments into delta.partial_json fragments, keyed by
// the event's top-level index and terminated by content_block_stop. The names
// and nesting differ from OpenAI's, but these are the same incomplete JSON
// fragments: restoring them per frame reproduces, verbatim, the invalid-JSON
// bug just fixed on the OpenAI path. Hence the same barrier.
func (s *StreamRestorer) absorbAnthropicToolCalls(doc map[string]any) []string {
	idx, hasIdx := doc["index"].(float64)
	if !hasIdx {
		return nil
	}
	key := "anthropic:" + strconv.Itoa(int(idx))

	switch doc["type"] {
	case "content_block_start":
		// 记住 tool_use 块的骨架，放行时回填 id / name
		if cb, ok := doc["content_block"].(map[string]any); ok && cb["type"] == "tool_use" {
			s.toolShape[key] = cb
		}
		return nil

	case "content_block_delta":
		delta, ok := doc["delta"].(map[string]any)
		if !ok || delta["type"] != "input_json_delta" {
			return nil
		}
		frag, ok := delta["partial_json"].(string)
		if !ok {
			return nil
		}
		b, ok := s.toolArgs[key]
		if !ok {
			b = &strings.Builder{}
			s.toolArgs[key] = b
			s.toolOrder = append(s.toolOrder, key)
		}
		b.WriteString(frag)
		// 分片从本帧抹去：屏障放行前不向下游吐任何入参
		delta["partial_json"] = ""
		return nil

	case "content_block_stop":
		if _, ok := s.toolArgs[key]; ok {
			return []string{key}
		}
	}
	return nil
}

// renderReleased 把放行的工具调用还原成一个完整的增量帧。
// Renders released tool calls as one complete delta frame.
//
// 客户端按 index 拼接 arguments，因此「一次性给出完整字符串」与
// 「分多次给出」在协议上等价——屏障不改变客户端看到的最终结果，
// 只改变它何时看到，以及看到的是不是合法 JSON。
//
// Clients concatenate arguments by index, so delivering the whole string at
// once is protocol-equivalent to delivering it in pieces. The barrier changes
// when the client sees it and whether it is valid JSON, not what it assembles.
func (s *StreamRestorer) renderReleased(ctx context.Context, keys []string) []byte {
	if len(keys) == 0 {
		return nil
	}
	byChoice := map[string][]any{}
	for _, key := range keys {
		b, ok := s.toolArgs[key]
		if !ok {
			continue
		}
		delete(s.toolArgs, key)
		choiceID, rest, _ := strings.Cut(key, ":")
		restored := s.restoreArgs(ctx, b.String())

		// Anthropic 形态单独成帧：它的线上结构与 OpenAI 的 choices/delta
		// 完全不同，硬塞进同一个信封客户端会认不出来。
		if choiceID == "anthropic" {
			idx, _ := strconv.Atoi(rest)
			frame := map[string]any{
				"type":  "content_block_delta",
				"index": idx,
				"delta": map[string]any{
					"type":         "input_json_delta",
					"partial_json": restored,
				},
			}
			if out, err := MarshalPreserving(frame); err == nil {
				s.pendingFrames = append(s.pendingFrames, out)
			}
			continue
		}

		shape := s.toolShape[key]
		call := map[string]any{
			"function": map[string]any{"arguments": restored},
		}
		// 回填 index / id / name：客户端靠它们把分片归位
		for _, f := range []string{"index", "id", "type"} {
			if v, ok := shape[f]; ok {
				call[f] = v
			}
		}
		if fn, ok := shape["function"].(map[string]any); ok {
			if n, ok := fn["name"]; ok {
				call["function"].(map[string]any)["name"] = n
			}
		}
		byChoice[choiceID] = append(byChoice[choiceID], call)
	}
	if len(byChoice) == 0 {
		if len(s.pendingFrames) > 0 {
			out := s.pendingFrames[0]
			s.pendingFrames = s.pendingFrames[1:]
			return out
		}
		return nil
	}
	var choices []any
	for choiceID, calls := range byChoice {
		c := map[string]any{"delta": map[string]any{"tool_calls": calls}}
		if n, err := strconv.Atoi(choiceID); err == nil {
			c["index"] = n
		}
		choices = append(choices, c)
	}
	out, err := MarshalPreserving(map[string]any{"choices": choices})
	if err != nil {
		return nil
	}
	return out
}

// restoreArgs 对完整的工具入参做结构化复原。
// Restores a complete tool-argument payload structurally.
//
// 走 transformJSONString：解析后只替换值，键名（工具 schema 定义的参数名）
// 原样保留，真值里的引号与换行由重新序列化负责转义。
//
// 解析失败时退回文本复原：模型偶尔生成非法 JSON，此时它已经是坏的，
// 至少要保证占位符被换成真值，而不是把占位符原样交给工具。
//
// Parse failure falls back to text restoration: the model occasionally emits
// invalid JSON, and at that point the payload is already broken — better to at
// least resolve the placeholders than hand them to the tool verbatim.
func (s *StreamRestorer) restoreArgs(ctx context.Context, raw string) string {
	plain := func(_, text string) (string, error) {
		res, err := s.redactor.Unredact(ctx, text, s.scope)
		if err != nil {
			return "", err
		}
		s.phantom = append(s.phantom, res.Phantom...)
		return res.Text, nil
	}
	v, err := transformJSONString(raw, "", plain)
	if err != nil {
		return raw
	}
	if out, ok := v.(string); ok {
		return out
	}
	return raw
}

// FlushToolCalls 放行流结束时仍未放行的工具调用。
// Releases tool calls still held when the stream ends.
//
// 上游可能没吐 finish_reason 就结束（截断、连接断开）。此时缓冲里压着的
// 是完整或半截的入参——半截的入参本身已经坏了，但仍要发出去，
// 因为吞掉它会让客户端永远等一个不会到来的工具调用。
//
// Upstream may end without a finish_reason (truncation, disconnect). Whatever
// is buffered must still be emitted: swallowing it leaves the client waiting
// forever for a tool call that never arrives.
func (s *StreamRestorer) FlushToolCalls(ctx context.Context) []byte {
	if len(s.toolArgs) == 0 {
		return nil
	}
	keys := make([]string, 0, len(s.toolArgs))
	for _, k := range s.toolOrder {
		if _, ok := s.toolArgs[k]; ok {
			keys = append(keys, k)
		}
	}
	return s.renderReleased(ctx, keys)
}

// Flush emits whatever remains in each buffer at end of stream.
// 在流结束时吐出各缓冲的残留。
//
// The return value is concatenated plain text. Callers should emit it as one
// extra delta frame — the hold-back buffer may still hold the tail half of a
// placeholder, and dropping it drops content.
// 返回的是拼接后的纯文本。调用方应把它作为一个额外的增量帧发出——
// 滞留缓冲里可能压着占位符的后半截，丢掉就是丢内容。
func (s *StreamRestorer) Flush(ctx context.Context) (string, error) {
	var b strings.Builder
	for _, buf := range s.buffers {
		text, err := buf.Flush(ctx)
		if err != nil {
			return "", err
		}
		b.WriteString(text)
		s.phantom = append(s.phantom, buf.Phantom()...)
	}
	return b.String(), nil
}

// Phantom 返回整条流中模型捏造的占位符。
func (s *StreamRestorer) Phantom() []string {
	out := append([]string(nil), s.phantom...)
	for _, buf := range s.buffers {
		out = append(out, buf.Phantom()...)
	}
	return out
}

// RestoreBody applies targeted restoration to a non-streaming response body.
// 对非流式响应体执行定向复原。
func RestoreBody(ctx context.Context, body []byte, redactor *anonymize.Redactor,
	scope anonymize.StrategyScope) []byte {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return body
	}
	err := RestoreDocument(doc, func(_, text string) (string, error) {
		res, err := redactor.Unredact(ctx, text, scope)
		if err != nil {
			return "", err
		}
		return res.Text, nil
	})
	if err != nil {
		return body
	}
	out, err := MarshalPreserving(doc)
	if err != nil {
		return body
	}
	return out
}

// joinKey 拼接结构路径，用作流式滞留缓冲的键。
// Joins a structural path, used as the streaming hold-back buffer's key.
func joinKey(prefix, seg string) string {
	if prefix == "" {
		return seg
	}
	return prefix + "." + seg
}

// elementID 返回数组元素在流式协议里的稳定身份。
// Returns an array element's stable identity in the streaming protocol.
//
// # 数组位置不是身份
// # Array position is not identity
//
// OpenAI 流式里 choices 与 tool_calls 的元素都带显式 index 字段，而每个
// delta 帧只携带发生变化的那几个元素。于是「第 1 个工具调用」在某一帧里
// 可能是数组的第 0 个元素——用数组位置做身份，两股文本流就会错位。
//
// 实测：首帧带调用 0 与调用 1（调用 1 的入参在占位符中间被切断），
// 次帧只带调用 1 的尾巴。按数组位置算，次帧那个元素落到调用 0 的滞留
// 缓冲上，占位符的两半被分到两个缓冲里，永远拼不回来——工具收到的是
// 字面量 "ME_0"，而另一半 "ANONYMIZED_NA" 挂在流末尾。全程不报错。
//
// 请求侧的 messages[*] 没有 index 字段，落回数组位置，这是对的：
// 请求体是完整文档而非增量分片，位置本身就是身份。
//
// In OpenAI streaming both choices and tool_calls elements carry an explicit
// index, and each delta frame carries only the elements that changed — so
// "tool call 1" can be array element 0 in a given frame. Keying by array
// position misaligns the streams.
//
// Measured: frame one carried calls 0 and 1 with call 1's arguments cut
// mid-placeholder; frame two carried only call 1's tail. By array position that
// element landed in call 0's buffer, splitting the placeholder across two
// buffers so it could never be rejoined — the tool received the literal "ME_0"
// while "ANONYMIZED_NA" dangled at end of stream. Nothing errored.
//
// Request-side messages[*] has no index field and falls back to position, which
// is correct: a request body is a whole document, not an incremental fragment,
// so position is identity.
func elementID(item any, pos int) string {
	obj, ok := item.(map[string]any)
	if !ok {
		return strconv.Itoa(pos)
	}
	// JSON 数字统一解码为 float64
	if n, ok := obj["index"].(float64); ok {
		return strconv.Itoa(int(n))
	}
	return strconv.Itoa(pos)
}

// FrameClass 是一个 SSE 数据帧携带的内容类别。
// The kind of payload an SSE data frame carries.
type FrameClass uint8

const (
	// FrameOther：既无正文也无工具调用（角色声明、usage、纯 finish_reason 等）
	FrameOther FrameClass = iota
	// FrameText：携带用户可见正文
	FrameText
	// FrameToolCall：只携带工具调用，用户看不到任何东西
	FrameToolCall
)

// ClassifyFrame 判断一个 SSE 数据帧携带的是正文还是工具调用。
// Classifies whether an SSE frame carries body text or a tool call.
//
// # 为什么这个区分值得单独算一次 JSON 解析
// # Why this distinction is worth one extra JSON parse
//
// TTFT 的含义是「用户多久看到第一个字」。工具调用帧里没有任何用户能看到
// 的东西——它是发给机器的载荷，客户端要等整个调用拼完才能动作。把两者
// 混进同一个平均值，指标会变成双峰分布：纯对话与工具调用轮的延迟性质
// 不同，均值落在两峰之间，既不描述任何一类，也无法用来定容量。
//
// 解析成本可以忽略：分类只在流的开头做，一旦定性就不再解析。
//
// TTFT means "how long until the user sees the first character". A tool-call
// frame contains nothing a user sees — it is a machine payload the client
// cannot act on until the whole call is assembled. Averaging both yields a
// bimodal metric whose mean describes neither population.
//
// The parse is negligible: classification runs only at the head of a stream and
// stops once the stream is characterized.
func ClassifyFrame(data []byte) FrameClass {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return FrameOther
	}
	choices, ok := doc["choices"].([]any)
	if !ok {
		return FrameOther
	}
	for _, c := range choices {
		choice, ok := c.(map[string]any)
		if !ok {
			continue
		}
		delta, ok := choice["delta"].(map[string]any)
		if !ok {
			continue
		}
		for _, f := range []string{"content", "reasoning_content", "text"} {
			if v, ok := delta[f].(string); ok && v != "" {
				return FrameText
			}
		}
		if calls, ok := delta["tool_calls"].([]any); ok && len(calls) > 0 {
			return FrameToolCall
		}
	}
	return FrameOther
}
