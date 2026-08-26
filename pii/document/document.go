package document

import (
	"encoding/json"
	"fmt"
	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
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
type textTransform func(string) (string, error)

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
		if err := walk(doc, r.path, r.kind, transform); err != nil {
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
func walk(node any, path []segment, kind valueKind, transform textTransform) error {
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
		if len(rest) == 0 {
			// 到达叶子：这是唯一会调用 transform 的地方
			newVal, err := applyTransform(child, kind, transform)
			if err != nil {
				return err
			}
			obj[current.name] = newVal
			return nil
		}
		return walk(child, rest, kind, transform)

	case segIndex:
		arr, ok := node.([]any)
		if !ok {
			return nil
		}
		for i, item := range arr {
			if len(rest) == 0 {
				newVal, err := applyTransform(item, kind, transform)
				if err != nil {
					return err
				}
				arr[i] = newVal
				continue
			}
			if err := walk(item, rest, kind, transform); err != nil {
				return err
			}
		}
		return nil

	case segDeepAny:
		// 任意深度下探，但**只在剩余路径匹配时才净化**。
		// 用于 JSON Schema 里任意嵌套层级的 description 字段。
		return walkDeep(node, rest, kind, transform)
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
func walkDeep(node any, rest []segment, kind valueKind, transform textTransform) error {
	switch n := node.(type) {
	case map[string]any:
		// Try to match at this level. / 在本层尝试匹配
		if err := walk(n, rest, kind, transform); err != nil {
			return err
		}
		// 继续下探。注意：不能对已匹配的键再下探，否则
		// description 里若恰好是个对象会被重复处理
		for k, v := range n {
			if len(rest) > 0 && rest[0].kind == segKey && rest[0].name == k {
				continue
			}
			if err := walkDeep(v, rest, kind, transform); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range n {
			if err := walkDeep(item, rest, kind, transform); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyTransform sanitizes according to the value kind.
// 按值类型执行净化。
func applyTransform(value any, kind valueKind, transform textTransform) (any, error) {
	s, ok := value.(string)
	if !ok {
		return value, nil // type mismatch: rule does not apply / 类型不符，规则不适用
	}

	switch kind {
	case kindText:
		return transform(s)

	case kindJSONString:
		return transformJSONString(s, transform)
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
func transformJSONString(raw string, transform textTransform) (any, error) {
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return raw, nil
	}

	sanitized, err := transformJSONValue(parsed, transform)
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
func transformJSONValue(value any, transform textTransform) (any, error) {
	switch v := value.(type) {
	case string:
		return transform(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			// 键名是 schema 定义的参数名，属于协议骨架，绝不净化
			r, err := transformJSONValue(item, transform)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			r, err := transformJSONValue(item, transform)
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
	{
		path: seg("choices", "[*]", "delta", "tool_calls", "[*]", "function", "arguments"),
		kind: kindText,
		desc: "流式工具入参片段——是不完整的 JSON 分片，按纯文本处理",
	},
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
}

// RestoreDocument applies targeted restoration to a parsed response document.
// 对已解析的响应文档执行定向复原。
func RestoreDocument(doc map[string]any, transform textTransform) error {
	for _, r := range responseRules {
		if err := walk(doc, r.path, r.kind, transform); err != nil {
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
	vault    *anonymize.SessionVault
	buffers  map[string]*anonymize.StreamUnredactor
	phantom  []string
}

// NewStreamRestorer creates a restorer for one stream.
// 为一条流创建复原器。
func NewStreamRestorer(r *anonymize.Redactor, vault *anonymize.SessionVault) *StreamRestorer {
	return &StreamRestorer{
		redactor: r,
		vault:    vault,
		buffers:  make(map[string]*anonymize.StreamUnredactor, 2),
	}
}

// Frame restores one SSE data frame and returns the new frame content.
// 复原一个 SSE 数据帧，返回新的帧内容。
//
// A frame that does not parse as JSON is returned verbatim: upstream may emit
// non-JSON heartbeats or error text, and doing nothing is safer than guessing.
// 帧无法解析为 JSON 时原样返回：上游可能吐出非 JSON 的心跳或错误文本，
// 此时不做任何替换比猜测更安全。
func (s *StreamRestorer) Frame(data []byte) []byte {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return data
	}

	// 用路径标识区分不同的文本流。这里用规则描述作为键，
	// 同一条规则下的所有实例共用一个缓冲——单条流里
	// 同时出现多个 choice 或多个并行工具调用的情形极少，
	// 真出现时最坏结果只是滞留缓冲多滞留一帧。
	idx := 0
	err := RestoreDocument(doc, func(text string) (string, error) {
		key := s.keyFor(idx)
		idx++
		buf, ok := s.buffers[key]
		if !ok {
			buf = anonymize.NewStreamUnredactor(s.redactor, s.vault)
			s.buffers[key] = buf
		}
		return buf.Feed(text), nil
	})
	if err != nil {
		return data
	}

	out, err := MarshalPreserving(doc)
	if err != nil {
		// 序列化失败时退回原帧，绝不产出半截 JSON
		return data
	}
	return out
}

// Flush emits whatever remains in each buffer at end of stream.
// 在流结束时吐出各缓冲的残留。
//
// The return value is concatenated plain text. Callers should emit it as one
// extra delta frame — the hold-back buffer may still hold the tail half of a
// placeholder, and dropping it drops content.
// 返回的是拼接后的纯文本。调用方应把它作为一个额外的增量帧发出——
// 滞留缓冲里可能压着占位符的后半截，丢掉就是丢内容。
func (s *StreamRestorer) Flush() string {
	var b strings.Builder
	for _, buf := range s.buffers {
		b.WriteString(buf.Flush())
		s.phantom = append(s.phantom, buf.Phantom()...)
	}
	return b.String()
}

// Phantom 返回整条流中模型捏造的占位符。
func (s *StreamRestorer) Phantom() []string {
	out := append([]string(nil), s.phantom...)
	for _, buf := range s.buffers {
		out = append(out, buf.Phantom()...)
	}
	return out
}

// keyFor 生成滞留缓冲的键。
func (s *StreamRestorer) keyFor(index int) string {
	// The Nth restorable field within a frame. The same position across
	// frames belongs to the same text stream.
	// 单帧内的第 N 个可复原字段。同一位置在各帧间是同一股文本流。
	return "f" + string(rune('0'+index%10))
}

// RestoreBody applies targeted restoration to a non-streaming response body.
// 对非流式响应体执行定向复原。
func RestoreBody(body []byte, redactor *anonymize.Redactor, vault *anonymize.SessionVault) []byte {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return body
	}
	err := RestoreDocument(doc, func(text string) (string, error) {
		return redactor.Unredact(text, vault).Text, nil
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
