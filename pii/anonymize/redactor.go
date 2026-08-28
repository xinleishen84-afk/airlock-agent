// Package anonymize replaces detected PII with lossless placeholders and
// restores them afterwards.
// 把检出的 PII 替换为无损占位符，并在之后还原。
//
// Unlike one-way anonymization, this is a round trip: redact before the request
// leaves your boundary, restore when the model's answer comes back. A
// SessionVault keeps the placeholder mapping stable across turns so the model
// can reason that "ANONYMIZED_NAME_0" is the same person throughout.
// 与单向匿名化不同，这是一次往返：请求出边界前脱敏，模型回答返回时复原。
// SessionVault 让占位符跨轮次保持稳定，模型才能推理出前后是同一个人。
//
// The mapping never leaves memory. SessionVault exposes no serialization
// method — once it reaches disk it stops being a redactor and becomes a PII
// database.
// 映射永不出内存。SessionVault 不提供任何序列化方法——
// 一旦落盘，它就不再是脱敏器，而成了 PII 数据库。
package anonymize

import (
	"context"
	"errors"
	"fmt"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"regexp"
	"sort"
	"strings"
)

// ErrRedactionFailed signals a redaction-pipeline failure. The default
// handling is fail-closed: block the request.
// 表示脱敏管道故障。默认按 fail-closed 处理，阻断请求。
var ErrRedactionFailed = errors.New("PII 脱敏失败")

// placeholderRe matches placeholders, tolerating the rewrites models commonly
// apply (case changes, wrapping in backticks or brackets).
// 匹配占位符，容忍模型的常见改写。
//
// The two alternatives are deliberate: written as "optional wrapper + \s*",
// the regex would also swallow the ordinary space *before* the placeholder,
// losing the original whitespace after restoration.
// 分成两个分支是刻意的：如果写成「可选包裹符 + \s*」，正则会连占位符
// 前面的普通空格一起吞掉，复原后原文的空白就丢了。
var placeholderRe = regexp.MustCompile(
	"(?i)" +
		"[`\\[\\{<【（(]\\s*(ANONYMIZED_[A-Z_]+?_[0-9]+)\\s*[`\\]\\}>】）)]" +
		"|(ANONYMIZED_[A-Z_]+?_[0-9]+)")

// Redactor performs bidirectional redaction.
// 是双向脱敏器。
type Redactor struct {
	detector   detect.Detector
	failClosed bool
	allowed    map[detect.EntityType]bool // nil 表示不限类型
	tokens     TokenStore                 // nil 表示不解析 [tok:...] 形态
}

// RedactorOption configures a Redactor at construction time.
// 在构造期配置 Redactor。
//
// Options rather than setters: a gateway shares one Redactor across every
// in-flight request, so a field mutated after start is a data race and, worse,
// a policy change that takes effect halfway through a stream.
// 用选项而非 setter：网关的所有在途请求共用同一个 Redactor，
// 启动后再改字段既是数据竞争，更是一次「在流式响应中途生效」的策略变更。
type RedactorOption func(*Redactor)

// WithRedactTypes limits redaction to the given entity types.
// 把脱敏限定在给定的实体类型上。
func WithRedactTypes(types ...detect.EntityType) RedactorOption {
	return func(r *Redactor) {
		if len(types) == 0 {
			return
		}
		r.allowed = make(map[detect.EntityType]bool, len(types))
		for _, t := range types {
			r.allowed[t] = true
		}
	}
}

// WithTokenStore lets Unredact resolve [tok:ns:token] values.
// 让 Unredact 能解析 [tok:ns:token] 形态。
//
// Required whenever a flow uses the tokenize operator: without it the tokens
// come back as phantoms and the end user is handed "[tok:email:9df3a0c1]"
// where an address belongs.
// 只要有链路使用令牌化算子就必须配置：否则令牌会被当成幻影，
// 终端用户会在本该是邮箱的位置拿到 "[tok:email:9df3a0c1]"。
func WithTokenStore(s TokenStore) RedactorOption {
	return func(r *Redactor) {
		if s == nil {
			return
		}
		r.tokens = s
	}
}

// NewRedactorWith builds a redactor from options.
// 用选项构造脱敏器。
func NewRedactorWith(detector detect.Detector, failClosed bool, opts ...RedactorOption) *Redactor {
	r := &Redactor{detector: detector, failClosed: failClosed}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// NewRedactor builds a redactor.
// 构造脱敏器。
//
// With failClosed=true a detector failure blocks the request instead of letting
// the raw text through — the only safe default for a redaction gateway.
// failClosed=true 时，检测器故障会阻断请求而非放行原文——
// 这是脱敏网关唯一安全的默认行为。
func NewRedactor(detector detect.Detector, failClosed bool, redactTypes ...detect.EntityType) *Redactor {
	r := &Redactor{detector: detector, failClosed: failClosed}
	if len(redactTypes) > 0 {
		r.allowed = make(map[detect.EntityType]bool, len(redactTypes))
		for _, t := range redactTypes {
			r.allowed[t] = true
		}
	}
	return r
}

// RedactResult is the outcome of one redaction pass.
// 是一次脱敏的结果。
type RedactResult struct {
	Text     string
	Entities []detect.Entity
	// TypeCounts 记录每种实体类型被处理了几次。
	TypeCounts map[string]int
	// StrategyCounts 记录每个算子被用了几次。
	//
	// 审计需要的是「本次请求里 3 个值走了 hash、1 个走了 drop」，
	// 而不只是「处理了 4 个 PII」——两次配置改动之间，后者完全一样。
	// Audit needs "3 values were hashed and 1 was dropped", not just "4 PII
	// handled": across a configuration change the latter reads identically.
	StrategyCounts map[string]int
}

// Redact replaces PII in the text with placeholders.
// 把文本中的 PII 替换为占位符。
//
// Entities are applied in offset order so that earlier offsets stay valid.
// 按偏移顺序处理，保证前面实体的偏移量不会失效。
func (r *Redactor) Redact(ctx context.Context, text string, scope StrategyScope) (RedactResult, error) {
	return r.RedactTo(ctx, text, scope, maskOnlyFlow)
}

// maskOnlyFlow is the policy Redact uses: placeholders for everything.
// 是 Redact 使用的策略：一律占位符。
var maskOnlyFlow = Flow{Name: "default", Default: NewMask(), Restores: true}

// DefaultMaskFlow returns the placeholder-only policy.
// 返回「一律占位符」的策略。
//
// This is what a deployment gets before it configures a matrix, and it is the
// safe default precisely because it is reversible: the restore path works, so
// nothing downstream breaks while the operator is still deciding.
// 这是部署方在配置矩阵之前得到的策略，而它之所以是安全的默认值，
// 恰恰因为它可逆：复原路径能工作，于是运维还在斟酌配置期间，下游不会坏。
func DefaultMaskFlow() Flow { return maskOnlyFlow }

// RedactTo redacts according to one flow's strategy matrix.
// 按某条链路的策略矩阵脱敏。
//
// Entities are applied in offset order so that earlier offsets stay valid.
// 按偏移顺序处理，保证前面实体的偏移量不会失效。
func (r *Redactor) RedactTo(ctx context.Context, text string, scope StrategyScope, flow Flow) (RedactResult, error) {
	if flow.Default == nil {
		return RedactResult{}, fmt.Errorf("%w: 链路 %q 没有默认算子 / flow %q has no default strategy",
			ErrRedactionFailed, flow.Name, flow.Name)
	}
	if text == "" {
		return RedactResult{Text: text}, nil
	}

	entities, err := r.detector.Detect(text)
	if err != nil {
		if r.failClosed {
			// If it cannot be detected, it must not leave. / 检测不了就不许出站
			return RedactResult{}, fmt.Errorf("%w: 按 fail-closed 阻断出站请求: %v", ErrRedactionFailed, err)
		}
		// fail-open 是显式选择，必须留下痕迹供审计追责
		return RedactResult{Text: text}, fmt.Errorf("%w(已放行原文，存在泄露风险): %v", ErrRedactionFailed, err)
	}

	if r.allowed != nil {
		filtered := entities[:0:0]
		for _, e := range entities {
			if r.allowed[e.Type] {
				filtered = append(filtered, e)
			}
		}
		entities = filtered
	}
	if len(entities) == 0 {
		return RedactResult{Text: text}, nil
	}

	// 按起点升序单遍重建：Python 版是「从后往前原地替换」以免偏移失效，
	// Go 里用 Builder 正序拼接更直接，也省掉一次字符串拷贝。
	ordered := make([]detect.Entity, len(entities))
	copy(ordered, entities)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Start < ordered[j].Start })

	var b strings.Builder
	b.Grow(len(text))
	cursor := 0
	counts := make(map[string]int)
	stratCounts := make(map[string]int)
	for _, e := range ordered {
		if e.Start < cursor {
			// 重叠实体一律阻断，绝不跳过。
			//
			// 曾经这里是 continue，注释写着「重叠消解之后不该发生，防御性跳过」。
			// 它确实不该发生，但一旦发生，后果是**半截 PII 原样出境**：
			// 实测「客户张伟的手机是 13812345678」在两个重叠实体下产出
			// 「客户ANONYMIZED_ADDRESS_0345678」——手机号的尾巴留在了原文里，
			// 而 TypeCounts 显示 {ADDRESS:1}，没有任何迹象表明跳过了什么。
			//
			// 「不该发生」不是不处理的理由。上游的重叠消解有 bug、
			// 或调用方传了一个不做消解的自定义检测器，都会到这里，
			// 而静默跳过让这两种情况都表现为「脱敏成功了」。
			//
			// This used to be a continue, commented "should not happen after
			// overlap resolution". It should not — but when it does, half a PII
			// value leaves verbatim: measured, two overlapping entities turned
			// 客户张伟的手机是 13812345678 into 客户ANONYMIZED_ADDRESS_0345678,
			// with the phone number's tail intact and TypeCounts reading
			// {ADDRESS:1}, showing nothing was skipped.
			//
			// "Should not happen" is not a reason to leave it unhandled: a bug
			// in overlap resolution and a caller-supplied detector that does no
			// resolution both land here, and a silent skip makes both look like
			// a successful redaction.
			// 报错里必须同时有「是谁」与「怎么修」。
			//
			// 上一版只留了「怎么修」，把检测器名字删掉了——而收到这条报错的人
			// 第一个要问的就是「哪个检测器」。是测试把它抓回来的。
			//
			// Both "which" and "how to fix": an earlier version kept only the
			// fix and dropped the detector name, which is the first thing
			// anyone receiving this error needs.
			fix := fmt.Sprintf("检测器 %q 未做重叠消解", e.Detector)
			if d, ok := r.detector.(interface{ DefersOverlapResolution() bool }); ok &&
				d.DefersOverlapResolution() {
				// 这是最常见的成因，值得单独说清楚修法。
				// The most common cause; worth naming the fix precisely.
				fix = fmt.Sprintf("检测器 %q 来自刻意延后重叠消解的装配"+
					"（NewCompositeDetectorDeferred），", e.Detector) +
					"它产出的是候选不是判决——必须先过证据链验证器" +
					"（verify.EvidenceValidator.ValidateAll）再送来脱敏。" +
					"sidecar 用 Options.Evidence 接它"
			}
			return RedactResult{}, fmt.Errorf(
				"%w: 检测结果存在重叠区间——实体 %s [%d,%d) 与前一个实体重叠"+
					"（前一个结束于 %d）。继续处理会让重叠部分之外的 PII 原样出境，"+
					"因此阻断。%s / overlapping spans",
				ErrRedactionFailed, e.Type, e.Start, e.End, cursor, fix)
		}
		strategy := flow.Strategy(e.Type)
		replacement, err := strategy.Apply(ctx, scope, e)
		if err != nil {
			// 算子失败一律阻断，不受 fail_closed 影响：fail_closed 说的是
			// 「检测器不可用时怎么办」，而算子失败意味着这个已经检出的 PII
			// 没能被处理。放行它等同于明知有 PII 仍原样送出。
			// A strategy failure always blocks, regardless of fail_closed:
			// that setting is about an unavailable detector, whereas this is a
			// PII value already found and not handled. Letting it through is
			// shipping known PII verbatim.
			return RedactResult{}, fmt.Errorf(
				"%w: 链路 %q 的 %s 算子处理 %s 失败: %v",
				ErrRedactionFailed, flow.Name, strategy.Name(), e.Type, err)
		}
		b.WriteString(text[cursor:e.Start])
		b.WriteString(replacement)
		cursor = e.End
		counts[string(e.Type)]++
		stratCounts[strategy.Name()]++
	}
	b.WriteString(text[cursor:])

	return RedactResult{
		Text: b.String(), Entities: entities,
		TypeCounts: counts, StrategyCounts: stratCounts,
	}, nil
}

// UnredactResult is the outcome of one restoration pass.
// 是一次复原的结果。
type UnredactResult struct {
	Text     string
	Restored int
	// Phantom 是模型凭空捏造、无法还原的占位符，属于需要告警的信号
	Phantom []string
}

// Unredact turns placeholders back into real values.
// 把占位符还原为真实值。
//
// Tolerates the rewrites models commonly apply (case, backticks, brackets).
// Placeholders that cannot be resolved are kept verbatim and recorded —
// never guessed at.
// 容忍模型对占位符的常见改写（大小写、反引号或方括号包裹）。
// 还原不了的占位符原样保留并记录——绝不猜测。
func (r *Redactor) Unredact(ctx context.Context, text string, scope StrategyScope) (UnredactResult, error) {
	if text == "" {
		return UnredactResult{Text: text}, nil
	}
	if scope.Vault == nil {
		return UnredactResult{}, fmt.Errorf("复原需要会话保险库 / restore requires a session vault")
	}

	res := UnredactResult{}
	var b strings.Builder
	b.Grow(len(text))
	cursor := 0

	for _, m := range placeholderRe.FindAllStringSubmatchIndex(text, -1) {
		// 两个分支只会命中其一：group 1 为带包裹符的，group 2 为裸露的
		start, end := m[2], m[3]
		if start < 0 {
			start, end = m[4], m[5]
		}
		if start < 0 {
			continue
		}
		token := strings.ToUpper(text[start:end])
		value, ok := scope.Vault.Resolve(token)
		if !ok {
			res.Phantom = append(res.Phantom, token)
			continue // 原样保留：不改写 cursor，整段匹配随后续拷贝原样输出
		}
		b.WriteString(text[cursor:m[0]])
		b.WriteString(value)
		cursor = m[1]
		res.Restored++
	}
	b.WriteString(text[cursor:])
	res.Text = b.String()

	if r.tokens != nil {
		if err := r.unredactTokens(ctx, scope, &res); err != nil {
			// 存储故障绝不能长得像「令牌不存在」：前者可重试，
			// 后者说明模型编造了令牌。把两者混为一谈，
			// 会让一次故障看起来像一次幻觉，并同时掩盖两者。
			// A store failure must never look like "token not found": the
			// first is retryable, the second means the model invented it.
			return UnredactResult{}, err
		}
	}
	return res, nil
}

// tokenRe matches a tokenize-operator output.
// 匹配令牌化算子的输出。
// tokenNamespaceRe 单独暴露 tokenRe 的命名空间部分，供一致性测试比对。
// Exposes tokenRe's namespace component so the charset can be cross-checked.
var tokenNamespaceRe = regexp.MustCompile(`^[a-z0-9_]+$`)

var tokenRe = regexp.MustCompile(`\[tok:([a-z0-9_]+):([0-9a-fA-F]{8,64})\]`)

// completeTokenRe tells whether a token has fully appeared.
// 判断一个令牌是否已完整出现。
var completeTokenRe = regexp.MustCompile(`\[tok:[a-z0-9_]+:[0-9a-fA-F]{8,64}\]`)

// unredactTokens resolves [tok:ns:token] values in place.
// 就地解析 [tok:ns:token]。
//
// Unresolvable tokens are recorded as phantoms and left verbatim, exactly like
// placeholders. A model that invents a plausible-looking token must not cause
// the gateway to invent a plausible-looking person.
// 解析不了的令牌与占位符一样，记为幻影并原样保留。
// 模型凭空造出一个像模像样的令牌，不能让网关跟着造出一个像模像样的人。
func (r *Redactor) unredactTokens(ctx context.Context, scope StrategyScope, res *UnredactResult) error {
	text := res.Text
	if !strings.Contains(text, "[tok:") {
		return nil
	}

	var b strings.Builder
	b.Grow(len(text))
	cursor := 0
	for _, m := range tokenRe.FindAllStringSubmatchIndex(text, -1) {
		ns := text[m[2]:m[3]]
		tok := strings.ToLower(text[m[4]:m[5]])
		value, ok, err := r.tokens.Resolve(ctx, TokenKey{Tenant: scope.Tenant, Namespace: ns}, tok)
		if err != nil {
			return err
		}
		if !ok {
			res.Phantom = append(res.Phantom, text[m[0]:m[1]])
			continue
		}
		b.WriteString(text[cursor:m[0]])
		b.WriteString(value)
		cursor = m[1]
		res.Restored++
	}
	b.WriteString(text[cursor:])
	res.Text = b.String()
	return nil
}

// ---------------------------------------------------------------------------
// Streaming restoration / 流式复原
// ---------------------------------------------------------------------------

// maxPlaceholderLen is the longest a placeholder can be; used to decide how
// much of the streaming buffer must be held back.
// 是占位符的最长可能长度，用于流式缓冲的滞留判定。
const maxPlaceholderLen = 64

// StreamUnredactor restores placeholders incrementally across an SSE stream.
// 对 SSE 流做增量复原。
//
// The inherent difficulty: a placeholder can be split across two chunks
// ("ANONYMIZED_NA" + "ME_0"). This is solved with a hold-back buffer — only the
// prefix that provably contains no partial placeholder is emitted; the rest
// waits for the next chunk.
// 流式复原的固有难题：一个占位符可能被切分到两个 chunk 里
// （"ANONYMIZED_NA" + "ME_0"）。此处用滞留缓冲解决——
// 只输出确定不含半个占位符的前缀，其余留到下一个 chunk 再判定。
//
// Not safe for concurrent use: one stream is owned by one goroutine.
// 本类型非并发安全：一条流由一个 goroutine 独占处理。
type StreamUnredactor struct {
	redactor *Redactor
	scope    StrategyScope
	buffer   strings.Builder
	phantom  []string
}

// NewStreamUnredactor creates an incremental restorer for one stream.
// 为一条流创建增量复原器。
func NewStreamUnredactor(r *Redactor, scope StrategyScope) *StreamUnredactor {
	return &StreamUnredactor{redactor: r, scope: scope}
}

// Feed consumes one incremental chunk and returns the restored text that is
// safe to forward downstream.
// 吃进一个增量分片，返回可安全下发给业务端的已复原文本。
func (s *StreamUnredactor) Feed(ctx context.Context, chunk string) (string, error) {
	s.buffer.WriteString(chunk)
	buffered := s.buffer.String()

	safe, held := splitSafePrefix(buffered)
	s.buffer.Reset()
	s.buffer.WriteString(held)

	if safe == "" {
		return "", nil
	}
	res, err := s.redactor.Unredact(ctx, safe, s.scope)
	if err != nil {
		// 令牌库故障时不得下发这一片：半复原的分片已经把令牌泄露给了
		// 终端用户，而它本该是被还原掉的那个值。
		// A store failure must not emit the chunk: a half-restored chunk has
		// already handed the token to the end user in place of the value.
		return "", err
	}
	s.phantom = append(s.phantom, res.Phantom...)
	return res.Text, nil
}

// Flush emits whatever remains in the hold-back buffer at end of stream.
// 在流结束时吐出缓冲残留。
func (s *StreamUnredactor) Flush(ctx context.Context) (string, error) {
	held := s.buffer.String()
	s.buffer.Reset()
	if held == "" {
		return "", nil
	}
	res, err := s.redactor.Unredact(ctx, held, s.scope)
	if err != nil {
		return "", err
	}
	s.phantom = append(s.phantom, res.Phantom...)
	return res.Text, nil
}

// Phantom returns the placeholders the model invented across the whole stream.
// 返回整条流中出现的、模型捏造的占位符。
func (s *StreamUnredactor) Phantom() []string { return s.phantom }

// splitSafePrefix splits the buffer into "safe to emit" and "must hold back".
// 把缓冲拆成「可安全输出的前缀」与「需滞留的尾部」。
//
// If the tail could be half a placeholder (any proper prefix of ANONYMIZED),
// it must wait for the next chunk — otherwise a placeholder would be emitted
// split in two.
// 尾部只要可能是半个占位符（含 ANONYMIZED 前缀的任意真前缀），
// 就必须留到下一个分片再判定，否则占位符会被拆开输出给用户。
func splitSafePrefix(buf string) (safe, held string) {
	// 两种可复原构造都要滞留，取更靠前的切点。
	//
	// 只认 "ANONYMIZED_" 会让一个被帧边界切开的 [tok:email:9df3a0c1]
	// 前半截直接发给终端用户——既泄露了令牌，也让剩下的半截永远还原不了。
	// Holding back only "ANONYMIZED_" lets the first half of a frame-split
	// [tok:email:9df3a0c1] reach the end user: the token leaks and the
	// remainder can never be restored.
	cut := len(buf)
	if c := holdPoint(buf, PlaceholderPrefix, completePlaceholderRe); c < cut {
		cut = c
	}
	if c := holdPoint(buf, tokenPrefix, completeTokenRe); c < cut {
		cut = c
	}
	return buf[:cut], buf[cut:]
}

// tokenPrefix is the literal that opens a tokenize-operator output.
// 是令牌化算子输出的起始字面量。
const tokenPrefix = "[tok:"

// holdPoint returns the offset from which the buffer must be held back for one
// marker, or len(buf) if nothing is pending.
// 返回针对某个标记必须开始滞留的偏移；没有待完成构造时返回 len(buf)。
func holdPoint(buf, marker string, complete *regexp.Regexp) int {
	searchFrom := 0
	if len(buf) > maxPlaceholderLen {
		searchFrom = len(buf) - maxPlaceholderLen
	}
	idx := strings.LastIndex(strings.ToUpper(buf[searchFrom:]), strings.ToUpper(marker))

	if idx < 0 {
		// 也可能尾部正在拼 "ANONYM" 或 "[to" 这样的半个前缀
		upper := strings.ToUpper(buf)
		for n := min(len(marker)-1, len(buf)); n > 0; n-- {
			if strings.HasSuffix(upper, strings.ToUpper(marker[:n])) {
				return len(buf) - n
			}
		}
		return len(buf)
	}

	abs := searchFrom + idx
	// A trailing non-identifier char means the construct is complete.
	// 已出现结束特征说明构造是完整的
	if complete.MatchString(buf[abs:]) {
		return len(buf)
	}
	return abs
}

// completePlaceholderRe tells whether a placeholder has fully appeared
// (followed by a non-identifier character).
// 判断一个占位符是否已完整出现（后面跟了非标识符字符）。
var completePlaceholderRe = regexp.MustCompile(`(?i)ANONYMIZED_[A-Z_]+_[0-9]+[^0-9A-Za-z_]`)
