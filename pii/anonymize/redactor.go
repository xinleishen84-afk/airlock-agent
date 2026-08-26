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
	Text       string
	Entities   []detect.Entity
	TypeCounts map[string]int
}

// Redact replaces PII in the text with placeholders.
// 把文本中的 PII 替换为占位符。
//
// Entities are applied in offset order so that earlier offsets stay valid.
// 按偏移顺序处理，保证前面实体的偏移量不会失效。
func (r *Redactor) Redact(text string, vault *SessionVault) (RedactResult, error) {
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
	for _, e := range ordered {
		if e.Start < cursor {
			continue // should not happen after overlap resolution; defensive / 防御性跳过
		}
		b.WriteString(text[cursor:e.Start])
		b.WriteString(vault.PlaceholderFor(e))
		cursor = e.End
		counts[string(e.Type)]++
	}
	b.WriteString(text[cursor:])

	return RedactResult{Text: b.String(), Entities: entities, TypeCounts: counts}, nil
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
func (r *Redactor) Unredact(text string, vault *SessionVault) UnredactResult {
	if text == "" {
		return UnredactResult{Text: text}
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
		value, ok := vault.Resolve(token)
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
	return res
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
	vault    *SessionVault
	buffer   strings.Builder
	phantom  []string
}

// NewStreamUnredactor creates an incremental restorer for one stream.
// 为一条流创建增量复原器。
func NewStreamUnredactor(r *Redactor, vault *SessionVault) *StreamUnredactor {
	return &StreamUnredactor{redactor: r, vault: vault}
}

// Feed consumes one incremental chunk and returns the restored text that is
// safe to forward downstream.
// 吃进一个增量分片，返回可安全下发给业务端的已复原文本。
func (s *StreamUnredactor) Feed(chunk string) string {
	s.buffer.WriteString(chunk)
	buffered := s.buffer.String()

	safe, held := splitSafePrefix(buffered)
	s.buffer.Reset()
	s.buffer.WriteString(held)

	if safe == "" {
		return ""
	}
	res := s.redactor.Unredact(safe, s.vault)
	s.phantom = append(s.phantom, res.Phantom...)
	return res.Text
}

// Flush emits whatever remains in the hold-back buffer at end of stream.
// 在流结束时吐出缓冲残留。
func (s *StreamUnredactor) Flush() string {
	held := s.buffer.String()
	s.buffer.Reset()
	if held == "" {
		return ""
	}
	res := s.redactor.Unredact(held, s.vault)
	s.phantom = append(s.phantom, res.Phantom...)
	return res.Text
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
	const marker = PlaceholderPrefix // "ANONYMIZED_"

	searchFrom := 0
	if len(buf) > maxPlaceholderLen {
		searchFrom = len(buf) - maxPlaceholderLen
	}
	idx := strings.LastIndex(strings.ToUpper(buf[searchFrom:]), marker)

	if idx < 0 {
		// 也可能尾部正在拼 "ANONYM" 这样的半个前缀
		upper := strings.ToUpper(buf)
		for n := min(len(marker)-1, len(buf)); n > 0; n-- {
			if strings.HasSuffix(upper, marker[:n]) {
				return buf[:len(buf)-n], buf[len(buf)-n:]
			}
		}
		return buf, ""
	}

	abs := searchFrom + idx
	tail := buf[abs:]
	// A trailing non-identifier char means the placeholder is complete.
	// 已出现结束特征说明占位符是完整的
	if completePlaceholderRe.MatchString(tail) {
		return buf, ""
	}
	return buf[:abs], tail
}

// completePlaceholderRe tells whether a placeholder has fully appeared
// (followed by a non-identifier character).
// 判断一个占位符是否已完整出现（后面跟了非标识符字符）。
var completePlaceholderRe = regexp.MustCompile(`(?i)ANONYMIZED_[A-Z_]+_[0-9]+[^0-9A-Za-z_]`)
