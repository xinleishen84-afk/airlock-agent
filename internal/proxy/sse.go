// Package proxy 实现全链路 SSE 流式代理。
//
// # 为什么必须全链路流式
//
// LLM 动辄数秒的生成延迟决定了阻塞式请求-响应模型不可行：连接与内存
// 会大量挂起。全链路 SSE 让 token 像涓涓细流实时抵达客户端，
// 把感知延迟（TTFT）从「等完整响应」压到「等第一个 token」。
//
// # 「流税」从哪来
//
// 代理插在中间必然带来额外开销，主要有四处，本包逐一消除：
//
//  1. 缓冲——任何一层缓冲都会把流式退化成批式。upstream 关压缩、
//     下游每帧 Flush、Transport 不设 ResponseHeaderTimeout 之外的缓冲。
//  2. 分配——每帧一次 []byte/string 转换，在万级并发下是 GC 灾难。
//     用 sync.Pool 复用缓冲，扫描阶段全程 []byte 不转 string。
//  3. 写超时——服务端全局 WriteTimeout 会掐断长流，这是最常见的
//     SSE 线上事故。必须逐连接解除写截止时间。
//  4. 调度——见 cpulimit 包处理的 CFS 限流。
package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
)

// SSE 协议的字段前缀。见 W3C EventSource 规范。
var (
	fieldData     = []byte("data:")
	fieldEvent    = []byte("event:")
	fieldID       = []byte("id:")
	fieldRetry    = []byte("retry:")
	commentPrefix = []byte(":")
)

// doneMarker 是 OpenAI 兼容流的结束哨兵。
var doneMarker = []byte("[DONE]")

// Event 是一个已解析的 SSE 事件。
//
// Data 字段直接引用底层读缓冲，**仅在下一次 Next 调用前有效**。
// 需要跨事件保留时必须自行拷贝——这是为了避免每帧一次分配所付出的代价，
// 在万级并发下这个取舍很关键。
type Event struct {
	Event []byte
	ID    []byte
	Data  []byte
	Retry []byte
	// Comment 为 true 表示这是一条注释帧（心跳），无需转发给业务逻辑，
	// 但**必须原样转发给客户端**——它是保活信号。
	Comment bool
}

// IsDone 判断是否为 OpenAI 兼容流的结束标记。
func (e *Event) IsDone() bool {
	return bytes.Equal(bytes.TrimSpace(e.Data), doneMarker)
}

// ErrEventTooLarge 表示单个 SSE 事件超过了缓冲上限。
// 这通常意味着上游不是合法 SSE 流（比如返回了一个巨大的 JSON 错误体）。
var ErrEventTooLarge = errors.New("SSE 事件超过缓冲上限")

// Scanner 是流式 SSE 解析器。
//
// 逐行读取并按空行切分事件，全程操作 []byte 不做 string 转换——
// 每帧一次 string() 在高并发下就是每秒数十万次分配。
type Scanner struct {
	reader  *bufio.Reader
	event   Event
	dataBuf []byte // 累积多行 data:，跨事件复用
	err     error
	maxSize int
}

// DefaultMaxEventSize 是单事件缓冲上限。
// LLM 的单个 chunk 通常几百字节，1MB 足够容纳异常大的工具调用参数。
const DefaultMaxEventSize = 1 << 20

// NewScanner 创建 SSE 解析器。bufSize 为底层读缓冲大小。
func NewScanner(r io.Reader, bufSize, maxEventSize int) *Scanner {
	if bufSize <= 0 {
		bufSize = 16 << 10
	}
	if maxEventSize <= 0 {
		maxEventSize = DefaultMaxEventSize
	}
	return &Scanner{
		reader:  bufio.NewReaderSize(r, bufSize),
		dataBuf: make([]byte, 0, 4096),
		maxSize: maxEventSize,
	}
}

// Next 读取下一个完整事件。返回 false 表示流结束或出错，用 Err 区分。
func (s *Scanner) Next() bool {
	if s.err != nil {
		return false
	}

	s.event = Event{}
	s.dataBuf = s.dataBuf[:0]
	hasField := false

	for {
		line, err := s.readLine()
		if err != nil {
			if err == io.EOF && hasField {
				// 流在事件边界外结束：把已读到的部分作为最后一个事件吐出
				s.err = io.EOF
				s.finishEvent()
				return true
			}
			s.err = err
			return false
		}

		// 空行 = 事件结束
		if len(line) == 0 {
			if !hasField {
				continue // 连续空行，跳过
			}
			s.finishEvent()
			return true
		}

		hasField = true
		if bytes.HasPrefix(line, commentPrefix) && !bytes.HasPrefix(line, fieldData) {
			// 注释帧（如 ": keep-alive"）是保活心跳，必须原样透传
			s.event.Comment = true
			s.event.Data = append(s.dataBuf[:0], line...)
			s.dataBuf = s.event.Data
			continue
		}

		switch {
		case bytes.HasPrefix(line, fieldData):
			value := trimFieldValue(line[len(fieldData):])
			if len(s.dataBuf) > 0 {
				// 多行 data: 按规范用 \n 连接
				s.dataBuf = append(s.dataBuf, '\n')
			}
			if len(s.dataBuf)+len(value) > s.maxSize {
				s.err = fmt.Errorf("%w: 已累积 %d 字节", ErrEventTooLarge, len(s.dataBuf))
				return false
			}
			s.dataBuf = append(s.dataBuf, value...)
		case bytes.HasPrefix(line, fieldEvent):
			s.event.Event = trimFieldValue(line[len(fieldEvent):])
		case bytes.HasPrefix(line, fieldID):
			s.event.ID = trimFieldValue(line[len(fieldID):])
		case bytes.HasPrefix(line, fieldRetry):
			s.event.Retry = trimFieldValue(line[len(fieldRetry):])
		}
	}
}

// finishEvent 把累积的 data 装配进当前事件。
func (s *Scanner) finishEvent() {
	if !s.event.Comment {
		s.event.Data = s.dataBuf
	}
}

// Event 返回当前事件。其中的切片在下次 Next 前有效。
func (s *Scanner) Event() *Event { return &s.event }

// Err 返回终止原因。流正常结束时为 io.EOF。
func (s *Scanner) Err() error { return s.err }

// readLine 读取一行并剥掉行尾的 \r\n 或 \n。
//
// 用 ReadSlice 而非 ReadString：前者返回底层缓冲的切片，零分配；
// 只在遇到超长行（缓冲装不下）时才回退到累积模式。
func (s *Scanner) readLine() ([]byte, error) {
	line, err := s.reader.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		// 超长行：退化为累积读取。正常 LLM chunk 不会走到这里。
		buf := append([]byte(nil), line...)
		for err == bufio.ErrBufferFull {
			if len(buf) > s.maxSize {
				return nil, fmt.Errorf("%w: 单行超过 %d 字节", ErrEventTooLarge, s.maxSize)
			}
			line, err = s.reader.ReadSlice('\n')
			buf = append(buf, line...)
		}
		if err != nil && err != io.EOF {
			return nil, err
		}
		return trimEOL(buf), nil
	}
	if err != nil {
		if err == io.EOF && len(line) > 0 {
			return trimEOL(line), nil
		}
		return nil, err
	}
	return trimEOL(line), nil
}

// trimEOL 剥掉行尾的 \n 与可选的 \r。
func trimEOL(line []byte) []byte {
	line = bytes.TrimSuffix(line, []byte("\n"))
	return bytes.TrimSuffix(line, []byte("\r"))
}

// trimFieldValue 剥掉字段值前的单个可选空格（SSE 规范要求）。
func trimFieldValue(v []byte) []byte {
	if len(v) > 0 && v[0] == ' ' {
		return v[1:]
	}
	return v
}

// ---------------------------------------------------------------------------
// 事件写出
// ---------------------------------------------------------------------------

// WriteEvent 把一个事件按 SSE 格式写出。
//
// 直接写入 io.Writer 而不经过 fmt.Fprintf：后者会走反射与分配，
// 在每秒数十万帧的量级上是纯粹的浪费。
func WriteEvent(w io.Writer, e *Event) error {
	if e.Comment {
		if _, err := w.Write(e.Data); err != nil {
			return err
		}
		_, err := w.Write([]byte("\n\n"))
		return err
	}

	if len(e.Event) > 0 {
		if err := writeField(w, fieldEvent, e.Event); err != nil {
			return err
		}
	}
	if len(e.ID) > 0 {
		if err := writeField(w, fieldID, e.ID); err != nil {
			return err
		}
	}
	if len(e.Retry) > 0 {
		if err := writeField(w, fieldRetry, e.Retry); err != nil {
			return err
		}
	}
	// data 可能含换行，按规范逐行加前缀
	for _, line := range bytes.Split(e.Data, []byte("\n")) {
		if err := writeField(w, fieldData, line); err != nil {
			return err
		}
	}
	_, err := w.Write([]byte("\n"))
	return err
}

// writeField 写出一个 "name: value\n" 字段。
func writeField(w io.Writer, name, value []byte) error {
	if _, err := w.Write(name); err != nil {
		return err
	}
	if _, err := w.Write([]byte(" ")); err != nil {
		return err
	}
	if _, err := w.Write(value); err != nil {
		return err
	}
	_, err := w.Write([]byte("\n"))
	return err
}

// WriteDone 写出 OpenAI 兼容流的结束标记。
func WriteDone(w io.Writer) error {
	_, err := w.Write([]byte("data: [DONE]\n\n"))
	return err
}
