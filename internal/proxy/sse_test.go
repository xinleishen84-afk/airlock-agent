package proxy

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

// collect 把整条流解析成事件切片（拷贝 Data，因为底层缓冲会被复用）。
func collect(t *testing.T, raw string) ([]Event, error) {
	t.Helper()
	s := NewScanner(strings.NewReader(raw), 0, 0)
	var out []Event
	for s.Next() {
		e := *s.Event()
		e.Data = append([]byte(nil), e.Data...)
		e.Event = append([]byte(nil), e.Event...)
		e.ID = append([]byte(nil), e.ID...)
		out = append(out, e)
	}
	if err := s.Err(); err != nil && !errors.Is(err, io.EOF) {
		return out, err
	}
	return out, nil
}

// TestScanBasicStream 校验典型的 OpenAI 兼容流解析。
func TestScanBasicStream(t *testing.T) {
	raw := "data: {\"delta\":\"你\"}\n\n" +
		"data: {\"delta\":\"好\"}\n\n" +
		"data: [DONE]\n\n"
	events, err := collect(t, raw)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("应解析出 3 个事件，实际 %d: %+v", len(events), events)
	}
	if string(events[0].Data) != `{"delta":"你"}` {
		t.Errorf("首帧数据错误: %q", events[0].Data)
	}
	if !events[2].IsDone() {
		t.Error("末帧应识别为 [DONE]")
	}
}

// TestScanFieldVariants 校验各类字段与可选空格。
func TestScanFieldVariants(t *testing.T) {
	raw := "event: message\nid: 42\nretry: 3000\ndata: hello\n\n" +
		"data:no-space\n\n" // 冒号后无空格也合法
	events, err := collect(t, raw)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if string(events[0].Event) != "message" || string(events[0].ID) != "42" ||
		string(events[0].Data) != "hello" {
		t.Errorf("字段解析错误: %+v", events[0])
	}
	if string(events[1].Data) != "no-space" {
		t.Errorf("无空格形式解析错误: %q", events[1].Data)
	}
}

// TestScanMultilineData 校验多行 data 按规范用 \n 连接。
func TestScanMultilineData(t *testing.T) {
	events, err := collect(t, "data: line1\ndata: line2\ndata: line3\n\n")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if string(events[0].Data) != "line1\nline2\nline3" {
		t.Errorf("多行拼接错误: %q", events[0].Data)
	}
}

// TestScanCommentIsHeartbeat 校验注释帧被识别为心跳。
// 心跳必须原样转发给客户端——它是保活信号，吞掉会导致中间设备断连。
func TestScanCommentIsHeartbeat(t *testing.T) {
	events, err := collect(t, ": keep-alive\n\ndata: real\n\n")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(events) != 2 || !events[0].Comment {
		t.Fatalf("首帧应为注释帧: %+v", events)
	}
	if events[1].Comment {
		t.Error("数据帧不应被判为注释")
	}
}

// TestScanCRLF 校验 \r\n 行尾（部分上游会用）。
func TestScanCRLF(t *testing.T) {
	events, err := collect(t, "data: hello\r\n\r\ndata: world\r\n\r\n")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(events) != 2 || string(events[0].Data) != "hello" {
		t.Errorf("CRLF 解析错误: %+v", events)
	}
}

// TestScanUnterminatedFinalEvent 校验流在事件边界外结束时不丢最后一帧。
// 上游异常断开时最后一个 chunk 常常没有收尾空行，丢掉它等于丢内容。
func TestScanUnterminatedFinalEvent(t *testing.T) {
	events, err := collect(t, "data: complete\n\ndata: truncated")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("应保留未闭合的末帧，实际 %d 个: %+v", len(events), events)
	}
	if string(events[1].Data) != "truncated" {
		t.Errorf("末帧内容错误: %q", events[1].Data)
	}
}

// TestScanBlankLinesSkipped 校验连续空行不产生空事件。
func TestScanBlankLinesSkipped(t *testing.T) {
	events, err := collect(t, "\n\n\ndata: only\n\n\n\n")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("连续空行不应产生空事件，实际 %d 个", len(events))
	}
}

// TestScanOversizedEventRejected 校验超大事件被拒而非无限吃内存。
// 上游返回巨大 JSON 错误体时，没有这道闸会直接打爆内存。
func TestScanOversizedEventRejected(t *testing.T) {
	huge := "data: " + strings.Repeat("x", 5000) + "\n\n"
	s := NewScanner(strings.NewReader(huge), 1024, 1024)
	for s.Next() {
	}
	if !errors.Is(s.Err(), ErrEventTooLarge) {
		t.Errorf("超大事件应被拒，得到 %v", s.Err())
	}
}

// TestScanLongLineWithinLimit 校验超过读缓冲但未超上限的长行能正确读出。
func TestScanLongLineWithinLimit(t *testing.T) {
	payload := strings.Repeat("y", 8000)
	s := NewScanner(strings.NewReader("data: "+payload+"\n\n"), 1024, 1<<20)
	if !s.Next() {
		t.Fatalf("应解析出事件，err=%v", s.Err())
	}
	if string(s.Event().Data) != payload {
		t.Errorf("长行内容不完整: 期望 %d 字节，实际 %d", len(payload), len(s.Event().Data))
	}
}

// TestScanPropagatesReadError 校验底层读错误被上抛而非当成正常结束。
func TestScanPropagatesReadError(t *testing.T) {
	want := errors.New("上游连接重置")
	r := io.MultiReader(strings.NewReader("data: a\n\n"), iotest.ErrReader(want))
	s := NewScanner(r, 0, 0)
	for s.Next() {
	}
	if !errors.Is(s.Err(), want) {
		t.Errorf("读错误应被上抛，得到 %v", s.Err())
	}
}

// ---------------------------------------------------------------------------
// 写出
// ---------------------------------------------------------------------------

// TestWriteEventRoundTrip 校验写出的格式能被自己解析回来。
func TestWriteEventRoundTrip(t *testing.T) {
	original := Event{
		Event: []byte("message"),
		ID:    []byte("7"),
		Data:  []byte(`{"delta":"你好"}`),
	}
	var buf bytes.Buffer
	if err := WriteEvent(&buf, &original); err != nil {
		t.Fatalf("写出失败: %v", err)
	}
	events, err := collect(t, buf.String())
	if err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if len(events) != 1 || string(events[0].Data) != string(original.Data) ||
		string(events[0].ID) != "7" || string(events[0].Event) != "message" {
		t.Errorf("往返不一致: %+v", events)
	}
}

// TestWriteMultilineData 校验含换行的数据按规范逐行加前缀。
func TestWriteMultilineData(t *testing.T) {
	var buf bytes.Buffer
	WriteEvent(&buf, &Event{Data: []byte("a\nb")})
	if buf.String() != "data: a\ndata: b\n\n" {
		t.Errorf("多行写出格式错误: %q", buf.String())
	}
	events, _ := collect(t, buf.String())
	if string(events[0].Data) != "a\nb" {
		t.Errorf("多行往返失败: %q", events[0].Data)
	}
}

// TestWriteCommentPassthrough 校验注释帧原样写出。
func TestWriteCommentPassthrough(t *testing.T) {
	var buf bytes.Buffer
	WriteEvent(&buf, &Event{Comment: true, Data: []byte(": keep-alive")})
	if buf.String() != ": keep-alive\n\n" {
		t.Errorf("注释帧写出错误: %q", buf.String())
	}
}

// ---------------------------------------------------------------------------
// 分配基准：验证「零分配扫描」这一设计目标
// ---------------------------------------------------------------------------

// BenchmarkScanner 度量每帧分配次数。
// 这是「流税」的直接指标：万级并发下每帧一次分配就是每秒数十万次 GC 压力。
func BenchmarkScanner(b *testing.B) {
	raw := strings.Repeat("data: {\"choices\":[{\"delta\":{\"content\":\"token\"}}]}\n\n", 100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := NewScanner(strings.NewReader(raw), 16<<10, 1<<20)
		for s.Next() {
			_ = s.Event().Data
		}
	}
}
