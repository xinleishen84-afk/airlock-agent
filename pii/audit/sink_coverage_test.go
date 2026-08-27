package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// 探针：三个 sink 真的能工作吗？
func TestSinkProbe(t *testing.T) {
	ev := Event{
		Schema: Schema, EventID: "abc", Tenant: "acme",
		Action: ActionRedact, Outcome: OutcomeOK,
		Entities: map[string]int{"PHONE": 1},
	}

	t.Run("WriterSink 写出合法 JSON 行", func(t *testing.T) {
		var buf bytes.Buffer
		s := NewWriterSink(&buf)
		if err := s.Emit(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
		if err := s.Emit(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
		if len(lines) != 2 {
			t.Fatalf("应写出 2 行，实际 %d：%q", len(lines), buf.String())
		}
		for i, line := range lines {
			var back Event
			if err := json.Unmarshal([]byte(line), &back); err != nil {
				t.Errorf("第 %d 行不是合法 JSON：%v\n%q", i, err, line)
			}
			if back.Tenant != "acme" {
				t.Errorf("第 %d 行内容不对：%+v", i, back)
			}
		}
		t.Logf("输出：%q", buf.String())
	})

	t.Run("WriterSink 并发写不交错", func(t *testing.T) {
		var buf bytes.Buffer
		s := NewWriterSink(&buf)
		var wg sync.WaitGroup
		for range 50 {
			wg.Add(1)
			go func() { defer wg.Done(); _ = s.Emit(context.Background(), ev) }()
		}
		wg.Wait()
		lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
		if len(lines) != 50 {
			t.Errorf("应有 50 行，实际 %d", len(lines))
		}
		for i, line := range lines {
			if !json.Valid([]byte(line)) {
				t.Fatalf("第 %d 行被交错写坏了：%q", i, line)
			}
		}
	})

	t.Run("MultiSink 一个失败不影响其他", func(t *testing.T) {
		good := &captureSink{}
		m := NewMultiSink(failingSink{}, good, failingSink{})
		err := m.Emit(context.Background(), ev)
		if err == nil {
			t.Error("应上报第一个失败")
		}
		if len(good.events) != 1 {
			t.Errorf("正常的 sink 应仍收到事件，实际 %d 条——"+
				"SIEM 挂掉不该连本地记录也一起赔进去", len(good.events))
		}
	})

	t.Run("MultiSink 名字列出全部后端", func(t *testing.T) {
		m := NewMultiSink(NopSink{}, &captureSink{})
		if !strings.Contains(m.Name(), "none") || !strings.Contains(m.Name(), "capture") {
			t.Errorf("名字应列出全部后端，实际 %q", m.Name())
		}
	})

	t.Run("EmitErasure", func(t *testing.T) {
		sink := &captureSink{}
		rec := NewRecorder(sink, nil, nil)
		rec.EmitErasure(context.Background(), "acme", 3, 7, ErrNone)
		if len(sink.events) != 1 {
			t.Fatalf("应发出 1 条，实际 %d", len(sink.events))
		}
		e := sink.events[0]
		if e.Action != ActionErase || e.SessionsErased != 3 || e.TokensErased != 7 {
			t.Errorf("擦除回执不对：%+v", e)
		}
		if e.Outcome != OutcomeOK {
			t.Errorf("无错误时 outcome 应为 ok：%s", e.Outcome)
		}
	})

	t.Run("EmitErasure 失败时 outcome 为 failed", func(t *testing.T) {
		sink := &captureSink{}
		rec := NewRecorder(sink, nil, nil)
		rec.EmitErasure(context.Background(), "acme", 3, 0, ErrTokenStore)
		e := sink.events[0]
		if e.Outcome != OutcomeFailed {
			t.Errorf("令牌库擦除失败时 outcome 应为 failed，实际 %s——"+
				"部分擦除被报告为成功，会被签字为完成而数据还在库里", e.Outcome)
		}
	})

	t.Run("SinkName 与 Close", func(t *testing.T) {
		rec := NewRecorder(&captureSink{}, nil, nil)
		if rec.SinkName() != "capture" {
			t.Errorf("SinkName 不对：%q", rec.SinkName())
		}
		if err := rec.Close(); err != nil {
			t.Errorf("Close 不该报错：%v", err)
		}
	})
}
