package proxy

import (
	"net/http"
	"strings"
	"sync"
	"testing"
)

// captureUpstream 启动一个记录请求体的假上游。
func captureUpstream(t *testing.T, chunks []string) (*upstreamCapture, func()) {
	t.Helper()
	cap := &upstreamCapture{}
	up := newUpstream(t, upstreamOpts{
		onRequest: func(_ *http.Request, body []byte) {
			cap.mu.Lock()
			cap.bodies = append(cap.bodies, string(body))
			cap.mu.Unlock()
		},
		chunks: chunks,
	})
	cap.url = up.URL
	return cap, up.Close
}

type upstreamCapture struct {
	mu     sync.Mutex
	bodies []string
	url    string
}

func (c *upstreamCapture) at(i int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i >= len(c.bodies) {
		return ""
	}
	return c.bodies[i]
}

// sseContent 把 SSE 流里的 delta.content 拼起来。
func sseContent(body string) string {
	var b strings.Builder
	for _, line := range strings.Split(body, "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		if i := strings.Index(data, `"content":"`); i >= 0 {
			rest := data[i+len(`"content":"`):]
			if j := strings.Index(rest, `"`); j >= 0 {
				b.WriteString(rest[:j])
			}
		}
	}
	return b.String()
}

// TestSameReplicaMultiTurnIsConsistent 证明单副本内多轮同会话占位符稳定。
// Proves placeholders stay stable across turns within one replica.
//
// 保险库是进程内活对象，映射在请求脱敏时同步写入，早于上游调用——
// 因此不需要「流结束时提交」这类事务语义，也不需要在每轮开头阻塞加载。
// 并发轮次由 SessionVault 自己的读写锁保证。
//
// The vault is a live in-process object and the mapping is written during
// request redaction, before the upstream call — so no end-of-stream commit and
// no per-turn blocking load are needed. Concurrent turns are covered by the
// vault's own lock.
func TestSameReplicaMultiTurnIsConsistent(t *testing.T) {
	cap, closeUp := captureUpstream(t,
		[]string{`{"choices":[{"index":0,"delta":{"content":"ok"}}]}`})
	defer closeUp()

	h := newTestHandler(t, cap.url, true, true)
	hdr := map[string]string{"X-Session-ID": "s-multi"}
	for _, msg := range []string{"张伟的档案", "再查一次张伟", "张伟的电话"} {
		rec := doRequest(t, h,
			`{"stream":true,"messages":[{"role":"user","content":"`+msg+`"}]}`, hdr)
		if rec.Code != http.StatusOK {
			t.Fatalf("状态码 %d", rec.Code)
		}
	}
	for i := 0; i < 3; i++ {
		body := cap.at(i)
		if strings.Contains(body, "张伟") {
			t.Errorf("第 %d 轮真名泄漏: %s", i+1, body)
		}
		if !strings.Contains(body, "ANONYMIZED_NAME_0") {
			t.Errorf("第 %d 轮占位符不稳定: %s", i+1, body)
		}
	}
}

// TestConcurrentTurnsSameSessionAreConsistent 证明同会话并发轮次不会拿到不同占位符。
// Proves concurrent turns of one session do not diverge.
func TestConcurrentTurnsSameSessionAreConsistent(t *testing.T) {
	cap, closeUp := captureUpstream(t,
		[]string{`{"choices":[{"index":0,"delta":{"content":"ok"}}]}`})
	defer closeUp()

	h := newTestHandler(t, cap.url, true, true)
	hdr := map[string]string{"X-Session-ID": "s-race"}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			doRequest(t, h,
				`{"stream":true,"messages":[{"role":"user","content":"张伟"}]}`, hdr)
		}()
	}
	wg.Wait()
	for i := 0; i < 16; i++ {
		if body := cap.at(i); !strings.Contains(body, "ANONYMIZED_NAME_0") {
			t.Errorf("并发第 %d 轮占位符不一致: %s", i+1, body)
		}
	}
}

// TestPlaceholdersAreReplicaLocal 钉住「占位符是副本本地的」这一事实。
// Pins the fact that placeholders are replica-local.
//
// # 这条测试断言的是一个缺陷，不是一个特性
// # This test asserts a defect, not a feature
//
// 占位符是按类型递增的序号，编号取决于该副本见过的文本顺序。同一会话下
// 副本 A 可以把 13800138000 编成 PHONE_0，副本 B 把 13900139000 也编成
// PHONE_0——上游回一句引用 PHONE_0 的话，两边复原出不同的真实号码，
// 用户会拿到别人的数据，全程不报错。
//
// 客户端每轮重发完整历史时看不出来（分配顺序由文本确定，两副本算得一样），
// 长会话一裁剪历史就复现——会话越长越容易出事，短测试永远测不到。
//
// 现阶段的控制措施是部署层的：pii.session_consistency 必须显式声明
// single-replica 或 session-affinity，见 internal/config。本用例存在的意义
// 是：谁把占位符改成会话内确定性派生（例如 HMAC(session_key, type||value)）
// 之后，这条会红，从而提醒一并撤掉那条部署约束与 README 里的说明——
// 否则会留下一条已经没必要、却仍在限制扩容的规矩。
//
// Placeholders are per-type ordinals numbered in the order a replica happened
// to see them, so two replicas number one session differently and a response
// citing PHONE_0 restores to different real values on each — silently handing
// one user another's data. Resending full history hides it; trimming a long
// session brings it back.
//
// The control today is deployment-level (pii.session_consistency). This test
// exists so that whoever makes placeholders deterministic within a session sees
// it go red and remembers to retire that constraint, rather than leaving a rule
// that no longer buys anything but still caps scale-out.
func TestPlaceholdersAreReplicaLocal(t *testing.T) {
	cap, closeUp := captureUpstream(t, []string{
		`{"choices":[{"index":0,"delta":{"content":"账单属于 ANONYMIZED_PHONE_0"}}]}`,
	})
	defer closeUp()

	replicaA := newTestHandler(t, cap.url, true, true)
	replicaB := newTestHandler(t, cap.url, true, true)
	hdr := map[string]string{"X-Session-ID": "s-lb"}

	recA := doRequest(t, replicaA,
		`{"stream":true,"messages":[{"role":"user","content":"13800138000 和 13900139000"}]}`, hdr)
	// 第 2 轮落到另一个副本，且历史被滑动窗口裁掉——长会话里的常态
	recB := doRequest(t, replicaB,
		`{"stream":true,"messages":[{"role":"user","content":"13900139000 的账单"}]}`, hdr)

	outA, outB := sseContent(recA.Body.String()), sseContent(recB.Body.String())
	if !strings.Contains(outA, "13800138000") {
		t.Fatalf("副本 A 未按自己的表复原: %q", outA)
	}
	if !strings.Contains(outB, "13900139000") {
		t.Fatalf("副本 B 未按自己的表复原: %q", outB)
	}
	if outA == outB {
		t.Fatalf("两个副本复原出了同一个值（%q）——占位符已不再是副本本地的。"+
			"若这是有意的改动（例如改成会话内确定性派生），请一并撤掉 "+
			"pii.session_consistency 这条部署约束与 README 中的对应说明", outA)
	}
}
