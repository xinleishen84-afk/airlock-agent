package nerclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"

	piiv1 "github.com/xinleishen84-afk/airlock-agent/nerclient/genproto/piiv1"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// recordingStub 记录 wire 上实际发出去的请求。
type recordingStub struct {
	lastLanguage string
	calls        int
	failWith     error
}

func (s *recordingStub) Analyze(_ context.Context, in *piiv1.AnalyzeRequest,
	_ ...grpc.CallOption) (*piiv1.AnalyzeResponse, error) {
	s.calls++
	s.lastLanguage = in.GetLanguage()
	if s.failWith != nil {
		return nil, s.failWith
	}
	return &piiv1.AnalyzeResponse{}, nil
}

func (s *recordingStub) Health(_ context.Context, _ *piiv1.HealthRequest,
	_ ...grpc.CallOption) (*piiv1.HealthResponse, error) {
	return &piiv1.HealthResponse{}, nil
}

// newStubClient 造一个只替换了 stub 的客户端。
func newStubClient(t *testing.T, stub piiv1.NERServiceClient, opts Options) *Client {
	t.Helper()
	if opts.Timeout == 0 {
		opts.Timeout = time.Second
	}
	if opts.MaxTextBytes == 0 {
		opts.MaxTextBytes = 1 << 20
	}
	if len(opts.Types) == 0 {
		opts.Types = []detect.EntityType{detect.TypeName}
	}
	return &Client{stub: stub, opts: opts}
}

// TestPerCallLanguageReachesTheWire 证明每次调用的 language 真的发到了线上。
// Proves the per-call language actually reaches the wire.
//
// # 只测 ScriptOf() 抓不到这个
// # Testing ScriptOf() alone cannot catch this
//
// 这里曾经写 Language: c.opts.Language——函数签名收了 language 参数，注释也说
// 「cascade overrides this per call」，而 wire 上一律发客户端默认值。整条语言
// 路由链因此在最后一跳作废：Cascade 按文字系统算出 zh / en 并逐段传下来，
// 服务端收到的却永远是同一个值。
//
// 症状是安静的——请求成功、实体也检出来了，只是拉丁文段落被送进了中文模型
// （分布外输入，实测把 declined、deps、Codice 判成人名），而 metrics 里的
// language 标签显示的是路由算出来的那个，与实际发出去的对不上。
//
// 上游的单测测的是 ScriptOf() 算得对不对，它算得一直很对。缺的是这一跳：
// 算出来的东西有没有被用上。
//
// The wire carried the client's default while the signature took a language
// parameter and the comment claimed cascade overrode it per call. Upstream
// tests checked that ScriptOf() computed the right value — it always did. What
// was missing was whether the computed value was used.
func TestPerCallLanguageReachesTheWire(t *testing.T) {
	// 客户端默认值刻意与 per-call 值不同——相同就测不出区别
	stub := &recordingStub{}
	c := newStubClient(t, stub, Options{Language: "zh"})

	for _, want := range []string{"en", "de", ""} {
		stub.lastLanguage = "<未设置>"
		if _, err := c.DetectContextLanguage(context.Background(), "some text", want); err != nil {
			t.Fatalf("language=%q 调用失败: %v", want, err)
		}
		if stub.lastLanguage != want {
			t.Errorf("wire 上的 language 是 %q，本次调用要求的是 %q——"+
				"客户端默认值覆盖了 per-call 值，整条语言路由在最后一跳作废",
				stub.lastLanguage, want)
		}
	}
}

// TestDetectContextUsesConfiguredLanguage 确认默认路径仍然用客户端配置的语言。
// Confirms the default path still uses the client's configured language.
//
// 修 per-call 那条时容易把默认路径一起改坏：DetectContext 不带 language 参数，
// 它必须继续用 c.opts.Language，否则直接调用方会静默变成 auto。
func TestDetectContextUsesConfiguredLanguage(t *testing.T) {
	stub := &recordingStub{}
	c := newStubClient(t, stub, Options{Language: "zh"})
	if _, err := c.DetectContext(context.Background(), "文本"); err != nil {
		t.Fatalf("调用失败: %v", err)
	}
	if stub.lastLanguage != "zh" {
		t.Errorf("默认路径应发客户端配置的 zh，实际 %q", stub.lastLanguage)
	}
}

// TestFailOpenMarksFailureAsDegradable 证明 fail-open 把故障标成「可降级」。
// Proves fail-open marks the failure as degradable.
//
// # 「已按 fail-open 放行」这句话此前与控制流矛盾
// # The message contradicted the control flow
//
// FailOpen=true 且 gRPC 出错时，客户端返回的错误文本写着「已按 fail-open
// 放行」，而 Cascade 收到 error 后直接 return nil, err——没有降级为前两层，
// 请求整条失败。这个开关只改了错误消息，没有改变任何行为：配了 fail-open
// 的部署，在 NER 挂掉时和 fail-closed 表现完全一样。
//
// 现在传输层只标记类别，不替安全策略拿主意；由级联层决定拿这个标记做什么。
// 两层各自的行为分开测：这里测标记，Cascade 那边测降级。
//
// With FailOpen=true the client returned an error saying it had let the request
// through while the cascade propagated it, so the switch changed the message
// and nothing else. Transport now marks the class and the cascade decides;
// the two behaviours are tested separately.
func TestFailOpenMarksFailureAsDegradable(t *testing.T) {
	stub := &recordingStub{failWith: errors.New("connection refused")}
	c := newStubClient(t, stub, Options{Language: "zh", FailOpen: true})

	_, err := c.DetectContextLanguage(context.Background(), "文本", "zh")
	if err == nil {
		t.Fatal("传输层仍应如实报告故障——静默返回空结果会让调用方无法区分" +
			"「没检出实体」与「模型根本没跑」")
	}
	if !errors.Is(err, detect.ErrModelDegraded) {
		t.Errorf("FailOpen=true 时故障必须标成可降级，否则级联层无从降级，"+
			"这个开关就只改了错误文案：%v", err)
	}
	if !errors.Is(err, ErrNERUnavailable) {
		t.Errorf("底层原因必须一并保留——排障时那才是唯一有用的东西：%v", err)
	}
}

// TestFailClosedIsNotMarkedDegradable 确认 fail-closed 不带可降级标记。
// 两种语义必须真的不同，否则这个开关没有意义。
func TestFailClosedIsNotMarkedDegradable(t *testing.T) {
	stub := &recordingStub{failWith: errors.New("connection refused")}
	c := newStubClient(t, stub, Options{Language: "zh", FailOpen: false})

	_, err := c.DetectContextLanguage(context.Background(), "文本", "zh")
	if err == nil {
		t.Fatal("FailOpen=false 时必须报错——NER 不可用意味着姓名类完全未检测，" +
			"放行等于把未脱敏的 PII 送出边界")
	}
	if errors.Is(err, detect.ErrModelDegraded) {
		t.Error("fail-closed 的故障不能带可降级标记，否则级联层会把它降级放行")
	}
}
