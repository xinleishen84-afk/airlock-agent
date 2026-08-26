package audit

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/anonymize"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

func testKeyring(t testing.TB) *anonymize.Keyring {
	t.Helper()
	k, err := anonymize.NewKeyring([]byte("0123456789abcdef-0123456789abcdef"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ---------------------------------------------------------------------------
// 结构性保证 / The structural guarantee
// ---------------------------------------------------------------------------

// 这是本包最重要的一条用例。
// The most important test in this package.
//
// 「不要把原值记进审计事件」是一条人会遵守的规则——直到某天有人为了排查
// 加一个 `SampleText string`。那条字段会通过评审（它看起来无害）、
// 会通过全部现有用例（它们不知道它存在），然后把 PII 送进 SIEM。
//
// 因此这条用例用反射遍历 Event 的每一个字段，只放行三类：
// 计数、时间，以及一份逐个写下理由的普通字符串白名单。
// 任何新增的普通字符串字段都会让它失败，直到有人把理由写进这里。
//
// "Do not log the value" is a rule a person follows until the day they add a
// SampleText field for debugging. It would pass review (it looks harmless) and
// pass every existing test (none of them know it exists), and ship PII to the
// SIEM. So this walks every field by reflection and admits only counts, times,
// and a plain-string allowlist with a written reason for each entry.
func TestEventCarriesNoFreeText(t *testing.T) {
	// 每一条都必须带理由：为什么这个字符串字段不可能装下调用方可控的文本。
	// Each entry needs a reason: why this string field cannot hold
	// caller-controlled text.
	allowedStrings := map[string]string{
		"Schema":  "常量，取自本包的 Schema 常量",
		"EventID": "本进程生成的随机十六进制",
		"Tenant":  "组织标识，字符集受 ValidateTenant 约束，非个人数据",
		"SessionFingerprint": "会话标识的带密钥 HMAC 摘要，" +
			"不是标识本身——会话 ID 是调用方自由文本",
		"Destination": "运维配置里的链路名，不来自请求",
	}
	// 枚举类型：取值来自封闭集合
	// Enum types: values come from a closed set
	enumTypes := map[reflect.Type]bool{
		reflect.TypeOf(Action("")):     true,
		reflect.TypeOf(Outcome("")):    true,
		reflect.TypeOf(ErrorClass("")): true,
	}

	typ := reflect.TypeOf(Event{})
	for i := range typ.NumField() {
		f := typ.Field(i)
		switch {
		case enumTypes[f.Type]:
			continue
		case f.Type.Kind() == reflect.Int, f.Type.Kind() == reflect.Int64:
			continue
		case f.Type == reflect.TypeOf(time.Time{}):
			continue
		case f.Type == reflect.TypeOf(map[string]int{}):
			// 键来自内部词表（实体类型、算子名、识别器名），值是计数
			continue
		case f.Type.Kind() == reflect.String:
			if _, ok := allowedStrings[f.Name]; !ok {
				t.Errorf("Event.%s 是一个未经论证的字符串字段。\n"+
					"审计事件绝不能携带调用方可控的文本——它会被送进 SIEM、"+
					"建索引、留存数年、对每个有账号的人可读。\n"+
					"如果这个字段确实不可能装下自由文本，请把理由写进 allowedStrings；"+
					"如果会，请换成计数或枚举。", f.Name)
			}
		default:
			t.Errorf("Event.%s 的类型 %s 未被论证过，无法判断它能否装下自由文本",
				f.Name, f.Type)
		}
	}
}

// 会话 ID 是调用方自由文本，绝不能原样出现在事件里。
// The session id is caller-supplied free text and must never appear verbatim.
//
// 调用方会拿手边有的东西当会话 ID —— 很常见地，就是用户的邮箱。
// Callers use whatever they have as a conversation id — routinely, the user's
// email address.
func TestSessionIDIsFingerprintedNotLogged(t *testing.T) {
	fp, err := NewFingerprinter(testKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	rec := NewRecorder(sink, fp, nil)

	const sessionAsEmail = "zhang.wei@example.com"
	rec.EmitRedaction(context.Background(), Redaction{
		Tenant: "acme", Session: sessionAsEmail, Destination: "public_llm",
		TypeCounts: map[string]int{"PHONE": 1},
		Strategies: map[string]int{"mask": 1},
	})

	dump := sink.dump(t)
	if strings.Contains(dump, sessionAsEmail) {
		t.Fatalf("会话 ID 原样进了审计事件：%s", dump)
	}
	if !strings.Contains(dump, `"session_fingerprint"`) {
		t.Fatalf("应记录指纹：%s", dump)
	}
	t.Logf("事件：%s", dump)
}

// 同一会话的指纹必须稳定（否则无法关联），跨租户必须不同（否则可关联租户）。
// Stable within a tenant (or correlation is lost), different across tenants
// (or tenants become linkable).
func TestFingerprintIsStableAndTenantScoped(t *testing.T) {
	fp, _ := NewFingerprinter(testKeyring(t))

	a1, _ := fp.Fingerprint("tenant-a", "conv-42")
	a2, _ := fp.Fingerprint("tenant-a", "conv-42")
	b1, _ := fp.Fingerprint("tenant-b", "conv-42")

	if a1 != a2 {
		t.Errorf("同一租户内指纹必须稳定：%s vs %s", a1, a2)
	}
	if a1 == b1 {
		t.Errorf("跨租户指纹不应相同：%s", a1)
	}
	if strings.Contains(a1, "conv-42") {
		t.Errorf("指纹里含原标识：%s", a1)
	}
	t.Logf("A=%s  B=%s", a1, b1)
}

// 没有密钥环时拒绝构造：无密钥的摘要可被穷举回原标识。
// Refuse without a keyring: an unkeyed digest is brute-forceable.
func TestFingerprinterRequiresKeyring(t *testing.T) {
	if _, err := NewFingerprinter(nil); err == nil {
		t.Fatal("缺少密钥环应被拒绝")
	}
}

// 幻影只记数量，不记字符串：幻影文本由模型控制。
// Phantoms are counted, never quoted: their text is model-controlled.
func TestPhantomsAreCountedNotQuoted(t *testing.T) {
	fp, _ := NewFingerprinter(testKeyring(t))
	sink := &captureSink{}
	rec := NewRecorder(sink, fp, nil)

	rec.EmitRestoration(context.Background(), Restoration{
		Tenant: "acme", Session: "s1", Restored: 2, Phantom: 3,
	})
	dump := sink.dump(t)
	if strings.Contains(dump, "ANONYMIZED") {
		t.Fatalf("幻影字符串进了事件：%s", dump)
	}
	if !strings.Contains(dump, `"phantom":3`) {
		t.Fatalf("应记录幻影数量：%s", dump)
	}
}

// 识别器计数让「一条不再命中的规则」在 SIEM 里可见。
// Per-recognizer counts make a rule that stopped firing visible from the SIEM.
func TestRecognizerCountsAreRecorded(t *testing.T) {
	fp, _ := NewFingerprinter(testKeyring(t))
	sink := &captureSink{}
	rec := NewRecorder(sink, fp, nil)

	rec.EmitRedaction(context.Background(), Redaction{
		Tenant: "acme", Session: "s1",
		Entities: []detect.Entity{
			{Type: detect.TypePhone, Value: "13812345678", Detector: "cn_mobile"},
			{Type: detect.TypePhone, Value: "13900001111", Detector: "cn_mobile"},
			{Type: detect.TypeEmail, Value: "a@b.com", Detector: "email"},
		},
		TypeCounts: map[string]int{"PHONE": 2, "EMAIL": 1},
	})

	dump := sink.dump(t)
	// 实体的 Value 字段进了 Recorder，但绝不能进事件
	for _, leaked := range []string{"13812345678", "13900001111", "a@b.com"} {
		if strings.Contains(dump, leaked) {
			t.Fatalf("实体原值进了事件：%s", dump)
		}
	}
	if !strings.Contains(dump, `"cn_mobile":2`) {
		t.Fatalf("应记录识别器命中数：%s", dump)
	}
	t.Logf("事件：%s", dump)
}

// 错误类别是枚举，绝不是 err.Error()：错误文本会引用出问题的那个值。
// The error class is an enum, never err.Error(): error text quotes the value.
func TestErrorClassIsEnumerated(t *testing.T) {
	fp, _ := NewFingerprinter(testKeyring(t))
	sink := &captureSink{}
	rec := NewRecorder(sink, fp, nil)

	rec.EmitBlock(context.Background(), "acme", "s1", ErrLeakDetected,
		map[string]int{"ID_CARD": 1})

	dump := sink.dump(t)
	if !strings.Contains(dump, `"error_class":"residual_pii_detected"`) {
		t.Fatalf("应记录错误类别：%s", dump)
	}
	var e Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(dump)), &e); err != nil {
		t.Fatal(err)
	}
	if e.Outcome != OutcomeBlocked {
		t.Errorf("阻断事件的 outcome 不符：%s", e.Outcome)
	}
}

// sink 故障必须让运维知道，但绝不能让请求失败。
// A sink failure must reach the operator without failing the request.
func TestSinkFailureIsReportedNotFatal(t *testing.T) {
	var got error
	rec := NewRecorder(failingSink{}, nil, func(err error) { got = err })
	rec.EmitRedaction(context.Background(), Redaction{Tenant: "acme", Session: "s1"})
	if got == nil {
		t.Fatal("sink 故障应上报给运维")
	}
	t.Logf("按预期上报：%v", got)
}

// 缓冲满时丢弃并计数，绝不阻塞请求路径。
// A full buffer drops and counts; it never blocks the request path.
func TestHTTPSinkDropsRatherThanBlocks(t *testing.T) {
	s, err := NewHTTPSink(HTTPSinkOptions{
		Endpoint:   "http://127.0.0.1:1", // 不可达 / unreachable
		BufferSize: 1, BatchSize: 1000, FlushInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			_ = s.Emit(context.Background(), Event{Schema: Schema})
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Emit 阻塞了——SIEM 慢会变成网关每个请求上的延迟")
	}

	_, dropped, _ := s.Stats()
	if dropped == 0 {
		t.Fatal("缓冲满时应计数丢弃，而不是静默吞掉")
	}
	t.Logf("丢弃 %d 条（已计数）", dropped)
}

// ---------------------------------------------------------------------------
// 测试替身 / Test doubles
// ---------------------------------------------------------------------------

type captureSink struct{ events []Event }

func (c *captureSink) Name() string { return "capture" }
func (c *captureSink) Emit(_ context.Context, e Event) error {
	c.events = append(c.events, e)
	return nil
}
func (c *captureSink) Close() error { return nil }

func (c *captureSink) dump(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, e := range c.events {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String()
}

type failingSink struct{}

func (failingSink) Name() string { return "failing" }
func (failingSink) Emit(context.Context, Event) error {
	return errSinkDown{}
}
func (failingSink) Close() error { return nil }

type errSinkDown struct{}

func (errSinkDown) Error() string { return "SIEM 不可达 / SIEM unreachable" }
