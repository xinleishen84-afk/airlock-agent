package piiredactionprocessor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/processor/processortest"
)

func keyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hash-key")
	if err := os.WriteFile(path, []byte("0123456789abcdef-0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testConfig(t *testing.T) *Config {
	t.Helper()
	cfg := createDefaultConfig().(*Config)
	cfg.Jurisdictions = []string{"GEN", "CN"}
	cfg.Tenant = "acme"
	cfg.HashKeyFile = keyFile(t)
	return cfg
}

// 一条带 PII 的真实 trace 走完整个处理器，落到下游 sink。
// A realistic PII-carrying trace passes through the processor to a sink.
func TestTracesAreRedactedInPlace(t *testing.T) {
	cfg := testConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	sink := new(consumertest.TracesSink)
	proc, err := createTraces(context.Background(),
		processortest.NewNopSettings(typeStr), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proc.Shutdown(context.Background()) })

	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "checkout")
	rs.Resource().Attributes().PutStr("deployment.owner", "zhang.wei@example.com")

	span := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetTraceID(pcommon.TraceID([16]byte{1, 2, 3}))
	span.SetSpanID(pcommon.SpanID([8]byte{4, 5, 6}))
	span.SetName("GET /api/users/13812345678/orders")
	span.Attributes().PutStr("http.url", "https://x.io/u?phone=13812345678")
	span.Attributes().PutInt("http.status_code", 500)
	span.Status().SetMessage("卡号 4111 1111 1111 1111 被拒")

	ev := span.Events().AppendEmpty()
	ev.SetName("exception")
	ev.Attributes().PutStr("exception.message", "无效身份证 11010519491231002X")

	// 嵌套值：结构化日志把有价值的字段放在这里
	nested := span.Attributes().PutEmptyMap("http.request")
	nested.PutStr("x-user", "zhang.wei@example.com")

	if err := proc.ConsumeTraces(context.Background(), td); err != nil {
		t.Fatal(err)
	}

	got := sink.AllTraces()
	if len(got) != 1 {
		t.Fatalf("下游应收到 1 个批次，实际 %d", len(got))
	}
	dump := marshalTraces(t, got[0])

	for _, leaked := range []string{
		"13812345678", "zhang.wei@example.com",
		"4111 1111 1111 1111", "11010519491231002X",
	} {
		if strings.Contains(dump, leaked) {
			t.Errorf("下游收到的批次里残留了 %q", leaked)
		}
	}
	for _, keep := range []string{"checkout", "500"} {
		if !strings.Contains(dump, keep) {
			t.Errorf("不该被改写的 %q 丢失了", keep)
		}
	}

	// 链路标识必须原封不动，否则脱敏掉的是可观测性
	out := got[0].ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	if out.TraceID() != (pcommon.TraceID([16]byte{1, 2, 3})) {
		t.Error("TraceID 被改写了")
	}
	if out.SpanID() != (pcommon.SpanID([8]byte{4, 5, 6})) {
		t.Error("SpanID 被改写了")
	}
	t.Logf("脱敏后 span 名：%s", out.Name())
	t.Logf("状态消息：%s", out.Status().Message())
}

func TestLogsAreRedactedInPlace(t *testing.T) {
	cfg := testConfig(t)
	sink := new(consumertest.LogsSink)
	proc, err := createLogs(context.Background(),
		processortest.NewNopSettings(typeStr), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}

	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rec := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	rec.Body().SetStr("用户提交提示词：我的手机是 13812345678")
	rec.Attributes().PutStr("enduser.id", "zhang.wei@example.com")

	if err := proc.ConsumeLogs(context.Background(), ld); err != nil {
		t.Fatal(err)
	}
	out := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	if strings.Contains(out.Body().Str(), "13812345678") {
		t.Errorf("日志正文未脱敏：%s", out.Body().Str())
	}
	v, _ := out.Attributes().Get("enduser.id")
	if strings.Contains(v.Str(), "example.com") {
		t.Errorf("日志属性未脱敏：%s", v.Str())
	}
	t.Logf("正文：%s", out.Body().Str())
}

// 指标标签是基数所在：同一个手机号必须映射到同一个摘要。
// Metric labels are where cardinality lives.
func TestMetricLabelsAreStableAndBounded(t *testing.T) {
	cfg := testConfig(t)
	sink := new(consumertest.MetricsSink)
	proc, err := createMetrics(context.Background(),
		processortest.NewNopSettings(typeStr), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}

	md := pmetric.NewMetrics()
	sum := md.ResourceMetrics().AppendEmpty().
		ScopeMetrics().AppendEmpty().
		Metrics().AppendEmpty()
	sum.SetName("orders.total")
	dps := sum.SetEmptySum().DataPoints()
	for _, phone := range []string{"13812345678", "13812345678", "13900001111"} {
		dps.AppendEmpty().Attributes().PutStr("user", phone)
	}

	if err := proc.ConsumeMetrics(context.Background(), md); err != nil {
		t.Fatal(err)
	}
	out := sink.AllMetrics()[0].ResourceMetrics().At(0).
		ScopeMetrics().At(0).Metrics().At(0)
	if out.Name() != "orders.total" {
		t.Errorf("指标名不应被改写：%s", out.Name())
	}

	var labels []string
	pts := out.Sum().DataPoints()
	for i := range pts.Len() {
		v, _ := pts.At(i).Attributes().Get("user")
		labels = append(labels, v.Str())
	}
	if strings.Contains(labels[0], "138") {
		t.Errorf("指标标签未脱敏：%v", labels)
	}
	if labels[0] != labels[1] {
		t.Errorf("同一个手机号应得到同一摘要，否则时间序列会分裂：%v", labels)
	}
	if labels[0] == labels[2] {
		t.Errorf("不同手机号不应塌缩成同一摘要：%v", labels)
	}
	t.Logf("标签：%v", labels)
}

// 同一批次内不同资源属于不同租户时，摘要必须不同。
// Different resources in one batch must hash under their own tenant.
func TestPerResourceTenant(t *testing.T) {
	cfg := testConfig(t)
	cfg.Tenant = ""
	cfg.TenantAttribute = "tenant.id"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	sink := new(consumertest.TracesSink)
	proc, err := createTraces(context.Background(),
		processortest.NewNopSettings(typeStr), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}

	td := ptrace.NewTraces()
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		rs := td.ResourceSpans().AppendEmpty()
		rs.Resource().Attributes().PutStr("tenant.id", tenant)
		rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty().
			Attributes().PutStr("user", "13812345678")
	}
	if err := proc.ConsumeTraces(context.Background(), td); err != nil {
		t.Fatal(err)
	}

	out := sink.AllTraces()[0].ResourceSpans()
	var digests []string
	for i := range out.Len() {
		v, _ := out.At(i).ScopeSpans().At(0).Spans().At(0).Attributes().Get("user")
		digests = append(digests, v.Str())
	}
	if digests[0] == digests[1] {
		t.Fatalf("两个租户的同一个手机号不应得到相同摘要：%v", digests)
	}
	t.Logf("A=%s  B=%s", digests[0], digests[1])
}

// 租户解析不出来时不得回退到某个默认租户。
// No fallback tenant when resolution fails.
func TestUnresolvableTenantFails(t *testing.T) {
	cfg := testConfig(t)
	cfg.Tenant = ""
	cfg.TenantAttribute = "tenant.id"

	sink := new(consumertest.TracesSink)
	proc, err := createTraces(context.Background(),
		processortest.NewNopSettings(typeStr), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}

	td := ptrace.NewTraces()
	td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().
		Spans().AppendEmpty().SetName("无租户属性")

	if err := proc.ConsumeTraces(context.Background(), td); err == nil {
		t.Fatal("租户解析不出来应报错")
	} else {
		t.Logf("按预期阻断：%v", err)
	}
	if len(sink.AllTraces()) != 0 {
		t.Fatal("阻断的批次不应到达下游")
	}
}

// failure_mode=drop 时，脱敏失败的批次不得到达下游。
// With failure_mode=drop, an unredactable batch must not reach the exporter.
func TestFailureModeDropDiscardsBatch(t *testing.T) {
	cfg := testConfig(t)
	cfg.Tenant = ""
	cfg.TenantAttribute = "tenant.id"
	cfg.FailureMode = FailureDrop

	sink := new(consumertest.TracesSink)
	proc, _ := createTraces(context.Background(),
		processortest.NewNopSettings(typeStr), cfg, sink)

	td := ptrace.NewTraces()
	td.ResourceSpans().AppendEmpty()
	if err := proc.ConsumeTraces(context.Background(), td); err == nil {
		t.Fatal("drop 模式应返回错误")
	}
	if len(sink.AllTraces()) != 0 {
		t.Fatal("drop 模式下批次不应到达下游")
	}
}

// 配置校验必须挡住那些「能跑、不出声、但是错的」组合。
// Validation must stop the combinations that run quietly and wrongly.
func TestConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"没有国家包", func(c *Config) { c.Jurisdictions = nil }, "jurisdictions"},
		{"hash 缺密钥", func(c *Config) { c.HashKeyFile = "" }, "hash_key_file"},
		{"mask 不支持", func(c *Config) { c.Strategy = "mask" }, "mask"},
		{"未知算子", func(c *Config) { c.Strategy = "shred" }, "unknown strategy"},
		{"未知故障模式", func(c *Config) { c.FailureMode = "retry" }, "failure_mode"},
		{"没有租户", func(c *Config) { c.Tenant = ""; c.TenantAttribute = "" }, "tenant"},
		{"drop 配了密钥", func(c *Config) { c.Strategy = "drop" }, "hash_key_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			tc.mut(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("应校验失败")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("报错应含 %q，实际：%v", tc.want, err)
			}
		})
	}
	if err := testConfig(t).Validate(); err != nil {
		t.Fatalf("合法配置不应被拒绝：%v", err)
	}
}

func TestFactoryRegistersAllThreeSignals(t *testing.T) {
	f := NewFactory()
	if f.Type() != typeStr {
		t.Fatalf("组件类型不符：%s", f.Type())
	}
	cfg := testConfig(t)
	for name, build := range map[string]func() error{
		"traces": func() error {
			_, err := f.CreateTraces(context.Background(),
				processortest.NewNopSettings(typeStr), cfg, consumertest.NewNop())
			return err
		},
		"logs": func() error {
			_, err := f.CreateLogs(context.Background(),
				processortest.NewNopSettings(typeStr), cfg, consumertest.NewNop())
			return err
		},
		"metrics": func() error {
			_, err := f.CreateMetrics(context.Background(),
				processortest.NewNopSettings(typeStr), cfg, consumertest.NewNop())
			return err
		},
	} {
		if err := build(); err != nil {
			t.Errorf("%s 信号构建失败：%v", name, err)
		}
	}
}

// marshalTraces 把批次序列化成文本，供残留断言使用。
func marshalTraces(t *testing.T, td ptrace.Traces) string {
	t.Helper()
	m := &ptrace.JSONMarshaler{}
	b, err := m.MarshalTraces(td)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// 每个 span 都要过这一层，因此它的耗时必须实测而非断言。
// Every span pays this, so the cost must be measured rather than asserted.
func BenchmarkConsumeTraces(b *testing.B) {
	path := filepath.Join(b.TempDir(), "hash-key")
	if err := os.WriteFile(path, []byte("0123456789abcdef-0123456789abcdef"), 0o600); err != nil {
		b.Fatal(err)
	}
	cfg := createDefaultConfig().(*Config)
	cfg.Jurisdictions = []string{"GEN", "CN"}
	cfg.Tenant = "acme"
	cfg.HashKeyFile = path

	proc, err := createTraces(context.Background(),
		processortest.NewNopSettings(typeStr), cfg, consumertest.NewNop())
	if err != nil {
		b.Fatal(err)
	}

	build := func() ptrace.Traces {
		td := ptrace.NewTraces()
		rs := td.ResourceSpans().AppendEmpty()
		rs.Resource().Attributes().PutStr("service.name", "checkout")
		spans := rs.ScopeSpans().AppendEmpty().Spans()
		for range 10 {
			s := spans.AppendEmpty()
			s.SetName("GET /api/users/13812345678/orders")
			s.Attributes().PutStr("http.url", "https://x.io/u?phone=13812345678")
			s.Attributes().PutInt("http.status_code", 200)
			s.Status().SetMessage("ok")
		}
		return td
	}

	// 批次构造不计入：要量的是防火墙那一层，不是 pdata 的分配开销。
	// Batch construction is excluded: the number being measured is the
	// firewall layer, not pdata's allocation cost.
	batches := make([]ptrace.Traces, b.N)
	for i := range batches {
		batches[i] = build()
	}

	ctx := b.Context()
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		if err := proc.ConsumeTraces(ctx, batches[i]); err != nil {
			b.Fatal(err)
		}
	}
}
