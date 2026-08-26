package anonymize

import (
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
)

// 这是本包最重要的一条用例。
// The most important test in this package.
//
// 一条声明要复原响应、却用了不可逆算子的链路，运行时不会报任何错：
// 请求带着哈希正常出站，模型用哈希作答，网关把 "[hash:name:...]"
// 当作人名交给终端用户。故障从头到尾都是静默的，所以必须在构造期拦下。
// A flow that restores responses but uses an irreversible operator errors
// nowhere at runtime: the request goes out hashed, the model answers with the
// hash, and the gateway hands "[hash:name:...]" to the user as a person's
// name. The failure is silent end to end, so it must be caught at build time.
func TestRestoringFlowRejectsIrreversibleOperators(t *testing.T) {
	h, _ := NewHash(testKeyring(t), 8)

	t.Run("默认算子不可逆", func(t *testing.T) {
		err := NewMatrix().Add(Flow{Name: "public_llm", Default: h, Restores: true})
		if err == nil {
			t.Fatal("声明复原却用哈希做默认算子，应被拒绝")
		}
		if !strings.Contains(err.Error(), "hash") {
			t.Fatalf("报错应点名不可逆的算子：%v", err)
		}
		t.Logf("按预期拒绝：%v", err)
	})

	t.Run("单个类型覆盖不可逆", func(t *testing.T) {
		err := NewMatrix().Add(Flow{
			Name: "public_llm", Default: NewMask(), Restores: true,
			ByType: map[detect.EntityType]Strategy{detect.TypeEmail: NewDrop()},
		})
		if err == nil {
			t.Fatal("单个类型配了切除算子，同样应被拒绝")
		}
		if !strings.Contains(err.Error(), "EMAIL") {
			t.Fatalf("报错应点名出问题的类型：%v", err)
		}
		t.Logf("按预期拒绝：%v", err)
	})

	t.Run("全部可逆则通过", func(t *testing.T) {
		tk, _ := NewTokenize(NewMemoryTokenStore(time.Hour))
		err := NewMatrix().Add(Flow{
			Name: "public_llm", Default: NewMask(), Restores: true,
			ByType: map[detect.EntityType]Strategy{detect.TypeEmail: tk},
		})
		if err != nil {
			t.Fatalf("全部可逆的链路应通过：%v", err)
		}
	})
}

// 缺默认算子必须拒绝：没人想到的类型会原样放过。
// A flow with no default must be rejected: unanticipated types pass through.
func TestFlowRequiresDefault(t *testing.T) {
	err := NewMatrix().Add(Flow{
		Name:   "archive",
		ByType: map[detect.EntityType]Strategy{detect.TypeEmail: NewDrop()},
	})
	if err == nil {
		t.Fatal("缺少默认算子应被拒绝")
	}
}

// 未知流向必须报错，不能回退到某条默认链路。
// An unknown destination must error, not fall back to some default flow.
func TestUnknownDestinationIsAnError(t *testing.T) {
	m := NewMatrix().MustAdd(Flow{Name: "public_llm", Default: NewMask(), Restores: true})
	if _, err := m.Flow("analytics"); err == nil {
		t.Fatal("未配置的流向应报错")
	} else {
		t.Logf("按预期拒绝：%v", err)
	}
}

// 同一份请求体扇出到三个去向，同一个实体走三个不同算子。
// One request body fans out to three destinations; the same entity takes three
// different operators.
func TestSameBodyThreeDestinations(t *testing.T) {
	const text = "客户 张伟 的邮箱是 a.b@example.com，手机 13812345678"

	h, err := NewHash(testKeyring(t), 8)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryTokenStore(time.Hour)
	tk, err := NewTokenize(store)
	if err != nil {
		t.Fatal(err)
	}

	m := NewMatrix()
	// 公有云大模型：保指代一致，响应要复原
	m.MustAdd(Flow{Name: "public_llm", Default: NewMask(), Restores: true})
	// 分析数仓：要可关联的假名，不复原
	m.MustAdd(Flow{Name: "analytics", Default: h})
	// DLP 红线归档：字节必须消失
	m.MustAdd(Flow{Name: "archive", Default: NewDrop()})
	// 跨系统伪名化：可逆，但走令牌库而非会话
	m.MustAdd(Flow{Name: "pseudonymous", Default: tk, Restores: true})

	r := newStrategyTestRedactor(t, store)
	vault := newSessionVault("s1", time.Hour)

	for _, dest := range []Destination{"public_llm", "analytics", "archive", "pseudonymous"} {
		flow, err := m.Flow(dest)
		if err != nil {
			t.Fatal(err)
		}
		res, err := r.RedactTo(t.Context(), text, sessScope(vault), flow)
		if err != nil {
			t.Fatalf("%s: %v", dest, err)
		}
		t.Logf("%-13s %s", dest, res.Text)
		t.Logf("%-13s 算子计数 %v", "", res.StrategyCounts)

		if strings.Contains(res.Text, "a.b@example.com") || strings.Contains(res.Text, "13812345678") {
			t.Errorf("%s 的输出仍含原值：%s", dest, res.Text)
		}
	}
}

// 审计要的是「3 个走 hash、1 个走 drop」，不只是「处理了 4 个 PII」。
// Audit needs "3 hashed, 1 dropped", not just "4 PII handled".
func TestStrategyCountsAreRecorded(t *testing.T) {
	h, _ := NewHash(testKeyring(t), 8)
	m := NewMatrix().MustAdd(Flow{
		Name: "mixed", Default: h,
		ByType: map[detect.EntityType]Strategy{detect.TypePhone: NewDrop()},
	})
	flow, _ := m.Flow("mixed")

	r := newStrategyTestRedactor(t, nil)
	res, err := r.RedactTo(t.Context(), "邮箱 a.b@example.com，手机 13812345678", sessScope(newSessionVault("s", time.Hour)), flow)
	if err != nil {
		t.Fatal(err)
	}
	if res.StrategyCounts["hash"] != 1 || res.StrategyCounts["drop"] != 1 {
		t.Fatalf("算子计数不符：%v", res.StrategyCounts)
	}
}

// 令牌化的往返：脱敏 → 模型 → 复原。
// The tokenize round trip: redact -> model -> restore.
func TestTokenizeRoundTrip(t *testing.T) {
	store := NewMemoryTokenStore(time.Hour)
	tk, _ := NewTokenize(store)
	flow := Flow{Name: "pseudonymous", Default: tk, Restores: true}

	r := newStrategyTestRedactor(t, store)
	vault := newSessionVault("s", time.Hour)

	res, err := r.RedactTo(t.Context(), "请发到 a.b@example.com", sessScope(vault), flow)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Text, "a.b@example.com") {
		t.Fatalf("脱敏后仍含原值：%s", res.Text)
	}

	back := unredactT(t, r, "好的，已发送到 "+res.Text[strings.Index(res.Text, "[tok:"):], sessScope(vault))
	if !strings.Contains(back.Text, "a.b@example.com") {
		t.Fatalf("复原失败：%s（phantom=%v）", back.Text, back.Phantom)
	}
	if back.Restored != 1 {
		t.Errorf("复原计数应为 1，实际 %d", back.Restored)
	}
}

// 模型凭空捏造的令牌不能被还原成任何真实值。
// A token the model invented must not resolve to any real value.
func TestPhantomTokenIsNotGuessed(t *testing.T) {
	store := NewMemoryTokenStore(time.Hour)
	r := newStrategyTestRedactor(t, store)
	vault := newSessionVault("s", time.Hour)

	res := unredactT(t, r, "已发送到 [tok:email:deadbeefcafe0000]", sessScope(vault))
	if strings.Contains(res.Text, "@") {
		t.Fatalf("幻影令牌不应被还原：%s", res.Text)
	}
	if len(res.Phantom) != 1 {
		t.Fatalf("幻影令牌应被记录，实际 %v", res.Phantom)
	}
}

// 没配令牌库却用了令牌化算子，复原时令牌会成为幻影 —— 必须能被看见。
// Using tokenize without a token store leaves tokens as phantoms; that has to
// be visible.
func TestTokenWithoutStoreBecomesPhantom(t *testing.T) {
	r := NewRedactor(nil, true) // 无令牌库 / no token store
	res := unredactT(t, r, "已发送到 [tok:email:deadbeefcafe0000]", sessScope(newSessionVault("s", time.Hour)))
	if strings.Contains(res.Text, "@") {
		t.Fatal("没有令牌库时不应还原出任何值")
	}
	if !strings.Contains(res.Text, "[tok:email:") {
		t.Fatalf("无法解析的令牌应原样保留：%s", res.Text)
	}
}

// Describe 是审计索取的那份材料，必须从运行中的进程产出。
// Describe is the artefact an auditor asks for, produced from the live process.
func TestDescribeRendersMatrix(t *testing.T) {
	h, _ := NewHash(testKeyring(t), 8)
	m := NewMatrix()
	m.MustAdd(Flow{Name: "public_llm", Default: NewMask(), Restores: true})
	m.MustAdd(Flow{
		Name: "analytics", Default: h,
		ByType: map[detect.EntityType]Strategy{detect.TypePhone: NewDrop()},
	})

	out := m.Describe()
	for _, want := range []string{"public_llm", "analytics", "mask", "hash", "PHONE", "drop"} {
		if !strings.Contains(out, want) {
			t.Errorf("矩阵描述应包含 %q：\n%s", want, out)
		}
	}
	t.Logf("\n%s", out)
}

// newStrategyTestRedactor 构造一个带国家包检测器与名册的脱敏器。
func newStrategyTestRedactor(t *testing.T, store TokenStore) *Redactor {
	t.Helper()
	gaz, err := detect.NewGazetteerDetector(map[detect.EntityType][]string{
		detect.TypeName: {"张伟", "李娜"},
	}, false, 2)
	if err != nil {
		t.Fatalf("构造名册失败: %v", err)
	}
	d := detect.NewCompositeDetector(
		[]detect.Detector{packs.MustNewRegistry([]string{"GEN", "CN", "US"}), gaz}, 0)

	var opts []RedactorOption
	if store != nil {
		opts = append(opts, WithTokenStore(store))
	}
	return NewRedactorWith(d, true, opts...)
}
