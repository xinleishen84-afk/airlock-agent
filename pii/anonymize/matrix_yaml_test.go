package anonymize

import (
	"strings"
	"testing"
)

const goodMatrix = `
version: 1
options:
  char_mask: {char: "*", keep: 4}
  hash: {digits: 8}
  generalize: {granularity: decade, fallback: char_mask}
flows:
  - name: public_llm
    restores: true
    default: mask
  - name: analytics
    default: hash
    by_type:
      PHONE: drop
  - name: archive
    default: drop
  - name: research_export
    default: drop
    by_type:
      ORG: generalize
`

func testDeps() MatrixDeps {
	return MatrixDeps{
		HashKey:    testKey(),
		TokenStore: NewMemoryTokenStore(),
		Ontology:   testOntology(),
	}
}

func TestLoadMatrix(t *testing.T) {
	m, err := LoadMatrix(strings.NewReader(goodMatrix), testDeps(), "test.yaml")
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if got := m.Destinations(); len(got) != 4 {
		t.Fatalf("应有 4 条链路，实际 %v", got)
	}
	t.Logf("\n%s", m.Describe())
}

// 配置层必须能在算子构建之前就否掉不成立的策略。
// The configuration layer must reject an impossible policy before any operator
// is built.
//
// 密钥没挂上时，如果先报「缺密钥」，那条「既要复原又用哈希」的策略错误
// 就被盖住了 —— 运维补上密钥，然后带着一条静默损坏的链路上线。
// If a missing key is reported first, the "restores + hash" policy error is
// masked: the operator mounts the key and ships a silently broken flow.
func TestPolicyErrorsPrecedeDependencyErrors(t *testing.T) {
	src := `
version: 1
flows:
  - name: public_llm
    restores: true
    default: hash
`
	// 刻意不提供密钥 / deliberately no key
	_, err := LoadMatrix(strings.NewReader(src), MatrixDeps{}, "test.yaml")
	if err == nil {
		t.Fatal("应加载失败")
	}
	if strings.Contains(err.Error(), "HMAC") {
		t.Fatalf("依赖缺失的报错盖住了策略错误：%v", err)
	}
	if !strings.Contains(err.Error(), "restores") {
		t.Fatalf("报错应指出策略问题：%v", err)
	}
	t.Logf("按预期先报策略问题：%v", err)
}

func TestMatrixConfigRejections(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{
			"拼错的字段", "version: 1\nflows:\n  - name: a\n    defalut: mask\n",
			"field defalut not found",
		},
		{
			"未知算子", "version: 1\nflows:\n  - name: a\n    default: shred\n",
			"unknown strategy",
		},
		{
			"缺默认算子", "version: 1\nflows:\n  - name: a\n    by_type: {PHONE: drop}\n",
			"default is required",
		},
		{
			"未知实体类型", "version: 1\nflows:\n  - name: a\n    default: drop\n    by_type: {PHOEN: drop}\n",
			"unknown entity type",
		},
		{
			"版本不符", "version: 2\nflows: []\n", "version must be 1",
		},
		{
			"没有任何链路", "version: 1\nflows: []\n", "no flows configured",
		},
		{
			"链路重名",
			"version: 1\nflows:\n  - name: a\n    default: drop\n  - name: a\n    default: mask\n",
			"重复注册",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadMatrix(strings.NewReader(c.src), testDeps(), "test.yaml")
			if err == nil {
				t.Fatal("应加载失败")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("报错应含 %q，实际：%v", c.want, err)
			}
		})
	}
}

// 依赖缺失必须在启动期报错，而不是在第一个请求上。
// A missing dependency must fail at startup, not on the first request.
func TestMissingDependenciesFailAtLoad(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"缺密钥", "version: 1\nflows:\n  - name: a\n    default: hash\n", "HMAC"},
		{"缺令牌库", "version: 1\nflows:\n  - name: a\n    default: tokenize\n", "令牌库"},
		{"缺词表", "version: 1\nflows:\n  - name: a\n    default: generalize\n", "词表"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadMatrix(strings.NewReader(c.src), MatrixDeps{}, "test.yaml")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("报错应含 %q，实际：%v", c.want, err)
			}
		})
	}
}

// 配置里的可逆性表必须与算子的实际声明一致。
// The name-based reversibility table must agree with what the operators say.
//
// 表是为了「不构建也能校验」而存在的第二份真相，因此必须被钉住：
// 一旦某个算子改了可逆性而表没跟上，校验层就会开始批准一条静默损坏的链路。
// The table is a second source of truth that exists so validation can run
// without building, so it has to be pinned: if an operator's reversibility
// changes and the table does not, validation starts approving a silently
// broken flow.
func TestReversibilityTableMatchesOperators(t *testing.T) {
	deps := testDeps()
	var opts MatrixOptions
	for name, want := range reversibleByName {
		s, err := opts.build(name, deps)
		if err != nil {
			t.Fatalf("构造 %s 失败：%v", name, err)
		}
		if got := s.Reversible(); got != want {
			t.Errorf("%s：表里写 %v，算子说 %v", name, want, got)
		}
	}
}

// 仓库里发布的示例配置必须始终可加载。
// The example configuration shipped in the repo must always load.
func TestShippedExampleMatrixLoads(t *testing.T) {
	o, err := LoadOntologyFile("../../configs/ontology.yaml")
	if err != nil {
		t.Fatalf("发布的示例词表加载失败：%v", err)
	}
	m, err := LoadMatrixFile("../../configs/redaction-matrix.yaml", MatrixDeps{
		HashKey:    testKey(),
		TokenStore: NewMemoryTokenStore(),
		Ontology:   o,
	})
	if err != nil {
		t.Fatalf("发布的示例矩阵加载失败：%v", err)
	}
	t.Logf("\n%s", m.Describe())
}
