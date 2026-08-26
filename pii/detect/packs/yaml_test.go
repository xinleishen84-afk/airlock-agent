package packs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodRules = `
version: 1
tenant: acme-corp
rules:
  - name: employee_id
    type: CUSTOM_EMPLOYEE_ID
    pattern: 'ACME-[0-9]{6}'
    score: 0.9
    boundary: alnum
    prefilter:
      prefix: ["ACME-"]
    context:
      boost: 0.15
      words: ["工号", "employee"]
    samples:
      match: ["ACME-123456"]
      no_match: ["ACME-12345", "acme-123456", "XACME-123456"]
`

func loadString(t *testing.T, src string) ([]string, error) {
	t.Helper()
	recs, err := LoadYAML(strings.NewReader(src), "test.yaml")
	names := make([]string, 0, len(recs))
	for _, r := range recs {
		names = append(names, r.Name())
	}
	return names, err
}

func TestTenantRulesLoadAndDetect(t *testing.T) {
	recs, err := LoadYAML(strings.NewReader(goodRules), "test.yaml")
	if err != nil {
		t.Fatalf("加载失败 / load failed: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("期望 1 条识别器，得到 %d", len(recs))
	}
	if got := recs[0].Name(); got != "acme-corp/employee_id" {
		t.Fatalf("识别器名应带租户前缀，得到 %q", got)
	}
	ents, err := recs[0].Recognize("请把工号 ACME-778899 的权限撤销")
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Value != "ACME-778899" {
		t.Fatalf("检出结果不符：%+v", ents)
	}
	if ents[0].Confidence <= 0.9 {
		t.Fatalf("上下文词「工号」应提升置信度，得到 %v", ents[0].Confidence)
	}
}

// 这是本文件的核心用例：一条静默匹配不到任何东西的规则必须加载失败。
// The headline case: a rule that silently matches nothing must fail to load.
func TestPrefilterNotImpliedByPatternIsRejected(t *testing.T) {
	src := `
version: 1
tenant: acme
rules:
  - name: asset_tag
    type: CUSTOM_ASSET
    pattern: 'ASSET-[A-Z]{6}'
    score: 0.9
    prefilter:
      digit: true
    samples:
      match: ["ASSET-ABCDEF"]
`
	_, err := loadString(t, src)
	if err == nil {
		t.Fatal("前置过滤器与模式矛盾，应加载失败")
	}
	if !strings.Contains(err.Error(), "命中 0 次") {
		t.Fatalf("报错应指出样本零命中，实际：%v", err)
	}
	t.Logf("按预期拒绝：%v", err)
}

func TestCounterSampleCatchesOverbroadPattern(t *testing.T) {
	src := `
version: 1
tenant: acme
rules:
  - name: contract_no
    type: CUSTOM_CONTRACT
    pattern: '[0-9]{8}'
    score: 0.8
    samples:
      match: ["20240131"]
      no_match: ["订单号 87654321 已发货"]
`
	_, err := loadString(t, src)
	if err == nil {
		t.Fatal("过宽的模式应被反例拦下")
	}
	if !strings.Contains(err.Error(), "no_match") {
		t.Fatalf("报错应指向 no_match，实际：%v", err)
	}
	t.Logf("按预期拒绝：%v", err)
}

func TestPartialMatchIsRejected(t *testing.T) {
	src := `
version: 1
tenant: acme
rules:
  - name: badge
    type: CUSTOM_BADGE
    pattern: 'B[0-9]{4}'
    score: 0.8
    samples:
      match: ["B1234567"]
`
	_, err := loadString(t, src)
	if err == nil || !strings.Contains(err.Error(), "只命中片段") {
		t.Fatalf("部分命中应被拒绝，实际：%v", err)
	}
	t.Logf("按预期拒绝：%v", err)
}

func TestStrictFieldsAndEnums(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "拼错的字段名",
			src: `
version: 1
tenant: acme
rules:
  - name: r1
    type: CUSTOM_X
    patern: 'X[0-9]{4}'
    score: 0.8
    samples: {match: ["X1234"]}
`,
			want: "field patern not found",
		},
		{
			name: "拼错的实体类型",
			src: `
version: 1
tenant: acme
rules:
  - name: r1
    type: ID_CRAD
    pattern: 'X[0-9]{4}'
    score: 0.8
    samples: {match: ["X1234"]}
`,
			want: "CUSTOM_",
		},
		{
			name: "未知边界类",
			src: `
version: 1
tenant: acme
rules:
  - name: r1
    type: CUSTOM_X
    pattern: 'X[0-9]{4}'
    score: 0.8
    boundary: word
    samples: {match: ["X1234"]}
`,
			want: "unknown boundary",
		},
		{
			name: "未知校验器",
			src: `
version: 1
tenant: acme
rules:
  - name: r1
    type: CUSTOM_X
    pattern: 'X[0-9]{4}'
    score: 0.8
    validator: mod97
    samples: {match: ["X1234"]}
`,
			want: "unknown validator",
		},
		{
			name: "缺少样本",
			src: `
version: 1
tenant: acme
rules:
  - name: r1
    type: CUSTOM_X
    pattern: 'X[0-9]{4}'
    score: 0.8
`,
			want: "samples.match",
		},
		{
			name: "可匹配空串",
			src: `
version: 1
tenant: acme
rules:
  - name: r1
    type: CUSTOM_X
    pattern: '[0-9]*'
    score: 0.8
    samples: {match: ["1234"]}
`,
			want: "empty string",
		},
		{
			name: "版本不符",
			src: `
version: 2
tenant: acme
rules: []
`,
			want: "version must be 1",
		},
		{
			name: "规则名非法",
			src: `
version: 1
tenant: acme
rules:
  - name: EmployeeID
    type: CUSTOM_X
    pattern: 'X[0-9]{4}'
    score: 0.8
    samples: {match: ["X1234"]}
`,
			want: "invalid rule name",
		},
		{
			name: "重名规则",
			src: `
version: 1
tenant: acme
rules:
  - name: r1
    type: CUSTOM_X
    pattern: 'X[0-9]{4}'
    score: 0.8
    samples: {match: ["X1234"]}
  - name: r1
    type: CUSTOM_Y
    pattern: 'Y[0-9]{4}'
    score: 0.8
    samples: {match: ["Y1234"]}
`,
			want: "duplicate recognizer name",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadString(t, tc.src)
			if err == nil {
				t.Fatal("应当加载失败")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("报错应含 %q，实际：%v", tc.want, err)
			}
		})
	}
}

// 一次报出全部问题，而不是每重启一次发现下一个。
// All problems reported at once, not one per restart.
func TestAllProblemsReportedTogether(t *testing.T) {
	src := `
version: 1
tenant: acme
rules:
  - name: Bad-Name
    type: CUSTOM_X
    pattern: 'X[0-9]{4}'
    score: 0.8
    samples: {match: ["X1234"]}
  - name: r2
    type: NOPE
    pattern: 'Y[0-9]{4}'
    score: 0.8
    samples: {match: ["Y1234"]}
  - name: r3
    type: CUSTOM_Z
    pattern: 'Z[0-9]{4}'
    score: 0.8
    samples: {match: ["Z12345"]}
`
	_, err := loadString(t, src)
	if err == nil {
		t.Fatal("应当加载失败")
	}
	if n := strings.Count(err.Error(), "\n  - "); n != 3 {
		t.Fatalf("应一次报出 3 个问题，实际 %d：%v", n, err)
	}
	t.Logf("一次报出全部问题：\n%v", err)
}

func TestLoadYAMLDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(goodRules), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err := LoadYAMLDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("期望 1 条，得到 %d", len(recs))
	}

	// 挂错 ConfigMap：零条规则必须出声，而不是读作成功。
	// Wrong ConfigMap mounted: zero rules must speak up, not read as success.
	empty := t.TempDir()
	if _, err := LoadYAMLDir(empty); err == nil {
		t.Fatal("空目录应报错")
	}
}

func TestValidatorFromYAML(t *testing.T) {
	src := `
version: 1
tenant: bank
rules:
  - name: internal_card
    type: BANK_CARD
    pattern: '[0-9]{16}'
    score: 0.85
    boundary: digit_sep
    validator: luhn
    samples:
      match: ["4111111111111111"]
      no_match: ["4111111111111112"]
`
	names, err := loadString(t, src)
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if names[0] != "bank/internal_card" {
		t.Fatalf("名称不符：%v", names)
	}
}

// 仓库里发布的示例规则文件必须始终可加载。
// The example rule file shipped in the repo must always load.
//
// 文档里的示例一旦失效，就成了最难发现的错误来源：读者照抄它，
// 得到一条加载失败的规则，然后合理地怀疑是自己写错了。
// A stale example is the worst kind of documentation error: the reader copies
// it, gets a rule that will not load, and reasonably suspects themselves.
func TestShippedExampleFileLoads(t *testing.T) {
	const dir = "../../../configs/tenant-rules"
	recs, err := LoadYAMLDir(dir)
	if err != nil {
		t.Fatalf("发布的示例规则加载失败：%v", err)
	}
	if len(recs) == 0 {
		t.Fatal("示例目录没有产出任何识别器")
	}
	for _, r := range recs {
		t.Logf("%s (%s)", r.Name(), r.EntityType())
	}
}
