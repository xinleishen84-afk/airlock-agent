package packs

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// # Tenant rule packs
// # 租户规则包
//
// Country packs cover what jurisdictions define. They cannot cover what an
// individual company defines: an internal employee number, an asset tag, a
// contract ID. Those formats are known only to the tenant, change without
// notice, and are worthless to anyone else — the three properties that make
// them a configuration input rather than library code.
// 国家包覆盖司法管辖区定义的东西。它们无法覆盖单个公司自己定义的东西：
// 内部工号、资产编号、合同号。这些格式只有租户知道、说改就改、
// 对别人毫无价值——这三点正说明它们该是配置输入，而不是库代码。
//
// The hazard of a YAML rule engine is that it lets a non-engineer write a rule
// that silently matches nothing. Every failure mode here is silent: a prefilter
// the pattern does not imply, a boundary class that rejects every real
// occurrence, a validator that rejects the tenant's own format. All three
// register cleanly and report success while scanning past the data they were
// written to catch.
// YAML 规则引擎的风险在于：它让非工程师能写出一条静默匹配不到任何东西的规则。
// 这里的每种故障模式都是静默的——模式并不蕴含的前置过滤、
// 拒绝一切真实出现的边界类、拒绝租户自身格式的校验器。
// 这三者都能干净地注册、报告成功，同时从它们本该捕获的数据上扫过。
//
// The countermeasure is that samples are mandatory. A rule ships with the
// strings it must catch and the strings it must not, and the loader runs them
// through the assembled recognizer before accepting it. A rule that matches
// nothing fails to load instead of failing to protect.
// 对策是：样本是强制的。一条规则必须自带「它必须命中」与「它必须不命中」的字符串，
// 加载器在接受它之前，先把这些样本喂给组装好的识别器跑一遍。
// 于是「匹配不到任何东西」的规则会加载失败，而不是保护失败。

// TenantRules is one tenant rule file.
// 是一个租户规则文件。
type TenantRules struct {
	// Version pins the schema. An unrecognized version is an error, so a file
	// written for a future schema is never silently reinterpreted.
	// 固定 schema 版本。无法识别的版本视为错误，
	// 因此为未来 schema 写的文件绝不会被静默地按旧语义解释。
	Version int `yaml:"version"`

	// Tenant labels the owner; it prefixes every rule name so audit output can
	// attribute a detection to the tenant that configured it.
	// 标注归属方；它会作为每条规则名的前缀，
	// 使审计输出能把一次检出归因到配置它的租户。
	Tenant string `yaml:"tenant"`

	Rules []TenantRule `yaml:"rules"`
}

// TenantRule is one custom recognizer.
// 是一条自定义识别器。
type TenantRule struct {
	Name    string  `yaml:"name"`
	Type    string  `yaml:"type"`
	Pattern string  `yaml:"pattern"`
	Score   float64 `yaml:"score"`

	// Boundary is none | digit | digit_sep | alnum.
	// 取值 none | digit | digit_sep | alnum。
	Boundary string `yaml:"boundary"`

	// Validator names a check-digit algorithm from the built-in table. Tenants
	// cannot supply code; an unknown name is an error.
	// 从内置表中指定一个校验位算法。租户不能提供代码；未知名称视为错误。
	Validator string `yaml:"validator"`

	// StripSeparators removes spaces and hyphens before validation, for formats
	// written in groups.
	// 校验前去掉空格与连字符，用于分组书写的格式。
	StripSeparators bool `yaml:"strip_separators"`

	Context   *ruleContext   `yaml:"context"`
	Prefilter *rulePrefilter `yaml:"prefilter"`
	Samples   ruleSamples    `yaml:"samples"`
}

type ruleContext struct {
	Boost  float64  `yaml:"boost"`
	Window int      `yaml:"window"`
	Words  []string `yaml:"words"`
}

type rulePrefilter struct {
	Prefix     []string `yaml:"prefix"`
	Bytes      string   `yaml:"bytes"`
	Digit      bool     `yaml:"digit"`
	UpperAlpha bool     `yaml:"upper_alpha"`
	CJK        bool     `yaml:"cjk"`
}

// ruleSamples is the rule's own test suite, run at load time.
// 是规则自带的测试用例，在加载期执行。
type ruleSamples struct {
	// Match holds bare values. Each must yield exactly one entity spanning the
	// entire string — a partial match means the pattern is wrong about where
	// the value ends.
	// 存放裸值。每一个都必须恰好产出一个覆盖整串的实体——
	// 部分匹配意味着模式对值的结束位置判断有误。
	Match []string `yaml:"match"`

	// NoMatch holds arbitrary text that must yield nothing. This is where a
	// tenant encodes the near-miss that a naive pattern would swallow: the
	// order number that looks like an employee ID.
	// 存放必须零命中的任意文本。租户在这里编码那些朴素模式会误吞的近似串：
	// 那个长得像工号的订单号。
	NoMatch []string `yaml:"no_match"`
}

// namedValidators is the closed set of check-digit algorithms a tenant rule may
// reference by name.
// 是租户规则可按名引用的校验位算法的封闭集合。
var namedValidators = map[string]func(string) bool{
	"luhn":              detect.LuhnValid,
	"bank_card":         detect.BankCardLuhnValid,
	"cn_id_card":        detect.CNIDCardValid,
	"cn_uscc":           detect.CNUSCCValid,
	"iban":              detect.IBANValid,
	"it_codice_fiscale": detect.ItalyCodiceFiscaleValid,
	"de_steuer_id":      detect.GermanyTaxIDValid,
	"es_dni":            detect.SpainDNIValid,
}

var boundaryNames = map[string]detect.BoundaryClass{
	"":          detect.BoundaryNone,
	"none":      detect.BoundaryNone,
	"digit":     detect.BoundaryDigit,
	"digit_sep": detect.BoundaryDigitSep,
	"alnum":     detect.BoundaryAlnum,
}

// ruleNamePattern keeps rule names greppable in audit logs.
// 保证规则名在审计日志中可被 grep。
var ruleNamePattern = regexp.MustCompile(`^[a-z0-9]+(?:_[a-z0-9]+)*$`)

// tenantNamePattern applies the same constraint to the tenant label.
// 对租户标签施加同样的约束。
var tenantNamePattern = regexp.MustCompile(`^[a-z0-9]+(?:[-_][a-z0-9]+)*$`)

// LoadYAML parses tenant rules from r and returns the recognizers.
// 从 r 解析租户规则并返回识别器。
//
// Unknown fields are rejected. A misspelled key would otherwise be dropped in
// silence, and the keys that matter here are the ones that constrain matching —
// a dropped "boundary" widens the rule rather than breaking it.
// 未知字段一律拒绝。否则拼错的键会被静默丢弃，
// 而这里要紧的键恰恰是那些收紧匹配的键——
// 丢掉一个 "boundary" 会让规则变宽，而不是让它报错。
func LoadYAML(r io.Reader, source string) ([]detect.Recognizer, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var doc TenantRules
	if err := dec.Decode(&doc); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("%s：文件为空 / empty file", source)
		}
		return nil, fmt.Errorf("%s：解析失败 / parse failed: %w", source, err)
	}
	// A second document in the same file would be ignored entirely.
	// 同一文件中的第二个 YAML 文档会被完全忽略。
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("%s：不支持多文档 YAML / multi-document YAML not supported", source)
	}
	return doc.build(source)
}

// LoadYAMLFile reads one tenant rule file.
// 读取一个租户规则文件。
func LoadYAMLFile(path string) ([]detect.Recognizer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开租户规则失败 / opening tenant rules: %w", err)
	}
	defer f.Close()
	return LoadYAML(f, filepath.Base(path))
}

// LoadYAMLDir reads every .yaml/.yml file in dir, in sorted order.
// 按排序顺序读取 dir 下的每个 .yaml/.yml 文件。
//
// An empty directory is an error. Mounting the wrong ConfigMap is a routine
// deployment mistake, and its signature — zero custom rules loaded — is
// indistinguishable from success unless the loader says so.
// 空目录视为错误。挂错 ConfigMap 是常见的部署失误，
// 而它的表征——加载了零条自定义规则——除非加载器出声，
// 否则与成功无法区分。
func LoadYAMLDir(dir string) ([]detect.Recognizer, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".yaml", ".yml":
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("遍历租户规则目录失败 / walking tenant rules dir: %w", err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("目录 %s 中没有 .yaml 规则文件 / no .yaml rule files in %s", dir, dir)
	}
	sort.Strings(paths)

	var out []detect.Recognizer
	for _, p := range paths {
		recs, err := LoadYAMLFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, recs...)
	}
	return out, nil
}

// LoadYAMLInto loads tenant rules from dir and registers them.
// 从 dir 加载租户规则并注册。
func LoadYAMLInto(reg *detect.Registry, dir string) error {
	recs, err := LoadYAMLDir(dir)
	if err != nil {
		return err
	}
	for _, r := range recs {
		if err := reg.Register(r); err != nil {
			return fmt.Errorf("注册租户识别器 %s 失败 / registering %s: %w", r.Name(), r.Name(), err)
		}
	}
	return nil
}

// build validates the document and assembles its recognizers.
// 校验文档并组装识别器。
//
// Every rule is checked even after one fails, so an operator fixing a rule file
// sees the whole list rather than discovering the next problem on the next
// restart.
// 即使某条规则已失败，其余规则仍会被检查，
// 于是修文件的运维一次看到全部问题，而不是每重启一次发现下一个。
func (d TenantRules) build(source string) ([]detect.Recognizer, error) {
	var problems []string
	fail := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if d.Version != 1 {
		return nil, fmt.Errorf("%s：version 必须为 1，实际为 %d / version must be 1, got %d",
			source, d.Version, d.Version)
	}
	if !tenantNamePattern.MatchString(d.Tenant) {
		fail("tenant %q 非法，须为小写字母数字并以 - 或 _ 分隔 / invalid tenant label", d.Tenant)
	}
	if len(d.Rules) == 0 {
		fail("rules 为空 / no rules declared")
	}

	seen := map[string]bool{}
	out := make([]detect.Recognizer, 0, len(d.Rules))

	for i, rule := range d.Rules {
		rec, err := rule.build(d.Tenant)
		if err != nil {
			fail("rules[%d]：%v", i, err)
			continue
		}
		if seen[rec.Name()] {
			fail("rules[%d]：识别器名 %s 重复 / duplicate recognizer name", i, rec.Name())
			continue
		}
		seen[rec.Name()] = true
		out = append(out, rec)
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("%s：租户规则校验失败 / tenant rules invalid:\n  - %s",
			source, strings.Join(problems, "\n  - "))
	}
	return out, nil
}

// build assembles and self-tests one rule.
// 组装并自测一条规则。
func (r TenantRule) build(tenant string) (detect.Recognizer, error) {
	if !ruleNamePattern.MatchString(r.Name) {
		return nil, fmt.Errorf("name %q 非法，须为小写字母数字并以 _ 分隔 / invalid rule name", r.Name)
	}
	typ, err := r.entityType()
	if err != nil {
		return nil, err
	}
	boundary, ok := boundaryNames[r.Boundary]
	if !ok {
		return nil, fmt.Errorf("boundary %q 未知，可用 none|digit|digit_sep|alnum / unknown boundary",
			r.Boundary)
	}
	if r.Pattern == "" {
		return nil, fmt.Errorf("pattern 不能为空 / pattern is required")
	}
	// A pattern that can match the empty string matches at every byte offset.
	// 能匹配空串的模式会在每个字节偏移处命中。
	if probe, err := regexp.Compile(r.Pattern); err == nil && probe.MatchString("") {
		return nil, fmt.Errorf("pattern 可匹配空串 / pattern matches the empty string")
	}

	opts := []detect.PatternOption{detect.WithBoundary(boundary)}

	if r.Validator != "" {
		fn, ok := namedValidators[r.Validator]
		if !ok {
			return nil, fmt.Errorf("validator %q 未知，可用 %v / unknown validator",
				r.Validator, sortedValidatorNames())
		}
		opts = append(opts, detect.WithValidator(fn, r.StripSeparators))
	} else if r.StripSeparators {
		return nil, fmt.Errorf("strip_separators 需要同时设置 validator / strip_separators requires a validator")
	}

	if c := r.Context; c != nil {
		if len(c.Words) == 0 {
			return nil, fmt.Errorf("context.words 不能为空 / context.words is required when context is set")
		}
		if c.Boost <= 0 || c.Boost > 1 {
			return nil, fmt.Errorf("context.boost 须在 (0,1]，实际 %v / context.boost must be in (0,1]", c.Boost)
		}
		opts = append(opts, detect.WithContext(c.Boost, c.Words...))
		if c.Window > 0 {
			opts = append(opts, detect.WithContextWindow(c.Window))
		}
	}

	if p := r.Prefilter; p != nil {
		f, err := p.build()
		if err != nil {
			return nil, err
		}
		opts = append(opts, detect.WithPrefilter(f))
	}

	name := tenant + "/" + r.Name
	rec, err := detect.NewPatternRecognizer(name, typ, r.Pattern, r.Score, opts...)
	if err != nil {
		return nil, err
	}
	if err := selfTest(rec, r.Samples); err != nil {
		return nil, err
	}
	return rec, nil
}

// entityType resolves the declared type, allowing tenant-specific types only
// under an explicit CUSTOM_ prefix.
// 解析声明的类型；租户自有类型只允许在显式的 CUSTOM_ 前缀下存在。
//
// Without the prefix rule, a typo lands in the same namespace as the built-in
// types and looks like one. With it, anything unrecognized is either a known
// type or visibly not a type this library knows about.
// 没有前缀规则，拼错的类型会落进与内置类型相同的命名空间，看上去就像内置的。
// 有了它，任何无法识别的东西，要么是已知类型，要么显然不是本库认识的类型。
func (r TenantRule) entityType() (detect.EntityType, error) {
	if r.Type == "" {
		return "", fmt.Errorf("type 不能为空 / type is required")
	}
	t := detect.EntityType(r.Type)
	if detect.IsBuiltinType(t) {
		return t, nil
	}
	if strings.HasPrefix(r.Type, "CUSTOM_") && len(r.Type) > len("CUSTOM_") {
		return t, nil
	}
	return "", fmt.Errorf(
		"type %q 未知；内置类型为 %v，租户自有类型须以 CUSTOM_ 开头 / unknown type",
		r.Type, detect.BuiltinTypes())
}

// build turns the declared conditions into a single prefilter.
// 把声明的各项条件合成一个前置过滤器。
func (p rulePrefilter) build() (detect.Prefilter, error) {
	var parts []detect.Prefilter
	if len(p.Prefix) > 0 {
		for _, lit := range p.Prefix {
			if lit == "" {
				return nil, fmt.Errorf("prefilter.prefix 含空字符串 / empty literal in prefilter.prefix")
			}
		}
		parts = append(parts, detect.RequirePrefix(p.Prefix...))
	}
	if p.Bytes != "" {
		parts = append(parts, detect.RequireByte(p.Bytes))
	}
	if p.Digit {
		parts = append(parts, detect.RequireDigit)
	}
	if p.UpperAlpha {
		parts = append(parts, detect.RequireUpperAlpha)
	}
	if p.CJK {
		parts = append(parts, detect.RequireCJK)
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("prefilter 已声明但为空 / prefilter declared but empty")
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	// Conditions are conjunctive: all must hold for the regex to run.
	// 各条件取合取：全部成立时才运行正则。
	return func(text string) bool {
		for _, f := range parts {
			if !f(text) {
				return false
			}
		}
		return true
	}, nil
}

// selfTest runs the rule's samples through the assembled recognizer.
// 把规则的样本喂给组装好的识别器跑一遍。
func selfTest(rec detect.Recognizer, s ruleSamples) error {
	if len(s.Match) == 0 {
		return fmt.Errorf("samples.match 不能为空：规则必须自带它必须命中的值 / samples.match is required")
	}
	for _, sample := range s.Match {
		ents, err := rec.Recognize(sample)
		if err != nil {
			return fmt.Errorf("样本 %q 检测出错 / recognizing sample %q: %w", sample, sample, err)
		}
		if len(ents) != 1 {
			return fmt.Errorf(
				"samples.match 中的 %q 命中 %d 次，应为恰好 1 次 / matched %d times, want exactly 1",
				sample, len(ents), len(ents))
		}
		if ents[0].Start != 0 || ents[0].End != len(sample) {
			return fmt.Errorf(
				"samples.match 中的 %q 只命中片段 %q，模式未覆盖整个值 / partial match %q",
				sample, sample[ents[0].Start:ents[0].End], sample[ents[0].Start:ents[0].End])
		}
	}
	for _, sample := range s.NoMatch {
		ents, err := rec.Recognize(sample)
		if err != nil {
			return fmt.Errorf("反例 %q 检测出错 / recognizing counter-sample %q: %w", sample, sample, err)
		}
		if len(ents) > 0 {
			return fmt.Errorf(
				"samples.no_match 中的 %q 被误命中为 %q / counter-sample matched as %q",
				sample, ents[0].Value, ents[0].Value)
		}
	}
	return nil
}

// sortedValidatorNames lists the built-in validators for error messages.
// 为报错信息列出内置校验器名。
func sortedValidatorNames() []string {
	out := make([]string, 0, len(namedValidators))
	for name := range namedValidators {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
