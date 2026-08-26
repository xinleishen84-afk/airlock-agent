package anonymize

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// # Matrix configuration
// # 矩阵配置
//
// The matrix is a policy decision, so it belongs in configuration rather than
// in code. What must not go into configuration is the material that makes the
// operators safe: the HMAC key and the token store are supplied by the process
// from a secret mount, never parsed from the same file that describes the
// policy. A key that travels with the policy file travels with every copy of
// it.
// 矩阵是策略决定，因此应当在配置里，而不是在代码里。
// 不能进配置的，是让算子安全的那部分材料：HMAC 密钥与令牌库由进程
// 从密钥挂载点提供，绝不从描述策略的同一个文件里解析。
// 与策略文件同行的密钥，会随策略文件的每一份副本一起流传。

// MatrixDeps supplies what configuration is not allowed to carry.
// 提供配置不允许携带的东西。
type MatrixDeps struct {
	// Keyring derives per-tenant keys from a root secret the caller read from
	// a secret mount.
	// 从调用方在密钥挂载点读到的根密钥派生每个租户的子密钥。
	Keyring *Keyring

	// TokenStore backs the tokenize operator.
	// 支撑令牌化算子。
	TokenStore TokenStore

	// Ontology backs the generalize operator.
	// 支撑泛化算子。
	Ontology *Ontology
}

// MatrixConfig is one matrix configuration file.
// 是一个矩阵配置文件。
type MatrixConfig struct {
	Version int           `yaml:"version"`
	Options MatrixOptions `yaml:"options"`
	Flows   []FlowConfig  `yaml:"flows"`
}

// MatrixOptions tunes the operators that take parameters.
// 调整带参数的算子。
type MatrixOptions struct {
	CharMask   CharMaskOptions   `yaml:"char_mask"`
	Hash       HashOptions       `yaml:"hash"`
	Generalize GeneralizeOptions `yaml:"generalize"`
}

// CharMaskOptions configures the character-mask operator.
// 配置掩码字符算子。
type CharMaskOptions struct {
	Char string `yaml:"char"`
	Keep int    `yaml:"keep"`
}

// HashOptions configures the keyed-hash operator.
// 配置带密钥哈希算子。
type HashOptions struct {
	Digits int `yaml:"digits"`
}

// GeneralizeOptions configures the generalizing operator.
// 配置泛化算子。
type GeneralizeOptions struct {
	Granularity string `yaml:"granularity"`
	// Fallback names the operator used for values the ontology does not cover.
	// 指定词表未覆盖的值所使用的算子。
	Fallback string `yaml:"fallback"`
}

// FlowConfig is one destination's configured policy.
// 是一个目的地的配置化策略。
type FlowConfig struct {
	Name     string            `yaml:"name"`
	Restores bool              `yaml:"restores"`
	Default  string            `yaml:"default"`
	ByType   map[string]string `yaml:"by_type"`
}

// reversibleByName records each operator's reversibility so a configuration can
// be rejected without building it.
// 记录每个算子的可逆性，使配置无需构建即可被拒绝。
//
// Checking from names alone matters because the check must run even when the
// operator cannot be built — a flow that restores and hashes is invalid whether
// or not the HMAC key happens to be mounted, and the operator error would
// otherwise mask the policy error.
// 仅凭名字检查是要紧的：这个检查必须在算子无法构建时也能跑——
// 一条既要复原又用哈希的链路，无论 HMAC 密钥是否恰好挂上都是非法的，
// 否则算子的报错会盖住策略的报错。
var reversibleByName = map[string]bool{
	"mask":       true,
	"tokenize":   true,
	"char_mask":  false,
	"hash":       false,
	"drop":       false,
	"generalize": false,
}

// strategyNames lists the operators, sorted, for error messages.
// 为报错信息列出算子名（已排序）。
func strategyNames() []string {
	out := make([]string, 0, len(reversibleByName))
	for n := range reversibleByName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// LoadMatrix parses a matrix configuration.
// 解析矩阵配置。
func LoadMatrix(r io.Reader, deps MatrixDeps, source string) (*Matrix, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var cfg MatrixConfig
	if err := dec.Decode(&cfg); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("%s：文件为空 / empty file", source)
		}
		return nil, fmt.Errorf("%s：解析失败 / parse failed: %w", source, err)
	}
	return cfg.build(deps, source)
}

// LoadMatrixFile reads a matrix configuration from a file.
// 从文件读取矩阵配置。
func LoadMatrixFile(path string, deps MatrixDeps) (*Matrix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开脱敏矩阵配置失败 / opening matrix config: %w", err)
	}
	defer f.Close()
	return LoadMatrix(f, deps, path)
}

// build validates the configuration and assembles the matrix.
// 校验配置并组装矩阵。
//
// Every flow is checked even after one fails, so an operator sees the whole
// list rather than discovering the next problem on the next restart.
// 即使某条链路已失败，其余仍会被检查，
// 于是运维一次看到全部问题，而不是每重启一次发现下一个。
func (c MatrixConfig) build(deps MatrixDeps, source string) (*Matrix, error) {
	var problems []string
	fail := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if c.Version != 1 {
		return nil, fmt.Errorf("%s：version 必须为 1，实际为 %d / version must be 1", source, c.Version)
	}
	if len(c.Flows) == 0 {
		return nil, fmt.Errorf("%s：未配置任何链路 / no flows configured", source)
	}

	// 先做纯策略校验：这一层不依赖密钥或令牌库是否就绪。
	// Policy-only validation first: independent of whether the key or store
	// happens to be available.
	for i, f := range c.Flows {
		path := fmt.Sprintf("flows[%d]", i)
		if strings.TrimSpace(f.Name) == "" {
			fail("%s：name 不能为空 / name is required", path)
		}
		if f.Default == "" {
			fail("%s：default 不能为空——没人想到的实体类型会原样放过 / default is required", path)
		}
		for _, name := range append([]string{f.Default}, sortedValues(f.ByType)...) {
			if name == "" {
				continue
			}
			if _, ok := reversibleByName[name]; !ok {
				fail("%s：未知算子 %q，可用：%s / unknown strategy",
					path, name, strings.Join(strategyNames(), ", "))
			}
		}
		if f.Restores {
			for _, pair := range orderedPairs(f.Default, f.ByType) {
				typ, name := pair[0], pair[1]
				if rev, ok := reversibleByName[name]; ok && !rev {
					fail("%s：声明 restores 却对 %s 使用不可逆算子 %q——"+
						"这类配置不会报错，只会把脱敏后的符号当作原值交给终端用户 / "+
						"%s restores but uses irreversible %q for %s",
						path, typ, name, path, name, typ)
				}
			}
		}
		for typ := range f.ByType {
			if !detect.IsBuiltinType(detect.EntityType(typ)) && !strings.HasPrefix(typ, "CUSTOM_") {
				fail("%s：by_type 中的 %q 不是已知实体类型 / unknown entity type", path, typ)
			}
		}
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("%s：脱敏矩阵配置无效 / invalid matrix config:\n  - %s",
			source, strings.Join(problems, "\n  - "))
	}

	// 再构建算子：到这一步策略本身已成立，剩下的报错都是依赖缺失。
	// Now build the operators: the policy itself already holds, so anything
	// failing here is a missing dependency.
	built := map[string]Strategy{}
	get := func(name string) (Strategy, error) {
		if s, ok := built[name]; ok {
			return s, nil
		}
		s, err := c.Options.build(name, deps)
		if err != nil {
			return nil, err
		}
		built[name] = s
		return s, nil
	}

	m := NewMatrix()
	for i, f := range c.Flows {
		def, err := get(f.Default)
		if err != nil {
			return nil, fmt.Errorf("%s flows[%d](%s)：%w", source, i, f.Name, err)
		}
		flow := Flow{Name: Destination(f.Name), Default: def, Restores: f.Restores}
		if len(f.ByType) > 0 {
			flow.ByType = make(map[detect.EntityType]Strategy, len(f.ByType))
			for typ, name := range f.ByType {
				s, err := get(name)
				if err != nil {
					return nil, fmt.Errorf("%s flows[%d](%s).by_type[%s]：%w", source, i, f.Name, typ, err)
				}
				flow.ByType[detect.EntityType(typ)] = s
			}
		}
		if err := m.Add(flow); err != nil {
			return nil, fmt.Errorf("%s：%w", source, err)
		}
	}
	return m, nil
}

// build constructs one operator by name.
// 按名字构造一个算子。
func (o MatrixOptions) build(name string, deps MatrixDeps) (Strategy, error) {
	switch name {
	case "mask":
		return NewMask(), nil

	case "drop":
		return NewDrop(), nil

	case "char_mask":
		char := '*'
		if o.CharMask.Char != "" {
			runes := []rune(o.CharMask.Char)
			if len(runes) != 1 {
				return nil, fmt.Errorf("%w: options.char_mask.char 必须是单个字符 / must be one character",
					ErrStrategy)
			}
			char = runes[0]
		}
		return NewCharMask(char, o.CharMask.Keep), nil

	case "hash":
		digits := o.Hash.Digits
		if digits == 0 {
			digits = 8
		}
		if deps.Keyring == nil {
			return nil, fmt.Errorf(
				"%w: 配置使用了 hash 算子但未提供密钥环——"+
					"根密钥必须来自密钥挂载点，不能写在配置文件里 / hash requires a keyring",
				ErrStrategy)
		}
		return NewHash(deps.Keyring, digits)

	case "tokenize":
		if deps.TokenStore == nil {
			return nil, fmt.Errorf("%w: 配置使用了 tokenize 算子但未提供令牌库 / tokenize requires a token store",
				ErrStrategy)
		}
		return NewTokenize(deps.TokenStore)

	case "generalize":
		if deps.Ontology == nil {
			return nil, fmt.Errorf("%w: 配置使用了 generalize 算子但未加载本体词表 / generalize requires an ontology",
				ErrStrategy)
		}
		gran := dateGranularity(o.Generalize.Granularity)
		if gran == "" {
			gran = GranularityDecade
		}
		fallbackName := o.Generalize.Fallback
		if fallbackName == "" {
			fallbackName = "drop"
		}
		if fallbackName == "generalize" {
			return nil, fmt.Errorf("%w: generalize 的兜底算子不能是它自己 / fallback must not be generalize",
				ErrStrategy)
		}
		fallback, err := o.build(fallbackName, deps)
		if err != nil {
			return nil, fmt.Errorf("构造 generalize 的兜底算子失败 / building generalize fallback: %w", err)
		}
		return NewGeneralize(deps.Ontology, gran, fallback)
	}
	return nil, fmt.Errorf("%w: 未知算子 %q / unknown strategy", ErrStrategy, name)
}

// sortedValues returns a map's values in a stable order.
// 以稳定顺序返回 map 的值。
func sortedValues(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

// orderedPairs yields the default plus each override in a stable order.
// 以稳定顺序给出默认算子与各类型覆盖。
//
// A slice rather than a map: map iteration order is randomized, and an error
// list whose order changes between runs is one an operator cannot diff.
// 用切片而非 map：map 的迭代顺序是随机的，
// 而一份每次运行顺序都不同的报错清单，运维没法拿去做 diff。
func orderedPairs(def string, byType map[string]string) [][2]string {
	out := [][2]string{{"默认 / default", def}}
	keys := make([]string, 0, len(byType))
	for k := range byType {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, [2]string{k, byType[k]})
	}
	return out
}
