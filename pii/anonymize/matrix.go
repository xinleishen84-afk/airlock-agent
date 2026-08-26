package anonymize

import (
	"fmt"
	"sort"
	"strings"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// # The strategy matrix
// # 脱敏策略矩阵
//
// One operator for the whole gateway is one decision made once, by someone who
// was thinking about one destination. The same request body may fan out to a
// public-cloud model, an analytics warehouse and a cold archive, and the right
// operator differs for each: the model needs coreference, the warehouse needs
// joinable pseudonyms, the archive needs the bytes gone.
// 整个网关一个算子，等于让某个只想着一个去向的人，一次性做完了所有决定。
// 同一份请求体可能同时扇出到公有云模型、分析数仓和冷归档，
// 而三者要的算子并不相同：模型需要指代一致，数仓需要可关联的假名，
// 归档需要字节消失。
//
// The matrix is (destination × entity type) → operator, with a per-destination
// default so the common case stays one line.
// 矩阵是「目的地 × 实体类型 → 算子」，每个目的地带一个默认值，
// 使常见情形只占一行。

// Destination names a data flow.
// 标识一条数据流向。
type Destination string

// Flow is one destination's redaction policy.
// 是一个目的地的脱敏策略。
type Flow struct {
	// Name identifies the destination in configuration and audit output.
	// 在配置与审计输出中标识该目的地。
	Name Destination

	// Default applies to every entity type without an explicit override.
	// 适用于所有没有显式覆盖的实体类型。
	//
	// Required. A flow with no default would have to fall through to "leave the
	// value alone" for any type nobody thought about — and the types nobody
	// thought about are exactly the ones that leak.
	// 必填。没有默认值的链路，遇到没人想到的类型只能「原样放过」——
	// 而没人想到的类型恰恰就是会泄露的那些。
	Default Strategy

	// ByType overrides the default for specific entity types.
	// 为特定实体类型覆盖默认算子。
	ByType map[detect.EntityType]Strategy

	// Restores declares that responses from this destination are un-redacted
	// before reaching the end user.
	// 声明来自该目的地的响应会在到达终端用户前被复原。
	//
	// Setting it constrains every operator on this flow to be reversible, and
	// that check is the reason this field exists. Without it the failure is
	// silent end to end: the request leaves correctly hashed, the model answers
	// with the hash, and the gateway hands "[hash:name:a4b2efc8]" to the user
	// as a person's name.
	// 设置它会约束本链路的每个算子都必须可逆，而这个检查正是本字段存在的理由。
	// 没有它，故障从头到尾都是静默的：请求带着正确的哈希出站，
	// 模型用哈希作答，网关把 "[hash:name:a4b2efc8]" 当作人名交给用户。
	Restores bool
}

// Matrix resolves (destination, entity type) to an operator.
// 把「目的地 + 实体类型」解析为算子。
type Matrix struct {
	flows map[Destination]Flow
}

// NewMatrix builds an empty matrix.
// 构造空矩阵。
func NewMatrix() *Matrix { return &Matrix{flows: map[Destination]Flow{}} }

// Add registers a flow, rejecting one that cannot work.
// 注册一条链路，拒绝无法成立的配置。
func (m *Matrix) Add(f Flow) error {
	if strings.TrimSpace(string(f.Name)) == "" {
		return fmt.Errorf("链路名不能为空 / flow name is required")
	}
	if _, dup := m.flows[f.Name]; dup {
		return fmt.Errorf("链路 %q 重复注册 / duplicate flow %q", f.Name, f.Name)
	}
	if f.Default == nil {
		return fmt.Errorf("链路 %q 缺少默认算子——没人想到的实体类型会原样放过 / flow %q has no default",
			f.Name, f.Name)
	}

	if f.Restores {
		var bad []string
		if !f.Default.Reversible() {
			bad = append(bad, fmt.Sprintf("默认算子 %s", f.Default.Name()))
		}
		for _, typ := range sortedTypes(f.ByType) {
			if s := f.ByType[typ]; !s.Reversible() {
				bad = append(bad, fmt.Sprintf("%s 使用 %s", typ, s.Name()))
			}
		}
		if len(bad) > 0 {
			return fmt.Errorf(
				"链路 %q 声明要复原响应，但使用了不可逆算子：%s。"+
					"这类配置不会报错，只会把脱敏后的符号当作原值交给终端用户 / "+
					"flow %q restores responses but uses irreversible operators: %s",
				f.Name, strings.Join(bad, "、"), f.Name, strings.Join(bad, ", "))
		}
	}

	clone := Flow{Name: f.Name, Default: f.Default, Restores: f.Restores}
	if len(f.ByType) > 0 {
		clone.ByType = make(map[detect.EntityType]Strategy, len(f.ByType))
		for k, v := range f.ByType {
			if v == nil {
				return fmt.Errorf("链路 %q 的类型 %s 配了空算子 / nil strategy for %s", f.Name, k, k)
			}
			clone.ByType[k] = v
		}
	}
	m.flows[f.Name] = clone
	return nil
}

// MustAdd is Add for package-level initialisation and tests.
// 是供包级初始化与测试使用的 Add。
func (m *Matrix) MustAdd(f Flow) *Matrix {
	if err := m.Add(f); err != nil {
		panic(err)
	}
	return m
}

// Flow returns a destination's policy.
// 返回某个目的地的策略。
//
// An unknown destination is an error rather than a fallback to some default
// flow. Falling back would send data somewhere real under a policy written for
// somewhere else, which is worse than not sending it.
// 未知目的地视为错误，而不是回退到某条默认链路。
// 回退意味着数据带着为别处写的策略真的发了出去，这比不发更糟。
func (m *Matrix) Flow(dest Destination) (Flow, error) {
	f, ok := m.flows[dest]
	if !ok {
		return Flow{}, fmt.Errorf("未知的数据流向 %q，已配置：%s / unknown destination %q, configured: %s",
			dest, strings.Join(m.Destinations(), ", "), dest, strings.Join(m.Destinations(), ", "))
	}
	return f, nil
}

// Strategy resolves the operator for one entity on one flow.
// 解析某条链路上某个实体应使用的算子。
func (f Flow) Strategy(typ detect.EntityType) Strategy {
	if s, ok := f.ByType[typ]; ok {
		return s
	}
	return f.Default
}

// Destinations lists configured destinations, sorted.
// 列出已配置的目的地（已排序）。
func (m *Matrix) Destinations() []string {
	out := make([]string, 0, len(m.flows))
	for d := range m.flows {
		out = append(out, string(d))
	}
	sort.Strings(out)
	return out
}

// Describe renders the matrix as a table.
// 把矩阵渲染成表格。
//
// Exists because a redaction policy nobody can read is a redaction policy
// nobody reviews. This is the artefact an auditor asks for, and it should be
// producible from the running process rather than from the config file someone
// believes is deployed.
// 它存在的理由是：没人读得懂的脱敏策略，就是没人评审的脱敏策略。
// 这是审计会索取的那份材料，而它应当能从正在运行的进程里产出，
// 而不是从某个人以为已经部署了的配置文件里产出。
func (m *Matrix) Describe() string {
	var b strings.Builder
	for _, name := range m.Destinations() {
		f := m.flows[Destination(name)]
		restore := "否 / no"
		if f.Restores {
			restore = "是 / yes"
		}
		fmt.Fprintf(&b, "%s（复原响应：%s）\n", name, restore)
		fmt.Fprintf(&b, "  * 默认 / default        %s\n", f.Default.Name())
		for _, typ := range sortedTypes(f.ByType) {
			fmt.Fprintf(&b, "  %-20s %s\n", typ, f.ByType[typ].Name())
		}
	}
	return b.String()
}

// sortedTypes returns a map's entity types in a stable order.
// 以稳定顺序返回 map 中的实体类型。
func sortedTypes(m map[detect.EntityType]Strategy) []detect.EntityType {
	out := make([]detect.EntityType, 0, len(m))
	for t := range m {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
