package nerclient

import (
	"fmt"
	"sort"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// # 线上类型名与本端类型名的映射
// # Mapping wire type names to local ones
//
// 契约里的类型名是 Python 侧的词表（PERSON_NAME / LOCATION / ORGANIZATION），
// 而 Go 侧的 detect.EntityType 用的是 NAME / ADDRESS / ORG。两套词表都合理，
// 但它们不相等——而不相等的后果是静默的：
//
// The contract uses the Python vocabulary while detect.EntityType uses another.
// Both are reasonable, and they are not equal — with silent consequences:
//
//   - 脱敏策略矩阵按类型选算子，一个它不认识的类型会走默认算子
//   - 证据链按类型索引，PERSON_NAME 找不到 TypeName 那条链，
//     于是代码误判过滤、地址边界拉伸统统不生效
//   - 覆盖度自检会报告「NAME 完全裸奔」，而实际上人名一直在被检出
//
//   - The strategy matrix selects an operator by type; an unknown type takes
//     the default
//   - Evidence chains are keyed by type, so PERSON_NAME never finds the
//     TypeName chain and neither the code filter nor the address expander runs
//   - The coverage check reports NAME as uncovered while names are in fact
//     being found
//
// 三样都不会报错。这个映射是发现它的那次端到端测试留下的。
// None of the three errors. This map is what that end-to-end test left behind.

// wireToLocal maps contract type names onto detect.EntityType.
// 把契约里的类型名映射到 detect.EntityType。
var wireToLocal = map[string]detect.EntityType{
	"PERSON_NAME":  detect.TypeName,
	"PERSON":       detect.TypeName,
	"ORGANIZATION": detect.TypeOrg,
	"ORG":          detect.TypeOrg,
	"LOCATION":     detect.TypeAddress,
	"GPE":          detect.TypeAddress,
	"LOC":          detect.TypeAddress,
	"ADDRESS":      detect.TypeAddress,
}

// localToWire is the reverse, for the entity_types request field.
// 反向映射，供请求里的 entity_types 字段使用。
var localToWire = map[detect.EntityType][]string{
	detect.TypeName:    {"PERSON_NAME"},
	detect.TypeOrg:     {"ORGANIZATION"},
	detect.TypeAddress: {"LOCATION"},
}

// mapWireType converts a contract type name.
// 转换契约里的类型名。
//
// 未知类型是错误而非跳过。静默丢弃一个服务端确实检出的实体，
// 会让「模型换了个词表」这件事表现为「这一类突然不再被脱敏」，
// 而没有任何东西会报告它。
//
// An unknown type is an error, not a skip. Silently dropping an entity the
// server did find makes "the model changed its vocabulary" show up as "this
// class is no longer redacted", with nothing reporting it.
func mapWireType(wire string) (detect.EntityType, error) {
	if local, ok := wireToLocal[wire]; ok {
		return local, nil
	}
	known := make([]string, 0, len(wireToLocal))
	for k := range wireToLocal {
		known = append(known, k)
	}
	sort.Strings(known)
	return "", fmt.Errorf(
		"服务端返回了未知的实体类型 %q，本端可识别：%v——"+
			"多半是服务端换了模型或词表，而映射表没跟上 / unknown entity type %q",
		wire, known, wire)
}

// wireTypesFor renders local types as contract type names.
// 把本端类型渲染为契约里的类型名。
func wireTypesFor(types []detect.EntityType) []string {
	var out []string
	for _, t := range types {
		out = append(out, localToWire[t]...)
	}
	sort.Strings(out)
	return out
}
