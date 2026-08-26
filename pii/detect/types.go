package detect

// BuiltinTypes returns every entity type the library defines, sorted.
// 返回本库定义的全部实体类型（已排序）。
//
// Tenant YAML rules are validated against this list. A typo in a type name must
// fail at load time: a rule declaring "ID_CRAD" would otherwise register
// cleanly, detect correctly, and emit a type no downstream policy matches — the
// values would be found and then passed through.
// 租户 YAML 规则依此校验。类型名写错必须在加载期失败：
// 一条声明 "ID_CRAD" 的规则否则会正常注册、正常检出，
// 却产出一个下游策略都匹配不上的类型——值被找到了，然后照样放行。
func BuiltinTypes() []EntityType {
	return []EntityType{
		TypeAccount, TypeAddress, TypeBankCard, TypeCredential, TypeEmail,
		TypeIBAN, TypeIDCard, TypeIP, TypeLicensePlate, TypeName, TypeOrg,
		TypePassport, TypePhone, TypeSSN, TypeUSCC,
	}
}

// IsBuiltinType reports whether t is defined by the library.
// 报告 t 是否为本库定义的类型。
func IsBuiltinType(t EntityType) bool {
	for _, known := range BuiltinTypes() {
		if known == t {
			return true
		}
	}
	return false
}
