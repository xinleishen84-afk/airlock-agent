package anonymize

import (
	"strings"
	"testing"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// TestTokenKeyRejectsSeparatorInNamespace 证明命名空间不能带存储层分隔符。
// Proves a namespace cannot carry the storage-layer separator.
//
// CacheTokenStore 的键是 前缀+租户+":"+命名空间+":t:"+令牌。租户的字符集
// 禁止冒号，命名空间此前只查非空——(ns="a", tok="b:t:c") 与
// (ns="a:t:b", tok="c") 会拼出同一个键，互相读到对方的原值。
//
// 现网走不到：复原路径上的命名空间由 redactor.go 里 tokenRe 的
// [a-z0-9_]+ 捕获组限定。但那是另一个文件里的正则顺手保住的不变量，
// 而 pii/* 是文档里声明可单独 import 的公开包，任何直接调用 Issue/Resolve
// 的人都能把它重新打开。校验该在校验它的那个函数里。
//
// Keys render as prefix+tenant+":"+namespace+":t:"+token. The tenant charset
// forbids the colon; the namespace was only checked for emptiness, so two
// distinct (namespace, token) pairs rendered one key. Unreachable in production
// because a regex in another file happens to constrain it — but pii/* is
// documented as separately importable, so any direct caller reopens it.
func TestTokenKeyRejectsSeparatorInNamespace(t *testing.T) {
	bad := []string{"a:t:b", "a b", "A", "a\x00b", "", strings.Repeat("a", 65), "a/b", "a.b"}
	for _, ns := range bad {
		k := TokenKey{Tenant: "acme", Namespace: ns}
		if err := k.Validate(); err == nil {
			t.Errorf("命名空间 %q 应被拒绝——它会被拼进存储层的键", ns)
		}
	}
	for _, ns := range []string{"phone", "name", "bank_card", "a1"} {
		if err := (TokenKey{Tenant: "acme", Namespace: ns}).Validate(); err != nil {
			t.Errorf("合法命名空间 %q 被误拒: %v", ns, err)
		}
	}
}

// TestNamespaceOfMatchesTokenPattern 保证签发端与复原端的字符集一致。
// Keeps the issuing and restoring charsets in step.
//
// namespaceOf 由实体类型小写得来，tokenRe 的捕获组是 [a-z0-9_]+，
// TokenKey.Validate 是第三处。三者任意一处漂移，都会让合法签发的令牌在
// 复原时被自己的校验拒掉——症状是占位符还原不回来，而不是报错。
//
// Three places encode the same charset. Any drift makes legitimately issued
// tokens fail their own validation on the way back — surfacing as placeholders
// that never restore rather than as an error.
func TestNamespaceOfMatchesTokenPattern(t *testing.T) {
	for _, typ := range detect.BuiltinTypes() {
		ns := namespaceOf(typ)
		if err := (TokenKey{Tenant: "acme", Namespace: ns}).Validate(); err != nil {
			t.Errorf("实体类型 %s 派生出的命名空间 %q 通不过校验：%v——"+
				"该类型的令牌签发得出去，复原时会被自己的校验拒掉", typ, ns, err)
		}
		if !tokenNamespaceRe.MatchString(ns) {
			t.Errorf("实体类型 %s 派生出的命名空间 %q 与 tokenRe 的捕获组不符——"+
				"复原时正则匹配不上，占位符原样留在答案里", typ, ns)
		}
	}
}
