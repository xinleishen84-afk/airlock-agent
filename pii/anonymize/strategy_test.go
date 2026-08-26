package anonymize

import (
	"strings"
	"testing"
	"time"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

func ent(typ detect.EntityType, value string) detect.Entity {
	return detect.Entity{Type: typ, Value: value, End: len(value), Confidence: 1}
}

const testTenant Tenant = "acme"

func testKey() []byte { return []byte("0123456789abcdef-0123456789abcdef-test") }

// sessScope 是带会话保险库的算子作用域。
func sessScope(v *SessionVault) StrategyScope {
	return StrategyScope{Tenant: testTenant, Vault: v}
}

// mustKeyring 用给定根密钥构造密钥环。
func mustKeyring(t testing.TB, root string) *Keyring {
	t.Helper()
	k, err := NewKeyring([]byte(root), nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// testScope 是不涉及会话保险库的算子作用域。
func testScope() StrategyScope { return StrategyScope{Tenant: testTenant} }

// testKeyring 构造测试用密钥环。
func testKeyring(t testing.TB) *Keyring {
	t.Helper()
	k, err := NewKeyring(testKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ---------------------------------------------------------------------------
// Mask / 遮罩
// ---------------------------------------------------------------------------

// 同一个人在多轮里必须是同一个占位符，否则模型的指代推理会散架。
// The same person must keep the same placeholder across turns, or the model's
// coreference reasoning falls apart.
func TestMaskKeepsCoreferenceStable(t *testing.T) {
	vault := newSessionVault("s1", time.Hour)
	m := NewMask()

	first, err := m.Apply(t.Context(), sessScope(vault), ent(detect.TypeName, "张伟"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := m.Apply(t.Context(), sessScope(vault), ent(detect.TypeName, "张伟"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := m.Apply(t.Context(), sessScope(vault), ent(detect.TypeName, "李娜"))
	if err != nil {
		t.Fatal(err)
	}

	if first != again {
		t.Errorf("同一个人应得到同一占位符：%q vs %q", first, again)
	}
	if first == other {
		t.Errorf("不同的人不能塌缩成同一占位符：都是 %q", first)
	}
	if got, ok := vault.Resolve(first); !ok || got != "张伟" {
		t.Errorf("占位符应可还原为原值，得到 %q ok=%v", got, ok)
	}
}

// 掩码字符按 rune 计数：按字节会为每个汉字输出三个星号，泄露字数。
// Character masking counts runes: counting bytes would emit three asterisks
// per Chinese character and leak the length.
func TestCharMaskCountsRunesNotBytes(t *testing.T) {
	s := NewCharMask('*', 0)
	got, err := s.Apply(t.Context(), testScope(), ent(detect.TypeName, "张伟"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "**" {
		t.Errorf("两个汉字应得到两个星号，实际 %q（%d 字节）", got, len(got))
	}
}

func TestCharMaskKeepsSuffix(t *testing.T) {
	s := NewCharMask('*', 4)
	got, err := s.Apply(t.Context(), testScope(), ent(detect.TypeBankCard, "4111111111111111"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "************1111" {
		t.Errorf("得到 %q", got)
	}
}

// keep 覆盖整个值时等于原样输出，必须拒绝而不是把原值当脱敏结果交回去。
// A keep that covers the whole value is a no-op; refuse rather than return the
// original dressed as redacted output.
func TestCharMaskRefusesNoOp(t *testing.T) {
	s := NewCharMask('*', 8)
	if _, err := s.Apply(t.Context(), testScope(), ent(detect.TypePhone, "1381234")); err == nil {
		t.Fatal("keep >= 值长度时应报错")
	}
}

// ---------------------------------------------------------------------------
// Hash / 确定性哈希
// ---------------------------------------------------------------------------

func TestHashIsDeterministicAndTypeScoped(t *testing.T) {
	h, err := NewHash(testKeyring(t), 8)
	if err != nil {
		t.Fatal(err)
	}

	a, _ := h.Apply(t.Context(), testScope(), ent(detect.TypeEmail, "a.b@example.com"))
	b, _ := h.Apply(t.Context(), testScope(), ent(detect.TypeEmail, "a.b@example.com"))
	if a != b {
		t.Errorf("同一值必须得到同一摘要：%q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "[hash:email:") {
		t.Errorf("摘要应带类型命名空间，实际 %q", a)
	}

	// 同一字符串以两种类型出现，必须得到不同摘要——
	// 否则数仓里会把两个不同群体静默关联到一起。
	// The same string as two types must differ, or the warehouse silently
	// joins two different populations.
	asName, _ := h.Apply(t.Context(), testScope(), ent(detect.TypeName, "example"))
	asOrg, _ := h.Apply(t.Context(), testScope(), ent(detect.TypeOrg, "example"))
	if strings.TrimPrefix(asName, "[hash:name:") == strings.TrimPrefix(asOrg, "[hash:org:") {
		t.Error("不同实体类型的同一字符串不应产生相同摘要")
	}
}

// 换密钥必须换摘要——否则密钥轮转是假的。
// A new key must produce new digests, or key rotation is a no-op.
func TestHashKeyRotationChangesDigests(t *testing.T) {
	h1, _ := NewHash(testKeyring(t), 8)
	h2, _ := NewHash(mustKeyring(t, "a-completely-different-root-key-value-32b"), 8)

	a, _ := h1.Apply(t.Context(), testScope(), ent(detect.TypeEmail, "a.b@example.com"))
	b, _ := h2.Apply(t.Context(), testScope(), ent(detect.TypeEmail, "a.b@example.com"))
	if a == b {
		t.Error("不同密钥应产生不同摘要")
	}
}

// 过短的密钥会让构造退化为无盐哈希，必须在构造期拒绝。
// A short key degrades the construction to an unsalted hash; reject at build.
func TestHashRejectsWeakKey(t *testing.T) {
	if _, err := NewHash(nil, 8); err == nil {
		t.Fatal("过短的密钥应被拒绝")
	}
	if _, err := NewHash(testKeyring(t), 4); err == nil {
		t.Fatal("过短的摘要位数应被拒绝")
	}
}

// ---------------------------------------------------------------------------
// Tokenize / 令牌化
// ---------------------------------------------------------------------------

func TestTokenizeIsStableAndNamespaced(t *testing.T) {
	store := NewMemoryTokenStore(time.Hour)
	tk, err := NewTokenize(store)
	if err != nil {
		t.Fatal(err)
	}

	a, _ := tk.Apply(t.Context(), testScope(), ent(detect.TypeEmail, "a.b@example.com"))
	b, _ := tk.Apply(t.Context(), testScope(), ent(detect.TypeEmail, "a.b@example.com"))
	if a != b {
		t.Errorf("同一值必须得到同一令牌：%q vs %q", a, b)
	}
	if store.Size() != 1 {
		t.Errorf("同一值不应签发两个令牌，库内 %d 条", store.Size())
	}

	// 命名空间隔离：同一字符串在两个类型下互不可见
	// Namespace isolation: the same string is not visible across types.
	nameTok, _ := tk.Apply(t.Context(), testScope(), ent(detect.TypeName, "a.b@example.com"))
	if nameTok == a {
		t.Error("不同命名空间不应共用令牌")
	}
	raw := strings.TrimSuffix(strings.TrimPrefix(a, "[tok:email:"), "]")
	if _, ok := mustResolve(t, store, TokenKey{Tenant: testTenant, Namespace: "name"}, raw); ok {
		t.Error("email 命名空间的令牌不应在 name 命名空间下解析成功")
	}
}

// 令牌不得由原值推导——推导出来的令牌只是换了名字的哈希。
// Tokens must not be derived from the value: a derived token is a hash under
// another name.
func TestTokensAreNotDerivedFromValue(t *testing.T) {
	s1, s2 := NewMemoryTokenStore(time.Hour), NewMemoryTokenStore(time.Hour)
	t1, _ := NewTokenize(s1)
	t2, _ := NewTokenize(s2)

	a, _ := t1.Apply(t.Context(), testScope(), ent(detect.TypeEmail, "a.b@example.com"))
	b, _ := t2.Apply(t.Context(), testScope(), ent(detect.TypeEmail, "a.b@example.com"))
	if a == b {
		t.Error("两个独立令牌库对同一值不应产生相同令牌——说明令牌是由值推导的")
	}
}

func TestTokenStoreConcurrentIssueIsStable(t *testing.T) {
	store := NewMemoryTokenStore(time.Hour)
	const workers = 32

	results := make(chan string, workers)
	for i := 0; i < workers; i++ {
		go func() {
			tok, err := store.Issue(t.Context(), TokenKey{Tenant: testTenant, Namespace: "email"}, "a.b@example.com")
			if err != nil {
				t.Error(err)
			}
			results <- tok
		}()
	}
	first := <-results
	for i := 1; i < workers; i++ {
		if got := <-results; got != first {
			t.Fatalf("并发签发产生了两个令牌：%q vs %q", first, got)
		}
	}
	if store.Size() != 1 {
		t.Fatalf("并发签发后库内应只有 1 条，实际 %d", store.Size())
	}
}

// ---------------------------------------------------------------------------
// Drop / 切除
// ---------------------------------------------------------------------------

func TestDropRemovesBytes(t *testing.T) {
	got, err := NewDrop().Apply(t.Context(), testScope(), ent(detect.TypePhone, "13812345678"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("切除应产出空串，实际 %q", got)
	}
}

// ---------------------------------------------------------------------------
// 可逆性声明 / Reversibility declarations
// ---------------------------------------------------------------------------

// 可逆性是算子的硬属性，复原路径静默地依赖它。
// Reversibility is a hard property; the restore path silently depends on it.
func TestReversibilityDeclarations(t *testing.T) {
	h, _ := NewHash(testKeyring(t), 8)
	tk, _ := NewTokenize(NewMemoryTokenStore(time.Hour))
	g, _ := NewGeneralize(&Ontology{Terms: map[string]string{"外科医生": "医生"}},
		GranularityDecade, NewDrop())

	cases := []struct {
		s    Strategy
		want bool
	}{
		{NewMask(), true},
		{tk, true},
		{NewCharMask('*', 4), false},
		{h, false},
		{NewDrop(), false},
		{g, false},
	}
	for _, c := range cases {
		if got := c.s.Reversible(); got != c.want {
			t.Errorf("%s.Reversible() = %v, want %v", c.s.Name(), got, c.want)
		}
	}
}

// FeedT / FlushT 是流式复原器的测试包装，把 ctx 与错误处理收在一处。
// Test wrappers that keep ctx and error handling in one place.
func (s *StreamUnredactor) FeedT(t *testing.T, chunk string) string {
	t.Helper()
	out, err := s.Feed(t.Context(), chunk)
	if err != nil {
		t.Fatalf("流式复原失败: %v", err)
	}
	return out
}

func (s *StreamUnredactor) FlushT(t *testing.T) string {
	t.Helper()
	out, err := s.Flush(t.Context())
	if err != nil {
		t.Fatalf("流式收尾失败: %v", err)
	}
	return out
}

// unredactT 是复原的测试包装。
func unredactT(t *testing.T, r *Redactor, text string, scope StrategyScope) UnredactResult {
	t.Helper()
	res, err := r.Unredact(t.Context(), text, scope)
	if err != nil {
		t.Fatalf("复原失败: %v", err)
	}
	return res
}

// mustResolve 是令牌解析的测试包装。
func mustResolve(t *testing.T, s TokenStore, key TokenKey, token string) (string, bool) {
	t.Helper()
	v, ok, err := s.Resolve(t.Context(), key, token)
	if err != nil {
		t.Fatalf("解析令牌失败: %v", err)
	}
	return v, ok
}

// anonymize_SessionRef 是测试用的会话引用构造。
func anonymize_SessionRef(session string) SessionRef {
	return SessionRef{Tenant: testTenant, Session: session}
}
