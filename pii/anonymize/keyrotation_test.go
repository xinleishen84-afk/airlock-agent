package anonymize

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func rotationStore(t *testing.T, c Cache, opts ...CacheStoreOption) *CacheTokenStore {
	t.Helper()
	s, err := NewCacheTokenStore(c, testKeyring(t), time.Hour, "rot:", opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var rotKey = TokenKey{Tenant: "acme", Namespace: "phone"}

// TestDataKeyRotationKeepsTokenIdentity 是 Case A：
// K_token 不变、K_data v1→v2 时，同一个值必须算出同一个令牌。
// Case A: rotating the data key must not move token identity.
//
// # 这是把两把密钥分开的全部意义
// # This is the entire point of separating the two keys
//
// 整改之前，令牌由那把通用租户密钥 HMAC 得出，而同一把密钥又被 AES-GCM
// 用作加密密钥。于是「轮换加密密钥」与「改变令牌身份」是同一个动作——
// 想换加密密钥，就得接受所有历史令牌全部改变；不想改令牌，就永远不能换
// 加密密钥。两个需求被同一把密钥绑死。
//
// 拆开之后，K_data 可以自由向前推进，K_token 纹丝不动。
//
// Before the split, tokens were HMACed under the same per-tenant key that
// AES-GCM used, so rotating the encryption key and changing every token were
// the same act. Separating them lets K_data advance while K_token does not move.
func TestDataKeyRotationKeepsTokenIdentity(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	const value = "13800138000"

	v1 := rotationStore(t, c, WithDataKeyVersion("v1"))
	tokBefore, err := v1.Issue(ctx, rotKey, value)
	if err != nil {
		t.Fatal(err)
	}

	v2 := rotationStore(t, c, WithDataKeyVersion("v2"))
	tokAfter, err := v2.Issue(ctx, rotKey, value)
	if err != nil {
		t.Fatalf("轮换数据密钥后签发失败: %v", err)
	}

	if tokBefore != tokAfter {
		t.Errorf("数据密钥轮换改变了令牌身份: %s -> %s——"+
			"这会让所有已经发给模型的令牌在下一轮对话里对不上",
			tokBefore, tokAfter)
	}
}

// TestOldKeyVersionStillResolves 是 Case B：
// 用 v1 写入的记录，在当前版本已是 v2 时仍必须解得开。
// Case B: a record written under v1 must still resolve once v2 is current.
//
// 记录里存了自己的 key_version，Resolve 按它派生密钥，而不是拿当前版本去撞。
// 不存版本就只能假设「所有记录都用当前密钥」——那等于宣布轮换即数据丢失。
//
// The record names its own version and Resolve derives that one; assuming the
// current version would make rotation equivalent to data loss.
func TestOldKeyVersionStillResolves(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	const value = "13800138000"

	v1 := rotationStore(t, c, WithDataKeyVersion("v1"))
	tok, err := v1.Issue(ctx, rotKey, value)
	if err != nil {
		t.Fatal(err)
	}

	// 轮换之后，用新版本的 store 去解旧记录
	v2 := rotationStore(t, c, WithDataKeyVersion("v2"))
	got, ok, err := v2.Resolve(ctx, rotKey, tok)
	if err != nil {
		t.Fatalf("v2 解 v1 记录失败: %v——轮换不该让旧令牌无法恢复", err)
	}
	if !ok || got != value {
		t.Errorf("v1 记录在 v2 下还原失败 ok=%v got=%q", ok, got)
	}
}

// TestNewIssueUsesCurrentDataKey 是 Case C：
// 新签发必须用当前版本加密，而不是沿用记录里已有的旧版本。
// Case C: a fresh issue must encrypt under the current version.
func TestNewIssueUsesCurrentDataKey(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()

	v2 := rotationStore(t, c, WithDataKeyVersion("v2"))
	if _, err := v2.Issue(ctx, rotKey, "13900139000"); err != nil {
		t.Fatal(err)
	}
	for _, k := range c.keysWith(":t:") {
		raw, _, _ := c.Get(ctx, k)
		rec, err := DecodeTokenRecord(raw)
		if err != nil {
			t.Fatal(err)
		}
		if rec.KeyVersion != "v2" {
			t.Errorf("新记录的密钥版本是 %q，应为当前版本 v2", rec.KeyVersion)
		}
	}
}

// TestTamperingFailsAuthentication 是 Case D：
// 密文、AAD 的任一绑定字段被改动，认证必须失败。
// Case D: tampering with the ciphertext or any AAD-bound field must fail.
//
// AAD 绑定五项，每一项各挡住一类搬运。少绑一项，那类搬运就变成「解得开且
// 看起来完全正常」——AEAD 的价值全在这里，而不在加密本身。
//
// Five fields are bound and each blocks one kind of relocation; omitting any
// turns that relocation into a ciphertext that opens and looks normal.
func TestTamperingFailsAuthentication(t *testing.T) {
	ctx := context.Background()
	const value = "13800138000"

	// 每个用例先正常签发一条记录，再把它**搬到**目标位置，然后按目标位置的
	// 身份去解。搬运而不是「改了字段看查不查得到」——后者会因为键变了查不到
	// 而静默通过，根本没碰到 AEAD。真正要证的是：记录找得到，但认证失败。
	//
	// Each case issues a record then relocates it and resolves at the
	// destination. Relocation rather than "mutate a field and see if lookup
	// misses": the latter passes silently because the key changed, never
	// reaching the AEAD. What must be proven is that the record is found and
	// still fails authentication.
	for _, tc := range []struct {
		name string
		// mutate 改记录本身（原地），返回 true 表示记录被改过
		mutate func(*TokenRecord) bool
		// relocateTo 给出搬运目的地的身份；零值表示不搬运
		relocateTo func(orig TokenKey, origToken string) (TokenKey, string)
	}{
		{name: "改密文", mutate: func(r *TokenRecord) bool { r.Ciphertext[0] ^= 0xFF; return true }},
		{name: "改 nonce", mutate: func(r *TokenRecord) bool { r.Nonce[0] ^= 0xFF; return true }},
		{name: "改密钥版本标签", mutate: func(r *TokenRecord) bool { r.KeyVersion = "v2"; return true }},
		{name: "改身份 epoch 标签", mutate: func(r *TokenRecord) bool { r.IdentityEpoch = "e9"; return true }},
		{
			name: "搬到另一个租户",
			relocateTo: func(k TokenKey, tok string) (TokenKey, string) {
				return TokenKey{Tenant: "globex", Namespace: k.Namespace}, tok
			},
		},
		{
			name: "搬到另一个命名空间",
			relocateTo: func(k TokenKey, tok string) (TokenKey, string) {
				return TokenKey{Tenant: k.Tenant, Namespace: "name"}, tok
			},
		},
		{
			name: "搬到另一个令牌下",
			relocateTo: func(k TokenKey, tok string) (TokenKey, string) {
				return k, strings.Repeat("a", len(tok))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newFakeCache()
			s := rotationStore(t, c)
			tok, err := s.Issue(ctx, rotKey, value)
			if err != nil {
				t.Fatal(err)
			}
			keys := c.keysWith(":t:")
			if len(keys) != 1 {
				t.Fatalf("期望一条记录，实得 %v", keys)
			}
			raw, _, _ := c.Get(ctx, keys[0])
			rec, err := DecodeTokenRecord(raw)
			if err != nil {
				t.Fatal(err)
			}

			readKey, readTok := rotKey, tok
			if tc.mutate != nil {
				tc.mutate(&rec)
			}
			if tc.relocateTo != nil {
				readKey, readTok = tc.relocateTo(rotKey, tok)
			}

			// 把（可能被改过的）记录放到读取方会去查的那个位置
			c.mu.Lock()
			c.data[s.tokenKey(readKey, readTok)] = rec.Encode()
			c.mu.Unlock()

			got, ok, err := s.Resolve(ctx, readKey, readTok)
			if err == nil && ok {
				t.Errorf("%s 之后记录仍被成功解开，得到 %q——"+
					"AAD 没有绑住这一项，一份密文可以被搬到这个位置照常使用",
					tc.name, got)
			}
		})
	}
}

// TestSamePIIDifferentTenantsDiffer 是 Case E：不同租户、相同 PII，令牌必须不同。
// Case E: the same PII in different tenants must yield different tokens.
//
// 令牌确定性派生之后，随机性不再提供跨租户不可关联性——它完全落在密钥上。
// 两个租户算出同一个令牌，等于宣布他们共有一位客户，而这是一次谁都没同意
// 的跨租户披露。
//
// With deterministic tokens, unlinkability rests entirely on the keys. Equal
// tokens across tenants would announce a shared customer — a disclosure neither
// tenant consented to.
func TestSamePIIDifferentTenantsDiffer(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	s := rotationStore(t, c)
	const value = "13800138000"

	a, err := s.Issue(ctx, TokenKey{Tenant: "acme", Namespace: "phone"}, value)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Issue(ctx, TokenKey{Tenant: "globex", Namespace: "phone"}, value)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("两个租户对同一个手机号得到了同一个令牌——" +
			"比对各自的导出即可确认他们共有一位客户")
	}
}

// TestSamePIIDifferentNamespacesDiffer 是 Case F：不同命名空间、相同 PII，
// 令牌必须不同。
// Case F: the same PII in different namespaces must yield different tokens.
//
// 命名空间进 HMAC 输入。相同则意味着「作为手机号的 X」与「作为姓名的 X」
// 共用一个令牌，复原时无从区分该按哪一类还原。
func TestSamePIIDifferentNamespacesDiffer(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	s := rotationStore(t, c)
	const value = "13800138000"

	a, err := s.Issue(ctx, TokenKey{Tenant: "acme", Namespace: "phone"}, value)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Issue(ctx, TokenKey{Tenant: "acme", Namespace: "name"}, value)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("同一个值在两个命名空间下得到了同一个令牌——复原时无从区分类别")
	}
}

// TestIdentityEpochChangesTokenIdentity 钉住 epoch 的语义。
// Pins the epoch's semantics.
//
// 这条断言的是一个**代价**而不是一个特性：根密钥轮换（即新 epoch）会改变
// 全部令牌身份。把它写成测试，是为了让「令牌永远稳定」这种承诺不会悄悄
// 回到文档里——承诺是有边界的，边界就在这里。
//
// This asserts a cost rather than a feature: a new epoch moves every token.
// Writing it down keeps an unbounded stability promise from creeping back.
func TestIdentityEpochChangesTokenIdentity(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	const value = "13800138000"

	e1 := rotationStore(t, c, WithIdentityEpoch("e1"))
	tok1, err := e1.Issue(ctx, rotKey, value)
	if err != nil {
		t.Fatal(err)
	}
	e2 := rotationStore(t, c, WithIdentityEpoch("e2"))
	tok2, err := e2.Issue(ctx, rotKey, value)
	if err != nil {
		t.Fatal(err)
	}
	if tok1 == tok2 {
		t.Error("换了身份 epoch 令牌却没变——epoch 没有真正参与派生")
	}
	// 旧 epoch 的令牌仍应可解：它的记录还在，且 AAD 里记着自己的 epoch
	got, ok, err := e1.Resolve(ctx, rotKey, tok1)
	if err != nil || !ok || got != value {
		t.Errorf("旧 epoch 的令牌应仍可解 ok=%v got=%q err=%v", ok, got, err)
	}
}

// TestCacheHoldsNoPlaintext 是不变量 D：缓存里不得出现明文 PII。
// Invariant D: no plaintext PII in the cache.
//
// 缓存的 dump、备份、慢查询日志、监控面板与事故期间的 KEYS 输出都会把
// value 照原样显示出来。整改之前那里放的就是原值本身。
//
// Cache dumps, backups, slow-query logs and incident-time KEYS output all
// display the value verbatim; it used to be the plaintext itself.
func TestCacheHoldsNoPlaintext(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	s := rotationStore(t, c)
	const value = "13800138000"

	if _, err := s.Issue(ctx, rotKey, value); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.data {
		if strings.Contains(k, value) || strings.Contains(v, value) {
			t.Errorf("缓存里出现了明文 PII: 键 %q 值 %q", k, v)
		}
		// 密文经 base64 编码，原值的 base64 形式也不该出现
		if strings.Contains(v, base64.RawStdEncoding.EncodeToString([]byte(value))) {
			t.Errorf("缓存值里出现了原值的 base64 形式: %q", v)
		}
	}
}
