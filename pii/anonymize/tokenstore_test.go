package anonymize

import (
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 密钥环 / Keyring
// ---------------------------------------------------------------------------

// 同一个手机号在两个租户下必须得到不同摘要。
// The same phone number must digest differently in two tenants.
//
// 否则两个租户比对各自的数仓导出，就能确认他们共有一位客户 ——
// 一次谁都没同意的跨租户披露，而且是用双方都以为已经假名化的数据做到的。
// Otherwise two tenants can compare warehouse exports and confirm a shared
// customer: a disclosure neither consented to, made from data both believed
// was pseudonymized.
func TestHashDiffersPerTenant(t *testing.T) {
	h, err := NewHash(testKeyring(t), 8)
	if err != nil {
		t.Fatal(err)
	}
	e := ent(detect.TypePhone, "13812345678")

	a, err := h.Apply(t.Context(), StrategyScope{Tenant: "tenant-a"}, e)
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.Apply(t.Context(), StrategyScope{Tenant: "tenant-b"}, e)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("两个租户的同一个手机号不应产生相同摘要：%s", a)
	}

	// 同一租户内必须仍然确定——否则关联分析这个用途就没了
	again, _ := h.Apply(t.Context(), StrategyScope{Tenant: "tenant-a"}, e)
	if again != a {
		t.Fatalf("同一租户内摘要必须稳定：%s vs %s", a, again)
	}
	t.Logf("A=%s  B=%s", a, b)
}

func TestKeyringRejectsWeakRoot(t *testing.T) {
	if _, err := NewKeyring([]byte("too-short"), nil); err == nil {
		t.Fatal("过短的根密钥应被拒绝")
	}
}

func TestKeyringRejectsInvalidTenant(t *testing.T) {
	k := testKeyring(t)
	for _, bad := range []Tenant{"", "a\x00b", "has space", Tenant(strings.Repeat("x", 65))} {
		if _, err := k.Key(bad); err == nil {
			t.Errorf("非法租户 %q 应被拒绝", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// 通用契约：三个驱动跑同一套用例
// A shared contract exercised by all three drivers
// ---------------------------------------------------------------------------

// 三个驱动必须表现一致，否则「开发用内存、生产换 Redis」这句话不成立。
// The drivers must behave identically, or "memory in dev, Redis in prod" is
// not a statement anyone can rely on.
func TestTokenStoreContract(t *testing.T) {
	drivers := map[string]func(*testing.T) TokenStore{
		"memory": func(t *testing.T) TokenStore { return NewMemoryTokenStore(time.Hour) },
		"cache": func(t *testing.T) TokenStore {
			s, err := NewCacheTokenStore(newFakeCache(), testKeyring(t), time.Hour, "test:")
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
		"sql": func(t *testing.T) TokenStore {
			s, err := NewSQLTokenStore(newFakeDB(), testKeyring(t), "pii_tokens", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	}

	for name, build := range drivers {
		t.Run(name, func(t *testing.T) {
			store := build(t)
			ctx := t.Context()
			keyA := TokenKey{Tenant: "tenant-a", Namespace: "email"}
			keyB := TokenKey{Tenant: "tenant-b", Namespace: "email"}
			const value = "a.b@example.com"

			tok, err := store.Issue(ctx, keyA, value)
			if err != nil {
				t.Fatal(err)
			}

			// 稳定性：同一三元组始终得到同一令牌
			again, err := store.Issue(ctx, keyA, value)
			if err != nil {
				t.Fatal(err)
			}
			if again != tok {
				t.Fatalf("同一值签发了两个令牌：%s vs %s", tok, again)
			}

			// 令牌里不得含原值
			if strings.Contains(tok, "example.com") {
				t.Fatalf("令牌泄露了原值：%s", tok)
			}

			// 自己租户解析得到
			got, ok, err := store.Resolve(ctx, keyA, tok)
			if err != nil || !ok || got != value {
				t.Fatalf("解析失败：%q ok=%v err=%v", got, ok, err)
			}

			// 跨租户：拿着令牌也解析不出来
			if _, ok, err := store.Resolve(ctx, keyB, tok); err != nil || ok {
				t.Fatalf("越权：租户 B 解析出了租户 A 的令牌（ok=%v err=%v）", ok, err)
			}

			// 跨命名空间同样解析不出来
			nsKey := TokenKey{Tenant: "tenant-a", Namespace: "name"}
			if _, ok, _ := store.Resolve(ctx, nsKey, tok); ok {
				t.Fatal("越权：跨命名空间解析成功了")
			}

			// 同一个值在另一个租户下必须是另一个令牌
			otherTok, err := store.Issue(ctx, keyB, value)
			if err != nil {
				t.Fatal(err)
			}
			if otherTok == tok {
				t.Fatal("两个租户的同一个值共用了令牌")
			}

			// 精准擦除：只清租户 A
			n, err := store.Clear(ctx, "tenant-a")
			if err != nil {
				t.Fatal(err)
			}
			if n != 1 {
				t.Errorf("应擦除 1 条，实际 %d", n)
			}
			if _, ok, _ := store.Resolve(ctx, keyA, tok); ok {
				t.Error("擦除后仍能解析租户 A 的令牌")
			}
			if v, ok, _ := store.Resolve(ctx, keyB, otherTok); !ok || v != value {
				t.Error("擦除污染了租户 B 的数据")
			}

			// 非法键必须拒绝，而不是落进某个空租户的域
			if _, err := store.Issue(ctx, TokenKey{Namespace: "email"}, value); err == nil {
				t.Error("空租户应被拒绝")
			}
			if _, err := store.Issue(ctx, TokenKey{Tenant: "tenant-a"}, value); err == nil {
				t.Error("空命名空间应被拒绝")
			}
		})
	}
}

// TTL 到期后令牌必须解析不出来。
// A token must stop resolving once its TTL passes.
func TestMemoryTokenStoreTTL(t *testing.T) {
	store := NewMemoryTokenStore(30 * time.Millisecond)
	ctx := t.Context()
	key := TokenKey{Tenant: "acme", Namespace: "email"}

	tok, err := store.Issue(ctx, key, "a.b@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.Resolve(ctx, key, tok); !ok {
		t.Fatal("刚签发的令牌应可解析")
	}

	time.Sleep(60 * time.Millisecond)
	if _, ok, _ := store.Resolve(ctx, key, tok); ok {
		t.Fatal("过期令牌不应再解析成功")
	}
}

// 并发签发必须收敛到同一个令牌。
// Concurrent issuance must converge on one token.
func TestConcurrentIssueConverges(t *testing.T) {
	for name, store := range map[string]TokenStore{
		"memory": NewMemoryTokenStore(time.Hour),
		"cache":  mustCacheStore(t),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			key := TokenKey{Tenant: "acme", Namespace: "email"}

			const workers = 32
			var wg sync.WaitGroup
			results := make([]string, workers)
			for i := range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					tok, err := store.Issue(ctx, key, "a.b@example.com")
					if err != nil {
						t.Error(err)
						return
					}
					results[i] = tok
				}()
			}
			wg.Wait()

			for i, got := range results {
				if got != results[0] {
					t.Fatalf("并发签发出现分歧：worker %d 得到 %q，worker 0 得到 %q",
						i, got, results[0])
				}
			}
		})
	}
}

// 存储故障绝不能长得像「令牌不存在」。
// A store failure must never look like "token not found".
func TestStoreFailureIsNotAPhantom(t *testing.T) {
	cache := newFakeCache()
	cache.failGet = true
	store, err := NewCacheTokenStore(cache, testKeyring(t), time.Hour, "test:")
	if err != nil {
		t.Fatal(err)
	}
	_, ok, err := store.Resolve(t.Context(), TokenKey{Tenant: "acme", Namespace: "email"}, "abc")
	if err == nil {
		t.Fatal("存储故障应返回错误")
	}
	if ok {
		t.Fatal("故障时不应报告命中")
	}
	t.Logf("按预期报错：%v", err)
}

func mustCacheStore(t *testing.T) TokenStore {
	t.Helper()
	s, err := NewCacheTokenStore(newFakeCache(), testKeyring(t), time.Hour, "test:")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ---------------------------------------------------------------------------
// SQL 驱动的专项断言
// ---------------------------------------------------------------------------

// 复合主键必须在建表语句里，而不是靠调用方每次记得写 WHERE。
// The composite primary key must be in the DDL, not left to callers
// remembering a WHERE clause.
func TestSQLSchemaHasCompositeKey(t *testing.T) {
	store, err := NewSQLTokenStore(newFakeDB(), testKeyring(t), "pii_tokens", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ddl := store.Schema()
	for _, want := range []string{
		"PRIMARY KEY (tenant_id, namespace, token)",
		"UNIQUE (tenant_id, namespace, value_digest)",
		"value_cipher",
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("建表语句缺少 %q：\n%s", want, ddl)
		}
	}
	if strings.Contains(ddl, "value TEXT") || strings.Contains(ddl, "value VARCHAR") {
		t.Errorf("表里不应有明文 value 列：\n%s", ddl)
	}
}

// 落库的必须是密文，且原值不得出现在任何一条 SQL 参数里。
// What lands in the table must be ciphertext, and the plaintext must not
// appear in any statement's arguments.
//
// 存明文会把每一个被令牌化的值送进数据库的索引、备份、副本和查询日志——
// 而那正是买下令牌化本来要消除的暴露面。
// Storing plaintext puts every tokenized value into the database's indexes,
// backups, replicas and query logs — the exposure tokenization was bought to
// remove.
func TestSQLStoresCiphertextOnly(t *testing.T) {
	db := newFakeDB()
	store, err := NewSQLTokenStore(db, testKeyring(t), "pii_tokens", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	const value = "a.b@example.com"
	key := TokenKey{Tenant: "tenant-a", Namespace: "email"}

	if _, err := store.Issue(t.Context(), key, value); err != nil {
		t.Fatal(err)
	}

	db.mu.Lock()
	rows := append([]fakeRowRec(nil), db.rows...)
	db.mu.Unlock()

	if len(rows) != 1 {
		t.Fatalf("应写入 1 行，实际 %d", len(rows))
	}
	if strings.Contains(string(rows[0].cipher), value) {
		t.Fatal("落库的是明文")
	}
	if strings.Contains(rows[0].digest, value) {
		t.Fatal("摘要里含明文")
	}
	t.Logf("落库密文 %d 字节，摘要 %s…", len(rows[0].cipher), rows[0].digest[:16])
}

// 把一行密文挪到另一个租户名下必须解不开，而不是干净地解密出来。
// A ciphertext row moved under another tenant must fail to open, not decrypt
// cleanly.
func TestSQLCiphertextIsBoundToTenant(t *testing.T) {
	db := newFakeDB()
	store, err := NewSQLTokenStore(db, testKeyring(t), "pii_tokens", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := store.Issue(t.Context(),
		TokenKey{Tenant: "tenant-a", Namespace: "email"}, "a.b@example.com")
	if err != nil {
		t.Fatal(err)
	}

	// 模拟一次数据库层面的行搬运（备份恢复串了租户、或有人手工 UPDATE）
	db.mu.Lock()
	db.rows[0].tenant = "tenant-b"
	db.mu.Unlock()

	_, _, err = store.Resolve(t.Context(), TokenKey{Tenant: "tenant-b", Namespace: "email"}, tok)
	if err == nil {
		t.Fatal("被挪到别的租户名下的密文不应能解开")
	}
	t.Logf("按预期解不开：%v", err)
}

// 表名无法作为参数绑定，因此它是配置与注入之间唯一的东西。
// A table name cannot be bound as a parameter, so this check is the only thing
// between configuration and injection.
func TestSQLTableNameIsValidated(t *testing.T) {
	for _, bad := range []string{"", "tokens; DROP TABLE users", "tokens--", "1tokens", "令牌"} {
		if _, err := NewSQLTokenStore(newFakeDB(), testKeyring(t), bad, 0); err == nil {
			t.Errorf("非法表名 %q 应被拒绝", bad)
		}
	}
	if _, err := NewSQLTokenStore(newFakeDB(), testKeyring(t), "pii_tokens_v2", 0); err != nil {
		t.Errorf("合法表名不应被拒绝：%v", err)
	}
}

// 没有密钥环就只能存明文，因此构造期必须拒绝。
// Without a keyring only plaintext could be stored, so construction must fail.
func TestSQLRequiresKeyring(t *testing.T) {
	if _, err := NewSQLTokenStore(newFakeDB(), nil, "pii_tokens", 0); err == nil {
		t.Fatal("缺少密钥环应被拒绝")
	}
}

// 擦除语句必须带租户条件——一条没有 WHERE 的 DELETE 会清掉所有租户。
// The erasure statement must be tenant-scoped: a WHERE-less DELETE wipes every
// tenant.
func TestSQLEraseIsTenantScoped(t *testing.T) {
	db := newFakeDB()
	store, err := NewSQLTokenStore(db, testKeyring(t), "pii_tokens", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []Tenant{"tenant-a", "tenant-b"} {
		if _, err := store.Issue(t.Context(),
			TokenKey{Tenant: tenant, Namespace: "email"}, "a.b@example.com"); err != nil {
			t.Fatal(err)
		}
	}

	n, err := store.Clear(t.Context(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应擦除 1 行，实际 %d", n)
	}

	db.mu.Lock()
	stmts := append([]string(nil), db.statements...)
	remaining := len(db.rows)
	db.mu.Unlock()

	if remaining != 1 {
		t.Fatalf("租户 B 的行应保留，实际剩 %d 行", remaining)
	}
	var deleteStmt string
	for _, q := range stmts {
		if strings.HasPrefix(strings.TrimSpace(q), "DELETE") {
			deleteStmt = q
		}
	}
	if !strings.Contains(deleteStmt, "WHERE tenant_id = ?") {
		t.Fatalf("擦除语句必须带租户条件：%q", deleteStmt)
	}
	t.Logf("擦除语句：%s", strings.TrimSpace(deleteStmt))
}

// 缓存键里不得出现原值：键会出现在慢查询日志、监控面板和事故期间的 KEYS 输出里。
// The raw value must never appear in a cache key: keys show up in slow-query
// logs, dashboards, and someone's KEYS output during an incident.
func TestCacheKeysDoNotContainPlaintext(t *testing.T) {
	cache := newFakeCache()
	store, err := NewCacheTokenStore(cache, testKeyring(t), time.Hour, "test:")
	if err != nil {
		t.Fatal(err)
	}
	const value = "a.b@example.com"
	if _, err := store.Issue(t.Context(),
		TokenKey{Tenant: "tenant-a", Namespace: "email"}, value); err != nil {
		t.Fatal(err)
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()
	for k := range cache.data {
		if strings.Contains(k, "example.com") {
			t.Fatalf("缓存键里含原值：%s", k)
		}
		if !strings.HasPrefix(k, "test:tenant-a:") {
			t.Errorf("键未落在租户前缀下：%s", k)
		}
	}
	t.Logf("缓存键：%v", keysOf(cache.data))
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
