package anonymize

import (
	"context"
	"testing"
	"time"
)

// TestTTLIsNotRefreshedOnHit 钉住 TTL 的第一条语义：命中已有映射不续期。
// Pins the first TTL rule: a hit does not extend the mapping.
//
// # 默认不滑动，因为 TTL 就是 PII 的保留期
// # Not sliding by default, because the TTL is the PII retention period
//
// 滑动过期在缓存里是常见默认值——它假设「还在被用的东西就该留着」。
// 这条假设对 PII 映射不成立：一个被反复提到的手机号会因为「反复被提到」
// 而永远不过期，于是保留期这件事在事实上被取消了，而没有任何地方记录
// 这次取消。
//
// 需要滑动语义的产品可以显式选择，但那必须是写下来的决定。
//
// Sliding expiry assumes that what is still used should be kept, which does not
// hold for a PII mapping: a frequently mentioned phone number would never
// expire precisely because it is frequently mentioned, silently cancelling the
// retention period.
func TestTTLIsNotRefreshedOnHit(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	s, err := NewCacheTokenStore(c, testKeyring(t), time.Hour, "ttl:")
	if err != nil {
		t.Fatal(err)
	}
	key := TokenKey{Tenant: "acme", Namespace: "phone"}

	tok, err := s.Issue(ctx, key, "13800138000")
	if err != nil {
		t.Fatal(err)
	}
	cacheKey := s.tokenKey(key, tok)
	first, ok := c.ttlOf(cacheKey)
	if !ok {
		t.Fatal("首次签发没有记录 TTL")
	}

	// 反复签发同一个值：每次都命中已有映射
	for range 5 {
		if _, err := s.Issue(ctx, key, "13800138000"); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := c.ttlOf(cacheKey)
	if after != first {
		t.Errorf("命中已有映射后 TTL 从 %v 变成了 %v——"+
			"一个被反复提到的值会因此永不过期，保留期在事实上被取消", first, after)
	}
}

// TestExpiredMappingResolvesAsNotFound 钉住第二条：到期后 Resolve 必须确定性
// 返回未找到，而不是未定义行为。
// Pins the second rule: an expired mapping resolves as not-found, definitely.
//
// 记录里存了自己的到期时刻，因此不必信任后端的 TTL——后端把键留久了
// （驱逐策略、TTL 精度、时钟差），Resolve 仍按记录判过期。这让「到期」
// 成为一个确定的答案，而不是取决于后端实现细节的不确定行为。
//
// The record carries its own expiry, so a backend keeping the key longer than
// intended does not extend the mapping: expiry is a definite answer rather than
// something that depends on backend internals.
func TestExpiredMappingResolvesAsNotFound(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	s, err := NewCacheTokenStore(c, testKeyring(t), time.Hour, "ttl:")
	if err != nil {
		t.Fatal(err)
	}
	key := TokenKey{Tenant: "acme", Namespace: "phone"}

	tok, err := s.Issue(ctx, key, "13800138000")
	if err != nil {
		t.Fatal(err)
	}

	// 把记录的到期时刻改到过去，键仍留在后端——正是「后端还留着，
	// 但记录已过期」这个场景。不用负 TTL 造这个状态：负 TTL 现在会被
	// 构造器拒绝，而它本来就是一个语义未定义的输入。
	//
	// The key stays in the backend with an expiry in the past. Not built with a
	// negative TTL: the constructor now refuses those, and they were an
	// undefined input to begin with.
	cacheKey := s.tokenKey(key, tok)
	raw, _, _ := c.Get(ctx, cacheKey)
	rec, err := DecodeTokenRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	rec.ExpiresAt = time.Now().Add(-time.Minute)
	c.mu.Lock()
	c.data[cacheKey] = rec.Encode()
	c.mu.Unlock()
	got, ok, err := s.Resolve(ctx, key, tok)
	if err != nil {
		t.Errorf("过期应返回 (false, nil) 而不是错误——"+
			"「这个令牌已经不在了」是确定的答案，不是故障：%v", err)
	}
	if ok || got != "" {
		t.Errorf("过期的映射仍被解出 ok=%v got=%q", ok, got)
	}
}

// TestReIssueAfterExpiryReturnsSameTokenNewRecord 钉住第三条：
// 过期后重新签发同一个值，令牌不变，但记录是新的。
// Pins the third rule: re-issuing after expiry yields the same token and a new
// record.
//
// 令牌身份是确定性派生的，因此过期与否都算出同一个值——这是设计的直接后果，
// 不是巧合。要写清楚的是它的含义：**一个已经发给模型的令牌，在映射过期之后
// 仍然可能被重新签发出来并再次可解**。
//
// 对产品语义而言这通常是想要的（同一个人在下一轮对话里仍是同一个令牌），
// 但它意味着「过期」删除的是数据而不是标识符。真正需要让标识符也失效的场景，
// 要靠轮换身份 epoch，而不是等 TTL。
//
// Token identity is derived, so it survives expiry by construction. The
// consequence worth stating: a token already handed to a model can be reissued
// and become resolvable again. Expiry removes the data, not the identifier;
// invalidating identifiers requires rotating the identity epoch.
func TestReIssueAfterExpiryReturnsSameTokenNewRecord(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	s, err := NewCacheTokenStore(c, testKeyring(t), time.Hour, "ttl:")
	if err != nil {
		t.Fatal(err)
	}
	key := TokenKey{Tenant: "acme", Namespace: "phone"}
	const value = "13800138000"

	tok1, err := s.Issue(ctx, key, value)
	if err != nil {
		t.Fatal(err)
	}
	before, _, _ := c.Get(ctx, s.tokenKey(key, tok1))

	// 模拟映射过期消失
	c.mu.Lock()
	delete(c.data, s.tokenKey(key, tok1))
	c.mu.Unlock()

	tok2, err := s.Issue(ctx, key, value)
	if err != nil {
		t.Fatal(err)
	}
	if tok2 != tok1 {
		t.Errorf("过期后重新签发得到了不同的令牌 %s vs %s——"+
			"确定性派生的令牌身份不该随记录存亡而改变", tok2, tok1)
	}
	after, _, _ := c.Get(ctx, s.tokenKey(key, tok2))
	if after == before {
		t.Error("重新签发写入的记录与旧记录完全相同——" +
			"每次加密应当用新的随机 nonce，密文不该可预测地重复")
	}
	got, ok, err := s.Resolve(ctx, key, tok2)
	if err != nil || !ok || got != value {
		t.Errorf("重新签发后无法还原 ok=%v got=%q err=%v", ok, got, err)
	}
}

// TestLabelsWithSeparatorAreRejected 证明带分隔符的版本或 epoch 在构造期被拒。
// Proves a version or epoch containing the separator is refused at construction.
//
// 记录以 "." 分隔字段。版本号里带一个点——`v1.2` 这种完全合理的写法——会让
// 编码出来的记录多出一段，解码时报「字段数为 7，期望 6」。那句错误指向记录
// 格式，而真正的原因在一个构造参数上，排查会从错误的一端开始。
//
// 实测过：修之前 Issue 直接失败，错误信息完全没提版本号。
//
// Measured before the fix: Issue failed with an error that never mentioned the
// version string.
func TestLabelsWithSeparatorAreRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		opt  CacheStoreOption
	}{
		{"版本号带点", WithDataKeyVersion("v1.2")},
		{"epoch 带点", WithIdentityEpoch("e1.0")},
		{"版本号带大写", WithDataKeyVersion("V1")},
		{"版本号过长", WithDataKeyVersion("v-with-a-very-long-name")},
		{"版本号为空", WithDataKeyVersion("")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewCacheTokenStore(newFakeCache(), testKeyring(t),
				time.Hour, "lbl:", tc.opt)
			if err == nil {
				t.Error("非法标识符应在构造期被拒绝——放过去的话，" +
					"故障会以「记录字段数不对」的形式出现在几百行之外")
			}
		})
	}

	// 合法的写法不能被误杀
	for _, v := range []DataKeyVersion{"v1", "v2", "v10", "key_2", "2026-q1"} {
		if _, err := NewCacheTokenStore(newFakeCache(), testKeyring(t),
			time.Hour, "lbl:", WithDataKeyVersion(v)); err != nil {
			t.Errorf("合法版本号 %q 被误拒: %v", v, err)
		}
	}
}

// TestIssueRefusesExpiredExistingRecord 钉住不变量 A 在过期边界上的行为。
// Pins invariant A at the expiration boundary.
//
// # 这里曾经返回一个必定还原不了的令牌
// # This used to return a token guaranteed not to resolve
//
// 后端还留着键、而记录里的到期时刻已过，是可能出现的：后端 TTL 精度更粗、
// 后端根本不过期、或写入方与读取方之间有时钟偏移。
//
// Resolve 对这种记录返回 ok=false——它按记录判过期，不信任后端。而 Issue
// 此前只核对明文是否相等，于是**成功返回了一个 Resolve 一定会拒绝的令牌**，
// 直接违反「Issue 返回的令牌必须立即可 Resolve」。
//
// 现在响亮失败：不能就地覆盖（FindOrCreate 按定义不覆盖，加一个替换原语会
// 把单次原子调用拆成两步），而返回一个坏令牌比报错糟得多。这同时是后端契约
// 违规的信号——合规后端不该返回超过自身 TTL 的键。
//
// Resolve rejects such a record while Issue only compared plaintexts, so Issue
// returned a token Resolve was guaranteed to refuse. Failing loudly is the only
// remaining option: overwriting is unavailable and a bad token is worse.
func TestIssueRefusesExpiredExistingRecord(t *testing.T) {
	ctx := context.Background()
	c := newFakeCache()
	s, err := NewCacheTokenStore(c, testKeyring(t), time.Hour, "exp:")
	if err != nil {
		t.Fatal(err)
	}
	key := TokenKey{Tenant: "acme", Namespace: "phone"}
	const value = "13800138000"

	tok, err := s.Issue(ctx, key, value)
	if err != nil {
		t.Fatal(err)
	}

	// 制造「后端还留着键，但记录已过期」：只改记录，不动后端的 TTL。
	ck := s.tokenKey(key, tok)
	raw, _, _ := c.Get(ctx, ck)
	rec, err := DecodeTokenRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	rec.ExpiresAt = time.Now().Add(-time.Hour)
	c.mu.Lock()
	c.data[ck] = rec.Encode()
	c.mu.Unlock()

	// Resolve 必须拒绝
	if _, ok, err := s.Resolve(ctx, key, tok); ok || err != nil {
		t.Errorf("过期记录的 Resolve 应返回 (false, nil)，实得 ok=%v err=%v", ok, err)
	}

	// Issue 必须报错，而不是返回一个还原不了的令牌
	got, err := s.Issue(ctx, key, value)
	if err == nil {
		_, ok, _ := s.Resolve(ctx, key, got)
		t.Errorf("Issue 返回了令牌 %s（可还原=%v），而后端给的是一条已过期的记录——"+
			"返回一个 Resolve 一定拒绝的令牌，直接违反不变量 A", got, ok)
	}
}
