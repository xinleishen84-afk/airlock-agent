package anonymize

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// # Redaction strategies
// # 脱敏算子
//
// [REDACTED] is one answer to one question. It is the wrong answer to most of
// them: an analytics warehouse that needs to count distinct users cannot use
// it, a model that needs to keep "他" pointing at the same person cannot use
// it, and a DLP hard line that must not ship the bytes at all is not satisfied
// by a placeholder that still reserves space for them.
// [REDACTED] 是对某一个问题的答案，而对大多数问题都是错的答案：
// 需要统计去重用户数的分析仓库用不了它；需要让「他」始终指向同一个人的模型
// 用不了它；而必须一个字节都不出去的 DLP 红线，也不会满足于一个仍然
// 为这些字节留着位置的占位符。
//
// So the operator is chosen by where the data is going, not by what it is.
// 因此算子由数据的去向决定，而不是由数据本身决定。
//
// # The one invariant that matters
// # 唯一要紧的不变量
//
// Reversibility is a property of the operator, and the restore path silently
// depends on it. Configure a hash for a flow whose responses get un-redacted
// and nothing errors: the request goes out fine, the model answers with the
// hash, and the gateway hands the end user "[hash:name:a4b2efc8]" as if that
// were a person's name. Every strategy therefore declares Reversible(), and a
// destination that restores refuses to be built from operators that do not.
// 可逆性是算子的属性，而复原路径静默地依赖它。
// 给一条要做响应复原的链路配上哈希，不会有任何报错：请求正常出站，
// 模型用哈希作答，网关把 "[hash:name:a4b2efc8]" 当成人名交给终端用户。
// 因此每个算子都必须声明 Reversible()，而带复原的目的地拒绝用不可逆算子构建。

// StrategyScope carries everything an operator needs beyond the entity itself.
// 携带算子在实体之外所需的一切。
//
// The tenant is here rather than baked into each operator at construction: one
// gateway process serves every tenant, so an operator holding a tenant would
// have to be rebuilt per request, and the one that was not rebuilt would
// quietly serve tenant A's data under tenant B's key.
// 租户放在这里，而不是构造期烧进每个算子：一个网关进程服务所有租户，
// 因此持有租户的算子必须逐请求重建，
// 而那个没被重建的算子会悄悄地用租户 B 的密钥处理租户 A 的数据。
type StrategyScope struct {
	// Tenant is the isolation boundary this call belongs to.
	// 是本次调用所属的隔离边界。
	Tenant Tenant

	// Vault holds the session's placeholder mapping.
	// 持有本会话的占位符映射。
	Vault *SessionVault
}

// Strategy is a redaction operator.
// 是一个脱敏算子。
type Strategy interface {
	// Name identifies the operator in audit output.
	// 在审计输出中标识本算子。
	Name() string

	// Apply returns the replacement text for one entity.
	// 返回一个实体的替换文本。
	Apply(ctx context.Context, scope StrategyScope, e detect.Entity) (string, error)

	// Reversible reports whether Apply's output can be turned back into the
	// original value. It is a hard property of the operator, not a hint.
	// 报告 Apply 的输出能否还原为原值。这是算子的硬属性，不是提示。
	Reversible() bool
}

// ErrStrategy is returned when an operator cannot produce a replacement.
// 算子无法产出替换文本时返回。
var ErrStrategy = errors.New("脱敏算子执行失败 / redaction strategy failed")

// ---------------------------------------------------------------------------
// Mask / 遮罩替换
// ---------------------------------------------------------------------------

// MaskStrategy replaces a value with a numbered type placeholder.
// 用带序号的类型占位符替换值。
//
// This is the operator for public-cloud LLM traffic. The placeholder keeps the
// sentence grammatical and keeps coreference intact: the same person is the
// same ANONYMIZED_NAME_0 in turn one and turn nine, so "他" still resolves and
// the model can still reason about who did what. A blanket [REDACTED] collapses
// three different people into one token and quietly destroys that.
// 这是发往公有云大模型的算子。占位符保持句子语法完整，也保持指代一致：
// 同一个人在第 1 轮和第 9 轮都是 ANONYMIZED_NAME_0，于是「他」仍然解析得了，
// 模型仍然能推理谁做了什么。一刀切的 [REDACTED] 会把三个不同的人塌缩成
// 同一个符号，并悄悄毁掉这一点。
type MaskStrategy struct{}

// NewMask builds the placeholder mask operator.
// 构造占位符遮罩算子。
func NewMask() MaskStrategy { return MaskStrategy{} }

// Name implements Strategy.
func (MaskStrategy) Name() string { return "mask" }

// Reversible implements Strategy. The vault holds placeholder → value.
// 实现 Strategy。会话保险库持有「占位符 → 原值」。
func (MaskStrategy) Reversible() bool { return true }

// Apply implements Strategy.
func (MaskStrategy) Apply(_ context.Context, scope StrategyScope, e detect.Entity) (string, error) {
	if scope.Vault == nil {
		return "", fmt.Errorf("%w: mask 需要会话保险库 / mask requires a session vault", ErrStrategy)
	}
	return scope.Vault.PlaceholderFor(e), nil
}

// ---------------------------------------------------------------------------
// Character mask / 掩码字符
// ---------------------------------------------------------------------------

// CharMaskStrategy overwrites a value with a mask character, optionally keeping
// a suffix visible.
// 用掩码字符覆写值，可选保留末尾若干字符可见。
//
// Keeping a suffix is what users expect from a UI ("****1234"), and it is a
// deliberate leak: the last four digits of a card, combined with the cardholder
// name that some other field kept, is often enough to identify the account to a
// human. Keep>0 is therefore a display-layer choice, not a privacy control, and
// this type will not let it be treated as one — Reversible() is false, but that
// says nothing about how much was disclosed.
// 保留末尾是用户从界面上习得的期望（"****1234"），而它是一次刻意的泄露：
// 卡号后四位加上别处保留的持卡人姓名，往往足以让人识别出这个账户。
// 因此 Keep>0 是展示层的选择，不是隐私控制手段；本类型不会让它被当成后者——
// Reversible() 为 false，但这与「泄露了多少」无关。
type CharMaskStrategy struct {
	Char rune
	// Keep is how many trailing characters stay visible.
	// 是末尾保持可见的字符数。
	Keep int
}

// NewCharMask builds a character-mask operator.
// 构造掩码字符算子。
func NewCharMask(char rune, keep int) CharMaskStrategy {
	if char == 0 {
		char = '*'
	}
	if keep < 0 {
		keep = 0
	}
	return CharMaskStrategy{Char: char, Keep: keep}
}

// Name implements Strategy.
func (s CharMaskStrategy) Name() string { return "char_mask" }

// Reversible implements Strategy.
func (CharMaskStrategy) Reversible() bool { return false }

// Apply implements Strategy.
//
// Counting is by rune, not byte: masking a Chinese name by bytes would emit
// three asterisks per character and leak the character count of a value the
// operator meant to hide.
// 按字符（rune）而非字节计数：按字节遮罩中文姓名会每个字输出三个星号，
// 从而泄露一个本想隐藏的值的字数。
func (s CharMaskStrategy) Apply(_ context.Context, _ StrategyScope, e detect.Entity) (string, error) {
	runes := []rune(e.Value)
	if s.Keep >= len(runes) {
		// Keeping everything would emit the value unchanged. Refuse rather
		// than hand back the original in redacted clothing.
		// 全部保留等于原样输出。拒绝，而不是把原值套上脱敏的外衣交回去。
		return "", fmt.Errorf("%w: keep=%d >= 值长度 %d，遮罩后等于原值 / mask would be a no-op",
			ErrStrategy, s.Keep, len(runes))
	}
	var b strings.Builder
	for i := 0; i < len(runes)-s.Keep; i++ {
		b.WriteRune(s.Char)
	}
	b.WriteString(string(runes[len(runes)-s.Keep:]))
	return b.String(), nil
}

// ---------------------------------------------------------------------------
// Deterministic keyed hash / 确定性加盐哈希
// ---------------------------------------------------------------------------

// HashStrategy replaces a value with a deterministic keyed digest.
// 用确定性带密钥摘要替换值。
//
// Output: [hash:email:a4b2efc8] — the type namespace is inside the token, so
// the same string appearing as two different entity types does not collide, and
// an analyst reading a warehouse column can tell what the pseudonym stands for.
// 输出形如 [hash:email:a4b2efc8]——类型命名空间在令牌内部，
// 于是同一个字符串以两种实体类型出现时不会撞车，
// 而读数仓字段的分析师也能看出这个假名代表什么。
//
// # Why HMAC and not "SHA-256 with a salt"
// # 为什么用 HMAC 而不是「SHA-256 加盐」
//
// The value space of most PII is tiny. There are 10^11 mainland mobile numbers
// and far fewer plausible ones; a laptop enumerates all of them against a known
// salt in minutes. A salt stored next to the data therefore buys nothing once
// the data leaks — and the data leaking is the scenario this is for.
// 多数 PII 的取值空间极小。中国大陆手机号总量 10^11，实际可能的还要少得多；
// 已知盐的情况下，一台笔记本几分钟就能穷举完。
// 因此与数据放在一起的盐，在数据泄露之后一文不值——
// 而数据泄露正是这套机制要应对的场景。
//
// HMAC with a key that lives only in the gateway process removes the offline
// attack: without the key the digests are unlinkable to any candidate value.
// The key must come from a secret manager, never from the config file that
// travels with the data.
// 用只存在于网关进程内的密钥做 HMAC，消除了离线攻击：
// 没有密钥，摘要与任何候选值都无法关联。
// 密钥必须来自密钥管理服务，绝不能来自与数据一同流转的配置文件。
//
// # What this is still not
// # 它仍然不是什么
//
// A pseudonym that is stable enough to join on is stable enough to profile.
// Under GDPR this remains personal data, not anonymised data. It reduces
// exposure; it does not exit the regulation.
// 一个稳定到可以做关联的假名，也就稳定到可以做画像。
// 在 GDPR 下它仍然是个人数据，不是匿名数据。
// 它降低暴露面，但并没有走出监管范围。
type HashStrategy struct {
	keyring *Keyring
	digits  int
}

// NewHash builds the keyed-hash operator.
// 构造带密钥哈希算子。
//
// digits is the hex length of the digest suffix. Shorter is more readable and
// more collision-prone: at 8 hex digits two distinct values collide with
// probability ~50% around 77k distinct values (birthday bound), which for a
// warehouse column counting distinct users is a real undercount.
// digits 是摘要后缀的十六进制长度。越短越可读，也越容易碰撞：
// 8 位十六进制下，约 7.7 万个不同值时碰撞概率就到 50%（生日界），
// 对一个统计去重用户数的数仓字段而言，这是实打实的少算。
func NewHash(keyring *Keyring, digits int) (HashStrategy, error) {
	if keyring == nil {
		return HashStrategy{}, fmt.Errorf(
			"%w: 哈希算子需要密钥环——没有它就只能用固定密钥，"+
				"于是同一个手机号在每个租户下摘要相同，"+
				"两个租户比对数仓导出即可确认共有客户 / hash requires a keyring",
			ErrStrategy)
	}
	if digits < 8 || digits > 64 {
		return HashStrategy{}, fmt.Errorf(
			"%w: 摘要位数须在 [8,64]，实际 %d / digest length must be in [8,64]",
			ErrStrategy, digits)
	}
	return HashStrategy{keyring: keyring, digits: digits}, nil
}

// Name implements Strategy.
func (HashStrategy) Name() string { return "hash" }

// Reversible implements Strategy.
func (HashStrategy) Reversible() bool { return false }

// Apply implements Strategy.
func (s HashStrategy) Apply(_ context.Context, scope StrategyScope, e detect.Entity) (string, error) {
	if s.keyring == nil {
		return "", fmt.Errorf("%w: 哈希算子未初始化密钥环 / hash strategy has no keyring", ErrStrategy)
	}
	key, err := s.keyring.Key(scope.Tenant)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrStrategy, err)
	}
	mac := hmac.New(sha256.New, key)
	// The type is part of the MAC input, not only of the printed label: without
	// it, the same string as a NAME and as an ORG would produce one digest and
	// silently join two different populations in the warehouse.
	// 类型参与 MAC 计算，而不只是印在标签上：否则同一个字符串作为 NAME
	// 与作为 ORG 会得到同一个摘要，在数仓里静默地把两个不同的群体关联到一起。
	mac.Write([]byte(e.Type))
	mac.Write([]byte{0})
	mac.Write([]byte(e.Value))
	sum := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("[hash:%s:%s]", namespaceOf(e.Type), sum[:s.digits]), nil
}

// ---------------------------------------------------------------------------
// Tokenize / 可逆伪名化
// ---------------------------------------------------------------------------

// TokenizeStrategy replaces a value with a semantics-free token.
// 用无语义令牌替换值。
//
// Output: [tok:email:9df3a0c1].
type TokenizeStrategy struct {
	store TokenStore
}

// NewTokenize builds the tokenizing operator.
// 构造令牌化算子。
func NewTokenize(store TokenStore) (TokenizeStrategy, error) {
	if store == nil {
		return TokenizeStrategy{}, fmt.Errorf(
			"%w: 令牌化需要令牌库 / tokenize requires a token store", ErrStrategy)
	}
	return TokenizeStrategy{store: store}, nil
}

// Name implements Strategy.
func (TokenizeStrategy) Name() string { return "tokenize" }

// Reversible implements Strategy.
func (TokenizeStrategy) Reversible() bool { return true }

// Apply implements Strategy.
func (s TokenizeStrategy) Apply(ctx context.Context, scope StrategyScope, e detect.Entity) (string, error) {
	ns := namespaceOf(e.Type)
	tok, err := s.store.Issue(ctx, TokenKey{Tenant: scope.Tenant, Namespace: ns}, e.Value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("[tok:%s:%s]", ns, tok), nil
}

// ---------------------------------------------------------------------------
// Drop / 物理切除
// ---------------------------------------------------------------------------

// DropStrategy removes the byte range entirely, shortening the text.
// 彻底移除该字节区间，文本随之变短。
//
// This is the operator for a DLP hard line, where the requirement is that the
// bytes do not leave — not that they leave labelled. A placeholder still
// declares that something was there and how many of them; dropping does not.
// 这是 DLP 红线的算子：要求是这些字节不出去，而不是打上标签再出去。
// 占位符仍然宣告了「这里曾经有东西」以及有几个；切除则不会。
//
// The cost is that the text stops being a faithful rendering of the original.
// Offsets from any prior analysis no longer apply, and a sentence can become
// ungrammatical or, worse, reverse its meaning — "禁止 张伟 入内" dropped to
// "禁止 入内" is still coherent and now says something else.
// 代价是文本不再忠实于原文。此前任何分析得到的偏移量都不再适用，
// 句子可能不通顺，或者更糟——含义反转：「禁止 张伟 入内」切除后是
// 「禁止 入内」，依然通顺，但说的已是另一件事。
type DropStrategy struct{}

// NewDrop builds the drop operator.
// 构造切除算子。
func NewDrop() DropStrategy { return DropStrategy{} }

// Name implements Strategy.
func (DropStrategy) Name() string { return "drop" }

// Reversible implements Strategy.
func (DropStrategy) Reversible() bool { return false }

// Apply implements Strategy.
func (DropStrategy) Apply(context.Context, StrategyScope, detect.Entity) (string, error) {
	return "", nil
}

// ---------------------------------------------------------------------------
// Shared helpers / 公共辅助
// ---------------------------------------------------------------------------

// namespaceOf turns an entity type into a token namespace.
// 把实体类型转成令牌命名空间。
func namespaceOf(t detect.EntityType) string {
	return strings.ToLower(string(t))
}
