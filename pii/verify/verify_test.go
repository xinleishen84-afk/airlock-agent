package verify

import (
	"strings"
	"testing"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// stubVerifier returns a fixed verdict, optionally with fabricated evidence.
// 返回固定裁决的桩验证器，可选地给出编造的证据。
type stubVerifier struct {
	verdict  Verdict
	evidence string // "" means: quote the entity itself / 空表示引用实体本身
	fail     bool
}

func (stubVerifier) Name() string { return "stub" }

func (s stubVerifier) Verify(text string, cands []detect.Entity) ([]Result, error) {
	if s.fail {
		return nil, errStub
	}
	out := make([]Result, len(cands))
	for i, c := range cands {
		ev := s.evidence
		if ev == "" {
			ev = c.Value
		}
		out[i] = Result{Entity: c, Verdict: s.verdict, Evidence: ev, Confidence: 0.9}
	}
	return out, nil
}

type stubErr struct{}

func (*stubErr) Error() string { return "验证器不可用 / verifier unavailable" }

var errStub = &stubErr{}

// fixedExtractor returns preset entities.
// 返回预设实体的桩提取器。
type fixedExtractor struct{ ents []detect.Entity }

func (fixedExtractor) Name() string                             { return "fixed" }
func (fixedExtractor) CoveredTypes() []detect.EntityType        { return nil }
func (f fixedExtractor) Detect(string) ([]detect.Entity, error) { return f.ents, nil }

// ---------------------------------------------------------------------------
// 靶向分流 / targeted routing
// ---------------------------------------------------------------------------

// TestChecksumBackedTypesSkipVerification is the core of the hybrid split.
// 是混合分流的核心。
//
// A card number that passed Luhn has been verified by arithmetic. Sending it to
// a model buys nothing and adds a model call to the critical path — the whole
// point of routing by type is that these two classes need different treatment.
// 通过 Luhn 的卡号已被算术验证过。送去问模型换不来任何东西，
// 却给关键路径加了一次模型调用——按类型分流的全部意义就在于
// 这两类需要不同的处理。
func TestChecksumBackedTypesSkipVerification(t *testing.T) {
	p := DefaultAmbiguityPolicy()
	for _, typ := range []detect.EntityType{
		detect.TypeBankCard, detect.TypeIBAN, detect.TypeIDCard,
		detect.TypeUSCC, detect.TypeEmail, detect.TypeCredential,
	} {
		e := detect.Entity{Type: typ, Confidence: 0.5} // 低置信度也不该验证
		if p.NeedsVerification(e) {
			t.Errorf("%s 有校验和支撑，不该再花一次模型调用", typ)
		}
	}
}

// TestContextDependentTypesAlwaysVerified is the other half of the split.
// 是分流的另一半。
func TestContextDependentTypesAlwaysVerified(t *testing.T) {
	p := DefaultAmbiguityPolicy()
	for _, typ := range []detect.EntityType{
		detect.TypeAddress, detect.TypeOrg, detect.TypeName,
	} {
		e := detect.Entity{Type: typ, Confidence: 0.99} // 高置信度也要验证
		if !p.NeedsVerification(e) {
			t.Errorf("%s 高度依赖上下文，必须验证", typ)
		}
	}
}

// TestLowConfidenceTriggersVerification covers types not in either list.
// 覆盖两个列表都没有的类型。
func TestLowConfidenceTriggersVerification(t *testing.T) {
	p := DefaultAmbiguityPolicy()
	if !p.NeedsVerification(detect.Entity{Type: detect.TypePassport, Confidence: 0.6}) {
		t.Error("低置信度候选应触发验证")
	}
	if p.NeedsVerification(detect.Entity{Type: detect.TypePassport, Confidence: 0.95}) {
		t.Error("高置信度且非上下文依赖的候选不必验证")
	}
}

// ---------------------------------------------------------------------------
// 证据链 / evidence chain
// ---------------------------------------------------------------------------

// TestFabricatedEvidenceIsRejected is the guard on the audit trail.
// 是审计链条的守卫。
//
// A verifier backed by a language model can produce a snippet that reads
// plausibly but appears nowhere in the input. Accepting it makes the audit trail
// fiction — and a trail nobody can trust is worse than none, because it gets
// trusted anyway.
// 跑在语言模型上的验证器可能产出读起来合理、却在输入中根本不存在的片段。
// 接受它会让审计链条变成虚构——而无法信任的链条比没有更糟，因为人们照样会信。
func TestFabricatedEvidenceIsRejected(t *testing.T) {
	text := "请联系张伟处理这个工单"
	r := &Result{
		Entity:   detect.Entity{Type: detect.TypeName, Value: "张伟", Start: 6, End: 12},
		Verdict:  VerdictDrop,
		Evidence: "该姓名出现在虚构的上下文中", // 原文里没有 / absent from source
	}
	if err := ValidateEvidence(text, r); err == nil {
		t.Fatal("编造的证据必须被拒绝——否则审计链条是虚构的")
	}
}

// TestMissingEvidenceIsRejected covers the verifier that gives only a verdict.
// 覆盖只给裁决不给证据的验证器。
func TestMissingEvidenceIsRejected(t *testing.T) {
	r := &Result{Verdict: VerdictDrop, Evidence: "   "}
	if err := ValidateEvidence("任意文本", r); err == nil {
		t.Error("没有证据的裁决必须被拒绝——不可审计的决策等于没有决策")
	}
}

// TestEvidenceOffsetsAreRecomputed guards a cross-language trap.
// 守住一个跨语言陷阱。
//
// A verifier written in Python counts characters where Go counts bytes. Trusting
// its reported offsets silently points a reviewer at the wrong text — and only
// when the text is non-ASCII, so an English test suite never catches it.
// 用 Python 写的验证器按字符计数，而 Go 按字节计数。采信它自报的偏移
// 会静默地把评审者指向错误的文本——而且只在非 ASCII 文本上出错，
// 纯英文测试永远发现不了。
func TestEvidenceOffsetsAreRecomputed(t *testing.T) {
	text := "客户张伟住在北京市朝阳区"
	r := &Result{
		Entity:        detect.Entity{Type: detect.TypeName, Value: "张伟"},
		Verdict:       VerdictKeep,
		Evidence:      "住在",
		EvidenceStart: 4, // 字符偏移（错的）/ character offset (wrong)
		EvidenceEnd:   6,
	}
	if err := ValidateEvidence(text, r); err != nil {
		t.Fatal(err)
	}
	if got := text[r.EvidenceStart:r.EvidenceEnd]; got != "住在" {
		t.Errorf("偏移未按字节重算：text[%d:%d]=%q", r.EvidenceStart, r.EvidenceEnd, got)
	}
}

// ---------------------------------------------------------------------------
// 管道 / pipeline
// ---------------------------------------------------------------------------

// TestDropSuppressesFalsePositive is the payoff of the second stage.
// 是第二阶段的收益所在。
func TestDropSuppressesFalsePositive(t *testing.T) {
	text := "事故发生在中山路与人民路交叉口"
	ent := detect.Entity{Type: detect.TypeAddress, Value: "中山路与人民路交叉口",
		Start: 15, End: len(text), Confidence: 0.8}

	p := &Pipeline{
		Extractor:  fixedExtractor{[]detect.Entity{ent}},
		Verifier:   stubVerifier{verdict: VerdictDrop, evidence: "事故发生在"},
		Policy:     DefaultAmbiguityPolicy(),
		FailClosed: true,
	}
	out, err := p.Run(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Redact) != 0 {
		t.Errorf("验证器判定为事发地点，不该脱敏：%+v", out.Redact)
	}
	if len(out.Dropped) != 1 || out.Dropped[0].Evidence != "事故发生在" {
		t.Errorf("应记录排除理由与证据：%+v", out.Dropped)
	}
}

// TestVerifierFailureFailsClosed covers the failure path.
// 覆盖故障路径。
//
// A verifier outage must not silently degrade into "the extractor was right
// about everything". Under fail-closed every ambiguous candidate is redacted —
// utility lost, privacy kept.
// 验证器故障不能静默退化成「提取器全对」。fail-closed 下所有高歧义候选
// 都脱敏——损失可用性，保住隐私。
func TestVerifierFailureFailsClosed(t *testing.T) {
	ent := detect.Entity{Type: detect.TypeAddress, Value: "建国路88号", Confidence: 0.8}
	p := &Pipeline{
		Extractor:  fixedExtractor{[]detect.Entity{ent}},
		Verifier:   stubVerifier{fail: true},
		Policy:     DefaultAmbiguityPolicy(),
		FailClosed: true,
	}
	out, err := p.Run("住址建国路88号")
	if err == nil {
		t.Error("验证器故障必须上报，不能静默通过")
	}
	if out == nil || len(out.Redact) != 1 {
		t.Errorf("fail-closed 下应全部脱敏：%+v", out)
	}
}

// TestUnknownVerdictHonoursFailClosed covers the undecided case.
// 覆盖未决情形。
func TestUnknownVerdictHonoursFailClosed(t *testing.T) {
	ent := detect.Entity{Type: detect.TypeName, Value: "张伟", Start: 0, End: 6}
	for _, failClosed := range []bool{true, false} {
		p := &Pipeline{
			Extractor:  fixedExtractor{[]detect.Entity{ent}},
			Verifier:   stubVerifier{verdict: VerdictUnknown},
			Policy:     DefaultAmbiguityPolicy(),
			FailClosed: failClosed,
		}
		out, _ := p.Run("张伟是谁")
		want := 0
		if failClosed {
			want = 1
		}
		if len(out.Redact) != want {
			t.Errorf("failClosed=%v 时应脱敏 %d 个，实际 %d", failClosed, want, len(out.Redact))
		}
		if len(out.Undecided) != 1 {
			t.Errorf("未决候选应被单列出来，便于发现长期无法裁决的类型")
		}
	}
}

// TestFabricatedEvidenceDemotesToUnknown ties evidence validation into the flow.
// 把证据校验接进主流程。
func TestFabricatedEvidenceDemotesToUnknown(t *testing.T) {
	ent := detect.Entity{Type: detect.TypeAddress, Value: "建国路", Start: 0, End: 9}
	p := &Pipeline{
		Extractor:  fixedExtractor{[]detect.Entity{ent}},
		Verifier:   stubVerifier{verdict: VerdictDrop, evidence: "这段话原文里没有"},
		Policy:     DefaultAmbiguityPolicy(),
		FailClosed: true,
	}
	out, _ := p.Run("建国路怎么走")
	if len(out.Dropped) != 0 {
		t.Error("证据无法定位时不能采信 DROP 裁决")
	}
	if len(out.Undecided) != 1 {
		t.Errorf("应降级为 UNKNOWN：%+v", out)
	}
	if len(out.Redact) != 1 {
		t.Error("fail-closed 下降级后应脱敏")
	}
}

// ---------------------------------------------------------------------------
// CAPID
// ---------------------------------------------------------------------------

// TestCAPIDPreservesQuestionSubject is the utility half of the trade-off.
// 是这个取舍中「可用性」的那一半。
func TestCAPIDPreservesQuestionSubject(t *testing.T) {
	text := "北京市朝阳区建国路88号怎么走"
	ent := detect.Entity{Type: detect.TypeAddress, Value: "北京市朝阳区建国路88号",
		Start: 0, End: 33, Confidence: 0.9}

	d, preserve := DefaultRelevancePolicy().Assess(text, ent)
	if !preserve {
		t.Fatal("地址是问题主体，脱敏后问题无法回答")
	}
	if !strings.Contains(text, d.Evidence) {
		t.Errorf("保留决策的证据必须来自原文：%q", d.Evidence)
	}
}

// TestCAPIDRedactsPersonalAttribute is the privacy half.
// 是「隐私」的那一半。
func TestCAPIDRedactsPersonalAttribute(t *testing.T) {
	text := "客户住址是北京市朝阳区建国路88号"
	ent := detect.Entity{Type: detect.TypeAddress, Value: "北京市朝阳区建国路88号",
		Start: 15, End: len(text), Confidence: 0.9}

	if _, preserve := DefaultRelevancePolicy().Assess(text, ent); preserve {
		t.Error("同一个地址作为「客户住址」时是 PII，必须脱敏")
	}
}

// TestPossessiveMarkerVetoesEvenWithSubjectMarker covers the ambiguous sentence.
// 覆盖同时含两种标记的句子。
//
// "他家住建国路，怎么走" contains both a possessive marker and a subject marker.
// Preserving it would leak a home address; redacting it costs one bad answer.
// Only one of those is recoverable.
// 「他家住建国路，怎么走」同时含归属标记和主体标记。保留会泄露家庭住址，
// 脱敏只是损失一次回答质量。两者中只有一个是可挽回的。
func TestPossessiveMarkerVetoesEvenWithSubjectMarker(t *testing.T) {
	text := "他家住建国路88号，怎么走"
	ent := detect.Entity{Type: detect.TypeAddress, Value: "建国路88号",
		Start: 9, End: 24, Confidence: 0.9}

	if _, preserve := DefaultRelevancePolicy().Assess(text, ent); preserve {
		t.Error("归属标记必须否决保留——存疑时脱敏，因为反向失败是无声泄露")
	}
}

// TestCAPIDNeverPreservesIdentityTypes is the structural guarantee.
// 是结构性保证。
//
// Names, ID numbers and card numbers are excluded by construction rather than by
// rule tuning, so no amount of misconfiguration can widen the policy to cover
// them.
// 姓名、证件号、卡号在结构上被排除，而非靠调规则排除，
// 因此再怎么配错也无法把策略放宽到覆盖它们。
func TestCAPIDNeverPreservesIdentityTypes(t *testing.T) {
	// 一句同时含强主体标记的文本，最有可能诱使策略保留
	text := "张伟怎么走 110101199003078515 介绍一下 4111111111111111 在哪"
	for _, typ := range []detect.EntityType{
		detect.TypeName, detect.TypeIDCard, detect.TypeBankCard,
		detect.TypeIBAN, detect.TypeCredential, detect.TypePhone,
	} {
		ent := detect.Entity{Type: typ, Value: "x", Start: 0, End: 1, Confidence: 0.9}
		if _, preserve := DefaultRelevancePolicy().Assess(text, ent); preserve {
			t.Errorf("%s 承载身份，任何上下文下都不得保留", typ)
		}
	}
}

// TestPipelineCAPIDIntegration verifies the stage is wired in.
// 验证该阶段确实接进了管道。
func TestPipelineCAPIDIntegration(t *testing.T) {
	text := "北京市朝阳区建国路88号怎么走"
	ent := detect.Entity{Type: detect.TypeAddress, Value: "北京市朝阳区建国路88号",
		Start: 0, End: 33, Confidence: 0.9}

	p := &Pipeline{
		Extractor:  fixedExtractor{[]detect.Entity{ent}},
		Verifier:   stubVerifier{verdict: VerdictKeep, evidence: "怎么走"},
		Policy:     DefaultAmbiguityPolicy(),
		Relevance:  DefaultRelevancePolicy(),
		FailClosed: true,
	}
	out, err := p.Run(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Redact) != 0 {
		t.Errorf("CAPID 判定为问题主体，最终不该脱敏：%+v", out.Redact)
	}
	if len(out.Preserved) != 1 {
		t.Errorf("保留决策应单独记录，与 DROP 区分——理由不同：%+v", out)
	}
}

// TestAuditSummaryHasNoValues guards the log path.
// 守住日志路径。
func TestAuditSummaryHasNoValues(t *testing.T) {
	out := &Outcome{
		Redact:  []detect.Entity{{Type: detect.TypeName, Value: "张伟"}},
		Dropped: []Result{{Entity: detect.Entity{Value: "中山路"}, Evidence: "事故发生在"}},
	}
	for k, v := range out.AuditSummary() {
		if strings.Contains(k, "张伟") || strings.Contains(k, "中山路") {
			t.Errorf("摘要含真实值：%s=%d", k, v)
		}
	}
	if out.AuditSummary()["redacted"] != 1 {
		t.Error("摘要应含计数")
	}
}
