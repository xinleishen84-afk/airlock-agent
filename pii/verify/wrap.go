package verify

import "github.com/xinleishen84-afk/airlock-agent/pii/detect"

// WrapDetector 在检测之后、脱敏之前施加证据链。
// Applies the evidence chain between detection and redaction.
//
// # 为什么它必须在 verify 包里，而不是各自实现
// # Why this lives here rather than being reimplemented per caller
//
// 这套系统里有三条独立的脱敏路径：sidecar、Advanced sidecar、参考网关。
// 证据链最初只在 sidecar 里包上，另外两条各自漏掉过——网关这条是主动
// 找 bug 时发现的：它接了远程 NER，却把概率性输出直接送进脱敏管线。
//
// Three independent redaction paths exist: the sidecar, the advanced sidecar,
// and the reference gateway. The chain was wrapped only in the first; the
// gateway was found during a bug hunt to feed probabilistic NER output straight
// into redaction.
//
// 一份实现，三处使用。每多一份实现，就多一处会漏掉的地方。
// One implementation, three uses: every extra copy is another place to miss it.
//
// # 包装而不是改调用点
// # Wrapping rather than changing call sites
//
// 检测结果流向脱敏的路径不止一条：单段文本、AST 白名单里的七条路径、
// 流式分片。在每一处插入验证，意味着漏掉任何一处都会让那条路径上的
// 概率性判定原样进入脱敏管线——而漏掉不会报错。
//
// Detection reaches redaction by more than one path within a single request.
// Inserting verification at each means any missed one lets probabilistic
// verdicts through verbatim, silently.
func WrapDetector(inner detect.Detector, validator *EvidenceValidator) detect.Detector {
	if inner == nil || validator == nil {
		// nil 验证器时原样返回，而不是悄悄降级成「不验证」。
		//
		// 调用方若本就不想验证，它不会调这个函数；调到这里却传了 nil，
		// 多半是装配漏了。返回原检测器让行为可预期，而装配是否齐全
		// 由上层的能力拨测去保证。
		//
		// Returned as-is rather than silently degrading: a caller that does not
		// want verification would not call this, so a nil here is likely an
		// assembly omission. Behaviour stays predictable and the capability
		// probes upstream are what guarantee the assembly.
		return inner
	}
	return verifyingDetector{inner: inner, validator: validator}
}

type verifyingDetector struct {
	inner     detect.Detector
	validator *EvidenceValidator
}

// Name implements detect.Detector.
func (d verifyingDetector) Name() string { return d.inner.Name() + "+evidence" }

// CoveredTypes implements detect.Detector.
func (d verifyingDetector) CoveredTypes() []detect.EntityType {
	return d.inner.CoveredTypes()
}

// Detect implements detect.Detector.
//
// 验证会改动实体：边界拉伸（地址向后、机构向前）会改 Start/End/Value，
// 否决会把实体整个去掉。因此返回的不是输入的子集，而是一组被修正过的实体。
//
// Verification mutates entities: boundary expansion rewrites Start, End and
// Value, and a rejection removes one entirely. The result is a corrected set,
// not a subset.
func (d verifyingDetector) Detect(text string) ([]detect.Entity, error) {
	found, err := d.inner.Detect(text)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, nil
	}

	decisions := d.validator.ValidateAll(text, found)
	out := make([]detect.Entity, 0, len(decisions))
	for _, dec := range decisions {
		out = append(out, dec.Entity)
	}
	return out, nil
}

// Missing implements detect.GapReporter by delegating.
// 透传实现 detect.GapReporter。
//
// 不透传的后果是静默的：覆盖缺口告警会消失，而它说的是「姓名、地址、
// 机构名完全裸奔」。包装层吞掉一条安全信号，比包装层本身出错更难发现。
//
// Not delegating makes the coverage-gap warning vanish — a wrapper swallowing
// a safety signal is harder to notice than a wrapper that is simply wrong.
func (d verifyingDetector) Missing() []detect.EntityType {
	if g, ok := d.inner.(detect.GapReporter); ok {
		return g.Missing()
	}
	return nil
}

// DefersOverlapResolution reports false: this detector's output is resolved.
// 报告 false：本检测器的输出已经过重叠消解。
//
// ValidateAll 内部走 ResolveByEvidence，因此包装之后的结果可以安全地
// 直接送去脱敏——这正是包装的意义。
//
// ValidateAll resolves overlaps internally, so wrapped output is safe to
// redact directly, which is the point of wrapping.
func (d verifyingDetector) DefersOverlapResolution() bool { return false }
