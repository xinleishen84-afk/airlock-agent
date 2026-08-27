package sidecar

import (
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/verify"
)

// verifyingDetector 在检测之后、脱敏之前施加证据链。
// Applies the evidence chain between detection and redaction.
//
// # 为什么是包装而不是改调用点
// # Why a wrapper rather than changing the call sites
//
// 检测结果流向脱敏的路径不止一条：单段文本、AST 白名单里的七条路径、
// 流式分片。在每一处插入验证，意味着漏掉任何一处都会让那条路径上的
// 概率性判定原样进入脱敏管线——而漏掉不会报错。
//
// 包装成 Detector 之后，验证发生在所有路径的共同上游，漏不掉。
//
// Detection reaches redaction by more than one path: a plain text field, the
// seven allowlisted JSON paths, and streaming chunks. Inserting verification
// at each means any missed one lets probabilistic verdicts through verbatim,
// silently. Wrapping the detector puts verification upstream of all of them.
type verifyingDetector struct {
	inner     detect.Detector
	validator *verify.EvidenceValidator
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
// Value, and a rejection removes one entirely. The result is therefore not a
// subset of the input but a corrected set.
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
