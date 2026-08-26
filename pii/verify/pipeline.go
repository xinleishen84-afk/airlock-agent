package verify

import (
	"fmt"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// Pipeline runs extraction, then verification, then relevance assessment.
// 依次执行提取、验证、相关性评估。
//
//	Layer 1  extract   格式确定型走校验和，上下文依赖型走模型
//	Layer 2  verify    只复查高歧义候选，必须给出原文证据
//	CAPID    assess    保留回答质量所必需的非敏感实体
type Pipeline struct {
	Extractor detect.Detector
	Verifier  Verifier
	Policy    AmbiguityPolicy
	Relevance *RelevancePolicy

	// FailClosed decides what an UNKNOWN verdict means. With it set, an
	// undecided candidate is redacted; without it, the candidate passes.
	// Redacting on doubt costs data utility; passing on doubt costs privacy.
	// Only one of those is recoverable.
	// 决定 UNKNOWN 裁决意味着什么。开启时，未决候选按脱敏处理；
	// 关闭时放行。存疑而脱敏损失的是数据可用性，存疑而放行损失的是隐私。
	// 两者中只有一个是可挽回的。
	FailClosed bool
}

// Outcome is the full result of one pipeline run, retained for audit.
// 是一次管道运行的完整结果，供审计留存。
type Outcome struct {
	// Redact are the entities that will actually be replaced.
	// 是最终真正会被替换的实体。
	Redact []detect.Entity

	// Dropped are candidates the verifier ruled out, with the evidence that
	// justified each. This list is the answer to "why was this name left in the
	// clear" — without it, that question has no answer at all.
	// 是验证器排除的候选，附带支撑每一项的证据。这个列表是
	//「为什么这个姓名没被脱敏」的答案——没有它，这个问题根本无从回答。
	Dropped []Result

	// Preserved are entities kept in the clear because redacting them would
	// destroy the answer, recorded separately from Dropped because the reason
	// differs: these *are* PII, judged necessary.
	// 是为了不破坏回答而保留明文的实体，与 Dropped 分开记录，因为理由不同：
	// 这些**确实是** PII，只是被判定为必需。
	Preserved []RelevanceDecision

	// Undecided are candidates the verifier could not rule on. Their treatment
	// followed FailClosed; they are surfaced so a persistently undecided type
	// can be noticed and its recognizer fixed.
	// 是验证器无法裁决的候选。它们按 FailClosed 处理；单列出来是为了
	// 让某个长期无法裁决的类型能被发现，进而修正它的识别器。
	Undecided []Result
}

// Run executes all three stages.
// 执行三个阶段。
func (p *Pipeline) Run(text string) (*Outcome, error) {
	candidates, err := p.Extractor.Detect(text)
	if err != nil {
		return nil, fmt.Errorf("提取阶段失败 / extraction failed: %w", err)
	}

	out := &Outcome{}

	// ---- Layer 2: verify only what is ambiguous ----
	// ---- 第二层：只验证有歧义的部分 ----
	ambiguous, direct := p.Policy.Partition(candidates)
	out.Redact = append(out.Redact, direct...)

	if len(ambiguous) > 0 && p.Verifier != nil {
		results, err := p.Verifier.Verify(text, ambiguous)
		if err != nil {
			// A verifier failure must not silently degrade into "extractor was
			// right about everything". Under fail-closed the safe reading is to
			// redact every ambiguous candidate — losing utility, keeping privacy.
			// 验证器故障不能静默退化成「提取器全对」。fail-closed 下的安全读法
			// 是把所有高歧义候选都脱敏——损失可用性，保住隐私。
			if p.FailClosed {
				out.Redact = append(out.Redact, ambiguous...)
				return out, fmt.Errorf(
					"验证阶段失败，已按 fail-closed 全部脱敏 / verification failed, "+
						"all ambiguous candidates redacted: %w", err)
			}
			return nil, fmt.Errorf("验证阶段失败 / verification failed: %w", err)
		}
		if len(results) != len(ambiguous) {
			return nil, fmt.Errorf(
				"验证器返回 %d 条结果但输入 %d 个候选 / verifier returned %d results "+
					"for %d candidates", len(results), len(ambiguous), len(results), len(ambiguous))
		}

		for i := range results {
			r := &results[i]
			if err := ValidateEvidence(text, r); err != nil {
				// Evidence that cannot be located makes the verdict unauditable.
				// Demote to UNKNOWN rather than trusting an unverifiable claim.
				// 定位不到的证据让裁决不可审计。降级为 UNKNOWN，
				// 而不是相信一个无法核实的主张。
				r.Verdict = VerdictUnknown
				r.Reason = "证据无法在原文中定位 / evidence not locatable: " + err.Error()
			}
			switch r.Verdict {
			case VerdictKeep:
				out.Redact = append(out.Redact, r.Entity)
			case VerdictDrop:
				out.Dropped = append(out.Dropped, *r)
			default:
				out.Undecided = append(out.Undecided, *r)
				if p.FailClosed {
					out.Redact = append(out.Redact, r.Entity)
				}
			}
		}
	} else if len(ambiguous) > 0 {
		// No verifier configured: the ambiguous candidates keep the extractor's
		// verdict. This is the single-stage behaviour, and it is what the second
		// stage exists to improve on.
		// 未配置验证器：高歧义候选沿用提取器的判断。
		// 这就是单阶段行为，也正是第二阶段要改进的对象。
		out.Redact = append(out.Redact, ambiguous...)
	}

	// ---- CAPID: keep what the answer depends on ----
	// ---- CAPID：保留回答所依赖的部分 ----
	if p.Relevance != nil {
		kept := out.Redact[:0:0]
		for _, e := range out.Redact {
			if d, preserve := p.Relevance.Assess(text, e); preserve {
				out.Preserved = append(out.Preserved, d)
				continue
			}
			kept = append(kept, e)
		}
		out.Redact = kept
	}

	return out, nil
}

// AuditSummary renders counts only — never values. The summary is written to
// logs that outlive the request; a value written there is a permanent leak.
// 只渲染计数，绝不渲染值。摘要会写进比请求存活更久的日志，
// 写进去的值就是永久泄露。
func (o *Outcome) AuditSummary() map[string]int {
	return map[string]int{
		"redacted":  len(o.Redact),
		"dropped":   len(o.Dropped),
		"preserved": len(o.Preserved),
		"undecided": len(o.Undecided),
	}
}
