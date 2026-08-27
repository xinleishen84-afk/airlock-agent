// Package preset 提供检测器的标准装配。
//
// Standard detector assemblies.
//
// # 为什么它必须存在
// # Why this package exists
//
// 曾经有两份装配：二进制在 main.go 里搭一个，评测在测试里手工搭一个。
// 两份看起来一样，实际不一样——评测那份装了复姓识别，二进制那份没装。
//
// 后果是我拿评测的数字去描述二进制的能力：报告「Core 覆盖 90.5%，
// 复姓 欧阳志远 ✓」，而真实二进制对「经办人欧阳志远」返回的是
// {PHONE: 1}——一个字都没认出来。
//
// There used to be two assemblies: one in main.go and one hand-built in the
// evaluation. They looked the same and were not — the evaluation had surname
// recognition and the binary did not. The measured numbers therefore described
// a configuration the shipped binary could not produce.
//
// 一份装配，两处使用。评测量的就是二进制跑的。
// One assembly, used by both. What is measured is what runs.
package preset

import (
	"fmt"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
	"github.com/xinleishen84-afk/airlock-agent/pii/verify"
)

// CoreOptions configures the Core-mode assembly.
// 配置 Core 模式的装配。
type CoreOptions struct {
	// Jurisdictions 是要加载的国家包代码。必填。
	Jurisdictions []string

	// Roster 是企业主数据名册。
	Roster map[detect.EntityType][]string

	// Surnames 启用复姓识别。
	Surnames bool

	// SingleSurnames 启用单姓识别。
	//
	// 实测在对抗性语料上召回零增益、误报十四处，因此默认关闭。
	// Measured: zero recall gain and fourteen false positives on the
	// adversarial corpus.
	SingleSurnames bool

	// DisabledTypes 关闭特定实体类型。
	DisabledTypes []detect.EntityType
}

// Core builds the Core-mode detector and its evidence validator.
// 构建 Core 模式的检测器与证据链验证器。
//
// 验证器一并返回，而不是让调用方自己去建。
//
// 证据链不是可选装饰：复姓识别产出的是**候选**，「尉迟恭」与「尉迟恭负」
// 会同时产出，靠证据链按上下文收边界；而单姓候选（王者荣、李子、杨梅）
// 靠它按置信度否决。不接验证器就把候选当判决用，误报会直接进脱敏管线。
//
// The validator is returned alongside rather than left to the caller. It is
// not optional decoration: surname recognition emits candidates — 尉迟恭 and
// 尉迟恭负 both — which the evidence chain trims by context, and single-surname
// candidates which it rejects by confidence. Without it, candidates are used
// as verdicts.
func Core(opts CoreOptions) (detect.Detector, *verify.EvidenceValidator, error) {
	if len(opts.Jurisdictions) == 0 {
		return nil, nil, fmt.Errorf(
			"必须指定至少一个国家包——一个都不装意味着任何文本都扫不出 PII，" +
				"且看起来像「数据很干净」 / at least one jurisdiction is required")
	}

	reg, err := packs.NewRegistry(opts.Jurisdictions, opts.DisabledTypes...)
	if err != nil {
		return nil, nil, err
	}
	detectors := []detect.Detector{reg}

	if len(opts.Roster) > 0 {
		gaz, err := detect.NewGazetteerDetector(opts.Roster, false, 2)
		if err != nil {
			return nil, nil, fmt.Errorf("构造名册检测器: %w", err)
		}
		detectors = append(detectors, gaz)
	}

	if opts.Surnames {
		so := detect.DefaultSurnameOptions()
		so.IncludeSingle = opts.SingleSurnames
		sr, err := detect.NewSurnameRecognizer(so)
		if err != nil {
			return nil, nil, err
		}
		// 直接适配，不经 Registry —— Registry.Detect 内部会跑 ResolveOverlaps，
		// 而那会在证据链看到候选之前就按「长者优先」把正确的那个淘汰掉。
		// Adapted directly: Registry.Detect resolves overlaps internally, which
		// discards the right candidate before the evidence chain sees it.
		detectors = append(detectors, detect.AsDetector(sr))
	}

	validator, err := verify.NewDefaultEvidenceValidator()
	if err != nil {
		return nil, nil, err
	}

	// 重叠消解延后到证据链：它按结论强度与得分取舍，而「长者优先」
	// 会在它之前把正确的候选淘汰掉。
	// Overlap resolution is deferred to the evidence chain.
	return detect.NewCompositeDetectorDeferred(detectors, 0), validator, nil
}

// DefaultCoreOptions returns the assembly the measured numbers describe.
// 返回实测数字所描述的那套装配。
//
// 报告里的「Core 覆盖 90.5%」「261k QPS」都是在这套装配上量的。
// 改了这里，那些数字就不再成立——所以有一条用例把二进制的装配
// 与这个函数钉在一起。
//
// The reported coverage and throughput were measured on this. Changing it
// invalidates them, so a test pins the binary's assembly to this function.
func DefaultCoreOptions(jurisdictions []string) CoreOptions {
	return CoreOptions{
		Jurisdictions:  jurisdictions,
		Surnames:       true,
		SingleSurnames: false,
	}
}
