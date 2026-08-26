package eval

import (
	"fmt"
	"sort"
	"strings"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// Result holds one evaluation run's counts.
// 存放一次评测的计数。
type Result struct {
	TruePositives  int
	FalsePositives int
	FalseNegatives int

	// PartialMatches are predictions that overlap a gold span without matching
	// its boundaries.
	// 是与标准答案重叠但边界不符的预测。
	//
	// Counted separately rather than folded into either bucket. A partial match
	// is not a clean miss — the value was found — but it is not a success
	// either: a card number redacted from the fifth digit on has leaked its
	// first four, and the placeholder it produced will not restore to the
	// original.
	// 单独计数，不并入任何一桶。部分匹配不是干净的漏报——值被找到了——
	// 但也不是成功：一个从第五位起才被脱敏的卡号，前四位已经泄露出去了，
	// 而它产生的占位符也还原不回原值。
	PartialMatches int

	// TypeMismatches are spans found at the right place with the wrong type.
	// 是位置正确但类型错误的命中。
	//
	// The value is protected, so this is not a leak — but the type drives the
	// strategy matrix, so a phone classified as an account number is redacted
	// under whatever policy that flow set for accounts.
	// 值被保护了，所以这不是泄露——但类型驱动策略矩阵，
	// 一个被判成账号的手机号，会按该链路给账号配的策略脱敏。
	TypeMismatches int

	ByCategory map[string]*Result
	Misses     []string
	Spurious   []string
}

// Recall reports the fraction of gold spans found.
// 报告标准答案中被找到的比例。
func (r *Result) Recall() float64 {
	total := r.TruePositives + r.FalseNegatives + r.PartialMatches + r.TypeMismatches
	if total == 0 {
		return 1
	}
	return float64(r.TruePositives) / float64(total)
}

// Precision reports the fraction of predictions that were correct.
// 报告预测中正确的比例。
func (r *Result) Precision() float64 {
	total := r.TruePositives + r.FalsePositives + r.PartialMatches + r.TypeMismatches
	if total == 0 {
		return 1
	}
	return float64(r.TruePositives) / float64(total)
}

// F1 is the harmonic mean.
// 是调和平均。
func (r *Result) F1() float64 {
	p, rc := r.Precision(), r.Recall()
	if p+rc == 0 {
		return 0
	}
	return 2 * p * rc / (p + rc)
}

func newResult() *Result {
	return &Result{ByCategory: map[string]*Result{}}
}

func (r *Result) category(name string) *Result {
	if r.ByCategory == nil {
		r.ByCategory = map[string]*Result{}
	}
	c, ok := r.ByCategory[name]
	if !ok {
		c = &Result{}
		r.ByCategory[name] = c
	}
	return c
}

// Score runs a detector over samples and scores it span by span.
// 用检测器跑一遍样本，逐 span 打分。
//
// Exact boundaries are required for a true positive. A looser rule — "overlaps
// a gold span" — is the standard way an evaluation flatters the thing it is
// measuring, and it hides precisely the failure that matters: a match whose
// boundaries are wrong redacts the wrong bytes.
// 判为真阳性要求边界完全一致。更宽松的规则——「与标准答案重叠即可」——
// 是评测讨好被测对象的标准做法，而它恰好掩盖了最要紧的那种失败：
// 边界错的命中，脱敏的是错的字节。
func Score(d detect.Detector, samples []Sample) (*Result, error) {
	res := newResult()

	for _, s := range samples {
		cat := res.category(s.Category)

		found, err := d.Detect(s.Text)
		if err != nil {
			return nil, fmt.Errorf("样本 %s 检测失败 / detecting %s: %w", s.Name, s.Name, err)
		}

		matchedGold := make([]bool, len(s.Gold))
		matchedPred := make([]bool, len(found))

		// 第一轮：精确匹配（位置 + 类型）
		for pi, p := range found {
			for gi, g := range s.Gold {
				if matchedGold[gi] || matchedPred[pi] {
					continue
				}
				if p.Start == g.Start && p.End == g.End && p.Type == g.Type {
					matchedGold[gi], matchedPred[pi] = true, true
					res.TruePositives++
					cat.TruePositives++
					break
				}
			}
		}

		// 第二轮：位置对但类型错
		for pi, p := range found {
			if matchedPred[pi] {
				continue
			}
			for gi, g := range s.Gold {
				if matchedGold[gi] {
					continue
				}
				if p.Start == g.Start && p.End == g.End {
					matchedGold[gi], matchedPred[pi] = true, true
					res.TypeMismatches++
					cat.TypeMismatches++
					res.Misses = append(res.Misses, fmt.Sprintf(
						"%s: 类型不符 %q 判为 %s，应为 %s", s.Name, s.Text[g.Start:g.End], p.Type, g.Type))
					break
				}
			}
		}

		// 第三轮：重叠但边界错
		for pi, p := range found {
			if matchedPred[pi] {
				continue
			}
			for gi, g := range s.Gold {
				if matchedGold[gi] {
					continue
				}
				if p.Start < g.End && g.Start < p.End {
					matchedGold[gi], matchedPred[pi] = true, true
					res.PartialMatches++
					cat.PartialMatches++
					res.Misses = append(res.Misses, fmt.Sprintf(
						"%s: 边界不符 命中 %q，应为 %q",
						s.Name, s.Text[p.Start:p.End], s.Text[g.Start:g.End]))
					break
				}
			}
		}

		for gi, ok := range matchedGold {
			if !ok {
				g := s.Gold[gi]
				res.FalseNegatives++
				cat.FalseNegatives++
				res.Misses = append(res.Misses, fmt.Sprintf(
					"%s: 漏报 %s %q", s.Name, g.Type, s.Text[g.Start:g.End]))
			}
		}
		for pi, ok := range matchedPred {
			if !ok {
				p := found[pi]
				res.FalsePositives++
				cat.FalsePositives++
				res.Spurious = append(res.Spurious, fmt.Sprintf(
					"%s: 误报 %s %q", s.Name, p.Type, p.Value))
			}
		}
	}
	return res, nil
}

// Report renders a result table.
// 渲染结果表。
func (r *Result) Report(title string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n%s\n", title)
	fmt.Fprintf(&b, "%s\n", strings.Repeat("─", 78))
	fmt.Fprintf(&b, "%-16s %6s %6s %6s %6s %6s  %8s %8s\n",
		"分类", "TP", "FP", "FN", "部分", "类型错", "召回", "精确")

	cats := make([]string, 0, len(r.ByCategory))
	for name := range r.ByCategory {
		cats = append(cats, name)
	}
	sort.Strings(cats)
	for _, name := range cats {
		c := r.ByCategory[name]
		fmt.Fprintf(&b, "%-16s %6d %6d %6d %6d %6d  %7.2f%% %7.2f%%\n",
			name, c.TruePositives, c.FalsePositives, c.FalseNegatives,
			c.PartialMatches, c.TypeMismatches, c.Recall()*100, c.Precision()*100)
	}
	fmt.Fprintf(&b, "%s\n", strings.Repeat("─", 78))
	fmt.Fprintf(&b, "%-16s %6d %6d %6d %6d %6d  %7.2f%% %7.2f%%\n",
		"合计", r.TruePositives, r.FalsePositives, r.FalseNegatives,
		r.PartialMatches, r.TypeMismatches, r.Recall()*100, r.Precision()*100)
	return b.String()
}
