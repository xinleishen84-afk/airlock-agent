package anonymize

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
)

// # Generalization / 本体泛化
//
// Replacing a value with a broader term keeps the statistic and drops the
// identifier: a cohort study still needs to know the patient was born in the
// 1990s and is a doctor; it does not need 1995-10-24 and 外科医生.
// 用更抽象的上位词替换具体值，保住统计量、丢掉标识：
// 一项队列研究仍需要知道患者生于 1990 年代、职业是医生，
// 但它不需要 1995-10-24 和「外科医生」。
//
// # What generalization is not
// # 泛化不是什么
//
// It is not a privacy guarantee, and treating it as one is the classic way
// de-identified datasets get re-identified. Coarsening one field in isolation
// says nothing about how many people share the result: "1990s" plus a rare
// specialty plus a small city can still be exactly one person. The guarantee
// people actually want — k-anonymity — is a property of a whole released
// dataset, computed across quasi-identifiers, and a gateway looking at one
// request has no way to compute it.
// 它不是隐私保证，而把它当成隐私保证，正是「去标识化数据集被重新识别」
// 的经典成因。孤立地粗化一个字段，无法说明有多少人共享这个结果：
// 「1990 年代」加上一个罕见专科加上一座小城，仍然可能恰好是一个人。
// 人们真正想要的那个保证——k-匿名——是整个发布数据集的属性，
// 需要跨准标识符计算，而一个只看得见单条请求的网关无从计算。
//
// So this operator's honest claim is: it reduces precision in a way that
// preserves analytic utility. Whether the result is anonymous is a question
// about the corpus, answered somewhere else.
// 因此本算子诚实的说法是：它以保住分析效用的方式降低精度。
// 结果是否匿名，是关于整个语料的问题，要在别处回答。

// dateGranularity is how far a date is coarsened.
// 是日期被粗化到的粒度。
type dateGranularity string

const (
	// GranularityYear keeps the year: 1995-10-24 -> 1995.
	// 保留到年：1995-10-24 -> 1995。
	GranularityYear dateGranularity = "year"

	// GranularityDecade keeps the decade: 1995-10-24 -> 1990s.
	// 保留到十年：1995-10-24 -> 1990s。
	GranularityDecade dateGranularity = "decade"
)

// Ontology maps specific terms to their hypernyms.
// 把具体词映射到其上位词。
//
// Shipped empty on purpose. A built-in medical or occupational hierarchy would
// be wrong for most deployments and, worse, wrong invisibly: a term absent from
// the table passes through unchanged, so a table that looks plausible but does
// not match the corpus generalizes some values and silently leaks the rest.
// The real hierarchies (SNOMED CT, ICD, ISCO) are licensed, versioned, and
// domain-specific — they belong to the deployment, not to this library.
// 刻意不内置词表。内置一套医学或职业层级，对多数部署都是错的，
// 更糟的是错得看不见：表里没有的词会原样通过，
// 于是一张「看起来像那么回事」但与语料对不上的表，
// 会泛化掉一部分值、静默漏掉其余的。
// 真正的层级体系（SNOMED CT、ICD、ISCO）有授权、有版本、分领域——
// 它们属于部署方，不属于这个库。
type Ontology struct {
	// Terms maps a specific term to its hypernym.
	// 把具体词映射到上位词。
	Terms map[string]string `yaml:"terms"`
}

// LoadOntology reads an ontology from YAML.
// 从 YAML 读取本体词表。
func LoadOntology(r io.Reader) (*Ontology, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var o Ontology
	if err := dec.Decode(&o); err != nil {
		return nil, fmt.Errorf("解析本体词表失败 / parsing ontology: %w", err)
	}
	if len(o.Terms) == 0 {
		return nil, fmt.Errorf("本体词表为空——空表会让每个值原样通过 / ontology is empty")
	}
	for term, hypernym := range o.Terms {
		if strings.TrimSpace(hypernym) == "" {
			return nil, fmt.Errorf("词条 %q 的上位词为空 / empty hypernym for %q", term, term)
		}
		if term == hypernym {
			return nil, fmt.Errorf("词条 %q 的上位词与自身相同，泛化后等于原值 / %q generalizes to itself",
				term, term)
		}
	}
	return &o, nil
}

// LoadOntologyFile reads an ontology from a file.
// 从文件读取本体词表。
func LoadOntologyFile(path string) (*Ontology, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开本体词表失败 / opening ontology: %w", err)
	}
	defer f.Close()
	return LoadOntology(f)
}

// lookup returns the hypernym for a term, matching case-insensitively.
// 查找一个词的上位词，匹配时不区分大小写。
func (o *Ontology) lookup(term string) (string, bool) {
	if o == nil {
		return "", false
	}
	if h, ok := o.Terms[term]; ok {
		return h, true
	}
	lower := strings.ToLower(strings.TrimSpace(term))
	for k, v := range o.Terms {
		if strings.ToLower(k) == lower {
			return v, true
		}
	}
	return "", false
}

// isoDateRe matches the date forms this operator coarsens.
// 匹配本算子会粗化的日期形态。
var isoDateRe = regexp.MustCompile(
	`^(1[89][0-9]{2}|20[0-9]{2})[-/年]([0-9]{1,2})[-/月]([0-9]{1,2})日?$`)

// yearOnlyRe matches a bare four-digit year.
// 匹配裸的四位年份。
var yearOnlyRe = regexp.MustCompile(`^(1[89][0-9]{2}|20[0-9]{2})年?$`)

// GeneralizeStrategy replaces a value with a broader term.
// 用更抽象的词替换值。
type GeneralizeStrategy struct {
	ontology    *Ontology
	granularity dateGranularity

	// fallback is applied when neither the date rules nor the ontology match.
	// 当日期规则与本体词表都没命中时使用。
	//
	// Required, and required to be a real operator rather than "leave it": a
	// term missing from the ontology is precisely the value nobody anticipated,
	// which makes passing it through the worst possible default.
	// 必填，且必须是一个真正的算子而不是「原样放过」：
	// 词表里没有的词，恰恰是没人预料到的那个值，
	// 因此原样放过是最糟的默认行为。
	fallback Strategy
}

// NewGeneralize builds the generalizing operator.
// 构造泛化算子。
func NewGeneralize(o *Ontology, granularity dateGranularity, fallback Strategy) (GeneralizeStrategy, error) {
	switch granularity {
	case GranularityYear, GranularityDecade:
	default:
		return GeneralizeStrategy{}, fmt.Errorf(
			"%w: 未知的日期粒度 %q，可用 year|decade / unknown granularity",
			ErrStrategy, granularity)
	}
	if fallback == nil {
		return GeneralizeStrategy{}, fmt.Errorf(
			"%w: 泛化算子必须配置兜底算子——词表未覆盖的值若原样通过，"+
				"泄露的正是没人预料到的那一个/ generalize requires a fallback",
			ErrStrategy)
	}
	if _, isSelf := fallback.(GeneralizeStrategy); isSelf {
		return GeneralizeStrategy{}, fmt.Errorf(
			"%w: 兜底算子不能是泛化算子自身 / fallback must not be generalize itself", ErrStrategy)
	}
	return GeneralizeStrategy{ontology: o, granularity: granularity, fallback: fallback}, nil
}

// Name implements Strategy.
func (GeneralizeStrategy) Name() string { return "generalize" }

// Reversible implements Strategy.
//
// False even when the fallback is reversible: the caller cannot know which
// branch ran, so the flow as a whole cannot be restored.
// 即使兜底算子可逆也返回 false：调用方无从知道走了哪条分支，
// 因此整条链路无法复原。
func (GeneralizeStrategy) Reversible() bool { return false }

// Apply implements Strategy.
func (s GeneralizeStrategy) Apply(ctx context.Context, scope StrategyScope, e detect.Entity) (string, error) {
	value := strings.TrimSpace(e.Value)

	if out, ok := s.generalizeDate(value); ok {
		return out, nil
	}
	if h, ok := s.ontology.lookup(value); ok {
		return h, nil
	}
	return s.fallback.Apply(ctx, scope, e)
}

// generalizeDate coarsens a date to the configured granularity.
// 把日期粗化到配置的粒度。
func (s GeneralizeStrategy) generalizeDate(value string) (string, bool) {
	var year string
	switch {
	case isoDateRe.MatchString(value):
		year = isoDateRe.FindStringSubmatch(value)[1]
	case yearOnlyRe.MatchString(value):
		year = yearOnlyRe.FindStringSubmatch(value)[1]
	default:
		return "", false
	}

	if s.granularity == GranularityYear {
		return year, true
	}
	n, err := strconv.Atoi(year)
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("%ds", n/10*10), true
}
