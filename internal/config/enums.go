package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/xinleishen84-afk/airlock-agent/internal/credential"
	"github.com/xinleishen84-afk/airlock-agent/internal/identity"
	"github.com/xinleishen84-afk/airlock-agent/pii/detect"
	"go.yaml.in/yaml/v3"
)

// 枚举必须强类型解析，理由见包注释里的第 2 层。
//
// 一个具体的失效路径：NER 配置里把 "NAME" 拼成 "NAEM"。
// 若按普通字符串处理，网关会把它当成一个「未知但合法」的类型：
//
//   - 向 NER 服务申请的 types 里没有 NAME —— 人名从此不再被识别
//   - 但检测器的 CoveredTypes() 里有 "NAEM"，覆盖度自检看不出缺口
//   - 于是启动日志报告「无缺口」，姓名却在持续泄露
//
// 这类错误不会有任何报错、任何告警，只有在事后审计时才可能发现。

// EntityTypeName 是经校验的 PII 实体类型名。
type EntityTypeName string

// knownEntityTypes 是全部合法的实体类型。
var knownEntityTypes = map[detect.EntityType]bool{
	detect.TypeName: true, detect.TypePhone: true, detect.TypeEmail: true,
	detect.TypeIDCard: true, detect.TypeBankCard: true, detect.TypeAddress: true,
	detect.TypeOrg: true, detect.TypeIP: true, detect.TypeCredential: true,
	detect.TypePassport: true, detect.TypeLicensePlate: true, detect.TypeSSN: true,
	detect.TypeUSCC: true,
}

// EntityTypeNames 返回全部合法类型名（已排序），供报错信息与 schema 生成使用。
func EntityTypeNames() []string {
	out := make([]string, 0, len(knownEntityTypes))
	for t := range knownEntityTypes {
		out = append(out, string(t))
	}
	sort.Strings(out)
	return out
}

// UnmarshalYAML 解析并校验实体类型名。
func (e *EntityTypeName) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("第 %d 行：实体类型必须是字符串", node.Line)
	}
	normalized := detect.EntityType(strings.ToUpper(strings.TrimSpace(raw)))
	if !knownEntityTypes[normalized] {
		return fmt.Errorf(
			"第 %d 行：未知的 PII 实体类型 %q。合法取值：%s",
			node.Line, raw, strings.Join(EntityTypeNames(), " / "))
	}
	*e = EntityTypeName(normalized)
	return nil
}

// PII 返回底层类型。
func (e EntityTypeName) PII() detect.EntityType { return detect.EntityType(e) }

// TaskName 是经校验的任务类型名。
type TaskName string

// knownTasks 是全部合法任务类型。
var knownTasks = []identity.TaskKind{
	identity.TaskPlanning, identity.TaskReasoning, identity.TaskCodeGeneration,
	identity.TaskToolOrchestration, identity.TaskExtraction, identity.TaskClassification,
	identity.TaskSummarization, identity.TaskTranslation, identity.TaskRerank,
	identity.TaskEmbeddingPrep, identity.TaskUnknown,
}

// TaskNames 返回全部合法任务类型名。
func TaskNames() []string {
	out := make([]string, 0, len(knownTasks))
	for _, t := range knownTasks {
		out = append(out, string(t))
	}
	sort.Strings(out)
	return out
}

// UnmarshalYAML 解析并校验任务类型名。
//
// 这里同样是静默失效的高发区：规则里把 "extraction" 拼成 "extration"，
// 规则永远匹配不上，批量作业会一路走到昂贵的 Tier1，
// 而配置看起来完全正常。
func (t *TaskName) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("第 %d 行：任务类型必须是字符串", node.Line)
	}
	normalized := strings.ToLower(strings.TrimSpace(raw))
	for _, known := range knownTasks {
		if string(known) == normalized {
			*t = TaskName(normalized)
			return nil
		}
	}
	return fmt.Errorf("第 %d 行：未知的任务类型 %q。合法取值：%s",
		node.Line, raw, strings.Join(TaskNames(), " / "))
}

// Task 返回底层类型。
func (t TaskName) Task() identity.TaskKind { return identity.TaskKind(t) }

// InjectModeName 是经校验的凭证注入方式。
type InjectModeName string

// InjectModeNames 返回全部合法注入方式。
func InjectModeNames() []string {
	return []string{string(credential.InjectBearer), string(credential.InjectHeader)}
}

// UnmarshalYAML 解析并校验注入方式。
func (m *InjectModeName) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("第 %d 行：注入方式必须是字符串", node.Line)
	}
	normalized := strings.ToLower(strings.TrimSpace(raw))
	for _, known := range InjectModeNames() {
		if known == normalized {
			*m = InjectModeName(normalized)
			return nil
		}
	}
	return fmt.Errorf("第 %d 行：未知的凭证注入方式 %q。合法取值：%s",
		node.Line, raw, strings.Join(InjectModeNames(), " / "))
}

// Mode 返回底层类型。
func (m InjectModeName) Mode() credential.InjectMode {
	if m == "" {
		return credential.InjectBearer
	}
	return credential.InjectMode(m)
}

// TierNumber 是经校验的梯队编号。
type TierNumber int

// UnmarshalYAML 解析并校验梯队编号。
func (t *TierNumber) UnmarshalYAML(node *yaml.Node) error {
	var raw int
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("第 %d 行：梯队必须是整数", node.Line)
	}
	// 上限刻意留宽：三级、四级梯队都是合理的部署形态，
	// 不该被网关的类型定义限死
	if raw < 1 || raw > 9 {
		return fmt.Errorf("第 %d 行：梯队编号 %d 越界，须在 1~9 之间（数值越小档次越高）",
			node.Line, raw)
	}
	*t = TierNumber(raw)
	return nil
}
