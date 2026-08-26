package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// 由配置结构体反射生成 OpenAPI v3 Schema 与 Kubernetes CRD。
//
// # 为什么要生成而不是手写
//
// 手写的 CRD 会和 Go 结构体漂移：加了字段忘了同步 schema，
// APIServer 就会拒绝一个完全合法的配置；删了字段忘了同步，
// APIServer 就会放行一个网关不认识的字段。两种漂移都很难察觉。
//
// 反射生成保证单一事实来源，再配一个测试断言仓库里的 CRD
// 与生成结果一致，漂移在 CI 就会被拦下。
//
// # additionalProperties: false 是关键
//
// 它在 APIServer 侧实现了与 KnownFields(true) 完全相同的语义：
// 任何拼错的键在 kubectl apply 阶段就被拒绝，根本进不到网关内存里。
// 这是第三层拦截——最靠前、代价最小的那一层。

// Schema 是 OpenAPI v3 Schema 的一个子集，够用于 CRD。
type Schema struct {
	Type        string             `yaml:"type,omitempty" json:"type,omitempty"`
	Format      string             `yaml:"format,omitempty" json:"format,omitempty"`
	Description string             `yaml:"description,omitempty" json:"description,omitempty"`
	Properties  map[string]*Schema `yaml:"properties,omitempty" json:"properties,omitempty"`
	Items       *Schema            `yaml:"items,omitempty" json:"items,omitempty"`
	Enum        []string           `yaml:"enum,omitempty" json:"enum,omitempty"`
	Pattern     string             `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Minimum     *float64           `yaml:"minimum,omitempty" json:"minimum,omitempty"`
	Maximum     *float64           `yaml:"maximum,omitempty" json:"maximum,omitempty"`
	Required    []string           `yaml:"required,omitempty" json:"required,omitempty"`

	// AdditionalProperties 承担两种语义：
	//   false            —— 拒绝未声明字段（对象类型）
	//   {type: "..."}    —— map 的值类型
	AdditionalProperties any `yaml:"additionalProperties,omitempty" json:"additionalProperties,omitempty"`
}

// durationPattern 约束时长格式，与 Duration.UnmarshalYAML 保持一致。
// 在 APIServer 侧就拒绝 "300"（裸数字）和 "300mss"（非法单位）。
const durationPattern = `^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$`

// GenerateSchema 反射生成配置的 OpenAPI v3 Schema。
func GenerateSchema() *Schema {
	return schemaOf(reflect.TypeOf(Config{}))
}

// schemaOf 递归生成某个类型的 schema。
func schemaOf(t reflect.Type) *Schema {
	// 自定义类型优先：它们有专门的解析与校验语义
	if s := customSchema(t); s != nil {
		return s
	}

	switch t.Kind() {
	case reflect.String:
		return &Schema{Type: "string"}
	case reflect.Bool:
		return &Schema{Type: "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return &Schema{Type: "integer"}
	case reflect.Float32, reflect.Float64:
		return &Schema{Type: "number"}
	case reflect.Slice:
		return &Schema{Type: "array", Items: schemaOf(t.Elem())}
	case reflect.Map:
		// map 的键在 OpenAPI 里恒为 string，值类型由 additionalProperties 表达
		return &Schema{Type: "object", AdditionalProperties: schemaOf(t.Elem())}
	case reflect.Ptr:
		return schemaOf(t.Elem())
	case reflect.Struct:
		return structSchema(t)
	default:
		// 兜底为自由对象。出现这种情况说明配置里有 schema 表达不了的类型，
		// 应当调整结构体而不是放任它逃过校验
		return &Schema{Type: "object"}
	}
}

// customSchema 为带自定义解析逻辑的类型生成对应约束。
func customSchema(t reflect.Type) *Schema {
	switch t {
	case reflect.TypeOf(Duration(0)):
		return &Schema{
			Type: "string", Pattern: durationPattern,
			Description: "时长，必须带单位（如 300ms / 5s / 1h30m）。不接受裸数字",
		}
	case reflect.TypeOf(EntityTypeName("")):
		return &Schema{Type: "string", Enum: EntityTypeNames(),
			Description: "PII 实体类型"}
	case reflect.TypeOf(JurisdictionCode("")):
		return &Schema{Type: "string", Enum: JurisdictionCodes(),
			Description: "国家合规包代码"}
	case reflect.TypeOf(TaskName("")):
		return &Schema{Type: "string", Enum: TaskNames(),
			Description: "任务类型，用于路由定级"}
	case reflect.TypeOf(InjectModeName("")):
		return &Schema{Type: "string", Enum: InjectModeNames(),
			Description: "凭证注入方式"}
	case reflect.TypeOf(TierNumber(0)):
		min, max := 1.0, 9.0
		return &Schema{Type: "integer", Minimum: &min, Maximum: &max,
			Description: "性能梯队，数值越小档次越高"}
	}
	return nil
}

// structSchema 生成结构体的 schema。
func structSchema(t reflect.Type) *Schema {
	s := &Schema{
		Type:       "object",
		Properties: map[string]*Schema{},
		// 这一行是第三层拦截的核心：APIServer 会据此拒绝任何未声明的字段
		AdditionalProperties: false,
	}

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("yaml")
		name, opts, _ := strings.Cut(tag, ",")

		// 内嵌字段（`,inline`）的属性要提升到父层，
		// 否则生成的 schema 会多出一层不存在的嵌套
		if strings.Contains(opts, "inline") || (name == "" && f.Anonymous) {
			inner := schemaOf(f.Type)
			for k, v := range inner.Properties {
				s.Properties[k] = v
			}
			continue
		}
		if name == "" || name == "-" {
			continue
		}
		s.Properties[name] = schemaOf(f.Type)
	}
	return s
}

// CRDOptions 控制 CRD 生成。
type CRDOptions struct {
	Group    string
	Version  string
	Kind     string
	Plural   string
	Singular string
}

// DefaultCRDOptions 返回默认的 CRD 元数据。
func DefaultCRDOptions() CRDOptions {
	return CRDOptions{
		// CRD group 是集群内的永久标识：一旦有资源用它创建过，
		// 改 group 等于换一个全新的 CRD，旧资源全部失效。发布前必须定死。
		// The CRD group is a permanent cluster-wide identifier: once resources
		// exist under it, changing it means a brand-new CRD and every existing
		// resource becomes orphaned. It must be settled before release.
		Group:    "airlock.sh",
		Version:  "v1alpha1",
		Kind:     "AirlockConfig",
		Plural:   "airlockconfigs",
		Singular: "airlockconfig",
	}
}

// GenerateCRD 生成 Kubernetes CustomResourceDefinition。
//
// 部署后，一份拼错键的配置会在 kubectl apply 阶段被 APIServer 直接拒绝，
// 根本没有机会进入网关内存——这比进程启动时才 fail-fast 更靠前，
// 也更便宜：错误在提交时就被挡住，而不是在滚动更新一半时。
func GenerateCRD(opts CRDOptions) ([]byte, error) {
	spec := GenerateSchema()
	spec.Description = "AI 网关配置。所有对象均设 additionalProperties: false，" +
		"未声明的字段会在 kubectl apply 阶段被拒绝"

	crd := map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1",
		"kind":       "CustomResourceDefinition",
		"metadata": map[string]any{
			"name": opts.Plural + "." + opts.Group,
		},
		"spec": map[string]any{
			"group": opts.Group,
			"names": map[string]any{
				"kind":     opts.Kind,
				"listKind": opts.Kind + "List",
				"plural":   opts.Plural,
				"singular": opts.Singular,
			},
			"scope": "Namespaced",
			"versions": []any{map[string]any{
				"name":    opts.Version,
				"served":  true,
				"storage": true,
				"schema": map[string]any{
					"openAPIV3Schema": map[string]any{
						"type":                 "object",
						"additionalProperties": false,
						"properties": map[string]any{
							"apiVersion": map[string]any{"type": "string"},
							"kind":       map[string]any{"type": "string"},
							"metadata":   map[string]any{"type": "object"},
							"spec":       spec,
						},
						"required": []string{"spec"},
					},
				},
			}},
		},
	}

	var buf strings.Builder
	buf.WriteString("# 本文件由 `gateway --print-crd` 生成，请勿手工编辑。\n")
	buf.WriteString("# 单一事实来源是 internal/config 的结构体定义；\n")
	buf.WriteString("# CI 会断言本文件与生成结果一致，防止 schema 与代码漂移。\n")

	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(crd); err != nil {
		return nil, fmt.Errorf("序列化 CRD 失败: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// SchemaFieldPaths 返回 schema 中全部叶子字段路径，供文档与测试使用。
func SchemaFieldPaths() []string {
	var out []string
	var walk func(prefix string, s *Schema)
	walk = func(prefix string, s *Schema) {
		if len(s.Properties) == 0 {
			if prefix != "" {
				out = append(out, prefix)
			}
			return
		}
		for name, child := range s.Properties {
			p := name
			if prefix != "" {
				p = prefix + "." + name
			}
			if child.Type == "array" && child.Items != nil {
				walk(p+"[]", child.Items)
				continue
			}
			walk(p, child)
		}
	}
	walk("", GenerateSchema())
	sort.Strings(out)
	return out
}
