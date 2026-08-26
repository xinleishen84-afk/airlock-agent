// Package config 是网关的配置装配层。
//
// # 严格解析原则（Fail-Fast）
//
// 配置错误必须在进程初始化阶段就炸掉，而不是在运行时以「某个功能
// 静默失效」的形式表现出来。本包为此做三层强制：
//
//  1. 未知字段拒绝    KnownFields(true) —— 拼错的键立刻报错
//  2. 强类型枚举      拼错的枚举值立刻报错，而不是当成「未启用」
//  3. 语义校验        取值范围、字段间约束、必填项
//
// 三层缺一不可。只做第 1 层的话，`types: ["NAEM"]` 这种**值**的拼写错误
// 照样能过——而它意味着网关从未向 NER 申请过人名识别，姓名直接泄露，
// 且自检会报告「无缺口」。
package config

import (
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"
)

// Duration 是带严格解析的时长。
//
// 刻意**拒绝裸数字**。用纳秒整数表达时长（60000000000）有两个问题：
//
//  1. 无法人工复核——60000000000 与 6000000000 差 10 倍，肉眼看不出来
//  2. 单位歧义——写 300 到底是 300 纳秒、300 毫秒还是 300 秒？
//     任何一种默认都会在某些字段上出错
//
// 因此只接受带单位的字符串："300ms"、"1h30m"、"5s"。
type Duration time.Duration

// Std 返回标准库时长。
func (d Duration) Std() time.Duration { return time.Duration(d) }

// String 返回可读表示。
func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalYAML 解析时长。同时服务于 YAML 与 JSON（JSON 是 YAML 的子集）。
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		// 解不成字符串，多半是写了裸数字
		var num float64
		if node.Decode(&num) == nil {
			return fmt.Errorf(
				"第 %d 行：时长必须带单位（如 \"300ms\"、\"1h\"），不接受裸数字 %v——"+
					"纳秒整数无法人工复核，且单位含义有歧义", node.Line, num)
		}
		return fmt.Errorf("第 %d 行：无法解析为时长: %w", node.Line, err)
	}

	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("第 %d 行：非法时长 %q（合法示例：300ms / 5s / 1h30m）",
			node.Line, raw)
	}
	if parsed < 0 {
		return fmt.Errorf("第 %d 行：时长不能为负（%s）", node.Line, raw)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML 输出可读时长，保证 round-trip 后仍是人类可读的形式。
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }
