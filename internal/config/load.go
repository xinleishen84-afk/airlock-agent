package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Load 从文件严格加载配置。
//
// 同时支持 YAML 与 JSON：YAML 1.2 是 JSON 的超集，一套解析器通吃，
// 不必为两种格式各维护一条代码路径（那正是行为分叉的温床）。
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开配置文件失败: %w", err)
	}
	defer f.Close()
	return Decode(f, path)
}

// Decode 从流严格解码配置。
func Decode(r io.Reader, source string) (*Config, error) {
	dec := yaml.NewDecoder(r)

	// 这一行是整个严格解析的核心：任何与 struct tag 对不上的键
	// 都会立刻报错并中断，而不是被静默忽略。
	//
	// 没有它，`token_per_window`（少个 s）会被当作不存在，
	// 限流静默退回默认值——运维以为配了 500 万 token 配额，
	// 实际上是无限制，直到某天 GPU 被打爆才发现。
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: 配置文件为空", source)
		}
		return nil, fmt.Errorf("%s: %w", source, enrichDecodeError(err))
	}

	// 检查是否有多余的 YAML 文档。多文档配置几乎总是误操作
	// （比如从 K8s manifest 里复制粘贴时带上了 ---），
	// 静默只取第一个会让第二个文档里的配置神秘失效。
	var extra Config
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("%s: 配置文件含多个 YAML 文档，只允许一个", source)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: 解析第二个文档时出错: %w", source, err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	return &cfg, nil
}

// enrichDecodeError 把 yaml 库的报错整理得更可操作。
//
// yaml.v3 对未知字段的原始报错是「field X not found in type config.Y」，
// 对不熟悉 Go 类型名的运维不够友好，这里补上「这是拼写错误」的提示。
func enrichDecodeError(err error) error {
	msg := err.Error()
	if strings.Contains(msg, "not found in type") {
		return fmt.Errorf("%w\n"+
			"  ↑ 配置中存在未定义的字段。常见原因是键名拼写错误，"+
			"或使用了本版本尚不支持的配置项。\n"+
			"  未知字段一律拒绝——静默忽略会让「我明明配了」变成最难查的事故", err)
	}
	return err
}

// applyDefaults 补齐未设置的字段。
//
// 只补「不影响安全语义」的默认值。像 fail_closed 这种安全开关
// 绝不在这里给默认——它的零值就是安全的那一侧，且必须由 Validate
// 显式告警提醒运维自己关掉了什么。
func (c *Config) applyDefaults() {
	setIfZero := func(d *Duration, v time.Duration) {
		if *d == 0 {
			*d = Duration(v)
		}
	}
	if c.SecretsMountPath == "" {
		c.SecretsMountPath = "/var/run/secrets/llm"
	}
	setIfZero(&c.SecretsCacheTTL, 5*time.Minute)
	setIfZero(&c.SessionTTL, time.Hour)
	if c.MaxSessions == 0 {
		c.MaxSessions = 100_000
	}
	if c.Breaker.FailureThreshold == 0 {
		c.Breaker.FailureThreshold = 5
	}
	setIfZero(&c.Breaker.RecoveryTimeout, 30*time.Second)
	setIfZero(&c.RateLimit.Window, time.Minute)
	setIfZero(&c.GPU.ProbeInterval, 2*time.Second)
	if c.GPU.AffinityLoadFactor == 0 {
		c.GPU.AffinityLoadFactor = 1.25
	}
	if c.GPU.KVElevated == 0 {
		c.GPU.KVElevated = 0.75
	}
	if c.GPU.KVCritical == 0 {
		c.GPU.KVCritical = 0.90
	}
	for i := range c.Targets {
		if c.Targets[i].Weight == 0 {
			c.Targets[i].Weight = 100
		}
	}
	if c.PII.NER.Endpoint != "" {
		setIfZero(&c.PII.NER.Timeout, 300*time.Millisecond)
		setIfZero(&c.PII.NER.CacheTTL, 10*time.Minute)
		if c.PII.NER.CacheSize == 0 {
			c.PII.NER.CacheSize = 4096
		}
	}
}
