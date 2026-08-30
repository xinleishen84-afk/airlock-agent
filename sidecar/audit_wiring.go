package sidecar

import (
	"strings"

	"github.com/xinleishen84-afk/airlock-agent/pii/detect/packs"
)

// AuditSinkFlagUsage 与 AuditKeyFlagUsage 是两个二进制共用的 flag 说明文本。
//
// 装配代码放在这里而不是各自的 main 里，是上一次事故的直接结果：会话一致性
// 校验只写进了 Core 的 main，Advanced 因此完全不受那条约束，而部署清单已经在
// 传那个 flag——Pod 以「flag provided but not defined」崩溃循环。
// 安全相关的装配一旦在两个 main 里各写一份，就会漂移成「有的进程管、有的不管」。
//
// Shared so the two binaries cannot drift: duplicating a security-relevant
// assembly across mains is what previously left one binary unconstrained.

// CatalogFromJurisdictions 列出这些国家包实际加载的识别器。
// Lists the recognizers this assembly actually loaded.
//
// # 为什么快照里必须有这张表
// # Why the snapshot needs this table
//
// 「装了哪些国家包」与「这些包实际产出哪些识别器」是两件事：包能注册成功、
// 二进制能启动、请求能处理，而某个识别器因为一个长度断言从来匹配不到任何
// 东西——这种情况在本项目里真实发生过（意大利 11 位增值税号撞上写死
// 12–19 位的 Luhn 校验）。清单让运维能对着它问「我以为装了的那条，在吗」。
//
// Which packs are configured and which recognizers they actually produce are
// different questions: a pack can register, the binary can start and requests
// can flow while one recognizer never matches anything. That happened here —
// Italy's 11-digit VAT number met a Luhn check hardcoded to 12-19 digits.
func CatalogFromJurisdictions(codes []string) []RecognizerInfo {
	out := make([]RecognizerInfo, 0, 32)
	for _, code := range codes {
		recs, err := packs.Load(code)
		if err != nil {
			// 装配阶段已经校验过国家包，这里出错只可能是代码问题。
			// 快照缺一条比启动失败好——它不在关键路径上。
			continue
		}
		for _, r := range recs {
			out = append(out, RecognizerInfo{
				Name: r.Name(),
				// Type 此前声明了却从未被赋值，快照里的 entity_type 一直是空串。
				// Declared but never assigned before, so entity_type read empty.
				Type:   string(r.EntityType()),
				Source: "pack:" + strings.ToUpper(strings.TrimSpace(code)),
			})
		}
	}
	return out
}
