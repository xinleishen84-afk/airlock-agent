package nerclient

import "errors"

// ErrNERUnavailable 表示服务不可达或调用失败。
//
// 与「没有找到实体」严格区分。一个连不上的推理服务返回空列表，与一段
// 确实不含 PII 的文本返回空列表，在类型上必须是两件事——把两者混为一谈，
// 会让一次故障看起来像一次干净的扫描。
//
// Strictly distinguished from "no entities found". An unreachable service
// returning an empty list and a genuinely clean text returning an empty list
// must be different things: conflating them makes an outage look like a clean
// scan.
var ErrNERUnavailable = errors.New("NER 服务不可用 / NER service unavailable")

// ErrOffsetMismatch 表示服务端返回的偏移与本端文本对不上。
//
// 这是数据损坏，不是检测失败。继续下去会脱敏错误的字节区间。
//
// This is data corruption, not a detection failure. Proceeding would redact
// the wrong byte range.
var ErrOffsetMismatch = errors.New("偏移映射失败 / offset mapping failed")
