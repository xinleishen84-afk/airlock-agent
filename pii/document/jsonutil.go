package document

import (
	"bytes"
	"encoding/json"
)

// MarshalPreserving serializes JSON **without HTML escaping**.
// 序列化 JSON 且**不做 HTML 转义**。
//
// Go's json.Marshal escapes < > & into < > & by default. That is
// a historical default meant for embedding JSON inside HTML pages, and it is
// pure noise for an API gateway:
// Go 的 json.Marshal 默认把 < > & 转义成 < > &——这是为了把
// JSON 安全嵌进 HTML 页面的历史默认值，对 API 网关是纯粹的噪音：
//
//   - Semantically identical (any JSON parser decodes to the same string),
//     but the bytes change.
//     语义上等价（任何 JSON 解析器解码后是同一个字符串），但字节变了。
//   - A gateway's job is to forward, not to silently rewrite user content.
//     网关的职责是转发，不该无故改写用户内容。
//   - Content full of <> (code, HTML, stop sequences like <|end|>) balloons
//     from 1 byte to 6 bytes per character.
//     含大量 <> 的内容（代码、HTML、以及 <|end|> 这类停止序列）
//     每个字符从 1 字节膨胀到 6 字节。
//
// json.Encoder appends a trailing newline; it is stripped here to keep the
// same semantics as json.Marshal.
// json.Encoder 会在输出末尾追加换行，这里剥掉以保持与 Marshal 一致的语义。
func MarshalPreserving(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
