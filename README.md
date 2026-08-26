# airlock-agent
Bidirectional PII redaction for LLM gateways. Names, IDs and card numbers are replaced before they leave your boundary and restored when the model answers. A structural AST allowlist touches only natural-language fields, so `role`, tool names and schema enums are never corrupted. Runs as a language-agnostic HTTP sidecar or a Go library.
