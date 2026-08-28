"""PII 检测与脱敏的 Python 侧实现。

本包只负责推理与评测：把文本喂给模型，产出标准化的实体结果。
编排、路由、脱敏算子在 Go 侧（airlock-agent）。

Inference and evaluation only. Orchestration, routing and the redaction
operators live on the Go side.
"""
