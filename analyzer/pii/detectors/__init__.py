"""实体检测器。

对外只暴露 NERDetector 与标准化的结果结构；具体用哪个模型是实现细节。

Exposes NERDetector and the normalized result shape; which model backs it is
an implementation detail.
"""

from pii.detectors.base import (
    Entity,
    EntityType,
    NERError,
    NERModelNotAvailable,
    NERProvider,
    NERRuntimeError,
)
from pii.detectors.ner import NERDetector

__all__ = [
    "NERDetector",
    "Entity",
    "EntityType",
    "NERProvider",
    "NERError",
    "NERModelNotAvailable",
    "NERRuntimeError",
]
