"""spaCy 后端。

The spaCy backend.

这是仓库里唯一 import spaCy 的地方。
This is the only place in the repository that imports spaCy.
"""

from __future__ import annotations

import threading
from typing import Any

from pii.detectors.base import (
    Entity,
    EntityType,
    NERModelNotAvailable,
    NERRuntimeError,
)

#: 默认中文模型。
#:
#: 用 md 而不是 sm，是实测的结果而不是偏好。在 pii/eval_ner.py 的语料上：
#:
#:     zh_core_web_sm    召回 69.0%   精确 71.4%    13MB
#:     zh_core_web_md    召回 82.8%   精确 82.8%    74MB
#:
#: 差的这 14 个百分点里有两件要紧的事：sm 漏掉「张伟」这种极常见的中文名，
#: 以及 sm 会把源代码里的 func、nil 判成人名——后者会让脱敏管线去改写代码。
#: 换模型是一个参数的事，多出来的 61MB 换掉这两个问题是划算的。
#:
#: md over sm is a measured result, not a preference: sm misses very common
#: Chinese names and labels `func` and `nil` in source code as person names,
#: which would send a redaction pipeline into the code.
#:
#: 想换回 sm 或换成 lg：NERDetector(model="zh_core_web_sm")。
DEFAULT_MODEL = "zh_core_web_md"

#: spaCy 原生标签 → 标准化类型。
#:
#: 未列出的标签一律丢弃，而不是「原样透传」。透传会让 DATE、CARDINAL、
#: PERCENT 这些非 PII 的标签流进脱敏管线，而下游按类型选择脱敏算子——
#: 一个它不认识的类型会走默认算子，把「昨天」也脱敏掉。
#:
#: Unlisted labels are dropped, never passed through. Passing them through
#: would send DATE, CARDINAL and PERCENT into a redaction pipeline that selects
#: an operator by type, and an unknown type takes the default operator — which
#: would redact the word "yesterday".
LABEL_MAP: dict[str, str] = {
    "PERSON": EntityType.PERSON_NAME,
    "ORG": EntityType.ORGANIZATION,
    "GPE": EntityType.LOCATION,
    "LOC": EntityType.LOCATION,
}

#: 本后端产出的实体统一置信度。
#:
#: 这是一个**占位值，不是模型分数**。spaCy 的默认 EntityRecognizer 不输出
#: 逐实体的概率——要拿到得开 beam parsing 或换 transformer 后端。
#: 与其编一个像模像样的 0.95，不如给一个明显是常量的数：
#: 下游若据此做阈值判定，看到所有实体分数完全相同就会立刻发现这件事。
#:
#: A placeholder, not a model score. spaCy's default EntityRecognizer does not
#: emit per-entity probabilities. Rather than invent a plausible-looking 0.95,
#: this is visibly constant: a downstream threshold will notice immediately
#: that every entity scores identically.
NOMINAL_CONFIDENCE = 0.5


class SpacyNERProvider:
    """用 spaCy 管线做实体识别。

    Entity recognition backed by a spaCy pipeline.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        label_map: dict[str, str] | None = None,
        disable: tuple[str, ...] = ("parser",),
    ) -> None:
        """加载模型。加载失败立刻抛出，不推迟到第一个请求。

        Loads the model. A failure raises here, not on the first request.

        disable 默认关掉依存句法分析：NER 用不到它，而它占了这个管线相当
        一部分耗时。关掉 tagger 会让 zh 模型的 NER 质量下降，所以不关。

        The parser is disabled by default: NER does not use it and it accounts
        for a sizable share of the pipeline's cost. The tagger is kept, because
        disabling it measurably degrades NER on the Chinese model.
        """
        self._model_name = model
        self._label_map = dict(label_map) if label_map is not None else dict(LABEL_MAP)

        try:
            import spacy
        except ImportError as exc:  # pragma: no cover - 环境问题，非逻辑分支
            raise NERModelNotAvailable(
                "未安装 spaCy。请先安装：\n"
                "    pip install spacy\n"
                f"    python -m spacy download {model}\n"
                "spaCy is not installed."
            ) from exc

        try:
            self._nlp: Any = spacy.load(model, disable=list(disable))
        except OSError as exc:
            raise NERModelNotAvailable(
                f"无法加载 spaCy 模型 {model!r}。\n"
                f"多半是没下载。请执行：\n"
                f"    python -m spacy download {model}\n"
                f"已安装的 spaCy 版本：{spacy.__version__}\n"
                f"底层错误：{exc}\n"
                f"Could not load spaCy model {model!r}; it is probably not "
                f"downloaded."
            ) from exc
        except Exception as exc:  # noqa: BLE001 - 兜住任何加载期异常
            raise NERModelNotAvailable(
                f"加载 spaCy 模型 {model!r} 时发生未预期的错误：{exc}\n"
                f"Unexpected error while loading spaCy model {model!r}."
            ) from exc

        # spaCy 的 Language 对象在并发调用下不保证安全：管线组件之间共享
        # 可变的中间缓冲。用一把锁换取正确性；真要吞吐应当用 detect_batch，
        # 它走 nlp.pipe 的批处理路径。
        #
        # A spaCy Language object is not guaranteed safe under concurrent
        # calls: pipeline components share mutable scratch buffers. A lock buys
        # correctness; for throughput use detect_batch, which goes through
        # nlp.pipe.
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return f"spacy:{self._model_name}"

    @property
    def supported_labels(self) -> frozenset[str]:
        """本后端实际会产出的标准化类型。

        The normalized types this backend can actually produce.

        供上层做覆盖度自检：一个不产出 ORGANIZATION 的后端，
        配上一条要求脱敏机构名的策略，是一个静默的缺口。

        Lets callers check coverage: a backend that never emits ORGANIZATION,
        paired with a policy that redacts organizations, is a silent gap.
        """
        return frozenset(self._label_map.values())

    def extract(self, text: str) -> list[Entity]:
        """跑一次识别。"""
        try:
            with self._lock:
                doc = self._nlp(text)
        except Exception as exc:  # noqa: BLE001 - 模型内部异常一律归一
            raise NERRuntimeError(
                f"{self.name} 推理失败：{exc}\ninference failed"
            ) from exc

        return [
            Entity(
                text=ent.text,
                type=mapped,
                start=ent.start_char,
                end=ent.end_char,
                source="NER",
                confidence=NOMINAL_CONFIDENCE,
            )
            for ent in doc.ents
            if (mapped := self._label_map.get(ent.label_)) is not None
        ]

    def extract_batch(self, texts: list[str]) -> list[list[Entity]]:
        """批量识别，走 spaCy 的 pipe 路径。

        Batched recognition through spaCy's pipe.

        逐条调用的开销主要在管线的启停上，批处理把它摊薄。评测与离线扫描
        应当走这条路；在线单请求走 extract。

        Per-call overhead is dominated by pipeline setup, which batching
        amortizes. Evaluation and offline scans should use this path.
        """
        if not texts:
            return []
        try:
            with self._lock:
                docs = list(self._nlp.pipe(texts))
        except Exception as exc:  # noqa: BLE001
            raise NERRuntimeError(
                f"{self.name} 批量推理失败：{exc}\nbatch inference failed"
            ) from exc

        return [
            [
                Entity(
                    text=ent.text,
                    type=mapped,
                    start=ent.start_char,
                    end=ent.end_char,
                    source="NER",
                    confidence=NOMINAL_CONFIDENCE,
                )
                for ent in doc.ents
                if (mapped := self._label_map.get(ent.label_)) is not None
            ]
            for doc in docs
        ]
