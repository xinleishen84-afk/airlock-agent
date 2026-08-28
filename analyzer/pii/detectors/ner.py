"""NERDetector：对上层唯一的 NER 入口。

NERDetector: the single NER entry point for callers above.

    Text → NERDetector → Provider → 模型 → 标准化实体结果

上层只认识这个类和 Entity。换后端时，改的是构造函数的一个参数。

Callers know only this class and Entity. Swapping backends changes one
constructor argument.
"""

from __future__ import annotations

from typing import Any, Sequence

from pii.detectors.base import (
    Entity,
    EntityType,
    NERModelNotAvailable,
    NERProvider,
)


class NERDetector:
    """识别人名、地点、组织机构，并输出标准化结果。

    Recognizes people, places and organizations, normalized.

    职责边界：本类不做脱敏、不做策略选择、不持有会话状态。它只回答
    「这段文本里有哪些实体、在什么位置」。把脱敏也塞进来，会让「换模型」
    和「换脱敏策略」这两件本来正交的事互相牵扯。

    Scope: this class does not redact, choose policies, or hold session state.
    It answers only "which entities are in this text and where". Folding
    redaction in here would couple two things that are properly orthogonal.
    """

    def __init__(
        self,
        provider: NERProvider | None = None,
        *,
        model: str | None = None,
        types: Sequence[str] | None = None,
    ) -> None:
        """构造检测器。

        provider 为 None 时默认装配 spaCy 后端。传入自己的 provider 即可
        替换后端——这是 HuggingFace 版本将来接进来的地方，无需改动本文件。

        With provider=None a spaCy backend is assembled. Passing your own
        provider replaces the backend; that is where a HuggingFace version
        plugs in, with no change to this file.

        model 留空时由后端决定用哪个模型。这一层不持有模型名的默认值——
        持有就等于同一个默认值存在两份，而两份会漂移：改了 provider 里的
        那份、忘了这份，得到的是「配置说用 A、实际加载 B」，且不报错。

        A model of None lets the backend decide. This layer holds no default
        model name: holding one would mean the same default exists twice, and
        two copies drift into "the config says A while B is loaded", silently.

        types 限定输出的类型。留空表示全部。
        """
        if provider is None:
            # 延迟到这里 import，使不使用 spaCy 后端的调用方
            # 不必安装 spaCy。
            # Imported here so callers using another backend need not install
            # spaCy at all.
            from pii.detectors.providers.spacy_provider import (
                DEFAULT_MODEL,
                SpacyNERProvider,
            )

            provider = SpacyNERProvider(model=model or DEFAULT_MODEL)

        self._provider = provider

        if types is None:
            self._types: frozenset[str] | None = None
        else:
            unknown = set(types) - EntityType.ALL
            if unknown:
                raise ValueError(
                    f"未知的实体类型 {sorted(unknown)}，合法取值："
                    f"{sorted(EntityType.ALL)}\n"
                    f"unknown entity types {sorted(unknown)}"
                )
            self._types = frozenset(types)

    @property
    def provider_name(self) -> str:
        """当前后端标识，供日志与审计使用。"""
        return self._provider.name

    def detect(self, text: str, *, language: str = "auto") -> list[dict[str, Any]]:
        """识别文本中的实体，返回字典列表。

        Recognize entities and return them as dictionaries.

        输出形如：
            [{"text": "张三", "type": "PERSON_NAME",
              "start": 0, "end": 2, "source": "NER"}]

        空输入（含全空白）返回 []，不调用模型。
        Empty or whitespace-only input returns [] without invoking the model.
        """
        return [e.to_dict() for e in self.detect_entities(text, language=language)]

    def detect_entities(self, text: str, *, language: str = "auto") -> list[Entity]:
        """detect 的强类型版本，返回 Entity 对象。

        The typed form of detect.

        需要字节偏移、置信度，或想避免一次字典构造的调用方走这个。
        For callers that need byte offsets or confidence, or want to skip
        building dictionaries.
        """
        if not text or not text.strip():
            return []

        # 支持按语言路由的 provider 走 extract_for；不支持的沿用 extract。
        # 协议里没有 extract_for，因此不能假设它存在。
        #
        # Providers that route by language expose extract_for; the protocol does
        # not require it, so its presence cannot be assumed.
        route = getattr(self._provider, "extract_for", None)
        if callable(route):
            entities = route(text, language=language)
        else:
            entities = self._provider.extract(text)
        return self._finalize(text, entities)

    def detect_batch(self, texts: Sequence[str]) -> list[list[dict[str, Any]]]:
        """批量识别，逐条对应输入顺序。

        Batched recognition, aligned with the input order.

        空串照样占一个位置并返回 []，因为调用方几乎总是按下标把结果对回
        原始记录——为了「省一次推理」而把空串从结果里删掉，会让所有后续
        下标错位，而且只在输入里恰好有空串时才出错。

        An empty string still occupies its slot and yields []: callers almost
        always map results back by index, and dropping empties to "save an
        inference" shifts every subsequent index — but only when an empty
        string happens to be present.
        """
        return [
            [e.to_dict() for e in entities]
            for entities in self.detect_batch_entities(texts)
        ]

    def detect_batch_entities(self, texts: Sequence[str]) -> list[list[Entity]]:
        """detect_batch 的强类型版本。"""
        texts = list(texts)
        if not texts:
            return []

        # 只把非空文本送进模型，再按原下标放回去
        indexed = [(i, t) for i, t in enumerate(texts) if t and t.strip()]
        results: list[list[Entity]] = [[] for _ in texts]
        if not indexed:
            return results

        batch_fn = getattr(self._provider, "extract_batch", None)
        if callable(batch_fn):
            extracted = batch_fn([t for _, t in indexed])
        else:
            # Provider 未实现批处理：退回逐条。契约里没有 extract_batch，
            # 因此不能假设它存在。
            # The provider does not implement batching; fall back to one by
            # one. extract_batch is not in the protocol, so its presence
            # cannot be assumed.
            extracted = [self._provider.extract(t) for _, t in indexed]

        for (original_index, original_text), entities in zip(indexed, extracted):
            results[original_index] = self._finalize(original_text, entities)
        return results

    def _finalize(self, text: str, entities: list[Entity]) -> list[Entity]:
        """补齐字节偏移、按类型过滤、按位置排序、校验偏移自洽。

        Fill in byte offsets, filter by type, sort by position, and check the
        offsets against the text.
        """
        out: list[Entity] = []
        for ent in entities:
            if self._types is not None and ent.type not in self._types:
                continue

            # 偏移自洽性检查。一个偏移与文本对不上的实体，会让下游按它去切
            # 原文时切到别的地方——而下游没有办法自己发现这件事。
            # 后端换了、分词器换了、或者上游做了 NFC 归一化，都可能造成这种
            # 错位，且症状是「脱敏了错的那几个字」，不是一个异常。
            #
            # An entity whose offsets disagree with the text makes downstream
            # slice the wrong span, and downstream cannot detect that on its
            # own. A backend change, a different tokenizer, or upstream Unicode
            # normalization can all cause it, and the symptom is "the wrong
            # characters were redacted", not an exception.
            if text[ent.start : ent.end] != ent.text:
                raise ValueError(
                    f"{self._provider.name} 返回的偏移与原文不符："
                    f"实体 {ent.text!r} 声称位于 [{ent.start},{ent.end})，"
                    f"但该处实际是 {text[ent.start:ent.end]!r}\n"
                    f"offset mismatch from {self._provider.name}"
                )

            out.append(
                Entity(
                    text=ent.text,
                    type=ent.type,
                    start=ent.start,
                    end=ent.end,
                    source=ent.source,
                    confidence=ent.confidence,
                    start_byte=len(text[: ent.start].encode("utf-8")),
                    end_byte=len(text[: ent.end].encode("utf-8")),
                )
            )

        out.sort(key=lambda e: (e.start, e.end))
        return out


__all__ = ["NERDetector", "Entity", "EntityType", "NERModelNotAvailable"]
