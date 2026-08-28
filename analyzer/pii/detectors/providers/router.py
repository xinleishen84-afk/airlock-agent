"""按文字系统把文本路由到对应语言的模型。

Routes text to the model for its script.

# 为什么必须路由，而不是挑一个模型凑合
# Why routing, not picking one model and living with it

实测：中文模型对拉丁文是分布外输入，产出的不是「不够准」，是胡乱输出。
把英语、意大利语、德语的样本送进 zh_core_web_md，它把 declined、leaked、
Codice、Steuer、deps 判成人名或地址——而同样的文本送进 en_core_web_sm，
其中几条一个实体都不返回。

反过来也一样：英文模型对中文文本同样是分布外。

Measured: a Chinese model on Latin text does not produce "less accurate"
results, it produces noise. Fed English, Italian and German samples,
zh_core_web_md labelled declined, leaked, Codice, Steuer and deps as names or
addresses; en_core_web_sm returns nothing at all for several of them.

# 为什么按段而不是按整篇
# Why per-segment rather than per-document

真实提示词是混排的：中文散文里夹着英文人名、产品名、代码。按整篇挑一个
语言，等于对另一半语言的内容要么不检测、要么用错模型检测。

按文字系统切段之后，每一段送给它对应的模型，两边都拿到自己分布内的输入。

Real prompts are mixed: Chinese prose with English names, product names and
code. Choosing one language per document means the other half is either not
scanned or scanned by the wrong model.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from pii.detectors.base import Entity, NERError, NERProvider


@dataclass(frozen=True, slots=True)
class Segment:
    """一段文字系统一致的连续文本。"""

    text: str
    #: 该段在全文中的起始字符偏移
    start: int
    #: 该段应当路由到的语言
    language: str


#: 中性字符（数字、标点、空白）跟随当前段，不自己开段。
#:
#: 「Margaret Okonkwo」中间的空格若被判成中性并因此断段，英文模型会分别
#: 看到「Margaret」与「Okonkwo」，而一个孤立的首字母大写词很难被判成人名。
#: 名字里的空格必须留在名字那一段里。
#:
#: Neutral characters follow the current segment rather than starting one. If
#: the space inside "Margaret Okonkwo" broke the segment, the English model
#: would see two isolated capitalized words.
def _script_of(ch: str) -> str | None:
    """返回字符所属的文字系统：zh、en，或 None（中性）。"""
    if ch.isspace():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    if "CJK" in name or "HIRAGANA" in name or "KATAKANA" in name:
        return "zh"
    if "LATIN" in name and ch.isalpha():
        return "en"
    return None


def segment_by_script(text: str, default_language: str = "zh") -> list[Segment]:
    """把文本按文字系统切成若干段。

    Split the text into script-consistent segments.

    偏移是全文的字符偏移，不是段内的——段内偏移交给调用方去加基址，
    是这类架构里最常见的错位来源，所以这里直接给全文偏移。

    Offsets are absolute character offsets, not segment-relative: making the
    caller add a base is the most common source of misalignment in this kind of
    architecture.
    """
    if not text:
        return []

    segments: list[Segment] = []
    current_lang: str | None = None
    start = 0

    for i, ch in enumerate(text):
        script = _script_of(ch)
        if script is None:
            continue
        if current_lang is None:
            current_lang = script
            start = 0 if not segments else start
            continue
        if script != current_lang:
            segments.append(Segment(text[start:i], start, current_lang))
            current_lang = script
            start = i

    if current_lang is None:
        # 全是中性字符：没有任何字母，不值得送进任何模型
        return []
    segments.append(Segment(text[start:], start, current_lang))
    return segments


class LanguageRouter:
    """按语言把每一段路由到对应的 provider。

    Routes each segment to the provider for its language.

    它自己也是一个 NERProvider：上层的 NERDetector 不需要知道下面挂了
    一个还是三个模型。

    It is itself a NERProvider: the NERDetector above does not need to know
    whether one model or three sit below.
    """

    def __init__(
        self,
        providers: dict[str, NERProvider],
        *,
        default_language: str = "zh",
    ) -> None:
        if not providers:
            raise NERError("语言路由至少需要一个 provider / router needs a provider")
        if default_language not in providers:
            raise NERError(
                f"默认语言 {default_language!r} 没有对应的 provider，"
                f"已配置：{sorted(providers)}\n"
                f"default language has no provider"
            )
        self._providers = dict(providers)
        self._default = default_language

    @property
    def name(self) -> str:
        parts = ",".join(f"{lang}={p.name}" for lang, p in sorted(self._providers.items()))
        return f"router({parts})"

    @property
    def supported_labels(self) -> frozenset[str]:
        """各后端支持类型的并集。"""
        out: set[str] = set()
        for p in self._providers.values():
            labels = getattr(p, "supported_labels", None)
            if labels:
                out |= set(labels)
        return frozenset(out)

    @property
    def languages(self) -> list[str]:
        return sorted(self._providers)

    def extract(self, text: str) -> list[Entity]:
        """按段路由，合并结果。"""
        return self.extract_for(text, language="auto")

    def extract_for(self, text: str, *, language: str) -> list[Entity]:
        """按指定语言处理；language 为 auto 时按文字系统切段路由。

        Process with the given language; "auto" segments by script and routes.
        """
        if language and language != "auto":
            provider = self._providers.get(language)
            if provider is None:
                raise NERError(
                    f"没有语言 {language!r} 的 provider，已配置：{self.languages}\n"
                    f"no provider for language {language!r}"
                )
            return provider.extract(text)

        out: list[Entity] = []
        for seg in segment_by_script(text, self._default):
            provider = self._providers.get(seg.language)
            if provider is None:
                # 没有对应模型的语言直接跳过，而不是拿默认模型去凑合。
                #
                # 用错模型的产出是分布外噪音，它会以「检出了实体」的形态
                # 进入管线——比不检测更糟，因为不检测至少是可见的缺口。
                #
                # A language with no model is skipped rather than handed to the
                # default: wrong-model output is noise that enters the pipeline
                # looking like a detection, which is worse than a visible gap.
                continue

            for e in provider.extract(seg.text):
                # 段内偏移换算为全文偏移。
                # 这一步错了，脱敏就洗错字符——而症状是「洗掉了旁边几个字」，
                # 不是一个异常。
                #
                # Segment-relative offsets become absolute. Getting this wrong
                # redacts the wrong characters, and the symptom is not an
                # exception.
                out.append(
                    Entity(
                        text=e.text,
                        type=e.type,
                        start=seg.start + e.start,
                        end=seg.start + e.end,
                        source=e.source,
                        confidence=e.confidence,
                    )
                )

        out.sort(key=lambda e: (e.start, e.end))
        return out
