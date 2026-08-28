"""NER 的类型契约：实体结构、标签词表、Provider 协议、异常。

The NER contract: entity shape, label vocabulary, provider protocol, errors.

这个文件里没有任何 spaCy 的痕迹，这是刻意的。上层代码只依赖这里的东西，
因此把 spaCy 换成 HuggingFace 时，需要改的只有 providers/ 下的一个文件。

Nothing in this file mentions spaCy, deliberately. Upper layers depend only on
what is declared here, so swapping spaCy for a HuggingFace model touches one
file under providers/.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


class EntityType:
    """标准化的实体类型。

    Normalized entity types.

    与各家模型的原始标签解耦。spaCy 用 PERSON/ORG/GPE，HuggingFace 的
    中文模型常用 PER/ORG/LOC，还有用 B-PER/I-PER 的。让上层去认这些标签，
    等于把「换模型」变成「改上层代码」。

    Decoupled from any model's native labels: spaCy says PERSON/ORG/GPE,
    Chinese HuggingFace models often say PER/ORG/LOC. Making callers speak
    those labels turns "swap the model" into "rewrite the callers".
    """

    PERSON_NAME = "PERSON_NAME"
    ORGANIZATION = "ORGANIZATION"
    LOCATION = "LOCATION"

    ALL = frozenset({PERSON_NAME, ORGANIZATION, LOCATION})


@dataclass(frozen=True, slots=True)
class Entity:
    """一处被识别出的实体。

    One recognized entity.
    """

    text: str
    type: str
    start: int
    end: int
    source: str = "NER"

    #: 置信度。见下方 confidence 一节的说明——它不一定是真实的模型分数。
    #: Confidence. See the note below: it is not always a real model score.
    confidence: float = 0.0

    #: UTF-8 字节偏移。
    #:
    #: start/end 是 Python 的字符偏移，而 Go、Rust 与绝大多数网络协议按字节
    #: 计算偏移，中文一个字占 3 字节。把字符偏移直接交给按字节切片的一侧，
    #: 会把文本切碎，而且**只在含中文时出错**——用英文测试完全正常，
    #: 能一路带到生产。两套偏移都给出来，让调用方无需自己换算。
    #:
    #: start/end are Python character offsets; Go, Rust and most wire protocols
    #: index by byte, and a Chinese character is three bytes. Handing character
    #: offsets to a byte-indexing consumer shreds the text — and only when the
    #: text contains Chinese, so an English test suite passes all the way to
    #: production. Both are provided so no caller has to convert.
    start_byte: int = 0
    end_byte: int = 0

    def to_dict(self, *, with_bytes: bool = False) -> dict[str, Any]:
        """转成 JSON 可序列化的字典。

        默认输出正是约定的那五个字段；字节偏移需要显式索取，
        因为多给的字段会成为下游解析器的意外。

        The default output is exactly the five agreed fields; byte offsets must
        be asked for, because extra fields surprise downstream parsers.
        """
        out: dict[str, Any] = {
            "text": self.text,
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "source": self.source,
        }
        if with_bytes:
            out["start_byte"] = self.start_byte
            out["end_byte"] = self.end_byte
            out["confidence"] = self.confidence
        return out


class NERError(Exception):
    """本模块所有异常的基类。

    Base for every error this module raises.

    上层可以只 catch 这一个，而不必知道底层是 spaCy 还是别的什么。
    Callers can catch just this one without knowing what backs the detector.
    """


class NERModelNotAvailable(NERError):
    """模型加载失败：没装、名字错了、或与当前环境不兼容。

    The model could not be loaded: not installed, misnamed, or incompatible.

    这类失败必须在**启动期**发生并带上修复指引。让它在第一个请求上以一个
    底层 OSError 的形式炸出来，意味着服务已经对外声称自己就绪了。

    This must surface at startup with a fix, not as a raw OSError on the first
    request — by then the service has already reported itself ready.
    """


class NERRuntimeError(NERError):
    """模型已加载，但这次推理失败了。

    The model loaded but this inference failed.
    """


@runtime_checkable
class NERProvider(Protocol):
    """一个 NER 后端必须满足的契约。

    What an NER backend must satisfy.

    刻意只有两个方法。Provider 负责「跑模型 + 把原始标签翻译成标准类型」，
    其余的（空输入、字节偏移、类型过滤）由 NERDetector 统一处理——
    否则每换一个 Provider 都要把这些规则重写一遍，而重写就会有出入。

    Deliberately two methods. A provider runs the model and translates native
    labels; everything else (empty input, byte offsets, type filtering) is
    handled once in NERDetector. Otherwise every new provider reimplements
    those rules, and reimplementations diverge.
    """

    @property
    def name(self) -> str:
        """供日志与审计使用的后端标识，例如 "spacy:zh_core_web_md"。"""
        ...

    def extract(self, text: str) -> list[Entity]:
        """对非空文本跑一次识别，返回已标准化类型的实体。

        字节偏移可以留 0，由 NERDetector 负责补齐。
        Byte offsets may be left at 0; NERDetector fills them in.
        """
        ...
