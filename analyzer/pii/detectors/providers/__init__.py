"""NER 后端实现。

每个文件一个后端。除了这个目录，仓库里不应该有第二处 import spaCy
（或将来的 transformers）的地方——那正是「可替换」这句话的具体含义。

One backend per file. Nothing outside this directory should import spaCy (or,
later, transformers) — that is what "replaceable" concretely means.
"""

from pii.detectors.providers.spacy_provider import SpacyNERProvider

__all__ = ["SpacyNERProvider"]
