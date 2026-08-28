"""NER 模块单元测试。

大部分用例用假 Provider，因此不加载任何模型、不碰磁盘、可在无模型的 CI 中
运行。只有明确标注的那几条需要真实的 spaCy 模型，缺模型时跳过而不是失败——
但「跳过」会被打印出来，因为一条静默跳过的用例与一条通过的用例，
在 CI 的绿色对勾里长得一模一样。

Most tests use a fake provider: no model is loaded, nothing touches disk, and
they run in a CI without the model. The few that need the real model skip
loudly when it is missing — a silently skipped test and a passing one look
identical in a green CI.
"""

from __future__ import annotations

import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pii.detectors import (  # noqa: E402
    Entity,
    EntityType,
    NERDetector,
    NERModelNotAvailable,
)


class FakeProvider:
    """可控的假后端：用来测 NERDetector 自己的逻辑，而不是测模型。

    A controllable fake: exercises NERDetector's own logic, not the model's.
    """

    def __init__(self, entities: list[Entity] | None = None, name: str = "fake") -> None:
        self._entities = entities or []
        self._name = name
        self.calls: list[str] = []

    @property
    def name(self) -> str:
        return self._name

    def extract(self, text: str) -> list[Entity]:
        self.calls.append(text)
        return list(self._entities)


def ent(text: str, typ: str, start: int, end: int) -> Entity:
    return Entity(text=text, type=typ, start=start, end=end)


class TestOutputContract(unittest.TestCase):
    """输出结构必须与约定逐字一致。"""

    def test_dict_shape_is_exactly_five_keys(self) -> None:
        provider = FakeProvider([ent("张三", EntityType.PERSON_NAME, 0, 2)])
        detector = NERDetector(provider=provider)

        got = detector.detect("张三目前住在杭州。")

        self.assertEqual(
            got,
            [{"text": "张三", "type": "PERSON_NAME", "start": 0, "end": 2, "source": "NER"}],
        )

    def test_results_are_sorted_by_position(self) -> None:
        provider = FakeProvider(
            [
                ent("阿里巴巴", EntityType.ORGANIZATION, 12, 16),
                ent("张三", EntityType.PERSON_NAME, 0, 2),
                ent("杭州", EntityType.LOCATION, 6, 8),
            ]
        )
        detector = NERDetector(provider=provider)

        starts = [e["start"] for e in detector.detect("张三目前住在杭州，并且在阿里巴巴工作。")]

        self.assertEqual(starts, sorted(starts))


class TestEmptyInput(unittest.TestCase):
    """空输入返回 []，且不应触碰模型。"""

    def test_empty_string(self) -> None:
        provider = FakeProvider([ent("张三", EntityType.PERSON_NAME, 0, 2)])
        detector = NERDetector(provider=provider)

        self.assertEqual(detector.detect(""), [])
        self.assertEqual(provider.calls, [], "空输入不应调用模型")

    def test_whitespace_only(self) -> None:
        provider = FakeProvider([ent("张三", EntityType.PERSON_NAME, 0, 2)])
        detector = NERDetector(provider=provider)

        for blank in ("   ", "\n\t", "　　"):  # 含全角空格
            with self.subTest(blank=repr(blank)):
                self.assertEqual(detector.detect(blank), [])
        self.assertEqual(provider.calls, [], "全空白输入不应调用模型")


class TestByteOffsets(unittest.TestCase):
    """中文的字符偏移与字节偏移不同，两套都必须给对。

    Character and byte offsets differ for Chinese; both must be right.
    """

    def test_chinese_byte_offsets(self) -> None:
        text = "张三目前住在杭州"
        provider = FakeProvider([ent("杭州", EntityType.LOCATION, 6, 8)])
        detector = NERDetector(provider=provider)

        [entity] = detector.detect_entities(text)

        self.assertEqual((entity.start, entity.end), (6, 8))
        self.assertEqual((entity.start_byte, entity.end_byte), (18, 24))
        # 两套偏移都必须能切出同一个值
        self.assertEqual(text[entity.start : entity.end], "杭州")
        self.assertEqual(
            text.encode("utf-8")[entity.start_byte : entity.end_byte].decode("utf-8"),
            "杭州",
        )

    def test_byte_offsets_are_opt_in(self) -> None:
        provider = FakeProvider([ent("杭州", EntityType.LOCATION, 6, 8)])
        detector = NERDetector(provider=provider)

        [plain] = detector.detect("张三目前住在杭州")
        self.assertNotIn("start_byte", plain)

        [full] = [e.to_dict(with_bytes=True) for e in detector.detect_entities("张三目前住在杭州")]
        self.assertEqual(full["start_byte"], 18)


class TestOffsetIntegrity(unittest.TestCase):
    """偏移与原文对不上必须报错，而不是把错的位置交给下游。

    Offsets that disagree with the text must raise, not be handed downstream.
    """

    def test_lying_provider_is_caught(self) -> None:
        # 声称 "杭州" 在 [0,2)，而那里其实是 "张三"
        provider = FakeProvider([ent("杭州", EntityType.LOCATION, 0, 2)])
        detector = NERDetector(provider=provider)

        with self.assertRaises(ValueError) as ctx:
            detector.detect("张三目前住在杭州")

        self.assertIn("偏移与原文不符", str(ctx.exception))
        self.assertIn("fake", str(ctx.exception), "报错应点名是哪个后端")


class TestTypeFiltering(unittest.TestCase):
    def test_filter_to_person_only(self) -> None:
        provider = FakeProvider(
            [
                ent("张三", EntityType.PERSON_NAME, 0, 2),
                ent("杭州", EntityType.LOCATION, 6, 8),
            ]
        )
        detector = NERDetector(provider=provider, types=[EntityType.PERSON_NAME])

        got = detector.detect("张三目前住在杭州")

        self.assertEqual([e["type"] for e in got], ["PERSON_NAME"])

    def test_unknown_type_is_rejected_at_construction(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            NERDetector(provider=FakeProvider(), types=["PERSON"])

        self.assertIn("PERSON", str(ctx.exception))
        self.assertIn("PERSON_NAME", str(ctx.exception), "报错应给出合法取值")


class TestBatch(unittest.TestCase):
    """批量结果必须与输入下标一一对应，空串照样占位。"""

    def test_empty_strings_keep_their_slots(self) -> None:
        provider = FakeProvider([ent("张三", EntityType.PERSON_NAME, 0, 2)])
        detector = NERDetector(provider=provider)

        got = detector.detect_batch(["张三来了", "", "  ", "张三又来了"])

        self.assertEqual(len(got), 4, "输出条数必须与输入相同")
        self.assertEqual(got[1], [])
        self.assertEqual(got[2], [])
        self.assertEqual(got[0][0]["text"], "张三")
        self.assertEqual(got[3][0]["text"], "张三")

    def test_empty_batch(self) -> None:
        detector = NERDetector(provider=FakeProvider())
        self.assertEqual(detector.detect_batch([]), [])


class TestProviderReplaceability(unittest.TestCase):
    """换后端不需要改上层代码 —— 本用例全程不 import spaCy。

    Swapping backends requires no caller change; this test never imports spaCy.
    """

    def test_custom_provider_needs_no_spacy(self) -> None:
        class HuggingFaceStub:
            """假装是将来的 transformer 后端。"""

            @property
            def name(self) -> str:
                return "hf:bert-base-chinese-ner"

            def extract(self, text: str) -> list[Entity]:
                return [ent("张三", EntityType.PERSON_NAME, 0, 2)]

        detector = NERDetector(provider=HuggingFaceStub())

        self.assertEqual(detector.provider_name, "hf:bert-base-chinese-ner")
        self.assertEqual(detector.detect("张三来了")[0]["type"], "PERSON_NAME")

    def test_provider_without_batch_support_falls_back(self) -> None:
        """Provider 协议里没有 extract_batch，因此不能假设它存在。"""
        detector = NERDetector(
            provider=FakeProvider([ent("张三", EntityType.PERSON_NAME, 0, 2)])
        )

        got = detector.detect_batch(["张三来了", "张三又来了"])

        self.assertEqual(len(got), 2)
        self.assertEqual(got[0][0]["text"], "张三")


class TestModelLoadFailure(unittest.TestCase):
    """模型加载失败必须抛出清晰异常，而不是让底层错误炸穿。

    A load failure must raise a clear error, not let the underlying one escape.
    """

    def test_missing_model_message_is_actionable(self) -> None:
        with self.assertRaises(NERModelNotAvailable) as ctx:
            NERDetector(model="zz_this_model_does_not_exist_sm")

        message = str(ctx.exception)
        self.assertIn("zz_this_model_does_not_exist_sm", message, "应点名是哪个模型")
        self.assertIn("spacy download", message, "应给出修复命令")

    def test_error_is_catchable_as_ner_error(self) -> None:
        from pii.detectors import NERError

        with self.assertRaises(NERError):
            NERDetector(model="zz_this_model_does_not_exist_sm")


def _spacy_model_available() -> bool:
    try:
        NERDetector()
    except NERModelNotAvailable:
        return False
    return True


@unittest.skipUnless(
    _spacy_model_available(),
    "需要 zh_core_web_md：python -m spacy download zh_core_web_md",
)
class TestSpacyBackend(unittest.TestCase):
    """需要真实模型的用例。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.detector = NERDetector()

    def test_spec_example(self) -> None:
        """规格里给出的那个例子。"""
        got = self.detector.detect("张三目前住在杭州，并且在阿里巴巴工作。")

        self.assertEqual(
            got,
            [
                {"text": "张三", "type": "PERSON_NAME", "start": 0, "end": 2, "source": "NER"},
                {"text": "杭州", "type": "LOCATION", "start": 6, "end": 8, "source": "NER"},
                {"text": "阿里巴巴", "type": "ORGANIZATION", "start": 12, "end": 16, "source": "NER"},
            ],
        )

    def test_label_mapping_covers_all_four(self) -> None:
        from pii.detectors.providers.spacy_provider import LABEL_MAP

        self.assertEqual(LABEL_MAP["PERSON"], EntityType.PERSON_NAME)
        self.assertEqual(LABEL_MAP["ORG"], EntityType.ORGANIZATION)
        self.assertEqual(LABEL_MAP["GPE"], EntityType.LOCATION)
        self.assertEqual(LABEL_MAP["LOC"], EntityType.LOCATION)

    def test_non_pii_labels_are_dropped(self) -> None:
        """DATE / CARDINAL 这类标签不得流进结果。

        模型对「昨天」会打 DATE。它若透传，下游按类型选脱敏算子时会走默认
        算子，把「昨天」也脱敏掉。
        """
        got = self.detector.detect("张三昨天花了 100 元。")

        types = {e["type"] for e in got}
        self.assertTrue(types <= EntityType.ALL, f"出现了未标准化的类型：{types}")
        self.assertNotIn("昨天", [e["text"] for e in got])

    def test_offsets_slice_back_to_the_entity(self) -> None:
        text = "周慧敏和欧阳志远昨天去了北京市海淀区。"
        for e in self.detector.detect(text):
            with self.subTest(entity=e["text"]):
                self.assertEqual(text[e["start"] : e["end"]], e["text"])

    def test_provider_name(self) -> None:
        from pii.detectors.providers.spacy_provider import DEFAULT_MODEL

        self.assertEqual(self.detector.provider_name, f"spacy:{DEFAULT_MODEL}")

    def test_default_model_is_not_duplicated(self) -> None:
        """模型名的默认值只能有一份。

        NERDetector 不持有自己的默认模型名——持有就会与 provider 里的那份
        漂移，症状是「配置说用 A、实际加载 B」且不报错。
        """
        import inspect

        sig = inspect.signature(NERDetector.__init__)
        self.assertIsNone(
            sig.parameters["model"].default,
            "NERDetector 不应硬编码模型名，应交给 provider 决定",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
