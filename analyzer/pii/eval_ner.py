"""量一下 NER 后端实际能补上多少召回率。

Measure what the NER backend actually recovers.

    python -m pii.eval_ner

语料的正例是手写的，因此这里量出来的召回率**不是**循环论证——
模型不是我训的，它没见过这份语料。反例同理。

The positives are hand-written, so the recall number here is not circular: the
model was not trained by us and has not seen this corpus.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from pii.detectors import EntityType, NERDetector, NERModelNotAvailable


@dataclass(frozen=True)
class Sample:
    text: str
    #: (实体文本, 标准化类型)，位置由本脚本回原文定位
    gold: tuple[tuple[str, str], ...]
    category: str


P, O, L = EntityType.PERSON_NAME, EntityType.ORGANIZATION, EntityType.LOCATION


POSITIVES: list[Sample] = [
    # --- 常见姓名 ---
    Sample("请联系张伟处理此事。", (("张伟", P),), "常见姓名"),
    Sample("经办人李娜已签字确认。", (("李娜", P),), "常见姓名"),
    Sample("王强和刘洋昨天提交了报销单。", (("王强", P), ("刘洋", P)), "常见姓名"),
    # --- 生僻姓名与复姓 ---
    Sample("请联系周慧敏确认收货地址。", (("周慧敏", P),), "生僻/复姓"),
    Sample("经办人欧阳志远已签字。", (("欧阳志远", P),), "生僻/复姓"),
    Sample("司徒美堂出席了会议。", (("司徒美堂", P),), "生僻/复姓"),
    Sample("尉迟恭负责本次验收。", (("尉迟恭", P),), "生僻/复姓"),
    # --- 姓名在句中/句尾 ---
    Sample("本次审批由陈静完成。", (("陈静", P),), "位置变化"),
    Sample("赵敏、孙悟空与钱多多共同署名。", (("赵敏", P), ("孙悟空", P), ("钱多多", P)), "位置变化"),
    # --- 地点 ---
    Sample("寄往上海市浦东新区。", (("上海市浦东新区", L),), "地点"),
    Sample("客户在杭州，供应商在深圳。", (("杭州", L), ("深圳", L)), "地点"),
    Sample("北京市海淀区中关村大街 1 号。", (("北京市海淀区", L),), "地点"),
    # --- 机构 ---
    Sample("合同方为星辰科技有限公司。", (("星辰科技有限公司", O),), "机构"),
    Sample("供应商是临安远景机械制造有限公司。", (("临安远景机械制造有限公司", O),), "机构"),
    Sample("他在阿里巴巴工作，之前在腾讯。", (("阿里巴巴", O), ("腾讯", O)), "机构"),
    Sample("由中国工商银行代扣。", (("中国工商银行", O),), "机构"),
    # --- 混合 ---
    Sample(
        "张三目前住在杭州，并且在阿里巴巴工作。",
        (("张三", P), ("杭州", L), ("阿里巴巴", O)),
        "混合",
    ),
    Sample(
        "李娜从北京飞到深圳，与华为的王强会面。",
        (("李娜", P), ("北京", L), ("深圳", L), ("华为", O), ("王强", P)),
        "混合",
    ),
]

#: 必须零命中的文本。误杀专业术语会直接改坏内容。
NEGATIVES: list[Sample] = [
    Sample("患者主诉反复胸痛三月，诊断为不稳定型心绞痛。", (), "医学术语"),
    Sample("依据个人信息保护法第十三条第一款之规定处理。", (), "法律术语"),
    Sample("本期加权平均净资产收益率为百分之十二点三五。", (), "财务术语"),
    Sample("网关在显存超过阈值时进入分级降级。", (), "技术术语"),
    Sample("func retry(n int) error { return nil }", (), "源代码"),
    Sample("订单号 20240131000012345 已发货。", (), "业务编号"),
]


def locate(text: str, value: str) -> tuple[int, int] | None:
    idx = text.find(value)
    return None if idx < 0 else (idx, idx + len(value))


def main(model: str | None = None) -> int:
    try:
        detector = NERDetector(model=model)
    except NERModelNotAvailable as exc:
        print(f"跳过评测：{exc}", file=sys.stderr)
        return 1

    print(f"后端：{detector.provider_name}\n")

    by_category: dict[str, list[int]] = {}
    tp = fp = fn = partial = 0
    misses: list[str] = []
    spurious: list[str] = []

    for sample in POSITIVES + NEGATIVES:
        found = detector.detect(sample.text)
        gold = []
        for value, typ in sample.gold:
            span = locate(sample.text, value)
            assert span is not None, f"语料错误：{value!r} 不在 {sample.text!r} 中"
            gold.append((span[0], span[1], typ, value))

        matched_gold = [False] * len(gold)
        matched_pred = [False] * len(found)

        # 精确匹配：位置与类型都对
        for pi, pred in enumerate(found):
            for gi, (gs, ge, gt, _) in enumerate(gold):
                if matched_gold[gi] or matched_pred[pi]:
                    continue
                if pred["start"] == gs and pred["end"] == ge and pred["type"] == gt:
                    matched_gold[gi] = matched_pred[pi] = True
                    tp += 1
                    break

        # 重叠但边界或类型不符
        for pi, pred in enumerate(found):
            if matched_pred[pi]:
                continue
            for gi, (gs, ge, _, gv) in enumerate(gold):
                if matched_gold[gi]:
                    continue
                if pred["start"] < ge and gs < pred["end"]:
                    matched_gold[gi] = matched_pred[pi] = True
                    partial += 1
                    misses.append(
                        f"  ~ {sample.text[:18]}… 期望 {gv!r}，得到 "
                        f"{pred['text']!r}/{pred['type']}"
                    )
                    break

        for gi, ok in enumerate(matched_gold):
            if not ok:
                fn += 1
                misses.append(f"  ✗ 漏检 {gold[gi][3]!r}/{gold[gi][2]}  ← {sample.text}")
        for pi, ok in enumerate(matched_pred):
            if not ok:
                fp += 1
                spurious.append(
                    f"  ✗ 误报 {found[pi]['text']!r}/{found[pi]['type']}  ← {sample.text}"
                )

        stats = by_category.setdefault(sample.category, [0, 0, 0, 0])
        stats[0] += sum(matched_gold)
        stats[1] += len(gold) - sum(matched_gold)
        stats[2] += len(found) - sum(matched_pred)
        stats[3] += len(gold)

    print(f"{'分类':<12} {'命中':>5} {'漏检':>5} {'误报':>5}   {'召回':>8}")
    print("─" * 48)
    for name in sorted(by_category):
        hit, miss, spur, total = by_category[name]
        recall = hit / total * 100 if total else 100.0
        print(f"{name:<12} {hit:>5} {miss:>5} {spur:>5}   {recall:>7.1f}%")
    print("─" * 48)

    total_gold = tp + fn + partial
    total_pred = tp + fp + partial
    recall = tp / total_gold * 100 if total_gold else 100.0
    precision = tp / total_pred * 100 if total_pred else 100.0
    print(f"{'合计':<12} {tp:>5} {fn:>5} {fp:>5}   {recall:>7.1f}%")
    print(f"\n精确匹配召回率 {recall:.1f}%   精确率 {precision:.1f}%   部分匹配 {partial}")

    if misses:
        print("\n漏检与边界不符：")
        for line in misses:
            print(line)
    if spurious:
        print("\n误报：")
        for line in spurious:
            print(line)

    print(
        "\n对照：不接 NER 时，姓名/地点/机构这三类的召回率是 0% —— "
        "正则没有办法找到它们。"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else None))
