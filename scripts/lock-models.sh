#!/usr/bin/env bash
# 重新生成 analyzer/models.lock 里的校验和。
#
# 校验和是抄下来的事实，不是手填的数字——手填一次错了，之后每次构建都会
# 「验证通过」，因为验的是那个错的值。
set -euo pipefail

LOCK="$(dirname "$0")/../analyzer/models.lock"
VERSION="$(grep '^SPACY_MODEL_VERSION=' "${LOCK}" | cut -d= -f2)"

echo "spaCy 模型版本: ${VERSION}"
for model in $(grep -oE '^[a-z]+_core_[a-z]+_[a-z]+' "${LOCK}"); do
	url="https://github.com/explosion/spacy-models/releases/download/${model}-${VERSION}/${model}-${VERSION}-py3-none-any.whl"
	sum="$(curl -sL --fail "${url}" | sha256sum | cut -d' ' -f1)"
	echo "${model} sha256:${sum}"
done
