#!/usr/bin/env bash
# 可复现构建：三个二进制、四个平台，一份构建参数。
# Reproducible builds: three binaries, four platforms, one set of flags.
#
# # 为什么构建参数只写一份
# # Why the build flags live in exactly one place
#
# 本仓库有三个入口（cmd/airlock-agent、cmd/airlock-gateway、
# nerclient/cmd/airlock-agent-advanced）分属两个 Go 模块，加上 CI、
# release workflow 与 Dockerfile。这套参数在这些地方各写一份的话，
# 只要漏掉一处 -trimpath，那一处产出的二进制就带着构建机的绝对路径。
#
# 这不是假设：仓库里曾经提交过一个 12MB 的编译产物，strings 出来带着
# 构建机的家目录 /Users/apple。Dockerfile 当时是有 -trimpath 的，
# 而那个二进制是在本机 go build 出来的——参数写在别处，就等于没写。
#
# Three entry points across two modules, plus CI, the release workflow and a
# Dockerfile. Duplicating these flags means one missing -trimpath ships a binary
# carrying the build machine's absolute paths. That already happened here: a
# committed 12MB artifact contained the builder's home directory while the
# Dockerfile did have -trimpath — the flags lived somewhere the build did not.
set -euo pipefail

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUT="${OUT:-dist}"

# 绝对化输出目录。
#
# go build 的 -o 相对的是它自己的工作目录，而这里会 cd 进各模块根去构建，
# 相对路径会写到模块目录里而不是 dist/。直接拼 $(pwd)/ 又会在 OUT 本身
# 已是绝对路径时产出 /repo//abs/path 这种东西——实测它在仓库里建出了一棵
# 与绝对路径同形的空目录树，而构建看起来是成功的。
#
# go build's -o is relative to its own working directory, and this script cds
# into each module root. Prefixing $(pwd)/ unconditionally breaks when OUT is
# already absolute: measured, it created a directory tree inside the repository
# mirroring the absolute path while the build appeared to succeed.
case "${OUT}" in
	/*) ;;
	*) OUT="$(pwd)/${OUT}" ;;
esac

# SOURCE_DATE_EPOCH 让时间戳可复现。取最后一次提交的时间，而不是「现在」：
# 同一个提交在任何时刻、任何机器上构建都应当产出同一份字节。
# Timestamps come from the last commit rather than "now", so the same commit
# builds byte-identical at any time on any machine.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct 2>/dev/null || echo 0)}"

# -trimpath      去掉构建机的绝对路径
# -buildvcs=true 嵌入提交号，让二进制能自证来自哪次提交
# -s -w          去掉符号表与调试信息，缩小体积
# CGO_ENABLED=0  静态链接，产出与 libc 版本无关
LDFLAGS="-s -w -X main.version=${VERSION}"
BUILDFLAGS=(-trimpath -buildvcs=true -ldflags "${LDFLAGS}")

# 二进制与它所属的模块目录。第二列是模块根，第三列是模块内的包路径。
# Advanced 在 nerclient/ 这个独立模块里——它不在主模块的 ./... 之内，
# 逐个列出而不是遍历 cmd/，正是因为遍历会漏掉它。
TARGETS=(
	"airlock-agent:.:./cmd/airlock-agent"
	"airlock-gateway:.:./cmd/airlock-gateway"
	"airlock-agent-advanced:nerclient:./cmd/airlock-agent-advanced"
)

PLATFORMS="${PLATFORMS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64}"

mkdir -p "${OUT}"
for target in "${TARGETS[@]}"; do
	IFS=: read -r name moddir pkg <<<"${target}"
	for platform in ${PLATFORMS}; do
		IFS=/ read -r goos goarch <<<"${platform}"
		out="${OUT}/${name}_${goos}_${goarch}"
		(cd "${moddir}" && CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
			go build "${BUILDFLAGS[@]}" -o "${out}" "${pkg}")
		echo "  built ${OUT}/${name}_${goos}_${goarch}"
	done
done

# 校验和覆盖全部产物。SBOM 与签名都锚定在这份清单上，
# 因此它必须在 dist/ 里，而不是只存在于某个 CI 步骤的输出里。
(cd "${OUT}" && shasum -a 256 ./* > SHA256SUMS 2>/dev/null || sha256sum ./* > SHA256SUMS)
echo "  wrote ${OUT}/SHA256SUMS"
