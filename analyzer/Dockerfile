# PII 分析器（Python）—— 把重型依赖封在镜像里，对 Go 网关彻底屏蔽。
#
# The Python analyzer: heavy dependencies sealed inside the image, invisible to
# the Go gateway.
#
# 这个镜像存在的理由是把「依赖炸开」的痛苦挪个位置：spaCy、gRPC 与几百 MB
# 的模型都在这里，而网关那边仍然是一个 11MB、只有一个外部依赖的二进制。
# 痛苦没有消失，只是从「每个用网关的人」转移到了「运维这一个镜像的人」。
#
# The point is to relocate the dependency burden, not to remove it: spaCy, gRPC
# and hundreds of megabytes of models live here, while the gateway stays an
# 11MB binary with one dependency. Someone still carries the weight; it is now
# whoever operates this one image.

FROM python:3.12-slim AS builder

WORKDIR /build

# 依赖与模型分两层装：模型有几百 MB 且极少变，
# 而依赖版本变动时不该把模型层一起作废。
#
# Dependencies and models in separate layers: the models are hundreds of
# megabytes and rarely change, and a dependency bump should not invalidate them.
RUN pip install --no-cache-dir --prefix=/install \
        "spacy>=3.8.0" "grpcio>=1.60" "protobuf>=4.25"

ARG MODELS="zh_core_web_md"
# 变量必须 export 而不能作为前缀。
#
# `VAR=x for ...; do` 在 POSIX sh 里不合法：环境变量前缀只能加在**简单命令**
# 前面，加在 for/while/if 这类复合命令前，sh 会把 `for` 当成命令名，
# 于是在 `do` 处报 "Syntax error: do unexpected"。
#
# 这一行写下来就提交了，从没被构建过——直到 CI 第一次真正 docker build
# 才暴露。清单引用着这个镜像，README 让人构建它，而两者都无人验证。
#
# Assignments must be exported, not prefixed: `VAR=x for ...; do` is invalid in
# POSIX sh, where an assignment prefix applies only to a simple command. sh
# parses `for` as the command name and fails at `do`. This line was committed
# without ever being built — the manifests referenced the image and the README
# told people to build it, and nothing verified either.
COPY models.lock /tmp/models.lock

# 按锁定的 URL 与 sha256 装模型，不用 `spacy download`。
#
# `spacy download` 去索引取「当前兼容的那一个」：版本随时间漂移，没有校验，
# 也不出现在任何 SBOM 里。而模型**就是**检测器——换一个版本，姓名、地址、
# 机构名的召回率会变，且没有任何东西会报错。
#
# 校验失败必须让构建失败，而不是回退到无校验下载：一个「验不过就照常装」
# 的校验，比没有校验更糟，因为它让人以为验过了。
#
# Pinned URL plus sha256 rather than `spacy download`, which fetches whichever
# version is currently compatible with no verification and no SBOM presence.
# The model IS the detector: a different version shifts recall with nothing
# reporting an error. A failed check fails the build — a check that falls back
# to an unverified download is worse than none, because it looks verified.
RUN export PYTHONPATH=/install/lib/python3.12/site-packages \
        PATH=/install/bin:$PATH; \
    set -eu; \
    version="$(grep '^SPACY_MODEL_VERSION=' /tmp/models.lock | cut -d= -f2)"; \
    for m in ${MODELS}; do \
        expected="$(grep "^${m} " /tmp/models.lock | cut -d: -f2)"; \
        if [ -z "${expected}" ]; then \
            echo "models.lock 里没有 ${m} 的校验和——拒绝装一个没锁的模型"; \
            exit 1; \
        fi; \
        url="https://github.com/explosion/spacy-models/releases/download/${m}-${version}/${m}-${version}-py3-none-any.whl"; \
        wheel="/tmp/${m}.whl"; \
        echo "下载 ${m}-${version}"; \
        python -c "import urllib.request,sys; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])" "${url}" "${wheel}"; \
        actual="$(python -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "${wheel}")"; \
        if [ "${actual}" != "${expected}" ]; then \
            echo "${m} 校验和不符——构建中止"; \
            echo "  期望 ${expected}"; \
            echo "  实得 ${actual}"; \
            exit 1; \
        fi; \
        pip install --no-cache-dir --no-deps --target /install/lib/python3.12/site-packages "${wheel}"; \
        rm -f "${wheel}"; \
    done

FROM python:3.12-slim

# 非 root 运行。这个进程返回的是「PII 在哪」，
# 因此它拿到的权限越少越好。
#
# Runs as non-root: this process returns where the PII is, so it should hold as
# little privilege as possible.
RUN useradd --create-home --shell /usr/sbin/nologin analyzer

COPY --from=builder /install /usr/local
WORKDIR /app
COPY --chown=analyzer:analyzer pii/ /app/pii/

USER analyzer

# UDS 与 TCP 两种形态都支持，由启动参数决定：
#   同 Pod sidecar：--socket /var/run/airlock/ner.sock   （IPC ~110µs）
#   独立 Service ：--listen 0.0.0.0:9090                 （可单独扩缩容）
#
# 默认走 TCP，因为独立部署是这个镜像的主要用途；同 Pod 部署时覆盖 command。
ENV PYTHONUNBUFFERED=1
EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD python -c "import grpc, sys; \
from pii.service.genproto.pii.v1 import ner_pb2, ner_pb2_grpc; \
ch = grpc.insecure_channel('127.0.0.1:9090'); \
sys.exit(0 if ner_pb2_grpc.NERServiceStub(ch).Health(ner_pb2.HealthRequest(), timeout=4).ready else 1)"

ENTRYPOINT ["python", "-m", "pii.service.ner_server"]
CMD ["--listen", "0.0.0.0:9090", "--models", "zh=zh_core_web_md"]
