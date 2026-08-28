"""NER gRPC 服务端（Unix domain socket）。

The NER gRPC server, listening on a Unix domain socket.

    python -m pii.service.ner_server --socket /tmp/airlock-ner.sock

# 为什么是 UDS 而不是本地 TCP
# Why a Unix socket rather than local TCP

这条调用在 TTFT 关键路径上：每个未被前两层拦下的请求都要等它。
本地环回要走完整的 TCP 协议栈——握手、Nagle、内核收发缓冲、校验和——
而这些对同机进程间通信没有任何价值。UDS 只做一次内核内存拷贝。

This call sits on the TTFT critical path. Loopback pays for the full TCP
stack, none of which buys anything between two processes on one host.

# 并发模型
# Concurrency

spaCy 的 Language 对象在并发调用下不保证安全，SpacyNERProvider 因此持有一把
锁。gRPC 的线程池会把请求排到这把锁上，于是本进程的实际推理并发度是 1。
这是刻意的：正确性优先，吞吐靠横向加进程（每个进程一个 UDS）而不是靠
在一个模型实例上并发。

A spaCy Language object is not concurrency-safe, so the provider holds a lock.
The gRPC thread pool queues on it, making effective inference concurrency one.
Deliberate: correctness first; throughput comes from more processes, each with
its own socket, not from concurrent use of one model.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import stat
import sys
import threading
import time
from concurrent import futures

import grpc

from pii.detectors import NERDetector, NERError, NERModelNotAvailable
from pii.detectors.providers.router import LanguageRouter
from pii.detectors.providers.spacy_provider import SpacyNERProvider
from pii.service.genproto.pii.v1 import ner_pb2, ner_pb2_grpc

log = logging.getLogger("ner-server")


class NERServicer(ner_pb2_grpc.NERServiceServicer):
    """把 MultilingualNERDetector 暴露为 gRPC 服务。"""

    #: 请求没带 language 时使用的语言。
    #:
    #: 不猜语言：请求里没写就用配置的默认值，而不是根据文本去检测。
    #: 猜错的后果是拿错模型判，输出看起来正常、其实全错——
    #: 而调用方（Go 网关）本来就知道自己在处理什么语言，它该说出来。
    #:
    #: The language is not guessed from the text: a wrong guess means the wrong
    #: model, whose output looks normal and is entirely wrong. The caller knows
    #: what it is handling and should say so.
    DEFAULT_LANGUAGE = "zh"

    def __init__(self, detector: NERDetector, default_language: str) -> None:
        self._detector = detector
        self._default_language = default_language
        self._requests = 0
        self._lock = threading.Lock()

    def Analyze(self, request, context):  # noqa: N802 - gRPC 生成的方法名
        started = time.perf_counter()

        try:
            types = list(request.entity_types) or None
            if types is not None:
                detector = NERDetector(
                    provider=self._detector_provider(), types=types
                )
            else:
                detector = self._detector

            # language 为空时按 auto 处理：按文字系统切段，各段路由到
            # 对应语言的模型。写死一个语言等于对另一半语言的内容用错模型。
            #
            # An empty language means auto: segment by script and route. Pinning
            # one language means the other half is scanned by the wrong model.
            entities = detector.detect_entities(
                request.text, language=request.language or "auto"
            )
        except ValueError as exc:
            # 偏移与原文对不上：这是数据损坏，不是「没找到实体」。
            # 返回 INVALID_ARGUMENT 让 Go 侧阻断，而不是返回空列表让它以为
            # 这段文本干净。
            #
            # An offset mismatch is data corruption, not "no entities found".
            # Returning INVALID_ARGUMENT makes the Go side block rather than
            # concluding the text is clean.
            log.error("偏移校验失败 / offset check failed: %s", exc)
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
            return ner_pb2.AnalyzeResponse()
        except NERError as exc:
            log.error("推理失败 / inference failed: %s", exc)
            context.abort(grpc.StatusCode.INTERNAL, str(exc))
            return ner_pb2.AnalyzeResponse()

        with self._lock:
            self._requests += 1

        return ner_pb2.AnalyzeResponse(
            model=self._detector.provider_name,
            entities=[
                ner_pb2.NEREntity(
                    entity_type=e.type,
                    # 字符偏移，不是字节偏移。契约里写死了这一点，
                    # Go 侧负责映射。
                    # Character offsets; the Go side maps them.
                    start=e.start,
                    end=e.end,
                    text=e.text,
                    score=e.confidence,
                )
                for e in entities
            ],
            inference_micros=int((time.perf_counter() - started) * 1_000_000),
        )

    def Health(self, request, context):  # noqa: N802
        provider = self._detector._provider  # noqa: SLF001

        languages = list(getattr(provider, "languages", []))
        labels = getattr(provider, "supported_labels", None)
        types: set[str] = set(labels) if labels else set()
        if not types:
            from pii.detectors import EntityType

            types = set(EntityType.ALL)

        detail = f"已处理 {self._requests} 次请求"
        if languages:
            detail = f"语言 {languages}，默认 {self._default_language}，" + detail

        return ner_pb2.HealthResponse(
            ready=True,
            model=self._detector.provider_name,
            supported_types=sorted(types),
            detail=detail,
        )


def build_detector(models: dict[str, str]) -> NERDetector:
    """按 语言→模型 的映射装配检测器。

    Assemble the detector from a language→model mapping.

    只配了一个语言时也走路由：路由器对单语言是恒等的，而让「单语言」和
    「多语言」走两条不同的代码路径，意味着其中一条平时没人跑。

    A single language still goes through the router: it is the identity there,
    and two code paths would mean one of them is rarely exercised.
    """
    providers = {
        lang: SpacyNERProvider(model=name) for lang, name in sorted(models.items())
    }
    default = "zh" if "zh" in providers else sorted(providers)[0]
    return NERDetector(provider=LanguageRouter(providers, default_language=default))


def serve(socket_path: str, listen_addr: str, models: dict[str, str], workers: int) -> int:
    """在 UDS 上启动服务，直到收到停止信号。"""
    default_language = "zh" if "zh" in models else sorted(models)[0]
    try:
        detector = build_detector(models)
    except NERModelNotAvailable as exc:
        # 模型加载失败必须在启动期炸掉，且带修复指引。
        # 让它在第一个请求上以一个底层错误的形式出现，意味着服务已经
        # 对外声称自己就绪了。
        #
        # A load failure must abort at startup with a fix. Surfacing it on the
        # first request means the service already reported itself ready.
        print(f"启动失败 / startup failed:\n{exc}", file=sys.stderr)
        return 1

    # UDS 路径有硬长度上限（sockaddr_un.sun_path，macOS 104 字节、
    # Linux 108 字节）。超了之后 bind 会失败，而底层给出的报错是
    # "Path name should not have more than 103 characters"——
    # 它不说是哪个路径、也不说这是操作系统的结构体限制。
    # 在这里挡住，并把路径原样打出来。
    #
    # A Unix socket path has a hard limit (sockaddr_un.sun_path: 104 bytes on
    # macOS, 108 on Linux). Exceeding it fails at bind with a message that
    # names neither the path nor the reason.
    max_len = 103
    if socket_path and len(socket_path.encode("utf-8")) > max_len:
        print(
            f"socket 路径过长：{len(socket_path)} 字节 > {max_len}\n"
            f"  {socket_path}\n"
            f"这是操作系统 sockaddr_un 结构体的限制，不是本程序的。"
            f"请换一个更短的路径，例如 /tmp/airlock-ner.sock\n"
            f"Unix socket path too long; this is an OS limit.",
            file=sys.stderr,
        )
        return 1

    # 陈旧的 socket 文件会让 bind 失败。删除前先确认它确实是 socket——
    # 万一路径被配成了别的文件，删掉它就是一次意外的数据丢失。
    #
    # A stale socket file makes bind fail. Confirm it is a socket before
    # unlinking: if the path was misconfigured, deleting it would be data loss.
    if socket_path and os.path.exists(socket_path):
        if not stat.S_ISSOCK(os.stat(socket_path).st_mode):
            print(
                f"路径 {socket_path} 已存在且不是 socket，拒绝删除 / "
                f"refusing to unlink a non-socket",
                file=sys.stderr,
            )
            return 1
        os.unlink(socket_path)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=workers))
    ner_pb2_grpc.add_NERServiceServicer_to_server(
        NERServicer(detector, default_language), server
    )
    if socket_path:
        server.add_insecure_port(f"unix://{socket_path}")
        endpoint = f"unix://{socket_path}"
    else:
        server.add_insecure_port(listen_addr)
        endpoint = f"tcp://{listen_addr}"
    server.start()

    if socket_path:
        # UDS 的访问控制靠文件权限。默认 umask 可能让同机其他用户连上来，
        # 而这个服务会返回原始 PII 的位置——收紧到仅属主可读写。
        #
        # A Unix socket is guarded by file permissions. The default umask may
        # let other local users connect, and this service returns where the
        # PII is.
        os.chmod(socket_path, 0o600)
    else:
        # TCP 没有文件权限这道闸。这个端口上返回的是「PII 在哪」，
        # 因此它绝不能暴露在 Pod 网络之外——访问控制要靠 NetworkPolicy
        # 或 mTLS，而这两样都不在本进程的职责范围内。
        # 说出来，是因为 UDS 换成 TCP 时这道闸是静默消失的。
        #
        # TCP has no file-permission gate. This port returns where the PII is,
        # so it must not be reachable outside the Pod network; that is a
        # NetworkPolicy or mTLS concern, outside this process. Stated because
        # the gate disappears silently when a Unix socket becomes a TCP port.
        log.warning(
            "监听在 TCP %s —— 该端口返回 PII 的位置，"
            "必须用 NetworkPolicy 或 mTLS 限制访问，文件权限那道闸在这里不存在",
            listen_addr,
        )

    log.info("NER 服务已就绪 endpoint=%s models=%s workers=%d",
             endpoint, detector.provider_name, workers)
    print(f"READY {endpoint} {detector.provider_name}", flush=True)

    stopping = threading.Event()

    def shutdown(signum, _frame):
        log.info("收到信号 %s，开始停机", signum)
        stopping.set()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    try:
        stopping.wait()
    finally:
        # grace 让在途请求跑完。直接 stop(0) 会让正在推理的那个请求
        # 拿到一个连接错误，而 Go 侧会把它当成检测器故障去 fail-closed
        # 阻断一个本来正常的请求。
        #
        # The grace period lets in-flight requests finish. stop(0) would give
        # the request being inferred a connection error, which the Go side
        # reads as a detector failure and fail-closes an otherwise fine request.
        server.stop(grace=5).wait()
        if socket_path and os.path.exists(socket_path):
            os.unlink(socket_path)
        log.info("已停止")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="NER gRPC 服务（UDS）")
    parser.add_argument(
        "--socket", default="", help="Unix domain socket 路径（同 Pod sidecar）"
    )
    parser.add_argument(
        "--listen", default="",
        help="host:port（独立 Service 部署）。与 --socket 二选一。\n"
             "独立部署可以单独扩缩容，代价是失去 UDS 的延迟优势——"
             "流量要重新走完整 TCP 协议栈",
    )
    parser.add_argument(
        "--models",
        default="zh=zh_core_web_md,en=en_core_web_sm",
        help="语言→模型 的映射，逗号分隔。\n"
        "拿中文模型去判拉丁文是分布外输入——实测它会把 declined、deps、\n"
        "Codice 判成人名。每种语言都该有自己的模型。",
    )
    parser.add_argument(
        "--workers", type=int, default=4,
        help="gRPC 线程池大小。模型本身串行，这里主要吸收排队",
    )
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    models: dict[str, str] = {}
    for pair in args.models.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            print(
                f"--models 的格式是 语言=模型名，逗号分隔；无法解析 {pair!r}",
                file=sys.stderr,
            )
            return 1
        lang, name = pair.split("=", 1)
        models[lang.strip()] = name.strip()
    if not models:
        print("--models 不能为空", file=sys.stderr)
        return 1

    if bool(args.socket) == bool(args.listen):
        print(
            "--socket 与 --listen 必须且只能指定一个。\n"
            "  --socket  同 Pod sidecar，IPC 往返 ~100µs\n"
            "  --listen  独立 Service，可单独扩缩容，但要走完整 TCP 协议栈",
            file=sys.stderr,
        )
        return 1

    return serve(args.socket, args.listen, models, args.workers)


if __name__ == "__main__":
    raise SystemExit(main())
