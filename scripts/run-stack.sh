#!/usr/bin/env bash
# 起一套完整的三层栈：Python NER sidecar + Go 网关。
# Bring up the full three-layer stack: the Python NER sidecar and the Go gateway.
#
#   ./scripts/run-stack.sh
#
# 两个进程同机部署，通过 Unix domain socket 通信——实测 IPC 往返约 100µs，
# 而走本地 TCP 环回要付完整协议栈的代价。
#
# Same host, one Unix socket. Measured IPC round trip is about 100µs.
set -euo pipefail

SOCKET="${AIRLOCK_NER_SOCKET:-/tmp/airlock-ner.sock}"
PYTHON_ROOT="${PYTHON_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
PY="${PYTHON:-$PYTHON_ROOT/.venv/bin/python}"

# UDS 路径有硬长度上限（sockaddr_un，macOS 104 字节）。在这里挡住，
# 否则底层报错只说「路径超过 103 字符」，不说是哪个路径。
if [ ${#SOCKET} -gt 103 ]; then
  echo "socket 路径过长（${#SOCKET} > 103）：$SOCKET" >&2
  exit 1
fi

cleanup() {
  [ -n "${NER_PID:-}" ] && kill "$NER_PID" 2>/dev/null || true
  rm -f "$SOCKET"
}
trap cleanup EXIT

echo "启动 Python NER sidecar…"
"$PY" -m pii.service.ner_server --socket "$SOCKET" \
  --models "zh=zh_core_web_md,en=en_core_web_sm" &
NER_PID=$!

# 等就绪。模型加载要几秒，此时直接连会拿到连接错误——
# 而 Go 侧会把它当成服务不可用而拒绝启动。
for _ in $(seq 1 60); do
  [ -S "$SOCKET" ] && break
  sleep 0.5
done
if [ ! -S "$SOCKET" ]; then
  echo "NER 服务未能就绪" >&2
  exit 1
fi
echo "NER sidecar 就绪：$SOCKET"

echo "启动 Go 网关…"
go run ./cmd/airlock-agent \
  --addr :8888 \
  --jurisdictions GEN,CN \
  --tenant-header X-Tenant-Id \
  --ner-socket "$SOCKET" \
  "$@"
