# PII 脱敏 sidecar 镜像。
#
# 多阶段构建，最终镜像基于 distroless：无 shell、无包管理器、
# 无 libc 之外的任何东西。对一个处理 PII 的组件而言，
# 攻击面越小越好——即便被攻破，攻击者也没有可用的工具链。

FROM golang:1.27-alpine AS build
WORKDIR /src

# 先拷依赖清单，让依赖层能被缓存
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
# CGO_ENABLED=0 产出静态二进制，才能跑在 distroless/static 上
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w" \
    -o /airlock-agent ./cmd/airlock-agent

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /airlock-agent /airlock-agent

# 以非 root 运行。distroless 的 nonroot 标签内置了 uid 65532
USER nonroot:nonroot
EXPOSE 8888

# 健康检查交给编排层（K8s probe），镜像里不装 curl——
# 装了就等于给攻击者留了一个现成的外联工具
ENTRYPOINT ["/airlock-agent"]
CMD ["--addr", ":8888"]
