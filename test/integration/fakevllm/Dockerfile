# 假 vLLM 端点。多阶段构建，最终镜像只含静态二进制。
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY main.go .
RUN go mod init fakevllm && CGO_ENABLED=0 go build -o /fakevllm .

FROM gcr.io/distroless/static-debian12
COPY --from=build /fakevllm /fakevllm
EXPOSE 8000
ENTRYPOINT ["/fakevllm"]
