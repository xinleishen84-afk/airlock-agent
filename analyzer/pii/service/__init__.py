"""NER 推理服务。

把 pii.detectors 里的 NERDetector 包成 gRPC 服务，通过 Unix domain socket
供同机的 Go 网关调用。

Wraps NERDetector as a gRPC service over a Unix domain socket for the Go
gateway on the same host.
"""
