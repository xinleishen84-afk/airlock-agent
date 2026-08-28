# 契约

`pii/v1/ner.proto` 是 Go 网关与 Python 推理进程之间的唯一契约。

## 重新生成

改动 proto 之后两侧都要重新生成，否则一侧按新字段编码、另一侧按旧字段解码，
而 protobuf 会**静默忽略**它不认识的字段——不报错，只是那个字段永远是零值。

```bash
# Go
protoc -I proto \
  --go_out=. --go_opt=module=github.com/xinleishen84-afk/airlock-agent \
  --go-grpc_out=. --go-grpc_opt=module=github.com/xinleishen84-afk/airlock-agent \
  proto/pii/v1/ner.proto

# Python（在仓库根目录执行）
python -m grpc_tools.protoc \
  -I proto \
  --python_out=analyzer/pii/service/genproto \
  --grpc_python_out=analyzer/pii/service/genproto \
  --pyi_out=analyzer/pii/service/genproto \
  proto/pii/v1/ner.proto
```

生成的 Python 桩用的是绝对 import（`from pii.v1 import ner_pb2`），
需要改成 `from pii.service.genproto.pii.v1 import ner_pb2`。

## 偏移量：契约里最要紧的一条

`NEREntity.start` / `end` 是**字符**偏移（Unicode code point），不是字节偏移。

Python 的 `str` 按字符索引，Go 的 `string` 按字节索引，一个汉字占 3 字节。
文本「你好张三」里 Python 说「张三」在 `[2,4)`，而 Go 里它在 `[6,12)`。
拿前者直接切 Go 的字符串，切出来的是半个汉字——敏感值没洗掉，报文还成了
非法 UTF-8。

Go 侧必须做 rune→byte 映射（`nerclient/offsets.go`），并用 `NEREntity.text`
验证映射结果。`text` 字段就是为这次验证存在的：少了它，一次错位只会表现为
「脱敏了错的几个字」，而没有任何东西能发现。
