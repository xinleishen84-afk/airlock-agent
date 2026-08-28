# PII 分析器（Python）

`airlock-agent` 的重型推理侧：spaCy NER，以 gRPC over Unix domain socket
对外服务。Go 网关通过 `nerclient/` 调用它。

## 它为什么单独一个目录，而不是散在仓库根上

Go 侧的 `pii/` 是 Go 包，这里的 `pii/` 是 Python 包，名字相同。分开放一层
`analyzer/` 让两者互不干扰，也让 Docker 构建上下文正好是这一个目录——
镜像里不会混进 26,000 行与推理无关的 Go 代码。

更要紧的是依赖边界：Core 模式的卖点是「一个 11MB 二进制、一个外部依赖」。
把 spaCy 那几百 MB 的依赖树放在这里，是为了让「不用 Advanced 就不用装它」
在物理上成立，而不只是文档里的一句话。

## 这个目录**之前不在版本控制里**

`analyzer/` 下的全部代码原本躺在仓库上一级目录，而那个目录不是 git 仓库。
后果是：克隆 `airlock-agent` 拿到的是一个 Core-only 的系统，
`deploy/advanced-*.yaml` 引用的 `ghcr.io/…/airlock-analyzer:latest`
没有任何东西能构建它——连 Dockerfile 都不在仓库里。

契约（`proto/pii/v1/ner.proto`）一直在仓库里，缺的是实现。也就是说
「两边都遵守同一份契约」这件事，此前只有一边能被审阅。

## 跑起来

```bash
# 依赖与模型
pip install -r analyzer/requirements.txt
python -m spacy download zh_core_web_md   # 74MB
python -m spacy download en_core_web_lg   # 400MB，处理拉丁文必装

# 启动服务（Unix socket，权限 0600）
cd analyzer
python -m pii.service.ner_server --socket /tmp/airlock-ner.sock \
    --models zh=zh_core_web_md,en=en_core_web_lg

# Go 侧接上它
go build -o airlock-agent-advanced ./nerclient/cmd/airlock-agent-advanced
./airlock-agent-advanced -jurisdictions GEN,CN -single-tenant acme \
    -session-consistency single-replica -ner-socket /tmp/airlock-ner.sock
```

socket 路径要短：`sockaddr_un` 上限 103 字节，是操作系统的限制不是本程序的。

## 测试

```bash
cd analyzer && python -m unittest discover tests -v
```

未安装 spaCy 时测试会跳过而不是失败——分析器的依赖是可选的，
CI 上不装模型也要能跑通其余部分。

## 桩代码

`pii/service/genproto/` 是从 `../proto/pii/v1/ner.proto` 生成的，
生成命令与那份契约里「偏移量」一节的注意事项见 `../proto/README.md`。
