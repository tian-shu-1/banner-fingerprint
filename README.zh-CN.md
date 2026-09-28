# Banner 指纹识别系统

[English](README.md) | [简体中文](README.zh-CN.md)

使用 Go 开发的 Banner 指纹识别服务，把原始 `(ip, port, banner)` 扫描数据识别为
协议、软件、版本和操作系统线索。项目以 server + client 架构交付，一条 Docker
Compose 命令即可启动。

## 快速开始

```bash
docker compose up --build
```

client 会等待 server 健康检查通过，读取 `examples/input.json`，把批量数据发送到
`POST /fingerprint`，打印 JSON 识别结果后退出。server 会继续运行。

常用变体：

```bash
# 后台启动 server，需要时再单独运行 client。
docker compose up --build -d server
docker compose run --rm client

# 使用其他本地输入文件（Linux/macOS shell）。
docker compose run --rm \
  -v "$PWD/your_input.json:/data/input.json:ro" \
  client -input /data/input.json -server http://server:8080

# Windows PowerShell 等价写法。
docker compose run --rm `
  -v "${PWD}\your_input.json:/data/input.json:ro" `
  client -input /data/input.json -server http://server:8080

# 输出便于阅读的表格。
docker compose run --rm client -input /data/input.json -server http://server:8080 -format table
```

server 默认只发布到 `127.0.0.1:8080`。如需在所有网卡上暴露端口，请在
`docker compose up` 前设置 `SERVER_BIND=0.0.0.0`。

## 接口说明

### `GET /health`

server 和规则都正常加载时返回 HTTP 200。

```json
{"status":"ok","version":"1.0.0","rules_loaded":29,"uptime_s":12}
```

### `POST /fingerprint`

请求体是扫描记录组成的 JSON 数组：

```json
[
  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
  {"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}
]
```

响应保持输入顺序，并且始终返回固定七个字段：

```json
[
  {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95},
  {"ip":"1.2.3.5","port":80,"protocol":"HTTP","product":"nginx","version":"1.24.0","os_hint":"","confidence":0.9}
]
```

无法识别的 banner 不算错误：接口仍返回 HTTP 200，该条结果为
`protocol: "unknown"`，未知字段为 `""`，`confidence` 为 `0`。顶层 JSON 格式错误
返回 HTTP 400。请求体超过 8 MiB 或批量超过 10000 条返回 HTTP 413。

```bash
curl -X POST http://127.0.0.1:8080/fingerprint \
  -H 'Content-Type: application/json' \
  --data-binary @examples/input.json
```

## 识别范围

产品级规则覆盖：

- SSH：OpenSSH（含 OpenSSH for Windows）、Dropbear、Cisco SSH
- HTTP：nginx、Apache、Jetty、Microsoft-IIS，以及通用 `Server:` 规则
- MySQL：MySQL 和 MariaDB（`5.5.5-10.11.2-MariaDB` 识别为 MariaDB `10.11.2`）
- Redis：`+PONG`、`-NOAUTH`、`-ERR`、`$-1`、RESP 数组，以及 `redis_version:` INFO 输出
- FTP：ProFTPD、vsFTPd、Pure-FTPd、FileZilla Server、Microsoft FTP
- SMTP：Postfix、Exim、Sendmail，以及通用 ESMTP/SMTP 问候规则
- TLS：把 TLS 握手记录识别为协议级线索

每个必需协议都还有一条低优先级协议兜底规则。因此即使产品名未知，也会返回正确
协议，而不是直接落到 `unknown`。

产品级规则不依赖端口：nginx 在 8443、ProFTPD 在 9999、结构化 MySQL 握手在
13306 仍然可以匹配。低置信度的协议兜底规则（`ftp-protocol`、`smtp-generic`、
`redis-generic`、`mysql-bare-version`、`mysql-fallback`）设置
`port_required: true`，因此通用 `220` 问候、裸 RESP 标记或裸版本号只会在预期
端口上被接受；产品级规则中，命中首选端口只用于优先级相同时的裁决。

## 规则与代码解耦

协议知识全部存放在 `rules/*.json`。Go 代码只负责编译正则，并把命名捕获组映射到
`product`、`version` 和 `os`。新增产品、修改版本正则都不需要改 Go 代码。

```json
{
  "id": "http-nginx",
  "protocol": "HTTP",
  "product": "nginx",
  "priority": 105,
  "ports": [80, 443, 8080, 8443],
  "pattern": "(?im)^Server:\\s*nginx/(?P<version>[0-9][0-9A-Za-z.\\-]*)",
  "confidence": 0.9
}
```

规则选择顺序为：优先级最高者优先，其次是首选端口匹配，最后按文件中的顺序。
每条规则使用第一个命中的正则。匹配前会先检查 `port_required`：设置为 `true`
且当前端口不在 `ports` 中时直接跳过；该字段只用于低置信度的协议兜底规则。

Compose 中的 server 会把 `./rules` 以只读方式挂载到 `/etc/bannerfp/rules`，
因此修改规则后重启即可：

```bash
docker compose restart server
```

镜像内也打包了同一份规则，在未挂载外部目录时可以直接运行。

## JSON 转义兼容

部分扫描导出数据会包含 `\x00`、`\x16\x03\x01` 或原始控制字节。这些不是合法
JSON 转义。服务会先严格解析；只有严格解析失败时，才把 `\xHH` 改写为 Unicode
码点 `U+00HH` 后再次解析。合法 JSON 永远不会被改写，`\\x00` 这种转义后的反斜杠
会保留为字面文本。

由于采用这一约定，规则引擎按 rune 字符串匹配：

- MySQL 的 `\x00` 按 NUL 码点匹配。
- TLS 的 `\x16\x03\x01` 按 U+0016、U+0003、U+0001 码点匹配。

使用兼容路径时，server 会在响应中增加 `X-Parse-Mode: lenient` 并记录警告日志；
client 也会向 stderr 输出警告。

## Docker 与安全设计

- 多阶段构建：`golang:1.25.0-bookworm` 编译静态二进制，运行镜像使用 `scratch`。
- 运行镜像没有包管理器，也没有 shell，减少可交互攻击面。
- 容器使用数字 UID/GID `65532:65532`，并启用 `read_only: true`、
  `cap_drop: [ALL]`、`no-new-privileges`、PID 限制以及内存/CPU 限制。
- server 健康检查使用 exec 形式 `["CMD", "/server", "healthcheck", ...]`，
  因为 `scratch` 没有 shell；写成 `CMD-SHELL` 会静默失败。
- client 是一次性任务，因此使用 `restart: "no"`。
- client 与 server 通过专用 Compose 网络和服务名通信
  （`http://server:8080`），只有 server 发布宿主机端口。
- 规则文件无效时 server 启动即失败；无法识别的 banner 则始终返回 `unknown`，
  不会导致进程崩溃。

## 本地开发

```bash
go test ./...
go vet ./...
go run ./cmd/server -listen :8080 -rules ./rules
go run ./cmd/client -input ./examples/input.json -server http://127.0.0.1:8080
```

引擎测试覆盖题目全部 20 条示例、协议兜底、MariaDB、严格/容错 JSON 解析，以及
`examples/regression_probes.json` 中的误报回归探针。

## 已知取舍

- `confidence` 是确定性的规则元数据，不是经过统计校准的概率。产品与版本都命中
  时高于仅识别出协议的兜底结果。
- banner 是 TLS 握手记录时返回 `protocol: "TLS"`，不解析证书或 SNI。
- 健康检查接口刻意保持精简，不暴露 metrics。
- 运行镜像不包含 CA 证书。client 在私有 Compose 网络内通过 HTTP 访问 server；
  TLS 终止不在本任务范围内。
