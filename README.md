# Banner Fingerprint

Banner 指纹识别系统，接收批量网络扫描原始数据（ip/port/banner），识别协议、软件与版本。

## 技术栈

- 语言：Go 1.22，仅 stdlib，无第三方依赖
- 识别规则：`rules/fingerprints.json`，JSON 格式，与程序代码完全解耦，可热替换
- 部署：Docker Compose，多阶段镜像（`golang:1.22-alpine` → `alpine:3.19`），非 root 用户，只读根文件系统，capabilities 全收紧

## 快速启动

```bash
git clone https://github.com/danche23/banner-fingerprint.git
cd banner-fingerprint
docker compose up
```

- `server` 启动后自动健康检查（`GET /health`）
- `client` 等待 server 就绪后读取 `data/input.json`，发送识别请求并打印结果
- 自带示例数据，零配置直接运行

替换为自己的数据：

```bash
# 把自己的 JSON 文件放到 data/ 目录
cp /your/path/scan.json data/input.json
docker compose run --rm client -data /data/input.json -server http://server:8080
```

## 接口

### POST /fingerprint

批量识别 Banner。

**请求**
```json
{
  "items": [
    {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}
  ]
}
```

**响应**
```json
{
  "results": [
    {
      "ip": "1.2.3.4",
      "port": 22,
      "protocol": "SSH",
      "product": "OpenSSH",
      "version": "8.9p1",
      "os_hint": "Ubuntu",
      "confidence": 0.95
    }
  ]
}
```

识别不出来时 `protocol` 为 `"unknown"`，服务不崩溃。

### GET /health

健康检查，返回 `{"status":"ok"}`，HTTP 200。

## 识别能力

| 协议 | 代表产品 | 示例 Banner |
|------|----------|-------------|
| SSH | OpenSSH | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3` |
| HTTP | nginx / Apache / Jetty / IIS | `Server: nginx/1.24.0` |
| MySQL | MySQL 5.x / 8.x | `J\x00\x00\x00\n8.0.32\x00` |
| Redis | Redis | `+PONG` / `-ERR ...` / `-NOAUTH ...` |
| FTP | ProFTPD / vsFTPd / Pure-FTPd | `220 ProFTPD 1.3.7 ...` |
| TLS | — | `\x16\x03\x01...` 握手特征 |
| SMTP | — | `220 ... ESMTP` |
| MongoDB | MongoDB | banner 含 `mongodb` |
| PostgreSQL | PostgreSQL | banner 含 `postgresql` |
| Elasticsearch | Elasticsearch | `"You Know, for Search"` |

无法匹配时返回 `protocol: "unknown"`。

规则文件位于 `rules/fingerprints.json`，可直接编辑增删规则，无需重新编译程序。

## 目录结构

```
.
├── cmd/
│   ├── server/main.go      # HTTP 服务入口
│   └── client/main.go      # CLI 客户端入口
├── internal/
│   ├── fingerprint/
│   │   ├── engine.go       # 识别引擎（规则加载、编译、匹配）
│   │   └── engine_test.go  # 单元测试（16+ 用例，覆盖边界和异常）
│   └── model/types.go      # 数据结构定义
├── rules/
│   └── fingerprints.json   # 识别规则（与代码解耦）
├── data/
│   └── input.json          # 示例输入数据
├── Dockerfile              # 多阶段构建：builder → server / client
├── docker-compose.yml      # 一键启动
└── .github/workflows/ci.yml
```

## 自测说明

本地运行（需要 Go 1.22+）：

```bash
go test -v ./internal/fingerprint/...
```

覆盖用例：SSH 三种格式、nginx/Apache/Jetty/IIS、MySQL 真实字节和转义字面量、Redis PONG/ERR/NOAUTH、FTP ProFTPD/vsFTPd/Pure-FTPd、unknown 二进制、空 banner 不崩溃。

Docker 运行已在 GitHub Actions CI 验证，CI 结果见 Actions 页面。

## 生产级部署说明

- **容器间访问**：client 通过 compose service name `server` 访问，无硬编码 IP
- **健康检测**：server 配置 `healthcheck`（wget），client `depends_on: service_healthy` 等待真正就绪才启动
- **镜像**：多阶段构建，最终镜像只含二进制和规则文件，无编译工具链
- **权限**：`cap_drop: ALL`，server 仅保留 `NET_BIND_SERVICE`，`read_only: true` + `tmpfs: /tmp`，非 root UID 10001/10002
- **规则解耦**：`rules/fingerprints.json` 通过 `RULES_PATH` 环境变量注入，不重新编译即可替换规则

---

AI 编程工具：Claude Code（模型 claude-opus-5-5）
