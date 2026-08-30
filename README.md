# ServerProxy

一个「控制面 + 代理运行面」分层架构的轻量代理管理面板：Go 单二进制 + Vue 3 前端（`go:embed` 内嵌），驱动真实 **sing-box** 内核，提供订阅管理、节点切换、代理模式、TUN 接管、实时监控与配置回滚。

## 特性

- **订阅管理**：支持 Base64 节点列表、单节点 URI 与 Clash YAML/JSON 配置档；自动识别 SS / VMess / VLESS / Trojan / Hysteria2 / TUIC / AnyTLS / SOCKS / HTTP；按完整配置指纹去重；失败更新不清空旧节点；按 UA 白名单适配机场（自动降级重试）。
- **代理模式**：规则（rule）/ 全局（global）/ 直连（direct）一键切换，内核自动重载生效。
- **节点管理**：手动选择 + 自动测速组，按订阅过滤节点，实时延迟展示。
- **TUN 虚拟网卡**：接管系统全部流量（需管理员权限），支持 gVisor 栈。
- **实时监控**：流量速率/累计、活动连接、内核日志实时推送（SSE），日志支持搜索、分级筛选与清除。
- **配置事务**：校验 → 原子发布 → 内核重载 → 健康检查 → 失败自动回滚；保留最近 10 个已应用修订，支持一键恢复。
- **运维能力**：审计日志、订阅/规则集定时更新、systemd 单元生成、内核自动下载。

## 架构

```
控制面（本仓库，Go）
├── internal/api          Web API（会话/CSRF、SSE 实时通道）
├── internal/app          组装根（服务、密钥、调度循环）
├── internal/config       配置编译与六步应用事务
├── internal/subscription 订阅抓取/解析（SSRF 防护、UA 降级）
├── internal/ruleset      远程规则集管理
├── internal/observability日志缓冲、指标采样、审计
├── internal/store        JSON 文件存储（AES-GCM 主密钥）
└── internal/core         内核适配器（dev 模拟 / sing-box 真实内核）

运行面：sing-box 子进程，通过 Clash API 与本机内核交互
运行时数据：<data-dir>/（默认 ./.serverproxy）
```

## 快速开始

### 前置要求

- [Go](https://go.dev/dl/) 1.27+
- Node.js 18+（**仅修改前端时需要**；仓库内已包含构建好的前端产物）
- [sing-box](https://github.com/SagerNet/sing-box/releases)（可运行面板后在「设置 → 内核部署」一键下载，或自行安装）

### 构建

```bash
git clone https://github.com/Gloria0929/ServerProxy.git
cd ServerProxy

# 直接运行
go run ./cmd/sp serve

# 或编译单二进制
go build -o sp ./cmd/sp
```

### 修改前端后重新构建

```bash
cd web
npm install
npm run build        # 产物输出到 ../internal/app/static，随 go:embed 打包
cd ..
go build -o sp ./cmd/sp
```

### 首次启动

```bash
./sp serve --listen 127.0.0.1:9090
```

首次启动会：

1. 在 `<data-dir>` 内生成种子托管配置与演示数据；
2. 生成网页访问密钥并**仅打印一次**（以 Argon2id 哈希持久化）。

打开 <http://127.0.0.1:9090>，输入该密钥登录。

- 忘记密钥：设置环境变量 `SP_SECRET=你的新密钥` 或 `--secret` 覆盖；也可用 `--reset-secret` 重新生成并打印。
- 默认仅监听回环地址；远程访问请自行配置 HTTPS 与反向代理。

## 部署

### macOS

```bash
# 1. 安装依赖（构建用）
brew install go

# 2. 构建
cd ServerProxy
go build -o sp ./cmd/sp

# 3. 启动（使用真实内核；内核未安装时先在面板“设置 → 内核部署”下载）
./sp serve --listen 127.0.0.1:9090 --core singbox

# 4. 开启 TUN（需要 root，创建 utun 并修改路由表）
sudo ./sp serve --listen 127.0.0.1:9090 --core singbox
```

> TUN 开启后由面板接管系统全部流量，无需再设置系统代理/SwitchyOmega；关闭 TUN 时请清除系统代理，仅将浏览器代理指向面板混合入站端口（默认 7897）。

### Linux（systemd）

```bash
# 1. 构建并安装二进制
cd ServerProxy
go build -o sp ./cmd/sp
sudo cp sp /usr/local/bin/sp

# 2. 生成 systemd 单元（自动下载 sing-box 内核到 <data-dir>/bin/）
sudo /usr/local/bin/sp install-service --data-dir /var/lib/serverproxy \
  | sudo tee /etc/systemd/system/serverproxy.service

# 可选参数：--skip-kernel 跳过内核下载；--version 指定内核版本；--platform 指定平台

# 3. 启用并启动
sudo systemctl daemon-reload
sudo systemctl enable --now serverproxy
systemctl status serverproxy
```

- TUN 需要：内核加载 tun 模块（`ls /dev/net/tun`），并以 root 运行（unit 默认即 root）。
- 面板默认监听 `127.0.0.1:9090`；日志：`journalctl -u serverproxy -f`。

### Docker

镜像多阶段构建：内置 sing-box 内核 + 编译后的控制面，前端产物随 `go:embed` 打进二进制（无需 Node）。

```bash
# 方式一：docker compose（推荐）
cd packaging/docker
docker compose up -d --build

# 方式二：直接用 Docker 命令
docker build -t serverproxy -f packaging/docker/Dockerfile .
docker run -d --name serverproxy \
  -p 9090:9090 \
  -v serverproxy-data:/var/lib/serverproxy \
  serverproxy
```

- 首次启动生成的登录密钥打印在容器日志：`docker logs serverproxy`；也可用 `-e SP_SECRET=你的密钥` 固定密钥。
- 数据保存在卷 `serverproxy-data`（compose 方式为 `packaging/docker/data/` 目录），升级镜像不丢配置。
- 镜像入口即 `sp`，可运行其他子命令：`docker run --rm serverproxy version`。
- **TUN**：容器内使用 TUN 需添加 `--cap-add NET_ADMIN`、挂载 `/dev/net/tun`（compose 文件里已给出注释配置），并建议配合 `network_mode: host`。
- 内核版本更新：面板「设置 → 内核部署」可随时重新下载到数据目录，覆盖镜像内置版本。

### Windows

```powershell
# 1. 安装 Go 1.27+（choco install golang 或官网安装包）

# 2. 构建
cd ServerProxy
go build -o sp.exe ./cmd/sp

# 3. 启动
.\sp.exe serve --listen 127.0.0.1:9090 --core singbox
```

- 内核下载：面板「设置 → 内核部署」会自动下载到 `<data-dir>\bin\sing-box.exe`；也可手动放置。
- TUN 需要以**管理员身份**运行终端（右键 → 以管理员身份运行），并确保内核支持 gVisor 栈。
- 建议显式指定数据目录：`.\sp.exe serve --core singbox --data-dir %USERPROFILE%\.serverproxy`。

## 命令行参考

### serve 参数

| 参数 | 环境变量 | 说明 |
| --- | --- | --- |
| `--listen` | - | HTTP 监听地址（默认 `127.0.0.1:9090`） |
| `--secret` | `SP_SECRET` | 网页访问密钥（覆盖已保存的密钥） |
| `--data-dir` | `SP_DATA_DIR` | 运行时数据目录（默认 `./.serverproxy`） |
| `--core` | `SP_CORE` | 内核适配器：`dev`（模拟）或 `singbox`（真实内核） |
| `--sing-box-bin` | `SP_SINGBOX_BIN` | sing-box 二进制路径（默认自动探测 `<data-dir>/bin/` 或 `PATH`） |
| `--controller` | `SP_SINGBOX_CONTROLLER` | Clash API 监听地址（默认自动分配随机端口并持久化） |
| `--core-secret` | `SP_SINGBOX_SECRET` | Clash API 密钥（默认自动生成并持久化） |
| `--external-core` | `SP_EXTERNAL_CORE=1` | 内核由外部管理（如 systemd），面板不拉起子进程 |
| `--core-pid` | `SP_SINGBOX_PID` | 外部内核模式的 PID 文件路径 |
| `--reset-secret` | - | 强制重新生成网页密钥并打印一次 |

### 其他子命令

| 命令 | 说明 |
| --- | --- |
| `sp status` | 查看面板/内核状态（需 `--secret` 或 `SP_SECRET`） |
| `sp switch rule\|global\|direct --secret <s>` | 切换代理模式 |
| `sp update --secret <s>` | 立即更新全部订阅 |
| `sp reload --secret <s>` | 请求内核重载配置 |
| `sp log` | 输出最近日志 |
| `sp check <config.json>` | 校验配置文件 |
| `sp install-service --data-dir <dir>` | 生成 systemd 单元并下载内核 |
| `sp install-kernel --data-dir <dir>` | 仅下载 sing-box 内核 |
| `sp version` | 显示版本 |

## 数据目录

```
.serverproxy/
├── bin/sing-box          下载的内核
├── settings.json         面板设置（含密钥哈希、代理模式、TUN 开关）
├── subscriptions.json    订阅定义
├── nodes/                解析出的节点
├── rules/                下载的规则集（.srs）
├── revisions/            不可变配置修订（可回滚）
├── runtime/config.json   当前生效的内核配置
├── snapshots/            订阅抓取快照（最近 5 份）
├── audit.log             审计事件（JSONL）
└── secrets/master.key    数据加密主密钥
```

## 常见问题

- **订阅更新报 502**：部分机场按 User-Agent 白名单分发内容，面板会自动以 Clash/Mihomo 系 UA 降级重试；若仍失败说明订阅源侧故障，旧节点会保留不受影响。
- **全局/直连/规则模式不生效**：切换模式会重编译配置并重启内核子进程（sing-box 的 SIGHUP 不重载主配置）；「当前出口」在直连模式下显示「直连」，全局/规则模式显示实际节点。
- **TUN 报 `operation not permitted`**：需要以 root（sudo）/管理员权限运行面板。
- **内核启动失败 `bad tun name` / `detour to an empty direct outbound`**：sing-box 1.13+ 的约束，面板已自动规避（不写接口名、DNS 不写 detour）。