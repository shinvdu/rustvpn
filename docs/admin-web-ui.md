# 管理端 Web UI

> 状态：已按“独立管理进程”实现于分支 `feature/admin-web-ui`
> 设计调研与取舍见 [`admin-web-ui-plan.md`](admin-web-ui-plan.md)（0.2 节为目标架构）

管理端由两个**独立程序**组成，只共享底层库：

```text
Browser ──TLS──▶ Caddy/Nginx ──▶ rustvpn-admind
                                  ├─ HTTP API + 静态 UI
                                  ├─ Argon2id 登录 / CSRF / 角色
                                  ├─ SQLite 历史 / 审计
                                  └─ 配置校验 / 备份 / 写 peers.yaml
                                           │
                                           │ /run/rustvpn/control.sock
                                           │ 长度前缀 JSON + peer 凭据
                                  rustvpn-server
                                  ├─ UDP/TCP/TAP 数据面
                                  └─ status/sessions/kick/reload/subscribe
```

- `rustvpn-server` 不链接 axum/SQLite/静态资源，不因管理端故障而退出。
- `rustvpn-admind` 以独立用户运行，**不需要 `CAP_NET_ADMIN`**；只通过控制 socket 踢线/触发热重载，通过文件读写配置。
- 未启用 `-control` 时，server 与之前完全一致；admind 仍可启动，但处于“服务端离线：只读查看配置/备份/历史，不能应用配置”模式。

## 功能

- **客户端列表**：配置中的全部客户端（启用/禁用）+ 当前在线会话，显示名称、id、地址、UDP/TCP、模式、MTU、速率、本月用量、累计流量、最后活跃。
- **流量统计**：每 10 秒采样；1h/24h/7d/30d 折线图；会话历史；按身份的终身累计与月度用量；原始线路字节与 TAP 载荷字节分别展示。
- **客户端管理**：新增（自动生成口令或导入长格式 verifier）、编辑、禁用/启用、删除、轮换口令、立即断开（控制命令，无需等 60 秒）。
- **运维**：服务状态、最近事件、配置 YAML 预览/应用/备份/恢复、审计日志、Prometheus `/metrics`、健康检查、SSE 实时刷新。
- **认证**：Argon2id 管理员口令、内存会话 Cookie、CSRF、登录限速、`admin`/`viewer` 角色。

## 构建

```bash
# 数据面（不含管理端依赖）
cargo build --release -p rustvpn-server

# 管理端守护进程 + 初始化工具
cargo build --release -p rustvpn-admin --bins
# 产出：rustvpn-admind、rustvpn-admin-passwd

# 静态 musl（server 与 admind 均可单独构建）
cargo build --release --target x86_64-unknown-linux-musl -p rustvpn-server
cargo build --release --target x86_64-unknown-linux-musl -p rustvpn-admin --bins
```

默认 `cargo build` 仍只包含原有 CLI/server 等默认成员；管理端依赖（axum、hyper、rust-embed、rusqlite bundled）只进入 `rustvpn-admind`。

## 初始化管理员

管理端不会开放“首次访问设置口令”的窗口；数据库中没有管理员时 `rustvpn-admind` 拒绝启动，数据面 VPN 不受影响。

```bash
# 目录属于管理端用户
sudo install -d -m 0750 -o rustvpn-admin -g rustvpn-adm /var/lib/rustvpn
sudo rustvpn-admin-passwd -db /var/lib/rustvpn/admin.db -user admin
# 交互式输入口令两次；非交互可用 -password-file PATH（文件仅含口令，用后删除）
```

数据库首次创建时权限为 `0600`，包含口令哈希与审计信息，请按凭据保护。

## 启动

```bash
# 1) 数据面：启用控制 socket
sudo rustvpn-server -proto all -bind 0.0.0.0:1194 \
    -conf /etc/rustvpn/peers.yaml \
    -stats 127.0.0.1:1294 \
    -control /run/rustvpn/control.sock \
    -control-group rustvpn-adm \
    -script-dir /etc/rustvpn/scripts

# 2) 管理端：独立进程、无 capability
sudo rustvpn-admind -listen 127.0.0.1:8080 \
    -control /run/rustvpn/control.sock \
    -db /var/lib/rustvpn/admin.db \
    -conf /etc/rustvpn/peers.yaml \
    -disabled-conf /etc/rustvpn/peers.disabled.yaml \
    -backup-dir /var/lib/rustvpn/backups
```

`rustvpn-server` 新增参数：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-control PATH` | 空（禁用） | 本地控制 socket；启用后管理端才能读取实时会话/踢线/立即重载 |
| `-control-group GROUP` | 空 | socket 属组（组名或数字 gid）；设置后模式为 `0660`，否则 `0600` |
| `-script-dir PATH` | 空（不限制） | 可重复；**server 侧**强制 up/down 路径白名单。启用 `-control` 时**至少需要一个**，否则 server 拒绝启动 |

`rustvpn-admind` 参数：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-listen ADDR` | `127.0.0.1:8080` | HTTP 监听；建议只绑回环 |
| `-control PATH` | `/run/rustvpn/control.sock` | server 控制 socket |
| `-db PATH` | `/var/lib/rustvpn/admin.db` | 账号、历史、审计 |
| `-conf PATH` | `/etc/rustvpn/peers.yaml` | 启用配置 |
| `-disabled-conf PATH` | `-conf` 同目录的 `peers.disabled.yaml` | 禁用配置 |
| `-backup-dir PATH` | `-db` 同目录的 `backups/` | 配置备份 |
| `-cookie-secure` | 关 | 设置 `Secure` 与 `__Host-` Cookie；经 TLS 反代时启用 |
| `-script-dir PATH` | 空 | 可重复；用于 UI 侧前缀校验；最终以 server 的 `validate_config` 预检为准 |

旧的 `-admin*` 参数已移除；内嵌模式不再提供。

## systemd 与权限

仓库已提供模板：[`packaging/systemd/rustvpn-server.service`](../packaging/systemd/rustvpn-server.service)、[`packaging/systemd/rustvpn-admind.service`](../packaging/systemd/rustvpn-admind.service) 与 [`packaging/README.md`](../packaging/README.md)。下面是等价说明：

推荐两个系统用户 + 一个共享组：

| 对象 | 用户/组 | 权限 |
|---|---|---|
| `rustvpn-server` | `rustvpn`，组 `rustvpn-adm` | `CAP_NET_ADMIN`/`CAP_NET_RAW`；只读配置 |
| `rustvpn-admind` | `rustvpn-admin`，**主组** `rustvpn-adm` | **无 capability**；读写配置目录与自己的数据库 |
| 控制 socket | `rustvpn:rustvpn-adm` `0660` | 仅 admind 可连接 |
| 配置目录 | `root:rustvpn-adm` `2770` | server 读；admind 原子 rename 写 |
| 脚本目录 | `root:root` `0755`，文件 root 所有 | 管理组不可写；server 按 `-script-dir` 校验 |

```ini
# /etc/systemd/system/rustvpn-server.service
[Unit]
Description=RustVPN server
After=network-online.target
Wants=network-online.target

[Service]
User=rustvpn
Group=rustvpn-adm
SupplementaryGroups=rustvpn
RuntimeDirectory=rustvpn
RuntimeDirectoryMode=0750
ExecStart=/usr/local/bin/rustvpn-server -proto all -bind 0.0.0.0:1194 \
    -conf /etc/rustvpn/peers.yaml -stats 127.0.0.1:1294 \
    -control /run/rustvpn/control.sock -control-group rustvpn-adm \
    -script-dir /etc/rustvpn/scripts
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=full
PrivateTmp=yes

# /etc/systemd/system/rustvpn-admind.service
[Unit]
Description=RustVPN admin daemon
After=rustvpn-server.service
Wants=rustvpn-server.service

[Service]
User=rustvpn-admin
Group=rustvpn-adm
ExecStart=/usr/local/bin/rustvpn-admind -listen 127.0.0.1:8080 \
    -control /run/rustvpn/control.sock \
    -db /var/lib/rustvpn/admin.db \
    -conf /etc/rustvpn/peers.yaml \
    -disabled-conf /etc/rustvpn/peers.disabled.yaml \
    -backup-dir /var/lib/rustvpn/backups
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/etc/rustvpn /var/lib/rustvpn
PrivateTmp=yes
```

目录：

```bash
sudo groupadd --system rustvpn-adm
sudo useradd --system --no-create-home --shell /usr/sbin/nologin -G rustvpn-adm rustvpn-admin
sudo chgrp rustvpn-adm /etc/rustvpn
sudo chmod 2770 /etc/rustvpn          # 原子 rename 需要目录写权限
sudo chmod 0640 /etc/rustvpn/peers.yaml /etc/rustvpn/peers.disabled.yaml
sudo install -d -m 0755 -o root -g root /etc/rustvpn/scripts
sudo install -d -m 0750 -o rustvpn-admin -g rustvpn-adm \
    /var/lib/rustvpn /var/lib/rustvpn/backups
```

脚本必须是 root 或 server 用户所有、且组/其他不可写，且文件必须已存在；**脚本路径上的每一级目录**也必须满足同样的属主/权限要求。管理端用户不能写脚本目录。启用 `-control` 而未提供 `-script-dir` 时 server 拒绝启动。违反时 server 拒绝加载配置并保留上一份有效配置；每次执行 up/down 前还会重新校验，防止配置加载后脚本被替换。恢复备份同样要满足该白名单；若备份中的脚本已不在白名单，server 不会加载，需要先修正配置。

## 暴露方式

默认 `127.0.0.1:8080`，通过 SSH 隧道或同机反向代理访问。控制 socket **不出本机**。

Caddy：

```caddyfile
vpn-admin.example.com {
    encode gzip
    reverse_proxy 127.0.0.1:8080
}
```

使用 TLS 反代时加 `-cookie-secure`，并限制来源 IP / VPN 网段。不要在公网直接监听管理端口。

## 安全说明

- 登录口令使用 Argon2id（m=65536, t=3, p=1），会话 Cookie 为 HttpOnly + SameSite=Strict；所有写操作要求 CSRF token。
- `rustvpn-admind` 没有 `CAP_NET_ADMIN`，不能直接操作 TAP/路由；踢线和重载通过受控命令完成。
- 控制 socket 只允许 admind 用户/组；server 额外用 `SO_PEERCRED` 校验（root 或 socket 属组）。不监听 TCP。
- 管理端**不允许**编辑/上传 up/down 脚本内容，只能填写路径；server 侧 `-script-dir` + 所有权/权限校验是最终防线。
- 配置写入：渲染 → 用 server 同一套 `ConfigSet` 校验 → 调用 server `validate_config` 做脚本/路径预检 → 备份 → 同目录临时文件 → fsync → rename → 调用 `reload`。任何一步失败都不会写盘；server 离线时预检失败，因此不会写盘。
- 配置写入使用 ETag 乐观锁；若期间有人手工改了文件，接口返回 409。
- YAML 注释会在管理端写入时丢失；手工注释请放在独立文档或备注字段中。
- `/metrics` 与 `/healthz` 不鉴权；它们只在管理端监听地址上暴露，默认回环。
- 轮换口令保持身份 id 不变（只更换派生公钥），历史流量仍归到同一客户端；旧会话在配置重载时被吊销。

## 使用要点

1. 登录后“总览”显示在线数、实时速率、今日载荷流量、配置状态和最近事件；server 离线时有明确标识。
2. “客户端”页可搜索/筛选、新增、禁用/启用、轮换、断开；“详情”页有 1h/24h/7d/30d 流量图与会话历史。
3. 新增客户端后，**口令与短 verifier 只显示一次**；请立即复制。服务器不保存口令，只能轮换。
4. “系统设置”可直接编辑两个 YAML、预览 diff/吊销列表、应用、查看/恢复备份。
5. viewer 只能读取；写操作需要 `admin` 角色。

## 数据与统计口径

| 数据 | 位置/归属 |
|---|---|
| 启用配置（真源） | `/etc/rustvpn/peers.yaml` |
| 禁用配置 | `/etc/rustvpn/peers.disabled.yaml`（server 不读取） |
| 账号/历史/审计 | `/var/lib/rustvpn/admin.db`（WAL，admind 独占） |
| 配置备份 | `/var/lib/rustvpn/backups/`（默认保留全部，需手工清理） |
| 控制 socket | `/run/rustvpn/control.sock`（本地） |

- 采样周期 10 秒：admind 通过控制面拉取活动会话，并订阅 `session_started`/`session_ended`（含最终计数）。
- admind 单独重启不会结束在线会话：重连后按 server 的活动会话与最近结束事件对账，只把 server 已不认识的开放记录标记为 `server_restart`。
- server 保留最近 1024 条结束事件用于重连对账；admind 停机超过该窗口会丢失这段历史，但活动会话恢复后会重新开始记录。
- 每个 server 启动生成随机 52 位 `server_instance` 并作为进程内会话号的基数，避免重启后与历史行撞号；`/api/system/status` 会返回该值。
- `BytesIn/Out` 是线路字节（含心跳、noise/CPR 填充、encless 膨胀）；`BytesPayloadIn/Out` 是 TAP 载荷。计费时请明确口径。
- 建议只运行一个 admind 实例；SQLite WAL 允许并发读，但两个实例会重复采样/互相覆盖事件状态。
- 会话 id 以每次 server 启动的 52 位随机基数为起点，保证 SQLite 正数主键，并避免前端/外部消费者按 JS Number 使用时丢失精度。

## API 摘要

所有 `/api/*`（除 `/api/login`）需要 Cookie；写操作需要 `X-CSRF-Token`。协议形状与之前一致。

```text
POST /api/login                      登录
GET  /api/me                         当前用户 + CSRF
POST /api/logout
GET  /api/peers                      列表 + summary
POST /api/peers                      新增（一次性凭据）
GET  /api/peers/{id}
PATCH /api/peers/{id}
DELETE /api/peers/{id}?purge_history=
POST /api/peers/{id}/disable|enable|rotate|kick
GET  /api/peers/{id}/traffic?range=1h|24h|7d|30d
GET  /api/peers/{id}/sessions
GET  /api/sessions
GET  /api/system/status|events|config|backups
POST /api/system/config/preview
PUT  /api/system/config
POST /api/system/backups/restore
GET  /api/audit
GET  /api/events                     SSE tick
GET  /metrics                        Prometheus text
GET  /healthz /readyz
```

`id` 为 16 字节 verifier id 的 32 位 hex。`/api/system/status` 额外返回 `server_online` 与 `server_instance`。

## 已知限制

- 控制面是本地 Unix socket；不支持跨机管理 server（远程浏览器仍可经反代访问 admind，但控制通道必须在本机）。
- **server 离线时不能应用/恢复配置**：admind 需要先调用 server 的 `validate_config` 预检；离线时仍可查看配置、预览 diff、查看备份/历史/审计。这是为了避免留下 server 下次启动会拒绝的配置。
- admind 停机期间没有采样；server 环形缓冲之外的结束事件会丢失。
- 配额只展示，不自动禁用/限速；带宽整形未实现。
- TOTP 未实现；角色只区分 admin/viewer。
- 管理端写入会规范化 YAML（字段顺序、空值、注释）。
- 静态页无构建步骤，使用原生 JS + Canvas；未做深色/浅色之外的视觉定制。

## 故障排查

| 现象 | 处理 |
|---|---|
| `admin endpoint ... no admin user` | 先运行 `rustvpn-admin-passwd` |
| 页面显示“服务端离线”/`control unavailable` | server 未运行、未加 `-control`，或路径不一致 |
| 连接 socket 报 `Permission denied` | admind 的主组必须是 socket 属组；检查 socket `0660` 与目录权限 |
| 应用配置报 `server config preflight failed` | server 离线或控制面不可达；配置未写盘，恢复 server 后重试 |
| 应用配置返回 `applied:false` + warning | 预检通过并已写盘，但提交后 server 掉线；server 恢复后 60 秒内加载 |
| server 启动报 `-control requires at least one -script-dir` | 启用管理端时必须配置脚本白名单 |
| server 启动报 `script directory ... writable by group or others` | 脚本目录/路径上的某一级可被管理组写入；改成 root/server 所有且 `0755` |
| server 拒绝配置：`script ... outside ...` | 调整 `-script-dir` 或脚本位置；脚本须 root/server 所有且不可组写 |
| 应用配置返回 409 | 文件在编辑期间被外部修改；重新加载后重试 |
| 流量图为空 | 尚无 10 秒采样或该会话无载荷；保持会话运行一段时间 |
| 事件出现 `control_lagged` | admind 曾落后，已自动对账；若频繁出现请检查控制面延迟 |

## 回滚

- 关闭管理端：停止 `rustvpn-admind`，server 数据面继续运行。
- 完全移除控制面：server 去掉 `-control` 即可，行为与旧版一致。
- 配置回滚：管理端“备份”页恢复，或手工 `cp` 备份到 `peers.yaml` 后等待 60 秒热重载。
- 数据库损坏：停止 admind，删除/移走 `admin.db*`，重新运行 `rustvpn-admin-passwd`；历史流量与审计会丢失，`peers.yaml` 不受影响。