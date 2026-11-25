# 管理端 Web UI

> 状态：MVP 已实现于分支 `feature/admin-web-ui`
> 设计调研与取舍见 [`admin-web-ui-plan.md`](admin-web-ui-plan.md)

管理端是一个**可选、feature 门控**的内嵌服务：管理端编译进 `rustvpn-server` 后，通过 `-admin` 启用；未启用时默认构建不包含 axum/SQLite 等依赖，现有 CLI 与线协议完全不变。

## 功能

- **客户端列表**：配置中的全部客户端（启用/禁用）+ 当前在线会话，显示名称、id、地址、UDP/TCP、模式、MTU、速率、本月用量、累计流量、最后活跃。
- **流量统计**：10 秒采样；1h/24h/7d/30d 折线图；会话历史；按身份的终身累计与月度用量；原始线路字节与 TAP 载荷字节分别展示。
- **客户端管理**：新增（自动生成口令或导入长格式 verifier）、编辑、禁用/启用、删除、轮换口令、立即断开。
- **运维**：服务状态、最近事件、配置 YAML 预览/应用/备份/恢复、审计日志、Prometheus `/metrics`、健康检查、SSE 实时刷新。
- **认证**：Argon2id 管理员口令、内存会话 Cookie、CSRF、登录限速、`admin`/`viewer` 角色。

## 构建

```bash
# 默认构建（与之前完全一致，不含管理端）
cargo build --release

# 管理端构建
cargo build --release -p rustvpn-server --features admin
cargo build --release -p rustvpn-admin --bin rustvpn-admin-passwd

# 静态 musl（已在本仓库验证 cargo check 通过）
cargo build --release --target x86_64-unknown-linux-musl \
    -p rustvpn-server --features admin
```

管理端会引入 axum、hyper、rust-embed、rusqlite（bundled）等依赖，二进制体积会增加若干 MB。

## 初始化管理员

管理端不会开放“首次访问设置口令”的窗口；数据库中没有管理员或数据库无法打开时，管理端**不会监听**并在日志中记录 `admin disabled: ...`，数据面 VPN 继续运行。

```bash
sudo install -d -m 0750 -o rustvpn -g rustvpn /var/lib/rustvpn
sudo rustvpn-admin-passwd -db /var/lib/rustvpn/admin.db -user admin
# 交互式输入口令两次；非交互可用 -password-file PATH（文件仅含口令，用后删除）
```

数据库首次创建时权限为 `0600`，包含口令哈希与审计信息，请按凭据保护。

## 启动

```bash
sudo rustvpn-server -proto all -bind 0.0.0.0:1194 \
    -conf /etc/rustvpn/peers.yaml \
    -stats 127.0.0.1:1294 \
    -admin 127.0.0.1:8080 \
    -admin-db /var/lib/rustvpn/admin.db
```

新增参数：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-admin ADDR` | 空（禁用） | 管理端监听地址；建议只绑 `127.0.0.1` |
| `-admin-db PATH` | `/var/lib/rustvpn/admin.db` | SQLite 数据库（账号、历史、审计） |
| `-admin-disabled-conf PATH` | 与 `peers.yaml` 同目录的 `peers.disabled.yaml` | 禁用客户端配置 |
| `-admin-cookie-secure` | 关 | 设置 `Secure` 与 `__Host-` Cookie；经 TLS 反代时启用 |
| `-admin-script-dir PATH` | 空（不限制） | 可重复；限制 up/down 脚本只能位于这些目录 |

备份目录默认为 `-admin-db` 所在目录下的 `backups/`。

## systemd 与权限

管理端需要写 `peers.yaml`、`peers.disabled.yaml` 和备份目录；现有 unit 的 `ProtectSystem=full` 会让 `/etc` 只读。推荐：

```ini
[Service]
User=rustvpn
Group=rustvpn
StateDirectory=rustvpn
StateDirectoryMode=0750
ProtectSystem=strict
ReadWritePaths=/etc/rustvpn /var/lib/rustvpn
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=/usr/local/bin/rustvpn-server -proto all -bind 0.0.0.0:1194 \
    -conf /etc/rustvpn/peers.yaml -stats 127.0.0.1:1294 \
    -admin 127.0.0.1:8080 -admin-db /var/lib/rustvpn/admin.db
```

目录：

```bash
sudo chgrp rustvpn /etc/rustvpn
sudo chmod 0770 /etc/rustvpn          # 原子 rename 需要目录写权限
sudo chmod 0640 /etc/rustvpn/peers.yaml /etc/rustvpn/peers.disabled.yaml
sudo install -d -m 0750 -o rustvpn -g rustvpn \
    /var/lib/rustvpn /var/lib/rustvpn/backups
```

如果你希望 `/etc` 完全只读，可把 `peers.yaml` 移到 `/var/lib/rustvpn/` 并用 `-conf` 指向它；此时 `/etc/rustvpn` 仅保留脚本文档。

## 暴露方式

默认为 `127.0.0.1:8080`，通过 SSH 隧道或同机反向代理访问。

Caddy：

```caddyfile
vpn-admin.example.com {
    encode gzip
    reverse_proxy 127.0.0.1:8080
}
```

使用 TLS 反代时加 `-admin-cookie-secure`，并限制来源 IP / VPN 网段。不要在公网直接监听管理端口。

## 安全说明

- 登录口令使用 Argon2id（m=65536, t=3, p=1），会话 Cookie 为 HttpOnly + SameSite=Strict；所有写操作要求 CSRF token。
- 管理端**不允许**编辑/上传 up/down 脚本内容，只能填写路径；可用 `-admin-script-dir` 限制路径前缀。脚本以服务权限执行，绝不能成为任意命令入口。
- 管理端修改配置时：先渲染 + 用服务端同一套 `ConfigSet` 校验 → 备份 → 同目录临时文件 → fsync → rename → 立即热重载。校验失败不会写盘。
- 配置写入使用 ETag 乐观锁；若期间有人手工改了文件，接口返回 409，不会静默覆盖。
- YAML 注释会在管理端写入时丢失；手工注释请放在独立文档或备注字段中。
- `/metrics` 与 `/healthz` 不鉴权；它们只在管理端监听地址上暴露，默认回环。若把管理端绑到非回环地址，请用防火墙限制。
- 轮换口令保持身份 id 不变（只更换派生公钥），因此历史流量仍归到同一客户端；旧会话会在配置重载时被吊销。

## 使用要点

1. 登录后“总览”显示在线数、实时速率、今日载荷流量、配置状态和最近事件。
2. “客户端”页可搜索/筛选、新增、禁用/启用、轮换、断开；“详情”页有 1h/24h/7d/30d 流量图与会话历史。
3. 新增客户端后，**口令与短 verifier 只显示一次**；请立即复制。服务器不保存口令，只能轮换。
4. “系统设置”可直接编辑两个 YAML、预览 diff/吊销列表、应用、查看/恢复备份。
5. 管理员或 viewer 角色：viewer 只能读取；写操作需要 `admin`。

## 数据与统计口径

| 数据 | 位置 |
|---|---|
| 启用配置（真源） | `/etc/rustvpn/peers.yaml` |
| 禁用配置 | `/etc/rustvpn/peers.disabled.yaml`（server 不读取） |
| 账号/历史/审计 | `/var/lib/rustvpn/admin.db`（WAL） |
| 配置备份 | `/var/lib/rustvpn/backups/`（默认保留全部，需手工清理） |

- 采样周期 10 秒；`sample_1m` 保留 7 天，`sample_1h` 保留 90 天；会话记录长期保留。
- 速率来自相邻采样差值；会话结束后由钩子写入最终计数。进程崩溃最多丢失最后一个 10 秒窗口。
- `BytesIn/Out` 是线路字节（含心跳、noise/CPR 填充、encless 膨胀）；`BytesPayloadIn/Out` 是 TAP 载荷。计费时请明确口径。
- 一个身份同时只有一个活跃会话；重连会替换旧会话。
- 协议不携带客户端主机名/操作系统，也不记录访问目的地；UI 只能看到服务端视角的地址与流量。

## API 摘要

所有 `/api/*`（除 `/api/login`）需要 Cookie；写操作需要 `X-CSRF-Token`。

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

`id` 为 16 字节 verifier id 的 32 位 hex。

## 已知限制

- 单实例；多台服务器没有中央看板。
- 配额只展示，不自动禁用/限速；带宽整形未实现。
- TOTP 未实现；角色只区分 admin/viewer。
- 管理端写入会规范化 YAML（字段顺序、空值、注释）。
- 管理端与数据面同进程；若需要把 HTTP 攻击面与 `CAP_NET_ADMIN` 隔离，可后续拆分独立 admin 守护进程（设计文档中的方案 C）。
- 管理端静态页无构建步骤，使用原生 JS + Canvas；未做深色/浅色之外的视觉定制。

## 故障排查

| 现象 | 处理 |
|---|---|
| 日志出现 `admin disabled: no admin user` | 先运行 `rustvpn-admin-passwd` |
| 启动报 `admin support is not compiled in` | 用 `--features admin` 重新构建 |
| 登录后立即 401 | 检查 Cookie 名（TLS 时应为 `__Host-rvpn_admin`）与 `-admin-cookie-secure` |
| 写配置 500/只读文件系统 | 检查 systemd `ReadWritePaths` 与 `/etc/rustvpn` 目录写权限 |
| 应用配置返回 409 | 文件在编辑期间被外部修改；重新加载后重试 |
| 客户端创建后连不上 | 检查 TAP 名称/up 脚本、MTU、noise/encless 是否与客户端一致 |
| 流量图为空 | 尚无 10 秒采样或该会话无载荷；先保持会话运行一段时间 |

## 回滚

- 关闭管理端：去掉 `-admin`，用普通构建的二进制即可。
- 配置回滚：管理端“备份”页恢复，或手工 `cp` 备份到 `peers.yaml` 后等待 60 秒热重载。
- 数据库损坏：停止服务，删除/移走 `admin.db*`，重新运行 `rustvpn-admin-passwd`；历史流量与审计会丢失，`peers.yaml` 不受影响。