# 客户端桌面 UI（Linux / Tauri 2）

> 状态：Linux MVP 已实现（分支 `feature/client-ui`）
> 调研与跨平台方案：[`client-ui-plan.md`](client-ui-plan.md)
> 更新：2026-11-26

## 架构

GUI 不持有特权，也不链接隧道/密码学代码。隧道由独立的 `rustvpn-clientd`
在最小权限下运行，GUI 通过本地 Unix socket 控制它。

```text
rustvpn-client-ui（Tauri 2 + 静态 HTML/JS）
        │  /run/rustvpn-client/client.sock
        │  4B BE 长度 + JSON，协议 v1，SO_PEERCRED
rustvpn-clientd（TAP、路由、DNS、重连）
        │
rustvpn-client-core（Profile、Engine、会话、Linux 网络配置）
        │
rustvpn-crypto / proto / net（现有数据面库）
```

| crate | 作用 | 默认构建 |
|---|---|---|
| `rustvpn-client-core` | Profile 校验、单会话、重连状态机、TAP/路由/DNS | 否 |
| `rustvpn-client-ipc` | IPC DTO、帧编解码、GUI 客户端 | 否 |
| `rustvpn-clientd` | 特权守护进程 | 否 |
| `rustvpn-client-gui` | Tauri 2 外壳（`rustvpn-client-ui`） | 否 |
| `rustvpn-client` | 原 CLI，保持独立，不依赖 daemon/GUI/IPC | **是** |

## 构建依赖（Ubuntu 24.04）

```bash
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev \
    libayatana-appindicator3-dev librsvg2-dev libxdo-dev libssl-dev \
    build-essential pkg-config
```

```bash
cargo build --release -p rustvpn-client         # CLI（默认构建）
cargo build --release -p rustvpn-clientd        # 守护进程
cargo build --release -p rustvpn-client-gui     # GUI（产物：rustvpn-client-ui）
```

Tauri 前端是仓库内的静态 `ui/`，不需要 Node/npm。

## 开发运行

```bash
# 1) 守护进程（需要 TAP/路由权限；开发时可直接用 root 或带 caps 运行）
sudo target/debug/rustvpn-clientd \
    -socket /run/rustvpn-client/client.sock \
    -socket-group "$(id -gn)"

# 2) GUI（普通用户）
RUSTVPN_CLIENTD_SOCKET=/run/rustvpn-client/client.sock \
    target/debug/rustvpn-client-ui
```

非 root 开发时可以不传 `-socket`，双方默认使用
`$XDG_RUNTIME_DIR/rustvpn/client.sock`（socket 模式 `0600`）。

## 配置

GUI 的 profile 保存在 `~/.config/rustvpn/profiles/*.yaml`，格式：

```yaml
name: office
remote: vpn.example.com:1194
proto: udp                 # udp | tcp；设置 proxy 时强制 tcp
verifier: $argon2d$m=4096,t=128,p=1$<id>
mtu: 1515
timeout: 60
timesync: 0
noise: false
encless: false             # 仅 TCP
cpr: 0
proxy: ""
proxy_auth: ""
iface: rsvpn-gui
address: 10.88.0.2/24      # GUI/daemon 必填
gateway: 10.88.0.1
dns: [10.88.0.1]
routes: [default]          # default 或 CIDR
ipv6: false                # 暂不支持
```

- 口令**不写入 YAML**；每次连接由 GUI 在内存中传给守护进程，派生密钥后即释放。
- profile 目录为 `0700`、文件为 `0600`；`proxy_auth` 属于凭据，不要共享这些文件。
- 守护进程会重新校验所有字段；地址/路由由内置 Linux 配置应用，不接受
  `up`/`down` 脚本。
- GUI/daemon 配置必须有 `address`；全隧道（`routes` 含 `default` 或
  `0.0.0.0/0`）还必须提供 `gateway` 和至少一个 IPv4 `dns`。
- **首次握手成功后才安装路由/DNS**：服务器不可达或口令错误时不会把主机默认
  路由指向未建立的隧道，避免“连不上还断网”。
- 默认路由以 metric 50 安装；安装前先为服务器/代理地址添加 `/32` 防环路由，
  断开时按相反顺序清理。远程地址只在需要时解析一次，重连复用。
- 全隧道连接期间会添加 `ip -6 route blackhole default metric 50`，阻断 IPv6
  默认路由以避免泄漏；断开时删除。IPv6 本身仍不支持隧道。
- DNS 通过 `resolvectl` 设置并 `domain ~.`；全隧道配置下缺少 `resolvectl` 会
  拒绝连接，而不是静默泄漏 DNS。非标准路径可用
  `RUSTVPN_RESOLVECTL_BIN=/path/to/resolvectl` 指定。

## systemd 与权限

仓库模板：[`packaging/systemd/rustvpn-clientd.service`](../packaging/systemd/rustvpn-clientd.service)。

```bash
sudo groupadd --system rustvpn
sudo useradd --system --no-create-home --shell /usr/sbin/nologin -g rustvpn rustvpn
sudo usermod -aG rustvpn "$USER"     # GUI 用户加入共享组；重新登录生效

sudo install -m 0755 target/release/rustvpn-clientd /usr/local/bin/
sudo install -m 0644 packaging/systemd/rustvpn-clientd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rustvpn-clientd
```

- 守护进程以 `rustvpn` 用户运行，仅保留 `CAP_NET_ADMIN`/`CAP_NET_RAW`。
- socket 为 `rustvpn:rustvpn 0660`；`SO_PEERCRED` 校验 uid，主/补充组包含
  `rustvpn` 的用户可连接。
- GUI 进程无 capability；即使 WebView 被攻破，也只能操作该本地控制接口。
- CLI 与 daemon 共用 `flock` 隧道锁：root 使用 `/run/rustvpn-client/tunnel.lock`；
  非 root 优先使用运行目录（`$XDG_RUNTIME_DIR/rustvpn` 或 `/run/rustvpn-client`）。
  锁被占用时 daemon 返回错误，UI 显示占用者；可用
  `RUSTVPN_TUNNEL_LOCK=/path` 覆盖。
- CLI 仍可独立运行；同一时刻只有一个活动隧道。若同时部署 `rustvpn-client`
  服务，请给它也加 `RuntimeDirectory=rustvpn-client`，保证锁目录在 daemon 之前存在。

## 功能

- 连接 / 断开、指数退避重连、取消。
- 状态、服务器、协议/模式、接口、时长。
- 下行/上行速率与线路字节、TAP 载荷字节、60 秒 Canvas 曲线。
- profile 新增/编辑/删除；口令每次输入。
- 守护进程日志（SSE/事件流 + 2000 行环形缓冲）。
- 守护进程离线时显示离线并自动重试订阅。

## 已知限制

- 仅 Linux；Windows/macOS 需要 L3 适配器 + 以太网垫片，尚未实现。
- IPv6 暂不支持；profile 中 `ipv6: true` 会被拒绝。全隧道会阻断 IPv6 默认
  路由；更具体的 IPv6 链路路由仍可能存在。分流（无 `default` 路由）不会阻断
  IPv6 或系统 DNS，使用前应确认不会泄漏。
- 全隧道必须配置 DNS；分流模式若 `dns` 为空，仍使用系统 DNS。
- 托盘、开机自启、keychain、Tauri updater 尚未接入。
- GUI 使用 `withGlobalTauri` 以便零构建调用命令；CSP 仍只允许本地资源，
  后续可换成打包的 `@tauri-apps/api` 并关闭全局注入。
- 无 TOTP/多用户隔离；本机同组用户共享同一隧道控制权。

## 测试

```bash
cargo test -p rustvpn-client-core -p rustvpn-client-ipc -p rustvpn-clientd -p rustvpn-client-gui
cargo clippy --workspace --all-targets -- -D warnings
```

端到端验证（本机 netns，未改动现网）：

1. 用 `rustvpn-verifier` 生成临时 verifier，本地 `rustvpn-server` 监听
   veth 地址；
2. 在 netns 中运行 `rustvpn-clientd`，profile 指向 `10.x` 服务器地址；
3. `ping` 服务器 TAP 地址，确认会话 `connected`、流量计数增长；
4. 断开后确认 TAP 删除、路由/DNS 清理。

> 实测：UDP plain、TAP L2、双向流量与最终计数通过；`routes: [default]` 的
> metric-50 默认路由、服务器 `/32` 防环路由、IPv6 blackhole、断开后的路由
> 恢复均通过；GUI 连接/断开/错误状态与事件订阅正常；以 systemd 瞬时单元
> （`User=rustvpn` + ambient `CAP_NET_ADMIN`/`CAP_NET_RAW`）运行时 TAP 创建与
> SIGTERM 清理正常；daemon/CLI 隧道锁单测通过。

## 回滚 / 卸载

```bash
sudo systemctl disable --now rustvpn-clientd
sudo rm /etc/systemd/system/rustvpn-clientd.service
sudo systemctl daemon-reload
```

GUI 与 profiles 都在用户目录，删除 `~/.config/rustvpn` 即可；CLI 与
`rustvpn-client.service` 不受影响。