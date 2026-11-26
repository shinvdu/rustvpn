# 运维与部署

[English](../en/operations.md) | **中文** | [Русский](../ru/operations.md)

本页展示一种生产风格的 Linux 部署，使用 systemd、专用的非特权用户以及 Linux capabilities。同一套布局也适用于 RustVPN↔GoVPN 混合部署；只是可执行文件不同。

## 部署模型

以非 root 服务用户运行两个守护进程，只授予它们所需的 capabilities：

- `CAP_NET_ADMIN` —— 创建/配置 TAP 接口并运行 `ip`。
- `CAP_NET_RAW` —— TAP/io_uring 路径所需。

`NoNewPrivileges=yes` 和最小的 capability 边界集可防止进程获取更多权限。若你的发行版无法授予 ambient capabilities，用 `setcap` 对可执行文件加权限的小型包装脚本是替代方案，但专用用户加 `AmbientCapabilities` 更简单且更易于审计。

## 文件

```text
/usr/local/bin/rustvpn-server                 0755 root:root
/usr/local/bin/rustvpn-client                 0755 root:root
/etc/rustvpn/                               0750 root:rustvpn
/etc/rustvpn/peers.yaml                     0640 root:rustvpn
/etc/rustvpn/pass                           0640 root:rustvpn   # client only
/etc/rustvpn/client.env                     0640 root:rustvpn   # client only
/etc/rustvpn/up.sh                          0750 root:rustvpn
/etc/rustvpn/down.sh                        0750 root:rustvpn
/etc/systemd/system/rustvpn-server.service    0644 root:root
/etc/systemd/system/rustvpn-client.service    0644 root:root
```

一次性创建用户：

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin rustvpn
sudo install -d -m 0750 -o root -g rustvpn /etc/rustvpn
```

## 服务器配置

`peers.yaml`（验证器为**长格式**）：

```yaml
alice:
  iface: rsvpn0
  mtu: 1515
  timeout: 60
  noise: false
  encless: false
  verifier: '$argon2d$m=4096,t=128,p=1$BASE64_ID$BASE64_PUBLIC_KEY'
  up: /etc/rustvpn/up.sh
  down: /etc/rustvpn/down.sh
```

`up.sh` —— 注意它在守护进程打开 TAP **之前**运行，因此必须创建持久化设备：

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-rsvpn0}"
ip tuntap add dev "$IFACE" mode tap 2>/dev/null || true
ip link set dev "$IFACE" mtu 1515 up
ip addr replace 10.88.0.1/24 dev "$IFACE"
```

`down.sh`：

```sh
#!/bin/sh
IFACE="${GOVPN_IFACE:-rsvpn0}"
ip addr del 10.88.0.1/24 dev "$IFACE" 2>/dev/null || true
ip link set dev "$IFACE" down 2>/dev/null || true
```

## 客户端配置

口令和短格式验证器只应保存在客户端。

`/etc/rustvpn/pass` 包含口令，且不能有行尾换行问题；守护进程会去除单个行尾 `\n`。

`/etc/rustvpn/client.env`：

```sh
RUSTVPN_VERIFIER='$argon2d$m=4096,t=128,p=1$BASE64_ID'
```

`EnvironmentFile` 可避免 systemd 展开验证器中的 `$...`。

`up.sh`（在会话建立后运行）：

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-rsvpn0}"
ip tuntap add dev "$IFACE" mode tap 2>/dev/null || true
ip link set dev "$IFACE" mtu 1515 up
ip addr replace 10.88.0.2/24 dev "$IFACE"
ip route replace 10.88.0.0/24 dev "$IFACE"
```

`down.sh` 会删除路由和地址，并关闭链路。

## systemd 单元

`/etc/systemd/system/rustvpn-server.service`：

```ini
[Unit]
Description=RustVPN server (GoVPN 5.7 compatible)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rustvpn
Group=rustvpn
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=/usr/local/bin/rustvpn-server -proto udp -bind 0.0.0.0:1194 \
    -conf /etc/rustvpn/peers.yaml -stats 127.0.0.1:1294
Restart=on-failure
RestartSec=2
LimitNOFILE=65536
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ReadWritePaths=/run

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/rustvpn-client.service`：

```ini
[Unit]
Description=RustVPN client (GoVPN 5.7 compatible)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rustvpn
Group=rustvpn
EnvironmentFile=/etc/rustvpn/client.env
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=/usr/local/bin/rustvpn-client -remote 203.0.113.10:1194 \
    -proto udp -iface rsvpn0 -mtu 1515 -timeout 60 \
    -verifier "${RUSTVPN_VERIFIER}" -key /etc/rustvpn/pass \
    -up /etc/rustvpn/up.sh -down /etc/rustvpn/down.sh
Restart=always
RestartSec=5
LimitNOFILE=65536
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ReadWritePaths=/run

[Install]
WantedBy=multi-user.target
```

启用并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rustvpn-server
sudo systemctl enable --now rustvpn-client
```

## 监控

统计端点是一个极简 HTTP 服务器；在本地查询它：

```bash
curl -s http://127.0.0.1:1294/ | jq .
```

有用的检查：

- `FramesIn` / `FramesOut` 在有流量时增长。
- `FramesUnauth` 应保持为 0；若持续增长，说明存在 MAC 或握手校验失败的数据包（密钥错误、模式错误或遭受攻击）。
- `FramesDup` 应接近 0；增长意味着重放或重复投递。
- `Established` 对应最近一次成功的握手。
- `HeartbeatSent` / `HeartbeatRecv` 显示空闲链路的存活状态。

常用命令：

```bash
# client
systemctl status rustvpn-client
journalctl -u rustvpn-client -f
sudo systemctl restart rustvpn-client
ping 10.88.0.1

# server
ssh root@server systemctl status rustvpn-server
ssh root@server journalctl -u rustvpn-server -f
ssh root@server 'curl -s 127.0.0.1:1294/ | jq .'
```

## 管理端 Web UI（可选）

管理端是独立进程 `rustvpn-admind`，通过本地控制 socket 控制 `rustvpn-server`；不启用时 server 与 GoVPN 部署完全一致：

```bash
cargo build --release -p rustvpn-server
cargo build --release -p rustvpn-admin --bins
sudo rustvpn-admin-passwd -db /var/lib/rustvpn/admin.db -user admin
```

启动时给 server 增加控制 socket：

```bash
-control /run/rustvpn/control.sock -control-group rustvpn-adm \
-script-dir /etc/rustvpn/scripts
```

再启动管理端：

```bash
rustvpn-admind -listen 127.0.0.1:8080 -control /run/rustvpn/control.sock \
    -db /var/lib/rustvpn/admin.db -conf /etc/rustvpn/peers.yaml
```

要点：

- `rustvpn-admind` 不需要 `CAP_NET_ADMIN`，以独立用户运行；踢线/立即重载经控制命令完成。
- 启用控制 socket 时必须提供至少一个 `-script-dir`；脚本目录及路径上的各级目录需 root/server 所有且组/其他不可写。配置应用前会由 server 预检，server 离线时只读。
- 默认只绑回环；远程访问用 SSH 隧道或 TLS 反代，并在启用了 TLS 时加 `-cookie-secure`。
- 管理端要写 `peers.yaml`/备份，unit 需允许 `ReadWritePaths=/etc/rustvpn /var/lib/rustvpn`，目录组可写；脚本目录必须 root 所有且管理组不可写（见[管理端文档](../admin-web-ui.md)）。
- 管理端可禁用/轮换/踢下线，但**不能编辑 `up`/`down` 脚本内容**；server 侧 `-script-dir` 是最终校验。
- 详细用法、权限、API、统计口径与限制见 [`admin-web-ui.md`](../admin-web-ui.md)。

## 桌面客户端 UI（可选）

Linux 上可以使用 Tauri 桌面客户端，与 `rustvpn-client` CLI 完全独立：

```bash
cargo build --release -p rustvpn-clientd -p rustvpn-client-gui
sudo install -m 0755 target/release/rustvpn-clientd /usr/local/bin/
sudo install -m 0755 target/release/rustvpn-client-ui /usr/local/bin/
```

要点：

- GUI 以普通用户运行；`rustvpn-clientd` 使用 `CAP_NET_ADMIN`/`CAP_NET_RAW` 和本地 Unix socket。
- GUI profile 必须有 IPv4 `address`；全隧道（`routes` 含 `default`）还必须同时提供 `gateway` 和 IPv4 `dns`。
- 首次握手成功后才安装路由/DNS，失败握手不会把主机默认路由指向未建立的隧道；全隧道会阻断 IPv6 默认路由以避免泄漏。
- daemon 与 CLI 共用 `/run/rustvpn-client/tunnel.lock`，同一时刻只允许一个活动隧道。
- GUI 支持托盘、关闭到托盘、单实例、登录自启动、系统钥匙串（Secret Service）和中/英/俄界面切换；托盘/自启动依赖用户桌面会话，daemon 仍需由 systemd 启动。
- `packaging/linux/build-packages.sh` 可构建 deb/rpm（CLI + daemon + GUI + unit + desktop）；deb 已在 Ubuntu 验证，rpm 需 `rpmbuild` 环境。
- daemon 的 `-hello-timeout`（默认 5s）和 `-idle-timeout`（默认 300s）限制 IPC 握手与请求空闲；事件订阅不中断。签名 Tauri updater 为可选构建特性，需要自备密钥/端点。
- GUI 用户需加入 `rustvpn` 组；systemd unit、安装和迁移步骤见[客户端文档](../client-ui.md)。

<a id="passphrase-rotation"></a>
## 口令轮换

轮换方式是生成新的验证器，并**使用同一次运行的两行输出**（它们共享身份/盐）：

```bash
openssl rand -hex 24 | tr -d '\n' | sudo tee /etc/rustvpn/pass.raw >/dev/null
sudo /usr/local/bin/rustvpn-verifier -key /etc/rustvpn/pass.raw > /tmp/rvver
# line 1: long form  -> server peers.yaml
# line 2: short form -> client client.env
sudo mv /etc/rustvpn/pass.raw /etc/rustvpn/pass
sudo systemctl restart rustvpn-client
ssh root@server systemctl restart rustvpn-server
```

请让两侧的重新启动尽量接近；客户端会自动重试。

## 升级与回滚

1. 构建静态可执行文件（参见[快速上手](getting-started.md)）。
2. 将其复制到 `/usr/local/bin/`，替换旧文件。
3. 对两侧执行 `systemctl restart`。配置格式与线协议在 Rust 构建之间、以及与 GoVPN 5.7 之间均保持不变。

回滚即用上一版可执行文件执行相同流程。请保留上一份已知良好版本的可执行文件与 `peers.yaml` 副本。

## 卸载

```bash
# client
sudo systemctl disable --now rustvpn-client
sudo rm -f /etc/systemd/system/rustvpn-client.service /usr/local/bin/rustvpn-client
sudo rm -rf /etc/rustvpn
sudo systemctl daemon-reload
# optional: sudo userdel rustvpn

# server
sudo systemctl disable --now rustvpn-server
sudo rm -f /etc/systemd/system/rustvpn-server.service /usr/local/bin/rustvpn-server
sudo rm -rf /etc/rustvpn
sudo systemctl daemon-reload
sudo ip link del rsvpn0 2>/dev/null || true
```

<a id="coexistence-with-an-existing-govpn"></a>
## 与现有 GoVPN 共存

RustVPN 使用自己的端口和网络，因此两者可以在一台主机上同时运行：

- 为 RustVPN 分配不同的 UDP/TCP 端口（例如 1194）、不同的 TAP 名称/前缀（`rsvpn0`）和子网（`10.88.0.0/24`）；
- 不要改动现有 GoVPN 服务、其 TAP 设备或其 NAT 规则；
- 若主机对入站流量做了防火墙限制，只开放新端口，并考虑将其限制为客户端的当前地址。

## 故障排查

| 现象 | 诊断 |
|---|---|
| 服务器上出现 `Cannot find device` | `up` 脚本未运行 `ip tuntap add ... mode tap`。 |
| 握手正常但 ping 失败 | TAP 缺少地址/路由，或 MTU 对该模式过大。 |
| `FramesUnauth` 增长 | 模式不匹配（noise/encless）、验证器/口令错误，或存在注入流量。 |
| `session failed: random number mismatch` | 通常是同时重启后旧/新会话重叠；让客户端重连即可。 |
| 客户端每隔 `timeout` 秒才重连 | 首个握手包不会被重传；客户端会等到超时。降低 `-timeout` 可加快恢复。 |
| 统计端点不可达 | 它绑定在 `-stats` 地址上；使用 `127.0.0.1` 并从同一主机或通过隧道查询。 |

下一步：[安全](security.md)。