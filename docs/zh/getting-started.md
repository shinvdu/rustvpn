# 快速上手

[English](../en/getting-started.md) | **中文** | [Русский](../ru/getting-started.md)

本页带你从代码检出走到一对可用的客户端/服务器。所有选项请参见[配置参考](configuration.md)。

## 环境要求

- Rust **1.85** 或更新版本（工作区 MSRV）。
- 带 `/dev/net/tun` 的 Linux，以及创建 TAP 设备并运行 `ip` 命令所需的 root 或 `CAP_NET_ADMIN` + `CAP_NET_RAW`。
- 常规构建无需 C 工具链。若需完全静态的可执行文件（部署推荐），请使用下方的 musl target。

## 构建

在仓库根目录运行：

```bash
cargo build --release
```

可执行文件输出到 `target/release/`：

- `rustvpn-server` —— 终止客户端连接的守护进程。
- `rustvpn-client` —— 连接服务器的守护进程。
- `rustvpn-verifier` —— 生成并校验口令验证器。

若需在较旧 glibc 系统上运行的静态可执行文件：

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# target/x86_64-unknown-linux-musl/release/rustvpn-{server,client,verifier}
```

`.cargo/config.toml` 将 Poly1305 固定为 RustCrypto 软件后端；这是有意为之，在 Zen3 级别 CPU 上实测明显更快。参见[性能](performance.md)。

默认情况下 TAP 后端会尝试 io_uring，失败则回退到 epoll。若要强制使用 epoll 后端，请设置环境变量 `GOVPN_IO_URING=0`。

## 生成验证器

验证器由口令和一个随机的 128 位身份派生而来。该工具打印**两行**：第一行是供服务器使用的长格式（含 Ed25519 公钥），第二行是供客户端使用的短格式。

```bash
printf 'correct horse battery staple\n' > /tmp/rustvpn.pass
./target/release/rustvpn-verifier -key /tmp/rustvpn.pass
# $argon2d$m=4096,t=128,p=1$BASE64_ID$BASE64_PUBLIC_KEY   <- server
# $argon2d$m=4096,t=128,p=1$BASE64_ID                     <- client
```

两行必须来自**同一次运行**（它们共享同一个随机身份/盐）。常用标志：

| 标志 | 含义 | 默认值 |
|---|---|---|
| `-key PATH` | 从文件读取口令（否则交互式提示）。 | 交互式提示 |
| `-verifier STR` | 用长格式验证器校验口令；打印 `true`/`false`。 | — |
| `-m N` | Argon2d 内存开销，单位 KiB。 | 4096 |
| `-t N` | Argon2d 迭代次数。 | 128 |
| `-p N` | Argon2d 并行度。 | 1 |
| `-egd PATH` | 从 EGD socket 读取随机性。 | `/dev/urandom` |

```bash
# Check a passphrase against the long form
./target/release/rustvpn-verifier -verifier "$LONG_FORM" -key /tmp/rustvpn.pass
```

口令只应保存在客户端，放入权限受限的文件中（例如 `0640 root:rustvpn`）。服务器只需要长格式验证器。

## 最小服务器

`peers.yaml` 将 peer 名称映射到配置。验证器必须是**长格式**；服务器进程会拒绝没有公钥的条目。

```yaml
alice:
  iface: tap0
  mtu: 1515
  timeout: 60
  noise: false
  encless: false
  verifier: $argon2d$m=4096,t=128,p=1$...$...
  up: /etc/rustvpn/up.sh
  down: /etc/rustvpn/down.sh
```

框架在打开 TAP 设备**之前**运行 `up` 脚本。因此脚本必须自行创建持久化的 TAP；随后守护进程会附加到该设备上。一个最小的 up 脚本：

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-tap0}"
ip tuntap add dev "$IFACE" mode tap 2>/dev/null || true
# 接口 IP MTU，不是线路 MTU：plain 线路 1515 -> 1500。
ip link set dev "$IFACE" mtu 1500 up
ip addr replace 10.88.0.1/24 dev "$IFACE"
```

`GOVPN_IFACE` 和 `GOVPN_REMOTE` 会被导出到两个脚本。若 YAML 中的 `iface` 为空，则使用 up 脚本 stdout 的第一行作为接口名。

启动服务器：

```bash
sudo ./target/release/rustvpn-server \
    -proto udp -bind 0.0.0.0:1194 \
    -conf /etc/rustvpn/peers.yaml \
    -stats 127.0.0.1:1294
```

配置文件每 60 秒重新读取一次；新 peer 会出现，被移除的 peer 会消失，无需重启。解析错误会保留上一份有效配置并记录一条消息。

## 最小客户端

客户端使用验证器的**短格式**和相同的口令。它先打开自己的 TAP 设备，然后执行握手，再运行 `up`。

```bash
sudo ./target/release/rustvpn-client \
    -remote 203.0.113.10:1194 -proto udp -iface tap0 -mtu 1515 -timeout 60 \
    -verifier '$argon2d$m=4096,t=128,p=1$...' \
    -key /etc/rustvpn/pass \
    -up /etc/rustvpn/up.sh -down /etc/rustvpn/down.sh
```

客户端 up 脚本（在隧道建立后运行）：

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-tap0}"
ip tuntap add dev "$IFACE" mode tap 2>/dev/null || true
# 接口 IP MTU，不是线路 MTU：plain 线路 1515 -> 1500。
ip link set dev "$IFACE" mtu 1500 up
ip addr replace 10.88.0.2/24 dev "$IFACE"
ip route replace 10.88.0.0/24 dev "$IFACE"
```

客户端在超时、重握手或 TCP 会话关闭后会自动重连，并在关闭时运行 `down`。

## 完整 IPv4 示例

假设客户端（`192.168.0.2`）与服务器（`192.168.0.1`）之间是一条不安全的 WiFi 链路，并且你想在其上跑一个加密的 `172.16.0.0/24` 网络。

在服务器上：

```bash
# TAP and addressing (also do this in up.sh for production)
ip tuntap add dev tap10 mode tap
ip addr replace 172.16.0.1/24 dev tap10
# TAP 接口 IP MTU，不是线路 MTU。plain 线路 1515 -> 1500。
ip link set dev tap10 mtu 1500 up

sudo rustvpn-server -bind 192.168.0.1:1194 -conf peers.yaml
```

在客户端上：

```bash
ip tuntap add dev tap10 mode tap
ip addr replace 172.16.0.2/24 dev tap10
ip link set dev tap10 mtu 1500 up   # plain 线路 1515 -> TAP IP MTU 1500
ip route add 0/1 via 172.16.0.1
ip route add 128/1 via 172.16.0.1

sudo rustvpn-client \
    -verifier '$argon2d$m=4096,t=128,p=1$...' \
    -iface tap10 -remote 192.168.0.1:1194
```

两条 `/1` 路由会在不删除默认路由的前提下覆盖它，因此隧道承载全部流量，而底层链路仍承载加密的 UDP 数据包。

请按数值线路 MTU 与模式设置 TAP **接口 IP MTU**，绝不要直接使用线路/帧预算：

```text
inner_ip_mtu = Mode::max_payload(wire_mtu) - 14
```

| 模式 | `mtu: 1515` 时的 TAP 接口 IP MTU |
|---|---:|
| plain | 1500 |
| noise | 1476 |
| encless | 1492 |

若使用其它数值线路 MTU，请按公式计算（或交给守护进程/声明式服务端路径）。线路 MTU 是双方契约；`mtu: auto` 与 `mtu: 0` 会被拒绝。参见[配置 → MTU](configuration.md#mtu)。

## 可选：桌面图形界面

Linux 上可以用 `rustvpn-client-ui` + `rustvpn-clientd` 代替 CLI 的日常操作。
GUI 不读取 CLI 参数，profile 放在 `~/.config/rustvpn/profiles/*.yaml`，并要求
IPv4 `address`（全隧道还要 `gateway` 和 IPv4 `dns`）。daemon 仍需由 systemd
启动，桌面用户需加入 `rustvpn` 组。deb/rpm 构建、界面语言、托盘、钥匙串和
排障见[客户端桌面 UI](../client-ui.md)。

## 测试与基准

```bash
cargo test
cargo run --release -p rustvpn-crypto --example crypto_bench
cargo run --release -p rustvpn-proto  --example proto_bench
cargo run --release -p rustvpn-net    --example mmsg_bench
```

差分测试读取从上游 GoVPN 5.7 代码树生成并已纳入版本控制的
`testdata/go_vectors.json`，因此测试套件是自包含的。重新生成它需要上游
Go 源码及其附带的向量生成器；本仓库不包含 Go 代码树。

## 首次运行常见问题

| 现象 | 原因 / 修复 |
|---|---|
| `Cannot find device "tap0"` | 服务器的 `up` 脚本未创建持久化 TAP。添加 `ip tuntap add ... mode tap`。 |
| 握手成功但无流量 | TAP 没有 IP、MTU 错误或缺少路由。检查 `ip addr` / `ip route`。 |
| 开启 noise/encless 后大包丢失 | 载荷超过 `MTU-25` / `MTU-9`。在两侧同时提高数值线路 MTU（并重新计算 TAP 接口 IP MTU），或降低内部网络的 MTU。 |
| `Currently encryptionless mode works only with TCP` | 对客户端的 encless 使用 `-proto tcp`（`-proxy` 也会隐含此设置）。 |
| `server verifier has no public key` | `peers.yaml` 中包含的是短格式；请使用同一次运行生成的长格式。 |
| 握手时出现 `random number mismatch` | 通常是同时重启导致两个会话重叠；干净重启或客户端自动重连即可解决。 |

下一步：[配置参考](configuration.md)。