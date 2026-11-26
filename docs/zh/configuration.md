# 配置参考

[English](../en/configuration.md) | **中文** | [Русский](../ru/configuration.md)

三个可执行文件都有意接受与 GoVPN 5.7 相同的标志、默认值和配置格式。本页是 Rust 构建的权威列表。

## `rustvpn-server` 标志

| 标志 | 含义 | 默认值 |
|---|---|---|
| `-bind ADDR` | 监听的 `host:port`。UDP 和 TCP 均使用该地址。 | `[::]:1194` |
| `-conf PATH` | YAML peer 配置文件。 | `peers.yaml` |
| `-proto udp\|tcp\|all` | 提供服务的传输方式。 | `udp` |
| `-stats ADDR` | 在 `host:port` 上启动 JSON 统计 HTTP 端点。 | 禁用 |
| `-proxy ADDR` | 在 `host:port` 上启动简易 HTTP CONNECT 代理。 | 禁用 |
| `-egd PATH` | 从 EGD unix socket 而非操作系统 RNG 读取随机性。 | 操作系统 RNG |
| `-control PATH` | **可选**：本地管理控制 socket；启用后管理端可查看实时会话/踢线/立即重载。 | 禁用 |
| `-control-group GROUP` | 控制 socket 属组（名称或数字 gid）；设置后模式为 `0660`。 | 空（`0600`，仅 owner） |
| `-script-dir PATH` | 可重复；限制 up/down 脚本路径（server 侧强制）。 | 不限制 |
| `-warranty` | 打印许可证担保声明并退出。 | — |

管理端是独立进程 `rustvpn-admind`，参数与部署见 [`admin-web-ui.md`](../admin-web-ui.md)。server 未启用 `-control` 时与旧版行为一致。

```bash
sudo rustvpn-server -proto all -bind 0.0.0.0:1194 \
    -conf /etc/rustvpn/peers.yaml -stats 127.0.0.1:1294
```

## `rustvpn-client` 标志

| 标志 | 含义 | 默认值 |
|---|---|---|
| `-remote ADDR` | 要连接的服务器 `host:port`。**必填。** | — |
| `-proto udp\|tcp` | 使用的传输方式。`-proxy` 会强制使用 `tcp`。 | `udp` |
| `-iface NAME` | TAP 接口名。 | `tap0` |
| `-verifier STR` | 客户端的短格式验证器。**必填。** | — |
| `-key PATH` | 口令文件；省略则在终端提示。 | 交互式提示 |
| `-up PATH` | 会话建立后运行的脚本。 | — |
| `-down PATH` | 断开/关闭时运行的脚本。 | — |
| `-stats ADDR` | JSON 统计 HTTP 端点。 | 禁用 |
| `-proxy ADDR` | HTTP CONNECT 代理 `host:port`。 | 直连 |
| `-proxy-auth USER:PASS` | 用于代理的 HTTP Basic 凭据。 | — |
| `-mtu N` | 最大 TAP 帧大小。 | `1515` |
| `-timeout N` | peer 存活超时（秒）。 | `60` |
| `-timesync N` | 握手时间戳窗口（秒，0 表示关闭）。 | `0` |
| `-noise` | 将出站数据包填充至 MTU。 | 关闭 |
| `-encless` | 无加密模式（隐含 noise，仅 TCP）。 | 关闭 |
| `-cpr KIB` | 恒定包速率，单位 KiB/s。 | `0` |
| `-egd PATH` | 用于随机性的 EGD socket。 | 操作系统 RNG |
| `-warranty` | 打印担保声明并退出。 | — |

启动时执行的校验：

- `mtu` 必须位于 `68..=9015` 区间；noise/encless 模式要求 `mtu >= 120`。
- `-encless` 要求 `-proto tcp`（或 `-proxy`，后者强制 TCP）。
- 未知的 `-proto` 值会被拒绝。

## `rustvpn-verifier` 标志

| 标志 | 含义 | 默认值 |
|---|---|---|
| `-key PATH` | 口令文件；省略则提示。 | 交互式提示 |
| `-verifier STR` | 用长格式验证器校验口令。 | — |
| `-m N` | Argon2d 内存开销（KiB）。 | `4096` |
| `-t N` | Argon2d 迭代次数。 | `128` |
| `-p N` | Argon2d 并行度。 | `1` |
| `-egd PATH` | EGD socket。 | 操作系统 RNG |
| `-warranty` | 打印担保声明并退出。 | — |

不带 `-verifier` 时，该工具会基于同一个共享身份（按此顺序）打印长格式与短格式。带 `-verifier` 时，它打印 `true` 或 `false`。

## `peers.yaml`

每个 peer 一个顶层键。未知字段会被忽略，与 Go 的 YAML 行为一致。

```yaml
alice:
  iface: tap0           # TAP device name; may be empty if up prints it
  mtu: 1515             # max TAP frame size (default 1515, clamped 68..9015)
  up: /etc/rustvpn/up.sh
  down: /etc/rustvpn/down.sh
  timeout: 60           # seconds; <= 0 means 60
  timesync: 0           # handshake timestamp window; 0 = off
  noise: false          # pad every outgoing frame to mtu
  cpr: 0                # constant packet rate, KiB/s; 0 = off
  encless: false        # encryptionless mode (forces noise)
  verifier: $argon2d$m=4096,t=128,p=1$...$...   # LONG form required
```

加载文件时应用的规则：

- `iface` 或 `up` 至少有一个可用。若 `iface` 为空，则使用 up 脚本 stdout 的第一行作为接口名。
- `verifier` 必须能解码且包含公钥。短格式会被拒绝并报 `server verifier has no public key`。
- `mtu: 0` 表示 1515。数值会被钳制到 `[68, 9015]`；noise/encless 条目会被提升到至少 120。
- `encless: true` 会强制 `noise: true`（填充是编码的一部分）。
- `timeout <= 0` 表示 60 秒。
- 该文件每 **60 秒**重新读取一次。解析失败会保留上一份有效配置并打印错误。

服务器上每个 peer 各自拥有一个 TAP 设备。若两个 peer 同时活跃，它们不得共享同一个 `iface`。

## 脚本（`up` / `down`）

两个脚本都会收到：

| 变量 | 值 |
|---|---|
| `GOVPN_IFACE` | 配置的接口名（服务器上可能为空）。 |
| `GOVPN_REMOTE` | 该 peer 的远端地址。 |

服务器顺序：**up 脚本 → 打开 TAP → 握手**。由于守护进程自行打开 TAP，`up` 必须创建持久化设备：

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-tap0}"
ip tuntap add dev "$IFACE" mode tap 2>/dev/null || true
ip link set dev "$IFACE" mtu 1540 up
ip addr replace 10.88.0.1/24 dev "$IFACE"
```

客户端顺序：**打开 TAP → 握手 → up 脚本**。客户端的 `-iface` 是真实值（默认 `tap0`），因此其 up 脚本通常配置一个已存在的设备：

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-tap0}"
ip link set dev "$IFACE" mtu 1540 up
ip addr replace 10.88.0.2/24 dev "$IFACE"
ip route replace 10.88.0.0/24 dev "$IFACE"
```

`down` 脚本在断开或关闭时运行。请让两个脚本保持幂等（`|| true`、用 `replace` 而非 `add`）；客户端在失败后会自动重连。

<a id="mtu"></a>
## MTU

`mtu` 是守护进程期望从 TAP 设备读取的最大帧大小。超过该模式有效载荷上限的帧会被拒绝并记录日志；它们绝不会被静默截断。

| 模式 | 有效载荷上限 |
|---|---|
| classic | `MTU - 1` |
| noise | `MTU - 25`（16 字节 tag + 8 字节 nonce + 1 字节 pad） |
| encless | `MTU - 9`（8 字节 nonce + 1 字节 pad） |

在默认的 `mtu: 1515` 下，分别是 1514 / 1490 / 1506 字节。如果你需要通过 noise 或 encless 隧道承载完整的 1500 字节 IP 包（1514 字节以太网帧），请将配置的 MTU 至少提高到 1540（noise）或 1524（encless），并在 up 脚本中相应设置 TAP 接口 MTU。peer 的内部 MTU 不应超过有效载荷。

## 超时与心跳

由于 UDP 是无状态的，peer 在 `timeout` 秒内没有数据包即被视为死亡。两侧应使用相同的值（默认 60）。若在超时的四分之一时间内没有发送任何内容，就会发出一个心跳包，使会话在 TAP 空闲时仍保持存活——这会产生少量流量。

服务器会定期清理陈旧的 peer 和被遗弃的握手状态（大约每 10 秒一次；超过 60 秒仍未完成的握手会被丢弃）。TCP 会话使用相同的超时：静默死亡的 TCP peer 会在超时后被检测到，而不是永久等待。

## CPR（恒定包速率）

`cpr: KIB`（或 `-cpr`）以约 `KIB` KiB/s 的速率发出填充流量。数据包周期根据线大小（包含 encless 膨胀）计算，并驱动填充传输与心跳间隔。CPR 可隐藏真实载荷流量的时间戳，但会消耗大量流量和 CPU。请与 noise 配合使用。

## Timesync（时间同步）

`timesync: N`（或 `-timesync`）要求握手包携带按当前时间戳（四舍五入到 `N` 秒）打上的标记。它可抵御主动 DPI 重放截获的首个握手包，以确认给定身份存在、且该服务器是 GoVPN。两侧时钟必须保持合理同步。`0` 表示关闭。

## Noise

`noise: true`（或 `-noise`）将每个出站帧填充至 MTU。它隐藏包长度，但可能显著增加流量。请在两侧都启用以达到预期效果。载荷开销见 [MTU](#mtu)。

<a id="encless"></a>
## Encless

`encless: true`（或 `-encless`）用 AONT + Chaffing-and-Winnowing 取代流加密，仅使用认证原语（不使用加密函数）来保持机密性。它会强制启用 noise，并为每个数据包增加 **4128 字节**，因此开销较大。客户端仅在 TCP 上支持它，与 Go 一致：使用默认 UDP proto 时，`-encless` 会被拒绝。参见[协议 → Encless](protocol.md#encless)。

## 统计端点

`-stats host:port` 启动一个极简的 TCP 监听器。它接受连接、忽略请求，并返回一个 `HTTP/1.0 200 OK` 响应，其中包含 peer 对象的 JSON 数组：

```bash
curl http://127.0.0.1:1294/ | jq .
```

```json
[
  {
    "Addr": "203.0.113.10:52341",
    "Id": "q83v...==",
    "BytesIn": 1392774,
    "BytesOut": 17228877,
    "BytesPayloadIn": 1389000,
    "BytesPayloadOut": 17220000,
    "FramesIn": 12412,
    "FramesOut": 16588,
    "FramesUnauth": 0,
    "FramesDup": 0,
    "HeartbeatRecv": 2,
    "HeartbeatSent": 1,
    "NoiseEnable": false,
    "CPR": 0,
    "Encless": false,
    "MTU": 1515,
    "Established": "2026-11-25T20:00:00Z",
    "LastPing": "2026-11-25T20:05:49Z",
    "LastSent": "2026-11-25T20:05:49Z"
  }
]
```

`Id` 是 peer 身份的 base64（无填充）编码。所有字段名均与 Go 实现一致。

## Proxy

两种角色都可以使用 HTTP CONNECT。

- **服务器 `-proxy host:port`**：接受任意 HTTP 请求，回复 `HTTP/1.0 200 OK`，然后切换到原始 TCP 会话状态机。它不对代理客户端进行认证。
- **客户端 `-proxy host:port`**：连接代理并发送 `CONNECT remote:port`。`-proxy-auth user:password` 会添加 HTTP Basic 授权。传输方式会变为 TCP。

只要外部 HTTP 代理支持 CONNECT，即可使用任意代理。

## EGD

`-egd PATH`（所有可执行文件）从 EGD（熵收集守护进程）unix socket 读取随机性。在 `/dev/urandom` 不可信的系统上使用它。若省略该选项，则使用操作系统 CSPRNG。

下一步：[协议](protocol.md)。