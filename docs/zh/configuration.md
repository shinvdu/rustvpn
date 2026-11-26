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
| `-script-dir PATH` | 可重复；限制 up/down 脚本路径（server 侧强制）。启用 `-control` 时至少需要一个。 | 不限制（未启用 control 时） |
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
| `-mtu N` | 与服务器一致的数值线路 MTU（双方契约；`auto`/`0` 无效）。 | `1515` |
| `-timeout N` | peer 存活超时（秒）。 | `60` |
| `-timesync N` | 握手时间戳窗口（秒，0 表示关闭）。 | `0` |
| `-noise` | 将出站数据包填充至 MTU。 | 关闭 |
| `-encless` | 无加密模式（隐含 noise，仅 TCP）。 | 关闭 |
| `-cpr KIB` | 恒定包速率，单位 KiB/s。 | `0` |
| `-egd PATH` | 用于随机性的 EGD socket。 | 操作系统 RNG |
| `-warranty` | 打印担保声明并退出。 | — |

启动时执行的校验：

- `mtu` 必须是正的数值，且位于 `68..=9015` 区间；`auto` 与 `0` 会被拒绝；noise/encless 模式要求 `mtu >= 120`。
- `-encless` 要求 `-proto tcp`（或 `-proxy`，后者强制 TCP）。
- 未知的 `-proto` 值会被拒绝。

## 桌面客户端 profile（可选）

Tauri 客户端不读取 CLI 参数，而是使用
`~/.config/rustvpn/profiles/*.yaml`。与 CLI 的主要差异：

- 必须有 IPv4 `address`；全隧道（`routes` 含 `default`、`0.0.0.0/0` 或被规范化为前缀 0 的写法）还必须提供 `gateway` 和至少一个 IPv4 `dns`。
- 默认 `iface` 为 `rsvpn-gui`，避免与本机 `rustvpn-client` 的 `tap0/rsvpn0` 冲突。
- 不支持 `up`/`down` 脚本；地址、路由、DNS 和 IPv6 防护由 `rustvpn-clientd` 内置管理。
- 无法解析的 profile 不会被静默隐藏。旧版 `mtu: auto` / `mtu: 0` 文件会在 UI 与 stderr 中带上路径提示，直到迁移为与服务端一致的数值线路 MTU（例如 `mtu: 1515`）；守护进程连接前还会按相同边界再次校验。
- 界面/托盘语言与登录自启动是 GUI 设置，不写入 profile；语言保存在 WebView
  本地存储，自启动文件在 `~/.config/autostart/rustvpn-client.desktop`。
- 更新源（Tauri updater）是构建时配置，位于 `tauri.conf.json`，不在 profile 中。
- 完整字段、构建、systemd、迁移和排障见[客户端桌面 UI](../client-ui.md)。

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
  mtu: 1515             # 双方一致的数值线路 MTU（默认 1515，钳制 68..9015；0 无效）
  up: /etc/rustvpn/up.sh
  down: /etc/rustvpn/down.sh
  timeout: 60           # seconds; <= 0 means 60
  timesync: 0           # handshake timestamp window; 0 = off
  noise: false          # pad every outgoing frame to mtu
  cpr: 0                # constant packet rate, KiB/s; 0 = off
  encless: false        # encryptionless mode (forces noise)
  verifier: $argon2d$m=4096,t=128,p=1$...$...   # LONG form required
  # 可选：RustVPN 专属的声明式 TAP 配置（取代 up 脚本）：
  # network:
  #   address: 10.88.0.1/24
  #   dns: [10.88.0.1]
  #   routes: [10.88.0.0/24]      # 显式 CIDR；默认路由（含非规范前缀 0 写法）被拒绝
```

加载文件时应用的规则：

- `iface` 或 `up` 至少有一个可用。若 `iface` 为空，则使用 up 脚本 stdout 的第一行作为接口名。
- `verifier` 必须能解码且包含公钥。短格式会被拒绝并报 `server verifier has no public key`。
- `mtu: 0` 无效并被拒绝；省略 `mtu` 才使用历史默认值 1515。数值会被钳制到 `[68, 9015]`；noise/encless 条目会被提升到至少 120。
- `encless: true` 会强制 `noise: true`（填充是编码的一部分）。
- `timeout <= 0` 表示 60 秒。
- `network` 可选。若存在，需要 `iface`（或能打印接口名的 up 脚本）；IPv4 地址/网关/DNS/路由会被校验，默认路由（含 `00.0.0.0/0` 等非规范前缀 0 写法）会被拒绝。见下方“服务端声明式网络”。
- 该文件每 **60 秒**重新读取一次。解析失败会保留上一份有效配置并打印错误。

服务器上每个 peer 各自拥有一个 TAP 设备。若两个 peer 同时活跃，它们不得共享同一个 `iface`。

## 脚本（`up` / `down`）

两个脚本都会收到：

| 变量 | 值 |
|---|---|
| `GOVPN_IFACE` | 配置的接口名（服务器上可能为空）。 |
| `GOVPN_REMOTE` | 该 peer 的远端地址。 |

服务器顺序：**up 脚本 → 打开 TAP → 握手**。由于守护进程自行打开 TAP，`up` 必须创建持久化设备；**但**使用 `network:` 的 peer 由声明式路径创建 TAP，`up` 只可执行其它副作用，不得创建 `<iface>`（若必须创建则需自行写入 `rustvpn-managed` 标记）：

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-tap0}"
ip tuntap add dev "$IFACE" mode tap 2>/dev/null || true
# 这里设置的是 TAP 接口 IP MTU，不是线路 MTU（plain 线路 1515 -> 1500）。
ip link set dev "$IFACE" mtu 1500 up
ip addr replace 10.88.0.1/24 dev "$IFACE"
```

客户端顺序：**打开 TAP → 握手 → up 脚本**。客户端的 `-iface` 是真实值（默认 `tap0`），因此其 up 脚本通常配置一个已存在的设备：

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-tap0}"
# 这里设置的是 TAP 接口 IP MTU，不是线路 MTU（plain 线路 1515 -> 1500）。
ip link set dev "$IFACE" mtu 1500 up
ip addr replace 10.88.0.2/24 dev "$IFACE"
ip route replace 10.88.0.0/24 dev "$IFACE"
```

`down` 脚本在断开或关闭时运行。请让两个脚本保持幂等（`|| true`、用 `replace` 而非 `add`）；客户端在失败后会自动重连。

<a id="mtu"></a>
## MTU

在 v1 中，`mtu` 是**双方一致的数值线路契约**：客户端与服务器必须使用同一个数值。任何一侧根据本地路径推导都会改变握手/传输的线上长度，使对端以 `TooLarge` 拒绝数据包。因此：

- `mtu` 必须是正数；**`mtu: auto` 与 `mtu: 0` 会被拒绝**（省略服务端字段才使用默认 1515）。
- 本地只推导 TAP **接口 IP MTU** 与 TCP MSS：

```text
inner_ip_mtu = Mode::max_payload(wire_mtu) - 14
ipv4_mss     = inner_ip_mtu - 40
ipv6_mss     = inner_ip_mtu - 60
```

| 模式 | 有效载荷上限 | 线路 1515 时的 TAP IP MTU | MSS v4 / v6 |
|---|---|---:|---:|
| plain | `MTU - 1` | 1500 | 1460 / 1440 |
| noise | `MTU - 25`（16 tag + 8 nonce + 1 pad） | 1476 | 1436 / 1416 |
| encless | `MTU - 9`（8 nonce + 1 pad） | 1492 | 1452 / 1432 |

- 守护进程（`rustvpn-clientd`）与服务端声明式路径（`network:`）把 TAP 接口设置为 `inner_ip_mtu`，**绝不是帧预算本身**，并记录线路 MTU、模式、内部 MTU 与 MSS。
- 走 Go 兼容的 CLI/up 脚本且自行配置接口时，必须写入同一个内部值：如 plain `-mtu 1515` → `ip link set ... mtu 1500`，noise → `1476`，encless → `1492`。若改用其它线路 MTU，请按上面的公式计算。
- 超过模式有效载荷上限的帧会被拒绝并记录日志，绝不会被静默截断。
- **自动路径 MTU 推导推迟到 v2 的 MTU 协商**。v1 不宣称路径 MTU 自适应；若路径更小，请在**两侧**同时降低数值线路 MTU。
- encless 在普通 1500 字节外层路径上仍会记录容量告警：每个包增加 `4128` 字节。不要依赖 IP 分片；请使用 jumbo 帧或其它模式。

## 服务端声明式网络（`network:`）

当 `peers.yaml` 条目包含可选的 `network:` 时，`rustvpn-server` 无需 up 脚本即可管理该 peer 的 TAP：

- 缺失时创建 TAP，按数值线路 MTU 推导并设置 **接口 IP MTU**（`inner_ip_mtu = max_payload - 14`；plain 1515 → 1500、noise 1515 → 1476、encless 1515 → 1492），然后添加地址/路由，并在配置了 `dns` 时调用 `resolvectl`。
- **严格所有权**：新建 TAP 会写入 `ip link set dev <iface> alias rustvpn-managed`；已存在但未带该标记的 TAP 会被拒绝并保持原样，避免破坏管理员的地址/路由/DNS。带标记的 TAP 视为上次崩溃/重启遗留，接管时先清空该 TAP 上残留的 IPv4 地址/路由与 resolver 状态（标记即所有权证明），再应用新的 `network:` 配置，并在退出时删除。
- **`network:` 负责创建 TAP**：`up`/`down` 仍可运行（例如日志或其它副作用），但与该 peer 的 `network:` 同时配置时，`up` **不得**创建 `<iface>`。未标记的既有 TAP 会被明确拒绝；若脚本必须创建，则脚本必须自行写入 `ip link set dev <iface> alias rustvpn-managed`，之后服务端会像其它自有 TAP 一样接管并在退出时删除。声明式路径无需任何脚本。
- **非破坏式安装**：地址/路由使用 `ip addr add` / `ip route add`，**绝不使用 `replace`**。遇到 `EEXIST` 时，只有完全匹配的既有地址/路由才视为幂等（便于接管崩溃遗留）；其它冲突会中止并回滚。RustVPN 只记录并删除自己真正添加的项，既有路由（包括主机默认路由）绝不会被覆盖或删除。
- `network.routes` 必须是显式 IPv4 CIDR；默认路由（包括非规范前缀 0 写法）会被拒绝，以免劫持服务器自身路由。设置 `gateway` 时它作为这些路由的下一跳。
- 任一步失败都会回滚地址/路由/DNS/MTU 与 RustVPN 创建的 TAP；成功配置的状态在服务器退出时移除。
- **重载/移除清理**：peer 被移除、`network:` 被删除，或 mode/MTU/network 字段变化时，受影响会话吊销后会移除旧的声明式 guard。仍被未变化的活跃 peer 使用的 guard 会保留；因此把 peer 改回纯脚本路径不再需要重启服务器。
- `network:` 是 RustVPN 扩展；不含该节的条目与 GoVPN 5.7 YAML 完全兼容，含该节的文件会被 Go 服务端拒绝。

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