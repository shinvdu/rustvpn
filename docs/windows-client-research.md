# Windows 客户端调研与实施方案

> 日期：2026-11-26
> 状态：调研完成，尚未实现
> 目标：Windows 10/11 x64 桌面客户端（GUI + 本地服务）
> 基线：`feature/client-ui`（v0.2.0-beta.1）
> 原则：不改线协议、不改服务端、不破坏现有 Linux 客户端

---

## 0. 结论摘要

**推荐架构：无特权 Tauri GUI + 特权 Windows 服务 + Wintun L3 适配器 + 用户态以太网垫片。**

- 复用现有 `rustvpn-client-core`（Profile、Engine、会话、重连）与
  `rustvpn-client-ipc`（JSON 帧、事件流、请求/响应）。
- Windows 服务（LocalSystem）负责创建 Wintun 适配器、安装路由/DNS、
  运行隧道；GUI 以普通用户运行，通过命名管道控制服务。
- 协议 `DATA` 是**以太网帧**，而 Windows 的 Wintun 只有 L3 IP 包。
  因此必须在 L3 适配器与隧道之间实现**以太网垫片**：
  出站补 14 字节以太网头，入站去头，并实现 ARP 应答/解析。
- 不建议首选 `tap-windows6`。它是真正的 L2 驱动，能绕过垫片，但需要
  安装 NDIS 驱动、处理签名与 OpenVPN 依赖，且与 macOS/移动端方案不一致。
- 主要工作量不是 Tauri（Tauri 本身跨平台），而是：
  以太网垫片、Windows 服务/命名管道、Windows 路由/DNS、安装签名。

工作量粗估（1 名熟悉本仓库的工程师）：

| 范围 | 估算 |
|---|---|
| Phase 0：Wintun + ARP 技术验证 | 3–5 天 |
| Phase 1：垫片 + 平台层 | 1.5–2 周 |
| Phase 2：Windows 服务 + 命名管道 | 1.5–2 周 |
| Phase 3：GUI 平台适配 | 约 1 周 |
| Phase 4：路由/DNS/崩溃恢复 | 与 Phase 2 并行，约 1–1.5 周 |
| Phase 5：MSI、签名、CI、验收 | 1–2 周 |
| **合计** | **约 6–9 周** |

---

## 1. 现状与代码约束

### 1.1 数据路径

```text
应用 → OS 路由 → TAP/Wintun → 客户端进程 → RustVPN 加密 → UDP/TCP
```

- `crates/rustvpn-net/src/tap.rs:27` 的 `Tap::open` 在 Linux 上使用
  `tun` crate 的 `Layer::L2`，即以太网 TAP。
- `crates/rustvpn-net/src/peer.rs:203` 的 `tap_reader_task` 直接从 TAP
  读取帧，作为隧道 payload 发送；`peer.rs` 不解析 IP，只处理字节帧。
- `crates/rustvpn-client-core/src/engine.rs:156` 每个连接打开一次 TAP，
  握手成功后由 `NetworkGuard` 安装地址、路由、DNS。
- `crates/rustvpn-proto` 的 `Mode::max_payload(mtu)` 决定了 payload 上限：

  | 模式 | payload 上限 | 1500 IP 所需 `mtu` |
  |---|---|---|
  | plain | `mtu - 1` | 1515 |
  | noise | `mtu - 25` | 1539 |
  | encless | `mtu - 9` | 1523 |

  以太网头固定 14 字节，因此 L3 适配器的 IP MTU =
  `max_payload(mtu) - 14`。

### 1.2 Windows 平台能力

- `tun 0.7.13` 的 Windows 后端只实现 L3/Wintun：
  `src/platform/windows/device.rs` 中 `Layer::L2` 分支是 `todo!()`。
- Wintun 是 L3 驱动，只收发 IP 包，不提供 MAC/ARP。
- Wintun 驱动本身已由 WireGuard 项目签名，但 `wintun.dll` 需要随应用
  分发，并遵守其独立许可。
- 创建 Wintun 适配器、修改全局路由/DNS 需要管理员权限；因此必须使用
  Windows 服务，GUI 不能提权运行。
- `rustvpn-net/src/udp_batch.rs` 已有非 Linux 的单包回退，Windows 上
  UDP 收发可以直接工作，不需要 `sendmmsg/recvmmsg`。

### 1.3 现有代码的 Unix 绑定（Windows 编译阻塞点）

| 文件/位置 | 现状 | Windows 需要 |
|---|---|---|
| `crates/rustvpn-net/src/tap.rs` | `Layer::L2` + Linux `ensure_root_privileges` | 平台门面；Windows 走 Wintun L3 + 垫片 |
| `crates/rustvpn-crypto/src/egd.rs:7` | 无条件使用 `std::os::unix::net::UnixStream` | `cfg(unix)`，Windows 提供报错 stub |
| `crates/rustvpn-client-core/src/lock.rs:10` | `flock`、`/run`、`/etc/group`、`geteuid` | Windows 命名互斥量 |
| `crates/rustvpn-client-core/src/netcfg.rs:1` | `ip` / `resolvectl` | Windows 网络配置实现 |
| `crates/rustvpn-client-core/src/engine.rs:156` | `Tap::open(iface, mtu)` | 传入地址/网关/DNS 等配置 |
| `crates/rustvpn-client-ipc/src/client.rs:5` | `tokio::net::UnixStream` | Unix socket / 命名管道传输抽象 |
| `crates/rustvpn-client-ipc/src/lib.rs:29` | `/run/rustvpn-client/client.sock` | Windows 管道名与平台路径 |
| `crates/rustvpn-clientd/src/main.rs:194` | `UnixListener` | 命名管道服务端 |
| `crates/rustvpn-clientd/src/main.rs:553` | `SO_PEERCRED`、`/proc` | 管道 DACL + 客户端 PID 校验 |
| `crates/rustvpn-client-gui/src/main.rs:309` | XDG autostart | HKCU Run / Tauri autostart |
| `crates/rustvpn-client-gui/src/main.rs:502` | `XDG_CONFIG_HOME` / `HOME` | `%LOCALAPPDATA%\RustVPN` |
| `crates/rustvpn-client-gui/src/main.rs:305` | Secret Service keyring | Windows Credential Manager |
| `crates/rustvpn-client-gui/src/main.rs:557` 附近 | 环境变量判断语言 | `GetUserDefaultUILanguage` |
| `crates/rustvpn-net/src/scripts.rs` 测试 | Unix 权限测试 | 测试按平台 cfg |
| `crates/rustvpn-client` CLI | `-egd`、up/down 脚本 | 首版不承诺 Windows CLI |

---

## 2. 链路层方案选择

| 方案 | 优点 | 缺点 | 结论 |
|---|---|---|---|
| **Wintun（L3）+ 以太网垫片** | 驱动已签名、现代、无 OpenVPN 依赖；与 macOS/移动端方向一致 | 需要实现 ARP/MAC/MTU；丢失纯 L2 能力 | **推荐** |
| `tap-windows6`（L2） | 直接复用现有 L2 数据路径，不需要 ARP 垫片 | 需安装 NDIS 驱动；驱动签名/分发/兼容性成本；依赖 OpenVPN 生态；`tun` crate 的 Windows L2 仍是 `todo!()` | 仅当“必须真 L2”时备选 |
| 让服务端改成 L3/TUN | 客户端简单 | 改线协议/服务端行为，破坏 GoVPN 5.7 互操作 | **拒绝** |

### 2.1 首版范围建议

**MVP 支持：**

- Windows 10/11 x64
- IPv4 静态地址/网关/DNS
- UDP、TCP、plain、noise、encless（TCP）
- 全隧道与指定路由
- 服务安装/卸载、命名管道、托盘、单实例、钥匙串、开机自启

**MVP 暂不支持：**

- IPv6 隧道（需阻断或明确告警）
- DHCP 客户端
- 依赖以太网广播/VLAN/非 IP 协议的 L2 场景
- Windows CLI（可编译但不承诺功能）
- ARM64
- 应用内自更新（服务安装模式走 MSI 更新）

---

## 3. 目标架构

```text
┌─────────────────────────────────────────────┐
│ Tauri GUI（普通用户）                        │
│ 配置、状态、流量、日志、托盘、钥匙串、自启动   │
└──────────────────┬──────────────────────────┘
                   │ 命名管道 + 4 字节长度前缀 JSON
                   │ DACL + 服务端身份校验
┌──────────────────▼──────────────────────────┐
│ rustvpn-clientd.exe（Windows 服务，SYSTEM）  │
│ Engine、重连、路由/DNS、隧道锁、IPC 服务端    │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│ rustvpn-net / rustvpn-client-core            │
│ Wintun L3 + Ethernet shim（ARP/MAC/MTU）     │
└──────────────────┬──────────────────────────┘
                   │ 以太网帧
              RustVPN 隧道（协议不变）
```

关键边界：

- GUI 只依赖 `rustvpn-client-ipc`，不链接 crypto/proto/隧道代码。
- 服务只接受本地命名管道，不监听 TCP。
- 服务端/线协议完全不变。

---

## 4. 以太网垫片设计（核心新增组件）

### 4.1 出站：IP → 以太网帧

```text
Wintun 读出 IPv4 包
  → 确定下一跳（同网段目的 IP 或 gateway）
  → 查 ARP 缓存
  → 命中：加 [dst_mac][src_mac][0x0800][IPv4]
  → 未命中：发 ARP 请求，原包进入 pending 队列
  → 交给隧道
```

- 源 MAC 固定为从 verifier id 派生的本地管理单播 MAC，例如
  `02:52:56:xx:xx:xx`；重连保持不变。
- IPv4 包大小不得超过 `max_payload(mtu) - 14`。
- 广播/多播的下一跳 MAC 映射：IPv4 多播 `01:00:5e:...`；
  MVP 可限制为单播，其他丢弃并限速记日志。

### 4.2 入站：以太网帧 → IP

```text
隧道收到以太网帧
  → 长度 ≥ 14
  → 目标 MAC 是本机 / 广播 / 多播
  → EtherType == 0x0800
  → 按 IPv4 total_length 截取（去掉以太网 padding）
  → 写入 Wintun
  → ARP 帧交给 ARP 状态机
  → 其他 EtherType 丢弃
```

### 4.3 ARP 状态机

必须实现：

1. 收到 `ARP request(target_ip == 本机 IP)` → 用合成 MAC 回 `ARP reply`。
2. 出站 IP 未命中缓存 → 发 `ARP request`，原包进入 pending 队列。
3. 收到 `ARP reply` → 更新缓存（TTL，例如 60 秒），flush pending。
4. 免费 ARP → 更新缓存。
5. pending 队列、ARP 缓存、日志都要有上限，防止恶意帧耗尽内存。
6. 连接成功后可选发一次免费 ARP，刷新服务端桥表。

注意：垫片的 `recv()` 是“OS → 隧道”方向，ARP 回包不能写回 Wintun，
必须放入垫片内部队列，由下一次 `recv()` 返回给 peer。`send()` 是
“隧道 → OS”方向，收到 ARP 请求时只入队回包。

### 4.4 MTU

```text
ip_mtu = mode.max_payload(tunnel_mtu) - 14
```

- plain：`tunnel_mtu = ip_mtu + 15`
- noise：`tunnel_mtu = ip_mtu + 39`
- encless：`tunnel_mtu = ip_mtu + 23`

Wintun 适配器 MTU 设置为 `ip_mtu`。Windows 应在 `ip_mtu < 576` 时拒绝
连接或明确告警，避免产生不可用的接口。

### 4.5 并发与队列

`peer.rs` 的读取任务和发送任务会并发调用 `Tap::recv` / `Tap::send`：

- ARP 缓存和 pending 队列放在 `Mutex` 中；
- 持锁期间不做 `await`；
- `recv` 先检查内部出站队列（ARP 回包/请求），为空再读 Wintun；
- 所有队列有界，满时丢最旧并限速记录日志。

### 4.6 明确丢弃的行为

- VLAN（0x8100）
- IPv6（0x86DD，MVP 不承载）
- PPPoE/AppleTalk 等非 IP EtherType
- 目标 MAC 不是本机/广播/多播的未知单播
- 超过 MTU 的帧
- 畸形 ARP/IPv4 包

以上行为需要写入用户文档，避免“为什么局域网发现不能用”的误解。

---

## 5. Windows 服务与 IPC（M2 实装状态）

> 本节描述 `feature/client-ui` 上 M2 的实际实现。安装/注册服务仍属 M5，
> 当前没有 `-install`/`-uninstall` 命令，也不修改宿主服务。

### 5.1 服务

- `rustvpn-clientd.exe` 用 `windows-service` 0.8 接入 SCM，服务名
  `rustvpn-clientd`。
- 运行模式：
  - `-console`：前台模式，适合 SSH/开发；Windows 上未指定 `-service`
    时默认也是前台。
  - `-service`：SCM 分发器模式。M5 的 MSI 需把镜像路径写成
    `rustvpn-clientd.exe --service`。
- 正式模式以 `LocalSystem` 运行；服务进程不链接 GUI/Tauri。
- 控制处理：接受 `STOP` 与 `SHUTDOWN`，取消与 SIGTERM 相同的
  `CancellationToken`，由同一 `run` 路径执行 Engine 关闭、监听器关闭和
  （Unix）clean marker 写入。服务状态序列为
  `StartPending` → `Running` → `Stopped`。
- 服务启动失败（配置错误、监听失败、运行时创建失败）写日志并以非零
  退出码结束，便于 M5 的失败恢复策略识别。
- 服务日志：stderr + `%ProgramData%\RustVPN\clientd.log`；可用
  `RUSTVPN_CLIENTD_LOG` 覆盖路径。Event Log 集成留到 M5。
- Linux 的 kill-switch marker/firewall 启动清理逻辑保持不变；Windows 的
  路由/DNS/NRPT/防火墙状态由 M3 的 `cleanup_stale_network()` 在 Engine
  启动路径清理（详见第 6 节）。

### 5.2 命名管道

- 管道名：`\\.\pipe\rustvpn-clientd`；`-socket` 或
  `RUSTVPN_CLIENTD_SOCKET` 可覆盖，裸名称会展开为 `\\.\pipe\<name>`。
  服务模式使用生产管道；console 模式必须使用非生产 `-socket`，否则拒绝
  启动，避免普通用户通过安装目录里的 daemon 冒充服务或抢占生产管道。
- 字节模式；`PIPE_REJECT_REMOTE_CLIENTS`；首次实例用
  `FILE_FLAG_FIRST_PIPE_INSTANCE`，已存在同名管道（抢占/重复实例）直接
  失败。
- 4 字节大端长度 + JSON 的帧格式、Hello、空闲/写超时和 `Subscribe`
  语义与 Unix 完全一致，`PROTOCOL_VERSION` 仍为 2。
- 实例上限 17：最多 16 个并发连接 + 1 个始终待命的监听实例。daemon 的
  `Semaphore(16)` 上限不变。
- 客户端连接遇到 `ERROR_PIPE_BUSY` 最多重试 2 秒。

### 5.3 访问控制与威胁模型

- 用 `windows-sys` 构造 SDDL，通过 Tokio
  `ServerOptions::create_with_security_attributes_raw` 创建管道。DACL
  只授予 `SYSTEM + Administrators`、服务配置的 `RustVPN` 组，以及
  daemon 自身账户；**不再回退到 INTERACTIVE**。服务模式缺少 `RustVPN`
  组时拒绝启动（fail closed），console 模式只允许 daemon 自身用户。
  显式拒绝 Everyone / Anonymous；没有 null DACL。
- 专用组：`-pipe-group <name>` 可显式指定本地组；M5 安装器创建
  `RustVPN` 组并把安装用户加入。服务端还必须校验客户端所在用户组。
- 服务端在 Hello 之前用 `GetNamedPipeClientProcessId` 取客户端 PID，并
  `OpenProcessToken(TOKEN_QUERY)` 校验：
  - 与 daemon 自身用户 SID 相同，或
  - token 组包含 Administrators，或配置的专用 `RustVPN` 组。
  不再接受 INTERACTIVE 回退。
  Deny-only 组（UAC 过滤 token 里的 Administrators）不计为放行；任何
  API 失败按拒绝处理。
- 已知限制：同用户的恶意进程仍在信任集合内；DACL + PID 校验无法区分它。
  另外，管道对象上的 GENERIC_WRITE 映射包含 `FILE_CREATE_PIPE_INSTANCE`
  （同一个 0x4 位），所以被允许的同用户进程仍能创建额外实例。
- 服务端身份校验（GUI 使用所有 IPC 命令前）已在 M4/M6 实现：IPC 提供
  `Client::server_pid()`，GUI 用 `QueryFullProcessImageNameW` 读镜像路径、
  `WinVerifyTrust` 校验 Authenticode、并读取服务端 token user SID；只接受
  安装目录内且属于 SYSTEM 的服务，或与 GUI 同用户的 console/portable
  daemon，其余拒绝。status/logs/events 也先完成同一校验。console 模式禁止
  绑定生产管道，首次实例标志减少启动前的抢占窗口。
- 控制台管道的 `Local\`/`Global\` 与多用户策略：请勿在共享机上以普通
  用户长期运行；生产以服务 + 专用组为准。

### 5.4 隧道锁

- Windows 使用 `CreateMutexW` 的命名互斥量 `Global\RustVPNTunnel`。
  `TunnelLock` 的 `acquire`/`acquire_at`/`path()` API 与 Unix 相同。
- 互斥量所有权按线程计算，而 Tokio 任务会跨 await 迁移线程；因此
  获取与释放放在专用 OS 线程上，`Drop` 发送释放信号并 join。
- 进程崩溃时 OS 自动释放（下一次等待得到 `WAIT_ABANDONED`），不会留下
  永久锁。
- 普通用户无法创建 Global 对象且本机没有服务持锁时，回退到
  `Local\RustVPNTunnel` 供开发使用；服务持锁时通过
  `OpenMutexW` 检测为 busy。多用户共享机器的单隧道保证以正式服务为准。
- 元数据文件 `%ProgramData%\RustVPN\tunnel.lock` 仅供错误信息显示，不是
  锁的真源；`RUSTVPN_TUNNEL_LOCK` 覆盖名称/路径。Linux `flock` 行为未变。

---

## 6. Windows 路由、DNS 与恢复（M3 实装设计）

> 本节记录 `netcfg/windows.rs` + `netcfg/winplan.rs` 的实际实现；Linux 代码与
> 行为不变。所有命令使用绝对路径 `powershell.exe`，不启动 `cmd.exe`、不依赖
> PATH；参数只来自类型化 IP/索引/metric 与经过校验的接口名，并做 PowerShell
> 单引号转义。

### 6.1 配置时机

- Wintun 适配器在 `Tap::open` 时只创建/打开、启用、设置**派生接口 MTU**
  （`max_payload(wire)-14`，绝不是 wire budget），不设置地址/网关/DNS。
- 首次握手成功后，`NetworkGuard::install` 才安装地址、防环路由、默认/分流
  路由、DNS/NRPT 与 IPv6 阻断。失败握手不会提前改主机路由/DNS。
- 地址通过 `New-NetIPAddress -PolicyStore ActiveStore` 写入；安装前后都用
  `Get-NetIPAddress` 校验，接口 MTU 用 `Get-NetAdapter MtuSize` 和
  `Get-NetIPInterface NlMtu` 双重校验。若已有其他接口上的同子网路由，
  在添加地址前拒绝，避免静默抢占 LAN 子网。

### 6.2 防环

- 需要安装任何隧道路由时，先用 `Find-NetRoute -RemoteIPAddress <outer>
  -AddressFamily IPv4` 读取外层端点当前实际使用的接口与下一跳。
- 若该路径已经是 Wintun 接口，直接拒绝（会形成递归）。
- 添加 `<outer>/32` 主机路由（metric 1）到原接口/下一跳，**再**安装默认或
  分流路由；`/32` 比任何隧道路由更具体。
- 若 `/32` 已存在且完全一致：不拥有时不删除、只复用；若已记录为 owned 则
  幂等。若同目标但接口/下一跳不同则失败关闭。

### 6.3 默认路由与分流

- Wintun 是 L3，OS 路由使用 on-link `NextHop=0.0.0.0`；profile 网关只作为
  Ethernet 垫片的合成 ARP 下一跳。把网关当 OS 下一跳会让 Windows 尝试 ARP
  一个 Wintun 无法应答的地址，数据面会断。
- 全隧道：`Set-NetIPInterface -InterfaceMetric 1`（记录原 metric 与
  AutomaticMetric），`New-NetRoute 0.0.0.0/0 -RouteMetric 0`。原默认路由保留，
  不删除、不修改；清理时只删自己添加的项并恢复接口 metric。
- 分流：每条 profile 路由通过 Wintun，metric 50；接口 metric 不变。
- 冲突规则：同 `DestinationPrefix` 在任何其他接口上已存在 → 失败关闭；
  同接口上已有非 owned 的同目标路由 → 失败；完全一致的 owned 路由 → 幂等。
  Wintun 自己的 connected 子网（address/prefix 的网络地址）被跳过。
- 多个默认路由：对每个 connected 接口计算 effective metric =
  `InterfaceMetric + RouteMetric`；若存在 ≤1 的其他默认路由，就拒绝安装
  （不宣称已接管全隧道）。断开的接口不计入。

### 6.4 DNS / NRPT

- 全隧道：`Get-DnsClientServerAddress` 记录 Wintun 原 DNS，
  `Set-DnsClientServerAddress` 设置 profile DNS；再用
  `Add-DnsClientNrptRule -Namespace '.' -NameServers <profile DNS>` 强制
  所有 DNS 走隧道。NRPT 用固定 DisplayName `RustVPN tunnel DNS (<iface>)`
  记录，清理时按 DisplayName 查找并删除（也处理崩溃后没有 Name 记录的
  情况）。
- 分流：仅当 profile 显式配置 `dns` 时设置 Wintun 的 per-interface DNS，
  **不添加 NRPT**，系统 DNS 行为不变。
- `-no-host-dns`：完全跳过 DNS/NRPT（由调用方/容器管理）。
- 清理只在当前 Wintun DNS 仍等于我们设置的值时恢复旧值；若用户/其他程序
  已改动则跳过，避免覆盖。

### 6.5 IPv6

- MVP 不承载 IPv6。全隧道安装出站防火墙规则
  `New-NetFirewallRule -Direction Outbound -Action Block -Protocol Any
  -RemoteAddress @('2000::/3','fc00::/7')`。
  - 被阻断：全局单播（`2000::/3`，含公网/文档/大部分可路由前缀）与
    ULA（`fc00::/7`）。
  - 保留：loopback、`fe80::/10` 链路本地、`ff00::/8` 组播（ND/MLD 需要）。
  - 不阻断 IPv4，也不影响 IPv4 外层端点。
- 分流 profile 不安装该规则；IPv6 仍不承载，但没有静默全阻断。
- IPv6 外层端点（`remote`/`proxy` 解析为 IPv6）在 Windows 直接拒绝，因为
  全隧道会阻断 IPv6 且 M3 未实现 IPv6 防环。

### 6.6 崩溃恢复与清理

- 状态文件 `%ProgramData%\RustVPN\netstate.json`，可通过
  `RUSTVPN_STATE_DIR` 覆盖（仅绝对路径）；目录/文件 DACL 为
  `D:P(A;;FA;;;SY)(A;;FA;;;BA)`（SYSTEM + Administrators）。
- 内容：PID + 进程创建时间、接口、Wintun 索引、地址、路由（dest/ifindex/
  next-hop/metric/kind）、接口 metric 原值、DNS 原值/应用值、NRPT
  DisplayName、IPv6 防火墙规则名。
- 每完成一个可回滚操作就原子写状态（临时文件 + rename）。删除路由前重新
  `Get-NetRoute` 核对完整四元组，并用 `Get-NetAdapter` 校验接口名，检测
  Windows 接口索引复用（索引被其他适配器复用时跳过该接口上的路由/地址/
  DNS/metric）；DNS 只在仍等于应用值时恢复；metric 只在仍是设置值时恢复；
  NRPT/防火墙按唯一名称/DisplayName 删除。
- daemon 启动（Engine 启动路径）读取状态：owner 仍存活则跳过；已死亡则只
  清理记录项并删除状态文件。正常断开/停止清理后删除状态文件。
- 清理顺序：NRPT → DNS → 路由（先隧道、后防环）→ 地址 → 接口 metric →
  IPv6 防火墙规则（最后，保持 IPv6 保护直到其他状态已恢复）。

### 6.7 kill-switch / MSS 范围决策

- **kill-switch：Windows 明确不支持。** 用 Windows Filtering Platform 做到
  fail-closed 且崩溃后可恢复的复杂度与风险超出 M3；profile 校验和 guard
  都会拒绝 `kill_switch: true`，不会静默 fail-open。Linux nftables 实现不变。
- **MSS clamp：Windows 推迟。** 没有安全、稳定的系统级 API；连接时告警，
  状态里 `mss_applied=false`。v1 仍依赖双方一致的数值 wire MTU。
- 因此不声称 Windows 与 Linux 功能完全等价。

## 7. GUI 适配

> 下表已在 M4 实现并在 Windows RDP 实机验证；`bundle.active` 仍为 false。
> MSI/服务安装已在 M5 实现并实机验证，详见第 8 节、
> `windows-client-status.md` 2.9 / 3.4 / 2.10。

| 位置 | M4 实现 |
|---|---|
| Keyring | 目标平台特性：Linux Secret Service；Windows `windows-native`（Credential Manager） |
| 自启动 | Windows HKCU Run + `--minimized`；Linux XDG desktop 不变 |
| IPC | Unix socket / Windows 命名管道传输与事件流 |
| profile 目录 | `%LOCALAPPDATA%\RustVPN\profiles` + 受保护用户 ACL |
| 语言 | Windows `GetUserDefaultUILanguage`；Linux 环境变量；用户选择优先 |
| 文件权限 | Unix `0600/0700`；Windows 受保护 DACL |
| `daemon_info` | 显示 `\\.\pipe\rustvpn-clientd`、平台、profile 目录 |
| `tauri.conf.json` | Windows icon、WebView2 `downloadBootstrapper`、MSI/NSIS/resources 脚手架 |
| 服务端身份 | PID + 镜像路径 + Authenticode publisher，发口令前校验 |
| 托盘/单实例 | Tauri 插件；关闭到托盘/单实例已实机验证 |

“服务未安装/未启动/管道 ACL 拒绝”的提示已在 M4 的 IPC 错误映射和设置页
实现；M5 仍需验证标准用户对 LocalSystem 服务进程的查询权限。

---

## 8. 安装、签名与 CI（M5 已实现）

> 本节记录 M5 的最终实现；操作手册见
> [`windows-install.md`](windows-install.md)，打包细节见
> [`packaging/windows/README.md`](../packaging/windows/README.md)。

### 8.1 安装包

选择 **独立 WiX 3.14 项目**（`packaging/windows/rustvpn-client.wxs`），
不使用 NSIS，也不启用 Tauri bundler 的 WiX 模板。Tauri 模板拥有
Product/Feature/UpgradeCode 与打包资源布局；M5 需要服务注册、延迟自启、
失败恢复、组助手和升级停启顺序，独立 `.wxs` 更显式、可静态检查，并复用
同一 GUI exe。`bundle.active` 保持 `false`。

实现要点：

- per-machine 安装到 `Program Files\RustVPN\`，安装 GUI、daemon、
  `wintun.dll`、文档和许可证；不打包用户 profile/keychain。
- `ServiceInstall`：LocalSystem、own process、`--service`、自动启动；
- 服务启动方式与失败恢复：`ServiceInstall` 使用 automatic（非 delayed），
  安装期用 `sc.exe failure ... actions= restart/5000/restart/10000/restart/30000`
  配置失败恢复（Windows Installer 的 `ServiceConfig*` 表在实机触发 Error 1939）；
- `ServiceControl Stop="both" Start="install" Remove="uninstall" Wait="yes"`：
  升级/卸载前停止、安装后启动、卸载删除 SCM 项；
- 开始菜单快捷方式；桌面快捷方式由 `INSTALLDESKTOPSHORTCUT=1` 开启；
- 卸载停止服务，在删除文件前运行 `rustvpn-clientd.exe --cleanup` 清理
  deferred 反环路/netstate，然后删除文件/快捷方式/注册表/SCM；保留用户
  profile/钥匙串、`RustVPN` 组和 `%ProgramData%\RustVPN` 日志目录；
- 升级流程：停止服务 → 清理网络（daemon 正常停止路径）→ 替换文件 →
  重新创建/加入组 → 启动服务。

### 8.2 组、服务访问与进程查询

- 安装器在 `StartServices` 前运行 `installer\setup-group.ps1`，创建本地
  `RustVPN` 组并把 `[LogonUser]`（或 `RUSTVPN_USER`）加入；失败时回滚
  本次创建的组；服务模式缺少该组时拒绝启动，而不是回退到 INTERACTIVE。
- daemon 的 pipe DACL 使用该组；M2 的客户端 token 校验也在同一组上。
- daemon 启动时给同一组与 daemon 自身账户授予
  `PROCESS_QUERY_LIMITED_INFORMATION`（仅 0x1000），使 M4 GUI 能在发送
  口令前解析 LocalSystem 服务镜像并校验 Authenticode；不授予内存、句柄
  或终止权限。
- 标准用户需要重新登录以刷新包含组的 token；安装器/文档已说明。
- M5 修复了 `group_sid_bytes()` 保留 68 字节缓冲区的 bug：Windows 10 的
  `LookupAccountNameW` 成功时不总是更新 `cbSid`，导致 `ClientPolicy` 的
  字节比较拒绝合法组成员（pipe/进程 DACL 使用字符串 SID，不受影响）。
  现在用 `GetLengthSid` 截断，并有 Windows 回归测试。

### 8.3 Wintun 分发

- 只分发 Wintun 0.14.1 amd64；构建脚本校验 PE 架构和 SHA-256
  `e5da8447...dafce`。
- 附带 `wintun-LICENSE.txt`、`wintun-VERSION.txt`、`wintun-SHA256SUMS.txt`；
  许可证文本进入仓库，DLL 本身由构建机/CI 提供。
- `rustvpn-net` 默认绝对路径 `C:\Program Files\RustVPN\wintun.dll`，加载前
  再次校验哈希；服务工作目录为 System32 也不会误加载。

### 8.4 版本、升级与签名

- Cargo/Tauri `0.2.0-beta.1` → MSI `ProductVersion 0.1.99.0`；semver 保留在
  Product name、GUI、`HKLM\Software\RustVPN\Client\Version`、
  `docs\VERSION.txt` 与产物名。
- `MajorUpgrade AllowSameVersionUpgrades="yes"`：同数字版本的 beta 重建可用
  新 ProductCode 升级；更低版本被拒绝并提示先卸载。实际旧版本降级安装未
  在 M5 实机执行。
- `sign-artifacts.ps1` 支持证书存储指纹/PFX 环境变量；先签 exe，再签 MSI，
  并 `signtool verify /pa`。仓库不保存证书/私钥。无证书时验证产物确实
  未签名，写 `UNSIGNED.txt`/Product comments/`docs\SIGNING.txt`。
- 正式分发建议 EV/OV 证书 + RFC 3161 时间戳；未签名或新 OV 会触发
  SmartScreen 警告，企业应在部署策略中校验签名/指纹。

### 8.5 CI

- `.github/workflows/windows-client.yml` 独立 job（`windows-latest`）：
  安装 Rust/WiX 3.14、下载并校验 Wintun、运行客户端 crate 的
  check/clippy/test、构建未签名 MSI、用 `msiexec /a` + MSI 表 + dark 检查。
- 不安装 MSI/服务，不使用签名密钥；原型 `windows-shim.yml` 保持不变。
- 真实证书签名留给 release job；WebDriver UI 测试仍后置。

## 9. 分阶段实施计划

### Phase 0：技术验证（3–5 天）

1. Windows VM 上 `cargo check --workspace`，确认所有 Unix 阻塞点。
2. 最小 Rust 程序创建 Wintun 适配器，设置地址/网关/MTU。
3. 最小 ARP 垫片连通 Linux 服务端，`ping 10.88.0.1` 成功。
4. `windows-service` + 命名管道空壳跑通 SCM 启停。
5. 记录 Wintun DLL 版本、驱动安装行为、是否需要重启。

**验收：** Windows 能通过垫片 ping 通服务端 TAP 地址。

### Phase 1：平台层与垫片（1.5–2 周）

- `rustvpn-net` 增加 `TapConfig`，`Tap` 平台门面。
- 新增 `windows_shim.rs`：帧编解码、ARP、MTU、MAC。
- `engine.rs` 在 `TapClosed` 时重新打开适配器。
- `rustvpn-crypto::egd` 按平台 cfg。
- 修复 Windows 测试编译。

**验收：** 单元测试覆盖 ARP/帧/MTU；Windows 连接后双向 ping。

### Phase 2：服务与 IPC（1.5–2 周）

- `rustvpn-client-ipc` 传输抽象（Unix socket / named pipe）。
- `rustvpn-clientd` 服务模式、管道 DACL、客户端校验。
- Windows 隧道锁。
- 服务停止/启动清理流程。

**验收：** GUI 通过管道连接/断开；非授权用户无法连接；服务重启后状态正确。

### Phase 3：GUI 适配（约 1 周）

- profile 路径、keyring、autostart、语言、daemon 信息。
- 服务未安装/未启动的提示。
- Tauri Windows 托盘/单实例验证。

**验收：** 普通用户可完成连接、断开、保存口令、开机自启。

### Phase 4：网络配置（1–1.5 周，可与 Phase 2 并行）

- 防环 `/32`、默认/分流路由、DNS/NRPT。
- IPv6 阻断或告警。
- 崩溃残留清理。

**验收：** 全隧道不泄漏、断开恢复原路由/DNS、崩溃重启后自动恢复。

M3 已按第 6 节实现；kill-switch 明确拒绝、MSS 推迟。Windows 实机验收
（真实 Wintun + PowerShell）仍待执行。

### Phase 5：打包、签名与硬化（1–2 周）

- MSI/WiX、服务安装/升级/卸载。
- Wintun DLL 分发与哈希。
- Authenticode 签名。
- Windows CI。
- 安装/升级/卸载 VM 测试。

**验收：** 干净 Windows 10/11 安装后即可连接；卸载无残留。

---

## 10. 测试矩阵

### 10.1 单元测试

- 以太网帧解析、IPv4 total_length 截取、padding 处理。
- ARP 请求/应答、缓存过期、pending 队列上限。
- MAC 派生稳定性、本地管理位。
- MTU 换算（plain/noise/encless）。
- 畸形/超长/未知 EtherType 帧。
- 命名管道协议帧、Hello、超时。

### 10.2 Windows 集成测试

- Windows VM + Linux `rustvpn-server`：
  - ping 网关；
  - ping 服务端 LAN 主机；
  - DNS 解析、HTTP、TCP、UDP；
  - 大包/分片；
  - noise、encless（TCP）；
  - 断开后路由/DNS 恢复；
  - 服务重启、休眠唤醒、Wi-Fi/有线切换。
- MSI 安装 → 连接 → 升级 → 卸载。
- 卸载后检查服务、适配器、路由、DNS、防火墙规则。

### 10.3 安全测试

- 非授权用户连接命名管道被拒绝。
- 伪造管道服务端被 GUI 拒绝。
- 口令不落盘、不写日志。
- Wintun DLL 哈希校验。
- 隧道帧 fuzz（垫片解析不可信输入）。

---

## 11. 风险与待决策项

| 风险/决策 | 说明 | 建议 |
|---|---|---|
| 目标架构 | x64 还是同时 ARM64 | 先 x64，ARM64 后置 |
| 是否接受服务 + 驱动 | Wintun 需要管理员安装 | 必须接受；这是 Windows 的权限模型 |
| L2 是否硬需求 | 需要 VLAN/广播发现/非 IP 协议时 Wintun 不够 | 默认 Wintun；真 L2 再评估 tap-windows6 |
| 服务访问控制 | 专用组；禁止 INTERACTIVE 回退 | 专用本地组；服务模式缺组时 fail closed |
| 签名证书 | 无证书会被 SmartScreen 拦截 | 开发版可未签名；正式版准备 EV 证书 |
| IPv6 | 当前协议/profile 不支持 | 首版阻断/告警，后续单独立项 |
| 更新方式 | Tauri updater 不适合替换服务 | 走签名 MSI，关闭 Windows 自更新 |
| Wintun 许可 | 预编译 DLL 有独立许可 | 分发前做许可确认并附许可证 |
| 崩溃残留 | 路由/DNS 可能留在系统 | 服务启动清理 + 状态文件 |
| 休眠/网络切换 | Wintun/会话可能失效 | 引擎检测 TapClosed 后重新打开适配器 |

---

## 12. 相关代码与文档

- `crates/rustvpn-net/src/tap.rs`：TAP 门面与 Linux 实现
- `crates/rustvpn-net/src/peer.rs`：TAP ↔ 隧道数据泵
- `crates/rustvpn-client-core/src/engine.rs`：重连与网络配置安装时机
- `crates/rustvpn-client-core/src/netcfg/`：Linux 与 Windows 路由/DNS（`linux.rs` / `windows.rs` / `winplan.rs`）
- `crates/rustvpn-client-core/src/lock.rs`：隧道锁
- `crates/rustvpn-client-ipc`：IPC 帧与客户端
- `crates/rustvpn-clientd/src/main.rs`：Unix socket 服务端
- `crates/rustvpn-client-gui`：Tauri UI、托盘、keyring、autostart
- `docs/client-ui.md`：现有 Linux 客户端手册
- `docs/client-ui-plan.md`：跨平台客户端总体方案