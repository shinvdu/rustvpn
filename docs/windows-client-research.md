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

## 5. Windows 服务与 IPC

### 5.1 服务

- `rustvpn-clientd.exe` 用 `windows-service` 接入 SCM。
- 正式模式以 `LocalSystem` 运行；开发模式提供 `--console`。
- 服务名建议 `rustvpn-clientd`，显示名 `RustVPN Client Daemon`。
- 启动类型：Automatic (Delayed Start)。
- 失败恢复：重启服务。
- 停止流程：取消 Engine → 关闭适配器 → 恢复路由/DNS/NRPT/防火墙规则 →
  退出。
- 启动流程：先清理上次崩溃遗留的网络状态，再启动 IPC。

### 5.2 命名管道

- 管道名：`\\.\pipe\rustvpn-clientd`。
- 字节模式；`PIPE_REJECT_REMOTE_CLIENTS`。
- 4 字节大端长度 + JSON 的帧格式保持不变。
- 实例数上限与现有 IPC 一致（16）。
- Hello 超时、空闲超时、写超时沿用现有实现。
- `Subscribe` 连接只推送事件，不处理其他请求。

### 5.3 访问控制

- 用 `windows` crate 构造安全描述符，通过 Tokio
  `ServerOptions::create_with_security_attributes_raw` 创建管道。
- DACL 至少包含：
  - `SYSTEM`
  - `Administrators`
  - 一个专用本地组（推荐）或 `INTERACTIVE`（MVP）
- 服务端用 `GetNamedPipeClientProcessId` 获取客户端 PID，再校验用户/会话。
- GUI 在发送口令前必须验证服务端身份：
  - 用 `GetNamedPipeServerProcessId` 获取 PID；
  - 读取镜像路径，确认是已安装的 `rustvpn-clientd.exe`；
  - 校验 Authenticode 签名。
  否则本地恶意进程可以抢占同名管道骗取口令。

### 5.4 隧道锁

- 现有 `flock` 锁在 Windows 上改为命名互斥量：
  `CreateMutexW(L"Global\\RustVPNTunnel", ...)`。
- 服务以 SYSTEM 创建；CLI 如未来支持，再处理 `Local\` 回退。
- 元数据文件只用于显示占用者，不作为锁的真源。
- 崩溃时由 OS 释放互斥量。

---

## 6. Windows 路由、DNS 与恢复

### 6.1 防环

- 解析远端地址后，先添加远端 IP `/32` 主机路由，走原默认网关/接口。
- 再安装指向 Wintun 的路由。
- 绝不能先装默认路由再解析域名。

### 6.2 默认路由与分流

- 保存原始默认路由（网关、接口、metric）。
- 添加指向 Wintun 的默认路由（或 profile 指定的路由）。
- 断开时只删除自己添加的条目，不删除用户的原始路由。
- 建议使用 IP Helper API（`CreateIpForwardEntry2`）或 `netsh` 的封装；
  `netsh` 输出会本地化，不要依赖 stderr 文本判断成功与否。

### 6.3 DNS

- 全隧道：设置 Wintun 的 DNS；建议同时添加 NRPT 规则强制 DNS 走隧道，
  断开时删除。
- 分流：保留系统 DNS，除非 profile 明确指定。
- 保存每个接口的原始 DNS 配置，断开恢复。

### 6.4 IPv6

- 首版不承载 IPv6。
- 全隧道连接期间建议用 Windows 防火墙出站规则阻断 IPv6，断开时删除。
- 至少要明确告警“IPv6 流量不会进入隧道”，不能静默泄漏。

### 6.5 崩溃恢复

- 把本次添加的路由/DNS/NRPT/防火墙规则写入
  `%ProgramData%\RustVPN\netstate.json`，ACL 限制为 SYSTEM/Administrators。
- 服务启动时读取并清理残留，再允许新连接。
- 卸载时清理服务、适配器、防火墙规则；用户 profile 和钥匙串保留。

---

## 7. GUI 适配

| 位置 | 现状 | Windows 改动 |
|---|---|---|
| `gui/src/main.rs:305` | Secret Service keyring | 增加 `windows-native` 后端（Credential Manager） |
| `gui/src/main.rs:309` | XDG autostart 文件 | HKCU Run 或 `tauri-plugin-autostart` |
| `gui/src/main.rs:448` | Unix socket 客户端 | 命名管道传输 |
| `gui/src/main.rs:460` | 事件订阅 Unix socket | 命名管道事件流 |
| `gui/src/main.rs:502` | XDG/HOME profile 目录 | `%LOCALAPPDATA%\RustVPN\profiles` + 用户 ACL |
| `initial_language()` | 只读环境变量 | `GetUserDefaultUILanguage`，中文/俄语/其他 |
| `set_file_private` | Unix `chmod` | Windows ACL |
| `daemon_info` | 显示 socket 路径 | 显示管道名 |
| `tauri.conf.json` | `bundle.active=false` | 启用 MSI/NSIS、资源、WebView2 检查 |

托盘、单实例、关闭到托盘可以直接复用 Tauri 插件；需要测试“服务未安装/
未启动/版本不匹配”时的提示。

---

## 8. 安装、签名与 CI

### 8.1 安装包

推荐 **MSI（WiX）**，而不是 NSIS：

- 安装 GUI 与 `rustvpn-clientd.exe` 到 `Program Files\RustVPN\`。
- `ServiceInstall`：LocalSystem、自动延迟启动、失败恢复。
- `ServiceControl`：安装后启动，升级/卸载前停止。
- 把 `wintun.dll`（x64）放在服务同目录，固定版本并校验哈希。
- 卸载时停止服务、清理网络状态、删除服务；保留用户 profile/钥匙串。
- 升级流程：停止服务 → 清理网络 → 替换文件 → 启动服务。

### 8.2 Wintun 分发

- 只分发与目标架构匹配的 `wintun.dll`。
- 附带 Wintun 许可证文本。
- 固定版本和 SHA-256；发布前校验。
- 服务应使用绝对路径加载 DLL，避免服务工作目录为 System32 时找不到。

### 8.3 签名

- GUI、daemon、MSI 全部 Authenticode SHA-256 时间戳签名。
- 正式分发建议 EV 证书，降低 SmartScreen 误报。
- 开发版可以先不签名，但必须标明未签名。

### 8.4 版本与更新

- Cargo/Tauri 版本可以用 `0.2.0-beta.1`。
- MSI 的 ProductVersion 只接受数字，需要把 beta 映射为更低的数字版本
  （例如 `0.1.99.0`），否则会排在正式 `0.2.0` 之后。
- Windows 服务安装模式建议首版关闭 Tauri updater；
  更新走“检查新 MSI → 校验签名 → 提权安装”，不要用普通用户进程替换
  Program Files 中的服务文件。

### 8.5 CI

- 新增 `windows-latest` job。
- `cargo check/test` 覆盖 Windows target。
- 构建 MSI。
- 签名只在有证书的 release job 执行。
- WebDriver UI 测试可后置，首版先保证编译、单元测试和安装包结构。

---

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
| 服务访问控制 | 所有交互用户 vs 专用组 | 专用本地组；MVP 可先 INTERACTIVE |
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
- `crates/rustvpn-client-core/src/netcfg.rs`：Linux 路由/DNS
- `crates/rustvpn-client-core/src/lock.rs`：隧道锁
- `crates/rustvpn-client-ipc`：IPC 帧与客户端
- `crates/rustvpn-clientd/src/main.rs`：Unix socket 服务端
- `crates/rustvpn-client-gui`：Tauri UI、托盘、keyring、autostart
- `docs/client-ui.md`：现有 Linux 客户端手册
- `docs/client-ui-plan.md`：跨平台客户端总体方案