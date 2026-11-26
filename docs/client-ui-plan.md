# RustVPN 客户端 UI 调研与跨平台方案

> 日期：2026-11-26
> 对象：`~/rustvpn`（GoVPN 5.7 线兼容 Rust 实现）
> 目标：为**客户端**增加跨平台图形界面，支持连接管理、配置、状态与流量展示
> 方式：只读分析现有代码 + 方案调研；本文不修改代码
> 依赖版本：2026-11-26 通过 crates.io / GitHub 查询（tauri 2.12.7、wry 0.58.1、tray-icon 0.27.0、slint 1.19.1、eframe/egui 0.37.0、iced 0.14.0、dioxus 0.7.10、freya 0.5.4、floem 0.2.0、tun 0.8.15）
>
> **实现状态（2026-11-26，Linux MVP，分支 `feature/client-ui`）**：
> `rustvpn-client-core`（Profile/Engine/会话/Linux 路由）、`rustvpn-client-ipc`
> （UDS JSON + SO_PEERCRED）、`rustvpn-clientd`、Tauri 2 `rustvpn-client-ui`
> 已落地；CLI 改为复用 core 的会话代码，行为与参数不变。使用说明见
> [`client-ui.md`](client-ui.md)。本阶段偏差：仅 Linux；未做 Windows/macOS、
> 以太网垫片、自动更新、i18n、deb/rpm 打包；GUI 为无构建静态页面，
> 已内置托盘、单实例、登录自启动和系统钥匙串，并关闭 `withGlobalTauri`。
> 已补齐首轮 review 的 P1：首次握手成功后才安装路由/DNS、
> 远程地址只解析一次、全隧道 IPv6 blackhole、全隧道 DNS 必填且 `resolvectl`
> 失败即拒绝连接、daemon/CLI `flock` 隧道锁、GUI 默认接口改为 `rsvpn-gui`
> 并强化 profile 校验、修复重命名 profile 误删文件。已用本机 netns + 本地
> server 验证失败握手不断网、成功后的 default/防环/IPv6 路由、断开恢复、
> 双向流量与最终统计；GUI 连接/断开/错误状态与事件订阅正常；锁冲突与单测
> 通过。

---

## 0. 结论摘要

**推荐架构：无特权 UI + 有特权本地守护进程 + 共享 Rust 核心。**

- **桌面端 UI 选 Tauri 2**：复用现有管理端“无构建静态 HTML/JS + 原生 Canvas”的思路，Tauri 只是把页面装进系统 WebView，并提供托盘、单实例、自启动、通知、签名更新等成熟插件；Tauri 2 同时支持 Windows/macOS/Linux 与 iOS/Android。
- **客户端不能把隧道放进 GUI 进程**：创建 TAP/TUN、改路由、改 DNS 都需要 root/管理员权限。GUI 必须以普通用户运行，通过本地 IPC 控制一个最小化权限的守护进程（Linux systemd + capabilities、Windows 服务、macOS LaunchDaemon/SMAppService）。
- **跨平台最大的技术障碍不是 UI，而是链路层**：协议 `DATA` 是以太网帧（`docs/zh/protocol.md:81`），客户端必须有 L2 TAP。Linux 有原生 TAP；Windows 需驱动；macOS/Android/iOS 只有 L3。若要真正跨平台，必须实现一个**用户态以太网垫片（Ethernet↔IP shim）**，在 L3 适配器上补齐 MAC/ARP/DHCP（可选）/IPv6 ND（可选）。这是本方案的主要工作量与兼容性边界。
- **移动端不要强行复用桌面 UI**：Android/iOS 的 VPN 必须分别落在 `VpnService` / `NEPacketTunnelProvider` 中，且受应用商店与 Apple entitlement 约束。建议共享 **Rust 核心**，UI 用原生 Kotlin/Swift；如果坚持“一套 UI 代码”，Tauri 2 mobile 或 Slint 可以做到，但系统集成与上架风险更高。
- **退路**：如果项目坚持“纯 Rust、无 WebView、静态单二进制”，选 **Slint**（GPLv3 兼容、官方支持移动端）；如果只需要一个内部工具式的控制面板，**egui** 成本最低；如果连 GUI 工具链都不想引入，守护进程内嵌一个**本地 Web UI**（复用管理端模式）也能跨平台。

工作量粗估（1 名熟悉本仓库的工程师，不含 Apple/商店审核等待）：

| 范围 | 内容 | 估算 |
|---|---|---|
| MVP | 核心抽取 + 守护进程 + IPC + Linux TAP + Tauri 桌面 UI（托盘/配置/状态/流量） | 4–6 周 |
| 桌面三平台 | + Windows 服务/Wintun/垫片/安装签名，+ macOS daemon/utun/垫片/公证 | 再 10–14 周 |
| 移动端 | Android VpnService + iOS NE，共用核心与垫片 | 再 8–14 周 |

**本文不改动线协议、不改变默认构建，新增代码应像 `rustvpn-admin` 一样独立 crate、可选构建。**

**CLI 与 GUI 的关系**：保留 `rustvpn-client` 作为完全独立的命令行程序（不依赖守护进程、参数与行为不变）；GUI 是另一个独立程序，二者只共享底层库。运行时可同时存在，但同一时刻只能有一个活动隧道——用系统级锁协调，详见 4.8 节。

---

## 1. 现状分析

### 1.1 客户端结构

| 位置 | 现状 |
|---|---|
| `crates/rustvpn-client/src/main.rs` | 564 行单文件二进制：参数解析、口令读取、TAP 打开、握手、重连循环、信号处理全在 `main`/`run` 中 |
| `crates/rustvpn-net/src/tap.rs` | `Tap` 仅实现 Linux（`tun` crate `Layer::L2`，io_uring/epoll 双后端）；平台条件编译之外没有其他实现 |
| `crates/rustvpn-net/src/peer.rs` | `spawn_tcp` / `spawn_udp_peer` 接收 `Arc<Tap>`，收发以太网帧 |
| `crates/rustvpn-net/src/stats.rs` | `LiveStats` 原子计数器：`BytesIn/Out` 为线路字节，`BytesPayloadIn/Out` 为 TAP 载荷，可直接复用为 UI 流量来源 |
| `crates/rustvpn-client/src/main.rs:499-520` | 断线后 250 ms / 1 s 固定间隔重连，无指数退避与网络切换感知 |
| `Cargo.toml` | `tun = "0.7.13"`（最新 0.8.15）；`rustvpn-net` 仅对 Linux 引入 uring 依赖 |

客户端**没有库化**：没有 `Profile`、没有可编程的 `Engine`、没有事件流，GUI 无法直接驱动。必须先做一次“核心抽取”，但可保持 CLI 行为与参数不变。

### 1.2 协议约束（决定跨平台方案的关键）

- `DATA` 帧就是以太网帧（`docs/zh/protocol.md:81`），不是 IP 包。
- 服务端为每个 peer 创建独立 TAP（`docs/zh/configuration.md:101`），客户端顺序是“打开 TAP → 握手 → up 脚本”（`configuration.md:123`）。
- 服务端 `peers.yaml` 的 `iface`/`up` 脚本通常把 TAP 桥接或路由到真实 LAN；客户端看到的是一个标准 L2 网段。
- 这意味着：**任何没有 L2 TAP 的平台，都必须把 IP 包伪装成以太网帧**，否则服务端/对端交换机不认识。
- 不能改线协议来绕过：新增 L3 模式会破坏 GoVPN 5.7 互操作，且需要双端支持，超出“客户端 UI”的范围。

### 1.3 项目定位与文档的非目标

现有文档明确把 **GUI、Windows/macOS 支持**列为非目标：

- `docs/zh/design.md:14`：非目标包括“协议 v2、Windows/macOS、GUI、路由/NAT 管理……”。
- `docs/zh/faq.md:38-40`：“为什么不支持 Windows 或 macOS？封闭的专有系统……”
- `README.zh.md:42`：尚未实现 FreeBSD/macOS 移植打包，仅在 Linux 验证。

要做客户端 UI 与跨平台，必须**有意识地修订这些表述**，并把新能力放进独立 crate/可选 feature，避免改变服务端与默认 CLI 的承诺。这是产品决策，不只是技术决策。

### 1.4 客户端 UI 的合理需求

| 类别 | 需求 |
|---|---|
| 连接 | 选择配置、连接/断开、自动重连、显示状态与错误、取消连接 |
| 配置 | 新增/编辑/删除/导入/导出配置；口令安全保存；默认配置 |
| 状态 | 服务器地址、协议（UDP/TCP）、模式（plain/noise/encless）、MTU、分配地址、连接时长 |
| 流量 | 实时上下行速率、会话累计、线路/载荷字节、可选 24h 曲线 |
| 系统集成 | 托盘图标与菜单、开机自启、单实例、通知、深链接/文件关联导入 |
| 运维 | 日志查看/导出、版本、更新检查、DNS/路由模式、IPv6 开关 |
| 安全 | 口令不进日志、不进配置文件；UI 不执行任意脚本；最小权限 |

### 1.5 不可违背的约束

1. **不改线协议**，保持 GoVPN 5.7 互操作。
2. **默认构建不变**：新依赖（Tauri/Slint/WebKit、Wintun 等）只能进入可选 crate/feature。
3. **特权与 UI 分离**：GUI 不能以 root/管理员运行；不能接受任意 `up`/`down` 脚本（脚本以特权执行 = RCE）。
4. **GPLv3**：引入的 UI/驱动/库许可证需兼容（Tauri MIT/Apache、Slint GPLv3 选项可用；Wintun 预编译 DLL 有单独限制，见 5.2）。
5. **不泄露口令/身份**：协议身份（verifier id）可以展示，口令绝不落盘明文。

---

## 2. 跨平台的核心技术障碍

### 2.1 各平台链路层能力

| 平台 | 原生 L2 TAP | `tun` crate 现状 | 可行方案 |
|---|---|---|---|
| Linux | ✅ `/dev/net/tun` `IFF_TAP` | `Layer::L2` 已实现并在用 | 原生 TAP，保持现状 |
| FreeBSD | ✅ `/dev/tap` | crate 只支持 L3（源码显式拒绝非 L3） | 自写 ~100 行 TAP 或走 L3 垫片 |
| Windows | ⚠️ 需第三方驱动：`tap-windows6`（NDIS 6，L2，OpenVPN 驱动）或 `Wintun`（L3） | Windows 分支 L3=Wintun；L2 是 `todo!()` | **Wintun + 以太网垫片**（推荐）；需要真 L2 时才用 tap-windows6 |
| macOS | ❌ 无内置 TAP；`utun` 只有 L3；第三方 kext 已不可用 | 源码显式拒绝非 L3 | **utun + 以太网垫片**；App Store 路线用 NetworkExtension |
| Android | ❌ `VpnService` 只有 L3 | 支持传入 fd（建议升级到 0.8） | **VpnService fd + 以太网垫片** |
| iOS | ❌ `NEPacketTunnelProvider` 只有 L3 | 支持传入 fd（0.8+） | **NE fd + 以太网垫片** |

结论：**除 Linux（以及可选的 FreeBSD 原生 TAP）外，所有平台都需要以太网垫片。** 这决定了“跨平台”不是换一个 UI 框架就能完成的。

### 2.2 以太网垫片（Ethernet shim）要做什么

```text
┌──────────────────────────────┐
│  OS 路由/应用（ping、浏览器） │
└──────────────┬───────────────┘
               │ IP 包（L3）
┌──────────────▼───────────────┐
│ L3 适配器：Wintun / utun /    │
│ VpnService fd / NE fd        │
└──────────────┬───────────────┘
               │ IP 包
┌──────────────▼───────────────┐
│ 以太网垫片                    │
│  - 出站：IP → Eth(14B) → 隧道 │
│  - 入站：Eth → IP → L3 适配器 │
│  - ARP 应答/缓存（必需）      │
│  - DHCP 客户端（可选）        │
│  - IPv6 ND（可选）            │
│  - 广播/多播/MTU 处理         │
└──────────────┬───────────────┘
               │ 以太网帧
        rustvpn 隧道（DATA）
```

关键细节：

1. **MAC 地址**：用 verifier id 派生本地管理、单播、稳定的 MAC（如 `02:52:56:xx:...`）。同一身份只允许一个会话，因此碰撞可控；MAC 变化会导致服务端桥表重新学习，重连时保持不变更好。
2. **ARP**：客户端不在真实 L2 段上，必须：
   - 对服务端 LAN 发来的“谁是 <客户端 IP>”请求，用自己的合成 MAC 应答；
   - 出站时解析下一跳（同网段目的 IP 或网关）的 MAC；未命中时发 ARP 请求、排队数据包、超时丢弃；
   - 处理免费 ARP。
3. **地址配置**：垫片需要知道 `address/prefix`、`gateway`、`dns`、`routes`。**MVP 只支持静态配置**：移动端在 `VpnService.Builder`/`NEPacketTunnelNetworkSettings` 建立隧道后无法轻易重新 DHCP；桌面端可后续加 DHCP 客户端。
4. **IPv6**：需要 ND 应答（NS/NA）与 RA 处理，复杂度高。**MVP 默认关闭 IPv6**，并在 UI 中明确提示；后续再做双栈或 IPv6-only。
5. **广播/多播**：只接受发往本 MAC、广播、多播的帧；未知 ethertype（VLAN、PPPoE、AppleTalk 等）丢弃并限速记日志。
6. **MTU**：L3 适配器 MTU = 隧道有效载荷 − 14。例：`mtu: 1515` classic 的有效载荷上限 1514 → IP MTU 1500；noise 下 `mtu: 1515` 只有 1490 → IP MTU 1476，要跑满 1500 需把配置 MTU 提到 1540（与现有文档的 MTU 规则一致）。
7. **L2 专有能力会丢失**：依赖 Ethernet 广播发现、非 IP 协议、VLAN、L2 桥接的场景无法工作；这是移动端/Windows 方案必须写进文档的限制。

### 2.3 特权模型

| 平台 | 谁创建隧道 | UI 如何控制 | 推荐 |
|---|---|---|---|
| Linux | 系统服务（`rustvpn` 用户 + `CAP_NET_ADMIN`） | Unix socket + SO_PEERCRED | systemd 服务 + socket activation |
| Windows | 服务（LocalSystem；Wintun 创建适配器需管理员） | 命名管道（DACL） | Windows Service + 命名管道 |
| macOS | LaunchDaemon（root）或 NetworkExtension | Unix socket / NE 配置 | SMAppService.daemon；上架用 NE |
| Android | 应用进程内的 `VpnService` | 进程内调用 | 前台服务 + JNI |
| iOS | Network Extension 进程 | App → NE 配置 | NE provider + App Group |

**不要**用 setuid GUI、polkit 每次连接提权、或让用户 `sudo` 启动 GUI；这些要么危险，要么体验差。守护进程 + 受保护 IPC 是行业通行做法（Tailscale、OpenVPN GUI、WireGuard 均类似）。

### 2.4 路由 / DNS 管理

现有客户端把路由/DNS 全部交给用户写的 `up`/`down` 脚本（`configuration.md:103-134`）。GUI 不能接受用户提供的脚本以 root 执行。两条路：

1. **内置路由/DNS 管理（推荐）**：守护进程用平台 API 编程配置，并能保存/恢复原始状态。
   - Linux：rtnetlink（或 `ip` 命令，但优先 netlink）+ systemd-resolved/D-Bus；恢复 resolv.conf 要谨慎。
   - Windows：IP Helper API（`CreateIpForwardEntry2`/`SetInterfaceDnsSettings`），Wintun 也可用其 bindings 设置地址/DNS。
   - macOS：route socket + SystemConfiguration（`scutil`）或 NE 自带设置。
   - Android/iOS：`VpnService.Builder` / `NEPacketTunnelNetworkSettings`。
2. **受限脚本**：仅允许 root 拥有、不可由用户写入的系统脚本目录（类似服务端的 `-script-dir` 白名单），作为高级用户的逃生口。UI 只填路径，不编辑内容。

必备的防环措施：连接前先为**服务器外层地址**添加一条经原网关的 /32 主机路由，再安装默认路由；断开/崩溃后恢复。否则全隧道会把 UDP/TCP 外层连接也吞进隧道。

### 2.5 口令与 Argon2 的 UX

- 客户端只需 `Verifier::password_apply(password)` 派生签名密钥；口令本身绝不落盘（可存 OS keychain，由 UI 读取后经 IPC 传给守护进程，用完 `zeroize`）。
- 默认参数 `Argon2d m=4096, t=128, p=1` 在桌面约数百毫秒到 1 秒，低端手机可能数秒；UI 必须显示“正在派生密钥”，不能看起来卡死。
- 验证器（短格式）不是秘密，但属于身份标识；日志中可显示 id，不要打印口令。

### 2.6 分发与签名成本

| 平台 | 必须/建议 | 成本与门槛 |
|---|---|---|
| Linux | deb/rpm + systemd unit；GPG 仓库签名（可选） | 低；AppImage 无法安装系统服务，Flatpak 沙箱与系统服务冲突 |
| Windows | Authenticode 签名（EV 更利于 SmartScreen）；MSI/NSIS；服务安装 | 证书年费；驱动不需要自签（Wintun 已签名） |
| macOS | Developer ID 签名 + 公证；LaunchDaemon 安装需管理员 | Apple Developer $99/年；上架 App Store 需 NE entitlement（向 Apple 申请） |
| Android | 签名 APK/AAB；Play 的 VPN 应用声明与审核 | $25 一次性；Play 政策与隐私披露 |
| iOS | Apple Developer + NE entitlement + App Store/TestFlight | 审核与 entitlement 批复不可控 |

---

## 3. UI 方案对比

### 3.1 评估维度

- 桌面覆盖：Windows / macOS / Linux
- 移动覆盖：Android / iOS（是否需要同一套 UI 代码）
- UI 表现力与迭代速度
- 托盘、后台、通知、自启动、更新等系统集成生态
- 运行依赖与二进制体积（是否依赖系统 WebView/GTK）
- 攻击面（是否解析 HTML/JS）
- 构建复杂度（是否需要 Node/Android SDK/Xcode）
- 许可证与本项目 GPLv3 的兼容性
- 维护活跃度

### 3.2 候选一览

| 方案 | 桌面 | 移动 | 渲染 | 主要优势 | 主要代价 | 结论 |
|---|---|---|---|---|---|---|
| **Tauri 2** | ✅ Win/mac/Linux | ✅ iOS/Android | 系统 WebView（WebView2/WKWebView/WebKitGTK/Android WebView） | 生态最全：托盘、单实例、自启动、通知、深链接、签名更新；可复用管理端静态页面 | Linux 依赖 WebKitGTK 4.1 + AppIndicator；WebView 攻击面；移动仍要原生 VPN 服务 | **推荐（桌面）** |
| **Slint** | ✅ | ✅ Android/iOS | 自绘（GPU/软件） | 纯 Rust、编译型 UI、低内存、可静态化；GPLv3 选项可用；移动端官方支持 | 托盘/更新/自启动需自己拼；组件与生态较小；移动工具链仍需 Gradle/Xcode | **推荐（无 WebView 备选）** |
| **egui/eframe** | ✅ | ⚠️ Android（eframe），iOS 非一等 | GPU（glow/wgpu） | 纯 Rust、单二进制、上手快、画流量图方便 | 非原生观感；文本/IME/无障碍较弱；托盘、更新、自启动都要自己接 | 内部工具/开发者面板 |
| **Iced** | ✅ Win/mac/Linux/Web | ❌ | wgpu/tiny-skia | Elm 架构、类型安全、观感较好 | 无移动；托盘等系统集成弱；生态中等 | 桌面专用可选 |
| **Dioxus** | ✅（WebView/WGPU） | ✅ Android/iOS | WebView 或实验性 WGPU | Rust 写 UI、移动支持、全栈能力 | 桌面默认仍依赖 WebView；系统集成不如 Tauri；快速演进 | 想用 Rust 写 UI 且要移动时考虑 |
| **Freya** | ✅ 桌面（Skia） | ⚠️ Android（社区贡献） | Skia | 声明式、原生渲染 | 年轻、生态小；无成熟托盘/更新 | 不推荐作为首版 |
| **Floem** | ✅ 桌面 | ❌ | wgpu/CPU | 细粒度响应式、性能好 | 维护节奏慢（0.2.0, 2024-11） | 不推荐 |
| **gpui** | ✅（Linux 仍在完善） | ❌ | GPU | Zed 同款、性能强 | 无移动、生态早期、文档少 | 不推荐 |
| **本地 Web UI**（daemon 内嵌 HTTP） | ✅ | ✅（浏览器） | 浏览器 | 零 GUI 依赖、复用管理端代码、天然跨平台 | 无托盘/自启动；浏览器标签页体验；本地 HTTP 需认证 | 开发/兜底方案 |
| **TUI（ratatui）** | ✅ | ❌ | 终端 | 极小、SSH 友好、实现快 | 不是消费级 GUI | 运维/调试补充 |
| Electron | ✅ | ❌ | Chromium | 生态成熟 | 100MB+、内存高、攻击面大 | 拒绝 |
| Flutter | ✅ | ✅ | Skia | 移动/桌面一套 UI | 引入 Dart 工具链；Rust 核心需 FFI；体积大 | 不契合本项目 |
| React Native | ⚠️ 桌面靠社区 | ✅ | 原生/JS | 移动生态 | 桌面支持弱、JS 工具链 | 拒绝 |
| 原生 Kotlin+Swift | ✅ 各自 | ✅ | 原生 | 系统集成最好、上架最稳 | 多套 UI、工作量最大 | **移动端推荐形态** |

活跃度参考（GitHub，2026-11-26）：Tauri 约 11.3 万星、Slint 约 2.5 万、egui 约 3.2 万、Iced 约 3.2 万、Dioxus 约 4.0 万、Floem 约 4.3 千。星数不等于适配度，但能反映生态体量。

### 3.3 Tauri 2 细节

- 版本：`tauri 2.12.7`、`tauri-build 2.7.6`、`wry 0.58.1`。
- 支持 Windows 10+、macOS 10.15+、Linux（WebKitGTK 4.1）、iOS/iPadOS、Android 7/8+（以官方 README 为准）。
- **不需要 Node**：前端可以是纯静态 `index.html` + `app.js` + `app.css`，`frontendDist` 指向目录即可，和现有管理端一致；Tauri CLI 本身是 Rust 工具。
- 插件生态：`tauri-plugin-updater 2.14.1`（签名更新）、`single-instance 2.5.5`、`autostart 2.7.0`、`deep-link 2.6.3`、`notification 2.8.1`、`store 2.5.1`。
- 托盘：Tauri 内部使用 `tray-icon 0.27.0`；Linux 需要 `libayatana-appindicator3`（或 GTK3 AppIndicator），或启用 `ksni` 后端（纯 D-Bus，不依赖 GTK）。
- 安全：默认关闭远程内容，设置严格 CSP；禁用 `withGlobalTauri`；只允许本地资源；发布版关闭 devtools；Tauri capability 只授予必要命令。
- 移动：Tauri 2 的 Android/iOS 应用是“系统 WebView + Rust 逻辑”；**VPN 服务仍需 Kotlin `VpnService` / Swift NE extension**，通过 JNI/FFI 调用同一 Rust 核心。不要把“Tauri 支持移动”误解为“VPN 也自动跨平台”。

### 3.4 Slint 细节

- 版本 `slint 1.19.1`；官方定位从桌面到 Android/iOS 再到嵌入式。
- 纯 Rust、无 WebView、可用软件渲染；适合“单二进制、低依赖”的发行方式。
- 许可证：GPLv3 可直接用于本项目；若未来要闭源分发，可改用其 Royalty-free（需展示 attribution）或商业许可。
- 移动：有 Android backend 与 iOS 构建文档；但托盘、更新、自启动、深链接都要自行实现（`tray-icon`、`auto-launch`、`self_update` 等）。
- 适合的团队画像：更愿意写 `.slint` + Rust、不愿维护 HTML/JS/WebView 依赖、对 UI 视觉定制要求不是极高。

### 3.5 egui / Iced / Dioxus / 其他

- **egui**：`eframe` 官方支持 Web、Linux、Mac、Windows、Android；无 iOS 一等支持。适合做“连接面板 + 实时曲线 + 日志”的工具型 UI；无障碍与 IME 是短板。如果首版只面向技术用户/内部，1–2 周就能出可用界面。
- **Iced**：桌面 + Web，无移动；Elm 架构清晰，但系统托盘/更新生态薄。
- **Dioxus**：桌面默认 WebView（与 Tauri 类似）或实验性 WGPU；移动支持好；如果你希望 UI 也用 Rust 写，它是 Tauri 之外最现实的选择。但它的桌面系统集成插件不如 Tauri 成熟。
- **Freya/Floem/gpui**：不建议作为首版基础；生态、移动、维护节奏都有明显短板。
- **本地 Web UI**：守护进程内嵌 axum（沿用管理端技术），浏览器访问 `127.0.0.1`。零 GUI 依赖、立刻跨平台；但无托盘、无自启动、需要本地认证与 CSRF 防护，用户体验更像“设备管理页”而不是 VPN 客户端。

### 3.6 推荐结论

1. **桌面首选 Tauri 2**：它的系统集成生态与“无构建静态前端”最契合现有仓库；UI 只是外壳，隧道仍在守护进程。
2. **纯 Rust/无 WebView 备选 Slint**：如果团队明确拒绝 WebView 依赖，或希望 Linux 上不装 WebKitGTK，就选 Slint；移动端也能一套 UI，但系统胶水更多。
3. **移动端推荐原生壳**：Kotlin `VpnService` + SwiftUI `NE`，共用 Rust 核心与以太网垫片；上架、always-on、网络切换都更可控。
4. **若必须“一套 UI 覆盖桌面+移动”**：Tauri 2 mobile（Web UI 复用）或 Slint mobile（Rust UI 复用）二选一；都要接受原生 VPN 服务代码与商店审核。
5. **不推荐 Electron/Flutter/RN/KMP**：引入第二套语言与运行时，和本项目的 Rust/最小依赖取向冲突，收益主要是 UI 生态。

---

## 4. 推荐总体架构

### 4.1 分层

```text
┌─────────────────────────────────────────────┐
│ UI（Tauri / Slint / 原生 Kotlin/Swift）       │  普通用户权限
│  - 配置管理、托盘、状态/流量/日志、更新       │
└──────────────────┬──────────────────────────┘
                   │ 本地 IPC（UDS / 命名管道）
                   │ JSON-RPC + 事件流；peer 凭据鉴权
┌──────────────────▼──────────────────────────┐
│ rustvpn-clientd（守护进程 / 系统服务）       │  最小特权
│  - 连接状态机、重连、取消                     │
│  - 路由/DNS 配置与恢复                        │
│  - 平台适配器（Tap / L3Shim）                 │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│ rustvpn-client-core（库）                    │
│  - Profile、Engine、事件、统计快照            │
│  - 复用 rustvpn-crypto/proto/net             │
│  - 以太网垫片、ARP、DHCP/ND（可选）          │
└──────────────────┬──────────────────────────┘
                   │ 以太网帧
             rustvpn 隧道（UDP/TCP）
```

CLI 不经过 IPC/daemon：`rustvpn-client` 直接链接 `rustvpn-client-core`，在进程内运行 Engine（Linux 上仍用原生 TAP 与 `up`/`down` 脚本），因此可以完全独立运行。

移动端没有独立守护进程：`VpnService`/NE 进程就是特权边界，Rust 核心以 `cdylib`（Android JNI）或静态库（iOS C ABI）嵌入。

### 4.2 新增 crate 与职责

| crate | 类型 | 职责 | 是否默认构建 |
|---|---|---|---|
| `rustvpn-client-core` | lib | Profile、Engine、状态机、统计快照、`FrameDevice` 实现（垫片）、路由计划计算 | 否（被 CLI/clientd 依赖） |
| `rustvpn-client-ipc` | lib | IPC 消息类型、帧编解码、客户端/服务端骨架 | 否（被 GUI/clientd 依赖） |
| `rustvpn-clientd` | bin | 平台服务、IPC 服务端、特权适配器、路由/DNS、日志缓冲 | 否 |
| `rustvpn-client-gui` | bin（Tauri） | 静态 UI、托盘、设置、keychain、更新；只依赖 `client-ipc`，不链接加密/隧道代码 | 否 |
| `rustvpn-client-tui`（可选） | bin | SSH/运维用 TUI，复用核心 | 否 |

原有的 `rustvpn-client`（CLI）继续作为独立二进制存在：**只依赖 `client-core`，不依赖 daemon、IPC 或 GUI**；默认构建仍然包含它。

`rustvpn-net` 增加：

```rust
pub trait FrameDevice: Send + Sync {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize>; // OS → 隧道
    async fn send(&self, frame: &[u8]) -> io::Result<usize>;   // 隧道 → OS
}
```

`spawn_tcp` / `spawn_udp_peer` 从 `Arc<Tap>` 改为 `Arc<dyn FrameDevice>`；`Tap` 实现该 trait，Linux 行为不变。垫片也实现该 trait，放在 `rustvpn-client-core`，避免给服务端引入垫片依赖。

> 垫片需要“主动向隧道注入帧”（ARP 应答、DHCP 请求）。由于 `send()` 是“隧道→OS”方向，不能直接回写隧道；可在垫片内部维护一个出站队列，`recv()` 先从队列取帧再读 L3 适配器，或在 peer 循环中 `select!` 该队列。实现时优先选前者，接口改动最小。

### 4.3 Engine 状态机与事件

```rust
pub struct Profile {
    pub name: String,
    pub remote: String,
    pub proto: Proto,          // Udp | Tcp
    pub verifier: String,      // 短格式
    pub mtu: u16,
    pub timeout_secs: u64,
    pub timesync: i64,
    pub noise: bool,
    pub encless: bool,
    pub cpr_kib: u32,
    pub proxy: Option<String>,
    pub proxy_auth: Option<String>,
    // UI/垫片字段（不属于 CLI 参数）
    pub address: Option<IpNet>,     // e.g. 10.88.0.2/24
    pub gateway: Option<IpAddr>,
    pub dns: Vec<IpAddr>,
    pub routes: Vec<IpNet>,
    pub ipv6: bool,
}

pub enum State {
    Idle,
    Connecting,             // DNS/解析/握手
    Connected { since: Instant, session: SessionInfo },
    Reconnecting { attempt: u32, next_in: Duration, last_error: String },
    Disconnecting,
    Error { message: String },
}

pub enum Event {
    State(State),
    Traffic(TrafficSample), // 1 Hz：rx/tx 字节、速率、时长
    Log { level: LogLevel, line: String },
}

impl Engine {
    pub async fn run(
        self,
        commands: tokio::sync::mpsc::Receiver<Command>,
        events: tokio::sync::broadcast::Sender<Event>,
    ) -> anyhow::Result<()>;
}

pub enum Command {
    Connect { profile: Profile, password: zeroize::Zeroizing<String> },
    Disconnect,
}
```

实现要点：

- 把现有 `run_once` 的握手/TAP/重连逻辑搬进来；CLI 作为“进程内引擎 + 信号处理器”的薄壳，保持参数与行为不变。
- 重连改为指数退避 + 抖动（250 ms → 1 s → 2 s → … → 30 s），可被 `Disconnect` 立即打断；UI 显示下次重试时间。
- 流量采样：直接读 `LiveStats` 原子值；1 秒差值算速率。`BytesIn`=下行（收到的线路字节），`BytesOut`=上行。
- 日志：`tracing` + 环形缓冲（默认 2000 行）；UI `logs.tail` 拉取；发布版不记录口令、代理凭据。
- 口令在派生后 `zeroize`；签名密钥随会话销毁。

### 4.4 本地 IPC

- Linux/macOS：Unix domain socket，`/run/rustvpn-client/client.sock`（`RuntimeDirectory=rustvpn-client`，模式 0660，组 `rustvpn`）。
- Windows：命名管道 `\\.\pipe\rustvpn-control`，DACL 只允许 `Administrators` + 交互用户/特定组；服务端用 `GetNamedPipeClientProcessId` 校验客户端身份（可选签名校验）。
- 帧格式：4 字节大端长度 + UTF-8 JSON（单条 ≤ 1 MiB），JSON-RPC 2.0 子集。
- 认证：Unix 用 `SO_PEERCRED`（Linux）/`LOCAL_PEERCRED`（macOS）检查 uid/gid；Windows 用管道 ACL + 客户端 PID。**不要监听 TCP**。
- 方法（草案）：

```text
status                      -> { state, session, traffic, version }
connect(profile, password)  -> { ok }  // password 仅内存传输
disconnect                  -> { ok }
stats.subscribe             -> 事件流（state/traffic/log）
logs.tail(limit)            -> [{ts, level, line}]
shutdown                    -> 仅管理员/本用户
```

- 事件示例：

```json
{"event":"traffic","data":{"rx_bytes":1048576,"tx_bytes":524288,"rx_bps":82000,"tx_bps":12000,"uptime_s":312}}
{"event":"state","data":{"state":"connected","remote":"203.0.113.10:1194","proto":"udp","mode":"noise","mtu":1540}}
```

### 4.5 配置与密钥

配置建议用 YAML（与 `peers.yaml` 风格一致），由 UI 保存到：

- Linux: `~/.config/rustvpn/profiles/*.yaml`
- Windows: `%APPDATA%\rustvpn\profiles\*.yaml`
- macOS: `~/Library/Application Support/rustvpn/profiles/*.yaml`

```yaml
name: office
remote: vpn.example.com:1194
proto: udp
verifier: $argon2d$m=4096,t=128,p=1$<id>
mtu: 1540
noise: false
timeout: 60
address: 10.88.0.2/24
gateway: 10.88.0.1
dns: [10.88.0.1]
routes: ["0.0.0.0/0"]
ipv6: false
```

- **口令不写入 YAML**；保存到 OS keychain（`keyring 4.2`：Windows Credential Manager / macOS Keychain / Linux Secret Service）。
- 若用户不保存口令，每次连接弹窗。
- 导入/导出：同一 YAML 格式；可选 `rustvpn://` 深链接，但深链接携带 verifier 会被浏览器/历史记录泄露，**默认只导入不含口令的配置**并提示。

### 4.6 UI 信息架构

```text
主窗口
├─ 首页：连接卡片（状态/服务器/时长/上/下行速率/累计流量）、连接/断开
├─ 配置：列表、搜索、新增、编辑、导入/导出、设为默认、删除
├─ 设置：开机自启、启动时自动连接、通知、主题、语言、IPv6、日志级别、更新
├─ 日志：实时 tail、过滤、复制、导出
└─ 关于：版本、许可、第三方组件（Wintun 许可声明）

托盘
├─ 状态图标（已连接/未连接/连接中）
├─ 连接 / 断开 / 切换配置
├─ 打开主窗口
└─ 退出
```

连接流程：

1. 选择配置 → 若未保存口令则输入口令；
2. UI 通过 IPC `connect` 把配置 + 口令交给守护进程；
3. 守护进程派生密钥（显示“正在验证口令…”）、解析远端、安装防环路由、打开适配器、握手；
4. 成功 → 事件 `connected`；失败 → 显示原因（DNS/超时/口令错误/权限/路由冲突）；
5. 断线 → `reconnecting` 事件，托盘图标变化；用户可取消。

必须处理：

- 首次安装的权限说明（为什么需要安装服务/驱动）。
- 口令错误与网络错误的区分：握手失败可能是口令错、时间戳窗口、服务器不可达；用足够具体的错误文案。
- 关闭窗口 = 最小化到托盘（而非退出），退出时断开并恢复路由/DNS。
- 单实例：第二次启动只唤起已有窗口。
- 深色/浅色、HiDPI、键盘导航；i18n（至少中文/英文），复用管理端文本风格。

### 4.7 安全设计清单

- [ ] GUI 以普通用户运行；隧道只在守护进程/NE/VpnService 中。
- [ ] IPC 只监听 UDS/命名管道，校验 peer 凭据；不监听 TCP。
- [ ] UI 不提供脚本编辑/上传；`up`/`down` 仅允许系统目录、root 拥有、不可用户写；默认禁用。
- [ ] 所有 profile 字段在守护进程侧重新校验（地址、MTU、协议、verifier 格式、代理 URL），不信任 UI。
- [ ] 口令不落日志、不写入 profile；keychain 访问失败时要求重输。
- [ ] 路由/DNS 修改前保存原状态；崩溃重启时恢复；避免把用户锁在“无网络”状态。
- [ ] WebView 只加载本地资源，严格 CSP，禁用远程导航、devtools（发布版）、`withGlobalTauri`。
- [ ] 更新包签名验证（Tauri updater/minisign；Windows/macOS 平台签名）。
- [ ] 依赖审计（`cargo deny`/`cargo audit`）；Wintun DLL 固定版本并校验哈希。
- [ ] 隐私：日志不记录访问目的地；客户端 UI 只展示本地统计。

### 4.8 独立 CLI 与 GUI 的共存（关键约束）

**结论：代码、构建、安装都可以独立；运行时的“活动隧道”不能同时有两份，必须用系统级锁协调。**

#### 依赖关系

```text
rustvpn-crypto / rustvpn-proto / rustvpn-net        （共享，保持不变）
                    │
        ┌───────────┴───────────┐
        │                       │
rustvpn-client-core        rustvpn-client-ipc
（Engine/Profile/垫片）      （IPC 类型 + 客户端）
        │                       │
   ┌────┴────┐             ┌────┴─────┐
   │         │             │          │
CLI        rustvpn-clientd  GUI      （TUI 可选）
（独立）    （服务）        （只依赖 IPC，不链接加密/隧道）
```

- **CLI（`rustvpn-client`）**：保留现有参数、行为与独立部署能力；不依赖 daemon、IPC、GUI；默认构建包含。
- **`rustvpn-clientd`**：GUI 使用的特权服务；不依赖 GUI/Tauri。
- **GUI**：只依赖 `client-ipc`，不把 crypto/proto/隧道代码链接进 GUI 进程；即使 WebView 被攻破，也拿不到隧道代码与 root 权限。

独立构建：

```bash
cargo build --release -p rustvpn-client        # CLI；无 GUI/daemon 依赖
cargo build --release -p rustvpn-clientd       # 守护进程
cargo build --release -p rustvpn-client-gui    # GUI；运行时才需要 daemon
```

三者都不是 `default-members` 中新增的重依赖；CLI 仍是默认构建的一部分，GUI/daemon 需显式指定（或由打包脚本构建）。

#### 为什么需要守护进程，而不是 GUI 直接调用 CLI

桌面 GUI 以普通用户运行，无法创建 TAP/Wintun/utun、改路由、改 DNS。可选做法：

| 做法 | 结果 |
|---|---|
| GUI 直接 `pkexec`/`sudo` 启动 CLI | 每次连接弹系统授权、口令走 stdin、只能轮询 `/stats`、无法可靠取消/获取状态；仅适合原型 |
| GUI 内置引擎并以 root 运行 | 严重违背最小权限；WebView/UI 漏洞直接等于 root；**拒绝** |
| GUI 包内私有 helper 进程 | 可行，但本质上仍是“特权 helper + IPC”，只是不单独命名；不如复用 `rustvpnd` |
| **独立 daemon + IPC** | **推荐**：CLI/daemon/GUI 各自独立，共享核心；权限边界清晰 |

所以“只保留 CLI 和 GUI 两个程序、不要第三个进程”在桌面上做不到；GUI 要改系统网络，必然需要一个特权执行体。可以让安装包把 daemon 作为 GUI 的私有组件分发，但架构上仍是独立进程。

#### 运行时共存

同一台机器同时只有一个活动隧道（OS 路由是全局的）。在两个程序都装好的情况下：

1. 连接前先获取**全局锁**（在打开适配器、安装路由之前）：
   - Linux/macOS：`flock(LOCK_EX|LOCK_NB)`，路径 `/run/rustvpn-client/tunnel.lock`（安装器创建目录，`0770`，组 `rustvpn`；root 的 CLI 可直接写）。
   - Windows：命名互斥量 `Global\RustVPNTunnel`（SYSTEM 服务与管理员 CLI 均可创建）。
2. 锁文件写入元数据（JSON）：

```json
{"mode":"cli","pid":1234,"uid":1000,"remote":"vpn.example.com:1194","profile":"office","since":"2026-11-26T10:00:00Z"}
```

3. 第二个进程拿不到锁时**明确失败**，而不是抢路由：
   - CLI：`tunnel is already in use by rustvpnd (pid 1234, profile office); disconnect it first`
   - GUI：daemon 返回 `blocked_by_external`，界面显示“命令行会话正在使用隧道”，并展示 PID/配置名；**不要自动杀进程**。
4. 正常退出/崩溃时，`flock`/命名互斥量由 OS 自动释放；锁文件残留的元数据只能用于展示，不能作为“是否占用”的依据。
5. 锁只覆盖“连接”阶段；GUI 与 CLI 可以同时运行（GUI 在托盘显示“外部会话”，CLI 在终端运行），只是不能同时连。
6. 崩溃可能留下路由/DNS：daemon 启动时应检查并恢复自己保存的状态；CLI 的 up/down 语义保持现状（用户脚本负责幂等），文档需提示。

#### 配置与版本

- **CLI 继续以参数为准**，行为不变；可选增加 `-profile PATH`（加法功能）读取与 GUI 相同的 YAML，方便复用配置，但默认不改变任何现有行为。
- GUI 的 profile 是 GUI 自己的文件；daemon 不持久化 profile，只接受 IPC 传入并校验。避免“两套真源”互相覆盖。
- GUI 可以提供“导出为 CLI 命令”，方便高级用户在终端复现；但 GUI 不写 CLI 的 `up`/`down` 脚本。
- IPC 带协议版本；GUI 与 daemon 版本不匹配时给出明确错误；CLI 独立运行，不受影响。
- 开机自启只允许一侧自动连接：要么 daemon 的 system-service 自动连接，要么 GUI 启动时连接，不要两者都开；锁能防止冲突，但会产生令人困惑的报错。

#### 可选演进

- 未来可给 CLI 增加 `--control <socket>` 客户端模式，让它也能操作 daemon；默认仍独立运行，不引入硬依赖。
- 不建议把 CLI 直接改成 daemon（`--daemon` 内嵌 IPC）：会让 CLI 背上 HTTP/Tauri 之外的依赖与生命周期逻辑，违背“轻量独立”的目标；共享核心已经足够避免协议代码重复。

#### 服务端同理

服务端采用同一原则：`rustvpn-server`（数据面 CLI）与 `rustvpn-admind`（管理端）是两个独立程序，共享 `crypto/proto/net` + `rustvpn-control`；server 只提供本地控制 socket（`status/sessions/kick/reload`），不链接 axum/SQLite，管理端不持有 `CAP_NET_ADMIN`。即时踢线与配置立即生效仍由控制命令保证。详细设计见 [`admin-web-ui-plan.md`](admin-web-ui-plan.md) 的 0.2 节。

---

## 5. 平台落地方案

### 5.1 Linux（第一阶段）

- 适配器：沿用 `Tap::open`（L2，io_uring/epoll），不改数据面。
- 守护进程：systemd 系统服务，非 root 用户 + `CAP_NET_ADMIN`/`CAP_NET_RAW`；socket activation 可选。

```ini
# /usr/lib/systemd/system/rustvpnd.service
[Unit]
Description=RustVPN client daemon
After=network-online.target
Wants=network-online.target

[Service]
User=rustvpn
Group=rustvpn
RuntimeDirectory=rustvpn-client
RuntimeDirectoryMode=0750
StateDirectory=rustvpn
ExecStart=/usr/libexec/rustvpnd --socket /run/rustvpn-client/client.sock
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
```

- 路由/DNS：rtnetlink + systemd-resolved（若存在）；保存原默认路由/DNS，断开恢复；对服务器地址加 /32 例外路由。
- UI：Tauri（需要 `webkit2gtk-4.1` 与 `libayatana-appindicator3`，或 `ksni` 托盘后端）；deb/rpm 打包 + desktop 文件 + AppStream 元数据。
- 用户组：`rustvpn` 系统组；安装器把桌面用户加入组，重新登录后生效。
- 注意：AppImage 不适合安装 systemd 服务；Flatpak 需要额外的系统服务桥接，首版不建议。

### 5.2 Windows

- 适配器：**Wintun（L3）+ 以太网垫片**（推荐）；`tun` crate 已封装 Wintun 适配器创建、地址、DNS、MTU、metric。需要 `wintun.dll`（架构匹配）随应用分发。
- 若必须真 L2：改用 `tap-windows6`（NDIS 6，OpenVPN 驱动，最新 9.27.0/2024-03），但需要处理驱动安装、签名与兼容性，且与 macOS 方案不一致；不建议作为默认。
- 服务：`rustvpnd.exe` 以 LocalSystem 运行（Wintun 创建适配器需管理员）；用 `windows-service 0.8` 实现 SCM 集成，`service-manager 0.11` 或 MSI 完成安装/卸载。
- IPC：命名管道 + DACL；UI 与服务均可多用户，首版假设单用户桌面。
- 路由/DNS：IP Helper API；安装默认路由时先给服务器 IP 加原网关主机路由；Wintun 适配器 metric 设低；DNS 用 `SetInterfaceDnsSettings` 或 Wintun bindings，断开恢复。
- 签名/分发：MSI（WiX）或 NSIS；服务安装需管理员；应用与安装器 Authenticode 签名；EV 证书减少 SmartScreen 误报；Wintun DLL 需带其许可证声明。
- 许可注意：Wintun 预编译二进制许可是“随使用其 API 的软件一起分发”的有限许可，且禁止逆向/修改；与本项目 GPLv3 的兼容性建议做一次法务确认。若要完全避免，可改用 tap-windows6（GPLv2 驱动，但它是独立内核组件）或自研 L3 驱动（工作量与签名成本更高）。

### 5.3 macOS

- 适配器：`utun`（L3）+ 以太网垫片；`tun` crate 可创建 utun 并配置地址/路由。**没有可用的 L2 TAP**（tuntaposx 已停止，Apple Silicon/macOS 11+ 不可用）。
- 特权：
  - **推荐（非 App Store）**：`SMAppService.daemon`（macOS 13+）注册 LaunchDaemon，root 运行，UDS 通信；安装包/应用首次运行请求用户批准。
  - **App Store**：`NEPacketTunnelProvider` + `com.apple.developer.networking.networkextension` entitlement（`packet-tunnel-provider`），需 Apple 审批；NE 自动处理路由/DNS，UI 通过 `NETunnelProviderManager` 配置。
- 路由/DNS：route socket + SystemConfiguration；或交给 NE。防环：服务器外层地址走原网关。
- 签名/分发：Developer ID + 公证（notarization）+ hardened runtime；LaunchDaemon 用 pkg 或 SMAppService；App Store 路线需要 NE entitlement 与审核。
- 注意：不要尝试加载 kext；不要假设 `/dev/tap*` 存在；TAP 模式在 macOS 上应直接标记为“不支持”。

### 5.4 Android

- 适配器：`VpnService.Builder` 建立 L3 tun，拿到 fd；Rust 核心通过 JNI（`jni 0.22`、`ndk 0.9`）运行，`tun` crate 用 `raw_fd` 接管。
- 权限/生命周期：
  - Manifest 声明 `BIND_VPN_SERVICE`；用户首次连接必须经过系统 `VpnService.prepare()` 授权对话框。
  - 前台服务：Android 14+ 使用 `foregroundServiceType="systemExempted"`（官方明确 VPN 应用适用），并声明 `FOREGROUND_SERVICE_SYSTEM_EXEMPTED`；通知常驻。
  - 处理 Wi-Fi/蜂窝切换、Doze、Always-on VPN（系统设置）；`setUnderlyingNetworks` 告知计费网络。
- UI：Kotlin + Jetpack Compose 原生；或 Tauri/Slint 壳。移动端垫片只支持静态地址（DHCP 需重建隧道，MVP 不做）。
- 分发：APK/AAB；Play 的 VPN 应用需声明用途、隐私政策与安全审核；F-Droid 可分发纯 FOSS 构建（注意依赖许可）。
- 性能：ARM 上 Salsa20 走纯 Rust 回退（当前 AVX2 仅 x86_64），吞吐低于桌面；可在后续加 NEON 优化，但不阻塞首版。

### 5.5 iOS

- 适配器：`NEPacketTunnelProvider`（L3）+ 垫片；Rust 核心编译为静态库（`aarch64-apple-ios` + 模拟器 slice 的 XCFramework），通过 C ABI 供 Swift 调用。
- 配置共享：App Group 存放 profile；主 App 用 `NETunnelProviderManager` 安装/启动配置；口令经 NE 的 `providerConfiguration` 或共享 Keychain 传递。
- entitlement：`com.apple.developer.networking.networkextension` = `packet-tunnel-provider`；需要 Apple Developer Program 并申请；上架审核通过率与用途说明相关。
- UI：SwiftUI 原生主 App；NE extension 无 UI。
- 限制：后台唤醒、NE 内存上限（约十几 MB 到几十 MB，取决于设备）、IPv6 必须处理（iOS 网络多为 IPv6-only + NAT64）；**这意味着 iOS 的 IPv6 不能像桌面 MVP 那样简单关闭**，需要至少支持 IPv6 垫片或确保分配 IPv4 且网络允许。上架前必须实测。
- 分发：App Store / TestFlight；不能像桌面那样自由分发。

### 5.6 FreeBSD（可选）

- 原生 `/dev/tap` 可实现 L2；`tun` crate 不支持，需要自写约 100 行 ioctl 代码，或复用 L3 垫片。
- 无消费级 UI 需求；可只提供 daemon + CLI，UI 不纳入首版。

---

## 6. 以太网垫片设计（核心新增组件）

### 6.1 帧编解码

- 出站：`[dst_mac(6)][src_mac(6)][0x0800/0x86DD][IP]`；总长 ≤ 隧道有效载荷（`mtu - 1` classic；noise `mtu - 25`）。
- 入站：校验长度 ≥ 14；只接受 `dst == 本 MAC` 或广播/多播；IPv4/IPv6 去头后写 L3；ARP 交给 ARP 状态机；其余丢弃。
- 源 MAC 固定为派生 MAC；目的 MAC 由 ARP 缓存决定。广播用 `ff:ff:ff:ff:ff:ff`；IPv4 多播映射 `01:00:5e:...`，IPv6 多播 `33:33:...`。

### 6.2 ARP 状态机

```text
收到 ARP request(target_ip == my_ip) -> 回 ARP reply(my_mac)  [入队到隧道]
出站 IP，目的在子网内 -> 查 ARP(dst_ip)；否则查 ARP(gateway)
  miss -> 发 ARP request，包入 pending 队列（上限如 64 包/1s）
  hit  -> 构造 Eth 帧发送
收到 ARP reply -> 更新缓存（TTL 60s），flush pending
定期清理；处理免费 ARP（更新缓存）
```

- 使用 `pnet 0.35` 或手写 28 字节 ARP 解析；手写足够，依赖更少。
- 服务端桥可能对未知单播泛洪；正确应答 ARP 后即可定向转发。
- 广播 IP（DHCP/发现协议）默认透传给 OS（L3 适配器），但很多 OS 不会处理；记录限制。

### 6.3 DHCP（可选，第二阶段）

- 桌面端可实现最小 DHCP 客户端：Discover/Request/Renew，收到 ACK 后通过平台 API 重新配置 L3 适配器地址/路由/DNS。
- 移动端不建议：隧道建立时就必须给出地址；DHCP 需要重建隧道，体验与实现都复杂。移动 profile 使用静态地址。
- 若服务端 LAN 只有 DHCP、没有静态分配能力，则移动端无法使用——必须在兼容性文档中明确。

### 6.4 IPv6（可选，第二阶段）

- 需要：RS/RA（获取前缀/默认路由）、NS/NA（应答邻居请求）、可能的 DHCPv6。
- iOS 的 IPv6-only 网络使这项从“可选”变为“上架必需”；建议在移动端立项前单独做 spike，评估用 `smoltcp` 还是手写 ND。
- 在未实现前，桌面 profile 默认 `ipv6: false`；UI 明确提示“IPv6 流量不会进入隧道”，避免泄漏误解。若系统仍有 IPv6 默认路由，可能泄漏；守护进程应在连接期间禁用/降级 IPv6 路由（平台相关）。

### 6.5 其他边界

| 场景 | 行为 |
|---|---|
| 802.1Q VLAN 帧 | 丢弃 + 限速日志（L3 适配器无法表达） |
| 非 IP ethertype（PPPoE、ARP 以外的 L2 发现） | 丢弃 |
| 巨型帧 | 按 profile MTU 截断/拒绝；L3 适配器 MTU 与隧道一致 |
| 多播 | 接受常见 IP 多播 MAC；是否透传由策略决定，MVP 可丢弃 |
| 客户端 MAC 冲突 | 由 verifier id 派生，同一身份单会话，冲突概率可忽略 |
| 服务端桥 MAC 过滤/端口安全 | 可能阻断合成 MAC；需在服务端文档说明放行 |

---

## 7. 分阶段实施计划

### P0：核心抽取与 Linux MVP（4–6 周）

1. `rustvpn-net`：引入 `FrameDevice` trait；`Tap` 实现；peer 泛化；保持服务端/CLI 行为不变。
2. `rustvpn-client-core`：Profile、Engine、状态机、事件、统计快照、重连退避；把 `main.rs` 改为薄壳。
3. `rustvpn-clientd`：Linux systemd 服务、UDS JSON-RPC、SO_PEERCRED、路由/DNS 管理（netlink + resolved）、日志缓冲。
4. `rustvpn-client-gui`：Tauri 2 + 静态 HTML/JS/CSS（复用管理端设计语言）；首页/配置/日志/设置/托盘；keychain。
5. 打包：deb/rpm + systemd unit + desktop 文件；文档。

验收：CLI 行为完全不变；Linux 桌面可连接 GoVPN/RustVPN 服务端（UDP/TCP、noise、encless TCP、proxy）；断线重连、托盘、开机自启、口令保存/不保存均可用。

### P1：Windows（5–7 周）

1. 服务（`windows-service`）+ 命名管道 + DACL。
2. Wintun 适配器（复用 `tun` 0.8 或 `wintun-bindings`）+ 以太网垫片（ARP、静态地址、MTU）。
3. 路由/DNS + 防环；服务崩溃恢复。
4. MSI/NSIS + 服务安装 + 签名；Wintun DLL 许可声明。
5. Tauri Windows 构建、托盘、自启动、更新。

验收：Windows 10/11 x64 连接成功；ping/DNS/TCP/UDP/大包；休眠唤醒；服务重启恢复；卸载干净。

### P2：macOS（4–6 周）

1. `SMAppService.daemon` + UDS；utun + 垫片；路由/DNS。
2. Tauri macOS 构建、托盘、公证。
3. （可选）NE provider 路线 spike，评估 App Store 可行性。

验收：macOS 13+ 连接成功；系统代理/DNS 正常；公证通过；卸载移除 daemon。

### P3：移动端（8–14 周，视范围）

- Android：JNI + `VpnService` + 前台服务 + Compose UI + 垫片（静态地址）；Play/F-Droid 构建。
- iOS：NE extension + SwiftUI 主 App + 静态库 + IPv6 支持；entitlement 申请与 TestFlight。
- 建议先 Android 后 iOS；iOS 的 entitlement 与 IPv6 是最大不确定性。

### 工作量拆分（单平台参考）

| 工作项 | 人日 |
|---|---|
| 核心抽取 + 引擎状态机 | 8–12 |
| Linux daemon + IPC + 路由/DNS | 8–12 |
| Tauri UI（首页/配置/日志/设置/托盘） | 10–15 |
| 以太网垫片（IPv4 + ARP + 静态地址） | 10–15 |
| Windows 服务 + Wintun 集成 + 路由 | 10–15 |
| macOS daemon + utun + 路由 + 公证 | 10–15 |
| 移动端原生壳（每端） | 15–25 |
| 打包/签名/CI/文档 | 8–12 |

---

## 8. 测试与验收

### 8.1 单元/集成

- 垫片：用固定的以太网/IP 帧样本测试编解码、ARP 缓存、pending 队列、MTU 边界、异常长度/未知 ethertype。
- 路由计划：给定服务器地址、原默认路由、profile 路由，验证防环路由顺序与恢复逻辑。
- 引擎：用假 `FrameDevice` + 本地 UDP/TCP 回环测试状态机、取消、退避、统计差值。
- IPC：鉴权（其他 uid 被拒）、非法 JSON、超大帧、慢客户端。
- 密码学/协议：沿用现有差分测试，确保核心抽取未改变线格式。

### 8.2 端到端

- Linux：真实 TAP + rustvpn-server + GoVPN 5.7 服务端；UDP/TCP；noise/encless（TCP）；proxy；MTU 1500；断线重连；路由/DNS 恢复。
- Windows/macOS：Wintun/utun + 垫片；ping、DNS、HTTP、大包、休眠唤醒、网络切换（拔网线/Wi-Fi 切换）。
- 移动：Android 真机 + Wi-Fi/蜂窝切换 + 后台；iOS 真机 + IPv6-only 网络 + 上架前 TestFlight。
- 安全：非授权用户无法连接 IPC；UI 无法触发任意脚本；口令不出现在日志/配置文件；服务崩溃后路由恢复。

### 8.3 验收清单

- [ ] 默认 `cargo build` 不引入 GUI/服务依赖。
- [ ] CLI 参数、输出、退出码与现状一致。
- [ ] 不改变线协议；GoVPN/RustVPN 双向互操作。
- [ ] 三桌面平台可连接/断开/重连/托盘/自启动。
- [ ] 口令错误、服务器不可达、权限不足、路由冲突都有可读错误。
- [ ] 断开/退出/崩溃后网络恢复，无残留路由/DNS。
- [ ] 安装/卸载不破坏系统网络配置。

---

## 9. 风险与未决问题

### 9.1 主要风险

1. **L2/L3 语义差异**：垫片无法覆盖 VLAN、非 IP 协议、L2 发现、部分广播应用；必须在产品文档中明确“跨平台客户端是 L3 兼容模式，Linux 才是完整 L2”。
2. **Apple 生态门槛**：NE entitlement 审批、公证、App Store 审核都可能阻塞 iOS/macOS 上架；时间不可控。
3. **Windows 签名与驱动许可**：Authenticode 成本；Wintun 预编译许可的限制；若改用 tap-windows6 则驱动安装与内核攻击面增加。
4. **特权守护进程的攻击面**：UDS 解析、profile 校验、路由操作都要安全评审；不能接受任意脚本。
5. **Linux 桌面依赖**：Tauri 需要 WebKitGTK 4.1；最小化发行版/旧发行版可能缺包；Slint 可规避。
6. **项目定位冲突**：文档目前明确不支持 Windows/macOS/GUI；需要维护者决策并同步 README/FAQ/design。
7. **多用户/共享机器**：系统级隧道全局唯一；多用户同时连接、隐私可见性需要额外设计。
8. **移动端 IPv6**：iOS 网络环境可能强制 IPv6；垫片必须支持 ND/RA，否则无法上架/可用。
9. **维护成本**：每平台一套服务/打包/签名/测试，长期 CI 与发布负担显著。
10. **Argon2 性能**：低端移动设备可能数秒；需要进度反馈与超时策略。

### 9.2 需要产品决策的问题

1. 首批目标平台：仅桌面（Linux/Windows/macOS），还是包含移动？
2. 是否接受“桌面 Tauri + 移动原生”的两套 UI，还是必须一套 UI 代码？
3. 是否接受 Windows/macOS 安装系统服务/驱动（管理员权限）？还是只做用户态（则无法改全局路由，功能受限）？
4. L2 完整性是否是硬需求？若是，Windows 需 tap-windows6，macOS 无法满足。
5. 分发渠道：GitHub Releases、系统商店、F-Droid、App Store；是否愿意承担签名/审核成本？
6. 是否需要 kill switch、分流（split tunneling）、always-on？这些会显著增加路由/防火墙工作。
7. 是否允许高级用户使用系统级 up/down 脚本？默认应关闭。

---

## 10. 与现有代码的具体改动点（建议）

1. `Cargo.toml`：新增 `crates/rustvpn-client-core`、`crates/rustvpn-client-ipc`、`crates/rustvpn-clientd`、`crates/rustvpn-client-gui` 到 `members`；**`client-core`/`client-ipc`/`clientd`/`client-gui` 不加入 `default-members`**（与 admin 同理）；`rustvpn-client`（CLI）仍在 `default-members`，保持默认构建可用。
2. `crates/rustvpn-net/src/tap.rs`：提取 `FrameDevice` trait；`Tap` 实现；必要时把 `tun` 升级到 0.8.x（验证 Linux 行为与 io_uring 后端）。
3. `crates/rustvpn-net/src/peer.rs`：`Arc<Tap>` → `Arc<dyn FrameDevice>`；不改变帧处理逻辑。
4. `crates/rustvpn-client/src/main.rs`：保留参数解析与信号处理，内部改为调用 `rustvpn-client-core::Engine`；行为不变；可加 `-profile PATH`（可选、加法）。
5. 新增 `crates/rustvpn-client-core/src/{profile,engine,shim,route,lock}.rs`（`lock` 为全局隧道锁抽象）。
6. 新增 `crates/rustvpn-client-ipc/src/{message,frame,client,server}.rs`。
7. 新增 `crates/rustvpn-clientd/src/{main,ipc,platform/...}.rs`。
8. 新增 `crates/rustvpn-client-gui/`（Tauri：`tauri.conf.json`、`ui/index.html|app.js|app.css`、`src-tauri` 或单 crate 结构）。
9. CI：新增 Linux GUI 构建（安装 webkit2gtk/appindicator 依赖）、Windows 服务/UI 构建、macOS 构建（可选）；移动端构建单独 job；三平台 `-p rustvpn-client` 独立构建必须通过。
10. 文档：新增 `docs/client-ui.md`（用户手册）与本文；修订 `docs/zh/design.md`、`faq.md`、`README*.md` 中“不支持 GUI/Windows/macOS”的表述；说明 CLI 与 GUI 的互斥/共存。
11. 打包：`packaging/linux/{systemd,deb,rpm}`、`packaging/windows/{wix,nsis}`、`packaging/macos/{pkg,plist}`、`mobile/{android,ios}`；CLI 包不依赖 daemon/GUI 包。

---

## 11. 参考

- Tauri：<https://github.com/tauri-apps/tauri>（README：平台支持、WebView 架构）
- Tauri 系统托盘：<https://v2.tauri.app/learn/system-tray/>
- tray-icon：<https://github.com/tauri-apps/tray-icon>（Linux AppIndicator/KSNI 依赖）
- Slint：<https://github.com/slint-ui/slint>（平台、许可、Android/iOS）
- egui：<https://github.com/emilk/egui>（eframe 支持 Web/Linux/Mac/Windows/Android）
- Iced：<https://github.com/iced-rs/iced>（Windows/macOS/Linux/Web）
- Dioxus：<https://github.com/DioxusLabs/dioxus>（桌面/移动）
- `tun` crate：<https://github.com/meh/rust-tun>（Linux L2；Windows Wintun L3；macOS/FreeBSD L3）
- Wintun：<https://www.wintun.net/>、<https://github.com/WireGuard/wintun>（L3 驱动、预编译许可）
- tap-windows6：<https://github.com/OpenVPN/tap-windows6>（NDIS 6 L2 驱动，v9.27.0）
- Apple Network Extension entitlement：<https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension>
- Android VpnService：<https://developer.android.com/reference/android/net/VpnService>
- Android 前台服务类型（VPN 属 systemExempted）：<https://developer.android.com/develop/background-work/services/fgs/service-types>
- 现有协议/配置文档：`docs/zh/protocol.md`、`docs/zh/configuration.md`、`docs/zh/design.md`
- 现有管理端实现（可复用静态 UI/无构建思路）：`crates/rustvpn-admin/`、`docs/admin-web-ui.md`

---

## 附：一句话选型

- **要最快做出好看、跨桌面且能扩展到移动的外壳** → Tauri 2 + 守护进程 + 垫片。
- **要纯 Rust、无 WebView、单二进制** → Slint + 守护进程 + 垫片。
- **只想先有个能用的控制面板** → egui 或本地 Web UI。
- **移动端要上架、要 always-on** → 原生 Kotlin/Swift + 共享 Rust 核心，别指望 UI 框架解决 VPN 集成。