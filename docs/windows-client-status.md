# Windows 客户端开发状态

> 最后更新：2026-11-27
> 分支：`feature/client-ui`
> 状态：M1（核心接入）与 M2（服务 + 本地 IPC）已完成并提交；M3（网络配置）
> 代码已在工作区实现，尚未提交，Windows 实机验收待执行
> 相关文档：
> - [Windows 客户端调研与方案](windows-client-research.md)
> - [Windows 开发环境与依赖](windows-dev-environment.md)
> - [P0 决策与修复状态](p0-decision-review.md)
> - [客户端桌面 UI](client-ui.md)

---

## 0. 一句话状态

Windows 端已经完成 **开发环境 + Wintun/以太网垫片原型**，并完成了 **M1 核心接入**（`9bc1466`）和 **M2 服务 + 本地 IPC**（`8cef993`）：命名管道传输、DACL、客户端身份校验、Windows SCM 服务外壳、命名互斥量隧道锁，以及 `--console` 端到端 IPC 测试。**M3 网络配置**已在工作区实现（未提交）：Wintun 地址/路由、防环 `/32`、默认/分流路由、per-interface DNS + NRPT、全隧道 IPv6 泄漏阻断、崩溃恢复状态文件与启动清理。
> 说明：M3 的 Windows 实机连接/清理验收尚未执行（当前开发机无可用 Windows SSH 主机）；Linux 单元测试、Windows 目标编译与 clippy 已通过。GUI 平台适配（M4）、MSI/服务注册（M5）仍未开始。

---

## 1. 当前基线

| 项 | 状态 |
|---|---|
| 代码分支 | `feature/client-ui` |
| 最近提交 | `8132f24 docs(windows): record M2 verification`（M2） |
| 前一个提交 | `8cef993 feat(windows): add service, named-pipe IPC and tunnel lock`（M2） |
| M2 验证 | Windows 实机命名管道 E2E、DACL、隧道锁测试通过 |
| 远端 | 领先 `origin/feature/client-ui`，**未推送** |
| 主仓库剩余改动 | M3 网络配置（未提交、未在 Windows 实机验收）；M2 已提交 |
| Windows 原型位置 | `prototypes/windows-shim/`，独立 crate，不加入 workspace |
| Windows CI | `.github/workflows/windows-shim.yml`，只测原型 |
| 原型状态 | Phase 0 参考实现，不是生产代码 |

---

## 2. 已完成

### 2.1 Windows 开发环境

在 Windows 10 Pro 19045 x64 上完成，Ubuntu 侧 AI agent 通过 SSH 操作。

| 组件 | 版本 / 路径 |
|---|---|
| Rust | 1.100.0 stable，`x86_64-pc-windows-msvc` |
| Cargo / Rustup | `D:\rustvpn-dev\cargo`、`D:\rustvpn-dev\rustup` |
| VS Build Tools | 2022 17.14，`D:\BuildTools`，MSVC v143 + Windows 11 SDK 22621 |
| WebView2 | 158.0.4370.33 |
| WiX Toolset | 3.14.1 |
| Tauri CLI | 2.12.6 |
| Wintun | 0.14.1 x64，`wintun.dll` + 许可证 + SHA-256 |
| Git | 2.53.0 |

已验证：

- MSVC 链接器 + Windows SDK 能编译真实项目（`link-check`）
- 无需 Node.js（前端是静态 HTML/JS）
- 未重启、未改 UAC/Defender/防火墙/VPN/DNS
- C: 空间较紧，构建 target 必须放 D:

### 2.2 Windows Phase 0 原型（`prototypes/windows-shim/`）

已完成并经 Windows 实机验证：

- 以太网帧编解码：IPv4、padding、VLAN/IPv6/未知 EtherType 丢弃
- ARP：请求/应答、缓存 TTL、pending 队列、重试、免费 ARP
- 合成 MAC：`02:52:56:xx:xx:xx`
- 数字 wire MTU → inner IP MTU / IPv4/IPv6 MSS
- 有界队列、drop 计数、无不可信长度导致的 panic/越界
- `ShimPump`：Wintun 阻塞读放独立线程，锁内不做设备 I/O
- Wintun 适配器：创建/配置/关闭、测试网段约束、DLL 哈希校验
- Windows 烟测：`RustVPN-Spike` + `10.88.0.0/24`，UDP 往返 PASS
- 关闭后适配器自动移除，默认路由/其他网卡未变

测试结果：

- Linux：74 单元 + 3 golden tests，`--self-test` 84/84
- Windows：同套测试通过，Wintun 烟测 PASS
- 原型 review 发现的 3 个 P1、9 个 P2 已修复

### 2.3 主仓库前置能力（Windows 集成依赖）

以下 P0 能力已落地，但 Windows 尚未接入：

- `mtu` 是双端数值契约；TAP 接口 IP MTU 由 `max_payload - 14` 推导
- IPC `PROTOCOL_VERSION=2`
- `status --json` schema 与事件流
- kill-switch、MSS clamp、声明式服务端 TAP、diff reload、keepalive、时间重协商
- 文档已更新 en/zh/ru

### 2.4 主仓库 P0 残留（已提交 `e8acf3b`）

- Tauri `save_profile` 增加后端 MTU 校验；`0`/`auto` 不再被静默序列化
- 旧 `mtu:auto` profile 通过 `profile_errors` 在 GUI 报告，不再静默消失
- 声明式 TAP 崩溃 adopt 时清理旧地址/路由/DNS
- peer 删除/重载时剪除对应 declarative guard
- `up` + `network:` 语义统一：`network:` 拥有 TAP 创建；脚本需自行标记才可创建
- P0-1/P0-2/P1-2 在 `docs/p0-decision-review.md` 标记为 CLOSED

> 这些改动已提交为 `e8acf3b`，仍待最终复审；复审通过后再开始 M1。

### 2.5 P2 与崩溃恢复修复（已提交 `b192d83`）

- kill-switch 崩溃后 fail-closed，但保留可恢复路径
- 每次主机名解析前重新打开临时 DNS 放行；握手成功后被完整规则替换
- 修复崩溃重启后握手失败导致的 DNS 死锁
- 重连后保留 `mss_applied`/`kill_switch_applied`
- 服务端显式越界 MTU 改为拒绝，不再 clamp
- 推导 TAP IP MTU <68 在触碰网络前拒绝
- CLI keepalive 统一为 10/25/3600 秒
- 服务端 `status --json` 文档拆分 common/client/server 字段
- 218+ 测试通过；最终针对性复审仍待完成

### 2.6 M1 核心接入（已提交 `9bc1466`）

- `rustvpn-net` 增加平台无关 `TapConfig` 与 Windows Wintun 后端，`Tap` 门面在
  Windows 走 Wintun L3 + Ethernet 垫片，Linux TAP 行为不变
- 以太网帧/ARP/MAC/IPv4/MTU 校验与有界异步 `ShimPump`；Engine 接线
- `rustvpn-crypto::egd` 按平台 cfg
- Windows 目标可编译；路由/DNS/NRPT 仍属 M3

### 2.7 M2 服务 + 本地 IPC（已提交 `8cef993`）

- `rustvpn-client-ipc`：新增 `transport` 抽象（Unix socket / Windows 命名管道），
  帧格式、Hello、超时、事件订阅、`PROTOCOL_VERSION=2` 不变
  - Windows 管道 `\\.\pipe\rustvpn-clientd`，字节模式、
    `PIPE_REJECT_REMOTE_CLIENTS`、首次实例标志、17 实例上限
    （16 连接 + 1 监听）
  - `Client`/`EventStream` 改为泛型 `AsyncStream`，保留
    `connect(path)`/`subscribe(path)` 公共 API；新增 `connect_stream`/
    `subscribe_stream` 与 `Client::server_pid()`（Windows，供 M4）
  - Windows 路径解析：裸名称自动展开为 `\\.\pipe\<name>`；Unix 路径逻辑不变
- 管道安全：显式 SDDL DACL（SYSTEM + Administrators + INTERACTIVE 或
  `-pipe-group` 指定的本地组），无 null/Everyone DACL；服务端在 Hello 前用
  `GetNamedPipeClientProcessId` + token 校验同用户/INTERACTIVE/管理员/
  专用组，deny-only 组不计入
- `rustvpn-clientd`：
  - Windows `--console`（前台）与 `--service`（SCM 分发器）；LocalSystem、
    无 GUI；STOP/SHUTDOWN 取消与 SIGTERM 相同的 shutdown token
  - 服务日志到 stderr + `%ProgramData%\RustVPN\clientd.log`（可覆盖）
  - Linux kill-switch clean marker/firewall 启动清理保持原样；Windows 侧
    在 M3 前不做防火墙清理
  - 新增 `--pipe-group`；服务模式下若存在本地 `RustVPN` 组则自动使用
- 隧道锁：Windows 命名互斥量 `Global\RustVPNTunnel`，专用线程获取/释放、
  崩溃由 OS 释放；非提权开发场景回退 `Local\`；Linux `flock` 不变
- 验证：
  - Linux：`cargo fmt --all`、`cargo clippy --workspace --all-targets -D warnings`、
    `cargo test --workspace`（含新增 console EXE 端到端测试）通过
  - Windows target：`cargo check` / `cargo clippy --all-targets`（`x86_64-pc-windows-msvc`）
    对 `rustvpn-client-ipc`、`rustvpn-clientd`、`rustvpn-client-core` 通过
  - Windows 实机：74 tests 通过（client-core 48、client-ipc 20+2、
    clientd 3+1），含命名管道 E2E、DACL、命名互斥量锁
  - 未执行：SCM 服务注册/启停（属 M5）、第二用户越权连接测试

### 2.8 M3 网络配置（工作区实现，未提交）

- **平台拆分**：`rustvpn-client-core/src/netcfg.rs` 拆成 `netcfg/mod.rs` +
  `netcfg/linux.rs` + `netcfg/windows.rs` + `netcfg/winplan.rs`；公共
  `NetworkGuard::install/remove/mss_applied/kill_switch_applied` 不变，Linux
  实现原样保留。`engine.rs` 在 Windows 也安装 guard，不再跳过 M3。
- **Wintun 地址**：适配器只在打开时设置派生接口 MTU（不是 wire budget）；
  profile 地址/前缀在**握手成功后**由 guard 用 `New-NetIPAddress` 安装，失败
  握手不会提前添加 on-link 路由或改 DNS。网关作为 Ethernet 垫片的合成
  ARP 下一跳；Wintun 是 L3，OS 路由使用 on-link `NextHop=0.0.0.0`，避免
  Windows 对 Wintun 无法应答的网关做 ARP。
- **路由**：安装任何隧道路由前，先用 `Find-NetRoute` 找外层端点的原始
  路径并添加 `/32` 防环主机路由。全隧道把 Wintun 接口 metric 降到 1、添加
  `0.0.0.0/0`（route metric 0）；分流路由 metric 50。原默认路由不删除、
  不修改；若已有等价 owned 路由则幂等，若冲突则失败并回滚。多个默认路由
  时按“接口 metric + route metric”检查，若其他 connected 默认路由仍会更优
  则拒绝宣称全隧道。
- **DNS/NRPT**：全隧道设置 Wintun per-interface DNS 并添加
  `Add-DnsClientNrptRule -Namespace '.'`，记录旧 DNS 和 NRPT DisplayName，
  断开恢复/删除；分流仅在 profile 显式配置 DNS 时设置，不加 NRPT。
  `-no-host-dns` 保持不管理 DNS 的语义。
- **IPv6**：全隧道出站阻断 `2000::/3`（全局单播）和 `fc00::/7`（ULA）
  防火墙规则；loopback、`fe80::/10` 链路本地与 `ff00::/8` 组播保留给 ND/
  本地服务。分流不添加该规则。IPv6 仍不承载；IPv6 外层端点直接拒绝。
  文档明确“被阻断的是全局单播与 ULA，不是所有 IPv6”。
- **效率/安全**：所有命令走绝对路径
  `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`，参数由类型化
  IP/索引/metric 和经过校验的名称构造并单引号转义；不经 `cmd.exe`/PATH。
  PowerShell 超时 30s。
- **崩溃恢复**：本次添加的地址/路由/DNS/NRPT/防火墙/接口 metric 记录到
  `%ProgramData%\RustVPN\netstate.json`，目录和文件 DACL 限制为 SYSTEM +
  Administrators（SDDL `D:P(A;;FA;;;SY)(A;;FA;;;BA)`）。状态文件含 PID +
  进程创建时间；daemon 启动时只清理“owner 已死亡”的已记录项，每项删除前
  重新核对，并用 `Get-NetAdapter` 的接口名检测 Windows 接口索引复用（索引
  被其他适配器复用则跳过该接口上的路由/地址/DNS/metric）。正常断开/停止
  清理后删除状态文件。清理顺序：NRPT → DNS → 路由（先隧道后防环）→ 地址 →
  接口 metric → IPv6 防火墙规则（最后，保持泄漏保护）。安装地址前还会拒绝
  已存在的同网段路由，避免静默抢占 LAN 子网。
- **kill-switch / MSS**：Windows kill-switch 继续**拒绝**（profile 校验与
  guard 双重拒绝），因为尚未做到 fail-closed + 可恢复；MSS clamp 推迟，
  连接时告警，`mss_applied=false`，不声称 Windows 与 Linux 等价。
- **测试**：`winplan` 在 Linux 上编译并测试（fake 命令/系统模型），覆盖防环、
  默认/分流路由、相同/冲突路由、DNS/NRPT、IPv6 阻断、清理、崩溃恢复、
  失败注入回滚、无状态 no-op、活 owner 跳过、kill-switch/IPv6 外层拒绝。
  `cargo test --workspace`、`cargo clippy --workspace --all-targets -D warnings`
  与 `cargo check/clippy --target x86_64-pc-windows-msvc` 通过。
- **未执行**：Windows 实机的真实 Wintun + PowerShell 路由/DNS/NRPT 冒烟、
  断线/崩溃清理验收；本轮无可用 Windows SSH 主机（本地 `win11` KVM 无登录
  凭据），只做编译/单测。已提供只读的
  `windows_read_only_probe`（`#[ignore]`）供后续在 Windows 上校验
  PowerShell 脚本/JSON 契约且不改网络状态。未触碰宿主机 VPN/NAT/防火墙，未重启。

---

## 3. 后续与未完成项

### 3.1 核心集成（M1 已完成）

`TapConfig`/平台门面、`Tap` ↔ shim、异步桥接、Engine 接线与共享 MTU/Mode
已在 `9bc1466` 完成。地址/网关/DNS、路由与 IPv6 阻断已在 M3 工作区实现，
Windows 实机验收待做。

### 3.2 Windows 服务与 IPC（M2 已实装，剩余项）

| 项 | 状态 |
|---|---|
| Windows 服务 | 🟡 代码完成；SCM 启停实机验证、服务注册/失败恢复策略属 M5 |
| 命名管道 / 帧 | ✅ Linux 与 Windows 实机端到端测试通过 |
| 管道 DACL | ✅ SYSTEM + Administrators + INTERACTIVE / `-pipe-group` 专用组；Windows 测试通过 |
| 客户端身份校验 | ✅ PID + token 组校验；GUI 侧服务端签名校验属 M4 |
| IPC v2 | ✅ 帧/Hello 不变 |
| 隧道锁 | ✅ `Global\RustVPNTunnel`，崩溃由 OS 释放；Windows 测试通过 |
| 服务停止清理 | ✅ 与 Linux 共用 shutdown 路径；Windows 清理由 M3 guard + 启动/停止清理实现 |
| 多用户/会话策略 | ⬜ M5 安装器创建 `RustVPN` 组并加用户；当前默认 INTERACTIVE |

### 3.3 Windows 网络配置（M3 已实现，实机验收待做）

| 项 | 状态 |
|---|---|
| Wintun 地址/网关/DNS | ✅ 地址/DNS 在握手后由 guard 安装；网关作为垫片下一跳；无任意脚本 |
| 防环 `/32` | ✅ `Find-NetRoute` + `/32` 主机路由，先于任何隧道路由 |
| 默认/分流路由 | ✅ owned 幂等、冲突失败、metric 1/0 与 50、只删记录项 |
| DNS/NRPT | ✅ 全隧道 per-interface DNS + NRPT；分流仅显式 DNS；恢复旧值 |
| IPv6 | ✅ 全隧道阻断 `2000::/3` + `fc00::/7`；分流不阻断；IPv6 外层拒绝 |
| DHCP | ⬜ MVP 静态地址；DHCP-only 服务端网络仍需另行设计 |
| 休眠/切网 | ⬜ M6 检测 `TapClosed`/重开适配器 |
| 崩溃残留 | ✅ `%ProgramData%\RustVPN\netstate.json`（SYSTEM/Administrators）+ 启动清理 |
| kill-switch | ⛔ Windows 明确拒绝（未做到 fail-closed 可恢复） |
| MSS clamp | ⚠️ 推迟；告警且 `mss_applied=false` |

### 3.4 GUI 平台适配

| 项 | 说明 |
|---|---|
| profile 目录 | `%LOCALAPPDATA%\RustVPN\profiles` + 用户 ACL |
| 钥匙串 | `keyring` + `windows-native`（Credential Manager） |
| 开机自启 | HKCU Run / `tauri-plugin-autostart` |
| 系统语言 | `GetUserDefaultUILanguage` |
| daemon 信息 | 显示管道名，不再显示 Unix socket |
| 文件权限 | Windows ACL 替代 Unix chmod |
| 托盘/单实例 | Tauri 插件复用，需 Windows 实机验收 |
| 安全开关可见性 | kill-switch/MSS/rekey 只读状态或开关，不能隐藏 |
| 更新 | 服务安装模式下关闭 Tauri 自更新，走签名 MSI |

### 3.5 安装与分发

| 项 | 说明 |
|---|---|
| MSI/WiX | 安装 GUI + 服务 + Wintun DLL + 服务安装/升级/卸载 |
| 服务注册 | `ServiceInstall` / `ServiceControl`，LocalSystem，自动延迟启动 |
| Wintun DLL | 固定版本、哈希、许可证、绝对路径加载 |
| Authenticode | GUI、daemon、MSI 签名；正式分发建议 EV 证书 |
| 版本映射 | Cargo/Tauri `0.2.0-beta.1` → MSI 数字版本（如 `0.1.99.0`） |
| 卸载清理 | 停服务、删规则/适配器/服务；保留用户 profile/钥匙串 |
| Windows CI | 主仓库 Windows 构建、测试、MSI；目前只有原型 CI |
| Wintun 许可 | 分发前确认许可并附声明 |

### 3.6 测试与验收

| 项 | 说明 |
|---|---|
| Windows 实机 E2E | Windows 客户端 ↔ Linux `rustvpn-server` |
| 基本连通 | ping 网关、LAN 主机、DNS、TCP/UDP、大包 |
| 模式覆盖 | plain、noise、encless（TCP）、UDP/TCP |
| 断线恢复 | 超时、重连、切网、休眠唤醒 |
| 路由/DNS 清理 | 断开/崩溃/服务重启后无残留、无泄漏 |
| kill-switch | 断开后无 IPv4/IPv6/DNS 泄漏；IPv6 ND 正常 |
| 安装测试 | 干净 Win10/Win11 安装 → 连接 → 升级 → 卸载 |
| 安全测试 | 管道 DACL、假服务端、口令不落盘、DLL 校验 |
| 垫片 fuzz | 帧/ARP/IPv4 解析不可信输入 |
| 性能 | 吞吐、CPU、延迟；Wintun 批量/队列调优 |

---

## 4. 隐患与未处理问题

### 4.1 架构 / 协议

| 隐患 | 影响 | 处理建议 |
|---|---|---|
| L3 垫片丢失 L2 能力 | VLAN、广播发现、非 IP 协议不可用 | 文档明确；需要真 L2 时评估 `tap-windows6` |
| IPv6 不承载 | 全隧道可能泄漏 IPv6 | M3 已对全隧道阻断 `2000::/3`/`fc00::/7`；链路本地/组播保留给 ND；仍不要声称完整 IPv6 隧道 |
| MTU 是双端契约 | 客户端/服务端 `mtu` 不一致会丢包 | 继续禁止 auto；文档要求两端一致；未来 v2 协商 |
| encless 膨胀 ~4128 B | 底层路径容量不足会严重分片 | 连接前校验并拒绝，不要靠分片硬撑 |
| 原生 L2 服务端桥接 | 合成 MAC/ARP 可能被桥安全策略阻断 | 服务端文档说明放行合成 MAC |
| DHCP-only 服务端网络 | 静态地址 MVP 不可用 | 明确限制，后续做 DHCP 客户端 |

### 4.2 安全

| 隐患 | 影响 | 处理建议 |
|---|---|---|
| Windows 服务 LocalSystem | 权限高，IPC 是攻击面 | 命名管道 DACL + 客户端身份校验；最小化命令集 |
| 假管道服务端 | GUI 可能把口令发给恶意进程 | 校验服务端 PID/镜像路径/签名后再发口令 |
| Wintun DLL | 未校验 DLL 可导致提权代码执行 | 固定绝对路径、哈希/签名、ACL、不可由配置指定 |
| Windows kill-switch fail-open | 崩溃/重启可能恢复明文出口 | Windows 明确拒绝 `kill_switch`（Fail-closed 可恢复方案未实现）；不要声称与 Linux 等价 |
| SSH 管理员 | Ubuntu 侧被攻破即 Windows 管理员 | 限制 SSH、密钥、专用账号、审计 |
| 日志/配置泄密 | 口令、代理凭据、verifier 泄露 | 不落盘、不进日志、status 脱敏 |
| 自动更新 | 普通用户进程替换服务文件 | 服务安装模式关闭自更新；走签名 MSI |

### 4.3 可靠性

| 隐患 | 影响 | 处理建议 |
|---|---|---|
| Wintun 阻塞读 | 可能卡住 async worker/持锁死锁 | 使用已验证的 `ShimPump` 设计，锁内不做 I/O |
| 适配器残留 | 崩溃后 `RustVPN-Spike`/TAP 残留 | 启动清理；状态文件；卸载删除 |
| 路由/DNS 残留 | 断网、DNS 劫持、无法上网 | M3 已实现记录/回滚/崩溃清理；实机验收待做 |
| 休眠/切网 | Wintun/session 失效 | 检测 `TapClosed`；重开适配器；网络事件监听 |
| C: 空间不足 | 构建失败/系统盘满 | `CARGO_TARGET_DIR` 放 D:；安装到 D: |
| 双实例 | 服务/管道/路由冲突 | 服务单实例 + 命名互斥量 |
| 多用户 | 一个用户的隧道影响全机路由 | 明确组权限；单活动隧道；UI 显示占用者 |

### 4.4 兼容性 / 维护

| 隐患 | 影响 | 处理建议 |
|---|---|---|
| IPC v2 | 新旧 GUI/daemon 不兼容 | 明确版本错误；安装包成对升级 |
| 旧 `mtu:auto` profile | GUI 可能拒绝/跳过 | 迁移提示；不要静默重写 |
| Windows CLI | 首版未承诺 | 只做 GUI/服务；CLI 后续单独立项 |
| ARM64 | Wintun/Rust/Tauri 需另一套构建 | 先 x64，后续评估 |
| PowerShell 依赖 | Windows PowerShell 被策略移除/损坏 | 使用绝对路径并检查存在；失败即拒绝安装，不回退到 PATH |
| Wintun L3 网关语义 | 把网关当 OS 下一跳会导致 ARP 失败 | 路由用 on-link `NextHop=0.0.0.0`；网关只给垫片用 |
| 文档语言 | 新文档英文优先 | zh/ru 后续补，不能长期缺失 |
| 原型与主代码漂移 | MTU/Mode 重复实现 | 集成时改用 `rustvpn-proto`；保留 golden test |
| P2/崩溃恢复修复已提交但未最终复审 | 最终复审仍可能要求调整行为 | 开始 M1 前做一次针对性复审；M1 基于复审后的接口 |

---

## 5. 里程碑

| 阶段 | 内容 | 状态 | 验收 |
|---|---|---|---|
| M0 环境 | Windows 工具链 + SSH + 验证 | ✅ 完成 | MSVC 编译 link-check 成功 |
| M0.5 原型 | Wintun + Ethernet shim + ARP + MTU | ✅ 完成 | Windows 烟测 PASS，测试通过 |
| M1 核心接入 | `TapConfig`、shim 接入、async 桥接、Engine | ✅ 已提交 `9bc1466` | Windows 能连接 Linux 服务端并 ping |
| M2 服务/IPC | Windows 服务 + 命名管道 + DACL + 锁 | ✅ 已提交 `8cef993`/`8132f24` | GUI 可连接/断开，无权限越界 |
| M3 网络 | 路由/DNS/NRPT、防环、IPv6 阻断、清理 | 🟡 代码完成（未提交）；Windows 实机验收待跑 | 全隧道无泄漏，断开恢复 |
| M4 GUI | 路径/钥匙串/自启/语言/状态显示 | ⬜ 未开始 | 普通用户完整操作 |
| M5 安装 | MSI、服务安装、签名、Wintun DLL | ⬜ 未开始 | 干净 Win10/11 安装/升级/卸载 |
| M6 硬化 | E2E、休眠/切网、fuzz、CI、性能 | ⬜ 未开始 | 验收矩阵通过 |

**当前阻塞：** M3 代码已在工作区，但还没有 Windows 实机验收。需要在真实
Windows 主机（服务或管理员 `--console`）上完成：连接后地址/默认路由/DNS/
NRPT/IPv6 规则的实际检查、断开与崩溃后的恢复检查、以及 M2 的 SCM 启停和
越权连接测试。本轮开发机没有可用的 Windows SSH 目标（本地 KVM 无登录凭据），
只能完成 Linux/Windows 目标编译、clippy 与平台无关单测；P2 复审仍未最终完成。

---

## 6. 待产品/架构决策

| # | 决策 | 当前倾向 | 影响 |
|---|---|---|---|
| 1 | 目标架构 | Windows 10/11 x64 | ARM64 后置 |
| 2 | 链路层 | Wintun L3 + shim | `tap-windows6` 仅作真 L2 备选 |
| 3 | 安装方式 | 机器级 MSI + Windows 服务 | 需要管理员安装 |
| 4 | 服务访问控制 | 专用本地组（MVP 可 INTERACTIVE） | 决定哪些用户能控制 VPN |
| 5 | IPv6 | 首版不支持，阻断/告警 | 全隧道合规性 |
| 6 | kill-switch 范围 | 仅主机 output | 路由器/容器转发不受保护 |
| 7 | 签名 | 开发版可未签名；正式 EV | SmartScreen/企业分发 |
| 8 | 自动更新 | 首版关闭，走签名 MSI | 服务文件替换安全 |
| 9 | Windows CLI | 首版不做 | 减少范围 |
| 10 | Wintun 许可 | 随包分发并附声明 | 法务确认 |

---

## 7. 新会话/新 AI agent 的接手顺序

1. 读本文件 + [Windows 调研](windows-client-research.md) + [开发环境](windows-dev-environment.md)。
2. 确认 Windows 环境仍可用（Rust MSVC、VS BuildTools、Wintun DLL、D: 空间）。
3. 在 Windows 主机运行 M2 验证：
   - `cargo test -p rustvpn-clientd -p rustvpn-client-ipc -p rustvpn-client-core --target x86_64-pc-windows-msvc`
     （`ipc_e2e` 会用唯一命名管道启动 `--console` daemon）
   - 用独立本地组/第二用户验证管道越权被拒绝；不要安装服务。
4. M3 代码完成后，在 Windows 实机验证：握手后地址/默认路由/DNS/NRPT/
   IPv6 规则；断开与崩溃后的恢复；不要在生产默认路由上直接测分流冲突。
5. 所有 Windows 网络测试只使用 `10.88.0.0/24` 和临时适配器；不碰现有 VPN/路由/防火墙。
6. 每完成一个里程碑，更新本文件的“已完成/未开始/隐患”和提交记录。

---

## 8. 更新规则

- 本文件是 Windows 客户端的**唯一状态入口**；计划细节放 `windows-client-research.md`，环境安装放 `windows-dev-environment.md`。
- 状态标记：✅ 完成 / 🟡 部分完成 / ⬜ 未开始 / ⛔ 阻塞 / ⚠️ 风险。
- 每次提交 Windows 相关代码后更新：
  - 最近提交、分支状态
  - 已完成项
  - 新发现的隐患
  - 里程碑状态
- 不要把密码、私钥、真实主机地址写进本文件或任何提交；主机/账号用占位符。
- 不把 `docs/*.local.md`、`docs/tianbao-server-deployment.md` 纳入提交。