# Windows 客户端开发状态

> 最后更新：2026-11-27
> 分支：`feature/client-ui`
> 状态：M1（核心接入）、M2（服务 + 本地 IPC）、M3（网络配置）、M4（GUI 平台适配）
> 已完成并提交；M5（MSI/WiX 打包、服务注册、组/DACL、Wintun、签名钩子、Windows CI）
> 已完成并在 Windows 实机完成安装/升级/卸载验证，已提交；
> M6（真实 E2E、硬化、fuzz、CI）进行中：分流 + 全隧道（plain/noise）、
> Disconnect、DNS/NRPT、IPv6 阻断、rekey/重连、链路抖动、强杀恢复、性能均已
> 在 Windows 11 VM 验证；IPv6 清理幂等修复已提交。
> encless、休眠（VM 不支持）、互联网出口（需 NAT）、Windows CI 实跑、
> 真实证书签名仍未完成
> 相关文档：
> - [Windows 安装/升级/卸载/签名](windows-install.md)
> - [Windows 客户端调研与方案](windows-client-research.md)
> - [Windows 开发环境与依赖](windows-dev-environment.md)
> - [P0 决策与修复状态](p0-decision-review.md)
> - [客户端桌面 UI](client-ui.md)

---

## 0. 一句话状态

Windows 端已经完成 **开发环境 + Wintun/以太网垫片原型**，并完成了 **M1 核心接入**（`9bc1466`）、**M2 服务 + 本地 IPC**（`8cef993`）、**M3 网络配置**（`cac143a`，测试修正 `2fdd705`）、**M4 GUI 平台适配**（`7b73a82`）和 **M5 打包/安装**（`cb39124`）：Windows 路径/ACL、Credential Manager、HKCU 自启动、Windows 语言、管道信息、发送口令前的服务端镜像/签名校验；M5 增加未签名的 per-machine MSI/WiX、LocalSystem 延迟自动服务、失败恢复、`RustVPN` 组与成员、标准用户进程查询 DACL、Wintun DLL/许可证、版本映射、签名钩子和独立 Windows CI。
> 说明：M5 的 Windows 实机验证包括 MSI 静态检查（`msiexec /a` + MSI 表 + dark）、安装、服务/管道、标准用户与非成员访问、GUI RDP 启动、升级、卸载与 profile 保留；没有连接隧道、没有改默认路由/DNS 或现有 VPN/防火墙。真实 Windows 路由/DNS/NRPT 冒烟、休眠/切网、崩溃验收、真实服务端 E2E 与性能仍归 M6。

---

## 1. 当前基线

| 项 | 状态 |
|---|---|
| 代码分支 | `feature/client-ui` |
| 最近提交 | `7f05a3e fix(windows): make firewall and NRPT cleanup idempotent` |
| M5 代码 | 已提交（MSI/服务/组/DACL/CI/文档） |
| M6 代码 | 已提交（分流/全隧道 E2E、DNS/NRPT、IPv6 阻断、Disconnect、直接路由删除、幂等清理、fuzz、手动 CI）；VM 已验证 rekey/重连、链路抖动、强杀恢复与 iperf3 性能；encless/休眠/互联网出口/CI 实跑/签名待条件成熟 |
| M4 代码 | `7b73a82 feat(windows): adapt GUI paths, keyring, autostart and identity checks` |
| M3 代码 | `cac143a feat(windows): add network guard and crash recovery` |
| M2 代码 | `8cef993 feat(windows): add service, named-pipe IPC and tunnel lock` |
| M1 代码 | `9bc1466 feat(windows): integrate Wintun shim into client core` |
| 远端 | 领先 `origin/feature/client-ui`，**未推送** |
| 主仓库剩余改动 | M5、M6 代码已提交；M6 encless、休眠、互联网出口、CI 实跑、签名待条件成熟 |
| Windows 原型位置 | `prototypes/windows-shim/`，独立 crate，不加入 workspace |
| Windows CI | `.github/workflows/windows-client.yml`（M5 客户端构建/MSI）与 `.github/workflows/windows-shim.yml`（原型）相互独立 |
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

### 2.8 M3 网络配置（已提交 `cac143a`）

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
- **Windows 目标测试**：client-core 72 passed、net 99 passed（1 ignored manual smoke）
- **未执行**：真实 Windows Wintun + PowerShell 路由/DNS/NRPT 冒烟、
  断线/崩溃清理验收（M6）。已提供只读的 `windows_read_only_probe`
  （`#[ignore]`）供后续在 Windows 上校验 PowerShell 脚本/JSON 契约且不改网络状态。
  未触碰宿主机 VPN/NAT/防火墙，未重启。

### 2.9 M4 GUI 平台适配（已提交 `7b73a82`）

- **Profiles / ACL**：Windows 使用 `%LOCALAPPDATA%\RustVPN\profiles`
  （`LOCALAPPDATA` 缺失时回退 `%USERPROFILE%\AppData\Local`）；目录和文件用
  显式受保护 DACL `D:P(A;...;FA;;;OW)(...;SY)(...;BA)`，只允许当前用户
  （owner rights）、SYSTEM、Administrators，无 Everyone/Users/Authenticated
  Users，且不接受父目录继承。ACL 设置失败会让保存失败，而不是静默落盘。
  Linux 仍是 `~/.config/rustvpn/profiles` + `0600/0700`；YAML 格式和后端
  MTU/profile 校验不变。`profile_errors` 现在在“配置”页有持久列表，不只
  一次 toast。
- **Keyring**：`keyring` 按目标平台分特性：Linux 保留
  `sync-secret-service` + `crypto-rust`；Windows 启用 `windows-native`
  （Credential Manager）。后端失败时命令返回错误，UI 继续提示输入口令，
  **不落盘明文**。新增 Rust roundtrip 测试（Windows，`#[ignore]`，使用一次性
  随机字符串）；在无交互登录会话的 SSH 下会明确跳过。
- **Autostart**：Windows 直接写
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\RustVPN =
  "…\rustvpn-client-ui.exe" --minimized`，不创建 XDG desktop 文件；登录时
  最小化到托盘，不自动连接。Linux 仍写 XDG autostart。
- **Locale**：Windows 用 `GetUserDefaultUILanguage()` 的 primary language
  id（0x04→中文、0x19→俄语、其他→英语）；Linux 仍读 `LC_ALL/LC_MESSAGES/LANG`。
  前端仍优先使用 localStorage 中用户选择的语言。
- **Daemon info / pipe**：`daemon_info` 返回命名管道
  `\\.\pipe\rustvpn-clientd`、`endpoint_kind=named-pipe`、平台、profile
  目录与最小 inner MTU，不再显示 Unix socket。`candidate_socket_paths`/
  `Client`/`EventStream` 直接复用 M2 的命名管道实现。
- **服务未安装/未启动**：Windows 下把 `ERROR_FILE_NOT_FOUND` 映射为
  “服务未安装或未运行（M5 安装器）…开发可用 `--console`”，把
  `ERROR_ACCESS_DENIED` 映射为管道 ACL/`RustVPN` 组提示；设置页显示端点和
  服务提示。
- **发送口令前的服务端身份校验**：`connect` 在 Hello 之后、`Connect`
  之前调用 `Client::server_pid()`，用 `QueryFullProcessImageNameW` 解析镜像，
  用 `WinVerifyTrust` 校验 Authenticode 并从 signer 证书取 publisher。
  接受条件：镜像是 `rustvpn-clientd.exe` 且位于
  `%ProgramFiles%\RustVPN`；或已签名且 subject 含 `RustVPN`；或 **仅 debug
  构建** 下与 GUI 同目录的未签名 daemon（供 `cargo tauri dev`）。否则拒绝
  发送口令。Unix 行为不变。
- **Windows 状态/错误**：状态页把 Windows 的 kill-switch 显示为“不支持”、
  MSS 显示为“暂不支持”，不隐藏安全开关；错误状态附加 Wintun DLL/驱动、
  路由冲突、服务状态的排查提示；设置页新增 Windows 故障排查卡片；
  更新源在 Windows 标记为 `managed_by_msi`，应用内更新关闭。
- **Tauri**：`tauri.conf.json` 增加 Windows icon、WebView2
  `downloadBootstrapper`、MSI/NSIS targets 和 resources 脚手架（`active`
  仍为 false，不安装服务、不打包）；单实例/托盘/关闭到托盘代码不变。
  Windows 实机 `cargo tauri build --target x86_64-pc-windows-msvc` 成功生成
  release exe；因 `bundle.active=false` 未产出 MSI/NSIS。M5 最终改用独立
  WiX 项目打包，`bundle.active` 保持 false。
- **测试**：Linux `cargo fmt/clippy/test` 通过；Windows 目标 check/clippy
  通过；Windows 实机 `cargo test -p rustvpn-client-gui` 31 passed + 2
  ignored；JS i18n 测试 7 passed。ACL、locale、profile 路径、管道错误映射、
  身份策略均在 Windows 实机通过单元测试；两个 ignored 测试（Credential
  Manager roundtrip、嵌入 Authenticode publisher）也已分别在交互式会话/
  签名二进制上单独运行通过。
- **Windows RDP 实机验证**（交互式 Administrator 会话）：
  - GUI 启动成功（WebView2 dark UI，中文 locale 来自
    `GetUserDefaultUILanguage`），连接 `\\.\pipe\rustvpn-clientd` 的
    `--console` daemon，界面显示守护进程在线。
  - 带 UTF-8 BOM 的 profile（Windows 记事本常见）此前报
    “more than one document” 并在 UI 显示 `profile_errors`；已修复为读取时
    去除 BOM，并在 Windows 实机确认 profile 正常加载。
  - 通过 UI 触发连接：日志出现
    `named-pipe server verified: … trust=debug sibling binary`，证明口令
    发送前的服务端身份校验生效；随后 daemon 因 M5 尚未安装
    `C:\Program Files\RustVPN\wintun.dll` 而失败，UI 显示 Wintun 排查提示
    （预期，未改网络）。
  - Credential Manager save/get/delete roundtrip（`#[ignore]` 测试）在交互式
    登录会话下通过；SSH 非交互会话会明确跳过。
  - HKCU Run 通过 UI 开关真实写入
    `"…\rustvpn-client-ui.exe" --minimized`，关闭后值被删除；以
    `--minimized` 启动时主窗口隐藏到托盘，进程保持单实例。
  - 单实例：第二次启动立即退出，只保留一个 GUI 进程；关闭窗口后进程仍存活
    （关闭到托盘），系统托盘存在 RustVPN 图标（UIA pane）。
- **未执行**：标准用户对 LocalSystem 服务进程的
  `PROCESS_QUERY_LIMITED_INFORMATION`/镜像路径查询（本轮以管理员交互会话
  验证；若 M5 服务进程 DACL 拒绝普通用户，GUI 会 fail-closed，需 M5 补
  查询权限）。真实服务端 E2E（需要 M5 安装 Wintun DLL）、M3 的路由/DNS/
  NRPT/IPv6 实机验收、休眠/切网/崩溃恢复；归入 M6。

### 2.10 M5 打包与安装（已提交 `cb39124`）

- **安装包选择**：使用独立 WiX 3.14 项目
  `packaging/windows/rustvpn-client.wxs` + `candle.exe`/`light.exe`，而不是
  Tauri bundler 的 WiX fragment。原因是 Tauri 模板拥有 Product/Feature/
  UpgradeCode，M5 需要 LocalSystem 服务、延迟自启、失败恢复、组助手以及
  “先停服务再替换文件、安装后再启动”的升级顺序；独立 WiX 让所有表显式、
  可检查，且仍使用 M4 已构建的同一 GUI exe。`bundle.active` 保持 `false`，
  GUI 行为不变。
- **MSI 内容**：per-machine `Program Files\RustVPN`，包含
  `rustvpn-client-ui.exe`、`rustvpn-clientd.exe`、`wintun.dll`、
  `installer\setup-group.ps1`、`docs\`（COPYING、windows-install.md、
  打包说明、SIGNING.txt、VERSION.txt）和 `licenses\`
  （Wintun 许可证/版本/SHA-256）。开始菜单快捷方式默认创建；桌面快捷方式
  默认关闭（`INSTALLDESKTOPSHORTCUT=1` 开启）。不打包用户 profile、
  keychain 或安装者信息。
- **服务**：`rustvpn-clientd --service`，LocalSystem、own process、
  自动延迟启动、失败后 5/10/30 秒重启（`reset=86400`）。
  `ServiceControl Stop="both" Start="install" Remove="uninstall" Wait="yes"`：
  升级/卸载前停止、安装后启动、卸载时删除 SCM 项。Windows Installer 的
  `ServiceConfig`/`ServiceConfigFailureActions` 在实机触发 Error 1939，
  改用安装期 `sc.exe config/failure` 自定义动作，避免依赖不可靠的 MSI
  服务配置 API；`verify-msi.ps1` 静态检查 `start= delayed-auto`、
  `restart/5000/10000/30000`。
- **组与访问控制**：延迟自定义动作在 `StartServices` 前运行
  `installer\setup-group.ps1`，创建本地 `RustVPN` 组并把
  `[LogonUser]`（可用公共属性 `RUSTVPN_USER` 覆盖）加入；无法加入时只回滚
  本次创建的组，保留 INTERACTIVE 回退。守护进程启动时把
  `PROCESS_QUERY_LIMITED_INFORMATION`（0x1000）授予同一组/INTERACTIVE，
  使 M4 GUI 能在发送口令前用 `QueryFullProcessImageNameW` 校验
  LocalSystem 服务镜像；没有授予内存/句柄/终止权限。
- **修复 M2 组策略 bug**：`group_sid_bytes()` 直接相信
  `LookupAccountNameW` 的 `cbSid`，在 Windows 10 上保留了 68 字节缓冲区，
  导致 `ClientPolicy` 的 SID 字节比较拒绝合法 `RustVPN` 组成员（pipe
  DACL/进程 DACL 用字符串 SID，不受影响）。改为用 `GetLengthSid` 截断，
  并新增 Windows 回归测试 `looked_up_sid_bytes_match_the_sid_header_length`。
  新增被拒绝客户端的日志（PID、用户 SID、组 SID、允许 SID），便于现场
  排查，不记录口令/profile。
- **版本**：Cargo/Tauri `0.2.0-beta.1` → MSI `ProductVersion 0.1.99.0`；
  Product name、`HKLM\Software\RustVPN\Client\Version`、GUI、
  `docs\VERSION.txt` 与产物名保留 semver。`MajorUpgrade`
  `AllowSameVersionUpgrades=yes`，同一数字版本的 beta 重建可通过新
  ProductCode 升级；更低版本被拒绝并提示先卸载。
- **签名**：`sign-artifacts.ps1` 支持证书存储指纹或 PFX 环境变量，
  在打包前签名 GUI/daemon、链接后签名 MSI，并 `signtool verify /pa`。
  仓库不保存证书/私钥。无证书时实际验证产物未签名，并写
  `UNSIGNED.txt`、Product comments、`docs\SIGNING.txt`。
- **Wintun**：构建时校验 DLL 为 amd64、SHA-256 为
  `e5da8447...dafce`；安装到 `C:\Program Files\RustVPN\wintun.dll`，
  与 `rustvpn-net` 的绝对默认路径一致；附带上游许可证、版本与 SHA 文件。
- **CI**：`.github/workflows/windows-client.yml` 独立于
  `windows-shim.yml`，在 `windows-latest` 上安装 Rust + WiX 3.14、下载并
  校验 Wintun 0.14.1、运行客户端 crate 的 check/clippy/test、构建未签名
  MSI 并用 `msiexec /a` + MSI 表 + dark 检查；不安装服务、不使用签名密钥。
- **Windows 实机验证（2026-11-27）**：
  - Linux `cargo fmt/clippy/test`；Windows 目标 check/clippy 通过；
    Windows 客户端 72 + 31(+2 ignored) + 24 + 2 + 3 + 1 + 99(+1 ignored)
    测试通过。
  - MSI 静态检查通过：payload 完整；`ProductVersion=0.1.99.0`；
    `ALLUSERS=1`；`ServiceInstall` 为 `rustvpn-clientd`/StartType=2/
    LocalSystem/`--service`；`ServiceControl` Event=163；
    delayed-auto 与 5/10/30 秒失败动作均存在；开始菜单/可选桌面快捷方式/
    组助手/升级表存在。
  - 安装 `msiexec /i ... /qn RUSTVPN_USER=Administrator` 退出 0；服务
    Running、`AUTO_START (DELAYED)`、`sc qfailure` 显示 5/10/30 秒；
    `RustVPN` 组包含 Administrator；文件与 `wintun.dll` SHA-256 正确；
    未签名状态经 signtool 验证。
  - 管理员与**新登录的标准用户**（临时本地账号，加入 RustVPN 组）都通过
    `verify-client-access.ps1`：连接命名管道、读取服务端 PID、以
    `PROCESS_QUERY_LIMITED_INFORMATION` 打开 LocalSystem 进程、解析
    `C:\Program Files\RustVPN\rustvpn-clientd.exe`、Hello v2 往返；非成员
    账号在 `Connect` 处被 DACL 拒绝（访问被拒绝）。
  - GUI 在 RDP 会话 1 启动（WebView2 子进程、UIA 窗口 `RustVPN`，
    1096×779、非 offscreen）；未连接隧道，未改路由/DNS/现有 VPN/防火墙。
  - 同版本升级：旧 ProductCode 卸载、新 ProductCode 安装，服务 PID
    变化，安装后二进制哈希与最终 release 一致，组成员保留。
  - 卸载退出 0：服务、`Program Files\RustVPN`、开始菜单、HKLM 注册表项
    全部移除；`%LOCALAPPDATA%\RustVPN\profiles` 中的测试 profile 保留；
    `RustVPN` 组和 `%ProgramData%\RustVPN` 按设计保留。
  - 未执行：真实 Wintun 适配器/隧道连接（M6）、实际旧版本降级安装
    （仅静态配置/文档）、Windows CI 运行（本机无法运行 GitHub Actions）、
    使用真实证书的签名（本机无证书）。

### 2.11 M6 硬化与真实 E2E（进行中，2026-11-27）

**真实拓扑（手动、临时资源）**

```text
Windows 10 Pro x64 (Wintun rsvpn-m6, 10.99.0.2/24)
  -> UDP 11940 (plain) -> <linux-host>
  rustvpn-server TAP rsvpn-m6 10.99.0.1/24 + 手动 10.99.1.1/24
  profile routes: 10.99.0.0/24, 10.99.1.0/24（分流；无 default）
  dns: []；gateway: 10.99.0.1；mtu: 1515
```

Windows 侧使用已安装的 MSI（LocalSystem 服务 + 命名管道），通过一个临时
PowerShell IPC 客户端驱动 `Connect/Status/Disconnect`；未修改现有 VPN/NAT/
默认路由，仅在 Ubuntu 上临时放行 `11940/udp`（限定 Windows 主机源地址），
结束时删除。Linux 侧使用独立的 `rsvpn-m6` TAP 和 `10.99.0.0/24`；服务端
以 `sudo` 运行（创建 TAP/配置地址需要 root），退出时用 trap 清理 TAP、
服务进程和临时防火墙规则。

**已通过**

- MSI 安装、服务运行、命名管道 + Hello v2 + `Status`；`verify-client-access.ps1`
  通过。
- 握手成功，状态 `connected`；两次实机运行均通过连通性检查。第二次使用仅
  调用原生 `route`/`netsh` 的轻量 harness：`ping 10.99.0.1` 4/4、
  `ping 10.99.1.1` 4/4；从 Windows 对 `10.99.0.1:22` 建立 TCP 并读到
  `SSH-2.0-OpenSSH_...` 横幅，证明隧道双向载荷。（第一次运行的首包在 ARP
  解析时超时，随后正常。）
- 路由：默认路由始终只有原物理默认路由（原接口, `<lan-gateway>`, metric 0）；
  Wintun 上 `10.99.0.2/24`、`10.99.0.0/24` 直连、`10.99.1.0/24 via 10.99.0.1`
  metric 50；防环 `<linux-host>/32` 走原接口 metric 1；无默认路由接管。
- DNS/NRPT/IPv6：分流 profile 未设置 DNS；Wintun 无 DNS，物理接口 DNS 不变；
  无 NRPT 规则，无 RustVPN IPv6 防火墙规则。
- `%ProgramData%\RustVPN\netstate.json` 记录了 owner、profile 地址、
  防环 `/32` 和分流路由，内容与上述状态一致。
- 垫片 fuzz：新增 7 个确定性 fuzz 测试（IPv4/ARP/inbound 分类/队列上界/
  出站帧预算/校验和工具），`rustvpn-net` 118 个测试通过。fuzz 额外发现
  `subnet_broadcast(ip, 0)` 的移位溢出（debug 构建 panic），已修复并加回归测试。
- CI：新增 `.github/workflows/windows-client-e2e.yml`，仅在
  `workflow_dispatch` + 自托管提权 Windows runner + 受保护 environment 下运行，
  默认分流、拒绝 default 路由（除非显式 `full_tunnel`），结束总是卸载。
  `.github/workflows/windows-client.yml` 经 YAML 静态校验，未实际运行 GitHub Actions。

**Windows 10 实机发现并修复的 M3 契约 bug**

1. `Get-NetAdapter MtuSize` 是 NDIS L2 MTU，Wintun 固定报 `65535`；原 guard 在
   安装地址前拿它和 inner IP MTU 比较，导致所有真实 Wintun 连接失败。现在
   只依赖 `Get-NetIPInterface NlMtu`（地址安装后、路由安装前）检查。
2. Windows 会给未配置静态地址的已启用适配器自动加 APIPA
   `169.254.0.0/16`；原 guard 把它当“无关地址”拒绝。现在忽略 IPv4 link-local
   自动地址，只拒绝其他非配置地址。
3. Windows PowerShell 5.1 把 `AutomaticMetric`/`ConnectionState` 枚举序列化成
   数字（0/1）；解析器现在同时接受名称和数字。
4. Windows 10 的 `Find-NetRoute` 没有 `-AddressFamily` 参数，且会先返回一条
   `DestinationPrefix=null` 的本机地址行；已移除该参数并只保留真正的路由行。
5. 上述 fuzz 发现的 `/0` 移位溢出。

**关键阻塞：Windows 断开路径可复现导致主机网络失联**

- 2026-11-27 第一次 E2E：发送 `Disconnect` 后 Windows 主机从网络消失
  （ARP/SSH/RDP 均不可达）。主机在约 05:13 后无任何 System 事件；
  07:08:05 `winlogon.exe` 代表 SYSTEM 发起**干净关机**（1074，Reason
  0x500ff），07:08:48 Kernel-Power 109，07:26:26 重新开机。无 Kernel-Power
  41（非意外断电），且 `powercfg /a` 显示 S3/休眠均不可用，因此**不是睡眠**，
  而是 OS/网络栈挂起后由人工干净关机/重启。
- 2026-11-27 主机恢复后重跑：分流 E2E 再次通过；随后仅发送
  `Disconnect`（harness 只使用 `route`/`netsh` 原生命令，断开期间没有
  WMI/快照调用），Windows 主机**第二次**立即失联（ARP/SSH 均不可达），
  服务端记录 `peer removed (Timeout)`。两次 2/2 复现，可排除 harness 的
  WMI 快照是触发因素。
- 断开前状态完全正确（`connected`、分流路由、无默认路由接管）；因此问题
  集中在 daemon 的断开清理/Wintun 拆除路径，而非隧道数据面。第一次故障后
  的 `clientd.log` 已经包含 `tunnel stopped` 和 `disconnected`：这发生在
  `guard.remove()`、`drop(tap)` 和 engine 的 idle 状态之后，说明断开逻辑
  至少跑到了结尾；因此挂起不一定在 `Remove-NetRoute`/`Remove-NetIPAddress`，
  也可能（甚至更可能）是 **Wintun 适配器关闭/NDIS 异步拆除** 触发的网络栈
  死锁。**修复前**代码在 `guard.remove()` 之后才 `drop(tap)`，清理会在
  Wintun 适配器仍打开时删路由/**地址**；另外 `Session::close` 只取消而不
  join peer 任务，任务仍持有 `Arc<Tap>`，`drop(tap)` 未必真正关闭会话/适配器。两
  条路径都需在一次性 VM 中用二分法验证（先只关闭适配器、不删地址；再只删
  地址、不关闭适配器）。
- **候选修复（`2dd3b66`）+ 复审 P1/P2 修复（已提交 `bb573e4`；已做物理机实测，仍失败）：**
  - **2026-11-27 物理机实测结果：** 使用 `bb573e4` 重新构建的 MSI，split-tunnel
    connect 成功，`ping 10.99.0.1` 4/4、TCP SSH banner 正常；发送 `Disconnect`
    后 Windows 主机**第三次**失联（ping/SSH 均不可用）。因此候选 teardown 重排
    不足以修复挂起；显式 `Remove-NetIPAddress` 不是唯一触发点，剩余高度可疑的是
    Wintun/NDIS `WintunCloseAdapter` 本身，或仍在对活跃 Wintun 执行
    `Remove-NetRoute`/DNS/NRPT/接口 metric 变更。
  - **结论：** 物理机在 VM 二分完成前禁止任何 connect/disconnect；下一次必须在
    一次性 VM 中分离“仅关闭适配器 / 仅删路由/DNS / 两者顺序”。
  - **根因假设（按可能性排序）：** (a) 关闭适配器前显式
    `Remove-NetIPAddress` 删除 Wintun 上唯一的 profile 地址（并触发隐式
    connected 路由拆除），与仍打开的 NDIS 会话冲突；(b) shim 专用阻塞读线程
    在删路由/地址时仍可能位于 Wintun `recv` 内，且 `drop(tap)` 不是最后一个
    `Arc` 引用，适配器关闭时机不确定；(c) 断开后 engine 立即执行的
    `cleanup_owned_network()`（`Get-NetAdapter`/`Get-NetRoute`）落在
    teardown 之后。
  - **新 teardown 契约（`engine.rs::teardown_connection` → `ConnectionCleanup::finish`）：**
    1. `session.close().await` 取消并 **join** 全部 peer 任务（`peer.rs` 为
       `PeerHandle` 记录 `JoinHandle`；超时则 abort+join），保证没有任务再用
       `tap.recv()`/`tap.send()`，也不再持有 `Arc<Tap>`；客户端 `PeerHandle`
       默认在 Drop 时 cancel（字段级 guard，不阻止移出字段），服务端在移出
       字段前显式 `disarm_cancel_on_drop()` 以保留自己的 token 生命周期；
    2. `tap.stop_reader()` 在 Windows join Wintun 垫片读线程（`ShimPump`
       已有 join；新增 `WindowsTap::stop_reader`/`Tap::stop_reader`）；
    3. `guard.begin_connection_teardown(keep_address = tap.adapter_created())`
       只删 NRPT → DNS → 路由（分流/默认，防环 `/32` 最后）→ 接口 metric →
       IPv6 防火墙；**close 前绝不执行 `Remove-NetIPAddress`**，也**不清除**
       `netstate.json`；
    4. `drop(tap)`（此时为最后一个 `Arc`）→ `WintunAdapter` 先
       `Session::shutdown` 再 `WintunCloseAdapter`；
    5. `ConnectionCleanup::finish()`（**close 之后**）：
       - `created=true`：地址/connected 路由已随适配器删除，直接清状态；
       - `created=false`（打开的是已存在适配器，close 不删设备）：在会话/句柄
         关闭后显式 `Remove-NetIPAddress`（`cleanup_recorded_address`），再清
         状态；地址删除失败则保留状态文件。只有确认最后一个 `Arc<Tap>` 已释放
         （`closed=true`）才执行；若仍有额外引用导致会话未关闭，跳过地址删除
         并保留状态，绝不向 live 会话发命令；
       - 只有所有清理都成功才删除 `netstate.json`；close 窗口内崩溃/挂起会留下
         完整状态供下次启动清理；
    6. close 之后不再执行任何 `Get-Net*`/PowerShell/`netsh` 查询；最后才发布
       `tunnel stopped` / idle 状态。
  - **created 标志贯穿：** `WintunAdapter.created` → `WindowsTap::created` →
    `Tap::adapter_created` → engine；`created=false` 时地址在 close **之后**
    删除，`created=true` 时保留给适配器关闭。这修复了“预存在适配器地址永不
    删除”的 P1。
  - **install 失败回滚（P1）：** `install_with_partial` 返回 `PartialInstall`
    （含 partial state）；engine 先 `session.close().await` +
    `tap.stop_reader()`，再 `failure.rollback(keep_address)`，然后 `drop(tap)`，
    最后 `cleanup.finish()`。`install_with` 不再在 install 内部 mutate/清理。
  - **previous-state 清理（P1）：** engine 在打开适配器**之前**运行
    `cleanup_before_opening_adapter()`（先清本进程残留，再清死 owner 状态；
    失败或仍有 live owner 则拒绝连接）；`install_inner` 若仍看到状态文件则拒绝
    安装，绝不向 live Wintun 会话发 `Remove-Net*`。
  - **断开后不立即重试清理：** 只有本进程从未完成过连接时才在 idle
    `Disconnect` 运行 `cleanup_owned_network()`；否则留给下次 daemon 启动
    （打开适配器之前）重试。
  - **ShimPump receiver 可重用：** `recv()` 用 `ReceiverLease` 在 future 被
    cancel（重连 join 旧 peer task）时归还 receiver；shutdown 时则关闭 channel
    唤醒阻塞的 reader。修复重连/复用适配器后收包失效的风险。
  - **IPC Disconnect 语义：** `Response::Ok` 只表示命令已入队；engine 在
    teardown 前发布 `disconnecting`，完成后发布 `idle`。客户端应等待 `idle`
    事件（或读取状态）而不是把 `Ok` 当完成。
  - **测试（Linux 可跑，无需 Wintun）：**
    `engine::teardown_order_is_reader_then_non_route_then_close_then_defer_cleanup`
    （stop → 非路由清理 → close → 延迟清理）；`shim::pump_shutdown_joins_the_dedicated_reader_thread`；
    `shim::cancelled_recv_restores_the_receiver_for_the_next_call`；
    `peer::shutdown_joins_cancelled_tasks_and_aborts_wedged_ones`；
    `peer::dropping_the_handle_cancels_the_peer_tasks`；
    `winplan::non_route_cleanup_never_removes_routes_or_the_address_before_close`；
    `winplan::disconnect_keeps_host_routes_and_state_without_post_close_commands`；
    `winplan::next_start_cleanup_removes_deferred_host_routes_and_clears_state`；
    `winplan::pre_open_cleanup_removes_deferred_host_routes_before_the_next_adapter`；
    `winplan::install_refuses_previous_state_without_mutating_a_live_adapter`；
    `winplan::injected_route_failure_defers_routes_address_and_state_to_next_start`。
    Linux `NetworkGuard::begin_connection_teardown` 完全委托原有 `remove()`，
    行为不变。
  - **仍未验证：** 上述修复仍是代码层假设，未在 Windows 上执行过一次断开。
    必须在一次性 VM 完成下面的矩阵后才可考虑物理机；若 VM 仍挂起，则
    (a)/(b) 不成立，需要转向 Wintun 驱动/NDIS 关闭本身（例如保留适配器句柄
    到进程退出、升级或更换 Wintun 版本）。
- **最终结论（2026-11-27 物理机二分）：** 触发点是 **daemon 内部由 PowerShell 执行的 `Get-NetRoute ... | Where-Object ... | Remove-NetRoute -PolicyStore ActiveStore` 路由删除流水线**，而不是适配器/会话是否存在：
  - 只读 `Get-Net*`、不改路由的 close-only 均安全；
  - cleanup-only/antiloop-only 在适配器打开时挂起；
  - 固定顺序（close 后立即删）仍挂起；
  - 延迟到下一次 daemon 启动、**无任何 Wintun 适配器**时由 startup 清理执行同一流水线，仍会在约 13–16s 后挂起；
  - 相反，外部直接 `Remove-NetRoute -DestinationPrefix '...' -Confirm:$false`（无 pipeline、无 `-PolicyStore`）在多次手工清理中均安全。
  因此 disconnect 路径**不做任何 close 后网络操作**，并把所有 daemon 路由删除改为**直接 cmdlet**：`Remove-NetRoute -DestinationPrefix '<prefix>' -InterfaceIndex <idx> -NextHop '<hop>' -RouteMetric <metric> -Confirm:$false`（精确身份、无流水线、无 `-PolicyStore`）：
  1. `session.close().await` + `tap.stop_reader()`；
  2. close 前只删 NRPT/DNS/接口 metric/IPv6 防火墙，不删路由/地址；
  3. 关闭 Wintun 适配器（地址与 connected/default/split 路由随设备删除）；
  4. **不删除防环/物理网卡主机路由，不清 `netstate.json`**；close 后不执行任何 `Get-Net*`/PowerShell/`Remove-NetRoute`，直接发布 `tunnel stopped`/idle；
  5. 下一次 Connect 在打开适配器前（`cleanup_before_opening_adapter`）或下一次 daemon 启动（`cleanup_stale_network`）在**无 Wintun 会话**时执行完整清理，删除防环路由并清除 `netstate.json`；
  6. 因此 daemon 空闲/断开期间，防环 `/32` 可能短暂保留；这是有意的 pending 清理记录（此时已无隧道适配器和 `10.x` 地址）。daemon 若在 idle 退出，下一次服务启动会先清理再允许打开适配器。
  install 失败回滚同样在 close 后保留路由/地址/状态，由下次启动清理；崩溃恢复仍是无适配器打开时的完整清理。
  **2026-11-27 物理机验证（直接 cmdlet）：** 正常 Disconnect 后主机存活 >120s，防环 `/32` 与 `netstate.json` 按要求保留，适配器/`10.99.*` 已消失；随后停止 daemon 再启动，startup 清理用直接 `Remove-NetRoute -DestinationPrefix '192.168.110.190/32' -InterfaceIndex 6 -NextHop '192.168.110.1' -RouteMetric 1 -Confirm:$false` 删除防环路由并清除 `netstate.json`，主机存活 >150s，默认路由仍为 `192.168.110.1`。因此 daemon 不再使用 `Get-NetRoute | Remove-NetRoute -PolicyStore ActiveStore` 流水线；Linux 保持不变。可选的重连（pre-open 清理）未再执行，以避免额外一次断开周期。
  **OpenVPN 参考与后续改进：** OpenVPN 在 Windows 用 IP Helper API（`CreateIpForwardEntry2`/`DeleteIpForwardEntry2`）或 `route.exe` 增删路由，不用 PowerShell/WMI；teardown 先恢复 DNS、删隧道路由、最后删防环 `/32`，然后关闭适配器。微软文档说明 `Remove-NetRoute` 在无有效过滤时会删除包括默认路由在内的全部路由，且 `-PolicyStore` 只存在于 By-Name 参数集，与 pipeline/InputObject 组合属未定义绑定；这正是旧流水线导致整机断网的原因（13–16s 后默认路由/缓存失效才显现）。当前直接 cmdlet 已验证；下一步建议改用 `DeleteIpForwardEntry2` 按记录行精确删除（`ERROR_NOT_FOUND` 视为已删除），或用 `route.exe DELETE <dest> MASK 255.255.255.255 <gateway> IF <idx>`，彻底移除 daemon 热路径中的 PowerShell。
- **一次性 VM 验证矩阵（修复后必须执行）：**
  1. connect → disconnect → **不做任何 OS 查询**，等待 120s，检查 ARP/ping/SSH/RDP；
  2. 同样流程，断开后延迟 60s 再做 `Get-Net*`/`netsh`，检查是否挂起；
  3. 旧构建二分：只关闭适配器不删地址；只删地址不关闭适配器（在 VM 快照上
     逐项执行，每次失败后回滚快照）；
  4. 断开清理失败注入（如临时阻断 PowerShell），重启 daemon，确认启动清理
     补删遗留项，且清理完成前拒绝新连接；
  5. install 失败回滚路径（例如故意让 `New-NetRoute` 失败）：确认先 stop
     reader/peer，再回滚，再 close，最后清状态；
  6. **预存在适配器（`created=false`）**：预先创建 `rsvpn0` 后连接/断开，确认
     close 之后才执行 `Remove-NetIPAddress`，地址消失且 `netstate.json` 清除；
     `created=true` 则全程不出现 `Remove-NetIPAddress`；
  7. 重连/复用适配器：连接后触发一次超时重连，确认 shim reader 仍能收包（取消
     的 `recv` 归还 receiver）；
  8. IPC `Disconnect` 后先看到 `disconnecting`、teardown 完成后才是 `idle`；
  9. 全隧道（DNS/NRPT/IPv6 阻断）connect/disconnect，确认 DNS 恢复、NRPT/
     防火墙规则删除、无 IPv6 泄漏。
  记录 `clientd.log` 最后几行和 System 事件（1074/109/41/42、NDIS/Wintun），
  并确认 `created=true` 时全程无 `Remove-NetIPAddress`、close 后无任何网络查询。
- **第三嫌疑：断开后的 OS 网络查询。** 两次失联都发生在断开完成后紧接着
  执行 `Get-Net*`/`netsh` 检查时；第二次 harness 已排除重 WMI 快照，但仍
  调用了 `netsh interface ipv4 show ...`。若 Wintun/NDIS 拆除是异步的，
  紧随其后的任何网络配置查询都可能撞上未完成的 teardown 而死锁。GUI 正常
  断开只读 IPC 状态，不会做这些查询，因此产品路径可能不受影响；必须在 VM
  中区分。
- **下一步取证/VM 二分矩阵：** 主机恢复后先读
  `C:\ProgramData\RustVPN\clientd.log` 最后几行和 System 事件
  （1074/109/41/42、NDIS/Wintun/网络）：若日志停在 `disconnected` /
  `tunnel stopped`，说明 daemon 清理与 `drop(tap)` 已返回，挂起在之后的
  teardown 或查询。VM 中按以下顺序测：(1) connect+disconnect 后**不做任何
  OS 查询**，等待 120s 并 ping；(2) 同样流程，断开后延迟 60s 再查询；
  (3) 只删除地址不关闭适配器；(4) 只关闭适配器不显式删除地址；
  (5) 保留适配器句柄、断开时只清路由/状态。记录哪种组合能不触发挂起。
  **未修复、未验证，禁止在可用主机上再次断开。**
- 由于断开本身会切断主机网络，断开清理、崩溃恢复和后续卸载均无法在当前
  主机上安全完成；全隧道/DNS/NRPT/IPv6、休眠/切网、性能同样未执行。
- 主机再次恢复后必须人工完成：检查 System 事件（1074/109/41/42）确认关机
  原因；**不要再次点击连接/断开**，直到在一次性 VM 中验证修复；删除
  `D:\temp\rustvpn-m6`（含临时测试口令和脚本）；用
  `msiexec /x {94FAB11C-141C-478E-A5B8-16D17C926075} /qn` 卸载测试 MSI
  （当前仍安装，daemon 已被替换为包含上述 4 个修复的重建二进制，但不含
  后续 `/0` fuzz 加固）；确认 `netstate.json`/临时路由已清理；在一次性
  VM 中补做断开/崩溃/全隧道验收。

---

## 3. 后续与未完成项

### 3.1 核心集成（M1 已完成）

`TapConfig`/平台门面、`Tap` ↔ shim、异步桥接、Engine 接线与共享 MTU/Mode
已在 `9bc1466` 完成。地址/网关/DNS、路由与 IPv6 阻断已在 M3 `cac143a`
实现；Windows 目标测试通过，真实 Windows 路由/DNS/NRPT 验收留待 M6。

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
| 多用户/会话策略 | ✅ M5 安装器创建 `RustVPN` 组并加入安装者；标准用户实测通过，非成员被拒绝 |

### 3.3 Windows 网络配置（M3 已实现并提交，实机验收待 M6）

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

### 3.4 GUI 平台适配（M4 已实现并提交）

| 项 | 状态 |
|---|---|
| profile 目录 | ✅ `%LOCALAPPDATA%\RustVPN\profiles`（含 USERPROFILE 回退；BOM profile 可读） |
| 钥匙串 | ✅ `keyring` + `windows-native`（Credential Manager）；交互式会话 roundtrip 通过 |
| 开机自启 | ✅ HKCU Run，`--minimized`（实机开关验证）；Linux XDG 不变 |
| 系统语言 | ✅ `GetUserDefaultUILanguage` primary language，用户选择优先 |
| daemon 信息 | ✅ 显示 `\\.\pipe\rustvpn-clientd` 与类型/服务提示 |
| 文件权限 | ✅ 受保护 DACL（owner/SYSTEM/Administrators），失败即保存失败 |
| 服务端身份校验 | ✅ PID + 镜像路径 + Authenticode publisher，发口令前拒绝未验证服务端；实机 debug daemon 校验通过 |
| 托盘/单实例 | ✅ 托盘图标、关闭到托盘、第二次启动退出均实机验证 |
| 安全开关可见性 | ✅ kill-switch/MSS 只读显示 Windows 不支持，不隐藏 |
| 更新 | ✅ Windows `managed_by_msi=true`，应用内更新关闭；MSI 属 M5 |

### 3.5 安装与分发

| 项 | 状态 |
|---|---|
| MSI/WiX | ✅ 独立 WiX 3.14 项目；包含 GUI、daemon、Wintun、文档/许可证 |
| 服务注册 | ✅ LocalSystem、自动延迟启动、5/10/30 秒失败恢复、升级/卸载控制；实机验证 |
| Wintun DLL | ✅ 版本/SHA 固定、amd64 校验、绝对路径、许可证随包 |
| Authenticode | 🟡 签名钩子/未签名标记/验证已实现；本机无证书，正式发布需 EV/OV |
| 版本映射 | ✅ `0.2.0-beta.1` → `0.1.99.0`；同版本 beta 升级实测 |
| 卸载清理 | ✅ 停服务、删文件/快捷方式/注册表/SCM；profile 保留；组/ProgramData 按设计保留 |
| Windows CI | ✅ `windows-client.yml` 构建/测试/未签名 MSI/静态检查；未在本机运行 |
| Wintun 许可 | ✅ WireGuard 预编译许可证、版本、SHA 随包 |

### 3.6 测试与验收

| 项 | 说明 |
|---|---|
| Windows 实机 E2E | 🟡 分流 plain/UDP 两次通过（第二次 ping 4/4、TCP 横幅）；noise/encless 未实测 |
| 基本连通 | 🟡 ping 网关与新增分流路由、TCP 双向已实测；DNS 解析、大包未实测 |
| 模式覆盖 | ⬜ plain 已测；noise、encless（TCP）、UDP/TCP 外层未实测 |
| 断线恢复 | 🟡 工作区已重排断开顺序（stop/join reader → 删路由/DNS/NRPT 保留地址 → 关适配器 → 无后续查询），未提交、未在 VM 验证；超时/重连/切网/休眠未测 |
| 路由/DNS 清理 | 🟡 连接态正确；断开清理新顺序已实现并有 Linux 单测，仍须一次性 VM 按矩阵验收 |
| kill-switch | ⛔ Windows 明确不支持；profile/guard 拒绝 |
| 安装测试 | 🟡 MSI 安装 + 真实隧道已实测；升级/卸载在 M5 已实测；干净 VM 待补 |
| 安全测试 | 🟡 `verify-client-access`、非成员拒绝、口令不落盘、DLL 哈希已测；假服务端/签名固定未补 |
| 垫片 fuzz | ✅ 7 个确定性 fuzz 测试；发现并修复 `/0` 广播移位溢出 |
| 性能 | ⬜ 未测（断开会致主机失联；需在一次性 VM 中做吞吐/CPU/延迟） |

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
| 假管道服务端 | GUI 可能把口令发给恶意进程 | ✅ M4 在发口令前校验 PID + 镜像名/安装路径 + Authenticode publisher；残留：debug 构建允许同目录未签名 daemon（便于 `cargo tauri dev`），有目标目录写权限的同用户进程仍可通过；只校验嵌入 Authenticode（catalog-only 视为未签名），接受条件是 subject 含 `RustVPN` 而非证书 pin，M5 应固定证书/指纹 |
| 服务端镜像校验的进程访问权 | ✅ 已解决：daemon 启动时给 pipe 同组/INTERACTIVE 授予 `PROCESS_QUERY_LIMITED_INFORMATION`（仅查询），标准用户实测可解析 LocalSystem 服务镜像并完成 Hello；未授予内存/句柄/终止权限。残留：日志会记录被拒绝客户端的 SID 组列表，但不含口令/profile |
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
| M3 网络 | 路由/DNS/NRPT、防环、IPv6 阻断、清理 | 🟡 已提交；Windows 实机路由/DNS 验收待 M6 | 全隧道无泄漏，断开恢复 |
| M4 GUI | 路径/钥匙串/自启/语言/状态/服务端身份 | ✅ 已提交 `7b73a82`，Windows RDP 实机验证 | 普通用户基础操作（真实服务端 E2E 归 M6） |
| M5 安装 | MSI、服务安装、组/DACL、Wintun、签名钩子、Windows CI | ✅ 已提交 `cb39124`；MSI 静态检查、安装/升级/卸载、标准用户/非成员、GUI RDP 已实测 | 干净 Win10/11 安装/升级/卸载；无证书构建标记为 unsigned |
| M6 硬化 | E2E、休眠/切网、fuzz、CI、性能 | 🟡 `7f05a3e`：分流 + 全隧道 plain/noise、DNS/NRPT、IPv6 阻断、Disconnect/服务重启清理、rekey/重连、链路抖动、强杀恢复、iperf3 性能、fuzz、手动 CI；encless/休眠/互联网出口/CI 实跑/签名待条件 | 全隧道无泄漏、断开恢复、性能基线 |

**当前状态：** M1–M6 代码已提交，Disconnect 根因修复为 `f4cc06e` 并已物理机验证：

- 根因是 daemon 内 `Get-NetRoute | Remove-NetRoute -PolicyStore ActiveStore`
  pipeline 在路由已消失/过滤为空时可能扩大删除范围，导致整机路由被删、约
  13–16 秒后网络失联。
- 修复改为直接 `Remove-NetRoute -DestinationPrefix ... -InterfaceIndex ...
  -NextHop ... -RouteMetric ... -Confirm:$false`，无 pipeline/无 `-PolicyStore`。
- 正常 Disconnect 保留防环 `/32` + `netstate.json`，关闭 Wintun 适配器后立即
  发布 idle；下次 Connect/daemon 启动在无适配器时直接清理并清状态。
- 物理验证：Disconnect 后主机存活 >130s；下次启动清理后存活 >145s；默认路由
  `192.168.110.1` 未变，防环/netstate 正确清除。
- OpenVPN 调研确认 Windows 客户端应优先使用 IP Helper
  `DeleteIpForwardEntry2`/`route.exe`，而不是 PowerShell/WMI 路由；当前直接
  cmdlet 是已验证的过渡实现，后续可替换为 Win32 API。

全隧道在 Windows 11 VM 验收通过：

- 默认路由切到 Wintun，防环 `/32` 走原物理路径
- NRPT `.` → 隧道 DNS，`Resolve-DnsName` 成功
- IPv6 `2000::/3`/`fc00::/7` 阻断，loopback/link-local 可用
- Disconnect 恢复默认路由/DNS/NRPT/IPv6；防环/netstate 延迟清理
- 服务重启后直接路由删除，清理成功
- 修复了防火墙/NRPT 规则不存在时 `Remove-*` 退出码 1 导致清理失败的问题
  （`7f05a3e`），无 seed 规则复测通过
- noise 模式通过；encless 因外层容量未测

M6 VM 硬化验收已通过：

- rekey 60s：140s 内两次重协商，68/69 ping 成功，状态未抖动
- 服务器短暂下线：reconnect 恢复，8 个丢包集中在 28s 断线窗口
- 网卡 down 12s：会话透明存活；down 30s：超时后自动重连并恢复路由
- 强杀 daemon 两次：SCM 重启、防环/netstate 启动清理、默认路由正常
- iperf3 split tunnel：VM→server ~174 Mbit/s，server→VM ~150 Mbit/s；
  VM 到 server 延迟 avg 4.9ms
- 残余：反向 193 次重传、`last_handshake_unix` 未暴露、crash 清理约 10–15s
  异步窗口

剩余 M6（条件不满足）：encless/TCP（1500B 外层容量）、休眠/唤醒（VM 禁用
suspend）、互联网出口（需 NAT 测试环境）、Windows CI 实际运行（需推送）、
真实证书签名（无证书）。

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
4. M4 验证（Windows 实机）：
   - `cargo test -p rustvpn-client-gui --target x86_64-pc-windows-msvc`
   - `cargo test -p rustvpn-client-gui --target x86_64-pc-windows-msvc windows_credential_manager_save_get_delete_roundtrip -- --ignored`
     必须在可交互登录的桌面会话运行；无交互会话（SSH）会因
     `ERROR_NO_SUCH_LOGON_SESSION` 明确跳过。
   - 启动 GUI 检查托盘/关闭到托盘/单实例/`--minimized`；用 `--console`
     daemon 检查命名管道连接和服务未运行提示。
5. M5 验证（Windows 实机，按 [`windows-install.md`](windows-install.md)）：
   - `packaging\windows\build-msi.ps1`，再用 `verify-msi.ps1` 做
     `msiexec /a` + MSI 表 + dark 静态检查。
   - 安装后检查服务/延迟启动/失败恢复/组，运行
     `verify-client-access.ps1`（管理员、RustVPN 组成员、非成员）；GUI 在
     RDP 会话启动；随后同版本升级、卸载与 profile 保留。
   - 不连接隧道、不改默认路由/DNS/现有 VPN/防火墙；无证书时确认
     `UNSIGNED.txt` 且 `signtool verify /pa` 失败。
6. M6 在 Windows 实机验证：分流 E2E 两次通过；但**断开路径 2/2 复现导致
   Windows 主机网络栈失联**（断开前状态正确，日志已到 `disconnected`）。
   在一次性 VM 中按“只关闭适配器 / 只删地址”二分定位并修复前，禁止在
   可用主机上再次连接/断开。主机恢复后先读
   `C:\ProgramData\RustVPN\clientd.log` 最后几行和 System 事件
   （1074/109/41/42、NDIS/网络），确认挂起发生在清理命令还是 Wintun 关闭。
   随后检查 `%ProgramData%\RustVPN\netstate.json` 与临时路由；全隧道也只
   能在一次性 VM 中测试，避免切断 RDP/SSH。
7. 所有 Windows 网络测试只使用独立测试子网和临时适配器；不碰现有
   VPN/路由/防火墙。2026-11-27 的测试还留下 `D:\temp\rustvpn-m6` 和已安装
   的测试 MSI（ProductCode `{94FAB11C-141C-478E-A5B8-16D17C926075}`），
   人工须删除临时口令/脚本并卸载 MSI。
8. 每完成一个里程碑，更新本文件的“已完成/未开始/隐患”和提交记录。

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