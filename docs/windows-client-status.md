# Windows 客户端开发状态

> 最后更新：2026-11-27
> 分支：`feature/client-ui`
> 状态：M1（核心接入，已提交）与 M2（服务 + 本地 IPC，未提交）代码完成
> 相关文档：
> - [Windows 客户端调研与方案](windows-client-research.md)
> - [Windows 开发环境与依赖](windows-dev-environment.md)
> - [P0 决策与修复状态](p0-decision-review.md)
> - [客户端桌面 UI](client-ui.md)

---

## 0. 一句话状态

Windows 端已经完成 **开发环境 + Wintun/以太网垫片原型**，并完成了 **M1 核心接入**（已提交 `9bc1466`）和 **M2 服务 + 本地 IPC**（本地未提交）：命名管道传输、DACL、客户端身份校验、Windows SCM 服务外壳、命名互斥量隧道锁，以及 `--console` 端到端 IPC 测试。路由/DNS/NRPT（M3）、GUI 平台适配（M4）、MSI/服务安装（M5）仍未开始。M2 的 Windows 目标交叉检查与 clippy 通过，Linux 上 console 端到端测试通过；Windows 实机上的同名测试与 SCM 启停验证仍需在 Windows 主机执行。

---

## 1. 当前基线

| 项 | 状态 |
|---|---|
| 代码分支 | `feature/client-ui` |
| 最近提交 | `9bc1466 feat(windows): integrate Wintun shim into client core`（M1） |
| M2 改动 | 工作区未提交（IPC 传输/安全、clientd 服务、隧道锁、文档） |
| 前一个提交 | `8d31571 fix(kill-switch): recover DNS after partial narrow failure` |
| 远端 | 领先 `origin/feature/client-ui`，**未推送** |
| 主仓库剩余改动 | M2 完成后需复审与提交；Windows 实机测试待执行 |
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

### 2.7 M2 服务 + 本地 IPC（本地未提交）

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
    对 `rustvpn-client-ipc`、`rustvpn-clientd`、`rustvpn-client-core` 通过；
    链接/运行需 Windows 主机 MSVC
  - 未执行：Windows 实机命名管道 E2E、SCM 启停、第二用户越权连接测试

---

## 3. 尚未开始（M3 及以后）

### 3.1 核心集成（M1 已完成）

`TapConfig`/平台门面、`Tap` ↔ shim、异步桥接、Engine 接线与共享 MTU/Mode
已在 `9bc1466` 完成。剩余网络配置（地址/网关/DNS、路由、IPv6 阻断）属 M3。

### 3.2 Windows 服务与 IPC（M2 已实装，剩余项）

| 项 | 状态 |
|---|---|
| Windows 服务 | 🟡 代码完成；SCM 启停实机验证、服务注册/失败恢复策略属 M5 |
| 命名管道 / 帧 | ✅ 代码完成，Linux 端端到端测试通过；Windows 实机测试待跑 |
| 管道 DACL | ✅ SYSTEM + Administrators + INTERACTIVE / `-pipe-group` 专用组 |
| 客户端身份校验 | ✅ PID + token 组校验；GUI 侧服务端签名校验属 M4 |
| IPC v2 | ✅ 帧/Hello 不变 |
| 隧道锁 | ✅ `Global\RustVPNTunnel`，崩溃由 OS 释放；实机测试待跑 |
| 服务停止清理 | 🟡 与 Linux 共用 shutdown 路径；Windows 路由/DNS/NRPT/防火墙清理属 M3 |
| 多用户/会话策略 | ⬜ M5 安装器创建 `RustVPN` 组并加用户；当前默认 INTERACTIVE |

### 3.3 Windows 网络配置

| 项 | 说明 |
|---|---|
| Wintun 地址/网关/DNS | 由服务配置，不接受 GUI/配置任意脚本 |
| 防环 `/32` | 先给外层 endpoint 加原网关主机路由 |
| 默认/分流路由 | 记录并恢复原默认路由，只删除自己添加的项 |
| DNS/NRPT | 全隧道强制隧道 DNS，断开恢复 |
| IPv6 | 不承载；全隧道需阻断或明确告警，避免泄漏 |
| DHCP | MVP 静态地址；若服务端 LAN 只支持 DHCP，需另行设计 |
| 休眠/切网 | Wintun/session 失效检测与恢复 |
| 崩溃残留 | 状态文件 + 启动清理 |

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
| IPv6 不承载 | 全隧道可能泄漏 IPv6 | 防火墙阻断或强告警；不要声称完整全隧道 |
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
| kill-switch fail-open | 崩溃/重启可能恢复明文出口 | 明确策略；启动清理；必要时 fail-closed |
| SSH 管理员 | Ubuntu 侧被攻破即 Windows 管理员 | 限制 SSH、密钥、专用账号、审计 |
| 日志/配置泄密 | 口令、代理凭据、verifier 泄露 | 不落盘、不进日志、status 脱敏 |
| 自动更新 | 普通用户进程替换服务文件 | 服务安装模式关闭自更新；走签名 MSI |

### 4.3 可靠性

| 隐患 | 影响 | 处理建议 |
|---|---|---|
| Wintun 阻塞读 | 可能卡住 async worker/持锁死锁 | 使用已验证的 `ShimPump` 设计，锁内不做 I/O |
| 适配器残留 | 崩溃后 `RustVPN-Spike`/TAP 残留 | 启动清理；状态文件；卸载删除 |
| 路由/DNS 残留 | 断网、DNS 劫持、无法上网 | 记录原状态；失败回滚；崩溃清理 |
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
| M2 服务/IPC | Windows 服务 + 命名管道 + DACL + 锁 | 🟡 代码完成（未提交）；Windows 实机测试待跑 | GUI 可连接/断开，无权限越界 |
| M3 网络 | 路由/DNS/NRPT、防环、IPv6 阻断、清理 | ⬜ 未开始 | 全隧道无泄漏，断开恢复 |
| M4 GUI | 路径/钥匙串/自启/语言/状态显示 | ⬜ 未开始 | 普通用户完整操作 |
| M5 安装 | MSI、服务安装、签名、Wintun DLL | ⬜ 未开始 | 干净 Win10/11 安装/升级/卸载 |
| M6 硬化 | E2E、休眠/切网、fuzz、CI、性能 | ⬜ 未开始 | 验收矩阵通过 |

**当前阻塞：** M1/M2 代码已在工作区/分支上；M2 需要在 Windows 主机执行实机 E2E
（命名管道 + `--console`）、SCM 启停和越权连接测试，并完成复审后提交。M3
（路由/DNS/NRPT）在 M2 复审后开始。

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
4. M2 复审/提交后开始 M3（路由/DNS/NRPT、防环、IPv6 阻断、崩溃清理）。
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