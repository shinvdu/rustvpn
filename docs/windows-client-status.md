# Windows 客户端开发状态

> **最后更新：** 2026-11-28
> **分支：** `feature/client-ui`
> **HEAD：** 以 `git log -1` 为准
> **同步状态：** 以 `git status` 为准
> **工作区：** 以 `git status` 为准；2026-11-28 第三轮复审修复已提交
> **问题索引：** `docs/windows-client-dev/windows-client-issues.xlsx`（仅本地）
> **问题详情：** `docs/windows-client-dev/issues/WIN-<NNN>-<slug>.md`（仅本地）

**总体状态：** M1-M5 已完成，M6 代码完成且大部分验收已完成。剩余项均为受条件阻塞或范围受限的排查，而非缺少 M6 实现。

相关文档：[Windows 安装/签名](windows-install.md) ·
[Authenticode 签名科普](authenticode-signing-primer.md) ·
[Windows 调研](windows-client-research.md) ·
[开发环境](windows-dev-environment.md) ·
[P0 决策](p0-decision-review.md) · [桌面 UI](client-ui.md)

---

## 1. 快照

| 项目 | 状态 |
|---|---|
| 里程碑 | M1-M5 已完成并提交；M6 代码完成，验收基本完成 |
| Windows 目标平台 | Windows 10/11 x64；ARM64 延期 |
| 安装程序 | 每机器安装的 MSI/WiX；开发自签 Authenticode 已验证，正式 EV/OV/发布签名待办 |
| 服务 | LocalSystem `rustvpn-clientd`，自动启动（非延迟），失败恢复；卸载时执行 `--cleanup` |
| 传输 | Wintun L3 + 进程内以太网 shim；仅 IPv4 |
| 验证主机 | Windows 10 物理机（分流隧道）、Windows 11 虚拟机（全隧道与加固） |

## 2. 里程碑

| 阶段 | 代码 | 状态 | 验收摘要 |
|---|---|---|---|
| M1 核心集成 | `9bc1466` | 完成 | 平台中立的 `TapConfig`、Wintun 后端、以太网 shim、有界异步 pump、引擎接线。Windows 目标可构建；真实 E2E 延后到 M6。 |
| M2 服务 + IPC | `8cef993`, `8132f24` | 完成 | 命名管道、显式 DACL、对等身份、SCM/控制台守护进程、隧道锁。Windows IPC/锁测试与标准用户访问通过。 |
| M3 网络配置 | `cac143a`, `06a092b` | 完成 | 地址/路由/DNS/NRPT/IPv6 防护、防环路路由、ACL 受限的 netstate、崩溃清理。真实 Windows 契约缺陷已修复，分流隧道路由在 M6 中验证。 |
| M4 GUI 适配 | `7b73a82` | 完成 | 配置 ACL、Credential Manager、HKCU 自启动、区域设置、命名管道信息、密码前守护进程身份校验。RDP 验证通过。 |
| M5 打包 | `cb39124` | 完成 | MSI、LocalSystem 服务、RustVPN 组、进程查询 DACL、Wintun 固定、签名钩子。安装、同版本升级、卸载以及标准用户访问均已验证。 |
| M6 加固 + E2E | `06a092b` … `ffe9657` | 基本完成 | 分流/全隧道 plain+noise、DNS/NRPT、IPv6 阻断、断连修复、rekey/重连、链路抖动、强杀恢复、fuzz、iperf3；VPS 全隧道互联网出口通过；Windows CI 已真实运行并通过。2026-11-27/28 三轮代码复审与 Windows 实机验证新增登记 WIN-025…052；其中 27 项已修复（跨用户守护进程冒充、状态/事件通道校验、既有 Wintun 清理、pipe 抢占、IPC 资源上限、空地址查询与卸载 cleanup 竞态等）；WIN-013/014/045 仍待专项。受条件阻塞的项列于下文。 |

## 3. 已在 Windows 上验证

- **分流隧道（Windows 10 物理机）：** 握手、对两个测试地址 ping 4/4、通过隧道取得 TCP SSH banner、默认路由未被接管。
- **全隧道（Windows 11 虚拟机，plain 与 noise）：** 默认路由切换到 Wintun，防环路 `/32` 保留底层路径，NRPT `.` 经隧道 DNS 解析，IPv6 `2000::/3` 与 `fc00::/7` 被阻断。2026-11-28 复验再次 connected，ping `10.200.0.1` 3/4，`last_handshake_unix` 非 null。
- **断开连接：** 采用直接 cmdlet 修复后，物理机存活 >130 秒；下一次守护进程启动清理了防环路路由/netstate 并存活 >145 秒；原始默认路由保持不变。
- **服务重启：** 无 Wintun 适配器时的直接启动清理成功；当规则已不存在时，防火墙/NRPT 清理具备幂等性。
- **Rekey：** 60 秒 rekey 测试在 140 秒内产生两次 rehandshake，ping 成功 68/69，状态无抖动。
- **重连与链路抖动：** 服务器中断后经重连恢复；网卡断开 12 秒保持会话，断开 30 秒超时并重连且路由恢复。
- **崩溃恢复：** 两次强制终止守护进程后，SCM 重启并执行启动时路由/netstate 清理；默认路由两次均正确。2026-11-28 VM：SCM 5.25 秒重启，netstate 12.34 秒后消失，物理默认路由保持（WIN-014 窗口仍约 12 秒）。
- **性能：** 2026-11-28 VM split 隧道 forward iperf3 8 秒约 264 Mbit/s；此前反向约 150 Mbit/s 且出现重传（WIN-013），本次反向受测试环境限制未完成。
- **互联网出口：** 全隧道经临时 VPS NAT 验证；`ifconfig.me` 返回 VPS 公网 IP，`example.com` HTTP 200，1 MiB 下载完整；VPS TAP/NAT/防火墙已清理。
- **Windows CI：** `windows-client` workflow 已真实运行并通过（format/check/clippy/test/MSI/inspect/upload），commit `ffe9657`，run 45995988463。
- **自签 Authenticode：** `CN=RustVPN Development` 证书签名 GUI/daemon/MSI；导入 CER 到 VM Root + TrustedPublisher 后，`signtool verify /pa` 与 `Get-AuthenticodeSignature` 均为 Valid，服务/管道与 GUI 服务端身份校验通过。
- **Fuzz：** 7 个确定性 shim fuzz 测试；`rustvpn-net` 报告 118 个通过测试。
- **打包：** MSI 静态检查、真实安装、服务/组状态、标准用户管道访问、非成员拒绝、同版本升级、卸载并保留配置。2026-11-28 在 VM 重新验证：automatic 服务、owner SID `S-1-5-32-544` probe、Wintun smoke、split/full tunnel、`--cleanup` 等待 StopPending 约 15 秒后清空 netstate/anti-loop。

## 4. 未决排查

| 问题 | 症状 | 下一步 |
|---|---|---|
| WIN-013 | 反向 iperf3 约 150 Mbit/s，出现 193 次重传 | 抓包、与 MSS clamp 对比、检查 Wintun RX/队列计数器 |
| WIN-014 | 崩溃清理需约 10-15 秒才允许重连 | 替换或批量执行重度依赖 PowerShell 的启动清理；发布清理进度 |
| WIN-027（剩余） | 服务被显式停止后，普通用户仍可抢占 global pipe | 已加 30×2s bind 重试；console 生产管道 guard 已在 VM 验证拒绝 |
| WIN-045 | Windows 安全/并发 E2E 缺口 | 在自托管 runner 增加跨用户、假 pipe、既有 adapter、并发 shutdown 回归 |

## 5. 受条件阻塞

| 问题 | 事项 | 阻塞原因 |
|---|---|---|
| WIN-016 | 睡眠/休眠恢复 | 虚拟机未提供可用的挂起；稍后使用一次性物理硬件 |
| WIN-019（剩余） | 正式 EV/OV/发布签名 | 开发自签已验证；仍缺正式证书、时间戳与 publisher/certificate pinning |
| WIN-018（剩余） | 自托管 Windows E2E workflow | `windows-client-e2e.yml` 需要已注册的高权限 self-hosted runner；当前 runner 数 0，且 workflow 仅在 `feature/client-ui` |

## 6. 已知不支持或延期

| 问题 | 能力 | 决定 |
|---|---|---|
| WIN-020 | Windows kill-switch | 未实现；配置/防护层拒绝，UI 显示不支持。Windows 在设计上为 fail-open。 |
| WIN-021 | Windows MSS clamp | 延期；连接时告警并报告 `mss_applied=false`。 |
| WIN-024 | IPv6 传输 | 仅 IPv4 的 shim。全隧道阻断全局单播/ULA；环回/链路本地/组播保持本地。 |
| WIN-015 | Encless/TCP 模式 | 延期；AONT 扩展（约 4128 B）需要更多外层容量，且无 Windows E2E。 |
| WIN-023 | 仅 DHCP 的服务器网络 | 仅静态地址 MVP；未实现 DHCP 客户端。 |
| WIN-022 | Windows ARM64 | 仅 x64 打包与 Wintun 固定；ARM64 需独立矩阵。 |
| WIN-001 | 真正的 L2 特性 | Wintun L3 会丢失 VLAN、广播发现和非 IP EtherType；`tap-windows6` 仅作为未来备选记录在案。 |

## 7. 参考入口

- **问题索引（权威）：** `docs/windows-client-dev/windows-client-issues.xlsx` — 工作表 `问题列表`、`汇总`、`图例`。
- **问题详情：** `docs/windows-client-dev/issues/WIN-<NNN>-<slug>.md` — 每个文件一个问题，含简洁的证据与后续。
- 这两个路径**仅用于开发且仅本地**，通过 `.git/info/exclude` 排除，绝不能上传或提交。
- 安装/签名流程：[windows-install.md](windows-install.md)。
- 架构与理由：[windows-client-research.md](windows-client-research.md)。
- 工具链与虚拟机搭建：[windows-dev-environment.md](windows-dev-environment.md)。

## 8. 安全与可运维约束

- 绝不在状态文档、Excel 索引或问题文件中存储密码、私钥、验证器密钥、真实主机凭据或隧道密钥。使用通用的测试主机描述。
- 守护进程以 LocalSystem 运行。其命名管道使用显式受保护的 DACL 与对等令牌校验；GUI 可读取进程 owner/镜像，进程访问不授予内存、句柄复制或终止权限。
- 生产分发必须使用已签名的 MSI。未签名的开发构建在 `UNSIGNED.txt`、Product comments 和 `docs\SIGNING.txt` 中标记。
- Windows 没有 kill switch；不要声称具备与 Linux 等价的 fail-closed 行为。
- 仅在一次性虚拟机/主机及专用测试子网上运行连接/断开、路由、DNS、NRPT、IPv6 和崩溃测试。
- 验收期间不得修改现有 VPN、生产默认路由、DNS、NAT 或防火墙。
- Wintun 必须从安装的绝对路径加载，并使用固定的 SHA-256；该项用户不可配置。
- 日志可能包含被拒绝客户端的 PID/SID 列表，但不会包含密码、配置或密钥材料。

## 9. 后续行动

1. 抓取反向 iperf3 流量，评估 MSS/路径影响以处理 WIN-013。
2. 批量化或替换重度依赖 PowerShell 的启动清理，以缩短 WIN-014 的窗口。
3. 在一次性物理硬件上验证睡眠/恢复（WIN-016）。
4. 为自托管 Windows E2E 注册受保护 runner，并让 workflow 进入默认分支（WIN-018 剩余项）。
5. 获取 EV/OV 证书，签名 GUI/守护进程/MSI，启用发布时间戳并固定 publisher/certificate（WIN-019 剩余项）。
6. 在一次性 Windows 环境执行 WIN-045 的安全/并发 E2E。
7. 仅在具备足够容量的外层路径可用后，再重新评估 encless/TCP（WIN-015）。

## 10. 更新节奏

- Excel 索引即问题登记册；每个被发现、已修复、延期或阻塞的项都对应一行 `WIN-NNN` 和一个匹配的 Markdown 文件。
- 同时更新 Excel 行和问题 Markdown。状态文档保持高层视角：里程碑、已验证能力、阻塞项、决策。
- 在问题文件中记录提交、变更文件、测试与剩余风险，而不是在此写长篇叙述。
- 每次 Windows 代码提交后，更新 HEAD/同步行、里程碑表以及任何有变化的验证条目。
- 发现新问题时，先添加对应的 Excel 行与 Markdown 文件，再刷新本文档中的高层摘要。