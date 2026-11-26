# Windows 客户端开发环境与依赖

> 日期：2026-11-26
> 适用：RustVPN Windows 客户端（Tauri GUI + `rustvpn-clientd` 服务）
> 相关文档：[`windows-client-research.md`](windows-client-research.md)

本文只列开发/构建/测试 Windows 客户端所需的软件与 Cargo 依赖，不包含服务端改动。

---

## 一、Windows 环境要求

- Windows 10 22H2 或 Windows 11 x64。
- 必须是带桌面的版本（需要 WebView2、托盘、服务管理器），不要用 Server Core/无头环境。
- 建议至少 8 GB 内存；构建 Tauri 与 MSI 建议 16 GB。
- VS Build Tools 与 Windows SDK 占用较大，安装前确认目标盘剩余空间。
- 当前测试机为 Windows 10 Pro 19045 x64，可作为基线。

---

## 二、Windows 上必装的软件

### 1. 编译工具链（必需）

| 软件 | 用途 |
|---|---|
| Visual Studio 2022 Build Tools | 提供 MSVC 链接器和 Windows SDK |
| workload：Desktop development with C++ | 必选 |
| 组件：MSVC v143 x64/x86、Windows 10/11 SDK | Rust MSVC 目标需要 |
| Rustup + stable Rust ≥ 1.90 | GUI crate 的 MSRV 是 1.90 |
| `x86_64-pc-windows-msvc` target | 不要用 GNU target |

```powershell
rustup target add x86_64-pc-windows-msvc
rustc -V
cargo check --workspace --target x86_64-pc-windows-msvc
```

### 2. GUI 与打包（必需）

| 软件 | 用途 |
|---|---|
| WebView2 Evergreen Runtime | Tauri 的 WebView；Windows 11 通常自带，Win10 可能要装 |
| Tauri CLI 2.x | `cargo install tauri-cli --version "^2"` |
| WiX Toolset 3.x | 构建 MSI、安装 Windows 服务；Tauri 可能自动下载，离线环境需预装 |
| Git for Windows | 版本控制 |
| Wintun DLL（x64） | 从 wintun.net 下载当前稳定版，固定版本和 SHA-256 |

项目前端是静态 HTML/JS，**不需要 Node.js**。

### 3. 调试与测试（强烈建议）

| 工具 | 用途 |
|---|---|
| `sc.exe`、`reg.exe`、`netsh` | 服务、注册表、路由/DNS 调试 |
| PowerShell `Get-NetRoute` / `Get-NetAdapter` / `Resolve-DnsName` | 验证路由和 DNS |
| Sysinternals Suite | Process Explorer、DebugView、Procmon、Autoruns |
| `pktmon`（Windows 自带） | 抓 Wintun/虚拟网卡流量 |
| Wireshark + Npcap（可选） | 抓 UDP/TCP 外层流量 |
| Windows 事件查看器 | 服务启动/停止/崩溃日志 |
| `signtool.exe`（Windows SDK） | 验签/签名 |
| `tauri-driver` + Edge WebDriver（可选） | GUI 自动化测试 |

服务模式下 `eprintln!` 不可见；实现时应写文件日志或 Event Log，否则调试会很痛苦。

### 4. 签名（正式发布才需要）

- Authenticode 代码签名证书；
- EV 证书通常配 USB Token，物理 Windows 或 USB 直通虚拟机；
- 开发阶段可以先用未签名版本，不阻塞功能开发。

---

## 三、Cargo 侧要新增的依赖

| crate | 用途 |
|---|---|
| `windows-service` | Windows SCM 服务集成 |
| `windows` 或 `windows-sys` | 命名管道 DACL、命名互斥量、IP Helper、语言、注册表 |
| `wintun-bindings` | 直接操作 Wintun（也可继续用 `tun` 的 Windows L3 后端） |
| `tokio` 的 `net` feature | Windows 命名管道 `tokio::net::windows::named_pipe` |
| `keyring` + `windows-native` | Windows Credential Manager |
| `tauri-plugin-autostart`（可选） | HKCU 开机自启 |
| `dirs` / `directories`（可选） | `%LOCALAPPDATA%` 等路径 |

Wintun DLL 建议放在 `vendor/windows/wintun/`，同时附 `LICENSE` 和 `SHA256SUMS`；不要提交证书私钥。

---

## 四、最小可开工环境

先做到这四条，就可以进入 Phase 0：

1. Windows 10/11 x64 机器或虚拟机，能装驱动、有桌面。
2. VS Build Tools + Windows SDK + Rust MSVC target。
3. WebView2 + Tauri CLI。
4. `wintun.dll` x64 + WiX Toolset。

然后在 Windows 上跑：

```powershell
cargo check --workspace --target x86_64-pc-windows-msvc
cargo test -p rustvpn-net --target x86_64-pc-windows-msvc
```

---

## 五、安装前检查

```powershell
# 查看磁盘空间，确认 VS Build Tools / Windows SDK 的安装盘
Get-Volume | Where-Object DriveType -eq 'Fixed' |
    Select-Object DriveLetter, FileSystemLabel,
        @{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}},
        @{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,1)}}

# 查看已有工具
foreach ($c in 'winget','git','rustc','cargo','rustup','msbuild','link','signtool','wix','tauri') {
    $x = Get-Command $c -ErrorAction SilentlyContinue
    if ($x) { "$c -> $($x.Source)" } else { "$c -> MISSING" }
}
```

如果 C: 剩余空间不足，应把 Visual Studio Build Tools、Windows SDK 和 Cargo 缓存迁到空间充足的数据盘，不要在系统盘上硬塞到低于 2 GB 可用空间。