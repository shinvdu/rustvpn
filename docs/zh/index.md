# RustVPN 手册 — 概述

[English](../en/index.md) | **中文** | [Русский](../ru/index.md)

RustVPN 是用 Rust 对 GoVPN 5.7 的线兼容重实现。本手册说明如何构建、配置、部署并理解它。本手册改编自原始 GoVPN 手册，其中每条命令、标志和默认值均已对照 Rust 代码核对。

## 它是什么

RustVPN 是一个小型虚拟专用网守护进程，通过加密、认证的隧道连接 TAP 接口。它不是一套新协议：Rust 客户端可以与 Go 服务器通信，Go 客户端可以与 Rust 服务器通信，任意一侧的可执行文件都能在不改动另一侧的情况下被替换。

设计目标继承自 GoVPN：

- **可审阅** —— 紧凑的代码库，以及标准、易懂的密码学原语。
- **安全** —— 口令认证密钥协商、认证传输、完美前向保密、重放保护。
- **抗审查** —— 握手和传输消息看起来就像随机噪声；可选填充隐藏其长度与时序。
- **运维省心** —— 守护进程只搬运数据包。地址、路由、MTU 和 NAT 均由管理员配置，正如对待一根以太网线缆。

## 特性摘要

- PAKE DH A-EKE 握手，具备零知识双向认证。
- Argon2d + Ed25519 验证器（verifier），可抵御离线字典攻击。
- Salsa20 + Poly1305 传输，具有 128 位安全裕度。
- 可选无加密模式（AONT + Chaffing-and-Winnowing）。
- 噪声填充（noise）与可选恒定包速率（CPR）。
- 可选时间戳窗口，用于抵御握手重放。
- 内置重握手、心跳、超时与 JSON 统计。
- 内置握手限速（每来源 5/s，全局 200/s）。
- UDP 和 TCP 传输，两侧均支持 HTTP CONNECT 代理。
- 支持 IPv4 和 IPv6。
- 为 `/dev/urandom` 较弱的系统提供 EGD 熵守护进程支持。

## 术语

| 术语 | 含义 |
|---|---|
| **Peer（对端）** | 服务器 `peers.yaml` 中的一个具名客户端条目；每个 peer 对应一个 TAP 设备。 |
| **Identity（身份）** | 128 位、非机密的客户端标识符。用作 `IDtag` 的 XTEA 密钥以及 Argon2 盐。 |
| **Passphrase（口令）** | 在客户端输入、便于人类记忆的机密。 |
| **Verifier（验证器）** | 由 Argon2d 派生的令牌。服务器存储长格式（含 Ed25519 公钥）；客户端使用短格式。 |
| **Handshake（握手）** | 建立会话密钥的四消息 PAKE 交换。 |
| **Transport（传输）** | 握手之后使用的认证、加密（或编码）数据包格式。 |
| **Noise（噪声填充）** | 将每个出站数据包填充至配置的 MTU。 |
| **Encless（无加密模式）** | 用 AONT + Chaffing-and-Winnowing 代替流加密。 |
| **CPR（恒定包速率）** | 以配置的 KiB/s 速率发出填充流量。 |
| **MTU** | 配置的最大 TAP 帧大小。在 noise/encless 模式下可用载荷更小。 |

## 文档地图

| 页面 | 涵盖内容 |
|---|---|
| [快速上手](getting-started.md) | 构建、验证器、最小服务器/客户端、测试与基准。 |
| [配置](configuration.md) | 所有 CLI 标志、`peers.yaml`、脚本、MTU/timeout/CPR/stats/proxy。 |
| [协议](protocol.md) | 验证器/PAKE、握手消息、传输格式、noise、encless。 |
| [运维](operations.md) | systemd 部署、capabilities、轮换、故障排查。 |
| [安全](security.md) | 威胁模型、注意事项、密钥处理、加固清单。 |
| [常见问题](faq.md) | 设计问题以及"何时该使用 X"的解答。 |
| [设计](design.md) | 架构、数据路径、兼容性不变量、测试。 |
| [性能](performance.md) | Go 侧优化与同机 Rust-vs-Go 结果。 |

## 状态与限制

已实现并完成差分测试：全部密码学原语、完整握手、classic/noise/encless 编解码器、TAP、YAML 配置与热重载、脚本、统计、代理、UDP 批量、io_uring TAP 以及 AVX2 Salsa20。与 Go 可执行文件的互操作性已在两个方向上的 UDP、TCP、代理、noise 和 encless 上验证。

已知限制：

- 仅在 Linux 上验证过。FreeBSD 和 macOS 可能通过 `tun` crate 工作，但未测试；设置 `GOVPN_IO_URING=0` 可强制使用 epoll TAP 后端。
- 有效 MTU 不会自动调整。在 noise/encless 模式下，`up` 脚本应提高接口 MTU（或接受较小的载荷）。
- 客户端仅在 TCP 上支持无加密模式，与 Go 保持一致。

下一步：[快速上手](getting-started.md)。