# RustVPN — 与 GoVPN 5.7 线兼容的 Rust 重写

[English](README.md) | **中文** | [Русский](README.ru.md)

RustVPN 是从零开始用 Rust 实现的 GoVPN 5.7 协议。它不是一套新的 VPN 设计：它使用完全相同的线格式（wire format），因此其 `rustvpn-server`、`rustvpn-client` 和 `rustvpn-verifier` 可执行文件可以替换现有部署中任意一侧的 Go 程序。

本仓库包含独立的 RustVPN 实现。上游 Go 代码树不包含在本仓库中、也不会被修改，仅用作差分测试的对照基准（oracle）。

## 亮点

- **PAKE 握手** —— 基于口令认证的增强型 Diffie-Hellman 密钥协商（DH A-EKE），具备零知识双向认证。
- **强验证器（verifier）** —— Argon2d + Ed25519 令牌，可抵御离线字典攻击；即使服务器上的验证器泄露，攻击者也无法冒充客户端。
- **认证传输** —— Salsa20 + Poly1305，基于 XTEA 的序列混淆，257 位重放窗口，以及完美前向保密。
- **抗审查** —— 握手与传输字节与随机数据无法区分；可选的 `noise` 填充隐藏包长度。
- **无加密模式（encless）** —— 通过 AONT + Chaffing-and-Winnowing，在不使用加密函数的情况下提供机密性（客户端仅支持 TCP）。
- **运维对等** —— 相同的 CLI 标志与默认值，相同的 `peers.yaml` 格式与 60 秒热重载，相同的 `up`/`down` 脚本环境，相同的 JSON 统计字段，相同的 UDP/TCP/HTTP-CONNECT 代理行为。
- **性能优化** —— 稳态零分配编解码器，`recvmmsg`/`sendmmsg` 批量处理，带 epoll 回退的 io_uring TAP 后端，以及支持运行时分派的 AVX2 Salsa20 后端。
- **可选管理端** —— 独立进程 `rustvpn-admind` 提供 Web UI，查看客户端与流量、增删改/禁用/轮换/踢下线，并安全管理 `peers.yaml`；它通过本地控制 socket 与 `rustvpn-server` 协作，默认构建不受影响。

## 状态

已实现并针对 Go 5.7 代码完成差分测试：

| Crate | 内容 |
|---|---|
| `rustvpn-crypto` | XTEA、Salsa20/XSalsa20、Poly1305、BLAKE2b-256、Chaffing-and-Winnowing、AONT、encless、Argon2d/Ed25519 验证器、EGD 读取器、`extra25519` 代表编码 |
| `rustvpn-proto` | Classic/noise/encless 传输编解码器、重放窗口、TCP 分帧、面向两种角色的完整 PAKE 握手 |
| `rustvpn-net` | TAP 设备、YAML 配置 + 热重载、脚本、统计、心跳/CPR/rekey 生命周期、UDP 批量、io_uring TAP |
| `rustvpn-client` / `rustvpn-server` | UDP 与 TCP 传输、HTTP CONNECT 代理、noise 与 encless 模式、统计端点、优雅关闭 |
| `rustvpn-verifier` | 与 CLI 兼容的验证器生成器/校验器 |

互操作性已完成端到端验证（loopback + TAP + network namespace、经隧道的 ICMP）：

| 方向 | UDP | TCP | Proxy | Noise | Encless |
|---|---|---|---|---|---|
| Rust 客户端 → Go 服务器 | 是 | 是 | 是 | （协议字节已验证）* | （协议字节已验证）* |
| Go 客户端 → Rust 服务器 | 是 | 是 | 是 | 是 | 是 |
| Rust 客户端 → Rust 服务器 | 是 | 是 | 是 | 是 | 是 |

\* 在此环境中，Go 的 water TAP 读取器会间歇性报告 `not pollable`；当 TAP 预先创建时，同一个 Go 服务器工作正常。无论如何，线格式均由字节精确的握手/传输向量覆盖。

尚未实现：面向 FreeBSD/macOS 的移植打包（目前仅在 Linux 上验证），以及 TAP 接口的有效 MTU（effective-MTU）自动处理。

## 快速开始

依赖：Rust >= 1.85、Linux `/dev/net/tun`，以及用于创建 TAP 的 root 或 `CAP_NET_ADMIN`。

```bash
cargo build --release
# binaries: target/release/rustvpn-{server,client,verifier}

# 1. Generate a verifier (prints the long form then the short form)
echo 'correct horse battery staple' > /tmp/rustvpn.pass
target/release/rustvpn-verifier -key /tmp/rustvpn.pass

# 2. Start the server (peers.yaml uses the Go format)
target/release/rustvpn-server -proto udp -bind 0.0.0.0:1194 \
    -conf /tmp/peers.yaml -stats 127.0.0.1:1294

# 3. Start the client (short verifier form)
target/release/rustvpn-client -remote server:1194 -proto udp -iface tap0 \
    -verifier '$argon2d$m=4096,t=128,p=1$...' -key /tmp/rustvpn.pass \
    -up /path/to/up.sh -down /path/to/down.sh
```

```yaml
# /tmp/peers.yaml
alice:
  iface: tap0
  mtu: 1515
  timeout: 60
  noise: false
  encless: false
  verifier: $argon2d$m=4096,t=128,p=1$...$...
  up: /path/to/up.sh
  down: /path/to/down.sh
```

服务器在打开 TAP 设备**之前**运行 `up`，因此脚本必须自行创建持久化的 TAP（`ip tuntap add ... mode tap`）；客户端则先打开自己的 TAP，在会话建立后再运行 `up`。完整流程见[快速上手](docs/zh/getting-started.md)。

## 文档

手册提供三种语言版本，每种语言位于各自独立的目录：

| 语言 | 入口 |
|---|---|
| English | [`docs/en/index.md`](docs/en/index.md) |
| 中文 | [`docs/zh/index.md`](docs/zh/index.md) |
| Русский | [`docs/ru/index.md`](docs/ru/index.md) |

中文页面：

- [概述与概念](docs/zh/index.md)
- [快速上手](docs/zh/getting-started.md)
- [配置参考](docs/zh/configuration.md)
- [协议](docs/zh/protocol.md)
- [运维与部署](docs/zh/operations.md)
- [安全](docs/zh/security.md)
- [常见问题](docs/zh/faq.md)
- [设计](docs/zh/design.md)
- [性能](docs/zh/performance.md)
- [管理端 Web UI（可选）](docs/admin-web-ui.md)
- [客户端桌面 UI（Linux，deb/rpm，中/英/俄界面）](docs/client-ui.md)

## 测试与基准

```bash
cargo test
cargo run --release -p rustvpn-crypto --example crypto_bench
cargo run --release -p rustvpn-proto  --example proto_bench
cargo run --release -p rustvpn-net    --example mmsg_bench
```

测试使用从上游 GoVPN 5.7 代码树生成的 `testdata/go_vectors.json`，该文件已纳入版本控制，因此测试套件是自包含的。重新生成它需要上游 Go 源码及其附带的向量生成器；本仓库不包含 Go 代码树。

## 验证器互操作

```bash
# RustVPN 校验 GoVPN 生成的 verifier：
target/debug/rustvpn-verifier -verifier "$LONG_FORM" -key pass.txt

# GoVPN 校验 RustVPN 生成的 verifier：
./govpn-verifier -verifier "$(target/debug/rustvpn-verifier \
    -key pass.txt -m 1024 -t 4 -p 1 | head -1)" -key pass.txt
```

两个方向目前都会输出 `true`。

## 与 GoVPN 的关系

RustVPN 是同一协议的独立实现，遵循 **GPL-3.0-or-later** 许可证，与 Go 项目一致。它不修改 Go 代码树；两套实现可以在不同端口/网络上并行运行。

## 许可证

GPL-3.0-or-later。