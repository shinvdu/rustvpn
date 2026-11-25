# 设计

[English](../en/design.md) | **中文** | [Русский](../ru/design.md)

本页描述已实现的架构。原始设计提案保存在本仓库的 [`docs/design.md`](../design.md)（写于重命名之前，因此仍使用旧的 `govpn-*` 命名）；本版记录的是实际构建了什么以及为何如此。

## 目标

1. **线兼容优先。** Rust 可执行文件必须是 GoVPN 5.7 的即插即用替代品。协议字节、CLI 标志、默认值、`peers.yaml`、脚本、统计 JSON 与代理行为都属于兼容性范围。
2. **以第二实现作为对照基准（oracle）。** 针对 Go 代码的差分测试能捕获仅靠单元测试会漏掉的协议漂移。
3. **可预测的数据路径。** 稳态下无逐包堆分配、有界队列、显式缓冲区所有权以及批量 I/O。
4. **运维对等。** 与 Go 守护进程相同的部署模型、权限和诊断能力。

本版本的非目标：协议 v2、Windows/macOS、GUI、路由/NAT 管理、负载均衡控制面，或改动任何密码学算法（那会破坏互操作性）。

## 工作区布局

```text
.
├── crates/rustvpn-crypto/   # primitives, AONT/CnW/encless, verifier, EGD
├── crates/rustvpn-proto/    # packet layout, codec, handshake state machines
├── crates/rustvpn-net/      # TAP, config, scripts, stats, peer lifecycle,
│                            # UDP batching, io_uring TAP
├── crates/rustvpn-client/   # client binary
├── crates/rustvpn-server/   # server binary
├── crates/rustvpn-verifier/ # verifier binary
├── testdata/                # Go-generated differential vectors
└── docs/                    # this manual (en/zh/ru) + upstream design notes
```

`rustvpn-crypto` 和 `rustvpn-proto` 是不含异步与 I/O 的纯逻辑，因此可以独立进行单元测试与模糊测试。`rustvpn-net` 拥有面向操作系统的部分。可执行文件则是轻量的组合层。

## 控制面

守护进程运行在 Tokio 之上：

- TCP 会话与 HTTP CONNECT 代理是 Tokio 任务。
- 握手、TAP 打开、脚本与统计属于控制面工作。
- 握手准入使用令牌桶：每来源 IP 5/s（突发 10），全局 200/s（突发 400）；TCP 还使用并发信号量。
- 配置存放在 `RwLock<ConfigSet>` 中，每 60 秒刷新一次；解析失败则保留上一份配置。

每个 UDP peer 有一个解码任务，由 mpsc 通道喂入；TCP 则为每个连接设一个读取任务。这比原提案中的"每核一个 worker"刻意更简单：它保持了正确性和有界队列，而昂贵部分（批量、SIMD、缓冲区复用）在各任务内部处理。

## 数据路径

### 发送

1. 从 TAP 读取一帧。
2. 校验模式相关的载荷上限（`MTU-1`、`MTU-25` 或 `MTU-9`）。超尺寸帧会被拒绝并计数，绝不截断。
3. 写入 `0x80` 填充，可选地填充至 MTU（noise/CPR）。
4. 用 `Encoder::encode_into` 编码到复用的缓冲区中：序列号 → XTEA PRP → Salsa20 密钥流切分 → Poly1305 tag。
5. 将线缓冲区交给共享的 UDP 批处理器（`sendmmsg`，每次系统调用最多 64 个数据报），或将其写入 TCP 流。
6. 更新原子计数器并将缓冲区归还到池中。

### 接收

1. `recvmmsg` 每次系统调用返回最多 64 个数据报（或一个 TCP 帧）。
2. 用 `Decoder::decode_into` 解码到复用的 `payload`/`scratch` 缓冲区；在接受序列号之前先验证 MAC。
3. 更新重放窗口，去除填充，校验尾部零字节。
4. 将以太网帧写入 TAP（io_uring 或基于 epoll 的异步写入）。
5. 更新统计；重复/过旧的序列号会被计数并丢弃。

`encode_into`/`decode_into` 使 classic 与 noise 路径达成每包零分配；encless 由于 AONT/CnW 变换仍会分配。

### I/O 后端

- UDP：`recvmmsg`/`sendmmsg` 批量，每个 socket 一个共享批处理器。
- TAP：io_uring 配 eventfd 唤醒（无空闲唤醒），带 epoll 回退。`GOVPN_IO_URING=0` 强制使用回退路径。
- 重放窗口：`[u64; 5]` 风格的 257 位位图，O(1)，无哈希，无分配。
- Rekey：客户端在 4 GiB（`MAX_BYTES_PER_KEY = 1 << 32`）线流量后触发一次新的握手。

### SIMD

Salsa20 拥有 AVX2 后端，运行时派发位于 `rustvpn-crypto/src/salsa_simd.rs`，每次核心调用覆盖八个块（或八条相互独立的 CnW 密钥流）。标量 RustCrypto 路径作为参考实现，并与 AVX2 路径做差分测试。`unsafe` 面仅限于该模块；其余代码全部使用安全 Rust。

## 密码学选择

| 原语 | 实现 |
|---|---|
| Salsa20/XSalsa20 | RustCrypto `salsa20` + AVX2 快速路径 |
| Poly1305 | RustCrypto `poly1305`，通过 `.cargo/config.toml` 固定软件后端 |
| XTEA | 仓库内实现，与 Go 字节兼容 |
| BLAKE2b-256 | RustCrypto `blake2` |
| Argon2d v1.3 | RustCrypto `argon2`（`m/t/p`，32 字节输出作为 Ed25519 种子） |
| Ed25519 | `ed25519-dalek` |
| X25519 + Elligator | `curve25519-dalek` + Go `extra25519` 代表编码的移植 |
| 恒定时间 | `subtle` 用于 MAC/填充比较 |

Poly1305 固定软件后端是经过测量的选择：在 Zen3 上，该 crate 的 AVX2 后端每条消息有较大的固定成本，对小包而言比其标量后端慢数倍。Go 向量确认字节一致。参见[性能](performance.md)。

## 测试覆盖的协议不变量

- 握手：四种消息长度（48/80/120/16）、字段顺序、填充位置、`IDtag`，以及最终的主密钥。
- 传输：tag/ciphertext/nonce 布局、Salsa20 偏移、Poly1305 覆盖范围、序列号奇偶性/步长与 XTEA 字节序。
- 重放：UDP 窗口语义与 TCP 严格顺序规则。
- Encless：AONT/CnW 字节序列、4128 字节膨胀、XSalsa20 nonce 布局、最小长度拒绝。
- Noise：填充长度与零字节填充。
- Timesync：`IDtag` 中秒级粒度时间戳的 XOR。
- 验证器：字符串格式、Argon2d 参数、Ed25519 种子派生。
- 配置：字段名/默认值、MTU 钳制、encless→noise、长格式验证器要求。
- 脚本：`GOVPN_IFACE`/`GOVPN_REMOTE`；当 `iface` 为空时服务器使用 `up` 的 stdout。
- 统计：JSON 字段名/类型。
- 代理：CONNECT 响应与原始 TCP 交接。

## 测试策略

- **差分向量。** `testdata/go_vectors.json` 包含来自 Go 实现的字节精确输出，覆盖每个原语、传输模式、握手消息与验证器形式。测试对两个方向都进行比较。
- **单元/等价测试。** AVX2 对标量密钥流、CnW/AONT 往返、重放窗口性质、`encode_into` 与便捷 API 的等价性、回环 `sendmmsg`/`recvmmsg`，以及通过 io_uring 循环的 socketpair 往返。
- **互操作性矩阵。** `{Go,Rust} × {client,server} × {UDP,TCP,proxy} × {plain,noise,encless}`，配合 TAP 与 network namespace，包括经隧道的 ICMP。该矩阵记录在根 README 中。
- **模糊测试**（尚未接入 CI）是下一步的自然方向，覆盖包解析、握手状态、TCP 分帧、YAML/验证器解析以及 AONT/CnW 解码；纯逻辑 crate 使这变得直接明了。

## 偏差与待办事项

- 没有每核一线程的 `SO_REUSEPORT` 分片；每种协议一个 socket 配一个共享批处理器。更简单，而且实测收益来自批量与 SIMD 而非分片。
- 没有自动的有效 MTU 配置。
- FreeBSD/macOS 构建未测试。
- encless 路径仍会分配；一个基于缓冲池的 AONT/CnW 编码器是可行的。

下一步：[性能](performance.md)。