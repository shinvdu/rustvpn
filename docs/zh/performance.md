# 性能

[English](../en/performance.md) | **中文** | [Русский](../ru/performance.md)

本页将 Go 侧的优化记录与同机 Rust-vs-Go 对比合并呈现。除非另有说明，所有数字均为数据包编解码器的微基准（不含 TAP、不含网卡），并且会因共享/虚拟化主机而波动；只应比较同一批次内的数字。

## 环境与方法

- CPU：AMD Ryzen 5 PRO 5675U（Zen3，AVX2），12 线程。
- Go 1.22.2 linux/amd64，`GO111MODULE=off GOPATH=$(pwd)`。
- Rust edition 2021，`cargo build --release`，运行时 AVX2 派发。
- Go：`-count 5 -benchmem`；Rust：`crypto_bench` / `proto_bench`，配内部计数分配器。结果为五次运行的中位数。
- 输入与 Go 基准对齐（`MTUDefault = 1515`）：classic 789 B、noise MTU 1490 B、encless 128 B、encless MTU 1506 B、CnW 16 B、AONT 128 B。

```bash
# Go（需要上游 GoVPN 5.7 源码树，本仓库不包含）
cd /path/to/upstream-govpn
GO111MODULE=off GOPATH=$(pwd) go test -run XXX -bench . -benchmem -count 5 \
  cypherpunk.ru/govpn cypherpunk.ru/govpn/cnw cypherpunk.ru/govpn/aont

# Rust（在本仓库根目录）
cargo build --release --examples
for i in 1 2 3 4 5; do ./target/release/examples/crypto_bench; done
for i in 1 2 3 4 5; do ./target/release/examples/proto_bench; done
```

## Go 侧优化

Go 实现先进行了优化，既为消除真实瓶颈，也为建立公平的基线。线字节保持不变。

| 改动 | 结果 |
|---|---|
| CnW：1 字节 Poly1305 公式 + 每包一次 HSalsa20 | Chaff **4.45×**，Winnow **6.72×** |
| Encless：移除中间切片/拷贝 | 128 B 解码 **5.49×**，MTU 解码 **5.44×**；解码分配 5 → 1 |
| Peer 发送路径：取消逐包 `append`，定点清零 | classic 加密 **1.54×**，解密 **1.13×**；分配 1 → 0 |
| Noise/encless MTU 校验 | 超尺寸帧被拒绝而非静默截断 |
| UDP 服务器数据路径 | 取消逐包 goroutine、取消每 peer 双缓冲限制、取消逐包字符串/全局锁 |
| 身份缓存、配置/TAP 并发 | 顺序扫描、RWMutex 快照、TAP 读取错误不再 panic |

前后对比（3 次中位数）：

| 场景 | 之前 | 之后 | 提升 |
|---|---:|---:|---:|
| classic 789 B 加密 | 2,805 ns | 1,827 ns | 1.54× |
| classic 789 B 解密 | 2,068 ns | 1,827 ns | 1.13× |
| classic noise MTU 加密 | 4,217 ns / 359 MB/s | 3,040 ns / 490 MB/s | 1.39× |
| encless 128 B 编码 | 32,817 ns | 11,232 ns | 2.92× |
| encless 128 B 解码 | 54,688 ns | 9,964 ns | 5.49× |
| encless MTU 编码 | 42,288 ns / 35.8 MB/s | 15,326 ns / 98.3 MB/s | 2.76× |
| encless MTU 解码 | 75,593 ns / 20.0 MB/s | 13,889 ns / 108.8 MB/s | 5.44× |
| CnW Chaff（16 B） | 41,097 ns | 9,235 ns | 4.45× |
| CnW Winnow（16 B） | 58,928 ns | 8,769 ns | 6.72× |

CnW 为何重要：Winnow 对每个数据包执行 512 次单字节 Poly1305 计算（256 个一次性密钥 × 2 个候选 tag）。通用 Poly1305 调用的开销主要来自密钥解析与终结，因此优化形式用一个 **130 位乘法**同时计算某密钥的两个候选 tag：

```text
block("0") = 0x30 + 0x01 * 2^8 = 0x130
block("1") = 0x131

h0   = 0x130 * r  mod (2^130 - 5)
h1   = (h0 + r)   mod (2^130 - 5)
tag0 = low128(h0 + s)
tag1 = low128(h1 + s)
```

其中 `r` 按 RFC 8439 钳制，并采用恒定时间的选择/比较。Rust 实现使用相同的公式，并额外通过 AVX2 对八条相互独立的密钥流进行批处理。

## Rust 实现选择

- `encode_into` / `decode_into` 配复用缓冲区：classic/noise 在 peer 路径中达成**每包零分配**。
- AVX2 Salsa20 覆盖所有完整的 64 字节块*以及*最后的残块；标量尾部已被移除。CnW 以 8 字节为批调用 8 流 AVX2 核心。
- Poly1305 固定为软件后端。在这台 Zen3 机器上，该 crate 的 AVX2 后端有约 845 ns 固定成本，在 16 B–1500 B 范围内比标量后端慢 2.5–4.5×。
- UDP 使用 64 数据报的 `recvmmsg`/`sendmmsg`；TAP 使用 io_uring 配 eventfd 唤醒及 epoll 回退。

## Rust vs Go（同一批次，中位数）

`Go/Rust > 1` 表示 Rust 更快。

| 场景 | Go ns/op | Go 分配 | Rust ns/op | Rust 分配 | Go/Rust |
|---|---:|---:|---:|---:|---:|
| classic 789 B 编码 | 1,967 | 0 | 1,308 | 0 | **1.50×** |
| classic 789 B 解码 | 1,979 | 0 | 1,338 | 0 | **1.48×** |
| noise MTU 编码（1490 B） | 3,320 | 0 | 2,070 | 0 | **1.60×** |
| noise MTU 解码（1490 B） | — | — | 2,122 | 0 | — |
| encless 128 B 编码 | 13,128 | 5 | 7,023 | 2 | **1.87×** |
| encless 128 B 解码 | 10,970 | 1 | 7,040 | 1 | **1.56×** |
| encless MTU 编码（1506 B） | 17,240 | 5 | 9,820 | 2 | **1.76×** |
| encless MTU 解码（1506 B） | 15,257 | 1 | 10,209 | 1 | **1.49×** |
| CnW chaff 16 B | 10,410 | 1 | 6,025 | 1 | **1.73×** |
| CnW winnow 16 B | 9,845 | 1 | 6,122 | 1 | **1.61×** |
| AONT 128 B 编码 | 1,355 | 3 | 910 | 1 | **1.49×** |
| AONT 128 B 解码 | 1,312 | 3 | 982 | 1 | **1.34×** |

单核载荷吞吐量：

| 场景 | Go | Rust |
|---|---:|---:|
| classic 789 B 编码 | 401 MB/s | 603 MB/s |
| classic 789 B 解码 | 399 MB/s | 590 MB/s |
| noise MTU 编码 | 449 MB/s | 720 MB/s |
| noise MTU 解码 | — | 702 MB/s |
| encless MTU 编码 | 87.4 MB/s | 153.4 MB/s |
| encless MTU 解码 | 98.7 MB/s | 147.5 MB/s |

Rust 便捷 API（`encode`/`decode`）会分配一个结果缓冲区，比原地路径慢 1–6%；生产环境使用原地路径，但 UDP 批处理器交接处除外（目前每包 1 次分配）。

## 组件耗时（classic 789 B，Rust）

| 组件 | 时间 | 说明 |
|---|---:|---|
| XTEA 加密/解密 8 B | 76.0 / 73.9 ns | 64 轮，预计算表 |
| Salsa20 XOR 854 B | 574.7 ns | AVX2，全部块 + 尾部 |
| Salsa20 XOR 1500 B | 793.5 ns | AVX2 |
| Poly1305 tag 798 B（软件） | 590.7 ns | 固定的后端 |
| Poly1305 tag 798 B（AVX2 路径） | 1,523 ns | 未使用 |
| Poly1305 tag 16 B（软件 / AVX2） | 24.8 / 845.1 ns | 可见的 AVX2 固定成本 |

76 + 575 + 591 ≈ 1,242 ns，加上约 60 ns 的拷贝/分帧，与实测的 1,308 ns 相符。

## 注意事项

- 结果来自共享/虚拟化主机；单次运行波动可达 ±20%。不同的 Go 批次（较早与较晚）相差 10–15%，因此不要跨文档混合数字。
- 批量 I/O 吞吐量不在此表中：端到端 pps 取决于网卡、内核与 TAP 后端，且测试主机无特权时无法创建 TAP。批量/io_uring 路径的正确性由回环/socketpair 测试覆盖。
- 没有 Go 的 noise-MTU 解码基准，因此该行仅报告 Rust。
- 仍存在的优化机会：多包 SIMD Poly1305、基于缓冲池的 encless 编码、跨数据包的 XTEA 位切片（bitslicing），以及针对超大 peer 数量的定时器轮（timer wheel）。服务器 UDP 发送交接每包消耗 1 次分配；用池可消除它（预计 <100 ns/包）。

下一步：[概述](index.md)。