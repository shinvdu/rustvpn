# RustVPN 代码审查报告

> 日期：2026-11-25
> 对象：`~/rustvpn` @ commit `8492d8d`
> 方法：4 个并行只读子审查（crypto / proto / net / daemons+运维）+ 复核关键项；未修改代码
> 基线：`cargo test --workspace` 35 个测试通过；`cargo clippy --workspace --all-targets` 0 警告；`cargo fmt --check` 通过

> ⚠️ **C-01 已在代码中修复并有回归测试（Rust + Go），但当前运行中的部署仍使用旧二进制；在重新构建/部署前，请保持仓库为 Private。**

---

## 0. 结论摘要

整体实现质量较高：Go 逐字节兼容向量、AVX2 unsafe 边界、`recvmmsg`/`sendmmsg` 与 io_uring 的基础生命周期未发现内存安全问题。但存在：

- **1 个协议级 CRITICAL（C-01）**：低阶 DH 点未拒绝。Rust 与 **Go 实现同样存在**，属继承缺陷。
- **5 个 HIGH**：脚本无超时、握手不重传、io_uring 静默黑洞、TAP 共享/缓存失效、握手回复早于 peer 建立。多数已在本次部署中实际触发或得到印证。
- **10 个 MEDIUM**、**若干 LOW**，以及明显的负向测试/CI 缺口。

修复优先级建议：C-01 → H-01..H-05 → MEDIUM → 测试/CI。

### 严重度定义

| 级别 | 含义 |
|---|---|
| CRITICAL | 认证/密钥安全被破坏，或可远程导致密钥泄露/完全冒充 |
| HIGH | 可导致持续断网、数据黑洞、明显 DoS，或安全边界被实质削弱 |
| MEDIUM | 特定配置/时序下的错误行为、API 误用风险、运维风险 |
| LOW | 加固项、边界情况、文档/测试缺口 |

---

## 1. CRITICAL

### C-01 低阶 DH 点未拒绝，可冒充客户端
**位置**：`crates/rustvpn-proto/src/handshake.rs:124`（`dh_key_gen`），使用点 `:333`（客户端签名）、`:484`（服务端验签）

```rust
let shared = MontgomeryPoint(public).mul_clamped(*private).to_bytes();
blake2b::hash(&shared)
```

`dh_key_gen` 直接接受对端 32 字节代表元，没有检查结果是否退化。所有低阶点（阶 1/2/4/8）经 clamped scalar 乘后都变成 `[0u8;32]`，于是 `key = BLAKE2b([0;32])` 是一个**公开常量**。

**攻击场景**：
1. 恶意/失陷服务器（持有 verifier，知道 `dsa_pub_h`）在 msg2 放入低阶 `sdh_repr`；
2. 客户端推出常量 `key`，在 msg3 中签名该常量并附带 `s_client`；
3. 攻击者解密 msg3，获得客户端对常量 key 的 Ed25519 签名（Ed25519 是确定性签名，可无限重放）；
4. 攻击者再以客户端身份连接真实服务器，msg1 放入低阶 `c_repr`，服务器得到同一常量 key；重放签名即可通过 `stage_third` 验签；攻击者同时已知 `s_server` 与 `s_client`，**无需客户端私钥即可完全冒充客户端**。

**预置条件**：客户端至少连接过一次恶意服务器（或 verifier 公钥泄露后实施服务器侧中间人）。这违反 README/设计宣称的“失陷服务器 verifier 不能冒充客户端”。

**与 Go 的关系**：Go 的 `curve25519.ScalarMult` 同样不检查全零结果，**上游同样受影响**。修复应两端同步。

**建议修复**：
- Rust：`dh_key_gen` 返回 `Result`，常量时间检查 `shared == [0u8;32]` 并拒绝；
- Go：改用 `curve25519.X25519`（自带低阶点错误）或显式检查全零；
- 增加回归测试：全零代表元、映射到 `u=1` 的代表元 `1fc693abdb36b82dfb20d782d3a3e40be244a8e7c52a45ebd3dc2cacae515f62`，确保两端均拒绝；
- 合法客户端不会发送低阶点，不改变诚实对端的线格式。

**状态**：Fixed（见 §9）

---

## 2. HIGH

### H-01 up/down 脚本无超时，且服务端在 UDP 收包循环内联执行
**位置**：`crates/rustvpn-net/src/scripts.rs:17-22`；`crates/rustvpn-server/src/main.rs:233-248, 746, 761-764`

`Command::output().await` 无超时、无 `kill_on_drop`、stdout 无上限。`get_tap` 在 `handle_udp_packet` 中内联 `await`，所以一个卡住的脚本会停止所有已建连 peer 的收包、握手和超时处理；关停时 down 脚本顺序执行，systemd 超时后 SIGKILL。

**实际印证**：本次部署关停时出现 `script /etc/rustvpn/down.sh failed: signal: 15`。

**修复**：`tokio::time::timeout` + `kill_on_drop(true)` + stdout 上限；脚本移出收包循环；关停并行/限时。

**状态**：Fixed（见 §9）

### H-02 客户端握手不重传 msg1/msg3
**位置**：`crates/rustvpn-client/src/main.rs:311-335`

msg1 只发送一次，随后最多等待 `cfg.timeout`（默认 60s）的 1 秒接收循环；msg3 也只发送一次。任意一个握手包丢失都会让隧道空窗最长 60 秒。

**实际印证**：服务端重启与客户端重启重叠时，客户端约 31 秒未恢复。

**修复**：超时按退避重发当前阶段消息，设绝对 deadline；服务端对重复 msg1/msg3 保持幂等。

**状态**：Fixed（见 §9）

### H-03 io_uring TAP 线程死亡后静默黑洞
**位置**：`crates/rustvpn-net/src/uring_tap.rs:210-243`；`crates/rustvpn-net/src/peer.rs:210-217`

ring 提交失败、EBADF/ENODEV 读错误或 ring 退出后，`Tap::recv` 永久返回 `BrokenPipe`；`tap_reader_task` 仅打印日志并每秒 sleep，心跳继续，双方都显示“在线”但无任何数据，也不会触发重连。

**修复**：把致命错误作为 `PeerEvent` 上报并触发重握手/后端重启；同时停止心跳伪装存活。

**状态**：Fixed（见 §9）

### H-04 TAP 被多个 peer 共享 + 缓存永不失效
**位置**：`crates/rustvpn-server/src/main.rs:233-248`；`crates/rustvpn-net/src/tap.rs:26-52`；`crates/rustvpn-net/src/peer.rs:210`

`tap_cache` 按 iface 返回同一个 `Arc<Tap>`，而 `UringTap::recv` 只有一个接收队列（`tokio::Mutex<Receiver>`）。同 iface 的两个 peer 会随机分走对方的入站帧；down 脚本若删除接口，缓存仍持有死 fd，下一次连接直接黑洞；按连接生成 iface 时还会不断泄漏线程、fd 与缓存项。

**修复**：一 peer 一 TAP（设计文档也如此要求）；peer 移除时驱逐缓存并 join 后端；不要缓存可能失效的设备句柄。

**状态**：Fixed（见 §9）

### H-05 握手完成回复早于 peer/TAP 建立
**位置**：`crates/rustvpn-server/src/main.rs:374-381, 419-424`

先 `send_to(reply)`，再 `create_udp_peer`。若 TAP 打开、脚本或配置失败，客户端已认为建立、执行自己的 up 脚本，并把流量黑洞到超时；服务端只打印一行错误。

**修复**：先完成 peer/TAP 建立，再发送最终回复；建立失败则回握手错误或丢弃。

**状态**：Fixed（见 §9）

---

## 3. MEDIUM

### M-01 已建连地址优先于握手分类
**位置**：`crates/rustvpn-server/src/main.rs:363-368`

任何来自 registry 中地址的包都会进入旧 peer 的 decoder。客户端重连若复用源端口（NAT 常见），msg1 会被当数据帧拒绝并计入 `FramesUnauth`，新握手要等旧 peer 超时才能进行。

**修复**：按 ID-tag/长度先识别握手 msg1；或在收到合法握手包时作废旧会话。

**状态**：Fixed（见 §9）

### M-02 `Session`/`Encoder`/`Decoder` 派生 `Clone + Debug`，且无 zeroize
**位置**：`crates/rustvpn-proto/src/transport.rs:144,488,527`；`crates/rustvpn-crypto/src/xtea.rs:9`

- `Debug` 会打印 32 字节传输 key 与 XTEA 轮密钥；
- 克隆活跃 `Encoder` 会复制 serial，双方各编码一次即造成 nonce/keystream 复用；
- `key`、`prp`、`scratch`、握手中的 `dh_private`/`s_server`/`s_client` 无 `Drop` 清零。

当前无内部 clone/日志调用点，属公开 API 地雷。修复：手写脱敏 `Debug`、移除 `Clone`（或改为唯一借用编码）、`ZeroizeOnDrop`。

**状态**：Fixed（见 §9）

### M-03 传输 API 对过小 MTU 会 panic
**位置**：`crates/rustvpn-proto/src/transport.rs:39-44, 218-239`

`Mode::max_payload` 使用 `saturating_sub`，例如 `Noise + mtu=20` 时空载荷通过校验，随后 `frame_len=4`、`buf_len=60`，`scratch[S20_BS..]` 在 len 60 上切片 panic；`mtu<16` 还有减法下溢。CLI/配置会 clamp，但库 API 不设防。

**修复**：在 encode/decode 入口校验 `mtu` 最小值并返回 `TooLarge`。

**状态**：Fixed（见 §9）

### M-04 无按来源握手限速；TCP 连接数无上限
**位置**：`crates/rustvpn-server/src/main.rs:394-396, 502-509, 596-606`；`crates/rustvpn-net/src/config.rs:166-183`；README 已承认

全局 4096 pending 握手表，无 per-IP 配额；每个身份合法的 msg1 都消耗一次 Curve25519。伪造源可耗尽 CPU/槽位。TCP 每连接一个任务、60s 超时、无并发上限。

**修复**：per-IP/全局令牌桶、TCP accept 上限、尽早校验 msg1。

**状态**：Fixed（见 §9）

### M-05 热加载不能吊销/更新已建会话
**位置**：`crates/rustvpn-server/src/main.rs:721-733`

`PeerEntry` 持有 `Arc<PeerConfig>`；删除 peer 或轮换 verifier 只影响未来握手，旧会话可继续跑到客户端重协商或超时。

**修复**：配置 diff 后取消 id/verifier 变化的会话并执行 down。

**状态**：Fixed（见 §9）

### M-06 信号只在 select 轮询时监听，await 分支内可能丢失
**位置**：`crates/rustvpn-server/src/main.rs:736-738`；`crates/rustvpn-client/src/main.rs:531-538`

`wait_signal()` 在每轮 `select!` 新建；分支体（down 脚本、peer 建立、重连 sleep）执行期间的 SIGTERM 可能无人接收，`systemctl stop` 卡到 `TimeoutStopSec`。

**修复**：启动时注册一次信号处理，驱动全局 `CancellationToken`，所有 await 点可检查。

**状态**：Fixed（见 §9）

### M-07 客户端忽略 up 脚本结果与接口名约定
**位置**：`crates/rustvpn-client/src/main.rs:418, 492-495, 517-520`；`crates/rustvpn-net/src/scripts.rs:23-30`；`README.md:101-104`

脚本失败被吞掉，客户端仍显示已连接但没有地址/路由；README 承诺 `iface` 为空时用 up 脚本 stdout 首行命名，客户端未实现（服务端实现了）。

**修复**：传播脚本错误并中止 peer 建立；统一两端约定。

**状态**：Open

### M-08 配置静默容忍未知字段与重复 ID
**位置**：`crates/rustvpn-net/src/config.rs:83-120`

`YamlPeer` 无 `deny_unknown_fields`；`encless` 拼错会静默退回 plain。重复 verifier id 经 `HashMap` 覆盖，哪个 iface/up/down 存活不确定。

**修复**：拒绝未知字段、重复 id/name，保持确定性顺序。

**状态**：Fixed（见 §9）

### M-09 stats 监听器每连接无上限任务、无认证
**位置**：`crates/rustvpn-net/src/stats.rs:222-247`

可达 stats 端口者可创建大量空闲连接，每个任务最多 sleep 10s；数据含 peer ID 与流量。部署绑定 127.0.0.1 时安全，但 CLI 允许 0.0.0.0 且无警告。

**修复**：并发/速率上限、缩短读超时、文档明确仅回环或加 token。

**状态**：部分缓解（见 §9）

### M-10 verifier 参数边界与 Go 语义偏差
**位置**：`crates/rustvpn-crypto/src/verifier.rs:56-98`

接受任意 `m/t/p`，`m=4294967295` 会让 Argon2 申请 TB 级内存（本地 DoS）；参数顺序/重复、`m<8p` 的 clamp/rounding 与 Go 不一致，可能出现 Go 接受而 Rust 拒绝。

**修复**：范围限制并复刻 Go 的归一化规则。

**状态**：部分修复（上限已加，见 §9）

---

## 4. LOW / 加固

| ID | 问题 | 位置 | 建议 |
|---|---|---|---|
| L-01 | zeroization 缺口：出错路径提前返回未清 subkey；HSalsa20 子密钥、AONT/encless 栈密钥未清；`salsa20` 未启用 `zeroize` | `crates/rustvpn-crypto/src/cnw.rs:205-226`；`salsa.rs:42`；`aont.rs:27,43`；`encless.rs:46` | 统一 `Zeroizing`，所有错误路径先清零 |
| L-02 | `cnw` 用 `assert_eq!` 校验输出长度（Go 返回错误）；长度计算未检查乘法溢出 | `crates/rustvpn-crypto/src/cnw.rs:125,119`；`encless.rs:23` | 返回 `CryptoError`，使用 `checked_mul` |
| L-03 | `recvmmsg` 未传 `MSG_TRUNC`，超长报文被静默截断后计为非法包 | `crates/rustvpn-net/src/udp_batch.rs:57-63` | 传 `MSG_TRUNC` 并在 `msg_len > iov_len` 时显式丢弃/计数 |
| L-04 | `supports_uring()` 成功但 `UringTap::start` 失败时不回退 epoll | `crates/rustvpn-net/src/tap.rs:37-44` | 匹配 `start()` 错误并回退 `AsyncDevice` |
| L-05 | verifier 校验失败仍退出 0 | `crates/rustvpn-verifier/src/main.rs:146-160` | 不匹配时以非零退出 |
| L-06 | 首个坏 chaff 字节的提前返回构成计时旁路（与 Go 相同） | `crates/rustvpn-crypto/src/cnw.rs:244` | 记录为已知、与上游一致；如需消除则全量扫描 |
| L-07 | 传输/握手 secrets 无 `Drop` 清零 | `crates/rustvpn-proto/src/transport.rs:144`；`handshake.rs` | 与 M-02 一并处理 |
| L-08 | 服务端 `Restart=on-failure` 默认启动限流可能在瞬时端口冲突后进入 `start-limit-hit`；客户端 `Restart=always` 永久错误会无限循环 | systemd unit | 调整 `StartLimit*`/退避并加告警 |
| L-09 | `Debug` 暴露 XTEA 轮密钥 | `crates/rustvpn-crypto/src/xtea.rs:9` | 脱敏 Debug，与 M-02 一并处理 |

---

## 5. 测试与 CI 缺口

| ID | 缺口 |
|---|---|
| T-01 | 无重放窗口边界测试（256/257、跳变、乱序、wraparound）；Go 有 `TestNonceWindow*` |
| T-02 | 无负向传输测试：截断、错误长度、篡改 tag/nonce、错误 padding、MTU 最小值 |
| T-03 | 无负向握手测试：坏签名、rServer/rClient 不匹配、各阶段截断、重复消息、**低阶 DH 点** |
| T-04 | `peer.rs`、两端 daemon、`scripts.rs`、verifier 几乎没有单元测试；无脚本超时/失败、信号关停、重连、rekey、registry 替换测试 |
| T-05 | 无 CI workflow；`docs/design.md` 提及的 CI 门禁尚未落地 |
| T-06 | crypto 的 Go 向量偏小（Salsa 128B < AVX2 阈值），缺少 ≥512B AVX2 与 encless 的逐字节向量；CnW 缺少 8 字节批处理 + 标量尾部混合长度 |

---

## 6. 已确认良好/未发现问题的部分

- 握手/传输与 Go 的逐字节兼容（四阶段 × plain/noise/encless，master key 一致）。
- `extra25519`/Elligator、AONT、CnW、encless、XTEA、Argon2 参数顺序与 Go 一致。
- 重放窗口位图、`Ordering::Exact`、padding 搜索排除尾部 nonce、MAC/rServer/rClient 常量时间比较正确。
- AVX2 SIMD unsafe：`storeu`/`read_unaligned`、偏移有界、运行时特性探测；未发现越界或别名问题。
- `recvmmsg`/`sendmmsg`：msghdr/iovec/sockaddr 零初始化、部分发送重试、EAGAIN 处理正确。
- io_uring：read buffer 在重新挂载前复制、写缓冲保持存活、eventfd dup 共享计数、Drop 先关 channel 再 join、EINTR 不丢 SQE。
- 配置 MTU clamp、脚本只通过环境变量传参（无 shell 注入）、事件移除前校验 id+token、未发现口令/密钥日志。
- 部署验证：修复 up 脚本后两端 0% 丢包；现有 GoVPN 服务未受影响。

**未覆盖**：模糊测试、正式密码学审计、FreeBSD/macOS、长时间高负载 soak。

---

## 7. 建议修复顺序

1. **P0**：C-01 低阶 DH 点拒绝（Rust + Go），低阶点回归测试。
2. **P1**：H-01 脚本超时/移出收包循环 → H-02 握手重传 → H-03 io_uring 致命错误上报 → H-04 一 peer 一 TAP/缓存失效 → H-05 建好 peer 再回握手完成。
3. **P2**：M-02 传输 API 脱敏 Debug/去 Clone/zeroize、M-03 MTU 校验、M-01 重连分类、M-04 限速、M-05 热加载吊销、M-06 信号统一、M-08 配置严格化、M-10 verifier 边界。
4. **P3**：L-* 加固与 T-01..T-06 测试/CI。

---

## 8. 复现与验证基线

```bash
cd ~/rustvpn
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all -- --check
```

审查时的结果：35 tests passed、0 clippy warnings、fmt clean。
注意：现有测试主要覆盖正向往返与 Go 向量，上述多数缺陷不在测试覆盖范围内。

---

## 9. 修复状态（2026-11-25）

> 审查基线为 commit `8492d8d`；以下修复已纳入本仓库，**尚未重新部署到运行实例**。
> Go 侧 `src/cypherpunks.ru/govpn/handshake.go` 已同步修复并通过 Go 全量测试。

### 已修复

| ID | 修复内容 |
|---|---|
| C-01 | `dh_key_gen` 常量时间拒绝全零共享密钥（低阶点）；Rust 客户端/服务端 + Go `dhKeyGen` 同步；新增全零/`u=1` 代表元与两端的负向测试 |
| H-01 | 脚本执行加 10s 超时、输出上限、`kill_on_drop`、失败传播；UDP 完成处理改为 spawn，不再阻塞收包循环；关停脚本受超时约束 |
| H-02 | 客户端握手按指数退避重传当前消息，握手总 deadline 收紧到 ≤10s；服务端缓存并重放上一段 server flight，msg1 重传可恢复 |
| H-03 | 新增 `PeerEvent::TapClosed`；TAP 读错误按致命/可重试分类，ring 死亡不再伪装在线，客户端重连、服务端移除 peer |
| H-04 | 删除按 iface 的 TAP 缓存；一 peer 一 TAP；同 id 替换才复用；配置加载拒绝多个 peer 共享非空 iface |
| H-05 | UDP 在 peer/TAP 建立成功后才发送最终握手回复；TCP 在 TAP/up 脚本成功后才写 msg4 |
| M-01 | 重连分类：peer 空闲 >500ms 且报文满足 msg1 长度与 ID-tag 关系时，替换旧会话而不是送入 decoder |
| M-02 | `Session`/`Encoder`/`Decoder` 移除 `Clone`、改用脱敏 `Debug`；`Session`/`Xtea`/`auth_key`/接收缓冲加入 zeroize；启用 `salsa20/zeroize` |
| M-03 | 新增 `TransportError::BadMtu`，encode/decode 入口校验最小 MTU；新增边界测试 |
| M-04 | 每 IP 5/s（burst 10）+ 全局 200/s（burst 400）握手令牌桶、每 IP pending ≤16；TCP/Proxy 连接 512 并发上限 |
| M-05 | 60s 热加载后按 verifier/iface/mtu/mode/cpr/timesync 指纹吊销变更或删除的会话并执行 down |
| M-06 | 客户端/服务端启动时各注册一次信号任务，驱动共享 `CancellationToken`，不再在每次 select 时重建 |
| M-08 | `deny_unknown_fields`；重复 verifier id、重复非空 iface、iface/up 同时为空、负 timesync 均拒绝 |
| M-10 | Argon2 参数上限（m≤262144、t≤4096、p≤64），超限快速拒绝，避免 TB 级分配 |
| L-01 | CnW subkey、HSalsa20 子密钥、AONT salsa key、encless winnowed `r` 全部 `Zeroizing`/zeroize，错误路径也覆盖 |
| L-03 | `recvmmsg` 传 `MSG_TRUNC`，超长报文标记为 0 长度并在调用方丢弃 |
| L-05 | verifier 校验不匹配时打印 `false` 并以非零退出 |
| L-07 | 随 M-02 处理 |
| L-09 | `Xtea` 脱敏 Debug + Drop zeroize |
| T-01..T-04（部分） | 新增协议重放窗口/负向传输/握手负向、crypto 边界/篡改、net 配置/scripts/超长 datagram 测试；测试数 35→61 |
| T-05 | 新增 `.github/workflows/ci.yml`：fmt + clippy `-D warnings` + test + release build |

### 仍待处理

| ID | 状态 | 说明 |
|---|---|---|
| M-07 | Open | 客户端仍吞掉 up 脚本失败，且未实现“iface 为空时用脚本首行命名” |
| M-09 | 部分缓解 | stats 并发任务已限制为 32；仍无认证，依赖绑定 127.0.0.1 |
| M-10 | 部分 | 已加上限；参数顺序/重复、`m<8p` 与 Go 的归一化差异仍在 |
| L-02 | Open | `cnw` 输出长度仍用 `assert_eq!`，长度乘法未 checked |
| L-04 | Open | `UringTap::start` 失败仍不回退 epoll（设备所有权导致回退改造较复杂） |
| L-06 | 保持 | 首个坏 chaff 字节提前返回，与 Go 行为一致 |
| L-08 | Open | systemd `StartLimit` 退避未调整（属部署配置） |
| T-01..T-04 | 部分 | `peer.rs`、daemon 生命周期、stats 并发、rekey/registry 替换仍缺测试 |
| T-06 | 部分 | 已有长度混合与 encless 负向；仍未补 ≥512B 的 Go AVX2 逐字节向量 |

### 验证

- `cargo test --workspace`：61 个测试通过
- `cargo clippy --workspace --all-targets`：0 警告；`fmt --check` 通过
- Go：`go test cypherpunks.ru/govpn ...` 通过
- 本机 loopback + 双 TAP 端到端（新 release 二进制）：ping 3/3、stats 正常、io_uring TAP 生效
