# 协议

[English](../en/protocol.md) | **中文** | [Русский](../ru/protocol.md)

RustVPN 逐字节实现 GoVPN 5.7 线协议。本页描述理解配置与安全属性所需的各个组成部分。当旧版 Go 手册与代码不一致时，以代码为准；Rust 实现已针对 Go 代码生成的向量完成差分测试。

## 密码学原语

| 用途 | 算法 |
|---|---|
| 密钥协商 | 基于 `extra25519` / Elligator 代表的 X25519 |
| 认证 | Ed25519（由 Argon2d 验证器派生） |
| 哈希 | BLAKE2b-256 |
| 口令 KDF | Argon2d v1.3，输出 32 字节作为 Ed25519 种子 |
| 流密码 | Salsa20（8 字节 nonce） / XSalsa20（24 字节 nonce） |
| MAC | Poly1305 |
| 序列 PRP | XTEA |
| 编码（encless） | AONT + Chaffing-and-Winnowing |

## 身份与验证器

客户端身份是一个 128 位、非机密的值。它用作握手 `IDtag` 的 XTEA 密钥以及 Argon2 盐，并出现在统计输出中。以明文传输和存储是安全的；握手消息中施加于其上的 PRP 会让 DPI/去匿名化更难。

**验证器（verifier）** 形如：

```
$argon2d$m=<KiB>,t=<iterations>,p=<parallelism>$base64(id)[$base64(pubkey)]
```

- 短格式（客户端）：仅含身份。客户端由口令和身份派生 Ed25519 密钥。
- 长格式（服务器）：身份 + Ed25519 公钥。服务器永远看不到口令，即使其文件泄露也无法冒充客户端。

Argon2d 输出（32 字节）直接用作 Ed25519 种子。默认参数为 `m=4096`、`t=128`、`p=1`。

## 握手（PAKE DH A-EKE）

四条消息建立会话。每条消息以一个 **IDtag** 结尾：前 8 个明文字节以客户端身份为密钥进行 XTEA 加密（当启用 `timesync` 时再与四舍五入后的时间戳进行 XOR）。服务器用它查找 peer；它同时将该数据包标记为握手。

准备：

1. 客户端拥有自己的身份、口令以及服务器的验证器公钥（`DSAPub`）。
2. 它派生出 `DSAPriv`/`DSAPub`，生成 DH 密钥对 `CDHPub`/`CDHPriv`，以及一个 64 位 nonce `R`。
3. `El()` 是 Elligator 代表编码；`enc(k, n, m)` 是使用密钥 `k` 和 nonce `n` 的 Salsa20/XSalsa20 加密。

```text
1. Client → Server   48 bytes
   R || enc(H(DSAPub), R, El(CDHPub)) || IDtag

2. Server → Client   80 bytes
   enc(H(DSAPub), R+1, El(SDHPub)) || enc(K, R, RS || SS) || IDtag

3. Client → Server  120 bytes
   enc(K, R+1, RS || RC || SC || Sign(DSAPriv, K)) || IDtag

4. Server → Client   16 bytes
   enc(K, R+2, RC) || IDtag
```

- 服务器得知客户端地址，解码 `CDHPub`，生成 `SDHPriv`/`SDHPub`，计算 `K = H(DH(SDHPriv, CDHPub))`，并发送一个 64 位 `RS` 和一个 256 位预主密钥 `SS`。
- 客户端计算 `K`，恢复 `SS`，生成 `RC` 和一个 256 位 `SC`，并用其 Ed25519 密钥对 `K` 签名。
- 服务器用验证器的公钥验证签名，比对 `RS`，并派生出会话密钥 **`MasterKey = SS XOR SC`**。
- 客户端确认 `RC`；双方此时共享 `MasterKey`。

`MasterKey` 是高熵的 256 位密钥。`K` 由 DH 派生，安全裕度至多 128 位，因此仅在握手期间使用。`R*` 各值提供握手机制中的随机化与双向认证。

开启 **noise** 时，握手消息会被填充至整个 MTU。开启 **encless** 时，每个 `enc()` 都会被替换为对填充数据施加的 AONT + chaffing。

## 传输

```text
PACKET = TAG || CIPHERTEXT || NONCE

NONCE      = XTEA(PRP_KEY, SERIAL)
CIPHERTEXT = Salsa20(KEY, NONCE, DATA || PAD(0x80) || ZEROS)
TAG        = Poly1305(AUTH_KEY, CIPHERTEXT || NONCE)
```

- `SERIAL` 是数据包序号：客户端→服务器为奇数，服务器→客户端为偶数，步增 2。客户端与服务器分别从 0 和 1 开始，并分别期望 2 和 3。
- `PRP_KEY` 是以会话密钥和全零 nonce 生成的 Salsa20 密钥流的前 128 位。`SERIAL` 在内部以明文保存，但仅以 XTEA 加密后的 `NONCE` 形式传输。
- `ENCRYPT` 使用已建立的会话密钥和加密后的序列号作为 Salsa20 nonce。密钥流的前 32 字节是 Poly1305 一次性密钥，接下来的 32 字节被丢弃，载荷加密从第 64 字节开始。
- `DATA` 是以太网帧。`PAD` 是单个 `0x80` 字节；其后可选零字节用于将数据包填充至 MTU（noise/CPR）。
- 重复或过旧的序列号会被 **257 位滑动重放窗口**丢弃。

## Noise

Noise 将每个出站数据包填充至配置的 MTU。它隐藏载荷长度，并且是 CPR 达到预期效果所必需的；请在两侧都启用。它默认关闭，可能显著增加流量。载荷开销见 [MTU](configuration.md#mtu)。

<a id="encless"></a>
## Encless

无加密模式用保持机密性的**编码**取代流加密：

```text
PACKET  = ENCODED || NONCE
ENCODED = Chaff(AONT(DATA || PAD || ZEROS))
NONCE   = XTEA(PRP_KEY, SERIAL)
```

- AONT（All-Or-Nothing Transformation，全有或全无变换）是一种无密钥变换：解码任意部分都需要整个编码值。
- Chaffing-and-Winnowing 仅使用 Poly1305（一种认证原语）将比特编码为成对的候选 MAC。它没有加密函数，也没有单独的显式 MAC。
- 每个数据包增长 **4128 字节**（32 字节 AONT 头 + 4096 字节 chaff），因此该模式开销较大。
- 它强制启用 noise。客户端仅在 TCP 上支持它，与 GoVPN 一致；服务器必须监听 TCP（或 `all`）。

它为何存在：某些司法辖区可强制披露加密密钥，但不能强制披露认证/签名密钥，还有些直接禁止加密。Encless 仅使用签名/MAC 原语来保持机密性。它的名字描述的是机制而非结果：传输的数据仍然机密且可认证。

## 网络传输

UDP 是默认方式，也是推荐方式：它更轻量，并能避免"TCP 崩溃（TCP meltdown）"病态（可靠协议叠加于可靠协议之上导致的行首阻塞）。TCP 用于只允许 TCP 的环境。服务器上的 `-proto all` 会同时监听两者。

## HTTP 代理

在线格式上，代理只是 TCP。服务器的 `-proxy` 监听器对任意请求回复 `HTTP/1.0 200 OK` 并进入 TCP 会话状态机；客户端发送 `CONNECT host:port`，可选发送 `Proxy-Authorization`。握手与传输字节与直连 TCP 完全一致。

## 兼容性说明

以下内容有意与 GoVPN 5.7 保持一致，并由字节精确的向量覆盖：

- 握手消息大小、字段顺序、填充位置与 `IDtag`；
- Salsa20 偏移（认证密钥、丢弃字节、载荷起点）；
- 序列号奇偶性、步长、初始/期望值以及 XTEA 字节序；
- 重放窗口语义；
- encless 膨胀与 XSalsa20 nonce 布局；
- 验证器字符串语法、Argon2d 参数与 Ed25519 种子派生；
- `GOVPN_IFACE` / `GOVPN_REMOTE` 脚本变量与统计 JSON 名称。

下一步：[运维](operations.md)。