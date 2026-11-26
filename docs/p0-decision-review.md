# P0 改进项：待决策问题评审

> 日期：2026-11-26（2026-11-26 更新：应用决策并修复对抗性评审发现）
> 状态：P0 Batch 1 / Batch 2 代码已落地，尚未提交；本文件同时记录**已执行决定与修复状态**。下方原始评审文本保留作背景。
> 范围：MTU/MSS、kill-switch、QR、GUI、文档、status schema、rekey、keepalive、服务端声明式 TAP、diff reload。
> 说明：代码、测试与英/中/俄文档的关键 MTU 语义已按“已执行决定”对齐；第二轮对抗性评审的 P1 修复记录见 P1-* 行，第三轮评审的 P2 修复记录见 P2-* 行（kill-switch 崩溃策略、重连 applied 状态、服务端 MTU 拒绝、派生 TAP IP MTU 下限、CLI keepalive、服务端 status 文档）。

---

## 已执行决定 / 修复状态（2026-11-26）

| # | 决策点 | 最终决定与已执行修复 | 状态 |
|---|---|---|---|
| P0-1 | `mtu: auto` 破坏双方线路尺寸 | v1 将 `mtu` 定义为**双方一致的线路契约**；移除自动推导；拒绝 `auto`/`0`；数字默认 1515；仅推导 TAP IP MTU/MSS。收尾：`save_profile_at` 写盘前校验数值范围与 noise/encless 下限；`ser_mtu` 不再把 0 静默改写为 `"auto"`（序列化直接报错）；GUI 通过 `profile_errors` 上报旧 `mtu:auto`/`0` 文件而非静默跳过；新增 IPC/GUI 回归测试 | **CLOSED** |
| P0-2 | 服务端声明式 TAP 把接口 MTU 设为帧预算 | 服务端与客户端均使用 `inner_ip_mtu = Mode::max_payload(wire) - 14`；plain 1515→1500、noise 1515→1476、encless 1515→1492；声明式指纹包含 mode/inner-IP-MTU，仅改模式也会在下一会话前重配 TAP；`configure_tap` 与 mode-only 指纹均有回归测试 | **CLOSED** |
| 1 | MTU 来源与失败回退 | 不再使用链路/路径 MTU 推导；`underlay_mtu` 显式覆盖与主动 PMTU **不实现**，路径 MTU 协商列入 v2 | **已改为数值契约；auto 推迟 v2** |
| 2 | `mtu: 0` 含义 | 客户端 IPC/profile 与服务端 `peers.yaml` 均明确拒绝显式 0；省略服务端字段仍为 1515 | **已修复** |
| 3 | MSS clamp 缺 `nft` | 默认 best-effort 并记录 `mss_applied`；`mss_clamp: required` 严格模式**未实现** | **部分修复；required 延后** |
| 4 | kill-switch 缺 `nft` / 崩溃策略 | 保持 fail-closed；clean-shutdown 标记区分正常停止与崩溃：正常停止删表，崩溃后下次启动**保留** kill-switch（仅删 MSS），空闲期间主机仍被 drop；连接时在保留链内引导放行外层端点，握手成功后替换为完整规则（新 profile 未启用则删表）；显式断开/停止删表恢复连通。补充 `nftables` 打包说明与手工清理命令 | **已修复（P2-1 收尾）** |
| 5 | kill-switch 覆盖范围 | 仅主机 `output`；文档明确不覆盖 forward/LAN/NAT；补 ICMPv6 ND/MLD 与 DHCPv6（546/547）且限定物理接口 | **已修复** |
| 6 | QR 生成方式 | 短期保留外部 `qrencode`；临时文件改为 `O_EXCL`/owner-only + 原子 rename，拒绝 symlink 竞态；内置 QR 延后 | **已加固；内置库延后** |
| 7 | GUI 安全开关可见性 | 新 profile 默认数值 MTU 1515、rekey 1800；首页新增只读 MTU（线路/接口）与 kill-switch/MSS/rekey 状态；复选框开关**未实现** | **已做只读；开关延后** |
| 8 | 新文档语言 | 英文文档已更新；zh/ru 的 MTU/0-auto、声明式 TAP 与 up 脚本语义已对齐，其余新章节仍可后续补齐 | **关键语义三语一致；其余翻译延后** |
| 9 | 服务端 status 速率 | 增加 `rates_available: false`、`rate_window_sec: null`；`unavailable` 文档改为 schema 完整（相同字段 + `last_error`） | **已修复** |
| 10 | `rekey_time` 默认值 | daemon/CLI 默认 0；新 GUI/onboarding profile 默认 1800；GUI 只读显示 | **已修复** |
| 11 | keepalive 上下限 | 默认关闭；plain 10 s、noise/encless 25 s、上限 3600 s；noise 成本告警；CLI 与 profile 共享常量，verifier 使用相同边界（P2-5 修复了 CLI 仍用 5/15 s 的不一致） | **已修复（P2-5 收尾）** |
| 12 | 时间重协商丢包 | 接受短暂断流；默认关闭（daemon）；文档明确非零丢包；零丢包留给 v2 | **已接受并文档化** |
| 13 | 服务端声明式 TAP 所有权 | 严格 RustVPN 所有权：创建时写 `alias rustvpn-managed`；拒绝未标记的既有 TAP；接管标记 TAP 前先清空残留 IPv4 地址/路由/DNS；地址/路由使用 `add`（非 `replace`），`EEXIST` 仅在完全匹配时幂等，只记录/删除自己添加的项。收尾：reload 移除/修改 peer 后按当前配置剪枝遗留 guard（未变化的活跃 peer 保留）；`network:` 明确负责创建 TAP，`up` 若创建未标记 TAP 会收到明确错误（或脚本自行打标记）；移除 `network:` 不再需要重启 | **CLOSED** |
| 14 | diff reload 吊销范围 | 保持严格吊销；日志列出变化字段；创建/插入 peer 前重查 config fingerprint；UDP 在 `registry.insert` 之后再次校验，过期则结束会话并清理本路径的声明式 guard | **已修复（P1-3 加固）** |
| P1-1 | 默认路由前缀 0 规范化 + 声明式安装非破坏性 | 新增共享 `is_default_route`（`default` 或解析为 `IpNet` 且 `prefix_len()==0`，覆盖 `00.0.0.0/0` 等）；服务端 `network.routes` 拒绝全部前缀 0；客户端全隧道检测覆盖所有写法；声明式地址/路由改为 `add` + `EEXIST` 校验，只回滚自己添加的项 | **已修复** |
| P1-2 | 仅改模式时复用旧 TAP MTU | 声明式 guard 指纹加入 `mode` 与派生的 `inner_ip_mtu`；复用旧 TAP 前检测指纹，变化则重建；plain 1515→1500、noise→1476、encless→1492 有回归测试；另新增 reload 剪枝回归测试，删除/修改 peer 不会遗留旧 guard | **CLOSED** |
| P1-3 | UDP 配置吊销 TOCTOU | UDP 建 peer 在派生任务中运行；改为 `registry.insert` 后重新校验 fingerprint，过期则 `end_session` + 仅移除匹配指纹的声明式 guard + 计数/日志；纠正“与主任务串行”的错误注释；新增插入后重载的可单测判定 | **已修复** |
| P1-4 | 文档仍教“线路 MTU 当作接口 MTU”、zh/ru 的 0/auto 语义 | en/zh/ru 的入门/配置/运维文档 up 脚本改为接口 IP MTU（1515 plain→1500、noise→1476、encless→1492），给出公式；删除 `mtu: 0 = 1515`，统一为 0/auto 拒绝、省略默认 1515 | **已修复** |
| P1-5 | 崩溃保留 kill-switch 下主机名远端重连死锁 | 临时 DNS 放行原先只在连接开始时打开一次，解析后立即收窄为外层端点；握手失败清空 `endpoints` 后 DNS 已关闭，后续解析全部被 drop，主机名远端永远无法重连（IP 字面量不受影响）。新增 `BootstrapState` 显式跟踪 `active`/`dns_open`：首次握手成功前，**每次**解析前都重新打开 DNS 放行（`bootstrap_commands` 先 flush，幂等、不重复加规则），解析后收窄、握手前关闭；`bootstrap_kill_switch` 返回 `Ok(false)`（表已消失）时立即停止 fail-closed 声明，不再伪装保留。握手成功后完整规则集替换（DNS 放行随之消失）或按 profile 删表。IP 字面量与正常无崩溃路径不变。新增状态机回归测试覆盖“首次解析成功→握手失败→再次解析→最终成功”和表消失场景；因 TAP 需特权，未在 CI 跑完整引擎循环（残余缺口见评审记录）。en/zh/ru 文档同步说明临时 DNS 会在每次解析前重开、握手前关闭 | **CLOSED** |
| P2-1 | systemd 自动重启后 kill switch 被启动清理删除（fail-open） | 新增 socket 旁的 clean-shutdown 标记（内容校验，拒绝截断）；正常停止删表并写标记，启动见标记才删遗留表；无标记视为崩溃：保留 kill-switch、只删 MSS；连接时 `flush chain output` 后仅放行 loopback/临时 DNS/新外层端点，握手成功后替换完整规则或按新 profile 删表；显式断开/停止删表。替换不再 delete 表，失败时保持 drop 策略。新增启动策略/标记/命令序列回归测试。手工恢复命令见 en/zh/ru 文档 | **CLOSED** |
| P2-2 | 重连后 `mss_applied`/`kill_switch_applied` 被重置为 `None` | `base_status` 接收 live guard 的 applied 状态；重连、rekey、失败重连与解析失败的状态重建都携带真实值（MSS 被跳过为 `false`，kill-switch 为实际 `true/false`）；新增重连状态回归测试 | **CLOSED** |
| P2-3 | 服务端显式 MTU 静默钳制，与客户端拒绝不一致 | `peers.yaml` 显式 `mtu` 越界（`<68`、`>9015`）、noise/encless `<120`、或推导 TAP IP MTU `<68` 一律拒绝，不再 clamp；省略仍默认 1515；admin 编辑器使用同一校验；en/zh/ru 文档改为“拒绝而非钳制”并新增边界测试 | **CLOSED** |
| P2-4 | 极小 MTU 推导 TAP IP MTU <68（`ip link set` 拒绝） | 共享校验要求派生 TAP IP MTU ≥68：plain 线路 ≥83，noise/encless 的 120 下限派生 81/97；profile、CLI、IPC/GUI 保存、verifier、admin、server 在触碰网络前拒绝并报告派生值与最小可用线路值；Windows 576 仍为平台特定限制；新增 plain 68/82/83、noise/encless 120 回归测试 | **CLOSED** |
| P2-5 | CLI keepalive 仍为 plain 5 s / padded 15 s | CLI 改用 `rustvpn-client-core::profile` 的 10/25/3600 常量，保留 `0`=关闭与 `<timeout` 校验；新增 CLI 边界测试，与 profile/verifier/文档一致 | **CLOSED** |
| P2-6 | 服务端 `status --json` 文档混入客户端字段 | en/zh/ru 文档拆分为公共/仅客户端/仅服务端字段，并记录 `sessions[]`；明确服务端无顶层 iface/endpoint/last_handshake/rekey/keepalive，速率为 `null` 且 `rates_available:false`；新增 `ServerStatusV1` 顶层与会话键序列化对照测试 | **CLOSED** |

其他一并修复的对抗性评审项：

- `-profile-out` 裸相对路径不再 chmod 空父目录；`HOME` 未设置时拒绝 `/tmp` 回退。
- IPC `ProfileSpec` 增加调优字段后把 `PROTOCOL_VERSION` 提升到 **2**，版本不匹配返回明确错误。
- nft 表名按 daemon 实例（IPC socket 路径哈希）隔离，避免同一 netns 多实例互删。
- 客户端 status 增补 `mss_applied`、`kill_switch`/`kill_switch_applied`、`mtu_source`、`rates_available`/`rate_window_sec`。
- MSS 使用独立 IPv4/IPv6 值（`inner-40` / `inner-60`）。
- QR/URI：URI 补齐网络字段，但**没有自动导入器**；文档改为“参考用途”，不再宣称扫码即连。

**明确延后（未在本批实现）**：`mtu: auto`/v2 MTU 协商、`mss_clamp: required`、内置 QR 库、`rustvpn://profile` 自动导入器、GUI 安全开关复选框、zh/ru 全量翻译。声明式 TAP 的 reload/移除清理已在本次收尾中实现，不再列为延后项。

---

## 0. 决策总览

| # | 决策点 | 当前实现 | 建议 | 是否阻塞合并 |
|---|---|---|---|---|
| 1 | MTU 来源与失败回退 | 链路 MTU + 路由查询；失败假设 1500 | 保留，增加显式 `underlay_mtu` 覆盖；暂不做主动 PMTU | 建议先补覆盖项 |
| 2 | `mtu: 0` 的含义 | 0 等价于 auto | 建议只接受 `"auto"`，拒绝 0 | 是 |
| 3 | MSS clamp 缺 `nft` | 仅告警，继续连接 | 保留；增加严格模式可选 | 否 |
| 4 | kill-switch 缺 `nft` | fail-closed，拒绝连接 | 保留 | 否 |
| 5 | kill-switch 覆盖范围 | 仅主机 `output`，不覆盖 forward/LAN | 保留，文档明确“工作站模式” | 建议确认 |
| 6 | QR 生成方式 | 依赖外部 `qrencode` | 短期保留；中期改为可选 Rust 依赖 | 否 |
| 7 | GUI 安全开关可见性 | 保留 YAML 值，但无复选框 | 至少增加只读状态显示，最好加开关 | 建议 |
| 8 | 新文档语言 | 英文为主 | 合并前补 zh/ru 关键页 | 建议 |
| 9 | 服务端 status 速率 | `null` | 保持 nullable，或增加服务端采样 | 否 |
| 10 | `rekey_time` 默认值 | 0（关闭） | daemon 保持 0；新 profile/GUI 默认 1800 | 是 |
| 11 | keepalive 上下限 | plain 5s，noise/encless 15s，上限 3600s | 改为 plain 10s、noise/encless 25s | 是 |
| 12 | 时间重协商丢包 | 定时重连，短暂丢包 | 接受并默认关闭；零丢包需 v2 会话重叠 | 是 |
| 13 | 服务端声明式 TAP 所有权 | `replace` 语义，移除 `network:` 需重启 | 严格所有权 + 重启清理；后续做热移除 | 是 |
| 14 | diff reload 吊销范围 | 语义变更即吊销该 peer | 保留严格吊销；按需增加 operational 策略 | 是 |

---

## 1. MTU 来源、失败回退与重连后的重新推导

> 以下 1–13 节是 2026-11-26 对抗性评审前的原始背景，部分“现状/建议”已被上方“已执行决定”取代；以该表为准。MTU 自动推导已从 v1 移除，`auto` 推迟到 v2。

### 现状

- `mtu: auto` 通过以下信息推导：
  - 外层地址族：IPv4 / IPv6；
  - 外层传输：UDP / TCP；
  - 模式开销：plain 1、noise 25、encless 9；
  - 以太网头 14；
  - 链路 MTU：`ip route get` + `ip link` 查询。
- 查询失败时：告警并假设底层 1500。
- 内层 IP MTU 目前有 1500 的上限，避免自动推导放大到 jumbo 后带来新的兼容问题。
- 首次成功后，endpoint 和 `NetworkGuard` 被固定；重连切到另一个地址族时不会重新推导 MTU。

### 为什么需要决策

- 链路 MTU 不等于路径 MTU。中间链路可能只有 1400 或 1280，而本地网卡仍是 1500；此时自动推导仍会黑洞。
- 主动 PMTU 探测（DF + ICMP Frag Needed）在真实网络中经常被防火墙过滤，且需要 raw socket/root；实现复杂，失败模式也多。
- 重连后重新推导会涉及 TAP MTU、路由、防环和已安装的 nft 规则，不能在会话中途悄悄改；否则可能出现“接口 MTU 改了但路由表还是旧的”。

### 选项

| 选项 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| A | 保持现状：链路 MTU + 失败假设 1500 | 简单、可预测、与 wg-quick 的保守思路接近 | 中间链路更小的时候仍可能黑洞 |
| B | 增加 `underlay_mtu` 显式覆盖 | 管理员可以按真实路径配置；不改协议 | 需要用户知道路径 MTU |
| C | 主动 PMTU 探测 | 自动适应中间链路 | ICMP 常被过滤；raw socket/root；探测本身可能泄漏或超时 |
| D | 重连时自动重新推导并重装网络 | 地址族变化后仍正确 | 需要安全地重建 TAP/路由/防环；中途切换风险高 |

### 建议

1. **保留 A 作为默认**，并优先补 **B：`underlay_mtu` 覆盖**。
2. 查询失败时继续告警并假设 1500，但把假设写进 `status --json`，不要静默。
3. **暂不做 C**。如果要支持“路径 MTU 小于链路 MTU”的生产网络，先用文档要求管理员填写 `underlay_mtu`。
4. **D 不做自动中途切换**：地址族变化时记录 warning，要求重新连接或重启 daemon，由新的 guard 重新推导；这样避免运行中 TAP/路由状态不一致。

### 验收

- 1500 与 9000 链路下推导结果正确，内层 IP 不超过 1500。
- 查询失败时有明确 warning，`status --json` 可见“assumed 1500”。
- 设置 `underlay_mtu` 后覆盖自动值。
- 地址族变化时不会在旧 guard 上悄悄改 MTU。

---

## 2. `mtu: 0` 是否等价于 `auto`

### 现状

- `ProfileSpec.mtu` 接受整数或 `"auto"`。
- 为了兼容字符串/整数解析，`0` 被当作 auto 的哨兵值；序列化回 `"auto"`。
- 之前 `0` 是非法值。

### 为什么需要决策

- `0` 在 YAML/JSON 中很容易被理解为“使用默认值”或“未设置”，而不是“自动推导”。
- 如果未来有人手写 profile，`mtu: 0` 会静默改变行为，排障时容易误判。
- 服务端 `peers.yaml` 的 `mtu` 是 GoVPN 数值字段，0 可能有“默认”语义；客户端 profile 与服务端配置不应混用同一套哨兵。

### 选项

| 选项 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| A | 保持 0 = auto | 兼容整数调用方；实现简单 | 语义不直观，容易误配 |
| B | 只接受 `"auto"`，0 报错 | 显式、无歧义；此前 0 本来就非法 | 需要改解析代码；整数 JSON 不能表达 auto |
| C | 增加独立 `mtu_auto: true`，0 仍非法 | 兼容数值字段，语义清楚 | 多一个字段，配置略啰嗦 |

### 建议

**选 B：只接受 `"auto"`；`0` 明确报错。**

理由：

- 这是新功能，尚未形成兼容包袱；显式字符串比哨兵数字更安全。
- 客户端 IPC 已经支持字符串，GUI/CLI 都能输出 `"auto"`。
- 服务端 `peers.yaml` 继续使用数值 `mtu`，不引入 0=auto 的歧义。

如果确实有只发整数的外部调用方，再考虑 C，而不是把 0 当 auto。

### 验收

- `mtu: "auto"` 成功；`mtu: 0` 返回清晰错误。
- 旧数值 MTU 行为不变。
- 文档明确“0 不等于 auto”。

---

## 3. MSS clamp 缺 `nft` 时告警 vs kill-switch fail-closed

### 现状

- MSS clamp：`nft` 缺失时只记录 warning，连接继续。
- kill-switch：`nft` 缺失或规则应用失败时拒绝连接（fail-closed）。

### 为什么合理

两者安全属性不同：

- **MSS clamp** 是性能/路径 MTU 辅助，不是安全边界。没有它，TCP 仍可能通过 PMTU 发现工作，只是更容易遇到大包黑洞。
- **kill-switch** 是安全边界。如果无法安装阻断规则却仍然连接，用户会以为“已经防泄漏”，实际流量可能回落到物理网卡；这比连接失败更危险。

### 选项

| 选项 | 做法 | 结果 |
|---|---|---|
| A | 保持现状 | MSS 缺失可连接；kill-switch 缺失拒绝连接 |
| B | MSS 也 fail-closed | 没有 nft 的系统完全不能连接，影响面过大 |
| C | 增加 `mss_clamp: required` | 需要严格保证的用户可以显式选择失败关闭 |

### 建议

**保持 A，并补 C 作为可选严格模式。**

- 默认 `mss_clamp: auto` 是 best-effort；
- 设置 `mss_clamp: required` 时，nft 缺失/失败则拒绝连接；
- 日志和 `status --json` 要显示“MSS clamp: applied / skipped (nft missing)”，不要只写 warning 到 stderr。

### 验收

- 无 nft 环境：默认连接成功，状态显示 skipped；
- `mss_clamp: required`：无 nft 时拒绝连接；
- kill-switch 无 nft：始终拒绝连接，不能“先连上再说”。

---

## 4. kill-switch 的覆盖范围与 DHCP 放行

### 现状

- 规则作用在主机 `output` 链：允许 `lo`、隧道接口、VPN 外层 endpoint、DHCP 续租；其余默认 drop。
- 不覆盖 `forward` 链，因此：
  - 本机作为路由器/NAT 网关时，转发流量不受保护；
  - 容器/虚拟机经由本机转发时，也不受保护；
  - LAN 访问是否可用取决于规则，不是“LAN 全放行”。

### 为什么需要决策

- “kill-switch”容易被理解为“整机所有流量都防泄漏”，但当前实际是“工作站主机自身流量”的防泄漏。
- 如果用户拿它当路由器/网关使用，会误以为 forward 流量也被保护。
- 放行 DHCP 是必要的，否则租约到期后物理网卡无法续租；但 DHCP 本身是一个窄的放行口。

### 选项

| 选项 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| A | 保持 host-only，文档明确“工作站模式” | 简单、风险低，覆盖绝大多数桌面场景 | 路由器/容器转发不受保护 |
| B | 同时过滤 `forward` | 覆盖网关场景 | 规则复杂，容易误伤 LAN/容器/ICS，需要定义允许网段 |
| C | 增加 `kill_switch_scope: host|all` | 用户按场景选择 | 需要实现和测试 `all` 语义 |

### 建议

**MVP 选 A，并显式命名/展示为“主机防泄漏”，后续再加 C 的 `all`。**

- 文档写清楚“不保护 forward/容器/ICS/NAT 转发”；
- DHCP 只放行 UDP 67/68，并限制在物理接口，不整体放行以太网；
- 如果用户明确需要网关模式，再做 `forward` 规则和 LAN 白名单。

### 验收

- 主机直连流量在隧道断开后阻断；
- DHCP 续租不被破坏；
- 路由器/容器转发场景文档标注“不支持”，不误报防泄漏。

---

## 5. QR 是否依赖外部 `qrencode`

### 现状

- `rustvpn-verifier` 可以生成 profile 和 `rustvpn://profile?...` URI。
- QR 图片需要外部 `qrencode`；没有时仍生成 profile 并打印 URI。
- 可执行文件路径可用 `RUSTVPN_QRENCODE_BIN` 覆盖。

### 为什么需要决策

- 外部二进制增加部署依赖，且不同发行版包名不同；调用外部程序也会扩大输入/路径处理面。
- 内置 QR 库会增加一个 Cargo 依赖和少量二进制体积，但可复现、可测试、无外部进程。
- QR 内容是 verifier id（非口令），但仍应提示“verifier 按凭据管理”。

### 选项

| 选项 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| A | 保持外部 `qrencode` | 不加依赖；实现已完成 | 需要用户安装；跨平台路径差异 |
| B | 增加可选 Rust QR feature（如 `qrcode` + PNG） | 自包含、可测试 | 新增依赖/体积；需选库 |
| C | 只输出 profile/URI，不做 QR | 最简单 | 失去“扫码”体验 |

### 建议

**短期保留 A；中期改为 B（可选 `qr` feature），A 作为 fallback。**

- 不要把外部命令拼进 shell；使用 `Command::new(bin).arg(...)`，不经过 shell。
- 没有 QR 时，明确提示“profile 已生成，URI 可手动导入”，退出码仍为成功。
- 发布包可选携带 QR 库，避免要求用户额外安装 `qrencode`。

### 验收

- 无 `qrencode` 时 profile + URI 正常生成；
- 有 `qrencode` 时 QR 可扫，内容不含口令；
- 路径覆盖不引入 shell 注入。

---

## 6. GUI 是否需要 MSS/kill-switch 开关

### 现状

- GUI 保存 profile 时会保留 `mss_clamp`、`kill_switch`、`keepalive`、`rekey_time` 等字段，避免静默丢失。
- 但 GUI 没有对应的复选框/说明，用户无法在界面中发现或开启这些安全选项。

### 为什么需要决策

- “保留字段”解决了数据丢失，但没有解决可发现性：用户在 GUI 中看不到 kill-switch 是否开启，容易误以为默认防泄漏。
- 安全选项隐藏在 YAML 中，与“GUI 是主要入口”的产品定位不一致。

### 选项

| 选项 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| A | 增加复选框/开关 | 完整、直观 | 需要 UI/文案/校验工作 |
| B | 只显示只读状态 + “编辑 YAML”入口 | 成本低，至少不误导 | 不能直接在 GUI 开启 |
| C | 保持现状，只写文档 | 成本最低 | 安全状态不可见 |

### 建议

**至少做 B；如果本版要面向普通用户，直接做 A。**

- 全隧道页面显示 “Kill-switch: 开/关/不可用(无 nft)”；
- 显示 “MSS clamp: 自动/已应用/跳过”；
- 分流 profile 的 kill-switch 应禁用并解释原因；
- 开启 kill-switch 时增加一次确认，说明“断开后可能无外网”。

### 验收

- GUI 能显示实际状态，而不是只保留隐藏字段；
- 修改开关后保存到 YAML，并在连接时生效；
- 分流 profile 不会被误开。

---

## 7. 新文档的中文/俄文翻译

### 现状

- Batch 1/2 新增文档和配置说明主要是英文：
  - `docs/netns-client.md`
  - `docs/en/configuration.md` 的新增章节
  - README/index 的新条目
- 现有项目承诺中/英/俄三语，`docs/zh/`、`docs/ru/` 是正式入口。

### 为什么需要决策

- 只补英文会形成“功能已做、用户手册只覆盖英文”的体验断层。
- 但把所有新内容立刻翻成三语成本高，且实现可能还会调整。

### 选项

| 选项 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| A | 合并前补齐 zh/ru | 体验完整 | 翻译成本高，可能随代码再改 |
| B | 合并代码，翻译单独 PR | 不阻塞功能 | 短期内文档不一致 |
| C | 只维护英文，明确“新功能英文优先” | 成本最低 | 违背现有三语承诺 |

### 建议

**选 B，但合并前至少补：`docs/zh/client-ui.md`、`docs/zh/configuration.md`、`docs/zh/faq.md` 的关键段落；`ru` 可随后补。**

- 新增的 netns、kill-switch、status --json、rekey/keepalive 必须有中文说明；
- 英文文档中的命令要能被中文页直接复用；
- 验收：语言切换链接不 404，关键安全语义一致。

---

## 8. 服务端 `status --json` 的速率字段为 `null`

### 现状

- 客户端 status 有 `tx_rate_bps` / `rx_rate_bps`。
- 服务端控制协议只暴露累计计数（会话流量、心跳、unauth/dup），没有速率采样，所以服务端 JSON 中速率为 `null`。

### 为什么需要决策

- 消费者可能把 `null` 当成 0，或以为字段损坏。
- 服务端速率需要时间窗口和采样状态；一次性 `status` 查询无法凭空得出速率。
- 也可以在客户端/监控侧对两次采样做差分，不必让服务端持有状态。

### 选项

| 选项 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| A | 保持 `null`，schema 文档说明 | 简单、诚实 | 消费者需处理 null |
| B | 服务端增加采样器，输出 rate | 直接可用 | 增加状态、时间窗口、锁竞争 |
| C | 移除服务端 rate 字段，只给 counters | schema 更干净 | 与客户端结构不完全对称 |

### 建议

**选 A，并在 schema 中加 `rates_available: false` 和 `rate_window_sec: null`；如果监控需要，后续做 B。**

- 不要用 0 伪装“没有速率”；
- 客户端/服务端字段名保持一致，但明确 nullable；
- 文档给出“用两次 counter 差分”的示例。

### 验收

- `jq` 能区分 `null` 与 0；
- schema 版本不变，新增字段可选；
- 监控示例可用。

---

## 9. `rekey_time` 默认 0 还是 1800

### 现状

- 默认 `rekey_time = 0`（关闭），保持历史行为，仅 4 GiB 触发。
- 文档建议 1800 秒（30 分钟）。
- 当前 v1 没有会话重叠，时间重协商实际是“立即重连”，可能产生短暂丢包。

### 为什么需要决策

- 选 0：兼容旧行为，不会引入周期性瞬断；但低流量长会话的密钥寿命仍无上限。
- 选 1800：安全窗口有上限；但每 30 分钟可能打断长 TCP，用户感知为周期性卡顿。
- 两者不能同时满足“零行为变化”和“强制密钥寿命”。

### 选项

| 选项 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| A | daemon 默认 0；新 profile/GUI 默认 1800 | 旧配置不变，新用户安全优先 | 两套默认值，需要文档解释 |
| B | 全局默认 1800 | 安全统一 | 所有旧客户端升级后周期性重连 |
| C | 全局默认 0，仅文档建议开启 | 最保守 | 多数用户不会主动开 |

### 建议

**选 A。**

- 已存在的 profile/CLI 行为不变；
- 新建 GUI profile 和 onboarding 生成的文件默认 `rekey_time: 1800`，并显示“可能短暂重连”；
- daemon 对 `0` 明确表示“关闭”；
- 等 v2 会话重叠完成后再考虑把全局默认改为 1800。

### 验收

- 旧 profile 不因升级改变行为；
- 新 profile 默认 1800，状态显示下次重协商时间；
- 关闭时日志/状态明确“rekey disabled”。

---

## 10. keepalive 下限与上限

### 现状

- plain 最低 5 秒；noise/encless 最低 15 秒；上限 3600 秒。
- 默认关闭。
- noise/encless 的保活仍按 v1 填充到 MTU，成本高。

### 成本参考

| 模式 | 间隔 | 每天包数 | 约流量 |
|---|---:|---:|---:|
| plain 空包（约 53 B） | 5 s | 17,280 | 约 0.9 MiB |
| plain 空包 | 25 s | 3,456 | 约 180 KiB |
| noise（填充到 1515 B） | 15 s | 5,760 | 约 8.7 MiB |
| noise（填充到 1515 B） | 25 s | 3,456 | 约 5.2 MiB |

### 为什么需要决策

- 5 秒对 NAT 保活通常过于激进，增加电量和流量，收益有限。
- noise 模式下 15 秒的填充成本可能超过业务流量；移动端尤其敏感。
- 但某些 CGNAT/企业防火墙的空闲时间很短，可能确实需要 <25 秒。

### 选项

| 选项 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| A | 保持 5/15/3600 | 灵活 | 默认值容易被误用；noise 成本高 |
| B | plain 10，noise/encless 25，上限 3600 | 与 WireGuard 25 秒建议一致，成本可控 | 极短 NAT 超时的用户需要另配 |
| C | 统一 25 秒 | 最简单 | 失去短间隔能力 |

### 建议

**选 B，并默认关闭。**

- 文档推荐 25 秒；
- noise/encless 低于 25 秒时明确警告“保活包会被填充到 MTU”；
- 保留 `keepalive: 5` 的显式覆盖能力（如果确实需要），但不要把它作为默认推荐值；
- v2 若实现“保活不填充”，再放宽 noise 下限。

### 验收

- 默认不发保活包；
- 25 秒配置下流量估算与文档一致；
- noise 模式配置 15 秒时出现成本警告。

---

## 11. 是否接受时间重协商的短暂丢包

### 现状

- v1 没有带内 rekey 或会话重叠消息。
- 时间到点后客户端关闭当前会话并立即重连；TAP/路由/防火墙保留，但数据面有短暂空窗。
- 文档/日志没有声称零丢包。

### 为什么需要决策

- 如果要求“重协商期间 TCP 不重置、丢包 <0.1%”，当前实现不满足。
- 真正的 make-before-break 需要协议 v2（或至少双会话/索引机制），超出 P0“不改线协议”的约束。

### 选项

| 选项 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| A | 接受短暂丢包，默认关闭 rekey | 不改协议，安全窗口可按需开启 | 开启后长 TCP 可能被影响 |
| B | 仅空闲时 rekey | 不影响活跃流 | 活跃长流的密钥寿命仍不受限 |
| C | 等 v2 会话重叠再启用 | 零丢包目标 | 时间驱动重协商推迟 |
| D | 强行做重叠 | 可能接近零丢包 | 需要协议/服务端改动，破坏 v1 兼容 |

### 建议

**选 A：P0 接受短暂丢包，`rekey_time` 默认 0；把 C 列入 v2。**

- 用户显式开启时，文档明确“可能有秒级中断”；
- 监控/状态暴露 `rekey_in_sec` 和最近一次重协商结果；
- 不把“零丢包”写进验收标准，除非完成 v2。

### 验收

- 开启后能按时间触发，且不会握手风暴；
- 关闭后行为与旧版本一致；
- 文档不承诺零丢包。

---

## 12. 服务端声明式 TAP 的 `replace` 语义与移除 `network:` 需重启

### 现状

- `peers.yaml` 新增可选 `network:`。
- 有 `network:` 时，服务端自动创建/配置 TAP、地址、路由、DNS；~~使用 `ip route replace` / `ip addr replace` 语义~~（P1-1 已改为非破坏性 `add` + `EEXIST` 校验）。
- 移除 `network:` 后，运行中的服务端不会自动拆除旧状态，需要重启。
- 无 `network:` 的旧配置行为不变；含 `network:` 的配置是 RustVPN-only，Go 服务端会拒绝。

### 为什么需要决策

- `replace` 会覆盖同名接口上的既有地址/路由；如果接口是用户手工管理的，可能破坏其他配置。
- 自动创建 TAP 需要明确“这个接口归 RustVPN 所有”，否则清理和回滚边界不清。
- 运行中移除 `network:` 不做热清理，会让管理员误以为已经恢复脚本模式。

### 选项

| 选项 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| A | 严格所有权：仅管理 RustVPN 创建的 TAP；拒绝已存在的非 TAP/非 RustVPN 接口 | 边界清晰、可回滚 | 不能接管已有 TAP |
| B | 允许接管任意 TAP，`replace` 覆盖 | 灵活 | 容易破坏手工配置 |
| C | 只做 additive，不 replace | 与手工配置共存 | 幂等难保证，容易残留 |
| D | 移除 `network:` 时热拆除 | 无重启 | 需要 diff/teardown，复杂 |

### 建议

**选 A + 暂时保留“移除需重启”，后续再做 D。**

- 接口名必须带 RustVPN 标记（命名前缀/状态文件/注释），不是任意 `iface`；
- 已存在但 `ip -d` 不是 TAP 的接口直接拒绝；
- 自动创建的 TAP 在服务退出时删除；不是自动创建的，不删除；
- 文档明确：移除 `network:` 后需重启，或先手动清理；
- GoVPN 兼容文件不要包含 `network:`。

### 验收

- 非 TAP 接口被拒绝，不修改；
- 自动 TAP 失败能回滚；
- 移除 `network:` 后重启能清理；
- 旧 YAML 无变化。

---

## 13. diff reload 扩大后的吊销范围

### 现状

- reload 指纹包含：name、timeout、up/down、keepalive、rekey、network、verifier/iface/MTU/mode/CPR/timesync 等。
- 语义变化会吊销该 peer 的会话；未变 peer 保持。
- 纯注释/空白/字段顺序变化不触发；语义 no-op 不 bump `config_generation`。

### 为什么需要决策

- 保守吊销符合现有安全不变量“配置变更必须吊销会话”，但会增加运维抖动：
  - 改一个显示名也可能断线；
  - 改 timeout/keepalive 是否需要断线，取决于是否能动态更新。
- 过于宽松的吊销会违反安全不变量，或让配置变更不生效。

### 选项

| 选项 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| A | 严格：任何语义变化都吊销 | 安全、行为可预测 | 运维抖动较大 |
| B | 分类：安全/会话字段吊销，运营字段热更新 | 减少抖动 | 需要可变配置/动态更新，复杂度高 |
| C | 只对 verifier/iface/MTU/mode/network 吊销 | 抖动最小 | 可能违反“变更必须吊销”的安全不变量 |

### 建议

**选 A，保持严格吊销；暂不做 B/C。**

- 日志明确列出“为什么吊销”（哪些字段变了），避免只看到 peer 名；
- 把 name 变化视为“显示名变更”仍吊销，是保守选择；如果运维强烈反对，再加 `reload_policy: operational` 显式放宽，并写清安全影响；
- `config_generation` 保持“语义变更才 bump”；如果 admin 需要检测文件任意改动，另加 `file_generation`，不要把两个语义混在一起。

### 验收

- 三 peer 场景，改一个只吊销一个；
- 语义等价 YAML 不触发；
- 日志能看出吊销原因；
- 安全不变量测试仍通过。

---

## 14. 建议直接采用的默认值

如果希望尽快合并，建议先按下面执行：

| 项 | 已执行决定 |
|---|---|
| MTU 来源 | **数值线路 MTU（双方一致）**；拒绝 `auto`/`0`；仅推导 TAP IP MTU/MSS；auto/主动 PMTU 推迟 v2 |
| `mtu: 0` | 客户端与服务端均拒绝显式 0（省略服务端字段默认 1515） |
| 显式 MTU | 越界/低于 noise 下限/派生 TAP IP MTU <68 一律拒绝，不钳制 |
| MSS clamp | 默认 best-effort；独立 IPv4/IPv6 值；`required` 严格模式延后 |
| kill-switch | 默认关闭；显式开启；无 nft 时 fail-closed；仅主机 output；放行物理接口 ND/MLD/DHCPv6 |
| kill-switch 崩溃 | clean-shutdown 标记；崩溃后保留表；首次握手成功前每次解析前重开临时 DNS、解析后收窄、握手前关闭；成功后替换/删除；表消失则不再声明 fail-closed；显式停止删表 |
| QR | 外部 `qrencode`；临时文件 O_EXCL + 原子 rename；内置 QR 延后 |
| GUI | 首页只读 MTU/安全状态；新 profile 默认 MTU 1515、rekey 1800；开关延后 |
| 文档 | en/zh/ru 已对齐 MTU、keepalive、kill-switch 崩溃策略与 status 形状 |
| status 形状 | 公共/仅客户端/仅服务端字段分离；服务端速率 `null` + `rates_available:false`；`unavailable` schema 完整 |
| `rekey_time` | daemon 默认 0；新 profile/GUI 默认 1800；GUI 只读显示 |
| keepalive | 默认关闭；plain 10s / noise 25s / 上限 3600s；CLI/profile 共享常量，verifier 使用相同边界 |
| 时间重协商丢包 | 接受；默认关闭；零丢包留给 v2 |
| 服务端声明式 TAP | 严格 RustVPN 所有权（`alias rustvpn-managed`）；拒绝未标记 TAP；移除 `network:`/删除 peer 时自动剪枝 guard，无需重启 |
| diff reload | 严格吊销；日志列出变化字段；创建前重查 generation，避免 TOCTOU |

---

## 15. 需要你明确的最终选择

请按编号回复即可，例如：

```text
1 A+B
2 B
3 A+C
4 A
5 A
6 B（后续）
7 B
8 A
9 A
10 B
11 A
12 A
13 A
```

需要特别确认的三项：

1. **时间重协商**：能否接受“开启后短暂断流”？如果不能，本版应保持默认关闭，并把零丢包列入 v2。
2. **`mtu: 0`**：是否允许继续作为 auto 的快捷写法？我建议禁止，只保留 `"auto"`。
3. **服务端声明式 TAP**：是否接受“RustVPN 独占接口 + 移除 `network:` 需重启”？如果要求它与手工 TAP 共存，需要改设计。