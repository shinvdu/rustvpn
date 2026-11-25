# RustVPN 管理端 Web UI 调研与实施方案

> 日期：2026-11-26
> 对象：`~/rustvpn`（GoVPN 5.7 线兼容 Rust 实现）
> 目标：为服务端增加管理端 Web UI，支持查看客户端、流量统计、客户端管理及必要的运维能力
> 方式：只读分析现有代码 + 方案调研；本文不修改代码
> 依赖版本：2026-11-26 通过 crates.io 查询（axum 0.8.9、tower-http 0.7.1、rust-embed 8.14.0、rusqlite 0.43.0、tokio-rusqlite 0.10.0、redb 5.0.0、totp-rs 6.0.0）

---

## 0. 结论摘要

**推荐方案：在 `rustvpn-server` 内嵌一个可选的、Cargo feature 门控的管理服务。启用的客户端仍以 `peers.yaml` 为唯一真源，禁用项放同格式的 `peers.disabled.yaml`；管理端通过“校验 → 原子写 → 备份 → 立即热重载”生效；历史流量落 SQLite；前端用无构建的静态页面 + SSE 实时刷新；默认只监听 `127.0.0.1`，由 Caddy/Nginx 终止 TLS，登录使用 Argon2id + HttpOnly Cookie + CSRF + 可选 TOTP。**

选择内嵌而不是独立 sidecar 的核心原因：需求 3「管理客户端」中的“立即断开会话”必须操作进程内的 `Registry`（`PeerEntry.cancel: CancellationToken`）与 `ConfigStore`，外部进程只能通过改文件 + 等 60 秒轮询，体验和实时性都不合格。内嵌可以直接复用现有 `Registry` / `StatsState` / `ConfigSet`，不碰数据面热路径。

必须一起解决的 6 个关键点：

1. **现有 `/stats` 只有“当前活跃会话”的累计计数器**，会话结束即删除（`stats.rs:195-221`、`server/src/main.rs:309,516,967,990`），没有历史、没有客户端名、没有协议类型，且无认证。管理端不能直接包装它，需要自己的 API 与历史存储。
2. **会话结束前必须抓取最终计数**，否则最后一次采样的流量会丢失。需要把 5 处会话移除路径收敛成一个 `end_session()` 钩子。
3. **`peers.yaml` 无法存放管理元数据**：`YamlPeer` 使用 `#[serde(deny_unknown_fields)]`（`config.rs:74`），加任何字段都会破坏加载。禁用/备注/配额/历史必须放在管理端自己的存储中；禁用客户端建议放同格式的 `peers.disabled.yaml`。
4. **配置写入与 60 秒轮询存在竞态**：需引入统一的 `Reloader`（互斥 + 内容比较 + ETag），否则管理端刚生效的配置可能被轮询线程用旧内容覆盖。
5. **systemd 当前禁止写 `/etc`**：`ProtectSystem=full`（`operations.md:126`）会让 `/etc/rustvpn` 只读，管理端写配置前必须调整 unit 与目录权限。
6. **安全边界**：管理端一旦被攻破就等于拿到服务进程能力；因此默认只绑回环、禁止在 UI 中编辑/上传 `up`/`down` 脚本（脚本以服务权限执行）、对危险操作二次确认并审计。

工作量估算：MVP（只读看板 + 会话/流量 + CRUD/踢下线 + 审计/部署）约 **12–15 人日**；含配额/告警/多服务器等增强的完整版本约 **3–4 周**。

---

## 0.1 实现状态（2026-11-26）

MVP 已在分支 `feature/admin-web-ui` 落地，使用说明见 [`admin-web-ui.md`](admin-web-ui.md)。相对本方案的实现偏差：

- 轮换口令**保持身份 id 不变**（只重新派生公钥），历史流量不丢失；比方案中的“生成新 id”更适合运维。
- 管理端配置保存使用请求体中的 `expected_etag`（而非 `If-Match` 头），语义相同。
- 前端为无构建原生 JS + Canvas，未引入 uPlot/Chart.js；CSP 的 `style-src` 允许 `inline`（脚本仍严格 `'self'`）。
- `/metrics` 不鉴权，依赖管理端默认只绑回环。
- 配额仅展示，不自动禁用/限速；TOTP 未实现；角色已支持 admin/viewer。
- `rustvpn-admin-passwd` 增加了 `-password-file`，便于自动化初始化。
- 为消除并行测试下的脚本超时抖动，`run_script` 的**测试专用**超时从 300ms 调整为 2s（生产仍为 10s）。

已实现：feature 门控、Argon2id 登录 + 会话 + CSRF + 登录限速、客户端/会话列表、10 秒采样与 1h/24h/7d/30d 图表、会话历史、终身/月度用量、新增/编辑/禁用/启用/删除/轮换/踢下线、配置预览/应用/备份/恢复、审计、SSE、Prometheus、健康检查、systemd/反代文档、API 与配置写入测试、musl admin 构建检查。

---

## 1. 现状分析

### 1.1 进程与配置模型

- 单进程 Tokio runtime，UDP 主循环 + 每 peer 的收发任务；TCP 每连接一组任务（`docs/zh/design.md:33-42`）。
- 配置：`Arc<RwLock<ConfigSet>>`，启动时读 `peers.yaml`，之后**每 60 秒重新读取**；解析失败保留上一份（`server/src/main.rs:923-946`）。
- 热重载语义：按 `id + verifier + iface + mtu + noise + encless + cpr + timesync` 生成指纹，指纹变化或从配置中消失的活跃会话会被吊销（`main.rs:409-420,982-999`）。这意味着“改配置即踢线”已经有现成机制，管理端应复用它，而不是另造一套。
- 一个客户端身份（16 字节 verifier id）同时只保留一个活跃会话；重连会替换旧会话并复用 TAP（`main.rs:305-314,499-520`）。

### 1.2 身份模型

| 概念 | 位置 | 说明 |
|---|---|---|
| 口令 | 仅客户端 | 人类唯一机密，服务器不保存 |
| 长格式 verifier | 服务端 `peers.yaml` | `$argon2d$m=..,t=..,p=..$<id>$<pubkey>`，含 id 与 Ed25519 公钥 |
| 短格式 verifier | 客户端 `client.env` | `$argon2d$...$<id>`，不含公钥 |
| 客户端名 | `peers.yaml` 顶层键 | 只是服务端标签；协议里没有主机名/操作系统信息 |
| 会话标识 | `PeerEntry.token` | 进程内单调递增 `u64`，只存在于服务端，未对外暴露 |

**重要预期管理**：管理端看到的“客户端”是**配置中的身份**，不是设备。协议不携带 hostname、OS、客户端版本，服务端也不做目的地流量日志（TAP 是 L2，服务端只路由/转发），因此无法在 UI 中展示“这台客户端访问了哪些网站”。若要按目的地统计，需要额外的 eBPF/conntrack 方案，且涉及隐私，不建议放进第一版。

### 1.3 现有统计能力与边界

现有 `/stats` 是 GoVPN 兼容端点（`stats.rs`）：

```json
[{
  "Addr": "203.0.113.10:52341",
  "Id": "base64(16B id)",
  "BytesIn": 1392774, "BytesOut": 17228877,
  "BytesPayloadIn": 1389000, "BytesPayloadOut": 17220000,
  "FramesIn": 12412, "FramesOut": 16588,
  "FramesUnauth": 0, "FramesDup": 0,
  "HeartbeatRecv": 2, "HeartbeatSent": 1,
  "NoiseEnable": false, "CPR": 0, "Encless": false, "MTU": 1515,
  "Established": "...", "LastPing": "...", "LastSent": "..."
}]
```

| 能力 | 现状 | 对管理端的含义 |
|---|---|---|
| 当前活跃会话 | 有 | 可作为实时数据的权威来源 |
| 每会话累计字节/包 | 有 | 需要定期采样并保存历史 |
| 客户端名称 | 无（只有 base64 id） | 用 `ConfigSet.by_id` 关联 |
| UDP/TCP 协议 | 无 | 需给 `PeerEntry` 增加 `proto` 字段 |
| 历史流量 | 无 | 必须新增采样 + 持久化 |
| 会话结束后的数据 | 随 `StatsState::remove` 删除 | 必须在移除前落盘最终快照 |
| 认证 | 无 | 绝不能直接暴露；管理 API 独立鉴权 |
| 请求语义 | 忽略请求，任何连接都返回全量 JSON | 不适合作为管理 API 基础 |

流量口径要注意：

- `BytesIn/Out` 是**线路字节**，包含心跳、noise 填充、CPR 填充、encless 的 4128 字节膨胀；`BytesPayloadIn/Out` 是 TAP 载荷。计费/配额建议明确选一种并在 UI 标注，通常“对用户展示用量”用 payload，“对带宽/成本核算”用线路字节。
- 计数器**按会话**重置；重连后从 0 开始。历史上限、当月用量必须由管理端按身份聚合。
- `FramesUnauth` / `FramesDup` 增长是异常信号（口令/模式错误、注入、重放），适合做 UI 告警。

### 1.4 需求映射与缺口

| 需求 | 现有能力 | 需要新增 |
|---|---|---|
| 1. 查看有哪些客户端 | 配置里有 name/verifier；运行时只有 addr/id | 配置列表 + 活跃会话列表 + id→name 关联 + 协议/模式/在线状态 |
| 2. 客户端流量统计 | 当前会话累计计数器 | 速率（差分）、会话历史、按身份的生命周期累计、按时间范围聚合、图表、Top 客户端 |
| 3. 管理客户端 | 只能改 YAML 等 60 秒重载 | 新增/编辑/禁用/启用/删除/轮换口令/立即踢下线/配额 |
| 4. 其他 | 无 | 服务状态、配置预览与回滚、事件/审计、Prometheus、健康检查、告警、备份 |
| 非功能 | 无 | 登录/CSRF/限速/审计/最小暴露面/不阻塞数据面/静态 musl 构建 |

### 1.5 兼容性契约（必须遵守）

依据 `AGENTS.md` 与 `docs/zh/design.md`：

- 不改线协议、握手、传输字节。
- 不改现有 CLI 标志、默认值、`peers.yaml` 的读取语义。
- 不改 `/stats` 的 JSON 字段名与类型（Go 兼容性测试 `stats.rs::json_field_names_match_go`）。
- 数据面热路径保持零分配稳态；管理端只能做原子计数与**非阻塞**事件投递。
- 默认 `cargo build` 的行为与依赖面尽量不变；管理端用 feature 门控。
- `up`/`down` 脚本以服务权限执行，管理端不得成为任意命令执行入口。

---

## 2. 方案选型

### 2.1 部署形态

| 方案 | 实时性 | 能踢线 | 能改配置 | 复杂度 | 风险 |
|---|---|---|---|---|---|
| **A. 内嵌 admin 服务（推荐）** | 秒级 | 是 | 是 | 中 | HTTP 解析在服务进程内 |
| B. 独立 sidecar 轮询 `/stats` | 5–10 秒 | 否 | 只能改文件等重载 | 低 | 管理能力残缺 |
| C. 独立 admin 守护进程 + 服务端 Unix socket 控制面 | 秒级 | 是 | 是 | 高 | 边界清晰，但需新协议/两进程 |

**推荐 A 作为第一版**：单二进制、部署简单、直接复用 `Registry`。C 作为安全加固的演进方向：admin 进程不带 `CAP_NET_ADMIN`，通过 `/run/rustvpn/admin.sock` + `SO_PEERCRED` 与 server 通信，把 HTTP/模板攻击面与数据面隔离；等 MVP 稳定后再评估。

管理服务只新增一个**可选**监听，例如：

```bash
sudo rustvpn-server -proto all -bind 0.0.0.0:1194 \
    -conf /etc/rustvpn/peers.yaml -stats 127.0.0.1:1294 \
    -admin 127.0.0.1:8080
```

未启用 feature 时 `-admin` 不存在，默认构建保持与 GoVPN 完全一致。

### 2.2 Rust Web 技术栈

| 方案 | 优点 | 缺点 | 结论 |
|---|---|---|---|
| axum 0.8 | 与 Tokio/tower 生态一致；SSE/JSON/中间件成熟；代码量小 | 引入 hyper/tower 依赖 | **推荐** |
| actix-web | 性能好、功能全 | 独立 actor 运行时，依赖更重 | 不推荐 |
| poem / warp | 也可用 | 生态/维护活跃度不如 axum | 不推荐 |
| 手写 HTTP（沿用 stats 风格） | 零新依赖 | 路由/鉴权/SSE/表单全部自造，安全风险高 | 不可行 |

配套：

- `tower-http`：请求体大小限制（配置 YAML 上限，如 1 MiB）、超时、限流、压缩、安全响应头。
- `rust-embed`：把 `ui/` 静态资源编进二进制，无需 Node 构建。
- `serde` / `serde_json`：API。
- `argon2`（工作区已有 0.5）：管理端口令哈希；用 `Argon2::hash_password_into`，避免开启 `password-hash` feature。
- `subtle`（已有）：口令哈希/CSRF token 常量时间比较。
- `totp-rs`（可选）：二步验证。
- `rusqlite`（bundled）或 `redb`：历史/审计/账号。
- `tokio-rusqlite` 或专用写线程：避免在 async runtime 上做阻塞 SQLite I/O。

### 2.3 前端

| 方案 | 构建 | 体积 | 适合度 |
|---|---|---|---|
| **静态 HTML + 原生 JS + uPlot/Chart.js（推荐）** | 无 | 小 | 单页管理面板足够；CI 不需要 Node；CSP 容易收紧 |
| React/Vue + Vite | 需要 Node | 大 | 交互复杂时再考虑；CI 复杂化 |
| 服务端模板（Askama/Leptos SSR） | Rust 内 | 中 | 表单友好，但实时图表仍要 JS |

推荐第一版用**无构建静态资源**：

```text
crates/rustvpn-admin/ui/
├── index.html
├── app.js          # hash 路由 + fetch + SSE
├── app.css
└── vendor/uplot.min.js   # 时间序列图，约 45 KB；Chart.js 约 200 KB，可替换
```

`index.html` 只做壳，页面切换由 `app.js` 完成；静态资源通过 `RustEmbed` 提供，带 ETag/缓存头。所有脚本、样式、字体均本地托管，满足 `CSP: script-src 'self'`。

### 2.4 存储

| 方案 | 优点 | 缺点 | 结论 |
|---|---|---|---|
| 纯内存环形缓冲 | 零依赖、最快 | 重启丢历史；无法审计 | 只适合临时速率 |
| JSONL 追加 + 内存聚合 | 轻量、可 grep | 查询/保留/并发写要自己实现 | 备选 |
| **SQLite（rusqlite bundled）** | SQL 查询、事务、迁移、`sqlite3` 手工排查方便 | musl 构建需 cc 编译 SQLite；依赖 +~1 MB | **推荐** |
| redb（纯 Rust） | 无 C 依赖、适合 musl | 无 SQL，聚合/迁移代码多 | 若拒绝 C 构建则选它 |

SQLite 建议参数：`journal_mode=WAL`、`synchronous=NORMAL`、`busy_timeout=5000`、单写连接。所有 DB 操作通过一个专用写入任务（bounded mpsc）或 `tokio-rusqlite` 执行，绝不在数据面任务里同步写盘。

### 2.5 认证与暴露方式

- **默认绑定 `127.0.0.1`**；跨机器访问用 SSH 隧道、WireGuard，或同机 Caddy/Nginx 反代 TLS。不要在 0.0.0.0 上裸奔。
- 管理口令用 **Argon2id**（`m=65536, t=3, p=1` 起步；按机器调整），32 字节盐 + 32 字节输出，存 salt/params/hash。
- 登录后发 **32 字节随机 session token**，Cookie：`__Host-rvpn_admin`、`HttpOnly`、`Secure`、`SameSite=Strict`、`Path=/`；内存会话表，空闲 30 分钟 / 绝对 12 小时过期。
- 所有非 GET 请求要求 `X-CSRF-Token`（登录后由 `/api/me` 下发），并校验 `Origin`/`Sec-Fetch-Site`。
- 登录限速：每 IP + 每用户名 5 次/5 分钟，指数退避；失败响应常量时间。
- 可选 TOTP + 恢复码；建议至少支持 `admin` / `viewer` 两种角色。
- 首次部署**拒绝启动**而不是开放初始化窗口：用独立命令写入首个管理员（见 §7.1）。

---

## 3. 总体架构

```text
                    ┌──────────────────────────────┐
  Browser ──TLS──▶  │ Caddy/Nginx (127.0.0.1:8080) │
                    └──────────────┬───────────────┘
                                   │ reverse proxy
                    ┌──────────────▼───────────────┐
                    │ rustvpn-server               │
                    │  ├─ 数据面 UDP/TCP/TAP        │
                    │  ├─ Registry / StatsState    │
                    │  ├─ ConfigStore (RwLock)      │
                    │  ├─ Reloader（60s + 管理触发）│
                    │  └─ feature=admin:           │
                    │      axum admin 服务          │
                    │      ├─ auth / session        │
                    │      ├─ peers / sessions API  │
                    │      ├─ traffic sampler       │
                    │      ├─ SQLite store          │
                    │      └─ embedded static UI    │
                    └──────────────────────────────┘
```

### 3.1 新增 crate 与职责

```text
crates/rustvpn-admin/
├── src/lib.rs
├── src/state.rs        # AdminState、AdminBackend trait、SessionObserver
├── src/api/mod.rs      # Router、中间件、错误映射
├── src/api/auth.rs     # 登录/登出/改密/TOTP
├── src/api/peers.rs    # 列表/详情/新增/编辑/禁用/删除/轮换/踢线
├── src/api/sessions.rs # 活跃会话
├── src/api/traffic.rs  # 时间序列与聚合
├── src/api/system.rs   # 状态、配置预览/应用/回滚、审计、事件
├── src/auth.rs         # Argon2id、内存会话、CSRF、登录限速
├── src/store.rs        # SQLite schema、迁移、查询
├── src/history.rs      # 采样器、分钟/小时聚合、保留策略、配额检查
├── src/config_edit.rs  # 渲染 YAML、校验、原子写、备份、ETag
├── src/metrics.rs      # Prometheus 文本
├── src/hooks.rs        # 非阻塞会话开始/结束事件投递
├── ui/                 # 静态资源
└── tests/              # API/鉴权/配置写入/聚合测试
```

`rustvpn-server` 只增加：feature 开关、`-admin` 参数、`AdminBackend` 实现、`MainRequest::Kick`、`Reloader` 重构、会话钩子调用、少量全局原子计数。

`rustvpn-net` 只增加：`YamlPeer` 的 `Serialize`、`ConfigSet::from_str()`、`ConfigSet::render_yaml()`（把 `PeerConfig` 渲染回 YAML）。不动协议与统计结构。

### 3.2 解耦接口（便于测试）

管理 crate 不直接依赖 TAP；通过 trait 与 server 解耦：

```rust
pub trait AdminBackend: Send + Sync {
    fn system_status(&self) -> SystemStatus;
    fn active_sessions(&self) -> Vec<SessionInfo>;
    fn configured_peers(&self) -> Vec<PeerView>;      // 含 disabled
    fn config_snapshot(&self) -> ConfigSnapshot;       // yaml + etag + generation
    fn apply_config(&self, next: ConfigFiles, expected_etag: &str)
        -> Result<ApplyReport, ConfigError>;
    fn preview_config(&self, next: &ConfigFiles)
        -> Result<PreviewReport, ConfigError>;
    async fn kick(&self, id: [u8; 16], reason: &str)
        -> Result<KickReport, KickError>;
    fn events(&self) -> Vec<EventView>;
}

pub trait SessionObserver: Send + Sync {
    fn session_started(&self, info: SessionStart);
    fn session_ended(&self, info: SessionEnd);   // 必须非阻塞：try_send / 计数
}
```

`SessionObserver` 的实现内部只做 `mpsc::Sender::try_send`，队列满时计数并丢弃，**绝不 await、绝不阻塞数据面**。测试用 fake backend 即可覆盖全部 API，无需 TAP/root。

---

## 4. 数据模型与统计口径

### 4.1 配置真源

- `peers.yaml`：**启用**的客户端，保持 GoVPN 格式与读取路径不变。
- `peers.disabled.yaml`：**禁用**的客户端，格式完全相同；server 不读取它，管理端读取/维护。
- SQLite：只放辅助元数据（备注、配额、历史、审计、管理员），不复制 verifier。

为什么不用 DB 的 `enabled` 标志：那会让 DB 变成禁用客户端配置的真源，DB 丢失/恢复不一致时容易丢客户端；独立 YAML 可被人直接查看、编辑、备份，且对 server 零侵入。代价是两份文件要保持 name/id 唯一，管理端在写入时校验。

`peers.yaml` 无法加字段（`config.rs:74` 拒绝未知字段），所以备注、配额等**绝不能**写进去。

### 4.2 SQLite schema（建议）

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

-- 辅助元数据；name 以 YAML 为准，这里保留删除后的展示名
CREATE TABLE IF NOT EXISTS peer_meta (
  id              BLOB PRIMARY KEY,       -- 16 字节 verifier id
  name            TEXT NOT NULL,
  notes           TEXT,
  quota_bytes_month INTEGER,              -- NULL = 不限；按 payload 字节
  created_at      INTEGER NOT NULL,       -- unix 秒
  updated_at      INTEGER NOT NULL,
  last_seen_at    INTEGER
);

CREATE TABLE IF NOT EXISTS session (
  session_id      INTEGER PRIMARY KEY,    -- NEXT_PEER_TOKEN
  peer_id         BLOB NOT NULL,
  addr            TEXT NOT NULL,
  proto           TEXT NOT NULL,          -- udp | tcp
  mode            TEXT NOT NULL,          -- plain | noise | encless
  started_at      INTEGER NOT NULL,
  ended_at        INTEGER,
  end_reason      TEXT,                   -- timeout|rehandshake|tcp_closed|tap_closed|replaced|admin_kick|config_revoke|shutdown
  bytes_in        INTEGER NOT NULL DEFAULT 0,
  bytes_out       INTEGER NOT NULL DEFAULT 0,
  payload_in      INTEGER NOT NULL DEFAULT 0,
  payload_out     INTEGER NOT NULL DEFAULT 0,
  frames_in       INTEGER NOT NULL DEFAULT 0,
  frames_out      INTEGER NOT NULL DEFAULT 0,
  unauth          INTEGER NOT NULL DEFAULT 0,
  dup             INTEGER NOT NULL DEFAULT 0,
  heartbeat_sent  INTEGER NOT NULL DEFAULT 0,
  heartbeat_recv  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS session_peer_started ON session(peer_id, started_at);

CREATE TABLE IF NOT EXISTS sample_1m (
  peer_id     BLOB NOT NULL,
  ts          INTEGER NOT NULL,          -- 分钟桶
  bytes_in    INTEGER NOT NULL,
  bytes_out   INTEGER NOT NULL,
  payload_in  INTEGER NOT NULL,
  payload_out INTEGER NOT NULL,
  PRIMARY KEY (peer_id, ts)
);

CREATE TABLE IF NOT EXISTS sample_1h (
  peer_id     BLOB NOT NULL,
  ts          INTEGER NOT NULL,          -- 小时桶
  bytes_in    INTEGER NOT NULL,
  bytes_out   INTEGER NOT NULL,
  payload_in  INTEGER NOT NULL,
  payload_out INTEGER NOT NULL,
  PRIMARY KEY (peer_id, ts)
);

CREATE TABLE IF NOT EXISTS audit (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ts       INTEGER NOT NULL,
  user     TEXT NOT NULL,
  ip       TEXT,
  action   TEXT NOT NULL,
  target   TEXT,
  detail   TEXT,                          -- JSON，已脱敏
  result   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_user (
  username     TEXT PRIMARY KEY,
  role         TEXT NOT NULL,             -- admin | viewer
  pw_salt      BLOB NOT NULL,
  pw_hash      BLOB NOT NULL,
  pw_m         INTEGER NOT NULL,
  pw_t         INTEGER NOT NULL,
  pw_p         INTEGER NOT NULL,
  totp_secret  BLOB,
  created_at   INTEGER NOT NULL,
  disabled     INTEGER NOT NULL DEFAULT 0
);
```

保留策略建议：

- `sample_1m` 保留 7 天；`sample_1h` 保留 90 天；`session` 永久保留（可按需清理）。
- 采样周期 10 秒，写入时直接累加到分钟桶；每小时由后台任务把分钟桶汇总到小时桶。
- 每个采样 tick 用**一个事务**批量写入，避免频繁 fsync。
- 容量估算：50 个客户端 × 7 天分钟桶 = 50 × 10080 ≈ 50 万行，SQLite 完全可承受。

### 4.3 统计口径

| 指标 | 来源 | UI 展示 |
|---|---|---|
| 当前速率 | 相邻两次采样差值 / 时间差 | 实时 ↑/↓（bit/s 或 B/s） |
| 当前会话累计 | `LiveStats::snapshot()` | 详情页原始值 |
| 生命周期累计 | `session` 表按 `peer_id` 求和 | 列表页“累计流量” |
| 时间范围流量 | `sample_1m` / `sample_1h` | 折线图、区间总量 |
| 月用量/配额 | `sample_1m`/`session` 按月聚合 | 进度条；接近阈值告警 |
| 异常 | `FramesUnauth` / `FramesDup` 增量 | 告警徽标、事件 |

**会话 id** 用 `PeerEntry.token`（进程内唯一），不要用 addr：UDP 重连可能复用源端口，addr 不能唯一标识一次会话。`Established` 变化可以辅助检测新会话，但 token 更可靠。管理 API 中对外用 `session_id` + `peer_id`（hex）。

**丢数据的边界**：进程崩溃时，最后一个采样点到崩溃之间的流量会丢（最多 10 秒）；会话结束钩子可以保证正常结束不丢。这是可接受且需在文档中说明的取舍。

### 4.4 会话结束钩子（关键正确性改造）

当前所有移除路径都直接 `stats.remove(...)`：

1. 替换旧会话：`take_old_peer()`（`main.rs:305-314`）
2. UDP 重连检测：`main.rs:514-517`
3. 主循环收到 `PeerEvent`：`main.rs:963-971`
4. 配置重载吊销：`main.rs:984-999`
5. 优雅关闭：`main.rs:1007-1010`

应统一为：

```rust
async fn end_session(ctx: &ServerContext, entry: Arc<PeerEntry>, reason: EndReason) {
    if ctx.registry.remove_addr(&entry.addr).is_none() {
        return; // 已被其他路径移除，避免重复 call_down / 重复计数
    }
    entry.cancel.cancel();
    let snap = entry.stats.snapshot();          // 先抓最终值
    ctx.stats.remove(&entry.stats.addr);
    if reason != EndReason::Replaced {
        call_down(&entry.cfg.down, entry.tap.name(), &entry.addr.to_string()).await;
    }
    if let Some(admin) = &ctx.admin {
        admin.session_ended(entry.token, entry.cfg.id, reason, snap); // 非阻塞
    }
}
```

`remove_addr` 的返回值天然保证“只有一个路径能完成移除”（现有 token/注册表设计已经具备这个性质），所以把 `call_down` 与统计落盘都放进这个函数是安全的。管理端“踢下线”也复用同一函数。

---

## 5. API 设计

### 5.1 约定

- 前缀 `/api`；JSON snake_case；错误统一 `{ "error": "...", "code": "..." }`。
- 身份 id 在 URL/JSON 中使用 **32 位小写 hex**（避免 base64 的 `+`/`/` 转义）；也接受 base64 输入，便于对照 `/stats`。
- 所有非 GET 要求 `X-CSRF-Token`；写操作记录审计。
- 乐观并发：配置相关接口用 `If-Match: <etag>`；冲突返回 409 + 当前 etag。
- 分页：`?limit=&cursor=`；排序白名单，不接受任意字段。
- 管理端点单独限速（如 50 req/s/IP），SSE 每连接占用一个受限 permit。
- `/metrics`、`/healthz` 可单独监听或允许无鉴权（仅回环）；`/api/*` 一律鉴权。

### 5.2 端点表

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| POST | `/api/login` | 公开（限速） | `{username,password[,totp]}` → Set-Cookie + `{csrf_token,user}` |
| POST | `/api/logout` | 登录 | 销毁会话 |
| GET | `/api/me` | 登录 | 当前用户、角色、CSRF token |
| POST | `/api/me/password` | 登录 | 修改自己的口令 |
| GET | `/api/peers` | viewer | 配置列表 + 在线会话合并 + summary |
| POST | `/api/peers` | admin | 新增客户端，可生成口令 |
| GET | `/api/peers/{id}` | viewer | 详情（配置、当前会话、生命周期汇总） |
| PATCH | `/api/peers/{id}` | admin | 改名称/参数/备注/配额；id 不变 |
| DELETE | `/api/peers/{id}` | admin | 从 YAML 删除；可选保留历史 |
| POST | `/api/peers/{id}/disable` | admin | 移到 `peers.disabled.yaml`，触发吊销 |
| POST | `/api/peers/{id}/enable` | admin | 移回 `peers.yaml` |
| POST | `/api/peers/{id}/rotate` | admin | 重新生成 id + 口令；返回一次性凭据 |
| POST | `/api/peers/{id}/kick` | admin | 立即断开会话（可带 reason） |
| GET | `/api/peers/{id}/traffic` | viewer | `?from=&to=&step=60` 时间序列 |
| GET | `/api/peers/{id}/sessions` | viewer | 历史会话列表 |
| GET | `/api/sessions` | viewer | 当前活跃会话（可 `?peer_id=`） |
| GET | `/api/traffic/summary` | viewer | 全局与 Top N |
| GET | `/api/system/status` | viewer | 运行状态、监听、限速丢弃、重载状态 |
| GET | `/api/system/events` | viewer | 最近事件（环形缓冲） |
| GET | `/api/system/config` | admin | 当前 enabled/disabled YAML + etag + generation |
| POST | `/api/system/config/preview` | admin | 应用前校验 + diff + 预计吊销 |
| PUT | `/api/system/config` | admin | 应用（`If-Match`），自动备份 |
| GET | `/api/system/backups` | admin | 备份列表 |
| POST | `/api/system/backups/{name}/restore` | admin | 回滚并重载 |
| GET | `/api/audit` | admin | 审计查询/导出 |
| GET | `/api/events` | 登录 | SSE：会话、速率、事件、配置状态 |
| GET | `/metrics` | 回环/可选 token | Prometheus 文本 |
| GET | `/healthz` `/readyz` | 公开/回环 | 存活/就绪 |

### 5.3 关键响应示例

`GET /api/peers`：

```json
{
  "summary": {
    "configured": 4, "disabled": 1, "online": 2,
    "rate_in_bps": 1203400, "rate_out_bps": 8300110,
    "today_payload_in": 123456789, "today_payload_out": 987654321
  },
  "peers": [
    {
      "id": "3f0a9c...",
      "name": "alice",
      "enabled": true,
      "state": "online",
      "session_id": 42,
      "addr": "203.0.113.10:52341",
      "proto": "udp",
      "mode": "noise",
      "mtu": 1540,
      "iface": "rsvpn0",
      "established": "2026-11-26T08:00:00Z",
      "last_ping": "2026-11-26T08:05:49Z",
      "uptime_seconds": 349,
      "rate_in_bps": 12034,
      "rate_out_bps": 830011,
      "session": {
        "bytes_in": 1392774, "bytes_out": 17228877,
        "payload_in": 1389000, "payload_out": 17220000,
        "unauth": 0, "dup": 0
      },
      "lifetime": { "bytes_in": 91234567, "bytes_out": 812345678 },
      "notes": "home laptop",
      "quota_bytes_month": null
    }
  ]
}
```

`POST /api/peers` 请求：

```json
{
  "name": "bob",
  "iface": "rsvpn1",
  "mtu": 1515,
  "timeout": 60,
  "noise": false,
  "encless": false,
  "cpr": 0,
  "timesync": 0,
  "up": "/etc/rustvpn/up.sh",
  "down": "/etc/rustvpn/down.sh",
  "notes": "home router",
  "quota_bytes_month": 107374182400,
  "generate_password": true
}
```

响应（**一次性**，之后无法取回口令）：

```json
{
  "id": "b7d1...",
  "name": "bob",
  "password": "…随机 32 字符…",
  "short_verifier": "$argon2d$m=4096,t=128,p=1$…",
  "client_env": "RUSTVPN_VERIFIER='$argon2d$…'\n"
}
```

> 若 `generate_password=false`，请求里带 `password`（仅 HTTPS/回环）；也可提供 `import_long_verifier` 导入已有客户端。服务端只在内存中短暂持有口令，用它派生 verifier 后立即 `zeroize`；绝不写日志/审计。

`POST /api/peers/{id}/rotate` 返回新的 `id/short_verifier/password`，并触发旧身份会话吊销（旧 id 从配置消失即吊销）。

`GET /api/peers/{id}/traffic?from=…&to=…&step=60`：

```json
{
  "step": 60,
  "series": [
    { "ts": 1795000000, "bytes_in": 12345, "bytes_out": 67890,
      "payload_in": 12000, "payload_out": 67000 }
  ],
  "totals": { "bytes_in": 1234567, "bytes_out": 7654321 },
  "sessions": 3
}
```

`POST /api/peers/{id}/kick`：

```json
{ "kicked": true, "session_id": 42, "addr": "203.0.113.10:52341", "reason": "admin_kick" }
```

`PUT /api/system/config`：

```json
{
  "enabled_yaml": "alice:\n  iface: rsvpn0\n  ...",
  "disabled_yaml": "carol:\n  iface: rsvpn1\n  ...",
  "comment": "disable carol"
}
```

```json
{
  "applied": true,
  "generation": 12,
  "etag": "blake2b-…",
  "backup": "peers-20261126-143022.yaml",
  "revoked": ["carol"],
  "warnings": []
}
```

### 5.4 SSE

`GET /api/events` 每秒推送两类帧：

```text
event: tick
data: {"ts":...,"summary":{"online":2,"rate_in_bps":...},"peers":[{"id":...,"rate_in_bps":...,"online":true}]}

event: event
data: {"ts":...,"kind":"peer_removed","peer":"alice","addr":"...","reason":"timeout"}
```

前端用 SSE 更新数字/表格；图表数据仍按范围接口拉取，避免推送过重。SSE 断线由浏览器自动重连；同时保留 5 秒轮询兜底。

---

## 6. UI 页面设计

### 6.1 信息架构

```text
登录
└─ 总览 Dashboard
   ├─ 客户端 Clients
   │  ├─ 客户端详情（概览 / 流量 / 会话历史 / 审计）
   │  └─ 新增 / 编辑
   ├─ 系统 Settings（配置预览与回滚、采样与保留、管理员）
   ├─ 审计日志 Audit
   └─ 事件 Events
```

### 6.2 总览

```text
┌─ 运行状态 ───────────────────────────────────────────────┐
│ 运行 12d 4h   监听 UDP/TCP :1194   活跃 2 / 配置 4 / 禁用 1 │
│ 当前速率 ↓ 1.2 MiB/s  ↑ 8.3 MiB/s   今日用量 1.1 GiB       │
│ 配置 generation 12 · 上次重载 10:22:01 · 无错误             │
├─ Top 客户端 ─────────────────────────────────────────────┤
│ alice   ███████████████ 830 KiB/s                         │
│ bob     ████ 120 KiB/s                                    │
├─ 最近事件 ───────────────────────────────────────────────┤
│ 10:22 alice 会话建立 203.0.113.10:52341 (udp)              │
│ 10:01 bob 超时离线                                         │
└───────────────────────────────────────────────────────────┘
```

### 6.3 客户端列表

列：名称 / 状态（在线·离线·禁用·异常）/ 地址 / 协议 / 在线时长 / 速率↓↑ / 会话累计 / 生命周期累计 / 最后活跃 / 模式·MTU / 操作。

- 顶部：搜索（名称/地址）、状态筛选、排序、导出 CSV、新增客户端。
- 行内操作：详情、踢下线、禁用/启用、轮换口令；删除放详情页（危险操作）。
- 状态判定：在 `Registry` 中 → 在线；在 disabled YAML → 禁用；否则离线；`FramesUnauth/Dup` 短时增长或频繁重连 → 异常徽标。
- 表格每 1 秒由 SSE 更新数字，不整表重绘。

### 6.4 客户端详情

- 概览：id、名称、备注、模式（plain/noise/encless）、MTU、CPR、timeout、timesync、TAP、up/down（只读展示，不可在 UI 编辑内容）、创建时间、最后活跃。
- 实时：当前会话计数（线路/载荷、帧、心跳、unauth/dup）、速率。
- 图表：1h / 24h / 7d / 30d；可切换线路字节/payload；显示心跳/填充开销比例。
- 会话历史：建立/结束时间、地址、协议、结束原因、本次流量。
- 操作：编辑、踢下线、轮换、禁用、删除；每个操作要求填写/确认 reason（写审计）。
- **一次性凭据弹窗**：短 verifier + 口令 + `client.env` 内容；复制/下载；必须勾选“我已保存”才能关闭；关闭后不可再查看。

### 6.5 新增/编辑

- 必填：名称、iface（或 up 脚本路径）。
- 高级：MTU、timeout、noise、encless（自动 noise）、CPR、timesync、up/down 路径。
- 口令：生成（推荐 32 字符）或手输；可导入长格式 verifier（只读展示 id/公钥）。
- 备注、月配额（可选）。
- 保存前调用 `/api/system/config/preview` 展示 diff 与即将被吊销的会话。

### 6.6 系统设置

- 配置 YAML 只读视图 + “高级编辑”模式（等宽字体、校验、diff、预览、应用、回滚）。
- 备份列表（时间、大小、操作人），一键恢复。
- 采样周期、保留天数、配额检查开关。
- 管理员账号、角色、TOTP 开启/重置；登录会话列表（可强制下线）。
- 展示当前监听地址与安全提示（如“管理端口仅绑定回环”）。

### 6.7 审计/事件

- 审计：时间、用户、来源 IP、动作、对象、结果、详情（脱敏）；支持筛选/导出。
- 事件：peer created/removed/timeout/replaced、配置重载成功/失败、限速丢弃、配额触发、登录失败。

---

## 7. 关键实现细节

### 7.1 管理员引导与登录

- 独立命令写入首个管理员（避免明文口令出现在 `ps`/shell history）：

```bash
sudo rustvpn-admin-passwd --db /var/lib/rustvpn/admin.db --user admin
# 交互式输入口令两次；写入 Argon2id 哈希后退出
```

- 服务启动时若 `admin_user` 为空，管理端口**不监听**并打印明确错误；不接受空口令/默认口令。
- 登录成功后轮换 session id（防固定），返回 CSRF token；登出/改密销毁其他会话。

### 7.2 配置写入（最关键的一段）

管理端的配置操作统一走 `ConfigEditor`：

```text
读取 enabled + disabled
  → 应用结构化变更（新增/编辑/禁用/启用/删除）
  → 生成 YAML（BTreeMap 按名称排序，稳定输出）
  → 写临时文件（同目录、0600、create_new）
  → 用 ConfigSet::from_file 校验 enabled（复用现有唯一 id/iface、MTU 钳制、verifier 校验）
  → fsync 临时文件
  → 备份旧文件到 /var/lib/rustvpn/backups/（0640，保留 N 份）
  → rename 覆盖
  → fsync 目录
  → 解析并交换 ConfigStore，向主循环发送 ConfigReloaded（吊销变更会话）
  → 更新 DB 元数据 + 审计
```

要点：

- **不要**接受 UI 传来的任意文件路径；只允许固定的两个配置文件，以及允许清单中的脚本路径。
- **不要**在 UI 中编辑 `up`/`down` 内容或上传脚本：脚本以服务权限执行，等价于 RCE。最多允许从 `/etc/rustvpn/scripts/` 允许清单里选择路径，且修改路径也进审计。
- 渲染时保留原有语义：`timeout<=0` 归一化为 60；`encless=true` 强制 `noise=true`；MTU 钳制到 `[68,9015]`（noise 至少 120）。这些由 `ConfigSet` 再校验一次。
- 序列化使用 `serde_yaml_ng::to_string`（已确认支持 `Serialize`，`serde_yaml_ng-0.10.0/src/ser.rs:707`）。YAML 注释会在写入时丢失，UI 需提示“手工注释将被规范化”；如需保留注释，只能用文本级编辑，不建议第一版做。
- **外部编辑冲突**：管理端记录上次写入的 etag（BLAKE2b）；应用前若磁盘内容 etag 不匹配，返回 409 + diff，让操作者选择“重新加载”或“强制覆盖”。轮询线程与管理端共用同一个 `Reloader` 互斥锁。
- **回滚**：备份文件可直接用 `restore` 接口原子替换并重载；备份不要无限增长，默认保留 20 份。

### 7.3 配置热重载重构

把现有 60 秒任务里的逻辑抽成：

```rust
struct Reloader {
    path: PathBuf,
    store: ConfigStore,
    requests: mpsc::Sender<MainRequest>,
    guard: tokio::sync::Mutex<()>,
    last_bytes: Mutex<Vec<u8>>,
}

impl Reloader {
    async fn reload_from_disk(&self) -> Result<ReloadOutcome> {
        let _g = self.guard.lock().await;
        let bytes = tokio::fs::read(&self.path).await?;
        if *self.last_bytes.lock().unwrap() == bytes {
            return Ok(ReloadOutcome::Unchanged);
        }
        let set = ConfigSet::from_str(str::from_utf8(&bytes)?)?;
        let fingerprints = set.peers.iter()
            .map(|p| (p.id, config_fingerprint(p))).collect();
        *self.store.write().await = set;
        *self.last_bytes.lock().unwrap() = bytes;
        let _ = self.requests.send(MainRequest::ConfigReloaded { fingerprints }).await;
        Ok(ReloadOutcome::Applied)
    }
}
```

- 轮询任务每 60 秒调用 `reload_from_disk()`；管理端写入后立即调用同一方法。
- `last_bytes` 比较避免无变化时反复交换；`guard` 消除“轮询读到旧文件、管理端已写新文件”的覆盖竞态。
- `ConfigSet::from_str()` 由现有 `from_file` 重构而来（解析逻辑不变），避免管理端写临时文件再读。

### 7.4 踢下线

不要从管理任务直接调用 `entry.cancel.cancel()`：需要与主循环的 `PeerEvent` 处理串行化，避免与 `call_down`/统计落盘重复。给 `MainRequest` 增加：

```rust
Kick {
    id: [u8; 16],
    reason: String,
    reply: tokio::sync::oneshot::Sender<Result<KickReport, String>>,
},
```

主循环处理：`addr_by_id(id)` → `registry.get` → `end_session(ctx, entry, EndReason::AdminKick)` → reply。若不存在，返回“当前无活跃会话”。这样踢线与超时/重连/配置吊销走同一条路径，统计与审计一致。

### 7.5 统计采集与聚合

- 采样任务每 10 秒：读取 `StatsState::snapshot()`（纯原子读），结合 `Registry` 的 token/proto，计算与上次采样的差值；若某会话首次出现或计数器回退，重置基线。
- 每个 tick 一个 SQLite 事务，写 `sample_1m` + 更新内存缓存（用于 SSE/速率）。
- 小时汇总任务把分钟桶写入 `sample_1h`；清理任务按保留策略删除。
- 会话开始/结束由 `SessionObserver` 钩子提供；结束时写入完整 `session` 行（含最终计数）。采样任务看到会话消失时，若钩子已写则跳过，避免重复。
- 若钩子队列满（理论上极少），记录 `rustvpn_admin_hook_dropped_total` 并在事件日志中提示；该会话的最终值退化为最后一次采样值。

### 7.6 Argon2 与 SQLite 不能阻塞 runtime

- 管理员登录/新增客户端派生 verifier 都是 CPU 重活：`tokio::task::spawn_blocking` 执行，设置并发上限（如 2），避免登录风暴打满 CPU。
- 新增客户端时 `Verifier::password_apply` 用默认 `m=4096,t=128,p=1` 约几十~几百毫秒，取决于机器；UI 显示“生成中”。
- SQLite 所有写操作走专用写任务或 `tokio-rusqlite`；读查询用 `spawn_blocking` 或只读连接。
- 获取口令后立即派生并 `zeroize`，不把 `String` 长时间留在堆上。

### 7.7 权限与 systemd（必须改）

现有 unit 的 `ProtectSystem=full` 使 `/etc` 只读（`docs/zh/operations.md:119-127`）。管理端要写 `peers.yaml`，需要：

```ini
[Service]
User=rustvpn
Group=rustvpn
ProtectSystem=strict
ReadWritePaths=/etc/rustvpn /var/lib/rustvpn
StateDirectory=rustvpn
StateDirectoryMode=0750
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
```

目录权限：

```bash
sudo chgrp rustvpn /etc/rustvpn
sudo chmod 0770 /etc/rustvpn          # 原子 rename 需要目录写权限
sudo chmod 0640 /etc/rustvpn/peers.yaml /etc/rustvpn/peers.disabled.yaml
sudo install -d -m 0750 -o rustvpn -g rustvpn /var/lib/rustvpn /var/lib/rustvpn/backups
```

注意：`docs/zh/security.md` 当前建议 `/etc/rustvpn` 为 `0750 root:rustvpn`；改成目录组可写是有意的安全权衡。更严格的做法是保持 `/etc` 只读，把可写配置放到 `/var/lib/rustvpn/` 并用 `-conf` 指向它；但 `peers.yaml` 通常被人期望在 `/etc`，需二选一。建议：

- **方案 1（推荐，简单）**：`/etc/rustvpn` 组可写 `0770`，文件 `0640`，备份受保护。
- **方案 2（最小权限）**：配置移到 `/var/lib/rustvpn/peers.yaml`，`/etc/rustvpn/peers.yaml` 只做只读指针/文档说明；unit 的 `ReadWritePaths` 只加 `/var/lib/rustvpn`，`/etc` 保持只读。

备份目录权限同样重要：其中包含 verifier，按凭据保护（`0750 rustvpn:rustvpn`，文件 `0640`）。

### 7.8 安全设计清单

- 默认 `-admin 127.0.0.1:8080`；如需远程，前置 TLS 反代，并额外加来源 IP 白名单/VPN 限制。
- `__Host-` Cookie + `HttpOnly` + `Secure` + `SameSite=Strict`；仅在本地 HTTP 调试时允许关闭 `Secure`（显式开关）。
- CSRF token + Origin 校验；所有写操作非幂等且需确认。
- CSP（示例）：`default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`。
- 响应头：`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`、`Cache-Control: no-store`（API）。
- 登录/操作审计；失败登录也审计（含来源 IP）。
- 不返回任何口令/短 verifier（除创建/轮换的一次性响应）；详情页默认遮蔽 verifier，需显式点“显示”并记审计。
- 管理端不提供文件浏览/上传/命令执行；脚本路径只从允许清单选择。
- 管理 API 请求体上限（1 MiB）、超时（10 秒）、并发上限（Semaphore），防止内存/CPU DoS。
- 定期 `cargo audit` / `cargo deny`；新增依赖固定版本并纳入 CI。
- 若管理端暴露在公网，强烈建议 TOTP + 反代层 mTLS/来源限制；否则只走 SSH 隧道/WireGuard。

### 7.9 Feature 门控与构建

`rustvpn-server/Cargo.toml`：

```toml
[features]
default = []
admin = ["dep:rustvpn-admin"]

[dependencies]
rustvpn-admin = { path = "../rustvpn-admin", optional = true }
```

`rustvpn-admin/Cargo.toml`（示意）：

```toml
[dependencies]
axum = { version = "0.8", features = ["macros"] }
tower-http = { version = "0.7", features = ["limit", "timeout", "compression-gzip", "set-header", "trace"] }
rust-embed = "8"
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
tokio-util = { workspace = true }
anyhow = { workspace = true }
argon2 = { workspace = true }
getrandom = { workspace = true }
subtle = { workspace = true }
chrono = { workspace = true }
rusqlite = { version = "0.43", features = ["bundled"] }
tokio-rusqlite = "0.10"   # 0.10 依赖 rusqlite ^0.43，二者需一起升级
```

构建：

```bash
# 默认构建：与现在完全一致，不含管理端
cargo build --release

# 管理端构建（部署用）
cargo build --release --features rustvpn-server/admin
cargo build --release --target x86_64-unknown-linux-musl --features rustvpn-server/admin
```

CI 增加一个 `--features admin` 的 fmt/clippy/test 任务与 musl 构建任务。musl + `rusqlite/bundled` 需要 `cc` 能交叉编译 SQLite（通常已有；若没有，改用 `redb` 可完全避开 C）。

### 7.10 全局计数与事件日志（服务端小改）

为了让总览页和告警有数据，建议在 server 增加少量原子计数：

- `sessions_started_total` / `sessions_finished_total{reason}`
- `handshake_requests_total` / `handshake_rate_limited_total` / `handshake_errors_total`
- `tcp_connections_rejected_total`
- `config_reload_total` / `config_reload_errors_total`
- `hook_dropped_total`（admin 侧）

事件日志用 `VecDeque<Event>`（上限 2000）+ `RwLock`；peer 创建/移除/重载/失败时 push。keeps `eprintln!` 不变，journald 仍是主日志；事件日志只服务 UI。

---

## 8. 分阶段实施计划

| 阶段 | 内容 | 交付 | 估算 |
|---|---|---|---|
| M0 | 新 crate、feature 门控、`-admin` 监听、Argon2id 登录、CSRF、静态壳、`/api/me`、`/api/system/status`、配置只读接口 | 可登录的总览骨架 | 2 天 |
| M1 | 会话快照 API、id→name 关联、`proto` 字段、速率差分、SSE、Top 客户端、事件环形缓冲 | 实时看板 + 客户端列表 | 2–3 天 |
| M2 | `end_session` 收敛、`SessionObserver`、SQLite schema、10s 采样、分钟/小时聚合、会话历史、流量图 | 完整流量统计 | 3 天 |
| M3 | 新增/编辑/禁用/启用/删除/轮换、配置渲染与原子写、备份/回滚、ETag/预览、`MainRequest::Kick` | 客户端管理闭环 | 4 天 |
| M4 | 审计、Prometheus、健康检查、登录限速/TOTP/RBAC、systemd/部署文档、CI/musl、安全测试 | 可上线版本 | 3 天 |
| M5（可选） | 配额自动禁用、Webhook 告警、CSV 导出、多服务器汇总、拆分 admin 守护进程 | 增强 | 3–5 天 |

总计：MVP（M0–M4）约 14 人日；建议按 M0→M1→M2→M3 顺序做，每一步都可独立验收。

---

## 9. 测试与验收

### 9.1 单元/集成

- 鉴权：Argon2id 哈希/校验、错误口令、限速、会话过期、CSRF、Cookie 属性、角色权限。
- 配置：渲染→解析往返；非法字段/重复 id/重复 iface 被拒；MTU 钳制；encless→noise；外部编辑冲突 409；备份/回滚。
- 流量：计数器回退检测、会话开始/结束、采样聚合、保留清理、月用量计算。
- 踢线：无会话、在线会话、并发双踢、踢线与超时竞态（只触发一次 `call_down`/一次结束记录）。
- 钩子：队列满时不阻塞数据面、丢弃计数正确。
- 安全：未登录访问、CSRF 缺失、XSS 载荷、超大请求体、路径穿越（不应存在文件路径输入）、暴力登录。
- API：错误码、分页、排序白名单、ETag。

### 9.2 端到端

- 用临时目录 + 真实 TAP（现有测试基础设施）启动 server，创建客户端 → 用新 short verifier + 口令启动 client → 验证握手/ping → 在 UI API 踢线 → 客户端自动重连 → 禁用 → 重连被拒 → 启用 → 恢复。
- 流量：跑 `iperf3`/ping，比较 UI 累计与 `/stats` 原始值；确认会话结束后最终值落库。
- 重启 server：历史仍在，活跃会话清空，配置正确加载。

### 9.3 验收清单

- [ ] 客户端列表能区分在线/离线/禁用，并显示名称、地址、协议、模式、速率、累计。
- [ ] 点击客户端能看到 1h/24h/7d 流量图；数值与 `/stats` 一致（线路字节口径）。
- [ ] 新增客户端后客户端能用一次性凭据立即连上。
- [ ] 禁用/轮换/删除后旧会话在数秒内断开（重载触发吊销）。
- [ ] 踢下线后客户端自动重连，UI 显示新会话/新地址。
- [ ] 配置改动前有 diff/预览；失败不会写坏文件；可一键回滚。
- [ ] 未登录/CSRF 缺失/越权请求被拒；登录失败有限速与审计。
- [ ] 管理端口默认仅回环；TLS 反代下 Cookie 为 Secure。
- [ ] `cargo fmt --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace` 通过；`--features admin` 同样通过；musl 构建成功。
- [ ] 数据面基准（`mmsg_bench`/`proto_bench`）与改动前无显著回归。

---

## 10. 风险与未决问题

| 风险 | 影响 | 缓解 |
|---|---|---|
| 管理端被攻破 | 可改配置、看客户端元数据、踢线 | 默认回环 + TLS + Argon2id + CSRF + TOTP；禁止脚本编辑；拆分进程作为演进 |
| 配置写坏 | 全站断连 | 预览 + `ConfigSet` 校验 + 原子写 + 备份 + 一键回滚 |
| 与外部手工编辑冲突 | 管理端覆盖人工改动 | ETag/内容比较 + 409 + diff，不静默覆盖 |
| 注释丢失/格式规范化 | 人工维护体验变差 | UI 明确提示；重要注释移到 README/备注字段 |
| 最终流量丢失 | 统计偏差 | `end_session` 抓最终快照；崩溃最多丢一个采样周期 |
| 60 秒轮询竞态 | 新配置被旧内容覆盖 | 统一 `Reloader` 互斥 + 字节比较 |
| systemd 只读 `/etc` | 写入失败 | 调整 `ProtectSystem`/`ReadWritePaths` 与目录权限，或把可写配置移到 `/var/lib` |
| 依赖膨胀/构建变慢 | 违背项目轻量原则 | feature 门控；默认构建不变；CI 分开跑 |
| musl + SQLite C 构建 | 交叉编译失败 | 使用 `bundled` 并验证 cc；必要时换 `redb` |
| 用户误解“流量” | 计费/对账争议 | UI 同时展示 payload 与线路字节，并解释心跳/填充/CPR 开销 |
| 误以为能看到访问目标 | 需求落空 | 明确协议不提供目的地信息；不做隐式抓包 |
| 多实例部署 | 每台独立，无法统一看板 | 第一版单实例；后续用中央 collector/只读 API 汇总 |

**需要确认的产品决策**（括号内为建议默认值）：

1. 管理端形态：内嵌 feature（建议）还是独立进程？
2. 暴露方式：仅回环 + 反代（建议）、直接 TLS、还是仅 SSH 隧道？
3. 是否允许 UI 写 `peers.yaml`（需求 3 隐含“是”）；禁用客户端放 `peers.disabled.yaml`（建议）还是 DB 标志？
4. 历史保留：分钟 7 天 + 小时 90 天（建议）是否足够？
5. 第一版是否要 TOTP/RBAC/配额（建议 TOTP 可后置，RBAC 先做 admin/viewer）？
6. 前端：无构建静态页（建议）还是 React SPA？
7. UI 语言：中文优先（建议），是否要 i18n？
8. 是否真的需要编辑 up/down 脚本（建议不提供，只从允许清单选路径）？

---

## 11. 与现有代码的具体改动点

| 文件 | 改动 | 性质 |
|---|---|---|
| `crates/rustvpn-net/src/config.rs` | `YamlPeer` 加 `Serialize`；新增 `ConfigSet::from_str`；新增 `render_yaml`/`PeerConfig::to_yaml` | 小，纯逻辑 |
| `crates/rustvpn-server/src/main.rs` | feature 门控；`-admin`；`ServerContext.admin`；`PeerEntry.proto`；`end_session()` 收敛 5 处移除；`MainRequest::Kick`；`Reloader` 抽取；全局原子计数/事件 | 中，控制面 |
| `crates/rustvpn-server/Cargo.toml` | `admin` feature + optional dep | 小 |
| `crates/rustvpn-admin/*` | 新 crate（API/UI/DB/采样/配置编辑） | 大，新增 |
| `.github/workflows/ci.yml` | 增加 `--features admin` 的检查与 musl 构建 | 小 |
| `docs/zh/operations.md` | 增加管理端部署、systemd 权限、反代示例 | 文档 |
| `docs/zh/security.md` | 增加管理端威胁模型与加固项 | 文档 |

不建议改动：`rustvpn-proto`、`rustvpn-crypto`、`rustvpn-client`、现有 `/stats` 字段、握手/传输逻辑。

### 11.1 反代示例

Caddy：

```caddyfile
vpn-admin.example.com {
    encode gzip
    reverse_proxy 127.0.0.1:8080
}
```

Nginx（要点）：

```nginx
server {
    listen 443 ssl http2;
    server_name vpn-admin.example.com;
    # ssl_certificate ...
    client_max_body_size 1m;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

仅允许 VPN/WireGuard 网段或固定 IP 访问 443；管理端自身仍只监听回环。

---

## 12. Prometheus 指标（建议）

```text
rustvpn_up 1
rustvpn_uptime_seconds
rustvpn_peers_active
rustvpn_peers_configured
rustvpn_peers_disabled
rustvpn_peer_payload_in_bytes_total{peer="alice",id="3f0a..."}   # 生命周期，单调
rustvpn_peer_payload_out_bytes_total{peer="alice",id="3f0a..."}
rustvpn_peer_wire_in_bytes_total{peer="alice",id="3f0a..."}
rustvpn_peer_wire_out_bytes_total{peer="alice",id="3f0a..."}
rustvpn_peer_online{peer="alice",id="3f0a..."} 0|1
rustvpn_peer_unauth_total{peer="alice"}
rustvpn_peer_dup_total{peer="alice"}
rustvpn_sessions_started_total
rustvpn_sessions_finished_total{reason="timeout"}
rustvpn_handshake_rate_limited_total
rustvpn_config_reload_errors_total
```

注意：生命周期计数器应从 `session` 表聚合，保证单调；**不要**直接暴露按会话会重置的计数器为 `*_total`，否则 `rate()`/`increase()` 在重连时会产生误导。按会话的实时值用 separate gauge/带 `session_id` 标签的指标。

---

## 13. 参考

- 现有统计实现：`crates/rustvpn-net/src/stats.rs:22-256`
- 会话注册表与生命周期：`crates/rustvpn-server/src/main.rs:153-200,305-314,349-392,743-785,958-1011`
- 配置与校验：`crates/rustvpn-net/src/config.rs:73-105,160-200`
- 配置热重载与吊销：`crates/rustvpn-server/src/main.rs:409-420,923-946,982-999`
- 统计端点文档：`docs/zh/configuration.md:165-200`
- 部署与 systemd：`docs/zh/operations.md:102-171`
- 安全边界：`docs/zh/security.md`
- 设计约束：`docs/zh/design.md`、`AGENTS.md`
- 依赖版本（2026-11-26 查询 crates.io）：axum 0.8.9、tower-http 0.7.1、rust-embed 8.14.0、rusqlite 0.43.0、tokio-rusqlite 0.10.0、redb 5.0.0、totp-rs 6.0.0
- 生态调研：未发现可复用的 GoVPN 5.7 管理面板（GitHub 检索到的 `govpn-api` 属 SoftEther，不适用）；现有多为脚本轮询 `/stats`，无法管理会话。