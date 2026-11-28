# Docker / Compose 部署

[English](../en/docker.md) | **中文**

本页给出“一条命令拉起服务端并生成 Windows 客户端配置”的容器化部署方式。
它使用 `rustvpn-server` + `rustvpn-admind` 两个镜像，TAP、转发和 NAT 都在
server 容器的网络命名空间内完成；宿主机只需要放行一个 VPN 端口。

已有 systemd 部署见[运维与部署](operations.md)；Windows 客户端安装见
[`docs/windows-install.md`](../windows-install.md)。

---

## 1. 前置条件

- Linux 主机，已安装 Docker 24+ 与 Docker Compose v2（rootful Docker）。
- 内核提供 `/dev/net/tun`；没有时 `sudo modprobe tun`。
- 至少一个可用的 IPv4 默认路由。server 容器需要 `NET_ADMIN`、`NET_RAW`、
  `CHOWN` 和 `DAC_READ_SEARCH` capability，并与宿主共享 `/dev/net/tun`。
- 公网可达的 TCP+UDP 端口（默认 1194），需要在主机防火墙和云安全组中放行；
  如果服务器在路由器/NAT 后面，还要把该端口转发到这台主机。
- 建议 1 vCPU / 512 MB 内存起步；管理端 SQLite 会额外占用少量磁盘。

不需要在宿主机安装 Rust、WiX 或 `nft`；这些都在镜像内。

---

## 2. 一条命令启动

在仓库根目录执行：

```bash
sudo ./deploy/docker/quickstart.sh --endpoint vpn.example.com
```

`--endpoint` 是客户端将连接的地址；省略时会自动探测出口 IPv4，但如果探测到
私网/CGNAT 地址会拒绝启动（服务器在 NAT 后面时必须显式指定公网域名/IP）。

如果仓库不在服务器上，也可以只用脚本：

```bash
curl -fsSL https://raw.githubusercontent.com/shinvdu/rustvpn/main/deploy/docker/quickstart.sh \
  -o rustvpn-quickstart.sh
sudo bash rustvpn-quickstart.sh --endpoint vpn.example.com
```

脚本会从同一 `RUSTVPN_RAW_BASE` 下载 `compose.yaml`；生产环境建议把 URL 固定到
一个 tag 或 commit，而不是跟踪 `main`。

脚本完成后会：

1. 创建数据目录（默认 `/opt/rustvpn`）以及正确权限；
2. 生成一个客户端口令，运行 `rustvpn-verifier` 得到 LONG/SHORT verifier；
3. 写入 `conf/peers.yaml`（LONG verifier + 声明式 `network:`）；
4. 初始化 admin 账号（口令只写入 0600 文件）；
5. `docker compose up -d`，等待控制 socket 和 admin 就绪；
6. 输出客户端 profile、口令文件、admin 口令文件路径和 SSH 隧道命令。

### 常用参数

| 参数 | 含义 | 默认值 |
|---|---|---|
| `--endpoint HOST[:PORT]` | 客户端连接的地址 | 自动探测 |
| `--client NAME` | 第一个客户端名称 | `windows` |
| `--pool CIDR` | 隧道地址池，必须是 IPv4 `/16` | `10.88.0.0/16` |
| `--dns IP` | 客户端 DNS，可重复 | `1.1.1.1` |
| `--split CIDR` | 分流路由，可重复；出现后不再下发默认路由 | 全隧道 |
| `--mtu N` | server 与客户端共用的线路 MTU | `1420` |
| `--data-dir PATH` | 数据目录 | `/opt/rustvpn` |
| `--port PORT` | 宿主机发布的 VPN 端口 | `1194` |
| `--admin-port PORT` | admin 监听的回环端口 | `8080` |
| `--no-admin` | 不启动管理端 | 启动 |
| `--no-nat` | 不在 server 容器内配置 NAT/转发 | 配置 |
| `--build` | 从当前源码构建镜像 | 拉取 GHCR 镜像 |
| `--open-firewall` | 为 ufw/firewalld 增加放行规则 | 不修改 |

> **地址池冲突：** 默认 `10.88.0.0/16` 与大量 GoVPN/WireGuard 示例相同。如果
> 宿主机或对端已有 `10.88.0.0/24`，请用 `--pool 10.99.0.0/16` 之类未占用的
> `/16`。每个客户端占用一个 `/24`（server `10.88.N.1`，客户端 `10.88.N.2`）。

---

## 3. 生成的客户端配置

默认第一个客户端叫 `windows`：

```text
/opt/rustvpn/clients/windows.yaml     # 客户端 profile，不含口令
/opt/rustvpn/secrets/windows.pass     # 口令，root-only
```

Windows 使用步骤：

1. 从 GitHub Releases 安装 `RustVPN-<version>-x64.msi`；
2. 把 `windows.yaml` 复制到：
   ```text
   %LOCALAPPDATA%\RustVPN\profiles\
   ```
3. 打开 GUI，选择该 profile，输入 `windows.pass` 中的口令（可保存到 Windows
   Credential Manager）。

profile 已包含 `remote`、SHORT verifier、MTU、地址、网关、DNS 和默认路由；
不包含口令。请通过安全渠道分别传输 profile 和口令文件，用完可删除口令文件。

添加更多客户端：

```bash
sudo ./deploy/docker/quickstart.sh add-client laptop
```

新客户端会自动分配下一个 `/24`，生成 `clients/laptop.yaml` 和
`secrets/laptop.pass`。server 在 60 秒内热加载；需要立即生效可加 `--restart`
（会断开当前会话）。轮换口令：

```bash
sudo ./deploy/docker/quickstart.sh rotate-client laptop
```

---

## 4. 管理端

管理端默认只监听宿主机回环 `127.0.0.1:8080`，不占用 VPN 端口：

```bash
ssh -N -L 8080:127.0.0.1:8080 root@vpn.example.com
# 浏览器打开 http://127.0.0.1:8080/
```

登录账号 `admin`，初始口令在：

```text
/opt/rustvpn/secrets/admin.pass      # root-only，不打印
```

轮换：

```bash
sudo ./deploy/docker/quickstart.sh rotate-admin-password
```

**已知限制：** 当前 0.2.x 管理端的“新增客户端”不会写入声明式 `network:`，
在这种容器部署里新建的 peer 不会自动创建 TAP。请用
`quickstart.sh add-client <name>` 创建客户端；管理端仍可用于查看会话、踢线、
禁用/启用、轮换口令、配置预览/应用/备份和历史统计。

如果需要对公网开放管理端，请在前面加 TLS 反向代理（Caddy/Nginx），启用
admin 的 `-cookie-secure`，并用防火墙限制来源；不要直接发布 8080。

---

## 5. 数据目录

```text
/opt/rustvpn/
  conf/peers.yaml               # 服务端真源；server 只读，admin 可写
  conf/peers.disabled.yaml      # 可选，admin 写入
  run/control.sock              # server 与 admin 共享的控制 socket
  state/admin.db                # admin 账号/历史/审计（SQLite）
  state/backups/                # 配置备份
  secrets/                      # 客户端与 admin 口令（0700 root）
  clients/                      # 客户端 profile（归部署用户）
  .env                          # Compose 变量（0600）
```

权限约定：

| 路径 | 权限 |
|---|---|
| `conf/`、`run/` | `0770 root:10001` |
| `peers*.yaml` | `0660 root:10001`（admin 写入后会变成 `0640 10001:10001`） |
| `state/`、`state/backups/` | `0700 10001:10001` |
| `secrets/` | `0700 root:root`，文件 `0600` |
| `clients/` | `0750`，归调用 `sudo` 的用户 |

server 容器内的 root 只带最小 capability，因此配置目录由 root 拥有、admin
组可写；server 通过 `DAC_READ_SEARCH` 读取 admin 重写后的配置。

备份：

```bash
sudo tar -C /opt -czf rustvpn-backup.tgz rustvpn
```

升级镜像（先备份数据目录）：

```bash
sudo ./deploy/docker/quickstart.sh setup --data-dir /opt/rustvpn --tag 0.3.0
```

脚本是幂等的：已有 `peers.yaml` 和客户端不会被重复创建；升级会重建容器但保留
数据。生产环境建议固定镜像 tag 或 digest，不要长期跟踪 `edge`。

停止 / 删除：

```bash
sudo ./deploy/docker/quickstart.sh down
sudo ./deploy/docker/quickstart.sh destroy --yes    # 连同数据目录一起删除
```

---

## 6. 镜像与 GHCR

镜像发布在：

```text
ghcr.io/shinvdu/rustvpn/rustvpn-server:<version>
ghcr.io/shinvdu/rustvpn/rustvpn-admind:<version>
```

- `main` 推送发布 `edge` 和 `sha-<commit>`；
- `v*` tag 发布版本号、`<major>.<minor>`、`latest` 和 `sha-<commit>`；
- 也可以手动 `workflow_dispatch` 指定与 `Cargo.toml` 一致的版本。

GHCR 包默认可能是 private；公开给终端用户前请在仓库的 Packages 设置里改为
public。私有包需要先 `docker login ghcr.io`。本地开发可以：

```bash
sudo ./deploy/docker/quickstart.sh setup --endpoint ... --build  # 源码构建 :dev 镜像
```

`rustvpn-clientd` 是 Windows 服务（Wintun + 命名管道），不以 Linux 容器形式
发布；Windows 客户端继续使用 MSI。server 镜像内附带 `rustvpn-client` 和
`rustvpn-verifier`，便于调试和自动化测试。

---

## 7. 网络与安全模型

- server 使用 Docker bridge 网络；TAP、`ip_forward` 和 nftables 表
  `inet rustvpn_nat` 都只存在于容器 netns，容器删除即清理。
- 只发布 `${RUSTVPN_PORT}/udp` 和 `${RUSTVPN_PORT}/tcp`；admin 通过
  `network_mode: host` 绑定宿主回环。
- server 容器：root + `cap_drop: ALL`，仅添加 `NET_ADMIN`、`NET_RAW`、
  `CHOWN`、`DAC_READ_SEARCH`；`no-new-privileges`、只读根文件系统。
- admin 容器：uid/gid `10001`、无 capability、只读根文件系统、`127.0.0.1`。
- 控制 socket 为 `0660 root:10001`；server 用 `SO_PEERCRED` 校验 admin 的
  主 gid。
- `--no-nat` 可用于已有外部 NAT/转发设备的场景；此时必须由宿主或上游提供
  转发和 `MASQUERADE`，否则全隧道只能到达服务器本身。
- 不提供 IPv6 隧道；Windows 客户端的全隧道会阻断 IPv6。需要 IPv6 出口时
  请等待后续版本。
- 默认 DNS `1.1.1.1` 会经隧道转发；如需自有解析器，用 `--dns` 指定。

---

## 8. 故障排查

| 现象 | 处理 |
|---|---|
| `quickstart` 报 `/dev/net/tun is missing` | 宿主机 `modprobe tun`，或使用带 tun 的内核/实例 |
| 容器启动后 `rustvpn-server` 立即退出 | `docker compose logs server`；检查 `peers.yaml` 和 `-script-dir` 权限 |
| TAP 未创建 | `docker exec ... ip -4 addr show rsvpn\*`；确认客户端已完成握手，且 `network:` 未被 admin 编辑丢失 |
| 客户端连上但无法上网 | 检查 1194/udp 云安全组；不要加 `--no-nat`；`docker exec server nft list table inet rustvpn_nat` |
| admin 页面“服务端离线” | server 未运行或未启用 `-control`；检查共享 `run/` 卷和 socket 权限 |
| `docker compose pull` 403 | GHCR 包是 private；`docker login ghcr.io` 或改为 public |
| `add-client` 后 60 秒仍不生效 | 加 `--restart`，或检查 `config_last_error` |

自测（会创建临时 Compose 项目，不改宿主路由/NAT）：

```bash
sudo RUSTVPN_SELFTEST_PORT=21941 ./deploy/docker/selftest.sh
```

它会构建/使用本地 `:dev` 镜像、启动 server、在隔离的 Docker 网络内跑一个
client 容器，验证 ping、全隧道出口、会话计数、第二个客户端和宿主隔离。
已有镜像时可加 `RUSTVPN_SELFTEST_SKIP_BUILD=1`。

---

## 9. 验证状态（2026-11-28）

- Linux 主机 Docker 29.7 + Compose v5.5：隔离网络内 server + client 容器
  E2E 通过（ping、全隧道出口、会话计数、第二个客户端、宿主无 TAP/NAT 泄漏）。
- Windows 11 VM，已安装 0.2.0 MSI，通过守护进程 IPC 使用本流程生成的
  profile（MTU 1420、`10.99.0.0/16` 池、全隧道）连接：ping 网关 4/4、
  ping `1.1.1.1` 4/4、DNS A 记录正常、TCP 443 可连、`curl` 出口 IP 与
  server 一致；断开后 Wintun 适配器、DNS 与默认路由恢复正常。
- 生成的 YAML 已放入 `%LOCALAPPDATA%\RustVPN\profiles\`；本次连接通过
  守护进程 IPC 验证，未做 GUI 可视化检查。口令仍在 GUI 中输入。

## 10. 本期不包含

- 独立 Linux 客户端镜像（server 镜像内的 `rustvpn-client` 仅供调试）。
- `rustvpn-clientd` 的 Linux 等价服务。
- ARM64 镜像、IPv6 传输、内置 DNS 服务、管理端自动分配 `network:`。
- 自动修改云安全组；端口放行由运维负责。