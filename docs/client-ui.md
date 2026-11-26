# 客户端桌面 UI（Linux / Tauri 2）

> 状态：Linux MVP 已实现（分支 `feature/client-ui`）
> 调研与跨平台方案：[`client-ui-plan.md`](client-ui-plan.md)
> 更新：2026-11-26

## 架构

GUI 不持有特权，也不链接隧道/密码学代码。隧道由独立的 `rustvpn-clientd`
在最小权限下运行，GUI 通过本地 Unix socket 控制它。

```text
rustvpn-client-ui（Tauri 2 + 静态 HTML/JS）
        │  /run/rustvpn-client/client.sock
        │  4B BE 长度 + JSON，协议 v1，SO_PEERCRED
rustvpn-clientd（TAP、路由、DNS、重连）
        │
rustvpn-client-core（Profile、Engine、会话、Linux 网络配置）
        │
rustvpn-crypto / proto / net（现有数据面库）
```

| crate | 作用 | 默认构建 |
|---|---|---|
| `rustvpn-client-core` | Profile 校验、单会话、重连状态机、TAP/路由/DNS | 否 |
| `rustvpn-client-ipc` | IPC DTO、帧编解码、GUI 客户端 | 否 |
| `rustvpn-clientd` | 特权守护进程 | 否 |
| `rustvpn-client-gui` | Tauri 2 外壳（`rustvpn-client-ui`） | 否 |
| `rustvpn-client` | 原 CLI，保持独立，不依赖 daemon/GUI/IPC | **是** |

## 快速开始（deb / rpm）

推荐用发行包安装 CLI、daemon、GUI、systemd unit 和 desktop 文件：

```bash
packaging/linux/build-packages.sh              # 构建 deb + rpm
sudo apt install ./dist/rustvpn-client_*.deb    # Debian/Ubuntu
# 或：sudo dnf install ./dist/rustvpn-client-*.rpm
sudo systemctl enable --now rustvpn-clientd
sudo usermod -aG rustvpn "$USER"               # 重新登录后 GUI 才有权限
rustvpn-client-ui
```

首次使用：

1. 打开“配置”，填写服务器、verifier、地址；全隧道再填网关和 IPv4 DNS；
2. 回到“连接”选择配置并连接；
3. 在“设置”选择界面语言（中文 / English / Русский），可开启登录自启动；
4. 口令可直接输入，或勾选保存到系统钥匙串。

如果只想从源码运行，跳过本节，按下文“构建依赖”和“开发运行”操作。

## 构建依赖（Ubuntu 24.04）

GUI crate 的 MSRV 为 **Rust 1.90**（Tauri 2.12 要求）；CLI/core 仍为 workspace
的 1.85。CI 使用 stable。

```bash
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev \
    libayatana-appindicator3-dev librsvg2-dev libxdo-dev libssl-dev \
    build-essential pkg-config libdbus-1-dev
# 可选运行依赖：托盘提示与钥匙串
sudo apt install libayatana-appindicator3-1 gnome-keyring
```

```bash
cargo build --release -p rustvpn-client         # CLI（默认构建）
cargo build --release -p rustvpn-clientd        # 守护进程
cargo build --release -p rustvpn-client-gui     # GUI（产物：rustvpn-client-ui）
```

Tauri 前端是仓库内的静态 `ui/`，不需要 Node/npm；`ui/tauri-bridge.js`
是已打包的 `@tauri-apps/api` 最小桥接（MIT/Apache-2.0，源文件在
`ui/vendor/tauri-api/`）。

## 开发运行

```bash
# 1) 守护进程（需要 TAP/路由权限；开发时可直接用 root 或带 caps 运行）
sudo target/debug/rustvpn-clientd \
    -socket /run/rustvpn-client/client.sock \
    -socket-group "$(id -gn)"

# 2) GUI（普通用户）
RUSTVPN_CLIENTD_SOCKET=/run/rustvpn-client/client.sock \
    target/debug/rustvpn-client-ui
```

非 root 开发时可以不传 `-socket`，双方默认使用
`$XDG_RUNTIME_DIR/rustvpn/client.sock`（socket 模式 `0600`）。

## 配置

GUI 的 profile 保存在 `~/.config/rustvpn/profiles/*.yaml`，格式：

```yaml
name: office
remote: vpn.example.com:1194
proto: udp                 # udp | tcp；设置 proxy 时强制 tcp
verifier: $argon2d$m=4096,t=128,p=1$<id>
mtu: 1515
timeout: 60
timesync: 0
noise: false
encless: false             # 仅 TCP
cpr: 0
proxy: ""
proxy_auth: ""
iface: rsvpn-gui
address: 10.88.0.2/24      # GUI/daemon 必填
gateway: 10.88.0.1
dns: [10.88.0.1]
routes: [default]          # default 或 CIDR
ipv6: false                # 暂不支持
```

- 口令**不写入 YAML**；每次连接由 GUI 在内存中传给守护进程，派生密钥后即释放。
- profile 目录为 `0700`、文件为 `0600`；`proxy_auth` 属于凭据，不要共享这些文件。
- 口令可选存入系统钥匙串（Secret Service）；钥匙串不可用或保存失败时不会阻塞连接，也不会回退到明文存储。
- 守护进程会重新校验所有字段；地址/路由由内置 Linux 配置应用，不接受
  `up`/`down` 脚本。
- GUI/daemon 配置必须有 `address`；全隧道（`routes` 含 `default` 或
  `0.0.0.0/0`）还必须提供 `gateway` 和至少一个 IPv4 `dns`。
- **首次握手成功后才安装路由/DNS**：服务器不可达或口令错误时不会把主机默认
  路由指向未建立的隧道，避免“连不上还断网”。
- 默认路由以 metric 50 安装；安装前先为服务器/代理地址添加 `/32` 防环路由，
  断开时按相反顺序清理。远程地址只在需要时解析一次，重连复用。
- 全隧道连接期间会添加带标记的 IPv6 黑洞路由
  `ip -6 route add blackhole default proto 66 metric 50`，阻断 IPv6 默认路由
  以避免泄漏；断开时删除。IPv6 本身仍不支持隧道。
- DNS 通过 `resolvectl` 设置并 `domain ~.`；全隧道配置下缺少 `resolvectl` 会
  拒绝连接，而不是静默泄漏 DNS。非标准路径可用
  `RUSTVPN_RESOLVECTL_BIN=/path/to/resolvectl` 指定。
- 若系统已有 metric 50 的同目标默认路由，安装会**失败关闭**，不会把“已连接”
  显示成实际接管了默认路由。

## systemd 与权限

仓库模板：[`packaging/systemd/rustvpn-clientd.service`](../packaging/systemd/rustvpn-clientd.service)。

```bash
sudo groupadd --system rustvpn
sudo useradd --system --no-create-home --shell /usr/sbin/nologin -g rustvpn rustvpn
sudo usermod -aG rustvpn "$USER"     # GUI 用户加入共享组；重新登录生效

sudo install -m 0755 target/release/rustvpn-clientd /usr/local/bin/
sudo install -m 0644 packaging/systemd/rustvpn-clientd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rustvpn-clientd
```

- 守护进程以 `rustvpn` 用户运行，仅保留 `CAP_NET_ADMIN`/`CAP_NET_RAW`。
- socket 为 `rustvpn:rustvpn 0660`；`SO_PEERCRED` 校验 uid，主/补充组包含
  `rustvpn` 的用户可连接。
- GUI 的托盘/自启动/钥匙串都在用户桌面会话内；托盘不可用时关闭窗口会正常退出。
- GUI 进程无 capability；即使 WebView 被攻破，也只能操作该本地控制接口。
- CLI 与 daemon 共用 `flock` 隧道锁：root 使用 `/run/rustvpn-client/tunnel.lock`；
  非 root 优先使用运行目录（`$XDG_RUNTIME_DIR/rustvpn` 或 `/run/rustvpn-client`）。
  锁被占用时 daemon 返回错误，UI 显示占用者；可用
  `RUSTVPN_TUNNEL_LOCK=/path` 覆盖。
- CLI 仍可独立运行；同一时刻只有一个活动隧道。若同时部署 `rustvpn-client`
  服务，请给它也加 `RuntimeDirectory=rustvpn-client`，保证锁目录在 daemon 之前存在。
- IPC 空闲超时：`-hello-timeout`（默认 5 秒）限制完成 Hello 前的等待，
  `-idle-timeout`（默认 300 秒）限制已握手连接两次请求之间的空闲；事件订阅
  不受空闲超时影响。设为 `0` 可关闭对应超时，systemd 模板已显式写出默认值。

### deb / rpm 包

正式包会同时安装 CLI、daemon、GUI、systemd unit、desktop 文件与图标，并创建
`rustvpn` 系统用户/组：

```bash
packaging/linux/build-packages.sh          # deb + rpm
packaging/linux/build-packages.sh deb      # 只构建 deb
sudo apt install ./dist/rustvpn-client_*.deb
sudo systemctl enable --now rustvpn-clientd
sudo usermod -aG rustvpn "$USER"          # 重新登录后 GUI 才能访问 socket
```

构建依赖见 [`packaging/linux/README.md`](../packaging/linux/README.md)。RPM 需要
`rpmbuild`；两种包均已检查文件与依赖，但仍应在目标发行版做安装/启动验收。
包不会写入用户级 profile、自启动或钥匙串。

## 功能

- 连接 / 断开、指数退避重连、取消。
- 状态、服务器、协议/模式、接口、时长。
- 下行/上行速率与线路字节、TAP 载荷字节、60 秒 Canvas 曲线。
- profile 新增/编辑/删除；口令每次输入，可选保存到系统钥匙串（Linux Secret Service）。
- 托盘菜单：打开主窗口、断开、退出；关闭窗口隐藏到托盘。
- 单实例：重复启动会唤起已有窗口。
- 登录自启动：设置页写入 `~/.config/autostart/rustvpn-client.desktop`；它只启动 GUI，`rustvpn-clientd` 仍需 `systemctl enable`。
- 钥匙串条目为 `rustvpn-client` 服务 + profile 名；删除/重命名 profile 会清理旧条目。
- 界面语言：中文 / English / Русский，设置页即时切换并同步托盘菜单；选择保存在本机。
- 软件更新：设置页提供检查/安装入口，但仅在启用 `updater` 特性并配置签名公钥与更新端点后可用（见下文）。
- 守护进程日志（SSE/事件流 + 2000 行环形缓冲）。
- 守护进程离线时显示离线并自动重试订阅。

### 界面语言、自启动与钥匙串

- 首次启动跟随系统 `LANG`（`zh*` / `ru*` / 其他回退英文）；之后使用设置页
  保存的选择，保存在 WebView 本地存储中，不写 profile。
- 切换语言立即更新页面和托盘菜单；守护进程的错误/日志仍是英文诊断文本。
- 登录自启动只启动 GUI，写入
  `~/.config/autostart/rustvpn-client.desktop`，不会启动 daemon。
- 勾选“保存到系统钥匙串”后，口令存入 Secret Service（服务名
  `rustvpn-client`，账户为 profile 名）；删除或重命名 profile 会清理旧条目。

### 可选：签名更新

Tauri updater 默认关闭，避免在没有签名密钥时误发布。启用步骤：

1. 生成/保管 updater 签名密钥，把公钥填入
   `crates/rustvpn-client-gui/tauri.conf.json` 的 `plugins.updater.pubkey`；
2. 在 `plugins.updater.endpoints` 填 HTTPS 更新端点（支持
   `{{target}}`/`{{arch}}`/`{{current_version}}` 模板）：

   ```json
   "plugins": {
     "updater": {
       "pubkey": "RW...",
       "endpoints": ["https://updates.example.com/{{target}}/{{arch}}/{{current_version}}"]
     }
   }
   ```
3. 用 `cargo build --release -p rustvpn-client-gui --features updater` 构建，
   或运行 Tauri CLI 打包并设置 `TAURI_SIGNING_PRIVATE_KEY`（私钥只放构建环境）；
4. 发布 `.sig` 与更新产物。更新包由公钥验证签名；私钥丢失将无法再发布可信更新。

未启用该特性的普通构建里，“检查更新”按钮为禁用状态。Linux 上 Tauri
updater 面向 AppImage 自更新；通过本仓库 deb/rpm 安装的副本应使用包管理器
升级，不要依赖 updater 替换系统文件。

## 已知限制

- 仅 Linux；Windows/macOS 需要 L3 适配器 + 以太网垫片，尚未实现。
- IPv6 暂不支持；profile 中 `ipv6: true` 会被拒绝。全隧道会阻断 IPv6 默认
  路由；更具体的 IPv6 链路路由仍可能存在。分流（无 `default` 路由）不会阻断
  IPv6 或系统 DNS，使用前应确认不会泄漏。
- 全隧道必须配置 DNS；分流模式若 `dns` 为空，仍使用系统 DNS。
- i18n 覆盖界面与托盘菜单；`rustvpn-clientd` 的错误文本和日志仍是英文诊断信息，便于检索与兼容。
- Tauri updater 是可选特性：默认构建不含更新插件，需要自己的签名密钥与更新端点；仓库不提供私钥或托管更新服务。Linux 自更新面向 AppImage，deb/rpm 用户应走包管理器升级。
- deb 与 rpm 均已在本机（Ubuntu + `rpmbuild`）构建并检查文件/依赖；仍建议在目标发行版（Fedora/openSUSE）做安装与启动验收。包不包含用户 profile、自启动或钥匙串条目。
- 钥匙串依赖 Linux Secret Service（GNOME Keyring/KWallet）；服务不可用时
  保存/读取会提示失败，但口令输入和连接不受影响。
- GUI 使用仓库内打包的 `@tauri-apps/api`（`withGlobalTauri` 已关闭），
  CSP 仍只允许本地资源。
- 无 TOTP/多用户隔离；本机同组用户共享同一隧道控制权。

## 测试

```bash
cargo test -p rustvpn-client-core -p rustvpn-client-ipc -p rustvpn-clientd -p rustvpn-client-gui
node --test crates/rustvpn-client-gui/ui-tests/i18n.test.js
cargo check -p rustvpn-client-gui --features updater
bash -n packaging/linux/build-packages.sh
cargo clippy --workspace --all-targets -- -D warnings
```

无头 UI 冒烟测试（CI 会跑；需要 `webkit2gtk-driver`、`xvfb` 和
`cargo install tauri-driver`）：

```bash
cargo build --release -p rustvpn-client-gui
xvfb-run -a -s "-screen 0 1280x900x24" dbus-run-session -- bash -c '
  export GDK_BACKEND=x11 WEBKIT_DISABLE_COMPOSITING_MODE=1
  tauri-driver --port 4444 & sleep 1
  node crates/rustvpn-client-gui/ui-tests/webdriver-smoke.js \
    target/release/rustvpn-client-ui
  kill %1
'
```

JS 测试会校验三语字典键一致、占位符保留、静态 HTML/动态 `t()` 文案全部有
翻译；WebDriver 冒烟测试会实际点击导航、切换 zh/en/ru 并打开配置弹窗；
Rust 测试覆盖语言标签解析、托盘文案、IPC Hello/空闲超时。deb 通过
`dpkg-deb -I/-c` 校验文件与依赖；托盘/钥匙串/自启动仍需要真实桌面会话，列
为手工验收项。

端到端验证（本机 netns，未改动现网）：

1. 用 `rustvpn-verifier` 生成临时 verifier，本地 `rustvpn-server` 监听
   veth 地址；
2. 在 netns 中运行 `rustvpn-clientd`，profile 指向 `10.x` 服务器地址；
3. `ping` 服务器 TAP 地址，确认会话 `connected`、流量计数增长；
4. 断开后确认 TAP 删除、路由/DNS 清理。

> 实测：UDP plain、TAP L2、双向流量与最终计数通过；`routes: [default]` 的
> metric-50 默认路由、服务器 `/32` 防环路由、IPv6 blackhole、断开后的路由
> 恢复均通过；GUI 连接/断开/错误状态与事件订阅正常；以 systemd 瞬时单元
> （`User=rustvpn` + ambient `CAP_NET_ADMIN`/`CAP_NET_RAW`）运行时 TAP 创建与
> SIGTERM 清理正常；daemon/CLI 隧道锁单测通过。GUI 已手工验证托盘、关闭到
> 托盘、第二个实例唤起已有窗口、钥匙串保存/预填/删除、登录自启动文件和
> 守护进程离线界面。三语切换、托盘文案同步、updater 特性构建和 deb 内容已
> 校验；deb/rpm 均已构建，目标发行版安装验收仍建议执行。

## 从旧版本升级

- 旧 profile 若 `address` 为空，现在会被 daemon 拒绝。编辑 profile 填写
  `address`（以及全隧道的 `gateway`/`dns`）。
- 旧 profile 若仍使用 `iface: rsvpn0`，请改成 `rsvpn-gui` 或 `rsvpn1`，
  避免与本机 CLI 服务冲突。
- 全隧道 profile 必须同时提供 `gateway` 和至少一个 IPv4 `dns`。
- daemon 与 CLI 现在共用隧道锁。若同时部署 `rustvpn-client.service`，
  给它补上 `RuntimeDirectory=rustvpn-client` 和
  `RuntimeDirectoryMode=0750`，否则锁目录可能由 daemon 之外的对象创建。
- socket 与锁默认位于 `/run/rustvpn-client/`，不再使用 `/run/rustvpn`。

## 故障排查

| 现象 | 处理 |
|---|---|
| `profile has no address` | profile 必须填写 TAP `address`；GUI 和 daemon 都会拒绝 |
| `full-tunnel profile requires ...` | 全隧道补 `gateway` 和 IPv4 `dns` |
| `another RustVPN tunnel is already active` | 关闭另一个 GUI/CLI；查看锁文件元数据，确认没有残留进程 |
| `default route metric 50 already exists` | 已有其他路由占用；停止冲突的 VPN/路由后再连接 |
| `resolvectl not found` / `resolvectl domain ~. failed` | 安装并启用 systemd-resolved，或设置 `RUSTVPN_RESOLVECTL_BIN` |
| `Device or resource busy` | profile `iface` 与本机接口（常见是 `rsvpn0`）冲突，换名 |
| 连接失败且主机断网 | 复查 daemon 日志；正常实现应在握手成功前不动路由。若日志显示 network setup 失败，检查网关/DNS |
| IPv6 被阻断但隧道已断开 | 仅在没有活动 RustVPN 隧道时执行 `ip -6 route del blackhole default proto 66 metric 50` |
| GUI 显示守护进程离线、`Permission denied` | 用户加入 `rustvpn` 组并重新登录；检查 socket `0660` 与 `/run/rustvpn-client` 目录权限 |
| 检查更新按钮灰色 | 当前构建未启用 `updater` 特性或未配置公钥/端点；见“可选：签名更新” |
| 托盘菜单仍是旧语言 | 托盘不可用或语言命令失败；查看启动日志，重启 GUI 后重试 |

## 回滚 / 卸载

```bash
sudo systemctl disable --now rustvpn-clientd
sudo rm /etc/systemd/system/rustvpn-clientd.service
sudo systemctl daemon-reload
```

GUI 与 profiles 都在用户目录，删除 `~/.config/rustvpn` 即可；CLI 与
`rustvpn-client.service` 不受影响。若卸载前 daemon 异常退出，确认没有残留的
`ip -6 route ... proto 66` 黑洞路由。