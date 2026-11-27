// Lightweight runtime translations for the RustVPN client UI.
//
// Chinese source strings are the dictionary keys.  Static markup is translated
// in place, while dynamic strings call `I18n.t(key, values)`.
"use strict";

(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.RustVpnI18n = api;
  }
})(typeof globalThis === "undefined" ? this : globalThis, function () {
  const LANGUAGES = [
    { id: "zh", label: "中文", html: "zh-CN" },
    { id: "en", label: "English", html: "en" },
    { id: "ru", label: "Русский", html: "ru" },
  ];

  const EN = {
    "客户端": "Client",
    "连接": "Connect",
    "配置": "Profiles",
    "日志": "Logs",
    "设置": "Settings",
    "检测守护进程…": "Checking daemon…",
    "本地守护进程管理隧道，UI 不持有特权。":
      "The local daemon owns the tunnel; the UI has no privileges.",
    "未连接": "Disconnected",
    "管理配置": "Manage profiles",
    "断开": "Disconnect",
    "退出": "Quit",
    "空闲": "Idle",
    "选择配置后连接。": "Select a profile to connect.",
    "服务器": "Server",
    "协议 / 模式": "Protocol / mode",
    "接口": "Interface",
    "连接时长": "Uptime",
    "安全": "Security",
    "下行速率": "Download rate",
    "上行速率": "Upload rate",
    "累计 0 B": "Total 0 B",
    "载荷下行": "Payload down",
    "载荷上行": "Payload up",
    "不含线路开销": "Excludes wire overhead",
    "实时流量": "Live traffic",
    "最近 60 秒 · 线路字节": "Last 60 s · wire bytes",
    "还没有配置": "No profiles yet",
    "先到“配置”页添加服务器地址、verifier 和地址分配。":
      "Add a server address, verifier and address allocation on the Profiles page.",
    "添加配置": "Add profile",
    "配置保存在": "Profiles are stored in",
    "，口令不会写入磁盘。": "; passwords are never written to disk.",
    "暂无配置": "No profiles",
    "添加一个 RustVPN/GoVPN 服务端配置即可开始。":
      "Add a RustVPN/GoVPN server profile to get started.",
    "级别": "Level",
    "全部": "All",
    "刷新": "Refresh",
    "清空视图": "Clear view",
    "0 行": "0 lines",
    "守护进程": "Daemon",
    "UI 版本": "UI version",
    "认证": "Authentication",
    "本地 Unix socket，SO_PEERCRED / 组权限":
      "Local Unix socket, SO_PEERCRED / group permissions",
    "重新检测": "Check again",
    "启动与托盘": "Startup & tray",
    "登录时启动 RustVPN": "Start RustVPN at login",
    "关闭窗口会隐藏到托盘；可从托盘菜单重新打开或退出。":
      "Closing the window hides it to the tray; reopen or quit from the tray menu.",
    "安全边界": "Security boundary",
    "UI 以普通用户运行，不创建 TAP、不改路由。":
      "The UI runs as a normal user; it does not create TAP or change routes.",
    "隧道由": "The tunnel runs in",
    "在最小权限下运行。": "with minimal privileges.",
    "配置里不保存口令，日志不会记录口令。":
      "Profiles contain no password, and logs never record it.",
    "GUI 不执行用户提供的 up/down 脚本。":
      "The GUI never runs user-supplied up/down scripts.",
    "关于": "About",
    "RustVPN 客户端 · GPL-3.0-or-later · Tauri 2 + GTK WebView":
      "RustVPN client · GPL-3.0-or-later · Tauri 2 + GTK WebView",
    "界面语言": "Interface language",
    "语言会立即应用到界面与托盘菜单。":
      "The language applies to the UI and tray menu immediately.",
    "软件更新": "Software update",
    "检查更新": "Check for updates",
    "当前版本": "Current version",
    "当前版本 {version}": "Current version {version}",
    "更新源未配置：请使用启用 updater 特性并配置签名公钥的构建。":
      "No update source configured: use a build with the updater feature and a signing public key.",
    "发现新版本 {version}": "Version {version} is available",
    "已是最新版本": "You are up to date",
    "检查失败：{error}": "Update check failed: {error}",
    "下载并安装": "Download and install",
    "正在下载更新…": "Downloading update…",
    "更新已安装，重启后生效": "Update installed; it takes effect after restart",
    "安装失败：{error}": "Install failed: {error}",
    "打开 RustVPN": "Open RustVPN",
    "输入口令": "Enter passphrase",
    "口令仅在内存中传给守护进程，用于派生 Argon2d 密钥。":
      "The passphrase is passed to the daemon in memory only, to derive the Argon2d key.",
    "口令": "Passphrase",
    "保存到系统钥匙串": "Save to the system keychain",
    "取消": "Cancel",
    "保存": "Save",
    "名称": "Name",
    "协议": "Protocol",
    "超时（秒）": "Timeout (s)",
    "Verifier（短格式）": "Verifier (short form)",
    "代理": "Proxy",
    "可选，HTTP CONNECT 代理": "Optional HTTP CONNECT proxy",
    "代理认证": "Proxy auth",
    "CPR（KiB/s）": "CPR (KiB/s)",
    "接口名": "Interface name",
    "地址": "Address",
    "网关": "Gateway",
    "路由": "Routes",
    "Noise（等长填充）": "Noise (constant-length padding)",
    "Encless（仅 TCP）": "Encless (TCP only)",
    "IPv6（全隧道时阻断，暂不支持隧道）":
      "IPv6 (blocked for full tunnel; tunnelling not supported)",
    "GUI 配置由守护进程内置的地址/路由管理生效；不接受 up/down 脚本。全隧道（routes 包含 default）必须填写地址、网关和 DNS；全隧道连接期间 IPv6 默认路由会被阻断，避免泄漏。":
      "The daemon's built-in address/route manager applies GUI profiles; up/down scripts are not accepted. A full tunnel (routes contains default) requires address, gateway and DNS; while it is connected the IPv6 default route is blackholed to prevent leaks.",
    "编辑配置": "Edit profile",
    "请选择配置": "Select a profile",
    "配置名称为空": "Profile name is empty",
    "服务器地址为空": "Server address is empty",
    "verifier 为空": "verifier is empty",
    "请填写 TAP 地址（例如 10.88.0.2/24）":
      "Enter a TAP address (for example 10.88.0.2/24)",
    "接口名为空": "Interface name is empty",
    "全隧道配置需要网关（例如 10.88.0.1）":
      "A full-tunnel profile needs a gateway (for example 10.88.0.1)",
    "全隧道配置需要至少一个 DNS 服务器":
      "A full-tunnel profile needs at least one DNS server",
    "Encless 只能配合 TCP": "Encless requires TCP",
    "名称不能为空": "Name cannot be empty",
    "守护进程在线": "Daemon online",
    "守护进程离线": "Daemon offline",
    "Tauri API 未注入": "Tauri API not injected",
    "请通过 Tauri 窗口打开：当前页面没有 IPC 注入。":
      "Open this page in the Tauri window: IPC is not injected here.",
    "请先添加配置": "Add a profile first",
    "守护进程不可达": "Daemon unreachable",
    "守护进程不可达：{error}": "Daemon unreachable: {error}",
    "读取配置失败：{error}": "Failed to load profiles: {error}",
    "{count} 个配置无法加载：{first}":
      "{count} profile(s) could not be loaded: {first}",
    "已启用登录自启动": "Start at login enabled",
    "已关闭登录自启动": "Start at login disabled",
    "设置自启动失败：{error}": "Failed to set autostart: {error}",
    "连接 {name}": "Connect {name}",
    "已从系统钥匙串载入口令": "Passphrase loaded from the system keychain",
    "请输入口令": "Enter the passphrase",
    "提交中…": "Submitting…",
    "连接已提交，但钥匙串操作失败：{error}":
      "Connection submitted, but the keychain operation failed: {error}",
    "已提交连接请求": "Connection request submitted",
    "连接失败：{error}": "Connection failed: {error}",
    "正在断开": "Disconnecting",
    "断开失败：{error}": "Disconnect failed: {error}",
    "配置已保存": "Profile saved",
    "保存失败：{error}": "Save failed: {error}",
    "删除配置“{name}”？此操作不会影响正在运行的隧道。":
      "Delete profile “{name}”? The running tunnel is not affected.",
    "配置已删除": "Profile deleted",
    "删除失败：{error}": "Delete failed: {error}",
    "读取日志失败：{error}": "Failed to read logs: {error}",
    "{count} 行": "{count} lines",
    "峰值 {value}": "Peak {value}",
    "等待流量采样…": "Waiting for traffic samples…",
    "连接后显示实时速率": "Rates appear after connecting",
    "连接中": "Connecting",
    "已连接": "Connected",
    "重连中": "Reconnecting",
    "断开中": "Disconnecting",
    "错误": "Error",
    "无法连接 rustvpn-clientd；检查服务、socket 和用户组权限。":
      "Cannot reach rustvpn-clientd; check the service, socket and group permissions.",
    "握手 {remote}": "Handshaking with {remote}",
    "解析地址并建立握手": "Resolving the address and starting the handshake",
    "正在连接…": "Connecting…",
    "正在重连": "Reconnecting",
    "，{seconds} 秒后重试": ", retrying in {seconds} s",
    "连接已结束": "Connection ended",
    "连接失败": "Connection failed",
    "查看日志获取详情": "See the logs for details",
    "正在断开…": "Disconnecting…",
    "恢复路由与 DNS": "Restoring routes and DNS",
    "已选择 {profile}": "Selected {profile}",
    "累计 {value}": "Total {value}",
    "部分配置无法加载": "Some profiles could not be loaded",
    "端点": "Endpoint",
    "类型": "Type",
    "命名管道": "Named pipe",
    "命名管道 DACL；发送口令前校验服务端 PID、镜像路径与 Authenticode 签名":
      "Named-pipe DACL; the server PID, image path and Authenticode signature are verified before the passphrase is sent",
    "Windows 服务未安装或未启动时，开发模式需运行 rustvpn-clientd.exe --console -socket <非生产管道>，并用 RUSTVPN_CLIENTD_SOCKET 指向同一管道；M5 安装器负责注册服务。":
      "If the Windows service is not installed or running, run rustvpn-clientd.exe --console -socket <dev-pipe> and point RUSTVPN_CLIENTD_SOCKET at it; the M5 installer registers the service.",
    "Windows 使用当前用户的 Run 注册表项；登录时最小化到托盘，不会自动连接。":
      "Windows uses the current user's Run registry entry; it starts minimized to the tray at login and never connects automatically.",
    "RustVPN 客户端 · GPL-3.0-or-later · Tauri 2 + WebView2":
      "RustVPN client · GPL-3.0-or-later · Tauri 2 + WebView2",
    "无法连接 rustvpn-clientd 命名管道；服务可能未安装或未启动（M5 安装器），或当前账户没有管道权限。":
      "Cannot reach the rustvpn-clientd named pipe; the service may be missing or stopped (the M5 installer registers it) or this account lacks pipe access.",
    "Windows：排查 Wintun DLL/驱动、路由冲突和服务状态。":
      "Windows: check the Wintun DLL/driver, route conflicts and the service state.",
    "MTU {mtu} 推导出的接口 IP MTU {derived} 小于最小值 {min}；至少使用 {minimum}":
      "MTU {mtu} derives interface IP MTU {derived}, below the minimum {min}; use at least {minimum}",
    "Windows 版不支持 kill-switch；请在配置中关闭后再连接。":
      "The Windows build does not support kill-switch; disable it in the profile before connecting.",
    "Windows 不支持": "unsupported on Windows",
    "Windows 暂不支持": "unavailable on Windows",
    "Windows 版不启用应用内更新；请使用签名 MSI 升级。":
      "In-app updates are disabled on Windows; upgrade with a signed MSI.",
    "Windows 故障排查": "Windows troubleshooting",
    "Wintun DLL 或驱动缺失：确认安装包包含 wintun.dll，开发时检查 RUSTVPN_WINTUN_DLL 绝对路径。":
      "Missing Wintun DLL or driver: verify the package includes wintun.dll; in development check the absolute RUSTVPN_WINTUN_DLL path.",
    "路由冲突：关闭其他 VPN 或默认路由程序，并移除与配置冲突的静态路由。":
      "Route conflict: stop other VPN or default-route software and remove static routes that conflict with the profile.",
    "服务未安装或未启动：M5 安装器会注册服务；开发时用 --console -socket <非生产管道>。":
      "Service not installed or running: the M5 installer registers it; for development use --console with a non-production -socket.",
    "服务未安装或未启动：M5 安装器会注册服务；开发时用 --console 指定非生产管道。":
      "Service not installed or running: the M5 installer registers it; for development use --console with a non-production pipe.",
    "管道权限被拒绝：把账户加入本地组 RustVPN（M5 安装器创建），或以守护进程用户身份运行。":
      "Pipe access denied: add the account to the local RustVPN group (created by the M5 installer) or run as the daemon user.",
    "kill-switch 与 MSS clamp 在 Windows 版不可用；界面只显示真实应用状态。":
      "kill-switch and MSS clamp are unavailable on Windows; the UI shows only the actually applied state.",
    "编辑": "Edit",
    "删除": "Delete",
    "服务器、verifier 与地址分配；口令不会落盘。":
      "Server, verifier and address allocation; passphrases are never written to disk.",
    "守护进程的连接、路由与重连记录。等级过滤只影响显示。":
      "Daemon connection, route and reconnect records. Level filtering only affects display.",
    "守护进程位置、安全边界与版本信息。":
      "Daemon location, security boundary and version information.",
  };

  const RU = {
    "客户端": "Клиент",
    "连接": "Подключить",
    "配置": "Профили",
    "日志": "Журнал",
    "设置": "Настройки",
    "检测守护进程…": "Проверка демона…",
    "本地守护进程管理隧道，UI 不持有特权。":
      "Туннелем управляет локальный демон; UI не имеет привилегий.",
    "未连接": "Не подключено",
    "管理配置": "Управление профилями",
    "断开": "Отключить",
    "退出": "Выйти",
    "空闲": "Простой",
    "选择配置后连接。": "Выберите профиль для подключения.",
    "服务器": "Сервер",
    "协议 / 模式": "Протокол / режим",
    "接口": "Интерфейс",
    "连接时长": "Время подключения",
    "安全": "Безопасность",
    "下行速率": "Скорость загрузки",
    "上行速率": "Скорость отдачи",
    "累计 0 B": "Всего 0 B",
    "载荷下行": "Полезная нагрузка (приём)",
    "载荷上行": "Полезная нагрузка (отдача)",
    "不含线路开销": "Без накладных расходов канала",
    "实时流量": "Трафик в реальном времени",
    "最近 60 秒 · 线路字节": "Последние 60 с · байты канала",
    "还没有配置": "Профилей пока нет",
    "先到“配置”页添加服务器地址、verifier 和地址分配。":
      "Добавьте адрес сервера, verifier и распределение адресов на странице «Профили».",
    "添加配置": "Добавить профиль",
    "配置保存在": "Профили хранятся в",
    "，口令不会写入磁盘。": "; пароли не записываются на диск.",
    "暂无配置": "Нет профилей",
    "添加一个 RustVPN/GoVPN 服务端配置即可开始。":
      "Добавьте профиль сервера RustVPN/GoVPN, чтобы начать.",
    "级别": "Уровень",
    "全部": "Все",
    "刷新": "Обновить",
    "清空视图": "Очистить вид",
    "0 行": "0 строк",
    "守护进程": "Демон",
    "UI 版本": "Версия UI",
    "认证": "Аутентификация",
    "本地 Unix socket，SO_PEERCRED / 组权限":
      "Локальный Unix-сокет, SO_PEERCRED / права группы",
    "重新检测": "Проверить снова",
    "启动与托盘": "Запуск и трей",
    "登录时启动 RustVPN": "Запускать RustVPN при входе",
    "关闭窗口会隐藏到托盘；可从托盘菜单重新打开或退出。":
      "Закрытие окна скрывает его в трей; открыть снова или выйти можно из меню трея.",
    "安全边界": "Граница безопасности",
    "UI 以普通用户运行，不创建 TAP、不改路由。":
      "UI работает от обычного пользователя; не создаёт TAP и не меняет маршруты.",
    "隧道由": "Туннель работает в",
    "在最小权限下运行。": "с минимальными привилегиями.",
    "配置里不保存口令，日志不会记录口令。":
      "Профили не содержат пароля, журналы его не записывают.",
    "GUI 不执行用户提供的 up/down 脚本。":
      "GUI никогда не запускает пользовательские скрипты up/down.",
    "关于": "О программе",
    "RustVPN 客户端 · GPL-3.0-or-later · Tauri 2 + GTK WebView":
      "Клиент RustVPN · GPL-3.0-or-later · Tauri 2 + GTK WebView",
    "界面语言": "Язык интерфейса",
    "语言会立即应用到界面与托盘菜单。":
      "Язык сразу применяется к интерфейсу и меню трея.",
    "软件更新": "Обновление ПО",
    "检查更新": "Проверить обновления",
    "当前版本": "Текущая версия",
    "当前版本 {version}": "Текущая версия {version}",
    "更新源未配置：请使用启用 updater 特性并配置签名公钥的构建。":
      "Источник обновлений не настроен: используйте сборку с функцией updater и открытым ключом подписи.",
    "发现新版本 {version}": "Доступна версия {version}",
    "已是最新版本": "Установлена последняя версия",
    "检查失败：{error}": "Ошибка проверки: {error}",
    "下载并安装": "Скачать и установить",
    "正在下载更新…": "Загрузка обновления…",
    "更新已安装，重启后生效": "Обновление установлено; вступит в силу после перезапуска",
    "安装失败：{error}": "Ошибка установки: {error}",
    "打开 RustVPN": "Открыть RustVPN",
    "输入口令": "Введите пароль",
    "口令仅在内存中传给守护进程，用于派生 Argon2d 密钥。":
      "Пароль передаётся демону только в памяти для вывода ключа Argon2d.",
    "口令": "Пароль",
    "保存到系统钥匙串": "Сохранить в системном хранилище ключей",
    "取消": "Отмена",
    "保存": "Сохранить",
    "名称": "Имя",
    "协议": "Протокол",
    "超时（秒）": "Тайм-аут (с)",
    "Verifier（短格式）": "Verifier (краткая форма)",
    "代理": "Прокси",
    "可选，HTTP CONNECT 代理": "Необязательный прокси HTTP CONNECT",
    "代理认证": "Аутентификация прокси",
    "CPR（KiB/s）": "CPR (КиБ/с)",
    "接口名": "Имя интерфейса",
    "地址": "Адрес",
    "网关": "Шлюз",
    "路由": "Маршруты",
    "Noise（等长填充）": "Noise (выравнивание длины)",
    "Encless（仅 TCP）": "Encless (только TCP)",
    "IPv6（全隧道时阻断，暂不支持隧道）":
      "IPv6 (блокируется при полном туннеле; туннелирование не поддерживается)",
    "GUI 配置由守护进程内置的地址/路由管理生效；不接受 up/down 脚本。全隧道（routes 包含 default）必须填写地址、网关和 DNS；全隧道连接期间 IPv6 默认路由会被阻断，避免泄漏。":
      "Профили GUI применяются встроенным менеджером адресов/маршрутов демона; скрипты up/down не принимаются. Полный туннель (routes содержит default) требует адреса, шлюза и DNS; на время подключения маршрут IPv6 по умолчанию блокируется, чтобы избежать утечек.",
    "编辑配置": "Изменить профиль",
    "请选择配置": "Выберите профиль",
    "配置名称为空": "Имя профиля пусто",
    "服务器地址为空": "Адрес сервера пуст",
    "verifier 为空": "verifier пуст",
    "请填写 TAP 地址（例如 10.88.0.2/24）":
      "Укажите адрес TAP (например 10.88.0.2/24)",
    "接口名为空": "Имя интерфейса пусто",
    "全隧道配置需要网关（例如 10.88.0.1）":
      "Для полного туннеля нужен шлюз (например 10.88.0.1)",
    "全隧道配置需要至少一个 DNS 服务器":
      "Для полного туннеля нужен хотя бы один DNS-сервер",
    "Encless 只能配合 TCP": "Encless работает только через TCP",
    "名称不能为空": "Имя не может быть пустым",
    "守护进程在线": "Демон в сети",
    "守护进程离线": "Демон не в сети",
    "Tauri API 未注入": "Tauri API не внедрён",
    "请通过 Tauri 窗口打开：当前页面没有 IPC 注入。":
      "Откройте страницу в окне Tauri: здесь IPC не внедрён.",
    "请先添加配置": "Сначала добавьте профиль",
    "守护进程不可达": "Демон недоступен",
    "守护进程不可达：{error}": "Демон недоступен: {error}",
    "读取配置失败：{error}": "Не удалось загрузить профили: {error}",
    "{count} 个配置无法加载：{first}":
      "Не удалось загрузить профилей: {count}. Первая ошибка: {first}",
    "已启用登录自启动": "Автозапуск включён",
    "已关闭登录自启动": "Автозапуск выключен",
    "设置自启动失败：{error}": "Не удалось настроить автозапуск: {error}",
    "连接 {name}": "Подключение {name}",
    "已从系统钥匙串载入口令": "Пароль загружен из системного хранилища",
    "请输入口令": "Введите пароль",
    "提交中…": "Отправка…",
    "连接已提交，但钥匙串操作失败：{error}":
      "Запрос отправлен, но операция с хранилищем не удалась: {error}",
    "已提交连接请求": "Запрос на подключение отправлен",
    "连接失败：{error}": "Ошибка подключения: {error}",
    "正在断开": "Отключение",
    "断开失败：{error}": "Ошибка отключения: {error}",
    "配置已保存": "Профиль сохранён",
    "保存失败：{error}": "Ошибка сохранения: {error}",
    "删除配置“{name}”？此操作不会影响正在运行的隧道。":
      "Удалить профиль «{name}»? Работающий туннель это не затронет.",
    "配置已删除": "Профиль удалён",
    "删除失败：{error}": "Ошибка удаления: {error}",
    "读取日志失败：{error}": "Ошибка чтения журнала: {error}",
    "{count} 行": "{count} строк",
    "峰值 {value}": "Пик {value}",
    "等待流量采样…": "Ожидание отсчётов трафика…",
    "连接后显示实时速率": "Скорости появятся после подключения",
    "连接中": "Подключение",
    "已连接": "Подключено",
    "重连中": "Переподключение",
    "断开中": "Отключение",
    "错误": "Ошибка",
    "无法连接 rustvpn-clientd；检查服务、socket 和用户组权限。":
      "Нет связи с rustvpn-clientd; проверьте службу, сокет и права группы.",
    "握手 {remote}": "Рукопожатие с {remote}",
    "解析地址并建立握手": "Разрешение адреса и установка рукопожатия",
    "正在连接…": "Подключение…",
    "正在重连": "Переподключение",
    "，{seconds} 秒后重试": ", повтор через {seconds} с",
    "连接已结束": "Подключение завершено",
    "连接失败": "Ошибка подключения",
    "查看日志获取详情": "Смотрите журнал",
    "正在断开…": "Отключение…",
    "恢复路由与 DNS": "Восстановление маршрутов и DNS",
    "已选择 {profile}": "Выбран {profile}",
    "累计 {value}": "Всего {value}",
    "部分配置无法加载": "Некоторые профили не удалось загрузить",
    "端点": "Конечная точка",
    "类型": "Тип",
    "命名管道": "Именованный канал",
    "命名管道 DACL；发送口令前校验服务端 PID、镜像路径与 Authenticode 签名":
      "DACL именованного канала; перед отправкой пароля проверяются PID сервера, путь к образу и подпись Authenticode",
    "Windows 服务未安装或未启动时，开发模式需运行 rustvpn-clientd.exe --console -socket <非生产管道>，并用 RUSTVPN_CLIENTD_SOCKET 指向同一管道；M5 安装器负责注册服务。":
      "Если служба Windows не установлена или не запущена, запустите rustvpn-clientd.exe --console -socket <dev-pipe> и укажите его в RUSTVPN_CLIENTD_SOCKET; установщик M5 регистрирует службу.",
    "Windows 使用当前用户的 Run 注册表项；登录时最小化到托盘，不会自动连接。":
      "Windows использует раздел Run текущего пользователя; при входе приложение сворачивается в трей и никогда не подключается автоматически.",
    "RustVPN 客户端 · GPL-3.0-or-later · Tauri 2 + WebView2":
      "Клиент RustVPN · GPL-3.0-or-later · Tauri 2 + WebView2",
    "无法连接 rustvpn-clientd 命名管道；服务可能未安装或未启动（M5 安装器），或当前账户没有管道权限。":
      "Нет связи с именованным каналом rustvpn-clientd; служба не установлена или не запущена (установщик M5), либо у учётной записи нет прав на канал.",
    "Windows：排查 Wintun DLL/驱动、路由冲突和服务状态。":
      "Windows: проверьте DLL/драйвер Wintun, конфликты маршрутов и состояние службы.",
    "MTU {mtu} 推导出的接口 IP MTU {derived} 小于最小值 {min}；至少使用 {minimum}":
      "MTU {mtu} даёт IP MTU интерфейса {derived}, меньше минимума {min}; используйте не менее {minimum}",
    "Windows 版不支持 kill-switch；请在配置中关闭后再连接。":
      "Сборка для Windows не поддерживает kill-switch; отключите его в профиле перед подключением.",
    "Windows 不支持": "не поддерживается в Windows",
    "Windows 暂不支持": "недоступно в Windows",
    "Windows 版不启用应用内更新；请使用签名 MSI 升级。":
      "Встроенное обновление в Windows отключено; обновляйтесь подписанным MSI.",
    "Windows 故障排查": "Диагностика Windows",
    "Wintun DLL 或驱动缺失：确认安装包包含 wintun.dll，开发时检查 RUSTVPN_WINTUN_DLL 绝对路径。":
      "Нет DLL или драйвера Wintun: убедитесь, что пакет содержит wintun.dll; в разработке проверьте абсолютный путь RUSTVPN_WINTUN_DLL.",
    "路由冲突：关闭其他 VPN 或默认路由程序，并移除与配置冲突的静态路由。":
      "Конфликт маршрутов: остановите другие VPN или программы, меняющие маршрут по умолчанию, и удалите конфликтующие статические маршруты.",
    "服务未安装或未启动：M5 安装器会注册服务；开发时用 --console -socket <非生产管道>。":
      "Служба не установлена или не запущена: установщик M5 регистрирует её; в разработке используйте --console с непроизводственным -socket.",
    "服务未安装或未启动：M5 安装器会注册服务；开发时用 --console 指定非生产管道。":
      "Служба не установлена или не запущена: установщик M5 регистрирует её; в разработке используйте --console с непроизводственным каналом.",
    "管道权限被拒绝：把账户加入本地组 RustVPN（M5 安装器创建），或以守护进程用户身份运行。":
      "Доступ к каналу запрещён: добавьте учётную запись в локальную группу RustVPN (создаётся установщиком M5) или работайте от имени пользователя демона.",
    "kill-switch 与 MSS clamp 在 Windows 版不可用；界面只显示真实应用状态。":
      "kill-switch и MSS clamp недоступны в Windows; интерфейс показывает только фактически применённое состояние.",
    "编辑": "Изменить",
    "删除": "Удалить",
    "服务器、verifier 与地址分配；口令不会落盘。":
      "Сервер, verifier и распределение адресов; пароли не записываются на диск.",
    "守护进程的连接、路由与重连记录。等级过滤只影响显示。":
      "Записи подключений, маршрутов и переподключений демона. Фильтр уровня влияет только на отображение.",
    "守护进程位置、安全边界与版本信息。":
      "Расположение демона, граница безопасности и сведения о версии.",
  };

  const MESSAGES = { en: EN, ru: RU };

  let current = "en";
  const textSources = new WeakMap();
  const attrSources = new WeakMap();

  function normalizeLang(tag) {
    const value = String(tag || "").trim().toLowerCase();
    if (value.startsWith("zh")) return "zh";
    if (value.startsWith("ru")) return "ru";
    if (value.startsWith("en")) return "en";
    return "";
  }

  function defaultLanguage(navTag) {
    try {
      const saved = normalizeLang(localStorage.getItem("rustvpn.lang"));
      if (saved) return saved;
    } catch (error) {
      // Storage can be unavailable in hardened webviews.
    }
    return normalizeLang(navTag) || "en";
  }

  function translate(source) {
    if (current === "zh") return source;
    return MESSAGES[current] && MESSAGES[current][source]
      ? MESSAGES[current][source]
      : source;
  }

  function t(source, values) {
    let text = translate(source);
    if (!values) return text;
    for (const [key, value] of Object.entries(values)) {
      text = text.split(`{${key}}`).join(String(value));
    }
    return text;
  }

  function translateTextNode(node) {
    const raw = node.nodeValue;
    const trimmed = raw.trim();
    if (!trimmed) return;
    let record = textSources.get(node);
    if (!record || record.applied !== raw) {
      record = { source: trimmed, applied: raw };
      textSources.set(node, record);
    }
    const next = raw.replace(trimmed, translate(record.source));
    if (next !== raw) {
      node.nodeValue = next;
      record.applied = next;
    } else {
      record.applied = raw;
    }
  }

  function translateAttributes(element) {
    for (const name of ["placeholder", "title", "aria-label"]) {
      if (!element.hasAttribute || !element.hasAttribute(name)) continue;
      const raw = element.getAttribute(name);
      const trimmed = raw.trim();
      if (!trimmed) continue;
      let record = attrSources.get(element);
      if (!record) {
        record = {};
        attrSources.set(element, record);
      }
      if (!record[name] || record[name].applied !== raw) {
        record[name] = { source: trimmed, applied: raw };
      }
      element.setAttribute(name, raw.replace(trimmed, translate(record[name].source)));
      record[name].applied = element.getAttribute(name);
    }
  }

  function apply(root) {
    const scope = root || (typeof document === "undefined" ? null : document.body);
    if (!scope || typeof document === "undefined") return;
    if (scope.nodeType === 3) {
      translateTextNode(scope);
      return;
    }
    const walker = document.createTreeWalker(scope, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const parent = node.parentNode;
        if (parent && /^(SCRIPT|STYLE)$/.test(parent.nodeName)) {
          return NodeFilter.FILTER_REJECT;
        }
        if (
          parent &&
          parent.closest &&
          parent.closest("[data-i18n-skip]")
        ) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      },
    });
    let node;
    while ((node = walker.nextNode())) translateTextNode(node);
    if (scope.querySelectorAll) {
      scope.querySelectorAll("[placeholder], [title], [aria-label]").forEach(
        translateAttributes
      );
      if (scope.hasAttribute && scope.hasAttribute("placeholder")) {
        translateAttributes(scope);
      }
    }
  }

  function setLang(lang) {
    const next = normalizeLang(lang) || "en";
    current = next;
    if (typeof document !== "undefined" && document.documentElement) {
      const meta = LANGUAGES.find((item) => item.id === next);
      document.documentElement.lang = meta ? meta.html : next;
    }
    try {
      localStorage.setItem("rustvpn.lang", next);
    } catch (error) {
      // Non-persistent mode is acceptable.
    }
    apply();
    return next;
  }

  function init(navLanguage) {
    if (typeof document !== "undefined" && document.documentElement) {
      current = defaultLanguage(navLanguage || (navigator.language || ""));
    }
    apply();
    return current;
  }

  return {
    LANGUAGES,
    MESSAGES,
    apply,
    defaultLanguage,
    getLang: () => current,
    init,
    normalizeLang,
    setLang,
    t,
    translate,
  };
});