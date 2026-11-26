# Эксплуатация и развёртывание

[English](../en/operations.md) | [中文](../zh/operations.md) | **Русский**

Эта страница описывает продакшн-развёртывание на Linux с systemd, выделенным непривилегированным пользователем и capability-правами Linux. Та же схема работает для смешанного развёртывания RustVPN↔GoVPN; меняется только бинарник.

## Модель развёртывания

Запускайте оба демона от имени непривилегированного сервисного пользователя, предоставляя только необходимые возможности (capabilities):

- `CAP_NET_ADMIN` — создание и настройка TAP-интерфейсов и выполнение `ip`.
- `CAP_NET_RAW` — требуется для пути TAP/io_uring.

`NoNewPrivileges=yes` и минимальный набор разрешённых capability-прав не дают процессу получить больше. Если ваш дистрибутив не может предоставить ambient capabilities, альтернативой является небольшой wrapper с `setcap` на бинарнике, но выделенный пользователь плюс `AmbientCapabilities` проще и поддаётся аудиту.

## Файлы

```text
/usr/local/bin/rustvpn-server                 0755 root:root
/usr/local/bin/rustvpn-client                 0755 root:root
/etc/rustvpn/                               0750 root:rustvpn
/etc/rustvpn/peers.yaml                     0640 root:rustvpn
/etc/rustvpn/pass                           0640 root:rustvpn   # client only
/etc/rustvpn/client.env                     0640 root:rustvpn   # client only
/etc/rustvpn/up.sh                          0750 root:rustvpn
/etc/rustvpn/down.sh                        0750 root:rustvpn
/etc/systemd/system/rustvpn-server.service    0644 root:root
/etc/systemd/system/rustvpn-client.service    0644 root:root
```

Создайте пользователя один раз:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin rustvpn
sudo install -d -m 0750 -o root -g rustvpn /etc/rustvpn
```

## Конфигурация сервера

`peers.yaml` (верификатор в **длинной форме**):

```yaml
alice:
  iface: rsvpn0
  mtu: 1515
  timeout: 60
  noise: false
  encless: false
  verifier: '$argon2d$m=4096,t=128,p=1$BASE64_ID$BASE64_PUBLIC_KEY'
  up: /etc/rustvpn/up.sh
  down: /etc/rustvpn/down.sh
```

`up.sh` — обратите внимание, что он запускается **до** открытия TAP демоном, поэтому должен создавать постоянное устройство:

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-rsvpn0}"
ip tuntap add dev "$IFACE" mode tap 2>/dev/null || true
# IP MTU TAP-интерфейса, а не MTU линии (plain линия 1515 -> 1500).
ip link set dev "$IFACE" mtu 1500 up
ip addr replace 10.88.0.1/24 dev "$IFACE"
```

`down.sh`:

```sh
#!/bin/sh
IFACE="${GOVPN_IFACE:-rsvpn0}"
ip addr del 10.88.0.1/24 dev "$IFACE" 2>/dev/null || true
ip link set dev "$IFACE" down 2>/dev/null || true
```

## Конфигурация клиента

Храните парольную фразу и верификатор в короткой форме только на клиенте.

`/etc/rustvpn/pass` содержит парольную фразу и не должен иметь проблемы с завершающим переводом строки; демон удаляет один завершающий `\n`.

`/etc/rustvpn/client.env`:

```sh
RUSTVPN_VERIFIER='$argon2d$m=4096,t=128,p=1$BASE64_ID'
```

`EnvironmentFile` не позволяет systemd раскрывать `$...` в верификаторе.

`up.sh` (запускается после установления сессии):

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-rsvpn0}"
ip tuntap add dev "$IFACE" mode tap 2>/dev/null || true
# IP MTU TAP-интерфейса, а не MTU линии (plain линия 1515 -> 1500).
ip link set dev "$IFACE" mtu 1500 up
ip addr replace 10.88.0.2/24 dev "$IFACE"
ip route replace 10.88.0.0/24 dev "$IFACE"
```

`down.sh` удаляет маршрут и адрес и опускает линк.

## Модули systemd

`/etc/systemd/system/rustvpn-server.service`:

```ini
[Unit]
Description=RustVPN server (GoVPN 5.7 compatible)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rustvpn
Group=rustvpn
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=/usr/local/bin/rustvpn-server -proto udp -bind 0.0.0.0:1194 \
    -conf /etc/rustvpn/peers.yaml -stats 127.0.0.1:1294
Restart=on-failure
RestartSec=2
LimitNOFILE=65536
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ReadWritePaths=/run

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/rustvpn-client.service`:

```ini
[Unit]
Description=RustVPN client (GoVPN 5.7 compatible)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rustvpn
Group=rustvpn
EnvironmentFile=/etc/rustvpn/client.env
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=/usr/local/bin/rustvpn-client -remote 203.0.113.10:1194 \
    -proto udp -iface rsvpn0 -mtu 1515 -timeout 60 \
    -verifier "${RUSTVPN_VERIFIER}" -key /etc/rustvpn/pass \
    -up /etc/rustvpn/up.sh -down /etc/rustvpn/down.sh
Restart=always
RestartSec=5
LimitNOFILE=65536
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ReadWritePaths=/run

[Install]
WantedBy=multi-user.target
```

Включите и запустите:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rustvpn-server
sudo systemctl enable --now rustvpn-client
```

## Мониторинг

Эндпоинт статистики — это минимальный HTTP-сервер; опрашивайте его локально:

```bash
curl -s http://127.0.0.1:1294/ | jq .
```

Полезные проверки:

- `FramesIn` / `FramesOut` растут при наличии трафика.
- `FramesUnauth` остаётся равным 0; растущее значение означает пакеты, не прошедшие проверку MAC или рукопожатия (неверный ключ, неверный режим или атака).
- `FramesDup` остаётся близким к 0; рост означает повторное воспроизведение или дублированную доставку.
- `Established` соответствует последнему успешному рукопожатию.
- `HeartbeatSent` / `HeartbeatRecv` показывают жизнеспособность на простаивающих каналах.

Типичные команды:

```bash
# client
systemctl status rustvpn-client
journalctl -u rustvpn-client -f
sudo systemctl restart rustvpn-client
ping 10.88.0.1

# server
ssh root@server systemctl status rustvpn-server
ssh root@server journalctl -u rustvpn-server -f
ssh root@server 'curl -s 127.0.0.1:1294/ | jq .'
```

<a id="passphrase-rotation"></a>
## Клиентский GUI (Linux, опционально)

Tauri-клиент (`rustvpn-clientd` + `rustvpn-client-ui`) не зависит от CLI
`rustvpn-client` и использует собственный локальный Unix socket. Установка:
`packaging/linux/build-packages.sh`, затем пакетный менеджер
(`apt install ./dist/rustvpn-client_*.deb` или
`dnf install ./dist/rustvpn-client-*.rpm`), включите демон и добавьте
пользователя в группу `rustvpn`.

- GUI работает без привилегий; `rustvpn-clientd` сохраняет только
  `CAP_NET_ADMIN`/`CAP_NET_RAW`.
- В каждом профиле обязателен IPv4 `address`. Для полного туннеля (`routes`
  содержит `default`/`0.0.0.0/0`) также нужны `gateway` и IPv4 `dns`.
- Маршруты и DNS устанавливаются только после первого успешного рукопожатия.
  Полный туннель добавляет IPv6 blackhole по умолчанию; раздельный туннель
  не блокирует IPv6/DNS.
- Демон и CLI используют общий `/run/rustvpn-client/tunnel.lock`, поэтому
  одновременно может быть только один активный туннель.
- GUI поддерживает трей, скрытие окна в трей, single instance, автозапуск
  при входе, опциональное хранение пароля в Secret Service и переключение
  интерфейса/меню трея zh/en/ru. Трей и автозапуск требуют графической сессии;
  демон по-прежнему запускает systemd.
- `packaging/linux/build-packages.sh` собирает deb/rpm с CLI, демоном, GUI,
  модулем systemd и desktop-файлом. Оба пакета собраны и проверены на Ubuntu
  с `rpmbuild`; установку всё равно стоит проверить в целевом дистрибутиве.
- `-hello-timeout` (5 с) и `-idle-timeout` (300 с) демона ограничивают IPC
  рукопожатие и простой между запросами; подписки на события не закрываются.
  Подписанный Tauri updater — опциональная функция сборки, требующая своих
  ключей и конечной точки обновлений.
- Пользователь GUI должен входить в группу `rustvpn`. systemd-модуль,
  миграция и диагностика — в [руководстве клиента](../client-ui.md)
  (сейчас на китайском).

## Ротация парольной фразы

Для ротации сгенерируйте новый верификатор и **используйте обе строки из одного запуска** (у них общая идентичность/соль):

```bash
openssl rand -hex 24 | tr -d '\n' | sudo tee /etc/rustvpn/pass.raw >/dev/null
sudo /usr/local/bin/rustvpn-verifier -key /etc/rustvpn/pass.raw > /tmp/rvver
# line 1: long form  -> server peers.yaml
# line 2: short form -> client client.env
sudo mv /etc/rustvpn/pass.raw /etc/rustvpn/pass
sudo systemctl restart rustvpn-client
ssh root@server systemctl restart rustvpn-server
```

Перезапускайте обе стороны почти одновременно; клиент повторяет попытки автоматически.

## Обновление и откат

1. Соберите статический бинарник (см. [Начало работы](getting-started.md)).
2. Скопируйте его в `/usr/local/bin/`, заменив старый.
3. Выполните `systemctl restart` на обеих сторонах. Формат конфигурации и проводной протокол не меняются между сборками Rust и по сравнению с GoVPN 5.7.

Откат выполняется той же процедурой с предыдущим бинарником. Храните копию последнего проверенного бинарника и `peers.yaml`.

## Удаление

```bash
# client
sudo systemctl disable --now rustvpn-client
sudo rm -f /etc/systemd/system/rustvpn-client.service /usr/local/bin/rustvpn-client
sudo rm -rf /etc/rustvpn
sudo systemctl daemon-reload
# optional: sudo userdel rustvpn

# server
sudo systemctl disable --now rustvpn-server
sudo rm -f /etc/systemd/system/rustvpn-server.service /usr/local/bin/rustvpn-server
sudo rm -rf /etc/rustvpn
sudo systemctl daemon-reload
sudo ip link del rsvpn0 2>/dev/null || true
```

<a id="coexistence-with-an-existing-govpn"></a>
## Сосуществование с существующим GoVPN

RustVPN использует собственные порты и сети, поэтому оба решения могут работать на одном хосте:

- назначьте RustVPN другой порт UDP/TCP (например, 1194), другое имя/префикс TAP (`rsvpn0`) и другую подсеть (`10.88.0.0/24`);
- не трогайте существующий сервис GoVPN, его TAP-устройство и его правила NAT;
- если хост фильтрует входящий трафик, откройте только новый порт и подумайте о том, чтобы ограничить его текущим адресом клиента.

## Поиск неисправностей

| Симптом | Диагностика |
|---|---|
| `Cannot find device` на сервере | Скрипт `up` не выполнил `ip tuntap add ... mode tap`. |
| Рукопожатие работает, ping не проходит | На TAP отсутствует адрес/маршрут или MTU слишком велик для данного режима. |
| `FramesUnauth` растёт | Несовпадение режимов (noise/encless), неверный верификатор/парольная фраза или инъецированный трафик. |
| `session failed: random number mismatch` | Обычно это перекрытие старых и новых сессий после одновременного перезапуска; дайте клиенту переподключиться. |
| Клиент переподключается только раз в `timeout` секунд | Первый пакет рукопожатия не передаётся повторно; клиент ждёт истечения тайм-аута. Уменьшите `-timeout` для более быстрого восстановления. |
| Эндпоинт статистики недоступен | Он привязан к адресу из `-stats`; используйте `127.0.0.1` и опрашивайте с того же хоста или через туннель. |

Далее: [Безопасность](security.md).