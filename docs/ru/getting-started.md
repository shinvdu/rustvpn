# Начало работы

[English](../en/getting-started.md) | [中文](../zh/getting-started.md) | **Русский**

Эта страница проведёт вас от клонирования репозитория до работающей пары клиент/сервер. Описание всех параметров см. в [справочнике по конфигурации](configuration.md).

## Требования

- Rust **1.85** или новее (MSRV воркспейса).
- Linux с `/dev/net/tun`, а также root или `CAP_NET_ADMIN` + `CAP_NET_RAW` для создания TAP-устройств и выполнения команд `ip`.
- Для обычной сборки C-тулчейн не требуется. Для полностью статического бинарника (рекомендуется для развёртывания) используйте цель musl, описанную ниже.

## Сборка

Запускайте из корня репозитория:

```bash
cargo build --release
```

Бинарники записываются в `target/release/`:

- `rustvpn-server` — демон, обслуживающий клиентов.
- `rustvpn-client` — демон, подключающийся к серверу.
- `rustvpn-verifier` — генерирует и проверяет верификаторы парольных фраз.

Для статического бинарника, работающего на системах со старой glibc:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# target/x86_64-unknown-linux-musl/release/rustvpn-{server,client,verifier}
```

`.cargo/config.toml` закрепляет Poly1305 за программным (software) бэкендом RustCrypto; это сделано намеренно и измеримо быстрее на процессорах класса Zen3. См. [Производительность](performance.md).

По умолчанию TAP-бэкенд пытается использовать io_uring и переходит на epoll при неудаче. Чтобы принудительно включить бэкенд epoll, задайте в окружении `GOVPN_IO_URING=0`.

## Генерация верификатора

Верификатор (verifier) выводится из парольной фразы и случайной 128-битной идентичности. Инструмент печатает **две строки**: первая — длинная форма (с открытым ключом Ed25519) для сервера, вторая — короткая форма для клиента.

```bash
printf 'correct horse battery staple\n' > /tmp/rustvpn.pass
./target/release/rustvpn-verifier -key /tmp/rustvpn.pass
# $argon2d$m=4096,t=128,p=1$BASE64_ID$BASE64_PUBLIC_KEY   <- server
# $argon2d$m=4096,t=128,p=1$BASE64_ID                     <- client
```

Обе строки должны быть получены в ходе **одного запуска** (у них общая случайная идентичность/соль). Полезные флаги:

| Флаг | Значение | По умолчанию |
|---|---|---|
| `-key PATH` | Прочитать парольную фразу из файла (иначе будет запрос). | запрос |
| `-verifier STR` | Проверить парольную фразу по верификатору в длинной форме; печатает `true`/`false`. | — |
| `-m N` | Стоимость памяти Argon2d в KiB. | 4096 |
| `-t N` | Число итераций Argon2d. | 128 |
| `-p N` | Степень параллелизма Argon2d. | 1 |
| `-egd PATH` | Читать случайные данные из сокета EGD. | `/dev/urandom` |

```bash
# Check a passphrase against the long form
./target/release/rustvpn-verifier -verifier "$LONG_FORM" -key /tmp/rustvpn.pass
```

Храните парольную фразу только на клиенте, в файле с ограниченными правами доступа (например, `0640 root:rustvpn`). Серверу нужен только верификатор в длинной форме.

## Минимальный сервер

`peers.yaml` сопоставляет имена peer'ов с конфигурацией. Верификатор должен быть в **длинной форме**; серверный процесс откажется принимать записи без открытого ключа.

```yaml
alice:
  iface: tap0
  mtu: 1515
  timeout: 60
  noise: false
  encless: false
  verifier: $argon2d$m=4096,t=128,p=1$...$...
  up: /etc/rustvpn/up.sh
  down: /etc/rustvpn/down.sh
```

Фреймворк запускает скрипт `up` **до** открытия TAP-устройства. Поэтому скрипт сам должен создавать постоянное (persistent) устройство TAP; затем демон подключается к нему. Минимальный скрипт up:

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-tap0}"
ip tuntap add dev "$IFACE" mode tap 2>/dev/null || true
ip link set dev "$IFACE" mtu 1515 up
ip addr replace 10.88.0.1/24 dev "$IFACE"
```

`GOVPN_IFACE` и `GOVPN_REMOTE` экспортируются в оба скрипта. Если `iface` в YAML пуст, именем интерфейса становится первая строка stdout скрипта up.

Запуск сервера:

```bash
sudo ./target/release/rustvpn-server \
    -proto udp -bind 0.0.0.0:1194 \
    -conf /etc/rustvpn/peers.yaml \
    -stats 127.0.0.1:1294
```

Файл конфигурации перечитывается каждые 60 секунд; новые peer'ы появляются, а удалённые исчезают без перезапуска. Ошибка разбора сохраняет последнюю корректную конфигурацию и записывает сообщение в лог.

## Минимальный клиент

Клиент использует **короткую форму** верификатора и ту же парольную фразу. Он сначала открывает своё TAP-устройство, затем выполняет рукопожатие и после этого запускает `up`.

```bash
sudo ./target/release/rustvpn-client \
    -remote 203.0.113.10:1194 -proto udp -iface tap0 -mtu 1515 -timeout 60 \
    -verifier '$argon2d$m=4096,t=128,p=1$...' \
    -key /etc/rustvpn/pass \
    -up /etc/rustvpn/up.sh -down /etc/rustvpn/down.sh
```

Клиентский скрипт up (запускается после установления туннеля):

```sh
#!/bin/sh
set -eu
IFACE="${GOVPN_IFACE:-tap0}"
ip tuntap add dev "$IFACE" mode tap 2>/dev/null || true
ip link set dev "$IFACE" mtu 1515 up
ip addr replace 10.88.0.2/24 dev "$IFACE"
ip route replace 10.88.0.0/24 dev "$IFACE"
```

Клиент автоматически переподключается после тайм-аута, повторного рукопожатия (rehandshake) или закрытия TCP-сессии, а при завершении работы запускает `down`.

## Полный пример для IPv4

Предположим, что между клиентом (`192.168.0.2`) и сервером (`192.168.0.1`) есть незащищённый канал WiFi и что поверх него нужна шифрованная сеть `172.16.0.0/24`.

На сервере:

```bash
# TAP and addressing (also do this in up.sh for production)
ip tuntap add dev tap10 mode tap
ip addr replace 172.16.0.1/24 dev tap10
ip link set dev tap10 mtu 1540 up   # 1515 + noise overhead if noise is on

sudo rustvpn-server -bind 192.168.0.1:1194 -conf peers.yaml
```

На клиенте:

```bash
ip tuntap add dev tap10 mode tap
ip addr replace 172.16.0.2/24 dev tap10
ip link set dev tap10 mtu 1540 up
ip route add 0/1 via 172.16.0.1
ip route add 128/1 via 172.16.0.1

sudo rustvpn-client \
    -verifier '$argon2d$m=4096,t=128,p=1$...' \
    -iface tap10 -remote 192.168.0.1:1194
```

Два маршрута `/1` переопределяют маршрут по умолчанию, не удаляя его, поэтому туннель переносит весь трафик, а нижележащий канал по-прежнему передаёт шифрованные UDP-пакеты. Подбирайте MTU в зависимости от режима:

| Режим | Полезная нагрузка при `mtu: 1515` |
|---|---|
| classic | 1514 байт |
| noise | 1490 байт |
| encless | 1506 байт |

Либо увеличьте настроенный MTU/MTU интерфейса, либо уменьшите MTU внутренней сети. См. [Конфигурация → MTU](configuration.md#mtu).

## Опционально: настольный GUI

В Linux `rustvpn-client-ui` вместе с `rustvpn-clientd` может заменить CLI для
повседневной работы. GUI не читает флаги CLI; профили лежат в
`~/.config/rustvpn/profiles/*.yaml` и требуют IPv4 `address` (полному туннелю
также нужны `gateway` и IPv4 `dns`). Демон по-прежнему запускается через
systemd, а пользователь должен входить в группу `rustvpn`. Пакеты deb/rpm,
языки интерфейса/трея, keychain и диагностика — в
[руководстве клиентского GUI](../client-ui.md) (на китайском).

## Тесты и бенчмарки

```bash
cargo test
cargo run --release -p rustvpn-crypto --example crypto_bench
cargo run --release -p rustvpn-proto  --example proto_bench
cargo run --release -p rustvpn-net    --example mmsg_bench
```

Дифференциальные тесты читают `testdata/go_vectors.json`, созданный из
исходного дерева GoVPN 5.7 и добавленный в репозиторий, поэтому набор
тестов самодостаточен. Для перегенерации нужны исходники Go и поставляемый
с тем проектом генератор векторов; дерево Go в этот репозиторий не входит.

## Типичные проблемы при первом запуске

| Симптом | Причина / решение |
|---|---|
| `Cannot find device "tap0"` | Скрипт `up` на сервере не создал постоянное устройство TAP. Добавьте `ip tuntap add ... mode tap`. |
| Рукопожатие проходит, трафика нет | У TAP нет IP-адреса, неверный MTU или отсутствует маршрут. Проверьте `ip addr` / `ip route`. |
| Крупные пакеты пропадают при noise/encless | Полезная нагрузка превышает `MTU-25` / `MTU-9`. Увеличьте MTU или уменьшите MTU внутренней сети. |
| `Currently encryptionless mode works only with TCP` | Используйте `-proto tcp` (также подразумевается при `-proxy`) для encless на клиенте. |
| `server verifier has no public key` | В `peers.yaml` указана короткая форма; используйте длинную форму, созданную в том же запуске. |
| `random number mismatch` во время рукопожатия | Обычно это две перекрывающиеся сессии после одновременного перезапуска; помогает чистый перезапуск или автопереподключение клиента. |

Далее: [Справочник по конфигурации](configuration.md).