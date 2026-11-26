# RustVPN — совместимая по проводному формату переработка GoVPN 5.7 на Rust

[English](README.md) | [中文](README.zh.md) | **Русский**

RustVPN — реализация протокола GoVPN 5.7 на Rust, написанная с нуля.
Это не новый дизайн VPN: она говорит в точно таком же проводном формате,
поэтому бинарники `rustvpn-server`, `rustvpn-client` и `rustvpn-verifier` могут
заменить бинарники на Go с любой стороны существующего развёртывания.

Этот репозиторий содержит самостоятельную реализацию RustVPN. Исходное
дерево GoVPN на Go не включено в репозиторий и не изменяется; оно
используется только как оракул для дифференциального тестирования.

## Ключевые особенности

- **Рукопожатие PAKE** — согласование ключей на основе дополненного
  Диффи–Хеллмана (DH A-EKE) с аутентификацией по парольной фразе и
  взаимной аутентификацией с нулевым разглашением.
- **Надёжные верификаторы (verifier)** — токены на основе Argon2d + Ed25519,
  устойчивые к офлайн-атакам по словарю; скомпрометированный серверный
  верификатор не позволяет выдать себя за клиента.
- **Аутентифицированный транспорт** — Salsa20 + Poly1305, последовательная
  обфускация на основе XTEA, 257-битное окно воспроизведения и perfect
  forward secrecy.
- **Устойчивость к цензуре** — байты рукопожатия и транспорта неотличимы
  от случайных данных; необязательное шумовое заполнение (noise) скрывает
  длины пакетов.
- **Режим без шифрования (encless)** — AONT + Chaffing-and-Winnowing
  обеспечивают конфиденциальность без функций шифрования (на клиенте
  только TCP).
- **Операционный паритет** — те же флаги CLI и значения по умолчанию, тот же
  формат `peers.yaml` и горячая перезагрузка каждые 60 секунд, то же
  окружение скриптов `up`/`down`, те же поля JSON статистики, то же поведение
  прокси UDP/TCP/HTTP-CONNECT.
- **Работа над производительностью** — кодек установившегося режима без
  выделений памяти, пакетная обработка `recvmmsg`/`sendmmsg`, TAP-бэкенд на
  io_uring с запасным вариантом на epoll и бэкенд Salsa20 с AVX2 и
  диспетчеризацией во время выполнения.

## Состояние

Реализовано и проверено дифференциальным тестированием против кода Go 5.7:

| Крейт | Содержимое |
|---|---|
| `rustvpn-crypto` | XTEA, Salsa20/XSalsa20, Poly1305, BLAKE2b-256, Chaffing-and-Winnowing, AONT, encless, верификаторы Argon2d/Ed25519, чтение EGD, кодирование представителей `extra25519` |
| `rustvpn-proto` | Кодек классического транспорта, а также транспорта для режимов noise и encless, окно воспроизведения, фрейминг TCP, полное рукопожатие PAKE для обеих ролей |
| `rustvpn-net` | TAP-устройства, конфигурация YAML и горячая перезагрузка, скрипты, статистика, жизненный цикл heartbeat/CPR/rekey, пакетная обработка UDP, TAP на io_uring |
| `rustvpn-client` / `rustvpn-server` | Транспорты UDP и TCP, HTTP CONNECT-прокси, режимы noise и encless, эндпоинт статистики, корректное завершение работы |
| `rustvpn-verifier` | Совместимый по CLI генератор/валидатор верификаторов |

Совместимость проверена сквозным образом (loopback + TAP + сетевые
пространства имён, ICMP через туннель):

| Направление | UDP | TCP | Proxy | Noise | Encless |
|---|---|---|---|---|---|
| Клиент Rust → сервер Go | да | да | да | (байты протокола проверены)* | (байты протокола проверены)* |
| Клиент Go → сервер Rust | да | да | да | да | да |
| Клиент Rust → сервер Rust | да | да | да | да | да |

\* В этой среде TAP-ридер water в Go время от времени сообщает
`not pollable`; тот же сервер Go работает, если его TAP создан заранее.
Проводной формат в любом случае покрыт байт-точными векторами
рукопожатия/транспорта.

Пока не реализовано: упаковка для переносимости под FreeBSD/macOS
(проверялся только Linux) и автоматическая обработка эффективного MTU для
TAP-интерфейсов.

## Быстрый старт

Требования: Rust >= 1.85, Linux `/dev/net/tun`, а также root или
`CAP_NET_ADMIN` для создания TAP.

```bash
cargo build --release
# binaries: target/release/rustvpn-{server,client,verifier}

# 1. Generate a verifier (prints the long form then the short form)
echo 'correct horse battery staple' > /tmp/rustvpn.pass
target/release/rustvpn-verifier -key /tmp/rustvpn.pass

# 2. Start the server (peers.yaml uses the Go format)
target/release/rustvpn-server -proto udp -bind 0.0.0.0:1194 \
    -conf /tmp/peers.yaml -stats 127.0.0.1:1294

# 3. Start the client (short verifier form)
target/release/rustvpn-client -remote server:1194 -proto udp -iface tap0 \
    -verifier '$argon2d$m=4096,t=128,p=1$...' -key /tmp/rustvpn.pass \
    -up /path/to/up.sh -down /path/to/down.sh
```

```yaml
# /tmp/peers.yaml
alice:
  iface: tap0
  mtu: 1515
  timeout: 60
  noise: false
  encless: false
  verifier: $argon2d$m=4096,t=128,p=1$...$...
  up: /path/to/up.sh
  down: /path/to/down.sh
```

Сервер запускает `up` **до** открытия TAP-устройства, поэтому скрипт сам
должен создавать постоянное устройство TAP (`ip tuntap add ... mode tap`);
клиент сначала открывает свой TAP и запускает `up` после установления
сессии. Полное пошаговое руководство см. в разделе
[Начало работы](docs/ru/getting-started.md).

## Документация

Руководство доступно на трёх языках, каждый в своём каталоге:

| Язык | Точка входа |
|---|---|
| English | [`docs/en/index.md`](docs/en/index.md) |
| 中文 | [`docs/zh/index.md`](docs/zh/index.md) |
| Русский | [`docs/ru/index.md`](docs/ru/index.md) |

Страницы на русском:

- [Обзор и концепции](docs/ru/index.md)
- [Начало работы](docs/ru/getting-started.md)
- [Справочник по конфигурации](docs/ru/configuration.md)
- [Протокол](docs/ru/protocol.md)
- [Эксплуатация и развёртывание](docs/ru/operations.md)
- [Безопасность](docs/ru/security.md)
- [FAQ](docs/ru/faq.md)
- [Дизайн](docs/ru/design.md)
- [Производительность](docs/ru/performance.md)
- [Клиентский GUI (Linux, deb/rpm; документация на китайском)](docs/client-ui.md)

## Тесты и бенчмарки

```bash
cargo test
cargo run --release -p rustvpn-crypto --example crypto_bench
cargo run --release -p rustvpn-proto  --example proto_bench
cargo run --release -p rustvpn-net    --example mmsg_bench
```

Тесты используют `testdata/go_vectors.json`, сгенерированный из исходного
дерева GoVPN 5.7 и добавленный в репозиторий, поэтому набор тестов
самодостаточен. Для перегенерации нужны исходники Go и поставляемый с тем
проектом генератор векторов; дерево Go в этот репозиторий не входит.

## Совместимость верификаторов

```bash
# RustVPN проверяет верификатор, созданный GoVPN:
target/debug/rustvpn-verifier -verifier "$LONG_FORM" -key pass.txt

# GoVPN проверяет верификатор, созданный RustVPN:
./govpn-verifier -verifier "$(target/debug/rustvpn-verifier \
    -key pass.txt -m 1024 -t 4 -p 1 | head -1)" -key pass.txt
```

В обоих направлениях выводится `true`.

## Связь с GoVPN

RustVPN — независимая реализация того же протокола, выпускаемая под
**GPL-3.0-or-later**, как и проект на Go. Она не изменяет дерево Go; обе
реализации могут работать рядом на разных портах или в разных сетях.

## Лицензия

GPL-3.0-or-later.