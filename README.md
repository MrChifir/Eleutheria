# Eleutheria — VPN на твоём сервере

Open-source инструмент для собственного VPN. Ты арендуешь сервер, Eleutheria подключается к нему по SSH,
ставит sing-box и настраивает обход блокировок по протоколу VLESS + Reality, затем выдаёт ссылку и QR-код
для клиента. Клиент работает как локальный прокси или как системный VPN через TUN.

Поддерживаемые платформы: Linux (проверен), Windows и macOS (написаны, но ещё не запускались на реальной машине).

## Что умеет

- **Установка сервера** одной командой: проверка ОС, установка sing-box, ключи Reality, systemd-служба.
- **Укрепление сервера:** вход по SSH-ключу вместо пароля, BBR, ufw. Каждый шаг откатывается при сбое.
- **Пользователи:** у каждого свой UUID и своя ссылка `vless://`.
- **Клиент:** импорт ссылки или подписки, авто-выбор сервера по задержке, переключение при отказе.
- **Системный VPN (TUN)** через helper-службу с правами root, с защитой DNS от утечек.
- **Обновления:** обновление sing-box на сервере и самого приложения с проверкой подписи.
- **Секреты** хранятся в системном keyring, без него в файлах с правами 600.

## Сборка

```
cargo build --release          # бинарник: target/release/eleutheria
cargo test
```

## Нет сервера?

На вкладке «Сервер» есть блок с партнёрскими хостингами. Можно арендовать VPS по ссылке из приложения, а затем ввести его адрес в форме. Если сервер уже есть, этот блок не нужен: установка VPN работает с любым VPS на Ubuntu или Debian.

Ссылки партнёрские: регистрация по ним может принести вознаграждение автору проекта. Покупать необязательно.

Список хостингов задаётся в `crates/eleutheria-app/src/partners.rs`. Приложение открывает только адреса из этого списка.

## Установка сервера

```
eleutheria provision <IP> [--user root] [--ssh-port 22] [--key PATH | --password-env VAR]
                  [--port 443] [--sni www.microsoft.com] [--name eleutheria] [--user-name default]
                  [--no-harden-ssh] [--no-bbr] [--no-firewall] [--host-key SHA256:...] [-y]

eleutheria user add|list|link|remove <IP> [<имя>]     # у каждого пользователя свой UUID и ссылка
eleutheria forget <IP>                                 # забыть ключ сервера после его переустановки
```

Пароль вводится один раз при первой установке (интерактивно или через `--password-env`). Дальше Eleutheria
использует свой SSH-ключ, который создаёт и хранит сама. `eleutheria secrets` показывает, где что лежит.
`ELEUTHERIA_SECRETS=keyring|file|auto` выбирает бэкенд хранения.

Повторный запуск идемпотентен: ключи, порт, SNI и пользователи берутся из `/etc/eleutheria/state.json`.
Ключ сервера запоминается (pinning): если он изменился, подключение блокируется до `eleutheria forget`.

Что делает `provision`:

1. Проверяет ОС (Ubuntu/Debian, systemd, root) и занятость порта.
2. Скачивает sing-box на твоей машине, сверяет SHA256 с закреплённым значением и заливает на сервер.
3. Генерирует ключи Reality, проверяет конфиг (`sing-box check`) и запускает systemd-службу.
   Если служба не поднялась, возвращается прежний конфиг.
4. Укрепляет сервер. Вход по ключу проверяется новым подключением, и только после этого отключается пароль.
   BBR включается, если ядро его поддерживает. ufw включается только если нет других публичных портов.
5. Печатает `vless://` для каждого пользователя и QR-код.

## Клиент

```
eleutheria import <vless://… | URL подписки> [--name N]   # сервер, поставленный через provision, добавляется сам
eleutheria servers | remove-server <имя>
eleutheria connect [--port 7890] [--server имя] [--ru-direct off|minimal|rulesets] [--test-url https://…]
eleutheria status       # режим, активный сервер, задержки
eleutheria disconnect
```

По умолчанию `connect` поднимает локальный прокси `127.0.0.1:7890` (HTTP и SOCKS5), его нужно указать
в браузере или системе. При нескольких серверах работает авто-выбор по задержке и переключение при отказе.

Подписки: base64-список или обычный список ссылок. Поддерживаются `vless://` с Reality или TLS поверх TCP.
Остальные схемы и транспорты (vmess, trojan, ws, grpc и др.) пропускаются с сообщением.

### Российские ресурсы (`--ru-direct`)

- `off`: всё идёт через VPN.
- `minimal` (по умолчанию): домены `.ru`, `.su`, `.рф` и приватные адреса идут напрямую. Ничего не скачивается.
- `rulesets`: то же плюс наборы правил `geoip-ru` и `geosite-category-ru`, которые покрывают российские сервисы
  на других доменах и российские IP-адреса. Наборы скачиваются через прокси при запуске.

## Системный VPN (TUN)

```
sudo eleutheria helper install     # один раз: ставит helper-службу и sing-box в /usr/lib/eleutheria
eleutheria connect --tun           # без sudo: весь трафик и DNS системы идут через VPN
eleutheria status | disconnect
sudo eleutheria helper uninstall
```

Windows (PowerShell или терминал **от имени администратора**, один запрос UAC):

```
eleutheria helper install          # служба EleutheriaHelper (LocalSystem), файлы в %ProgramFiles%\Eleutheria
eleutheria connect --tun           # обычный пользователь, без повышения прав
eleutheria status | disconnect
eleutheria helper uninstall
```

### Как устроена безопасность

- Helper работает от root и слушает unix-сокет, принадлежащий установившему пользователю (права 600).
  Дополнительно проверяется uid клиента через SO_PEERCRED. Чужие пользователи получают отказ.
- Windows: helper слушает named pipe `\\.\pipe\eleutheria-helper` с DACL. Полный доступ у SYSTEM и администраторов,
  чтение и запись у установившего пользователя, сетевые входы запрещены. Первый экземпляр создаётся с
  `FILE_FLAG_FIRST_PIPE_INSTANCE`. Каталог `%ProgramData%\Eleutheria` с конфигом sing-box закрыт ACL.
- Helper не принимает готовый конфиг sing-box, потому что через конфиг можно читать и писать файлы от root.
  Он получает только данные серверов, валидирует их (host, uuid, sni, ключи, fingerprint) и сам собирает конфиг.
  Бинарник sing-box берётся из каталога, куда пишет только root, SHA256 проверяется при установке.
- DNS: весь DNS системы перехватывается. Обычные имена получают fake-ip (198.18.0.0/15) и резолвятся на сервере
  через туннель, поэтому запросы не уходят к DNS локальной сети. Домены `.ru/.su/.рф` по умолчанию резолвятся
  системным DNS и идут напрямую. Это осознанная утечка ради доступа к российским сервисам, отключается `--ru-direct off`.
- IPv6 включается только если он есть в системе.
- Если sing-box упал аварийно, helper убирает оставленные им правила маршрутизации.

## Обновления

- **Сервер:** `eleutheria server status <хост>` показывает версии sing-box на сервере и в клиенте.
  `eleutheria server update <хост>` обновляет sing-box. Ключи и пользователи сохраняются, конфиг проверяется
  до перезапуска, при сбое возвращаются прежние конфиг и бинарник. То же есть на вкладке «Сервер» в GUI.
- **Приложение:** карточка «Обновления» на главной проверяет новые версии раз в сутки и по кнопке. Скачивание
  проверяется по подписи, затем установка и перезапуск. Пока в `tauri.conf.json` стоят заглушки `pubkey` и адресов,
  обновления выключены, и интерфейс об этом сообщает. На Linux обновление изнутри работает только в AppImage.

Выпуск релиза:

1. `cargo tauri signer generate -w ~/.tauri/eleutheria.key`. Приватный ключ и пароль идут в секреты репозитория
   `TAURI_SIGNING_PRIVATE_KEY` и `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. Офлайн-бэкап ключа обязателен: без него
   пользователям придётся переустанавливать приложение. Публичный ключ записывается в `plugins.updater.pubkey`.
2. Заменить адреса в `plugins.updater.endpoints` (GitHub Releases и зеркало).
3. `scripts/check-release.sh vX.Y.Z` (то же делает CI), затем тег `vX.Y.Z`. Workflow `release.yml` создаст черновик
   релиза с `latest.json`. Проверь его и нажми Publish.
4. Зеркало необязательно: секреты `MIRROR_*` описаны в шапке `release.yml`, `scripts/mirror-manifest.py` переписывает адреса.

## GUI

- `crates/eleutheria-app`: сервисный слой для интерфейса. Тесты: `cargo test -p eleutheria-app`.
- `crates/eleutheria-gui`: оболочка Tauri 2, фронтенд в `frontend/` (статический, без сборщика).
  Логика экрана в `frontend/model.js`, логика мастера сервера в `frontend/servermodel.js`.
- Сборка на Linux требует `libwebkit2gtk-4.1-dev libxdo-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev`.
- Запуск на Linux: `cargo run -p eleutheria-gui` (нужен дисплей; в контейнере используйте Xvfb и
  `WEBKIT_DISABLE_COMPOSITING_MODE=1 WEBKIT_DISABLE_DMABUF_RENDERER=1`).
- Установщики: `scripts/prepare-sidecars.sh`, затем в `crates/eleutheria-gui` выполнить
  `cargo tauri build --config tauri.bundle.conf.json` (нужен `cargo install tauri-cli --version "^2"`).
  Иконки: `python3 scripts/gen-icons.py`. CI: `.github/workflows/build.yml`.

## Тесты

- `cargo test`: юнит-тесты (состояние и миграция, конфиг, ссылки, pinning, генерация ключей, разбор портов).
- `node --test frontend/*.test.js` в `crates/eleutheria-gui`: тесты интерфейса (`npm install` перед первым запуском).
- `scripts/e2e-tun.sh`: клиент (helper, sing-box, CLI) и сервер в network namespace. Проверяет маршрут через TUN,
  выход трафика с сервера, fake-ip DNS, отсутствие утечек, права доступа к helper, отключение и повторное подключение.
  Создаёт netns, veth и адрес на lo.
- `scripts/e2e-helper-install.sh`: `helper install/uninstall` с заглушкой systemctl.
- `scripts/e2e-local.sh`: сквозной стенд на локальном sshd с реальным sing-box. Меняет систему (sshd_config,
  заглушки в /usr/local/bin, адрес на lo), запускать только в одноразовом контейнере или VM от root.
- `scripts/e2e-windows.ps1`: ручной сценарий для одноразовой Windows-ВМ.

## Ограничения

- Сервер: только root, только Ubuntu и Debian. sing-box работает от root.
- Протокол: пока только VLESS + Reality.
- Клиент на Linux проверен (прокси и TUN). macOS и Windows написаны, но не запускались и не собирались
  на реальной машине. Первый шаг на Windows: `cargo build --release`, затем `scripts/e2e-windows.ps1`.
- TUN проверен в netns на ядре без IPv6. Путь с включённым IPv6 не проверялся, на macOS и Windows TUN всегда создаётся с IPv6.
- Нет kill-switch: если helper или sing-box остановлены, трафик идёт напрямую. Так сделано намеренно,
  чтобы при аварии не оставить систему без сети.
- Unit helper-службы почти без sandbox-ограничений, под systemd не запускался. Жёсткие `CapabilityBoundingSet`
  не включены, потому что sing-box при auto_route требует нескольких capability.
- Fake-ip адреса не сохраняются между перезапусками туннеля.
- `--ru-direct rulesets` не проверен в живой сети. Наборы скачиваются с GitHub, а в России он может быть недоступен.
  По умолчанию включён `minimal`.
- `--test-url` обязан быть https://, потому что Clash API sing-box подменяет http:// на gstatic.
- Перезапуск службы при добавлении или удалении пользователя кратко рвёт активные соединения.
- Правила хостингов могут меняться. На момент выпуска VPN разрешён у всех партнёров из списка (проверено авторами).
- Реальные `systemd`, `ufw`, `sysctl` и cloud-init проверены только заглушками стенда. Перед публикацией
  проверь на тестовом сервере.
- Приватный SSH-ключ хранится файлом с правами 600 без шифрования, если не используется keyring.
- Установщики не подписаны сертификатом Windows или Apple, пока не заданы соответствующие секреты CI.
