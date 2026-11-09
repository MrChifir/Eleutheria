#!/bin/bash
# Подставляет настоящий публичный ключ и адреса обновлений в tauri.conf.json вместо заглушек.
# Использование:
#   scripts/set-updater.sh --pubkey-file KEY.pub --github OWNER/REPO [--mirror https://updates.site/eleutheria]
#   scripts/set-updater.sh --pubkey 'dW50cnVzdGVk…' --github OWNER/REPO
# Публичный ключ получается так: `cargo tauri signer generate -w ~/.tauri/eleutheria.key`
# (создаст eleutheria.key и eleutheria.key.pub; приватный ключ и пароль в репозиторий не кладём).
# В конце запускается scripts/check-release.sh: если что-то осталось заглушкой, скрипт скажет, что именно.
set -eu
cd "$(dirname "$0")/.."
CONF=${TAURI_CONF:-crates/eleutheria-gui/tauri.conf.json}
python3 - "$CONF" "$@" <<'PY'
import argparse, base64, json, re, sys

conf_path = sys.argv[1]
ap = argparse.ArgumentParser(prog="set-updater.sh")
ap.add_argument("--pubkey", help="публичный ключ minisign (содержимое .pub целиком, base64)")
ap.add_argument("--pubkey-file", help="файл .pub, созданный `tauri signer generate`")
ap.add_argument("--github", help="OWNER/REPO для адреса GitHub Releases")
ap.add_argument("--mirror", help="базовый https-адрес зеркала (без latest.json)")
a = ap.parse_args(sys.argv[2:])

def die(msg):
    print(f"Ошибка: {msg}", file=sys.stderr)
    sys.exit(2)

key = None
if a.pubkey_file:
    key = open(a.pubkey_file, encoding="utf-8").read().strip()
elif a.pubkey:
    key = a.pubkey.strip()
if key is not None:
    # Tauri ждёт base64 от всего текста minisign-ключа («untrusted comment: …\n<key>»).
    # Если дали сырой текст .pub (две строки), кодируем сами; если уже base64, проверяем его.
    if key.startswith("untrusted comment:"):
        key = base64.b64encode((key + "\n").encode()).decode()
    try:
        raw = base64.b64decode(key, validate=True).decode("utf-8")
    except Exception:
        die("публичный ключ не похож на base64 от minisign-ключа")
    if not raw.startswith("untrusted comment:"):
        die("после раскодирования нет строки «untrusted comment:»: это не публичный ключ minisign")
    if "secret key" in raw.split("\n", 1)[0].lower():
        die("это ПРИВАТНЫЙ ключ. Нужен файл .pub. Приватный ключ нельзя вставлять в конфиг")

endpoints = None
if a.github or a.mirror:
    endpoints = []
    if a.github:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", a.github):
            die("--github ожидает OWNER/REPO")
        endpoints.append(f"https://github.com/{a.github}/releases/latest/download/latest.json")
    if a.mirror:
        if not a.mirror.startswith("https://"):
            die("--mirror должен начинаться с https://")
        endpoints.append(a.mirror.rstrip("/") + "/latest.json")

if key is None and endpoints is None:
    die("нечего менять: укажи --pubkey/--pubkey-file и/или --github/--mirror")

conf = json.load(open(conf_path, encoding="utf-8"))
up = conf.setdefault("plugins", {}).setdefault("updater", {})
if key is not None:
    up["pubkey"] = key
if endpoints is not None:
    up["endpoints"] = endpoints
with open(conf_path, "w", encoding="utf-8") as f:
    json.dump(conf, f, ensure_ascii=False, indent=2)
    f.write("\n")
print(f"Обновлён {conf_path}")
PY
echo "Проверка релизных условий:"
scripts/check-release.sh || true
