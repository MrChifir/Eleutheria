#!/bin/bash
# Проверка перед релизом: не выпускать сборку с заглушками updater и с несовпадающими версиями.
# Использование: scripts/check-release.sh [vX.Y.Z]   (тег; без аргумента версии тега не сверяются)
set -u
cd "$(dirname "$0")/.."
CONF=${TAURI_CONF:-crates/eleutheria-gui/tauri.conf.json}
CARGO=${WORKSPACE_TOML:-Cargo.toml}
TAG=${1:-}
python3 - "$CONF" "$CARGO" "$TAG" <<'PY'
import json, re, sys
conf_path, cargo_path, tag = sys.argv[1:4]
errs = []
conf = json.load(open(conf_path))
up = conf.get("plugins", {}).get("updater", {})
key = (up.get("pubkey") or "").strip()
if not key or key == "REPLACE_WITH_UPDATER_PUBLIC_KEY":
    errs.append("plugins.updater.pubkey: не задан публичный ключ подписи (без него приложения не смогут обновляться)")
eps = up.get("endpoints") or []
if not eps:
    errs.append("plugins.updater.endpoints: пусто")
for e in eps:
    if not e.startswith("https://"):
        errs.append(f"endpoint не https: {e}")
    if "OWNER" in e or "example.org" in e or "example.com" in e:
        errs.append(f"endpoint остался заглушкой: {e}")
if up.get("requireSignedVersion") is not True:
    errs.append("plugins.updater.requireSignedVersion должен быть true (защита от подмены версии на зеркале)")
m = re.search(r'^\[workspace\.package\].*?^version\s*=\s*"([^"]+)"', open(cargo_path).read(), re.S | re.M)
ws = m.group(1) if m else None
if ws is None:
    errs.append("не нашёл version в [workspace.package]")
if conf.get("version") != ws:
    errs.append(f"версия в tauri.conf.json ({conf.get('version')}) не равна версии workspace ({ws})")
if tag and tag.lstrip("v") != ws:
    errs.append(f"тег {tag} не соответствует версии {ws}")
if errs:
    print("Релиз заблокирован:")
    for e in errs: print("  -", e)
    sys.exit(1)
print(f"OK: версия {ws}, ключ и {len(eps)} адреса(ов) обновлений настроены")
PY
