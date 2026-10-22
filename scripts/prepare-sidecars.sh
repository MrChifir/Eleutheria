#!/usr/bin/env bash
# Готовит CLI и helper как sidecar-бинарники для установщика: crates/eleutheria-gui/binaries/<имя>-<triple>[.exe].
# Tauri кладёт их рядом с приложением, а кнопка «Установить helper» ищет `eleutheria` и `eleutheria-helper`
# именно там. Запуск из корня репозитория: scripts/prepare-sidecars.sh  (PROFILE=debug для быстрой проверки).
set -euo pipefail
cd "$(dirname "$0")/.."
PROFILE=${PROFILE:-release}
TRIPLE=$(rustc -vV | sed -n 's/^host: //p')
[ -n "$TRIPLE" ] || { echo "не удалось определить target triple" >&2; exit 1; }
EXT=""; case "$TRIPLE" in *windows*) EXT=".exe";; esac
FLAG="--release"; DIR=release
if [ "$PROFILE" = "debug" ]; then FLAG=""; DIR=debug; fi
cargo build $FLAG -p eleutheria-cli -p eleutheria-helper
OUT=crates/eleutheria-gui/binaries
mkdir -p "$OUT"
for name in eleutheria eleutheria-helper; do
  src="target/$DIR/$name$EXT"
  [ -f "$src" ] || { echo "нет $src" >&2; exit 1; }
  cp "$src" "$OUT/$name-$TRIPLE$EXT"
  echo "sidecar: $OUT/$name-$TRIPLE$EXT"
done
