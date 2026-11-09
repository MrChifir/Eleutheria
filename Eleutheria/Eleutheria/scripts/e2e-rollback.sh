#!/bin/bash
# Сквозная проверка отката приложения на Linux: настоящий процесс-сторож (`eleutheria update-watchdog`),
# поддельный AppImage. Сценарии: (A) новая версия не стартовала, (B) стартовала и подтвердила,
# (C) подтверждение пришло, но сторож не трогает файл после дедлайна.
set -u
cd "$(dirname "$0")/.."
[ -d /usr/lib/rust-1.91/bin ] && export PATH="/usr/lib/rust-1.91/bin:$PATH"
cargo build -q -p eleutheria-cli || exit 1
cargo build -q -p eleutheria-app --example e2e_rollback || exit 1
CLI=$PWD/target/debug/eleutheria
H=$PWD/target/debug/examples/e2e_rollback
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
pass=0; fail=0
ok() { echo "  ok   $1"; pass=$((pass+1)); }
bad() { echo "  FAIL $1"; fail=$((fail+1)); }
mk() { printf '#!/bin/sh\necho "%s" >> "%s/runs.log"\n' "$1" "$W" > "$2"; chmod +x "$2"; }

echo "A: новая версия не стартовала -> откат и запуск прежней"
CFG=$W/a; mkdir -p $CFG; AI=$W/a.AppImage; : > $W/runs.log
mk v1 $AI
ELEUTHERIA_CONFIG_DIR=$CFG $H arm $CFG $AI $CLI 0.1.0 0.2.0 3 || bad "arm"
mk v2-broken $AI                      # «установщик» заменил файл
sleep 1; [ -f $CFG/pending-update.json ] && ok "маркер есть до дедлайна" || bad "маркер исчез рано"
grep -q v1 $AI && bad "до дедлайна откат не должен был случиться"
sleep 5
grep -q 'v1' $AI && ok "файл возвращён (v1)" || bad "файл не возвращён"
sleep 1; grep -q '^v1$' $W/runs.log && ok "прежняя версия запущена" || bad "прежняя версия не запущена"
[ ! -f $CFG/pending-update.json ] && ok "маркер удалён" || bad "маркер остался"
R=$(ELEUTHERIA_CONFIG_DIR=$CFG $H confirm $CFG 0.1.0)
echo "$R" | grep -q '"rolledBackFrom":"0.2.0"' && ok "интерфейс узнаёт об откате: $R" || bad "нет сообщения об откате: $R"

echo "B: новая версия подтвердила запуск -> сторож ничего не трогает"
CFG=$W/b; mkdir -p $CFG; AI=$W/b.AppImage; : > $W/runs.log
mk v1 $AI
$H arm $CFG $AI $CLI 0.1.0 0.2.0 3 || bad "arm"
mk v2-good $AI
R=$($H confirm $CFG 0.2.0)
echo "$R" | grep -q '"updatedTo":"0.2.0"' && ok "обновление подтверждено" || bad "нет подтверждения: $R"
sleep 6
grep -q v2-good $AI && ok "новая версия на месте после дедлайна" || bad "новая версия затёрта"
[ ! -s $W/runs.log ] && ok "прежняя версия не запускалась" || bad "лишний запуск"
pgrep -f "$CFG/rollback/watchdog" >/dev/null && bad "сторож не завершился" || ok "сторож завершился"

echo "итого: $pass ok, $fail fail"; [ $fail -eq 0 ]
