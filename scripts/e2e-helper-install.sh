#!/bin/bash
# Проверка helper install/uninstall (root, одноразовая среда): пишет в /usr/lib/eleutheria и /etc/eleutheria,
# systemctl подменён заглушкой, которая только логирует вызовы.
set -u
D=$(cd "$(dirname "$0")" && pwd); ROOT=$(dirname "$D")
PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
STUB=/tmp/el-stub; BIN=/tmp/elbin; mkdir -p $STUB $BIN
printf '#!/bin/sh\necho "systemctl $*" >> /tmp/systemctl.log\nexit 0\n' > $STUB/systemctl; chmod +x $STUB/systemctl
cp $ROOT/target/debug/eleutheria $ROOT/target/debug/eleutheria-helper $BIN/ 2>/dev/null; chmod 755 $BIN/*
export ELEUTHERIA_CONFIG_DIR=/tmp/elcfg-inst
rm -f /tmp/systemctl.log; rm -rf /usr/lib/eleutheria /etc/eleutheria/helper.json /etc/systemd/system/eleutheria-helper.service /run/eleutheria

echo "== install"
check "без root установка отказывается" 'ip netns identify >/dev/null 2>&1; setpriv --reuid=65534 --regid=65534 --clear-groups env PATH=$STUB:$PATH $BIN/eleutheria helper install 2>&1 | grep -q "нужны права root"'
OUT=$(SUDO_UID=1234 PATH=$STUB:$PATH $BIN/eleutheria helper install 2>&1); echo "$OUT" | sed 's/^/  | /'
check "sing-box установлен в /usr/lib/eleutheria (root, 755)" '[ "$(stat -c "%U %a" /usr/lib/eleutheria/sing-box)" = "root 755" ]'
check "helper установлен (root, 755)" '[ "$(stat -c "%U %a" /usr/lib/eleutheria/eleutheria-helper)" = "root 755" ]'
check "каталог установки не доступен на запись другим" '[ "$(stat -c %a /usr/lib/eleutheria)" = "755" ]'
check "установленный sing-box — релиз 1.14.3" '/usr/lib/eleutheria/sing-box version | head -1 | grep -q 1.14.3'
check "helper.json: allowed_uid из SUDO_UID" 'python3 -c "import json;c=json.load(open(\"/etc/eleutheria/helper.json\"));assert c[\"allowed_uid\"]==1234 and c[\"singbox_path\"]==\"/usr/lib/eleutheria/sing-box\"" '
check "unit-файл указывает на установленный helper" 'grep -q "ExecStart=/usr/lib/eleutheria/eleutheria-helper run" /etc/systemd/system/eleutheria-helper.service && grep -q NoNewPrivileges=yes /etc/systemd/system/eleutheria-helper.service'
check "systemctl: daemon-reload, enable, restart" 'grep -q "daemon-reload" /tmp/systemctl.log && grep -q "enable eleutheria-helper" /tmp/systemctl.log && grep -q "restart eleutheria-helper" /tmp/systemctl.log'

echo; echo "== установленный helper реально стартует с этим конфигом"
mkdir -p /run/eleutheria
setsid /usr/lib/eleutheria/eleutheria-helper run >/tmp/helper-inst.log 2>&1 </dev/null &
sleep 1.5
check "сокет создан, владелец uid 1234, права 600" '[ "$(stat -c "%u %a" /run/eleutheria/helper.sock)" = "1234 600" ]'
check "root видит helper (ping)" '$BIN/eleutheria helper status 2>&1 | grep -q "helper работает"'

echo; echo "== uninstall"
pkill -f '[e]leutheria-helper run'; sleep 0.5
OUT=$(PATH=$STUB:$PATH $BIN/eleutheria helper uninstall 2>&1); echo "$OUT" | sed 's/^/  | /'
check "файлы удалены" '[ ! -e /usr/lib/eleutheria/sing-box ] && [ ! -e /usr/lib/eleutheria/eleutheria-helper ] && [ ! -e /etc/eleutheria/helper.json ] && [ ! -e /etc/systemd/system/eleutheria-helper.service ]'
check "systemctl disable --now вызван" 'grep -q "disable --now eleutheria-helper" /tmp/systemctl.log'
check "повторный uninstall безопасен" 'PATH=$STUB:$PATH $BIN/eleutheria helper uninstall >/dev/null 2>&1'
echo; echo "== итог: PASS=$PASS FAIL=$FAIL"
[ $FAIL -eq 0 ]
