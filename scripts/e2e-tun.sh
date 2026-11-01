#!/bin/bash
# e2e режима TUN (ТОЛЬКО для одноразовой среды, root): клиент (helper + sing-box + CLI) в netns `elclient`,
# сервер Reality в основном netns, между ними veth. Меняет систему: netns, veth, адрес на lo, /etc/netns/elclient.
set -u
D=$(cd "$(dirname "$0")" && pwd); ROOT=$(dirname "$D")
SB=/usr/local/bin/sing-box; NS=elclient; BIN=/tmp/elbin
PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
inns() { ip netns exec $NS "$@"; }
EL() { inns env ELEUTHERIA_CONFIG_DIR=/tmp/elcfg-tun ELEUTHERIA_HELPER_SOCKET=/tmp/elhelper.sock $BIN/eleutheria "$@" 2>&1; }
cleanup() {
  # setsid форкается, поэтому $! не pid самого процесса: убиваем по точному имени/конфигу ([x]-трюк: не задеть себя)
  pkill -f '[e]leutheria-helper run' 2>/dev/null; pkill -f '[s]ing-box run -c /tmp/el-srv.json' 2>/dev/null
  pkill -f '[s]_server -accept 127.0.0.1:443' 2>/dev/null; pkill -f '[h]ttp.server 8000 --bind 203.0.113.50' 2>/dev/null
  pkill -f '[d]ns_target.py' 2>/dev/null
  sleep 0.5; ip netns del $NS 2>/dev/null; ip link del el-h 2>/dev/null; rm -rf /etc/netns/$NS
}
trap '[ -n "${E2E_KEEP:-}" ] || cleanup' EXIT

echo "== setup"
cleanup 2>/dev/null; rm -rf /tmp/elcfg-tun /tmp/elrt /tmp/elhelper.sock /tmp/target.log /tmp/dns-seen.log /tmp/helper.log
mkdir -p $BIN && cp $ROOT/target/debug/eleutheria $ROOT/target/debug/eleutheria-helper $BIN/ && chmod 755 $BIN/*
ip netns add $NS
ip link add el-h type veth peer name el-c; ip link set el-c netns $NS
ip addr add 10.200.0.1/24 dev el-h; ip link set el-h up
inns ip addr add 10.200.0.2/24 dev el-c; inns ip link set el-c up; inns ip link set lo up
inns ip route add default via 10.200.0.1
mkdir -p /etc/netns/$NS; echo "nameserver 10.200.0.1" > /etc/netns/$NS/resolv.conf   # «роутер» как DNS: соседняя подсеть
ip addr add 203.0.113.50/32 dev lo 2>/dev/null
grep -q localhost /etc/hosts || echo "127.0.0.1 localhost" >> /etc/hosts
[ -f /tmp/c.pem ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout /tmp/k.pem -out /tmp/c.pem -subj /CN=localhost -days 1 -addext subjectAltName=DNS:localhost 2>/dev/null
# маскировочный сайт Reality, цель, DNS-«роутер»
setsid openssl s_server -accept 127.0.0.1:443 -cert /tmp/c.pem -key /tmp/k.pem -tls1_3 -alpn h2 -www >/dev/null 2>&1 </dev/null & echo $! > /tmp/el-dest.pid
setsid python3 -m http.server 8000 --bind 203.0.113.50 --directory /tmp >/tmp/target.log 2>&1 </dev/null & echo $! > /tmp/el-target.pid
setsid python3 $D/dns_target.py 10.200.0.1 /tmp/dns-seen.log >/dev/null 2>&1 </dev/null & echo $! > /tmp/el-dns.pid
# сервер Reality на 10.200.0.1:4443
KP=$($SB generate reality-keypair); PRIV=$(echo "$KP" | awk '/PrivateKey/{print $2}'); PUB=$(echo "$KP" | awk '/PublicKey/{print $2}')
UUID=$($SB generate uuid); SID=$($SB generate rand --hex 8)
python3 - "$PRIV" "$UUID" "$SID" <<'PYIN'
import json,sys
priv,uuid,sid=sys.argv[1:4]
json.dump({"log":{"level":"warn"},"inbounds":[{"type":"vless","tag":"in","listen":"10.200.0.1","listen_port":4443,
 "users":[{"uuid":uuid,"flow":"xtls-rprx-vision"}],
 "tls":{"enabled":True,"server_name":"localhost","reality":{"enabled":True,"handshake":{"server":"localhost","server_port":443},"private_key":priv,"short_id":[sid]}}}],
 "outbounds":[{"type":"direct","tag":"direct"}]},open('/tmp/el-srv.json','w'))
PYIN
setsid $SB run -c /tmp/el-srv.json >/tmp/el-srv.log 2>&1 </dev/null & echo $! > /tmp/el-srv.pid
# helper в netns клиента, доступ только uid 65534
echo '{"allowed_uid":65534,"singbox_path":"/usr/local/bin/sing-box","runtime_dir":"/tmp/elrt","socket_path":"/tmp/elhelper.sock"}' > /tmp/elhelper.json
inns env ELEUTHERIA_HELPER_CONFIG=/tmp/elhelper.json setsid $BIN/eleutheria-helper run >/tmp/helper.log 2>&1 </dev/null & echo $! > /tmp/el-helper.pid
sleep 2
LINK="vless://$UUID@10.200.0.1:4443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=localhost&fp=chrome&pbk=$PUB&sid=$SID&type=tcp#tun-test"
EL import "$LINK" >/dev/null
src_of_last() { tail -1 /tmp/target.log | awk '{print $1}'; }
tgt() { inns curl -s -m 10 -o /dev/null -w "%{http_code}" http://203.0.113.50:8000/; }

echo; echo "== T0: до туннеля трафик идёт напрямую (контроль различимости)"
check "цель доступна напрямую" '[ "$(tgt)" = "200" ]'
check "цель видит клиента как 10.200.0.2" '[ "$(src_of_last)" = "10.200.0.2" ]'

echo; echo "== T1: доступ к helper"
check "helper запущен, сокет принадлежит 65534 с правами 600" '[ "$(stat -c "%u %a" /tmp/elhelper.sock)" = "65534 600" ]'
NOBODY="ip netns exec $NS setpriv --reuid=65534 --regid=65534 --clear-groups env ELEUTHERIA_HELPER_SOCKET=/tmp/elhelper.sock ELEUTHERIA_CONFIG_DIR=/tmp/elcfg-nobody $BIN/eleutheria"
OTHER="ip netns exec $NS setpriv --reuid=65533 --regid=65533 --clear-groups env ELEUTHERIA_HELPER_SOCKET=/tmp/elhelper.sock ELEUTHERIA_CONFIG_DIR=/tmp/elcfg-other $BIN/eleutheria"
check "владелец (65534) подключается" '$NOBODY helper status 2>&1 | grep -q "helper работает"'
check "root подключается" 'EL helper status | grep -q "helper работает"'
check "чужой пользователь (65533) отрезан правами сокета" '! $OTHER helper status 2>&1 | grep -q "helper работает"'
chmod 666 /tmp/elhelper.sock
echo "  (ответ чужому uid при открытом сокете: $($OTHER helper status 2>&1 | head -2 | tr "\n" " "))"
check "даже при открытом сокете чужой uid получает отказ по SO_PEERCRED" '$OTHER helper status 2>&1 | grep -q "доступ запрещён"'
chmod 600 /tmp/elhelper.sock

echo; echo "== T2: подъём TUN"
OUT=$(EL connect --tun --test-url https://127.0.0.1:1/); echo "$OUT" | head -3
check "connect --tun: туннель поднят" 'echo "$OUT" | grep -q "Туннель поднят"'
sleep 1
check "в netns появился TUN-интерфейс" 'inns ip -o link | grep -qiE "tun|sing"'
check "маршрут до цели идёт через TUN, не через veth" '! inns ip route get 203.0.113.50 | grep -q "el-c"'
check "статус через helper: pid и режим" 'EL status | grep -q "системный VPN (TUN)"'

echo; echo "== T3: трафик идёт через сервер"
check "цель доступна" '[ "$(tgt)" = "200" ]'
check "цель видит клиента НЕ как 10.200.0.2 (трафик вышел с сервера)" '[ "$(src_of_last)" != "10.200.0.2" ]'

echo; echo "== T4: DNS (fake-ip, перехват, утечки)"
: > /tmp/dns-seen.log
FAKE=$(inns python3 -c "import socket;print(socket.getaddrinfo('somename.test',80,socket.AF_INET)[0][4][0])" 2>&1)
echo "  somename.test -> $FAKE"
check "обычное имя получает fake-ip из 198.18.0.0/15" 'echo "$FAKE" | grep -qE "^198\.1[89]\."'
check "запрос НЕ дошёл до DNS соседней подсети (нет утечки)" '! grep -q somename.test /tmp/dns-seen.log'
RU=$(inns python3 -c "import socket;print(socket.getaddrinfo('foo.ru',80,socket.AF_INET)[0][4][0])" 2>&1)
echo "  foo.ru -> $RU"
check "RU-домен резолвится локальным (системным) DNS, как задумано" '[ "$RU" = "203.0.113.99" ] && grep -q "foo.ru" /tmp/dns-seen.log'

echo; echo "== T5: отключение"
OUT=$(EL disconnect); echo "  $OUT"
check "disconnect сообщает об отключении" 'echo "$OUT" | grep -q "Отключено"'
sleep 1
check "TUN-интерфейс исчез" '! inns ip -o link | grep -qiE "tun|sing"'
check "правила маршрутизации убраны (нет ip rule от sing-box)" '[ "$(inns ip rule | wc -l)" = "3" ]'
check "трафик снова идёт напрямую (10.200.0.2)" '[ "$(tgt)" = "200" ] && [ "$(src_of_last)" = "10.200.0.2" ]'
check "status: не подключено" 'EL status | grep -q "Не подключено"'

echo; echo "== T6: аварийное завершение sing-box (kill -9) не оставляет сеть сломанной"
EL connect --tun --test-url https://127.0.0.1:1/ >/dev/null; sleep 1
SBPID=$(inns pgrep -f "sing-box run -c /tmp/elrt" | head -1)
kill -9 $SBPID; sleep 2
check "helper заметил падение (status: не подключено)" 'EL status | grep -q "Не подключено"'
echo "  ip rule после kill -9:"; inns ip rule | sed 's/^/    /'
check "после падения прямой трафик работает" '[ "$(tgt)" = "200" ]'
check "после падения нет «висящих» правил sing-box" '[ "$(inns ip rule | wc -l)" = "3" ]'

echo; echo "== T7: перезапуск и чистое отключение"
OUT=$(EL connect --tun --test-url https://127.0.0.1:1/); check "повторный connect --tun после падения" 'echo "$OUT" | grep -q "Туннель поднят"'
sleep 1; check "трафик снова через сервер" '[ "$(tgt)" = "200" ] && [ "$(src_of_last)" != "10.200.0.2" ]'
EL disconnect >/dev/null; sleep 1
check "после disconnect сеть чистая" '[ "$(inns ip rule | wc -l)" = "3" ] && [ "$(tgt)" = "200" ] && [ "$(src_of_last)" = "10.200.0.2" ]'

echo; echo "== итог: PASS=$PASS FAIL=$FAIL"
[ $FAIL -eq 0 ]
