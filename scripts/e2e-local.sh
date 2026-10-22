#!/bin/bash
# Локальный e2e-стенд для eleutheria (ТОЛЬКО для разработки, меняет систему: запускать в одноразовом контейнере/VM как root).
# Поднимает sshd на :2222, подменяет systemctl и ufw заглушками (в контейнере нет systemd/iptables),
# поднимает локальный TLS 1.3 «маскировочный сайт» для Reality и HTTP-цель, затем гоняет сценарии.
set -u
ELBIN=${ELBIN:-/home/claude/eleutheria/target/debug/eleutheria}
export ELEUTHERIA_CONFIG_DIR=/tmp/elcfg ELEUTHERIA_PW=testpass123
PORT=4443; PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
elq() { "$ELBIN" "$@" 2>&1; }          # eleutheria, вывод целиком
H=127.0.0.1; C="--ssh-port 2222"

echo "== setup"
rm -rf /tmp/elcfg /etc/eleutheria /etc/sing-box /etc/systemd/system/eleutheria-sing-box.service /etc/ssh/sshd_config.d/00-*.conf /tmp/ufw.* /tmp/fail-restart
mkdir -p /run/sshd /run/systemd/system /etc/ssh/sshd_config.d
echo 'root:testpass123' | chpasswd
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/; s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
if ! grep -q '^Include /etc/ssh/sshd_config.d' /etc/ssh/sshd_config; then
  { echo 'Include /etc/ssh/sshd_config.d/*.conf'; cat /etc/ssh/sshd_config; } > /tmp/sc && mv /tmp/sc /etc/ssh/sshd_config
fi
[ -f /tmp/sshd.pid ] && kill "$(cat /tmp/sshd.pid)" 2>/dev/null; sleep 0.5
/usr/sbin/sshd -p 2222 -o PidFile=/tmp/sshd.pid
cat > /usr/local/bin/systemctl <<'EOF'
#!/bin/sh
PIDF=/tmp/eleutheria-fake.pid
case "$1" in
  daemon-reload|enable|disable) exit 0;;
  reload) kill -HUP "$(cat /tmp/sshd.pid)"; exit 0;;
  restart)
    [ -f $PIDF ] && kill "$(cat $PIDF)" 2>/dev/null; sleep 0.3; rm -f $PIDF
    if [ -f /tmp/fail-restart ]; then rm -f /tmp/fail-restart; exit 0; fi
    nohup /usr/local/bin/sing-box run -c /etc/sing-box/config.json >/tmp/eleutheria-fake.log 2>&1 &
    echo $! > $PIDF; exit 0;;
  is-active) [ -f $PIDF ] && kill -0 "$(cat $PIDF)" 2>/dev/null; exit $?;;
esac
exit 0
EOF
cat > /usr/local/bin/ufw <<'EOF'
#!/bin/sh
echo "ufw $*" >> /tmp/ufw.log
case "$*" in
  "status") [ -f /tmp/ufw.enabled ] && echo "Status: active" || echo "Status: inactive";;
  "--force enable") touch /tmp/ufw.enabled;;
  "--force disable") rm -f /tmp/ufw.enabled;;
esac
exit 0
EOF
# ss: в песочнице есть чужие слушающие порты (2024/2025); для сценария включения ufw их скрывает флаг /tmp/ss-hide
cat > /usr/local/bin/ss <<'EOF'
#!/bin/sh
if [ -f /tmp/ss-hide ]; then /usr/bin/ss "$@" | grep -vE ':(2024|2025) '; else /usr/bin/ss "$@"; fi
EOF
# sysctl: в песочнице /proc/sys недоступен для записи, имитируем переключение congestion control
cat > /usr/local/bin/sysctl <<'EOF'
#!/bin/sh
CC=/tmp/cc; [ -f $CC ] || echo cubic > $CC
case "$*" in
  "-n net.ipv4.tcp_congestion_control") cat $CC;;
  "-n net.ipv4.tcp_available_congestion_control") echo "reno cubic bbr";;
  "-p /etc/sysctl.d/99-eleutheria-bbr.conf") echo bbr > $CC; echo "net.ipv4.tcp_congestion_control = bbr";;
esac
exit 0
EOF
chmod +x /usr/local/bin/systemctl /usr/local/bin/ufw /usr/local/bin/ss /usr/local/bin/sysctl
rm -f /tmp/cc /tmp/ss-hide /etc/sysctl.d/99-eleutheria-bbr.conf
[ -f /tmp/eleutheria-fake.pid ] && kill "$(cat /tmp/eleutheria-fake.pid)" 2>/dev/null; rm -f /tmp/eleutheria-fake.pid
# локальный «маскировочный сайт» и HTTP-цель (только loopback, чтобы не считаться публичными портами)
for f in /tmp/dest.pid /tmp/http.pid; do [ -f $f ] && kill "$(cat $f)" 2>/dev/null; done
pkill -f '[h]ttp.server 8000 --bind' 2>/dev/null; pkill -f '[s]_server -accept' 2>/dev/null; pkill -f '[h]ttps_target.py' 2>/dev/null; sleep 0.5
grep -q localhost /etc/hosts || echo "127.0.0.1 localhost" >> /etc/hosts
[ -f /tmp/c.pem ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout /tmp/k.pem -out /tmp/c.pem -subj /CN=localhost -days 1 -addext subjectAltName=DNS:localhost 2>/dev/null
setsid openssl s_server -accept 127.0.0.1:443 -cert /tmp/c.pem -key /tmp/k.pem -tls1_3 -alpn h2 -www >/tmp/dest.log 2>&1 < /dev/null & echo $! > /tmp/dest.pid
setsid python3 -m http.server 8000 --bind 127.0.0.1 >/tmp/http.log 2>&1 < /dev/null & echo $! > /tmp/http.pid
# цель для клиентских тестов: «публичный» с точки зрения маршрутизатора адрес (loopback-алиас), иначе правило
# «приватные адреса напрямую» уведёт трафик мимо VPN и тест ничего не докажет
TARGET=203.0.113.50
ip addr add $TARGET/32 dev lo 2>/dev/null || true
sleep 1

tunnel() {  # tunnel <user> -> печатает HTTP-код через VPN этим пользователем
  python3 - "$1" <<'EOF'
import json,sys
s=json.load(open('/etc/eleutheria/state.json')); u=[x for x in s['users'] if x['name']==sys.argv[1]]
uuid=u[0]['uuid'] if u else '00000000-0000-0000-0000-000000000000'
json.dump({"log":{"level":"fatal"},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":10808}],
 "outbounds":[{"type":"vless","tag":"p","server":"127.0.0.1","server_port":s["port"],"uuid":uuid,"flow":"xtls-rprx-vision",
 "tls":{"enabled":True,"server_name":s["sni"],"utls":{"enabled":True,"fingerprint":"chrome"},
 "reality":{"enabled":True,"public_key":s["public_key"],"short_id":s["short_id"]}}}]},open('/tmp/cl.json','w'))
EOF
  setsid /usr/local/bin/sing-box run -c /tmp/cl.json >/tmp/cl.log 2>&1 < /dev/null & local cp=$!
  sleep 1.5
  timeout 12 curl -s -m 8 -x socks5h://127.0.0.1:10808 -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/ 2>/dev/null
  kill $cp 2>/dev/null; wait $cp 2>/dev/null
}

echo; echo "== S1: конфликт sshd (чужой конфиг включает пароль) -> откат, доступ не потерян"
printf 'PasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/00-aaa-conflict.conf; kill -HUP "$(cat /tmp/sshd.pid)"; sleep 0.5
OUT=$(elq provision $H $C --password-env ELEUTHERIA_PW --port $PORT --sni localhost --name t -y); echo "$OUT" | tail -12
check "ufw не включён, пока на сервере есть другие публичные порты" 'echo "$OUT" | grep -q "ufw не включал" && [ ! -f /tmp/ufw.enabled ]'
check "VPN установлен несмотря на сбой hardening" 'echo "$OUT" | grep -q "^vless://"'
check "сбой SSH-шага сообщён как предупреждение" 'echo "$OUT" | grep -q "⚠ SSH-ключ"'
check "drop-in 00-eleutheria.conf откатан" '[ ! -f /etc/ssh/sshd_config.d/00-eleutheria.conf ]'
check "вход по паролю по-прежнему работает" 'elq user list $H $C --password-env ELEUTHERIA_PW | grep -q default'
check "трафик идёт через VPN (default)" '[ "$(tunnel default)" = "200" ]'

echo; echo "== S2: конфликт убран -> ключ вместо пароля"
rm -f /etc/ssh/sshd_config.d/00-aaa-conflict.conf; kill -HUP "$(cat /tmp/sshd.pid)"; sleep 0.5
touch /tmp/ss-hide
OUT=$(elq provision $H $C --password-env ELEUTHERIA_PW -y); echo "$OUT" | sed -n '/Укрепление/,/Готово/p'
check "ключ сохранён в хранилище секретов (файловый бэкенд): файл 600, каталог 700, старого keys/ нет" '[ "$(stat -c %a /tmp/elcfg/secrets/7373682d6b65792f3132372e302e302e31)" = "600" ] && [ "$(stat -c %a /tmp/elcfg/secrets)" = "700" ] && [ ! -e /tmp/elcfg/keys ]'
check "sshd: PasswordAuthentication no" '/usr/sbin/sshd -T 2>/dev/null | grep -qi "^passwordauthentication no"'
check "вход по паролю теперь отклоняется" 'elq user list $H $C --password-env ELEUTHERIA_PW | grep -q "аутентификация отклонена"'
check "вход по сохранённому ключу работает без флагов" 'elq user list $H $C | grep -q default'
check "повторный запуск сохранил порт и ключи (идемпотентность)" 'echo "$OUT" | grep -q "прежнее состояние"'
check "ufw включён с нужными правилами" 'grep -q "allow 2222/tcp" /tmp/ufw.log && grep -q "allow $PORT/tcp" /tmp/ufw.log && grep -q "force enable" /tmp/ufw.log'
check "BBR включён и записан в sysctl.d" '[ "$(cat /tmp/cc)" = "bbr" ] && grep -q bbr /etc/sysctl.d/99-eleutheria-bbr.conf'
check "ufw включён, SSH после этого доступен" 'echo "$OUT" | grep -q "✓ ufw включён"'

echo; echo "== S3: несколько пользователей"
OUT=$(elq user add $H $C alice); echo "$OUT" | grep -E '^\[|^vless' | cut -c1-70
check "alice добавлена" 'elq user list $H $C | grep -q alice'
check "alice ходит через VPN" '[ "$(tunnel alice)" = "200" ]'
check "default продолжает работать" '[ "$(tunnel default)" = "200" ]'
check "дубликат имени отклонён" 'elq user add $H $C alice | grep -q "уже существует"'
check "плохое имя отклонено" 'elq user add $H $C "a b" | grep -q "недопустимое имя"'
elq user remove $H $C alice >/dev/null
check "alice удалена и больше не проходит" '[ "$(tunnel alice)" != "200" ]'
check "default после удаления alice работает" '[ "$(tunnel default)" = "200" ]'
check "последнего пользователя удалить нельзя" 'elq user remove $H $C default | grep -q "последнего"'

echo; echo "== S4: сбой рестарта с новым конфигом -> восстановление прежнего"
touch /tmp/fail-restart
OUT=$(elq user add $H $C bob); echo "$OUT" | grep -iE 'прежн|восстанов' | head -2
check "ошибка сообщена, прежний конфиг восстановлен" 'echo "$OUT" | grep -q "прежний конфиг восстановлен"'
check "bob не появился" '! elq user list $H $C | grep -q bob'
check "VPN после отката работает" '[ "$(tunnel default)" = "200" ]'

echo; echo "== S7: обновление сервера (M2.5): статус, откат бинарника при сбое, успешное обновление"
REAL=/tmp/sb-real; SB=/usr/local/bin/sing-box
setstate() { python3 - "$1" <<'PYIN'
import json,sys
p='/etc/eleutheria/state.json'; s=json.load(open(p)); s['singbox']=sys.argv[1]; json.dump(s,open(p,'w'))
PYIN
}
check "status: сервер актуален" 'elq server status $H $C | grep -q "актуально"'
# «старый» sing-box: обёртка, которая называет себя 1.0.0 и во всём остальном запускает настоящий бинарник
cp $SB $REAL
printf '#!/bin/sh\n[ "$1" = version ] && { echo "sing-box version 1.0.0"; exit 0; }\nexec %s "$@"\n' $REAL > $SB.tmp; chmod 755 $SB.tmp
mv -f $SB.tmp $SB   # mv, а не запись поверх: запущенный бинарник перезаписать нельзя («Text file busy»)
OLD_SUM=$(sha256sum < $SB); setstate 1.0.0
check "стенд: на сервере действительно «старый» sing-box 1.0.0" '$SB version | head -1 | grep -q 1.0.0'
check "status: старая версия видна, нужно обновление" 'elq server status $H $C | grep -q "нужно обновление"'
touch /tmp/fail-restart
OUT=$(elq server update $H $C); echo "$OUT" | grep -iE 'Скачиваю|Откат|прежн|сервис не поднялся' | head -6
check "сбой случился после замены бинарника (скачан новый sing-box)" 'echo "$OUT" | grep -q "Скачиваю sing-box"'
check "сбой рестарта: update завершился ошибкой" 'echo "$OUT" | grep -q "сервис не поднялся с новым конфигом"'
check "прежний бинарник вернулся на место (тот же хеш, версия 1.0.0)" '[ "$(sha256sum < $SB)" = "$OLD_SUM" ] && $SB version | head -1 | grep -q 1.0.0'
check "резервная копия sing-box.prev не осталась" '[ ! -e /usr/local/bin/sing-box.prev ]'
check "state.json не обновлён (всё ещё 1.0.0)" 'grep -q "\"singbox\": *\"1.0.0\"" /etc/eleutheria/state.json'
check "VPN после отката работает" '[ "$(tunnel default)" = "200" ]'
OUT=$(elq server update $H $C); echo "$OUT" | tail -3
check "успешное обновление сообщено" 'echo "$OUT" | grep -q "Готово: sing-box 1.14.3"'
check "бинарник на сервере теперь настоящий 1.14.3" '$SB version | head -1 | grep -q 1.14.3'
check "state.json: версия обновлена, пользователь default сохранён" 'grep -q "\"singbox\": *\"1.14.3\"" /etc/eleutheria/state.json && elq user list $H $C | grep -q default'
check "резервная копия после успеха удалена" '[ ! -e /usr/local/bin/sing-box.prev ]'
check "VPN после обновления работает" '[ "$(tunnel default)" = "200" ]'
OUT=$(elq server update $H $C); check "повторное обновление: уже актуально, ничего не ломает" 'echo "$OUT" | grep -q "уже актуален" && [ "$(tunnel default)" = "200" ]'
setstate 999.0.0
check "сервер новее клиента: понижать версию отказываемся" 'elq server update $H $C | grep -q "новее"'
setstate 1.14.3

echo; echo "== S5: защита host key"
python3 - <<'EOF'
import json
p='/tmp/elcfg/known_hosts.json'; d=json.load(open(p)); k=list(d)[0]; d[k]='SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; json.dump(d,open(p,'w'))
EOF
OUT=$(elq user list $H $C)
check "смена ключа сервера блокирует подключение" 'echo "$OUT" | grep -q "ВНИМАНИЕ: ключ сервера"'
elq forget $H >/dev/null
check "после eleutheria forget новый ключ принимается (с -y)" 'elq user list $H $C -y | grep -q default'

echo; echo "== S6: клиент (import, connect, авто-выбор, disconnect)"
CP=17890; CL=19090
mklink() {  # mklink <имя> <порт>: vless-ссылка на локальный сервер с заданным портом
  python3 - "$1" "$2" <<'PYIN'
import json,sys
s=json.load(open('/etc/eleutheria/state.json')); u=s['users'][0]
print(f"vless://{u['uuid']}@127.0.0.1:{sys.argv[2]}?encryption=none&flow=xtls-rprx-vision&security=reality&sni={s['sni']}&fp=chrome&pbk={s['public_key']}&sid={s['short_id']}&type=tcp#{sys.argv[1]}")
PYIN
}
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout /tmp/k2.pem -out /tmp/c2.pem -subj "/CN=$TARGET" -days 1 -addext "subjectAltName=IP:$TARGET" 2>/dev/null
cp /tmp/c2.pem /usr/local/share/ca-certificates/eleutheria-test.crt && update-ca-certificates >/dev/null 2>&1
echo hello > /tmp/index.html
setsid python3 -m http.server 8000 --bind $TARGET --directory /tmp >/tmp/http2.log 2>&1 < /dev/null & echo $! > /tmp/http2.pid
setsid python3 "$(dirname "$0")/https_target.py" $TARGET 8443 /tmp/c2.pem /tmp/k2.pem >/tmp/https2.log 2>&1 < /dev/null & echo $! > /tmp/https2.pid
sleep 1
TURL=https://$TARGET:8443/
check "provision сохранил сервер в списке клиента" '"$ELBIN" servers | grep -q "^127.0.0.1"'
OUT=$(elq import "$(mklink dead 1)"); check "одиночная ссылка импортируется" 'echo "$OUT" | grep -q "Добавлен: dead"'
mkdir -p /tmp/sub
{ mklink alive-dup $PORT; echo "vmess://eyJ2IjoiMiJ9"; } | base64 -w0 > /tmp/sub/s
setsid python3 -m http.server 8001 --bind 127.0.0.1 --directory /tmp/sub >/tmp/sub.log 2>&1 < /dev/null & echo $! > /tmp/sub.pid
sleep 1
OUT=$(elq import http://127.0.0.1:8001/s); echo "$OUT" | head -3
check "подписка: тот же сервер не дублируется, vmess пропущен" '[ "$("$ELBIN" servers | wc -l)" = "2" ] && echo "$OUT" | grep -q "Пропущено: схема .vmess"'
check "http:// в --test-url отклоняется с объяснением" 'elq connect --port $CP --clash-port $CL --test-url http://$TARGET:8000/ | grep -q "https://"'
check "импорт мусора отклоняется" 'elq import "ftp://x" | grep -q "нужна ссылка"'

OUT=$(elq connect --port $CP --clash-port $CL --test-url $TURL); echo "$OUT" | head -3
check "connect: прокси поднят, проверка через сервер прошла" 'echo "$OUT" | grep -q "Подключено" && echo "$OUT" | grep -q "Проверка через сервер:"'
check "трафик через SOCKS5-прокси клиента: 200" '[ "$(curl -s -m 10 -x socks5h://127.0.0.1:$CP -o /dev/null -w "%{http_code}" http://$TARGET:8000/)" = "200" ]'
check "трафик через HTTP-прокси клиента: 200" '[ "$(curl -s -m 10 -x http://127.0.0.1:$CP -o /dev/null -w "%{http_code}" http://$TARGET:8000/)" = "200" ]'
OUT=$(elq status); echo "$OUT"
check "status: режим авто, рабочий сервер с задержкой и меткой *, мёртвый недоступен" 'echo "$OUT" | grep -q "Режим: авто" && echo "$OUT" | grep -qE "^ \* 127.0.0.1.*мс" && echo "$OUT" | grep -q "dead.*недоступен"'
check "повторный connect отклонён" 'elq connect --port $CP --clash-port $CL | grep -q "уже подключено"'
elq disconnect | head -1
check "после disconnect прокси закрыт" '! (exec 3<>/dev/tcp/127.0.0.1/$CP) 2>/dev/null'
check "status: не подключено" 'elq status | grep -q "Не подключено"'

OUT=$(elq connect --port $CP --clash-port $CL --server dead --test-url $TURL)
check "жёсткий выбор мёртвого сервера: трафик не идёт" '[ "$(curl -s -m 8 -x socks5h://127.0.0.1:$CP -o /dev/null -w "%{http_code}" http://$TARGET:8000/)" != "200" ]'
elq disconnect >/dev/null
check "неизвестный сервер отклонён" 'elq connect --port $CP --clash-port $CL --server zzz | grep -q "нет в списке"'
setsid python3 -c "import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',17891));s.listen();time.sleep(30)" >/dev/null 2>&1 < /dev/null & BP=$!
sleep 0.5
check "занятый порт даёт понятную ошибку" 'elq connect --port 17891 --clash-port $CL | grep -q "занят"'
kill $BP 2>/dev/null
elq remove-server dead >/dev/null; elq remove-server 127.0.0.1 >/dev/null
check "без серверов connect объясняет, что делать" 'elq connect --port $CP --clash-port $CL | grep -q "нет серверов"'
for f in /tmp/sub.pid /tmp/https2.pid; do [ -f $f ] && kill "$(cat $f)" 2>/dev/null; done

echo; echo "== итог: PASS=$PASS FAIL=$FAIL"
[ -n "${E2E_KEEP:-}" ] || { rm -f /usr/local/share/ca-certificates/eleutheria-test.crt; update-ca-certificates --fresh >/dev/null 2>&1; }
[ -n "${E2E_KEEP:-}" ] || for f in /tmp/dest.pid /tmp/http.pid /tmp/http2.pid /tmp/https2.pid /tmp/sshd.pid /tmp/eleutheria-fake.pid; do [ -f $f ] && kill "$(cat $f)" 2>/dev/null; done
[ $FAIL -eq 0 ]
