#!/bin/bash
# Тесты scripts/check-signing.sh и scripts/windows-sign-config.py
cd "$(dirname "$0")/.."
pass=0; fail=0
t() { # описание, ожидаемый код, команда...
  local d=$1 want=$2; shift 2
  out=$("$@" 2>&1); rc=$?
  if [ $rc -eq $want ]; then pass=$((pass+1)); echo "  ok   $d"; else fail=$((fail+1)); echo "  FAIL $d (код $rc, ждали $want): $out"; fi
}
ALL="WINDOWS_CERTIFICATE=a WINDOWS_CERTIFICATE_PASSWORD=b APPLE_CERTIFICATE=c APPLE_CERTIFICATE_PASSWORD=d APPLE_SIGNING_IDENTITY=e APPLE_ID=f APPLE_PASSWORD=g APPLE_TEAM_ID=h"
t "ничего не задано, подпись не обязательна: предупреждение, код 0" 0 env -i PATH=$PATH scripts/check-signing.sh
t "ничего не задано, REQUIRE_SIGNING=true: блок" 1 env -i PATH=$PATH REQUIRE_SIGNING=true scripts/check-signing.sh
t "всё задано, REQUIRE_SIGNING=true: пропуск" 0 env -i PATH=$PATH REQUIRE_SIGNING=true $ALL scripts/check-signing.sh
t "Windows без пароля: ошибка даже без REQUIRE" 1 env -i PATH=$PATH WINDOWS_CERTIFICATE=a scripts/check-signing.sh
t "Apple без нотаризации (нет APPLE_ID): ошибка" 1 env -i PATH=$PATH APPLE_CERTIFICATE=c APPLE_CERTIFICATE_PASSWORD=d APPLE_SIGNING_IDENTITY=e scripts/check-signing.sh
t "только Windows при REQUIRE: блок из-за macOS" 1 env -i PATH=$PATH REQUIRE_SIGNING=true WINDOWS_CERTIFICATE=a WINDOWS_CERTIFICATE_PASSWORD=b scripts/check-signing.sh
out=$(env -i PATH=$PATH WINDOWS_CERTIFICATE=SECRETVALUE scripts/check-signing.sh 2>&1)
if echo "$out" | grep -q SECRETVALUE; then fail=$((fail+1)); echo "  FAIL значение секрета попало в вывод"; else pass=$((pass+1)); echo "  ok   значения секретов не печатаются"; fi
TP=$(printf 'AB%.0s' $(seq 20)); TMP=$(mktemp)
t "конфиг подписи Windows: верный отпечаток" 0 python3 scripts/windows-sign-config.py --thumbprint "$TP" -o $TMP
python3 - $TMP "$TP" <<'PY' && { pass=$((pass+1)); echo "  ok   содержимое overlay-конфига"; } || { fail=$((fail+1)); echo "  FAIL содержимое overlay-конфига"; }
import json,sys
w=json.load(open(sys.argv[1]))["bundle"]["windows"]
assert w["certificateThumbprint"]==sys.argv[2] and w["digestAlgorithm"]=="sha256" and w["timestampUrl"].startswith("http")
PY
t "отпечаток с пробелами и в нижнем регистре нормализуется" 0 python3 scripts/windows-sign-config.py --thumbprint "$(echo $TP | tr A-Z a-z | sed 's/../& /g')" -o $TMP
t "короткий отпечаток отвергается" 1 python3 scripts/windows-sign-config.py --thumbprint abc -o $TMP
t "не hex отвергается" 1 python3 scripts/windows-sign-config.py --thumbprint "$(printf 'Z%.0s' $(seq 40))" -o $TMP
t "timestamp не http отвергается" 1 python3 scripts/windows-sign-config.py --thumbprint "$TP" --timestamp-url ftp://x -o $TMP
rm -f $TMP
echo "итого: $pass ok, $fail fail"; [ $fail -eq 0 ]
