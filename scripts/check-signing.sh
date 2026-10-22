#!/bin/bash
# Проверка настроек подписи установщиков перед релизом (читает переменные окружения, значения не печатает).
#   Windows: WINDOWS_CERTIFICATE (base64 от .pfx), WINDOWS_CERTIFICATE_PASSWORD
#   macOS:   APPLE_CERTIFICATE (base64 от .p12), APPLE_CERTIFICATE_PASSWORD, APPLE_SIGNING_IDENTITY,
#            APPLE_ID, APPLE_PASSWORD (пароль приложения), APPLE_TEAM_ID  (подпись + нотаризация)
#   REQUIRE_SIGNING=true: релиз без полной подписи обеих ОС запрещён. Иначе без подписи только предупреждение.
# Частично заданный набор (например, сертификат без пароля) всегда ошибка: так не выпускают случайно.
set -u
req=${REQUIRE_SIGNING:-false}
errs=0; warns=0
group() { # имя, переменные...
  local name=$1; shift
  local set=0 total=0 missing=()
  for v in "$@"; do
    total=$((total+1))
    if [ -n "${!v:-}" ]; then set=$((set+1)); else missing+=("$v"); fi
  done
  if [ $set -eq $total ]; then echo "OK: подпись $name настроена"
  elif [ $set -gt 0 ]; then echo "ОШИБКА: подпись $name задана не полностью, нет: ${missing[*]}"; errs=$((errs+1))
  elif [ "$req" = "true" ]; then echo "ОШИБКА: подпись $name не настроена (REQUIRE_SIGNING=true): нет ${missing[*]}"; errs=$((errs+1))
  else echo "ПРЕДУПРЕЖДЕНИЕ: подпись $name не настроена, установщики будут неподписанными (SmartScreen/Gatekeeper предупредят пользователей)"; warns=$((warns+1))
  fi
}
group Windows WINDOWS_CERTIFICATE WINDOWS_CERTIFICATE_PASSWORD
group macOS APPLE_CERTIFICATE APPLE_CERTIFICATE_PASSWORD APPLE_SIGNING_IDENTITY APPLE_ID APPLE_PASSWORD APPLE_TEAM_ID
[ $errs -eq 0 ]
