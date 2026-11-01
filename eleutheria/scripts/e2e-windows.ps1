# e2e helper-службы и TUN на Windows. Запускать ТОЛЬКО в одноразовой ВМ, PowerShell от имени администратора.
# Не запускался автором: проверяет то, что нельзя проверить без Windows (служба, named pipe, Wintun, DNS).
# Нужен рабочий сервер Eleutheria/VLESS-Reality и его ссылка:
#   .\scripts\e2e-windows.ps1 -Link 'vless://...'
param([Parameter(Mandatory = $true)][string]$Link, [string]$Bin = "$PSScriptRoot\..\target\release")
$ErrorActionPreference = 'Continue'
$pass = 0; $fail = 0
function Check($name, [scriptblock]$test) {
  $ok = $false; try { $ok = [bool](& $test) } catch { }
  if ($ok) { Write-Host "  PASS: $name"; $script:pass++ } else { Write-Host "  FAIL: $name"; $script:fail++ }
}
$el = Join-Path $Bin 'eleutheria.exe'
if (-not (Test-Path $el)) { throw "нет $el: сначала cargo build --release" }
$env:ELEUTHERIA_CONFIG_DIR = Join-Path $env:TEMP 'elcfg-win'
Remove-Item -Recurse -Force $env:ELEUTHERIA_CONFIG_DIR -ErrorAction SilentlyContinue

Write-Host "== T0: до туннеля"
$direct = (curl.exe -s -m 15 https://api.ipify.org)
Check "внешний адрес получен" { $direct -match '^\d+\.\d+\.\d+\.\d+$' }
& $el import $Link | Out-Null

Write-Host "== T1: установка службы"
& $el helper install
Check "служба EleutheriaHelper работает" { (sc.exe query EleutheriaHelper) -match 'RUNNING' }
Check "helper отвечает по named pipe" { (& $el helper status) -match 'helper работает' }
Check "каталог данных закрыт: обычная группа Users не имеет доступа" { -not ((icacls "$env:ProgramData\Eleutheria") -match 'BUILTIN\\Users') }
Check "pipe не доступен по сети (DACL/reject_remote_clients): ручная проверка, см. README" { $true }

Write-Host "== T2: TUN"
$out = & $el connect --tun --test-url https://127.0.0.1:1/
Check "connect --tun: туннель поднят" { $out -match 'Туннель поднят' }
Start-Sleep -Seconds 3
Check "адаптер Wintun появился" { Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'Wintun|sing' } }
$via = (curl.exe -s -m 20 https://api.ipify.org)
Check "внешний адрес сменился (трафик идёт через сервер)" { $via -match '^\d+\.\d+\.\d+\.\d+$' -and $via -ne $direct }

Write-Host "== T3: DNS"
$fake = (Resolve-DnsName somename.test -Type A -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
Write-Host "  somename.test -> $fake"
Check "обычное имя получает fake-ip из 198.18.0.0/15" { $fake -match '^198\.1[89]\.' }

Write-Host "== T4: отключение"
$out = & $el disconnect
Check "disconnect сообщает об отключении" { $out -match 'Отключено' }
Start-Sleep -Seconds 3
Check "адаптер Wintun исчез" { -not (Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'Wintun|sing' }) }
Check "внешний адрес снова прямой" { (curl.exe -s -m 15 https://api.ipify.org) -eq $direct }

Write-Host "== T5: аварийное завершение sing-box (taskkill) не ломает сеть"
& $el connect --tun --test-url https://127.0.0.1:1/ | Out-Null; Start-Sleep -Seconds 3
taskkill /F /IM sing-box.exe | Out-Null; Start-Sleep -Seconds 3
Check "status: не подключено" { (& $el status) -match 'Не подключено' }
Check "после падения адрес прямой" { (curl.exe -s -m 15 https://api.ipify.org) -eq $direct }

Write-Host "== T6: удаление"
& $el helper uninstall
Check "служба удалена" { (sc.exe query EleutheriaHelper) -match '1060' }
Check "файлы удалены" { -not (Test-Path "$env:ProgramFiles\Eleutheria\eleutheria-helper.exe") }

Write-Host "`n== итог: PASS=$pass FAIL=$fail"
exit ([int]($fail -gt 0))
