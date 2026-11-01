#!/bin/sh
# Проверка M4 на настоящем sing-box (два сервера, цель с блокировкой выходного IP, настоящий Watcher).
# SINGBOX_BIN=/путь/к/sing-box scripts/e2e-prober.sh   (нужны python3, curl; пишет в /etc/hosts, нужен root)
set -e
grep -q 'canary.test' /etc/hosts || echo '127.0.0.1 target.test canary.test' >> /etc/hosts
exec cargo run -q -p eleutheria-core --example e2e_prober
