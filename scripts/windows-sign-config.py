#!/usr/bin/env python3
"""Пишет overlay-конфиг Tauri для подписи Windows-установщиков сертификатом из хранилища runner'а.
Использование: windows-sign-config.py --thumbprint <40 hex> [--timestamp-url URL] -o путь.json"""
import argparse, json, re, sys

ap = argparse.ArgumentParser()
ap.add_argument("--thumbprint", required=True)
ap.add_argument("--timestamp-url", default="http://timestamp.digicert.com")
ap.add_argument("-o", "--out", required=True)
a = ap.parse_args()

tp = re.sub(r"\s", "", a.thumbprint).upper()
if not re.fullmatch(r"[0-9A-F]{40}", tp):
    sys.exit("Ошибка: отпечаток сертификата должен быть 40 hex-символов (SHA-1)")
if not a.timestamp_url.startswith(("http://", "https://")):
    sys.exit("Ошибка: адрес службы меток времени должен быть http(s)")
conf = {
    "$schema": "https://schema.tauri.app/config/2",
    "bundle": {"windows": {"certificateThumbprint": tp, "digestAlgorithm": "sha256", "timestampUrl": a.timestamp_url}},
}
with open(a.out, "w", encoding="utf-8") as f:
    json.dump(conf, f, indent=2)
    f.write("\n")
print(f"Записан {a.out}")
