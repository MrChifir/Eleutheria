#!/usr/bin/env python3
"""Переписывает latest.json для зеркала: адреса скачивания указывают на зеркало, подписи остаются прежними
(подпись покрывает сам файл, а не адрес). Печатает список файлов, которые нужно выложить на зеркало.

  mirror-manifest.py latest.json --base https://updates.example.org/eleutheria/v0.2.0 -o mirror/latest.json
"""
import argparse, json, posixpath, sys
from urllib.parse import quote, urlparse


def rewrite(manifest: dict, base: str) -> tuple[dict, list[str]]:
    if not base.startswith("https://"):
        raise ValueError("база зеркала должна быть https://")
    base = base.rstrip("/")
    out = json.loads(json.dumps(manifest))
    files: list[str] = []
    platforms = out.get("platforms")
    if not isinstance(platforms, dict) or not platforms:
        raise ValueError("в манифесте нет platforms")
    for name, p in platforms.items():
        if not p.get("signature"):
            raise ValueError(f"{name}: нет подписи")
        u = urlparse(p.get("url", ""))
        if u.scheme != "https":
            raise ValueError(f"{name}: url не https: {p.get('url')!r}")
        fname = posixpath.basename(u.path)
        if not fname or fname in (".", ".."):
            raise ValueError(f"{name}: не удалось получить имя файла из {p['url']!r}")
        p["url"] = f"{base}/{quote(fname)}"
        if fname not in files:
            files.append(fname)
    return out, files


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest")
    ap.add_argument("--base", required=True)
    ap.add_argument("-o", "--output", required=True)
    a = ap.parse_args()
    try:
        out, files = rewrite(json.load(open(a.manifest)), a.base)
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f"ошибка: {e}", file=sys.stderr)
        return 1
    with open(a.output, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("\n".join(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
