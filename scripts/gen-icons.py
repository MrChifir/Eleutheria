#!/usr/bin/env python3
"""Генерирует иконки приложения (PNG, ICO, ICNS) из одного рисунка. Нужен Pillow.
Запуск: python3 scripts/gen-icons.py  (результат: crates/eleutheria-gui/icons/)"""
import io, struct, pathlib
from PIL import Image, ImageDraw

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "eleutheria-gui" / "icons"

def master(size=1024):
    """Скруглённый квадрат акцентного цвета с белым разомкнутым кольцом с ключом внутри."""
    im = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((0, 0, size - 1, size - 1), radius=int(size * 0.22), fill=(45, 108, 223, 255))
    cx, cy, r = size / 2, size / 2, size * 0.27
    w = int(size * 0.075)
    d.arc((cx - r, cy - r, cx + r, cy + r), start=-60, end=240, fill=(255, 255, 255, 255), width=w)  # кольцо с разрывом сверху
    d.ellipse((cx - w * 0.9, cy - w * 0.9, cx + w * 0.9, cy + w * 0.9), fill=(255, 255, 255, 255))
    d.line((cx, cy, cx, cy + r * 1.05), fill=(255, 255, 255, 255), width=w)
    return im

def png_bytes(im, s):
    b = io.BytesIO()
    im.resize((s, s), Image.LANCZOS).save(b, "PNG")
    return b.getvalue()

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    m = master()
    for name, s in [("32x32.png", 32), ("128x128.png", 128), ("128x128@2x.png", 256), ("icon.png", 512)]:
        (OUT / name).write_bytes(png_bytes(m, s))
    # ICO: несколько размеров, внутри PNG (поддерживается Windows Vista и новее)
    sizes = [16, 24, 32, 48, 64, 128, 256]
    blobs = [png_bytes(m, s) for s in sizes]
    head = struct.pack("<HHH", 0, 1, len(sizes))
    off = 6 + 16 * len(sizes)
    ents = b""
    for s, b in zip(sizes, blobs):
        ents += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(b), off)
        off += len(b)
    (OUT / "icon.ico").write_bytes(head + ents + b"".join(blobs))
    # ICNS: типы ic07 (128), ic08 (256), ic09 (512), ic10 (1024) с PNG внутри
    parts = b""
    for t, s in [(b"ic07", 128), (b"ic08", 256), (b"ic09", 512), (b"ic10", 1024)]:
        b = png_bytes(m, s)
        parts += t + struct.pack(">I", len(b) + 8) + b
    (OUT / "icon.icns").write_bytes(b"icns" + struct.pack(">I", len(parts) + 8) + parts)
    print("готово:", ", ".join(sorted(p.name for p in OUT.iterdir())))

if __name__ == "__main__":
    main()
