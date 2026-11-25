"""Render build/demo.txt (from scripts/demo.py) as an animated terminal GIF: docs/media/demo.gif."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "build" / "demo.txt"
OUT = ROOT / "docs" / "media" / "demo.gif"

BG, FG, DIM = (22, 24, 29), (220, 223, 228), (120, 126, 138)
GREEN, RED, AMBER, BLUE = (110, 200, 120), (235, 100, 95), (230, 180, 80), (110, 170, 240)
FONT_PATH = "/System/Library/Fonts/Menlo.ttc"
SIZE, LH, PAD, W = 15, 21, 18, 960
TITLE = "netchange - AI change assistant with pre-deployment verification (live lab + Batfish)"


def colour(line: str) -> tuple:
    s = line.strip()
    if s.startswith("> request"):
        return BLUE
    if s.startswith("#"):
        return DIM
    if "FAIL" in s or "REJECTED" in s:
        return RED
    if "ROLLED_BACK" in s or s.startswith("rollback"):
        return AMBER
    if "PASS" in s or "APPLIED" in s:
        return GREEN
    return FG


def main() -> None:
    lines = SRC.read_text().rstrip("\n").splitlines()
    font = ImageFont.truetype(FONT_PATH, SIZE)
    bold = ImageFont.truetype(FONT_PATH, SIZE, index=1)
    h = PAD * 2 + 34 + LH * len(lines)
    frames, durations = [], []

    def frame(n: int) -> Image.Image:
        im = Image.new("RGB", (W, h), BG)
        d = ImageDraw.Draw(im)
        d.rectangle([0, 0, W, 30], fill=(36, 39, 46))
        for i, c in enumerate([(235, 100, 95), (230, 180, 80), (110, 200, 120)]):
            d.ellipse([12 + i * 20, 9, 24 + i * 20, 21], fill=c)
        d.text((80, 7), TITLE, font=font, fill=DIM)
        for i, ln in enumerate(lines[:n]):
            f = bold if ln.strip().startswith(("RESULT", "> request")) else font
            d.text((PAD, 30 + PAD + i * LH), ln, font=f, fill=colour(ln))
        return im

    for n in range(1, len(lines) + 1):
        frames.append(frame(n))
        ln = lines[n - 1].strip()
        durations.append(1600 if ln.startswith("RESULT") else 900 if ln.startswith("> request") else 380)
    durations[-1] = 5000
    OUT.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(OUT, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True)
    frames[-1].save(OUT.with_suffix(".png"))
    print(OUT, f"{OUT.stat().st_size / 1024:.0f} KB, {len(frames)} frames")


if __name__ == "__main__":
    main()
