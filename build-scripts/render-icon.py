#!/usr/bin/env python3
"""Rasterize assets/icon.svg into the PNG, ICO, and ICNS files the app embeds.

Requires rsvg-convert (librsvg) and Pillow. Not used by CI; the generated
files are committed so release builds do not need those tools.
"""

from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
SVG = ROOT / "assets" / "icon.svg"
ASSETS = ROOT / "assets"

# Windows explorer sizes. 256 is stored as 0 in the ICO directory entry.
ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)

# PNG-backed icns types understood by macOS 11 (the bundle's minimum).
ICNS_TYPES = {
    16: "icp4",
    32: "icp5",
    64: "icp6",
    128: "ic07",
    256: "ic08",
    512: "ic09",
    1024: "ic10",
}
# Retina variants that repeat a size under another OSType.
ICNS_RETINA = {
    32: "ic11",  # 16x16@2x
    64: "ic12",  # 32x32@2x
    256: "ic13",  # 128x128@2x
    512: "ic14",  # 256x256@2x
}


def render(size: int, dest: Path) -> None:
    subprocess.check_call(
        [
            "rsvg-convert",
            "-w",
            str(size),
            "-h",
            str(size),
            str(SVG),
            "-o",
            str(dest),
        ]
    )


def dib_image(im: Image.Image) -> bytes:
    """32-bit BMP DIB (no file header) plus AND mask, bottom-up, for an ICO."""
    im = im.convert("RGBA")
    width, height = im.size
    xor_rows = bytearray()
    and_row_stride = ((width + 31) // 32) * 4
    and_rows = bytearray()
    pixels = im.load()
    for y in range(height - 1, -1, -1):
        row = bytearray()
        bits = 0
        bit_count = 0
        and_row = bytearray()
        for x in range(width):
            r, g, b, a = pixels[x, y]
            row += bytes((b, g, r, a))
            transparent = 1 if a < 128 else 0
            bits = (bits << 1) | transparent
            bit_count += 1
            if bit_count == 8:
                and_row.append(bits)
                bits = 0
                bit_count = 0
        if bit_count:
            bits <<= 8 - bit_count
            and_row.append(bits)
        while len(and_row) < and_row_stride:
            and_row.append(0)
        xor_rows += row
        and_rows += and_row
    image_size = len(xor_rows) + len(and_rows)
    header = struct.pack(
        "<IIIHHIIIIII",
        40,
        width,
        height * 2,
        1,
        32,
        0,
        image_size,
        0,
        0,
        0,
        0,
    )
    return header + xor_rows + and_rows


def write_ico(images: dict[int, Image.Image], dest: Path) -> None:
    blobs = [dib_image(images[size]) for size in ICO_SIZES]
    count = len(blobs)
    header = struct.pack("<HHH", 0, 1, count)
    directory = bytearray()
    offset = 6 + 16 * count
    payload = bytearray()
    for size, blob in zip(ICO_SIZES, blobs, strict=True):
        entry_size = 0 if size == 256 else size
        directory += struct.pack(
            "<BBBBHHII",
            entry_size,
            entry_size,
            0,
            0,
            1,
            32,
            len(blob),
            offset,
        )
        offset += len(blob)
        payload += blob
    dest.write_bytes(header + directory + payload)


def write_icns(pngs: dict[int, bytes], dest: Path) -> None:
    chunks = bytearray()

    def add(ostype: str, png: bytes) -> None:
        chunks.extend(ostype.encode("ascii"))
        chunks.extend(struct.pack(">I", 8 + len(png)))
        chunks.extend(png)

    for size, ostype in ICNS_TYPES.items():
        add(ostype, pngs[size])
    for size, ostype in ICNS_RETINA.items():
        add(ostype, pngs[size])
    dest.write_bytes(b"icns" + struct.pack(">I", 8 + len(chunks)) + chunks)


def main() -> int:
    if not SVG.is_file():
        print(f"missing {SVG}", file=sys.stderr)
        return 1
    ASSETS.mkdir(parents=True, exist_ok=True)
    needed = sorted(set(ICO_SIZES) | set(ICNS_TYPES) | {512, 1024})
    png_bytes: dict[int, bytes] = {}
    images: dict[int, Image.Image] = {}
    for size in needed:
        path = ASSETS / f".icon-{size}.png"
        render(size, path)
        png_bytes[size] = path.read_bytes()
        images[size] = Image.open(path).convert("RGBA")
        path.unlink()
    master = ASSETS / "icon-1024.png"
    master.write_bytes(png_bytes[1024])
    write_ico(images, ASSETS / "icon.ico")
    write_icns(png_bytes, ASSETS / "icon.icns")
    print(f"wrote {master.name}, icon.ico, icon.icns")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
