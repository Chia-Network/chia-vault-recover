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

# OSTypes that Icon Services actually renders, in the order iconutil writes them.
# 16px and 32px 1x icons are ARGB (ic04/ic05). PNG in icp4/icp5/icp6 is scrambled
# in Finder list view, Activity Monitor, and Trash. Retina sizes and 128px+ stay PNG.
ICNS_PNG = (
    ("ic07", 128),
    ("ic08", 256),
    ("ic09", 512),
    ("ic10", 1024),
    ("ic11", 32),  # 16x16@2x
    ("ic12", 64),  # 32x32@2x
    ("ic13", 256),  # 128x128@2x
    ("ic14", 512),  # 256x256@2x
)
ICNS_ARGB = (
    ("ic04", 16),
    ("ic05", 32),
)


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


def pack_bits(data: bytes) -> bytes:
    """ICNS PackBits. A run is 3..130 copies; shorter repeats stay literal."""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        run = 1
        while i + run < n and data[i + run] == data[i] and run < 130:
            run += 1
        if run >= 3:
            out.append(0x80 | (run - 3))
            out.append(data[i])
            i += run
            continue
        literal = bytearray()
        while i < n and len(literal) < 128:
            ahead = 1
            while i + ahead < n and data[i + ahead] == data[i] and ahead < 3:
                ahead += 1
            if ahead >= 3:
                break
            literal.append(data[i])
            i += 1
        out.append(len(literal) - 1)
        out.extend(literal)
    return bytes(out)


def unpack_bits(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        control = data[i]
        if control < 0x80:
            count = control + 1
            out.extend(data[i + 1 : i + 1 + count])
            i += 1 + count
        else:
            out.extend([data[i + 1]] * (control - 0x7D))
            i += 2
    return bytes(out)


def encode_argb(im: Image.Image) -> bytes:
    """Straight (non-premultiplied) A, R, G, B channels, each PackBits-compressed."""
    im = im.convert("RGBA")
    width, height = im.size
    if width != height:
        raise ValueError(f"ARGB icon must be square, got {width}x{height}")
    raw = im.tobytes()
    channels = [pack_bits(raw[index::4]) for index in (3, 0, 1, 2)]
    return b"ARGB" + b"".join(channels)


def decode_argb(payload: bytes, size: int) -> Image.Image:
    if not payload.startswith(b"ARGB"):
        raise ValueError("ARGB payload is missing its magic")
    raw = unpack_bits(payload[4:])
    count = size * size
    if len(raw) != count * 4:
        raise ValueError(f"ARGB decoded to {len(raw)} bytes, expected {count * 4}")
    alpha = raw[:count]
    red = raw[count : count * 2]
    green = raw[count * 2 : count * 3]
    blue = raw[count * 3 :]
    im = Image.new("RGBA", (size, size))
    im.putdata(
        [(red[i], green[i], blue[i], alpha[i]) for i in range(count)]
    )
    return im


def write_icns(pngs: dict[int, bytes], images: dict[int, Image.Image], dest: Path) -> None:
    chunks = bytearray()

    def add(ostype: str, payload: bytes) -> None:
        chunks.extend(ostype.encode("ascii"))
        chunks.extend(struct.pack(">I", 8 + len(payload)))
        chunks.extend(payload)

    # iconutil writes the 1x ARGB icons before the PNG sizes.
    for ostype, size in ICNS_ARGB:
        payload = encode_argb(images[size])
        decoded = decode_argb(payload, size).tobytes()
        source = images[size].convert("RGBA").tobytes()
        if decoded != source:
            raise RuntimeError(f"{ostype} ARGB did not round-trip")
        add(ostype, payload)
    for ostype, size in ICNS_PNG:
        add(ostype, pngs[size])
    dest.write_bytes(b"icns" + struct.pack(">I", 8 + len(chunks)) + chunks)


def main() -> int:
    if not SVG.is_file():
        print(f"missing {SVG}", file=sys.stderr)
        return 1
    ASSETS.mkdir(parents=True, exist_ok=True)
    needed = sorted(set(ICO_SIZES) | {size for _, size in ICNS_PNG} | {size for _, size in ICNS_ARGB})
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
    write_icns(png_bytes, images, ASSETS / "icon.icns")
    print(f"wrote {master.name}, icon.ico, icon.icns")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
