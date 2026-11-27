"""patch_256_v3.py -- iT30ProS V1.07 -> enable 1/256 (complete set).

Builds on patch_256_v2.py (74 sites, tenths/thirds base + slider max) and adds
the SECOND layer discovered via IDA/Hex-Rays: the power value itself is stored
as `tenths` in byte_2000058C[group] (0 = 1/1 full power, 70 = 1/128, 80 = 1/256,
90 = 1/512).  The display is generated mathematically (snprintf "1/%d",
denominator = 512 >> (tenths/10)), so NO icon resource changes are needed.

The real interactive boundary is a set of `tenths > 0x46 -> 70` clamps that
were NOT covered by v2:
  - M-mode editor widget renderer      0x800ABCC
  - Multi-mode widget renderer         0x800B8BC
  - main panel                         0x800D048
  - secondary UI copy                  0x8008E60
  - config validator (runs on config load/save, clamps ALL groups) 0x800AA2C
  - wireless command handlers 188/189  0x800F70C (power set via radio)

Container: [0..0xA8000) image | MD5(16) | name(28) | u16 len | magic.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026  iT30Pro S Patch Toolkit contributors
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.  It is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
# Public License (LICENSE) for more details.

import hashlib
import importlib.util
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FW = os.path.join(_ROOT, "firmware")
SRC = os.path.join(_FW, "iT30ProS_V1.07.bin")
DST = os.path.join(_FW, "iT30ProS_V1.09.bin")
BASE = 0x08000000
IMG = 0xA8000

# ---- layer 1: reuse v2 patch list ----
_V2_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patch_256_v2.py")
spec = importlib.util.spec_from_file_location("patch_256_v2", _V2_PATH)
v2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v2)
PATCH_V2 = list(v2.P)

# ---- layer 2: tenths clamps 0x46 -> 0x50 ----
# (VA, expected_thumb16_after_decode, note) -- value encodes cmp/movs rN, #0x46
T = []
def t(va, hw_new, note):
    T.append((va, hw_new, note))

t(0x0800ABE4, 0x2850, "M widget: cmp r0, #0x50")
t(0x0800ABEC, 0x2050, "M widget: movs r0, #0x50")
t(0x0800B8D8, 0x2850, "Multi widget: cmp r0, #0x50")
t(0x0800B8E0, 0x2050, "Multi widget: movs r0, #0x50")
t(0x0800D158, 0x2250, "main panel: movs r2, #0x50")
t(0x0800D15E, 0x2850, "main panel: cmp r0, #0x50")
t(0x08008FEC, 0x2850, "ui copy: cmp r0, #0x50")
t(0x08008FF0, 0x2050, "ui copy: movs r0, #0x50")
t(0x08009004, 0x2050, "ui copy 2nd array: movs r0, #0x50")
t(0x08009026, 0x2850, "ui copy 2nd array: cmp r0, #0x50")
t(0x0800AA4A, 0x2550, "validator: movs r5, #0x50 (clamp const)")
t(0x0800AA6E, 0x2950, "validator: cmp r1, #0x50")
t(0x0800AA94, 0x2950, "validator: cmp r1, #0x50")
t(0x0800AAA0, 0x2950, "validator: cmp r1, #0x50")
t(0x0800FBAC, 0x2A50, "wireless case188: cmp r2, #0x50")
t(0x0800FBB4, 0x2250, "wireless case188: movs r2, #0x50")
t(0x0800FBBE, 0x2A50, "wireless case189: cmp r2, #0x50")
t(0x0800FBCA, 0x2250, "wireless case189: movs r2, #0x50")

# ---- trailer version ----


def main():
    data = bytearray(open(SRC, "rb").read())
    if len(data) != IMG + 54:
        sys.exit(f"unexpected container size {len(data)}")
    if hashlib.md5(bytes(data[:IMG])).digest() != bytes(data[IMG:IMG + 16]):
        sys.exit("source MD5 trailer mismatch")

    bad = []
    applied = 0

    # v2 layer: byte patches with expected originals
    for va, off, old, new, note in PATCH_V2:
        fo = va - BASE + off
        if data[fo] != old:
            bad.append(f"v2 {va:#010x}+{off}: expect {old:#04x}, got {data[fo]:#04x} ({note})")
            continue
        data[fo] = new
        applied += 1

    # v3 layer: thumb16 patches with expected originals
    for va, hw_new, note in T:
        fo = va - BASE
        hw_old = int.from_bytes(data[fo:fo + 2], "little")
        # expected: same register/operation with 0x46 immediate
        if (hw_new & 0xFF00) != (hw_old & 0xFF00) or (hw_old & 0xFF) != 0x46:
            bad.append(f"v3 {va:#010x}: expect thumb16 imm 0x46 form, got {hw_old:#06x} ({note})")
            continue
        data[fo:fo + 2] = hw_new.to_bytes(2, "little")
        applied += 1

    if bad:
        print("ABORT, unexpected bytes:")
        for b in bad:
            print("  " + b)
        sys.exit(1)

    print(f"patched {applied} sites total ({applied} applied; + {len(T)} v3)")

    # trailer version V1.07 -> V1.09
    name = bytes(data[IMG + 16:IMG + 16 + 28])
    if b"V1.07" in name:
        i = name.index(b"V1.07")
        data[IMG + 16 + i + 4] = ord("9")
        print("trailer name ->", bytes(data[IMG + 16:IMG + 16 + 28]))

    data[IMG:IMG + 16] = hashlib.md5(bytes(data[:IMG])).digest()
    open(DST, "wb").write(bytes(data))
    print("wrote", DST)
    print("image md5:", data[IMG:IMG + 16].hex())
    print("file size:", len(data))


if __name__ == "__main__":
    main()
