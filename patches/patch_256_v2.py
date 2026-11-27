"""patch_256_v2.py -- iT30ProS V1.07 -> enable 1/256 for the four group outputs.

WHY THE PREVIOUS PATCH DID NOT WORK
-----------------------------------
The group power ladder is kept as  `stored = BASE - level`, where
`level` is the attenuation in tenths of a stop (0 = 1/1, 70 = 1/128).
The earlier patch moved BASE 0x46 -> 0x50 and the 1/3-stop base 0x15 -> 0x18.
It missed the *companion* constants that are BASE+1:

    movs r2, #0x47 ; bl <slider-set-max>     -> the power slider's max = 71
    rsb.w r0, r0, #0x47                      -> 71 - (level+1) = stored

With the slider still capped at 71 (value = level+1), the UI can never ask for
level 80 (1/256): you drag to the end, level stops at 70 and the firmware stores
0 => 1/128.  That is exactly the "patched but still cannot reach 1/256" symptom.

This script applies the complete, consistent set:
    tenths  base 0x46 -> 0x50   (70 -> 80)   and its +1 form 0x47 -> 0x51
    thirds  base 0x15 -> 0x18   (21 -> 24)   (no +1 form exists in code)
    trailer version string V1.07 -> V1.08 so the updater does not treat the
    file as "same version, nothing to do".

Container: [0 .. 0xA8000) image | MD5(image) 16B | name 28B | u16 len | magic.
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
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FW = os.path.join(_ROOT, "firmware")
SRC = os.path.join(_FW, "iT30ProS_V1.07.bin")
DST = os.path.join(_FW, "iT30ProS_V1.08_256.bin")
BASE = 0x08000000
IMG = 0xA8000

T_OLD, T_NEW = 0x46, 0x50   # tenths of a stop      70 -> 80  (1/128 -> 1/256)
T1_OLD, T1_NEW = 0x47, 0x51  # tenths + 1            71 -> 81  (slider max)
S_OLD, S_NEW = 0x15, 0x18   # 1/3-stop steps        21 -> 24  (7 -> 8 stops)

# (VA, byte offset inside instruction, expected old, new, note)
P = []


def add(va, off, old, new, note=""):
    P.append((va, off, old, new, note))


# ---- 0x800Dxx : main panel, level read / default ---------------------------
add(0x0800DDF0, 0, T_OLD, T_NEW, "default stored value")
add(0x0800DE02, 2, T_OLD, T_NEW, "level = base - stored")

# ---- group editor copy #1 : 0x800E9xx -------------------------------------
add(0x0800E944, 2, T_OLD, T_NEW, "default stored value")
add(0x0800E954, 2, T_OLD, T_NEW, "level = base - stored")
add(0x0800E966, 0, S_OLD, S_NEW, "thirds compare")
add(0x0800E96A, 2, S_OLD, S_NEW, "thirds compare")
add(0x0800E9A8, 0, S_OLD, S_NEW, "thirds compare")
add(0x0800E9B0, 2, S_OLD, S_NEW, "thirds compare")
add(0x0800E9BC, 0, T_OLD, T_NEW, "tenths compare")
add(0x0800E9C4, 2, T_OLD, T_NEW, "tenths compare")
add(0x0800E9EA, 0, T_OLD, T_NEW, "level clamp compare")
add(0x0800E9EE, 0, T_OLD, T_NEW, "level clamp movhi")
add(0x0800E9F0, 2, T_OLD, T_NEW, "stored = base - level")
add(0x0800EA90, 0, S_OLD, S_NEW, "thirds clamp compare")
add(0x0800EA94, 0, S_OLD, S_NEW, "thirds clamp movhi")
add(0x0800EA96, 2, S_OLD, S_NEW, "thirds base")
add(0x0800EACA, 2, T_OLD, T_NEW, "stored = base - level")

# ---- group editor copy #2 : 0x800F3xx -------------------------------------
add(0x0800F194, 0, T_OLD, T_NEW, "default stored value")
add(0x0800F308, 2, T_OLD, T_NEW, "level = base - stored")
add(0x0800F318, 0, S_OLD, S_NEW, "thirds compare")
add(0x0800F31C, 0, S_OLD, S_NEW, "thirds compare")
add(0x0800F35C, 0, S_OLD, S_NEW, "thirds compare")
add(0x0800F360, 0, S_OLD, S_NEW, "thirds compare")
add(0x0800F372, 0, S_OLD, S_NEW, "thirds clamp compare")
add(0x0800F376, 0, S_OLD, S_NEW, "thirds clamp movhi")
add(0x0800F378, 2, S_OLD, S_NEW, "thirds base")
add(0x0800F3AC, 2, T1_OLD, T1_NEW, "stored = (base+1) - (level+1)   <-- MISSED BEFORE")
add(0x0800F3C0, 0, T_OLD, T_NEW, "tenths compare")
add(0x0800F3C4, 2, T_OLD, T_NEW, "tenths compare")
add(0x0800F3DA, 0, T_OLD, T_NEW, "level clamp compare")
add(0x0800F3DE, 0, T_OLD, T_NEW, "level clamp movhi")
add(0x0800F3E0, 2, T_OLD, T_NEW, "stored = base - level")
add(0x0800F5DE, 2, T_OLD, T_NEW, "stored = base - level")

# ---- group editor copy #3 : 0x80124xx -------------------------------------
add(0x080122B0, 0, T_OLD, T_NEW, "default stored value")
add(0x08012424, 2, T_OLD, T_NEW, "level = base - stored")
add(0x08012434, 0, S_OLD, S_NEW, "thirds compare")
add(0x08012438, 0, S_OLD, S_NEW, "thirds compare")
add(0x08012478, 0, S_OLD, S_NEW, "thirds compare")
add(0x0801247C, 0, S_OLD, S_NEW, "thirds compare")
add(0x0801248E, 0, S_OLD, S_NEW, "thirds clamp compare")
add(0x08012492, 0, S_OLD, S_NEW, "thirds clamp movhi")
add(0x08012494, 2, S_OLD, S_NEW, "thirds base")
add(0x080124C8, 2, T1_OLD, T1_NEW, "stored = (base+1) - (level+1)   <-- MISSED BEFORE")
add(0x080124DC, 0, T_OLD, T_NEW, "tenths compare")
add(0x080124E0, 2, T_OLD, T_NEW, "tenths compare")
add(0x080124F6, 0, T_OLD, T_NEW, "level clamp compare")
add(0x080124FA, 0, T_OLD, T_NEW, "level clamp movhi")
add(0x080124FC, 2, T_OLD, T_NEW, "stored = base - level")
add(0x080126FA, 2, T_OLD, T_NEW, "stored = base - level")

# ---- editor copy #4 / UI sliders : 0x803Dxxx ------------------------------
add(0x0803D048, 2, T_OLD, T_NEW, "max const (tenths)")
add(0x0803D04C, 2, S_OLD, S_NEW, "max const (thirds)")
add(0x0803D160, 0, T1_OLD, T1_NEW, "slider max = 71        <-- MISSED BEFORE")
add(0x0803D16C, 2, T_OLD, T_NEW, "level = base - stored")
add(0x0803D188, 0, S_OLD, S_NEW, "slider max (thirds)")
add(0x0803D190, 0, S_OLD, S_NEW, "thirds clamp compare")
add(0x0803D19A, 0, T_OLD, T_NEW, "slider max (tenths)")
add(0x0803D1A2, 0, T_OLD, T_NEW, "tenths clamp compare")
add(0x0803D1DC, 2, T_OLD, T_NEW, "level = base - stored")
add(0x0803D296, 0, T1_OLD, T1_NEW, "slider max = 71        <-- MISSED BEFORE")
add(0x0803D2A2, 2, T_OLD, T_NEW, "level = base - stored")
add(0x0803D2BE, 0, S_OLD, S_NEW, "slider max (thirds)")
add(0x0803D2C6, 0, S_OLD, S_NEW, "thirds clamp compare")
add(0x0803D2CC, 0, T_OLD, T_NEW, "slider max (tenths)")
add(0x0803D2D4, 0, T_OLD, T_NEW, "tenths clamp compare")
add(0x0803D308, 2, T_OLD, T_NEW, "level = base - stored")
add(0x0803D354, 2, T_OLD, T_NEW, "stored = base - level")
add(0x0803D400, 0, T1_OLD, T1_NEW, "slider max = 71        <-- MISSED BEFORE")
add(0x0803D46E, 2, T_OLD, T_NEW, "stored = base - level")
add(0x0803D492, 0, S_OLD, S_NEW, "slider max (thirds)")
add(0x0803D49A, 0, S_OLD, S_NEW, "thirds clamp compare")
add(0x0803D49E, 0, S_OLD, S_NEW, "thirds clamp movhi")
add(0x0803D4A6, 0, T_OLD, T_NEW, "slider max (tenths)")
add(0x0803D4AE, 0, T_OLD, T_NEW, "tenths clamp compare")
add(0x0803D4B2, 0, T_OLD, T_NEW, "tenths clamp movhi")


def main():
    data = bytearray(open(SRC, "rb").read())
    if len(data) != IMG + 54:
        sys.exit(f"unexpected container size {len(data)}")
    if hashlib.md5(bytes(data[:IMG])).digest() != bytes(data[IMG:IMG + 16]):
        sys.exit("source MD5 trailer mismatch -- wrong input file?")

    bad = []
    for va, off, old, new, note in P:
        fo = va - BASE + off
        if data[fo] != old:
            bad.append(f"{va:#010x}+{off}: expect {old:#04x}, got {data[fo]:#04x}  ({note})")
            continue
        data[fo] = new
    if bad:
        print("ABORT, unexpected bytes:")
        for b in bad:
            print("  " + b)
        sys.exit(1)

    print(f"patched {len(P)} immediates in the image")

    # ---- version string in the trailer ------------------------------------
    name = bytes(data[IMG + 16:IMG + 16 + 28])
    print("trailer name  :", name)
    if b"V1.07" in name:
        i = name.index(b"V1.07")
        data[IMG + 16 + i + 4] = ord("8")   # "V1.07" -> "V1.08"
        print("trailer name  : ->", bytes(data[IMG + 16:IMG + 16 + 28]))

    data[IMG:IMG + 16] = hashlib.md5(bytes(data[:IMG])).digest()
    open(DST, "wb").write(bytes(data))
    print("wrote", DST)
    print("image md5     :", data[IMG:IMG + 16].hex())
    print("file size     :", len(data))

    # ---- quick self-check: re-disassemble the changed sites --------------
    # capstone is optional; it is only used for this printable report
    try:
        import capstone
    except ImportError:
        print("\n(capstone not installed -- skipping self-check)")
        return
    md = capstone.Cs(capstone.CS_ARCH_ARM,
                     capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)
    print("\nself-check (changed instructions as decoded):")
    seen = set()
    for va, off, old, new, note in P:
        if va in seen:
            continue
        seen.add(va)
        fo = va - BASE
        chunk = bytes(data[fo:fo + 4])
        ins = next(md.disasm(chunk, va), None)
        if ins:
            print(f"  {va:08X} {ins.bytes.hex():<10} {ins.mnemonic:<9} {ins.op_str:<22} {note}")


if __name__ == "__main__":
    main()
