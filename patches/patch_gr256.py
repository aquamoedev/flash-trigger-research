"""Generate a Godox iT30Pro S firmware with per-group power limits.

Result of the patch:
    Gr mode, groups A/B/C  -> tunable down to 1/256 (tenths 80) via touch slider,
                              touch +/- buttons, wheel knob and ALL-group adjust
    Gr mode, group M       -> unchanged floor of 1/128 (tenths 70)
    every other mode       -> untouched

Input : a stock iT30ProS V1.07 container (image + MD5 + name + magic, 688182 B)
Output: same container with a new image MD5

How it works
------------
The firmware stores each group's power as an attenuation value ("tenths") in
byte_2000058C[group] (0 = 1/1, 70 = 1/128, 80 = 1/256, 0xFF = OFF), where
index 0 is the M group and 1..3 are A/B/C.  Stock code clamps that value to
0x46 (70) in a dozen places.  Instead of rewriting every clamp in place, this
script copies the clamp/render/step logic into an unused 64 KB flash tail
(0x0808FA80.., erased 0xFF) and redirects the original sites with BL/B.W
thunks.  The copied helpers read the live mode byte (byte_200003D8 == 3 means
Gr) and the group index, then apply 0x46 for M, 0x50 for A/B/C.

Usage
-----
    python patches/patch_gr256.py                 # firmware/iT30ProS_V1.07.bin
                                                  #   -> firmware/iT30ProS_V1.07_Gr256.bin
    python patches/patch_gr256.py --src in.bin --dst out.bin
    python patches/patch_gr256.py --no-verify     # skip the capstone dump

Requires Python 3.8+.  capstone is optional and only used for the disassembly
report printed at the end.
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

import argparse
import hashlib
import os
import struct
import sys

try:  # optional, used only for the post-patch disassembly report
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
except ImportError:  # pragma: no cover
    Cs = None

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SRC = os.path.join(REPO_ROOT, "firmware", "iT30ProS_V1.07.bin")
DEFAULT_DST = os.path.join(REPO_ROOT, "firmware", "iT30ProS_V1.07_Gr256.bin")


def enc_b_w(pc, target):
    imm = target - (pc + 4)
    assert -0x1000000 <= imm < 0x1000000 and (imm & 1) == 0, f"B.W out of range: {pc:#x} -> {target:#x}"
    s = (imm >> 24) & 1
    j1 = (~((imm >> 23) ^ s)) & 1
    j2 = (~((imm >> 22) ^ s)) & 1
    imm10 = (imm >> 12) & 0x3FF
    imm11 = (imm >> 1) & 0x7FF
    hw1 = 0xF000 | (s << 10) | imm10
    hw2 = 0x9000 | (j1 << 13) | (j2 << 11) | imm11
    return struct.pack("<HH", hw1, hw2)


def enc_bl(pc, target):
    imm = target - (pc + 4)
    assert -0x1000000 <= imm < 0x1000000 and (imm & 1) == 0, f"BL out of range: {pc:#x} -> {target:#x}"
    s = (imm >> 24) & 1
    j1 = (~((imm >> 23) ^ s)) & 1
    j2 = (~((imm >> 22) ^ s)) & 1
    imm10 = (imm >> 12) & 0x3FF
    imm11 = (imm >> 1) & 0x7FF
    hw1 = 0xF000 | (s << 10) | imm10
    hw2 = 0xD000 | (j1 << 13) | (j2 << 11) | imm11
    return struct.pack("<HH", hw1, hw2)


def enc_b_cond16(pc, cond, target):
    imm = target - (pc + 4)
    assert -256 <= imm <= 254 and (imm & 1) == 0, f"Bcond16 out of range: {pc:#x} -> {target:#x}"
    return struct.pack("<H", 0xD000 | (cond << 8) | ((imm >> 1) & 0xFF))


def enc_b16(pc, target):
    imm = target - (pc + 4)
    assert -2048 <= imm <= 2046 and (imm & 1) == 0, f"B16 out of range: {pc:#x} -> {target:#x}"
    return struct.pack("<H", 0xE000 | ((imm >> 1) & 0x7FF))


def enc_cbz(pc, reg, target, nz=False):
    imm = target - (pc + 4)
    assert 0 <= imm <= 126 and (imm & 1) == 0 and reg < 8, f"CBZ out of range: {pc:#x} -> {target:#x}"
    i = (imm >> 6) & 1
    imm5 = (imm >> 1) & 0x1F
    op = 0xB900 if nz else 0xB100
    return struct.pack("<H", op | (i << 9) | (imm5 << 3) | reg)


def enc_ldr_pc_w(pc, rt, target):
    base = (pc + 4) & ~3
    imm = target - base
    assert 0 <= imm < 4096, f"LDR.W PC out of range: {pc:#x} -> {target:#x}"
    return struct.pack("<HH", 0xF8DF, (rt << 12) | imm)


# 16-bit Thumb helpers
NOP = b"\x00\xbf"
BX_LR = b"\x70\x47"


def movs(rd, imm8):
    return struct.pack("<H", 0x2000 | (rd << 8) | imm8)


def mov_reg(rd, rm):
    d = (rd >> 3) & 1
    return struct.pack("<H", 0x4600 | (d << 7) | (rm << 3) | (rd & 7))


def cmp_imm(rn, imm8):
    return struct.pack("<H", 0x2800 | (rn << 8) | imm8)


def cmp_reg(rn, rm):
    # CMP low/high registers: 0x4500 | N<<7 | Rm<<3 | Rn[2:0]
    n = (rn >> 3) & 1
    return struct.pack("<H", 0x4500 | (n << 7) | (rm << 3) | (rn & 7))


def adds_imm8(rd, imm8):
    return struct.pack("<H", 0x3000 | (rd << 8) | imm8)


def adds_imm3(rd, rn, imm3):
    return struct.pack("<H", 0x1C00 | (imm3 << 6) | (rn << 3) | rd)


def sub_w_imm(rd, rn, imm12):
    # Thumb-2 SUB.W Rd, Rn, #imm12 (no flags, T3 encoding: 1111 0 i 0 1101 0 Rn | 0 imm3 Rd imm8)
    assert 0 <= imm12 < 256
    return struct.pack("<HH", 0xF1A0 | rn, (rd << 8) | imm12)


def sub_reg16(rd, rn, rm):
    return struct.pack("<H", 0x1A00 | (rm << 6) | (rn << 3) | rd)


def rsb_w_imm(rd, rn, imm8):
    # RSB.W Rd, Rn, #imm8 (no flags): 0xF1C0 | Rn, (Rd << 8) | imm8
    return struct.pack("<HH", 0xF1C0 | rn, (rd << 8) | imm8)


def ldrb_reg16(rt, rn, rm):
    return struct.pack("<H", 0x5C00 | (rm << 6) | (rn << 3) | rt)


def ldrb_imm16(rt, rn, imm5=0):
    return struct.pack("<H", 0x7800 | (imm5 << 6) | (rn << 3) | rt)


def strb_reg16(rt, rn, rm):
    return struct.pack("<H", 0x5400 | (rm << 6) | (rn << 3) | rt)


def ldrb_w_reg(rt, rn, rm):
    return struct.pack("<HH", 0xF810 | rn, (rt << 12) | rm)


def strb_w_reg(rt, rn, rm):
    return struct.pack("<HH", 0xF800 | rn, (rt << 12) | rm)


def ldr_w_imm(rt, rn, imm12):
    return struct.pack("<HH", 0xF8D0 | rn, (rt << 12) | imm12)


def tst_w_imm(rn, imm8):
    # TST.W Rn, #imm8 (T1: 1111 0 i 0 0000 1 Rn | 0 imm3 1111 imm8)
    return struct.pack("<HH", 0xF010 | rn, 0x0F00 | imm8)


def uxtb16(rd, rm):
    return struct.pack("<H", 0xB2C0 | (rm << 3) | rd)


def push16(regmask, lr=False):
    return struct.pack("<H", 0xB400 | (0x100 if lr else 0) | regmask)


def pop16(regmask, pc=False):
    return struct.pack("<H", 0xBC00 | (0x100 if pc else 0) | regmask)


def it_enc(firstcond, pat):
    # pat is e.g. "T", "TT", "TE", "TTT"
    p0 = firstcond & 1
    bits = [p0]
    for ch in pat[1:]:
        bits.append(p0 if ch == "T" else (p0 ^ 1))
    bits.append(1)
    while len(bits) < 5:
        bits.append(0)
    mask = (bits[1] << 3) | (bits[2] << 2) | (bits[3] << 1) | bits[4]
    return struct.pack("<H", 0xBF00 | (firstcond << 4) | mask)


# Condition codes
COND_EQ = 0x0
COND_NE = 0x1
COND_LO = 0x3  # CC
COND_HI = 0x8
COND_LS = 0x9


class Assembler:
    def __init__(self, base_addr):
        self.base = base_addr
        self.buf = bytearray()
        self.labels = {}
        self.fixups = []
        self.literals = {}
        self.lit_fixups = []

    def pc(self):
        return self.base + len(self.buf)

    def label(self, name):
        assert name not in self.labels, f"Duplicate label {name}"
        self.labels[name] = self.pc()

    def emit(self, raw):
        self.buf.extend(raw)

    def align4(self):
        while (self.pc() & 3) != 0:
            self.emit(b"\x00\xbf")

    def b_cond(self, cond, target):
        p = self.pc()
        self.emit(b"\x00\x00")
        self.fixups.append(("bcond16", p, cond, target))

    def b16(self, target):
        p = self.pc()
        self.emit(b"\x00\x00")
        self.fixups.append(("b16", p, None, target))

    def b_w(self, target):
        p = self.pc()
        self.emit(b"\x00\x00\x00\x00")
        self.fixups.append(("b_w", p, None, target))

    def bl(self, target):
        p = self.pc()
        self.emit(b"\x00\x00\x00\x00")
        self.fixups.append(("bl", p, None, target))

    def cbz(self, reg, target):
        p = self.pc()
        self.emit(b"\x00\x00")
        self.fixups.append(("cbz", p, reg, target))

    def ldr_lit(self, rt, val):
        p = self.pc()
        self.emit(b"\x00\x00\x00\x00")
        self.lit_fixups.append((p, rt, val))

    def finalize(self):
        self.align4()
        lit_addrs = {}
        for _, _, val in self.lit_fixups:
            if val not in lit_addrs:
                lit_addrs[val] = self.pc()
                self.emit(struct.pack("<I", val))
        for kind, p, extra, target in self.fixups:
            t = self.labels[target] if isinstance(target, str) else target
            off = p - self.base
            if kind == "bcond16":
                self.buf[off:off+2] = enc_b_cond16(p, extra, t)
            elif kind == "b16":
                self.buf[off:off+2] = enc_b16(p, t)
            elif kind == "b_w":
                self.buf[off:off+4] = enc_b_w(p, t)
            elif kind == "bl":
                self.buf[off:off+4] = enc_bl(p, t)
            elif kind == "cbz":
                self.buf[off:off+2] = enc_cbz(p, extra, t)
        for p, rt, val in self.lit_fixups:
            off = p - self.base
            self.buf[off:off+4] = enc_ldr_pc_w(p, rt, lit_addrs[val])
        return bytes(self.buf)


def build_cave(cave_base):
    a = Assembler(cave_base)

    # 1a. sub_800AA2C HSS hook (from 0x0800AA6C)
    # R0 = index (1..5), R3 = &byte_2000058C, R5 = 0x46, return to 0x0800AA9E
    a.label("cave_aa_hss")
    a.emit(ldrb_reg16(1, 3, 0))          # ldrb r1, [r3, r0]
    a.emit(cmp_imm(0, 3))                # cmp r0, #3
    a.b_cond(COND_HI, "aa_chk_46")       # bhi -> 0x46 limit for unused D/E
    a.emit(cmp_imm(1, 0x50))             # cmp r1, #0x50
    a.b_cond(COND_LS, "aa_done")         # bls -> ok
    a.emit(cmp_imm(1, 0xFF))             # cmp r1, #0xFF
    a.b_cond(COND_EQ, "aa_done")         # beq -> ok
    a.emit(movs(1, 0x50))                # movs r1, #0x50
    a.emit(strb_reg16(1, 3, 0))          # strb r1, [r3, r0]
    a.b_w(0x0800AA9E)

    # 1b. sub_800AA2C non-HSS hook (from 0x0800AA92)
    # R0 = index (0..5), R2 = byte_200003D8, R3 = &byte_2000058C, R5 = 0x46
    a.label("cave_aa_nonhss")
    a.emit(ldrb_reg16(1, 3, 0))          # ldrb r1, [r3, r0]
    a.emit(cmp_imm(2, 3))                # cmp r2, #3 (Gr mode?)
    a.b_cond(COND_NE, "aa_chk_46")
    a.cbz(0, "aa_chk_46")                # M (index 0) stays 0x46
    a.emit(cmp_imm(0, 3))                # D/E (index > 3) stays 0x46
    a.b_cond(COND_HI, "aa_chk_46")
    a.emit(cmp_imm(1, 0x50))
    a.b_cond(COND_LS, "aa_done")
    a.emit(cmp_imm(1, 0xFF))
    a.b_cond(COND_EQ, "aa_done")
    a.emit(movs(1, 0x50))
    a.emit(strb_reg16(1, 3, 0))
    a.b_w(0x0800AA9E)

    a.label("aa_chk_46")
    a.emit(cmp_imm(1, 0x46))
    a.b_cond(COND_LS, "aa_done")
    a.emit(cmp_imm(1, 0xFF))
    a.b_cond(COND_EQ, "aa_done")
    a.emit(strb_reg16(5, 3, 0))
    a.label("aa_done")
    a.b_w(0x0800AA9E)

    # 2. sub_800D048 EEPROM load clamp (called via BL from 0x0800D15A)
    # R4 = index (0..5), R12 = &byte_2000058C, R2 = 0x46; preserve R1, R2, R3, R4, R12
    a.label("cave_d048")
    a.emit(push16(1 << 1))               # push {r1}
    a.cbz(4, "d0_46")
    a.emit(cmp_imm(4, 3))
    a.b_cond(COND_HI, "d0_46")
    a.ldr_lit(1, 0x200003D8)
    a.emit(ldrb_imm16(1, 1, 0))
    a.emit(cmp_imm(1, 3))
    a.b_cond(COND_NE, "d0_46")
    a.emit(movs(1, 0x50))
    a.b16("d0_cmp")
    a.label("d0_46")
    a.emit(mov_reg(1, 2))                # mov r1, r2 (#0x46)
    a.label("d0_cmp")
    a.emit(ldrb_w_reg(0, 12, 4))         # ldrb.w r0, [r12, r4]
    a.emit(cmp_reg(0, 1))                # cmp r0, r1
    a.emit(it_enc(COND_HI, "T"))         # it hi
    a.emit(strb_w_reg(1, 12, 4))         # strbhi.w r1, [r12, r4]
    a.emit(pop16(1 << 1))                # pop {r1}
    a.emit(BX_LR)

    # 3. sub_800ABCC display clamp (called via BL from 0x0800ABE4)
    # R0 = *R8, R8 = a8; R1 is scratch
    a.label("cave_abcc")
    a.ldr_lit(1, 0x200003D8)
    a.emit(ldrb_imm16(1, 1, 0))
    a.emit(cmp_imm(1, 3))
    a.b_cond(COND_NE, "ab_46")
    a.ldr_lit(1, 0x2000058D)             # &byte_2000058C[1] (Group A)
    a.emit(cmp_reg(8, 1))
    a.b_cond(COND_LO, "ab_46")
    a.emit(adds_imm8(1, 2))              # &byte_2000058C[3] (Group C)
    a.emit(cmp_reg(8, 1))
    a.b_cond(COND_HI, "ab_46")
    a.emit(movs(1, 0x50))
    a.b16("ab_cmp")
    a.label("ab_46")
    a.emit(movs(1, 0x46))
    a.label("ab_cmp")
    a.emit(cmp_reg(0, 1))
    a.b_cond(COND_LS, "ab_ret")
    a.emit(cmp_imm(0, 0xFF))
    a.emit(it_enc(COND_NE, "TT"))        # itt ne
    a.emit(mov_reg(0, 1))
    a.emit(struct.pack("<HH", 0xF888, 0x0000))  # strbne.w r0, [r8, #0]
    a.label("ab_ret")
    a.emit(BX_LR)

    # 4a. sub_8014E40 end clamp (jumped via B.W from 0x08014FB2)
    # R1 = candidate result; returns R0
    a.label("cave_14e40_end")
    a.ldr_lit(0, 0x200003D8)
    a.emit(ldrb_imm16(0, 0, 0))
    a.emit(cmp_imm(0, 3))
    a.b_cond(COND_NE, "e40_non_gr")
    a.emit(cmp_imm(1, 0x50))
    a.b_cond(COND_LS, "e40_ret")
    a.emit(cmp_imm(1, 0xFF))
    a.emit(it_enc(COND_NE, "T"))         # it ne
    a.emit(movs(1, 0x50))
    a.b16("e40_ret")
    a.label("e40_non_gr")
    a.ldr_lit(0, 0x20000580)
    a.emit(ldrb_imm16(0, 0, 0))
    a.emit(tst_w_imm(0, 0x10))
    a.emit(it_enc(COND_NE, "TE"))        # ite ne
    a.emit(movs(0, 0x28))
    a.emit(movs(0, 0x46))
    a.emit(cmp_reg(1, 0))
    a.b_cond(COND_LS, "e40_ret")
    a.emit(cmp_imm(1, 0xFF))
    a.emit(it_enc(COND_NE, "T"))         # it ne
    a.emit(mov_reg(1, 0))
    a.label("e40_ret")
    a.emit(mov_reg(0, 1))
    a.emit(BX_LR)

    # 4b. Gr-mode M-clamp store helpers
    # cave_store_r4_r1_r3: R0=val, R4=&byte_2000058C, R3=&byte_20000572, R2=scratch
    a.label("cave_store_r4_r1_r3")
    a.emit(ldrb_imm16(1, 3, 0))
    a.emit(cmp_imm(1, 0))
    a.b_cond(COND_EQ, "m_clamp_r2")
    a.emit(cmp_imm(1, 3))
    a.b_cond(COND_HI, "m_clamp_r2")
    a.b16("st_r4_do")
    a.label("m_clamp_r2")
    a.ldr_lit(2, 0x20000580)
    a.emit(ldrb_imm16(2, 2, 0))
    a.emit(tst_w_imm(2, 0x10))
    a.emit(it_enc(COND_NE, "TE"))
    a.emit(movs(2, 0x28))
    a.emit(movs(2, 0x46))
    a.emit(cmp_reg(0, 2))
    a.b_cond(COND_LS, "st_r4_do")
    a.emit(cmp_imm(0, 0xFF))
    a.emit(it_enc(COND_NE, "T"))
    a.emit(mov_reg(0, 2))
    a.label("st_r4_do")
    a.emit(strb_reg16(0, 4, 1))
    a.emit(BX_LR)

    # cave_store_r5_r1_r4: R0=val, R5=&byte_2000058C, R4=&byte_20000572, R2=scratch
    a.label("cave_store_r5_r1_r4")
    a.emit(ldrb_imm16(1, 4, 0))
    a.emit(cmp_imm(1, 0))
    a.b_cond(COND_EQ, "m_clamp_r2_r5")
    a.emit(cmp_imm(1, 3))
    a.b_cond(COND_HI, "m_clamp_r2_r5")
    a.b16("st_r5_do")
    a.label("m_clamp_r2_r5")
    a.ldr_lit(2, 0x20000580)
    a.emit(ldrb_imm16(2, 2, 0))
    a.emit(tst_w_imm(2, 0x10))
    a.emit(it_enc(COND_NE, "TE"))
    a.emit(movs(2, 0x28))
    a.emit(movs(2, 0x46))
    a.emit(cmp_reg(0, 2))
    a.b_cond(COND_LS, "st_r5_do")
    a.emit(cmp_imm(0, 0xFF))
    a.emit(it_enc(COND_NE, "T"))
    a.emit(mov_reg(0, 2))
    a.label("st_r5_do")
    a.emit(strb_reg16(0, 5, 1))
    a.emit(BX_LR)

    # cave_14bd8_step: calls sub_8014E40, clamps R0 to 0x28/0x46 if R3 == 0 (or > 3)
    a.label("cave_14bd8_step")
    a.emit(push16(1 << 3, lr=True))      # push {r3, lr}
    a.bl(0x08014E40)
    a.emit(struct.pack("<H", 0x9A00))    # ldr r2, [sp, #0] (old r3)
    a.emit(cmp_imm(2, 0))
    a.b_cond(COND_EQ, "bd8_clamp")
    a.emit(cmp_imm(2, 3))
    a.b_cond(COND_HI, "bd8_clamp")
    a.emit(pop16(1 << 3, pc=True))       # pop {r3, pc}
    a.label("bd8_clamp")
    a.ldr_lit(2, 0x20000580)
    a.emit(ldrb_imm16(2, 2, 0))
    a.emit(tst_w_imm(2, 0x10))
    a.emit(it_enc(COND_NE, "TE"))
    a.emit(movs(2, 0x28))
    a.emit(movs(2, 0x46))
    a.emit(cmp_reg(0, 2))
    a.b_cond(COND_LS, "bd8_ret")
    a.emit(cmp_imm(0, 0xFF))
    a.emit(it_enc(COND_NE, "T"))
    a.emit(mov_reg(0, 2))
    a.label("bd8_ret")
    a.emit(pop16(1 << 3, pc=True))       # pop {r3, pc}

    # 5. sub_803D014 helpers (R4 = group 0..3)
    a.label("cave_3d_bar_max")
    a.emit(cmp_imm(4, 0))
    a.emit(it_enc(COND_EQ, "TE"))        # ite eq
    a.emit(movs(2, 0x47))
    a.emit(movs(2, 0x51))
    a.emit(ldr_w_imm(0, 11, 0x68))       # ldr.w r0, [r11, #0x68]
    a.emit(BX_LR)

    a.label("cave_3d_bar_val")
    a.emit(cmp_imm(4, 0))
    a.emit(it_enc(COND_EQ, "TE"))        # ite eq
    a.emit(movs(1, 0x46))
    a.emit(movs(1, 0x50))
    a.emit(sub_reg16(0, 1, 0))           # subs r0, r1, r0
    a.emit(uxtb16(0, 0))
    a.emit(BX_LR)

    a.label("cave_3d_s03")
    a.emit(push16(1 << 4, lr=True))
    a.emit(cmp_imm(4, 0))
    a.emit(it_enc(COND_EQ, "TE"))
    a.emit(movs(2, 0x15))
    a.emit(movs(2, 0x18))
    a.bl(0x080267D0)
    a.emit(cmp_imm(4, 0))
    a.emit(it_enc(COND_EQ, "TE"))
    a.emit(movs(2, 0x15))
    a.emit(movs(2, 0x18))
    a.emit(ldrb_reg16(0, 5, 4))
    a.emit(cmp_reg(0, 2))
    a.emit(it_enc(COND_HI, "TT"))        # itt hi
    a.emit(mov_reg(0, 2))
    a.emit(strb_reg16(0, 5, 4))
    a.emit(pop16(1 << 4, pc=True))

    a.label("cave_3d_s01")
    a.emit(push16(1 << 4, lr=True))
    a.emit(cmp_imm(4, 0))
    a.emit(it_enc(COND_EQ, "TE"))
    a.emit(movs(2, 0x46))
    a.emit(movs(2, 0x50))
    a.bl(0x080267D0)
    a.emit(cmp_imm(4, 0))
    a.emit(it_enc(COND_EQ, "TE"))
    a.emit(movs(2, 0x46))
    a.emit(movs(2, 0x50))
    a.emit(ldrb_reg16(0, 5, 4))
    a.emit(cmp_reg(0, 2))
    a.emit(it_enc(COND_HI, "TT"))
    a.emit(mov_reg(0, 2))
    a.emit(strb_reg16(0, 5, 4))
    a.emit(pop16(1 << 4, pc=True))

    # 6. sub_800E72C helpers (R1 = byte_20000572, MUST preserve R1 and NOT clobber R12/R10/flags unexpectedly!)
    # 6a. 0x800E954: RSB.W R2, R2, #(0x46/0x50); UXTB R2, R2 -- MUST NOT TOUCH FLAGS!
    a.label("cave_e954")
    a.cbz(1, "e954_m")
    a.emit(rsb_w_imm(2, 2, 0x50))
    a.emit(uxtb16(2, 2))
    a.emit(BX_LR)
    a.label("e954_m")
    a.emit(rsb_w_imm(2, 2, 0x46))
    a.emit(uxtb16(2, 2))
    a.emit(BX_LR)

    # 6b. 0x800E966: CMP R0, #max03; ITE EQ; CMPEQ.W R11, #max03; CMPNE R0, R11 (sets CPSR for BCS)
    a.label("cave_e966")
    a.cbz(1, "e966_m")
    a.emit(cmp_imm(0, 0x18))
    a.emit(it_enc(COND_EQ, "TE"))        # ite eq
    a.emit(struct.pack("<HH", 0xF1BB, 0x0F18))  # cmp.w r11, #0x18
    a.emit(cmp_reg(0, 11))               # cmp r0, r11
    a.emit(BX_LR)
    a.label("e966_m")
    a.emit(cmp_imm(0, 0x15))
    a.emit(it_enc(COND_EQ, "TE"))
    a.emit(struct.pack("<HH", 0xF1BB, 0x0F15))  # cmp.w r11, #0x15
    a.emit(cmp_reg(0, 11))
    a.emit(BX_LR)

    # 6c. 0x800E9A8: CMP R0, #max03; ITTT EQ; LDRBEQ.W R10, [R5,R1]; CMPEQ.W R10, #max03; ADDEQ R0, R2, #1
    a.label("cave_e9a8")
    a.cbz(1, "e9a8_m")
    a.emit(cmp_imm(0, 0x18))
    a.emit(it_enc(COND_EQ, "TTT"))       # ittt eq
    a.emit(struct.pack("<HH", 0xF815, 0xA001))  # ldrb.w r10, [r5, r1]
    a.emit(struct.pack("<HH", 0xF1BA, 0x0F18))  # cmp.w r10, #0x18
    a.emit(struct.pack("<H", 0x1C50))    # add r0, r2, #1 (inside IT block: ADDEQ R0, R2, #1, no flags!)
    a.emit(BX_LR)
    a.label("e9a8_m")
    a.emit(cmp_imm(0, 0x15))
    a.emit(it_enc(COND_EQ, "TTT"))
    a.emit(struct.pack("<HH", 0xF815, 0xA001))  # ldrb.w r10, [r5, r1]
    a.emit(struct.pack("<HH", 0xF1BA, 0x0F15))  # cmp.w r10, #0x15
    a.emit(struct.pack("<H", 0x1C50))
    a.emit(BX_LR)

    # 6d. 0x800E9BC: CMP R0, #max01; ITTT EQ; LDRBEQ.W R12, [R5,R1]; CMPEQ.W R12, #max01; ADDEQ R0, R2, #1
    a.label("cave_e9bc")
    a.cbz(1, "e9bc_m")
    a.emit(cmp_imm(0, 0x50))
    a.emit(it_enc(COND_EQ, "TTT"))       # ittt eq
    a.emit(struct.pack("<HH", 0xF815, 0xC001))  # ldrb.w r12, [r5, r1]
    a.emit(struct.pack("<HH", 0xF1BC, 0x0F50))  # cmp.w r12, #0x50
    a.emit(struct.pack("<H", 0x1C50))    # addeq r0, r2, #1
    a.emit(BX_LR)
    a.label("e9bc_m")
    a.emit(cmp_imm(0, 0x46))
    a.emit(it_enc(COND_EQ, "TTT"))
    a.emit(struct.pack("<HH", 0xF815, 0xC001))  # ldrb.w r12, [r5, r1]
    a.emit(struct.pack("<HH", 0xF1BC, 0x0F46))  # cmp.w r12, #0x46
    a.emit(struct.pack("<H", 0x1C50))
    a.emit(BX_LR)

    # 6e. 0x800E9EA: CMP R2, #max01; IT HI; MOVHI R2, #max01
    a.label("cave_e9ea")
    a.cbz(1, "e9ea_m")
    a.emit(cmp_imm(2, 0x50))
    a.emit(it_enc(COND_HI, "T"))
    a.emit(movs(2, 0x50))
    a.emit(BX_LR)
    a.label("e9ea_m")
    a.emit(cmp_imm(2, 0x46))
    a.emit(it_enc(COND_HI, "T"))
    a.emit(movs(2, 0x46))
    a.emit(BX_LR)

    # 6f. 0x800E9F0: RSB.W R0, R2, #max01; STRB R0, [R3, R1]
    a.label("cave_e9f0")
    a.cbz(1, "e9f0_m")
    a.emit(rsb_w_imm(0, 2, 0x50))
    a.emit(strb_reg16(0, 3, 1))
    a.emit(BX_LR)
    a.label("e9f0_m")
    a.emit(rsb_w_imm(0, 2, 0x46))
    a.emit(strb_reg16(0, 3, 1))
    a.emit(BX_LR)

    # 6g. 0x800EA90: CMP R2, #max03; IT HI; MOVHI R2, #max03
    a.label("cave_ea90")
    a.cbz(1, "ea90_m")
    a.emit(cmp_imm(2, 0x18))
    a.emit(it_enc(COND_HI, "T"))
    a.emit(movs(2, 0x18))
    a.emit(BX_LR)
    a.label("ea90_m")
    a.emit(cmp_imm(2, 0x15))
    a.emit(it_enc(COND_HI, "T"))
    a.emit(movs(2, 0x15))
    a.emit(BX_LR)

    # 6h. 0x800EA96: RSB.W R0, R2, #max03; UXTB R0, R0
    a.label("cave_ea96")
    a.cbz(1, "ea96_m")
    a.emit(rsb_w_imm(0, 2, 0x18))
    a.emit(uxtb16(0, 0))
    a.emit(BX_LR)
    a.label("ea96_m")
    a.emit(rsb_w_imm(0, 2, 0x15))
    a.emit(uxtb16(0, 0))
    a.emit(BX_LR)

    # 6i. 0x800EACA: RSB.W R0, R0, #max01
    a.label("cave_eaca")
    a.cbz(1, "eaca_m")
    a.emit(rsb_w_imm(0, 0, 0x50))
    a.emit(BX_LR)
    a.label("eaca_m")
    a.emit(rsb_w_imm(0, 0, 0x46))
    a.emit(BX_LR)

    cave_bytes = a.finalize()
    return cave_bytes, a.labels


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--src", default=DEFAULT_SRC, help="stock V1.07 container")
    ap.add_argument("--dst", default=DEFAULT_DST, help="output container")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip the disassembly report")
    args = ap.parse_args(argv)

    orig = open(args.src, "rb").read()
    assert len(orig) == 0xA8036
    assert hashlib.md5(orig[:0xA8000]).digest() == orig[0xA8000:0xA8010], "Original MD5 mismatch!"

    cave_addr = 0x0808FA80
    cave_bytes, labels = build_cave(cave_addr)
    print(f"Code cave @ 0x{cave_addr:08X}, size = {len(cave_bytes)} bytes (ends 0x{cave_addr+len(cave_bytes):08X})")
    assert all(x == 0xFF for x in orig[cave_addr - 0x08000000 : cave_addr - 0x08000000 + len(cave_bytes)]), "Cave area not 0xFF!"

    fw = bytearray(orig)

    def patch(va, data, expected_len=None):
        off = va - 0x08000000
        if expected_len is not None:
            assert len(data) == expected_len, f"Patch size mismatch at {va:#x}: {len(data)} != {expected_len}"
        fw[off : off + len(data)] = data

    # Write cave
    patch(cave_addr, cave_bytes)

    # 1. sub_800AA2C
    patch(0x0800AA6C, enc_b_w(0x0800AA6C, labels["cave_aa_hss"]) + NOP * 4, 12)
    patch(0x0800AA92, enc_b_w(0x0800AA92, labels["cave_aa_nonhss"]) + NOP * 4, 12)

    # 2. sub_800D048
    patch(0x0800D15A, enc_bl(0x0800D15A, labels["cave_d048"]) + NOP * 4, 12)

    # 3. sub_800ABCC
    patch(0x0800ABE4, enc_bl(0x0800ABE4, labels["cave_abcc"]) + enc_b16(0x0800ABE8, 0x0800ABF2) + NOP * 4, 14)

    # 4. sub_8014E40 + Gr callers
    patch(0x08014FB2, enc_b_w(0x08014FB2, labels["cave_14e40_end"]), 4)
    patch(0x08008F82, enc_bl(0x08008F82, labels["cave_store_r4_r1_r3"]), 4)
    patch(0x08008FA4, enc_bl(0x08008FA4, labels["cave_store_r4_r1_r3"]), 4)
    patch(0x0800236A, enc_bl(0x0800236A, labels["cave_store_r4_r1_r3"]), 4)
    patch(0x08002388, enc_bl(0x08002388, labels["cave_store_r4_r1_r3"]), 4)
    patch(0x0800DFBC, enc_bl(0x0800DFBC, labels["cave_store_r5_r1_r4"]), 4)
    patch(0x0800DFCA, enc_bl(0x0800DFCA, labels["cave_store_r5_r1_r4"]), 4)
    patch(0x0800E000, enc_bl(0x0800E000, labels["cave_store_r5_r1_r4"]), 4)
    patch(0x0800E022, enc_bl(0x0800E022, labels["cave_store_r5_r1_r4"]), 4)
    patch(0x08014CC2, enc_bl(0x08014CC2, labels["cave_14bd8_step"]), 4)
    patch(0x08014D40, enc_bl(0x08014D40, labels["cave_14bd8_step"]), 4)

    # 5. sub_803D014
    patch(0x0803D400, enc_bl(0x0803D400, labels["cave_3d_bar_max"]) + NOP, 6)
    patch(0x0803D46E, enc_bl(0x0803D46E, labels["cave_3d_bar_val"]) + NOP, 6)
    patch(0x0803D492, enc_bl(0x0803D492, labels["cave_3d_s03"]) + enc_b16(0x0803D496, 0x0803D4F4) + NOP * 5, 16)
    patch(0x0803D4A6, enc_bl(0x0803D4A6, labels["cave_3d_s01"]) + enc_b16(0x0803D4AA, 0x0803D4F4) + NOP * 6, 18)

    # 6. sub_800E72C
    patch(0x0800E954, enc_bl(0x0800E954, labels["cave_e954"]) + NOP, 6)
    patch(0x0800E966, enc_bl(0x0800E966, labels["cave_e966"]) + NOP * 3, 10)
    patch(0x0800E9A8, enc_bl(0x0800E9A8, labels["cave_e9a8"]) + NOP * 5, 14)
    patch(0x0800E9BC, enc_bl(0x0800E9BC, labels["cave_e9bc"]) + NOP * 5, 14)
    patch(0x0800E9EA, enc_bl(0x0800E9EA, labels["cave_e9ea"]) + NOP, 6)
    patch(0x0800E9F0, enc_bl(0x0800E9F0, labels["cave_e9f0"]) + NOP, 6)
    patch(0x0800EA90, enc_bl(0x0800EA90, labels["cave_ea90"]) + NOP, 6)
    patch(0x0800EA96, enc_bl(0x0800EA96, labels["cave_ea96"]) + NOP, 6)
    patch(0x0800EACA, enc_bl(0x0800EACA, labels["cave_eaca"]), 4)

    # Update MD5 at 0x0A8000..0x0A8010
    new_md5 = hashlib.md5(fw[:0xA8000]).digest()
    fw[0xA8000:0xA8010] = new_md5
    print("New MD5:", new_md5.hex())

    out_path = args.dst
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "wb") as fh:
        fh.write(fw)
    print("Wrote", out_path)

    if args.no_verify or Cs is None:
        if Cs is None and not args.no_verify:
            print("(capstone not installed -- skipping disassembly report)")
        return 0

    # Disassemble the code cave so the generated thunks can be reviewed
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    print("\n=== Disassembly of Code Cave ===")
    inv_labels = {v: k for k, v in labels.items()}
    for ins in md.disasm(cave_bytes, cave_addr):
        lbl = inv_labels.get(ins.address, "")
        if lbl:
            print(f"{lbl}:")
        print(f"  0x{ins.address:08X}: {ins.mnemonic:<10} {ins.op_str}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
