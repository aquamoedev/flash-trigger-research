# Godox iT30Pro S — firmware patch toolkit

[中文](README.md) ・ English ・ [power model](docs/power-model.md) ・ [flashing skill](skills/godox-it30pro-flash/SKILL.md)

Reverse-engineering notes, firmware generation scripts and a from-scratch IAP
flasher for the Godox **iT30Pro S** (and its siblings sharing the
`iT30ProSiT30SV480S` image: iT30Pro C/N/F/O, iT30S, V480 series).

The one shipped feature: **Gr (group) mode — groups A/B/C can be dialled down to
`1/256`, while group M (the on-camera flash) keeps its stock `1/128` floor.**

> ⚠️ Vendor firmware, upgrade packages and manuals are proprietary and are **not**
> distributed here. `firmware/` and `tmp/` are git-ignored on purpose — see
> [Getting the stock image](#getting-the-stock-image).

---

## ⚠️ Disclaimer

**Read this before you flash anything. Writing firmware can brick the device and
you do so entirely at your own risk.**

1. **Unofficial.** This project has **no affiliation with, endorsement by, or
   licence from** Godox or any of its affiliates or resellers. Product and model
   names are used only to describe compatibility and belong to their respective
   owners.
2. **No warranty.** The project is provided **"as is"**, without warranty of any
   kind, express or implied, including merchantability, fitness for a particular
   purpose, or non-infringement.
3. **Your risk.** Flashing can leave the device unbootable or misbehaving because
   of power loss, a bad cable, a mismatched image, or a defect in the image
   itself, and may void the manufacturer warranty. The authors and contributors
   are **not liable** for any direct, indirect, incidental, special or
   consequential damage, including device damage, lost time, lost shots or lost
   revenue.
4. **No vendor firmware here.** This repository does **not** contain or
   redistribute Godox firmware, upgrade packages, manuals or decompiled output.
   Obtain the stock image yourself through legal means and keep it locally.
5. **Your own hardware only.** Use this only on hardware you legally own. Do not
   use it to circumvent technical protection measures, to modify someone else's
   device, or for commercial resale of modified units.
6. **Local law.** Radio transmitting equipment is regulated; output power, bands
   and use cases differ by jurisdiction. You are responsible for compliance where
   you operate.
7. **Back up first.** Keep a copy of the stock container and make sure you can
   re-enter upgrade mode (power off → hold `MENU` → plug in USB) before you start.
   The IAP bootloader is outside the writable image, but an interrupted write
   leaves the application area incomplete until you flash again.
8. **No support obligation.** The authors are under no obligation to provide
   support, updates or fixes.
9. **Acceptance.** Downloading, building or flashing anything from this project
   means you have read, understood and accepted all of the above.

---

## Repository layout

```
.
├── README.md                   Chinese README
├── README.en.md                this file
├── LICENSE                     GNU GPL v3
├── .gitignore / .gitattributes
├── docs/
│   └── power-model.md          power encoding, clamp inventory, patch design
├── patches/
│   ├── patch_gr256.py          ← the feature: Gr A/B/C = 1/256, M = 1/128
│   ├── patch_256_v2.py         historical: tenths/thirds base constants
│   └── patch_256_v3.py         historical: v2 + the 18 tenths clamps
├── skills/
│   └── godox-it30pro-flash/
│       ├── SKILL.md            protocol, safety rules, power model summary
│       └── scripts/
│           ├── godox_iap.py    HID IAP tool: query / read / erase+flash
│           └── hid_scan.py     HID enumeration helper (used by godox_iap)
├── firmware/                   (git-ignored) stock + generated containers,
│                               the official upgrade package and vendor manuals
└── tmp/                        (git-ignored) analysis scratch
```

Only source, docs and scripts belong in git. Recovered firmware images, USB
captures, IDA databases and vendor documents stay local.

---

## Requirements

* Python **3.8+** — the flasher is pure standard library (`ctypes` against
  `hid.dll` / `kernel32`), no `pip install` needed.
* Windows (the HID transport is Win32; the IAP protocol itself is portable).
* `capstone` — **optional**. `patches/patch_gr256.py` uses it only to print a
  disassembly report of the generated code cave (`--no-verify` skips it).

---

## Getting the stock image

Put the stock container here (any official V1.07 package works):

```
firmware/iT30ProS_V1.07.bin      688182 bytes
```

An official package is itself this container, so an upgrade `.zip` only needs to
be unzipped. Sanity check:

```bash
python - <<'PY'
import hashlib
d = open("firmware/iT30ProS_V1.07.bin", "rb").read()
assert len(d) == 688182
assert hashlib.md5(d[:0xA8000]).digest() == d[0xA8000:0xA8010]
print("ok:", d[0xA8010:0xA802C].decode())
PY
```

---

## Generate the patched firmware

```bash
python patches/patch_gr256.py
# firmware/iT30ProS_V1.07.bin
#   -> firmware/iT30ProS_V1.07_Gr256.bin
```

Options:

```bash
python patches/patch_gr256.py --src in.bin --dst out.bin   # explicit paths
python patches/patch_gr256.py --no-verify                  # no capstone report
```

The script verifies the input MD5, asserts the code cave is still erased `0xFF`,
applies 22 thunk rewrites plus the 640-byte helper library, and recomputes the
container MD5. A successful, unmodified stock input reproduces:

```
image MD5  36a1974b9bfadccb9869cdcb87925b64
file  MD5  de49a9d3a406dc2087a17c61cdcc6280
```

The historical scripts in the same folder (`patch_256_v2.py`,
`patch_256_v3.py`) are kept for provenance and read/write the same
`firmware/` folder. They widen the limits for *every* group (including M) and
are superseded by `patch_gr256.py`.

---

## Flash it

The device must be in upgrade (IAP) mode:

* power off → hold **MENU** → plug in USB (works even with a broken app image), or
* power on → menu → *device info* → *firmware upgrade*.

The device enumerates as HID **VID `0x0483` / PID `0x572B`**.

```bash
# 1. confirm the device answers (non-destructive)
python skills/godox-it30pro-flash/scripts/godox_iap.py --query

# 2. dry run: validate the container and build the packets without sending
python skills/godox-it30pro-flash/scripts/godox_iap.py \
    --flash firmware/iT30ProS_V1.07_Gr256.bin --i-know-this-bricks --dry-run

# 3. flash
python skills/godox-it30pro-flash/scripts/godox_iap.py \
    --flash firmware/iT30ProS_V1.07_Gr256.bin --i-know-this-bricks
```

Expected output: one `0x03` erase ACK, then `673/673` blocks each ACKed with
`0x05`. **Every block must ACK** — the tool aborts on the first missing ACK, so
a failure leaves the device recoverable by re-entering IAP mode.

Close the official Godox updater first; it grabs the same HID device.

### Restoring stock

Flash the unmodified container the same way:

```bash
python skills/godox-it30pro-flash/scripts/godox_iap.py \
    --flash firmware/iT30ProS_V1.07.bin --i-know-this-bricks
```

The IAP bootloader lives outside the writable image, so the device can always
re-enter upgrade mode.

---

## Verify on the device

1. Gr mode → group **A / B / C**: touch slider, touch `+`/`-`, wheel and
   ALL-group adjust should all reach **`1/256`** and stay there after a power
   cycle.
2. Gr mode → group **M**: the floor must stay **`1/128`** (and `1/16` with HSS).
3. Other modes (TTL, Multi, receiver) must behave exactly as before.

The version string never changes — it comes from the IAP bootloader, which is
never overwritten. **Verify by behaviour, not by version number.**

---

## How it works (short version)

Power per group is an attenuation in tenths of a stop in
`byte_2000058C[group]`: `0` = `1/1`, `70` = `1/128`, `80` = `1/256`,
`0xFF` = OFF. Stock code clamps it to `70` in three independent layers
(validator, slider ranges, step routine), and the wheel/button path also
converts through a `0..21` "thirds" scale. Rather than rewrite those clamp
sequences in place, `patch_gr256.py` moves the clamping decision into a helper
library placed in the erased flash tail at `0x0808FA80` and redirects the
original sites with `BL`/`B.W` thunks. Each helper checks the live mode and
group index and applies `0x50` for Gr A/B/C, `0x46` for M, `0x28` for HSS.

Full detail — container format, memory map, clamp inventory, the tables of
patched sites, and the reasoning — is in
[`docs/power-model.md`](docs/power-model.md).
The flasher protocol and operational rules are in
[`skills/godox-it30pro-flash/SKILL.md`](skills/godox-it30pro-flash/SKILL.md).

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| No answer to the query | Device is in normal mode, not upgrade mode — or the official updater still holds the HID device |
| `cmd 0 query failed` | Same. Power off → hold `MENU` → plug in USB |
| No erase ACK | Erase takes ~2.1 s; wait at least 25 s. Otherwise re-enter upgrade mode |
| `NO ACK` mid-flash | Device state went bad. Re-enter upgrade mode and flash again — the next run overwrites the partial image |
| Version number unchanged | **Expected.** It comes from the IAP bootloader; verify by the 1/256 ladder instead |
| Touch reaches 1/256, wheel does not | You are running an old V1.09-series patch. Regenerate with `patches/patch_gr256.py` |
| 1/256 selected but output unchanged | The M-group head driver table natively covers down to 1/512, so this is expected; as a master, the remote flash decides its own output |
| Touch UI freezes / reboots | An instruction-encoding bug in a hand patch (`IT` block masks). Regenerate with the scripts here |
| Value snaps back to 1/128 | An uncovered clamp still runs on save/boot. Report the entry point; check `0x0801EB28` first |

---

## Safety notes

* Flashing erases the application area; interrupting mid-write leaves the device
  unbootable until you re-flash. There is no risk to the bootloader.
* Keep a stock container handy before experimenting.
* Do not flash an image built for a different model unless you accept the risk —
  the shared image format does not guarantee identical hardware.
* This project is unaffiliated with Godox. Use on your own hardware.

---

## License

Unless stated otherwise, the **source code and documentation** in this repository
are licensed under the **GNU General Public License, version 3 or later**
(GPL-3.0-or-later). The full text is in [LICENSE](LICENSE).

```
Copyright (C) 2026  iT30Pro S Patch Toolkit contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
```

The GPL covers only what the authors of this repository wrote. It grants no
rights to Godox firmware, upgrade packages, manuals or trademarks — none of
which are included here or distributed with it.