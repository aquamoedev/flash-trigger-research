# iT30Pro S: power model and the 1/256 patch

Notes collected while reverse-engineering the stock V1.07 image. All addresses are
flash-mapped (`0x08000000` base); RAM names follow the IDA database
(`byte_2000xxxx`).

## 1. Container format

An upgrade file is a single container; the updater only checks the embedded MD5:

| offset          | size | content                                        |
| --------------- | ---- | ---------------------------------------------- |
| `0x00000`       | `0xA8000` | image (`0x08000000..0x080A7FFF`)          |
| `0x0A8000`      | 16   | `MD5(image)`                                   |
| `0x0A8010`      | 28   | name, e.g. `iT30ProSiT30SV480S_V1.07.bin`      |
| `0x0A802C`      | 2    | `0x001C` (little endian)                       |
| `0x0A802E`      | 8    | magic `AA 55 66 99 77 88 22 33`                |

Total `688182` bytes. The image itself holds two applications:

* `0x00000..0xA0000` (640 KiB) — main MCU (Cortex-M, vector table at `0x08000000`,
  initial SP `0x2001F478`), where all UI/power/wireless code lives;
* `0xA0000..0xA8000` (32 KiB) — second MCU image (own vector table,
  initial SP `0x20000C20`), **never touched** by the patch.

`0x0808FA80..0x080A0000` is erased `0xFF` in the main image and is used as the
code cave.

## 2. Power encoding

Each output group stores its power as an **attenuation in tenths of a stop**:

| `tenths` | displayed  | note                          |
| -------- | ---------- | ----------------------------- |
| 0        | `1/1`      | full power                    |
| 10..70   | `1/2..1/128` | native range                |
| 80       | `1/256`    | what this patch unlocks       |
| 90       | `1/512`    | supported by the maths/tables |
| `0xFF`   | `OFF`      | group disabled                |

Display is computed, not read from an icon table:

```
denominator = 512 >> ((90 - tenths) / 10)      # 70 -> 1/128, 80 -> 1/256
```

0.3-stop steps use a second scale, `thirds` (`0..21` native, `21` = 7 stops =
`1/128`; `24` = 8 stops = `1/256`).

Two arrays hold the values (both indexed by group):

| RAM                 | used for                              |
| ------------------- | ------------------------------------- |
| `byte_2000058C[i]`  | M / Gr manual power (i = 0..3)        |
| `byte_20000598[i]`  | Multi (stroboscopic) power            |

Group numbering in **Gr** mode: `0` = `M` (the on-camera flash itself),
`1..3` = `A`, `B`, `C` (remote groups).

Related state used by the patch:

| RAM                | meaning                                                        |
| ------------------ | -------------------------------------------------------------- |
| `byte_200003D8`    | wireless mode; `3` = **Gr**, `4` = Multi, `0` = single          |
| `byte_20000580`    | flash state; bits `0..1` = TTL/M/Multi, bit `0x10` = **HSS**    |
| `byte_20000572`    | group index in the touch/wheel event handlers                   |
| `byte_2000059E/F`  | group index used by the display/apply path                      |
| `byte_200005C1`    | currently selected group in the editor                          |

## 3. Stock limits (why 1/256 was unreachable)

The stock firmware clamps the attenuation at `0x46` (70 = `1/128`) in three
independent layers. Any one of them alone is enough to stop the UI at 1/128:

1. **Value clamps / validator** — run on every render, on load and on save:
   * `sub_800AA2C` (config validator, `0x0800AA4A` + `0x0800AA6E/AA94/AAA0`)
   * `sub_800D048` (`0x0800D158/D15E`, config load from internal flash)
   * `sub_800ABCC` (`0x0800ABE4/ABEC`, M-mode power widget text)
   * `sub_800B8BC` (Multi widget, left as-is)
2. **Slider ranges and step arithmetic** — `sub_803D014`
   (`0x0803D400/D46E/D492/D4A6`) sets slider `min/max`, 1/3-stop and 0.1-stop
   ranges, plus the `70 - value` conversion.
3. **Stepping from touch buttons and the wheel** — `sub_8014E40` is the shared
   step/limit routine; its tail (`0x08014FB2..0x08014FE6`) clamps to
   `0x46`, or `0x28` (`1/16`) when HSS is on and the mode is not Gr. Callers:
   * wheel `+1` / `-1`: `sub_8008E60` (`0x08008F82/8FA4`), `sub_8002274`
     (`0x0800236A/2388`)
   * Gr touch `+` / `-` buttons: `sub_800DEE4`
     (`0x0800DFBC/DFCA/E000/E022`)
   * ALL-group adjust: `sub_8014BD8` (`0x08014CC2/14D40`)
   * group slider drag: `sub_800E72C` (`case 28`, `0x0800E954..EAD4`)

Because the last layer also converts between `tenths` and `thirds`, simply
raising the `0x46` constants (the V1.09 approach) still left the *wheel* path
clamped.

## 4. Patch strategy: code cave + thunks

Patching every clamp in place would mean rewriting sequences of 6–14 bytes that
contain `IT` blocks and PC-relative literal loads, in a dozen functions, with no
room to grow. Instead `patches/patch_gr256.py`:

1. assembles a small helper library into the erased tail at `0x0808FA80`
   (640 bytes: 33 helpers + literal pool, ends `0x0808FD00`);
2. overwrites the original sites with `BL` / `B.W` thunks (padded with `NOP`).

Each helper answers the same question — *"may this value go to `0x50`?"* — using
the live group index and mode:

```
limit = 0x46                       # 1/128  (M group, all non-Gr modes)
if mode == Gr and group in 1..3:
    limit = 0x50                   # 1/256  (A/B/C)
if mode != Gr and HSS:
    limit = 0x28                   # 1/16   (unchanged stock behaviour)
```

Helpers deliberately avoid touching `CPSR` where the original sequence returned
flags to its caller (`sub_800E72C` branches on the flags set by the clamp), and
the register bank each call site actually observes is preserved.

### Sites rewritten (all 22)

| function     | sites                                                        |
| ------------ | ------------------------------------------------------------ |
| `sub_800AA2C`| `0x0800AA6C`, `0x0800AA92` (validator, HSS / non-HSS paths)  |
| `sub_800D048`| `0x0800D15A` (config load)                                   |
| `sub_800ABCC`| `0x0800ABE4` (M widget text)                                 |
| `sub_8014E40`| `0x08014FB2` (step limit tail)                               |
| `sub_8008E60`| `0x08008F82`, `0x08008FA4` (wheel)                           |
| `sub_8002274`| `0x0800236A`, `0x08002388` (wheel)                           |
| `sub_800DEE4`| `0x0800DFBC/DFCA/E000/E022` (touch +/-)                      |
| `sub_8014BD8`| `0x08014CC2`, `0x08014D40` (ALL groups)                      |
| `sub_803D014`| `0x0803D400`, `0x0803D46E`, `0x0803D492`, `0x0803D4A6`       |
| `sub_800E72C`| `0x0800E954/E966/E9A8/E9BC/E9EA/E9F0/EA90/EA96/EACA`        |

Deliberately **not** changed: Multi (`byte_20000598`), the `1/4` lower bound of
Multi, wireless receive paths, and every non-Gr mode.

## 5. Result and verification

* Gr → A/B/C: touch slider, touch `+`/`-`, wheel (single group and ALL) can all
  reach `1/256`, and the value survives a config save/reload.
* Gr → M: floor stays `1/128` (`1/16` with HSS), exactly as stock.
* Everything else: byte-for-byte stock behaviour.

Reproducibility check (stock input, no capstone needed):

```
python patches/patch_gr256.py --no-verify
# image MD5 36a1974b9bfadccb9869cdcb87925b64
# file  MD5 de49a9d3a406dc2087a17c61cdcc6280
```

## 6. Still open

* `0x0801EB28` contains a `movs r0, #0x46` whose caller is unknown; if some path
  still snaps back to 1/128, check it first.
* The wheel limit is timer/quantised: very fast spins may coalesce steps, which is
  stock behaviour and unrelated to the clamp.