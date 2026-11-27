"""godox_iap.py -- direct iT30ProS/V480S IAP tool (query / read / flash).

Protocol recovered by reverse-engineering Godox V2.0.exe:
  packet builder  0x407610   state machine 0x408300..   response decoder 0x4072b0
  hidapi exports at 0x40a6d0(hid_write) / 0x40a880(hid_read_timeout)

REQUEST reports (65-byte HID output buffer, buf[0] = 0xAA as the updater does):
  command report : AA 00 55 CMD <payload> <0xFF pad to 61> chk32BE
                   chk = sum(bytes[1..61)) & 0xffffffff   (covers 1..60 incl.)
                   payload lives at bytes [4 .. 4+L)
                   cmds: 0 query / 1 reboot(1B 0x55|0x66) / 2 erase /
                         3 read(addr BE32 + count BE32) / 4|((blk>>4)&0xF0) write
  data report    : AA + 64 raw bytes of the current 1024B block (16 per block)
                   (updater sends the header's chk field unchanged; the chk is
                    therefore informational for data reports)

RESPONSE reports (65-byte input buffer, byte0 = report id placeholder 0x00):
  B1=0xAA, B2=status (0xA1 = info: name follows at B3..B34, 32 bytes)
  chk24 at B60..B62 = sum(bytes B0..B59)  (informational, layout B61:B60:B62)

Only --flash is destructive; --query and --read never write device state.
"""
import argparse
import hashlib
import struct
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hid_scan import kernel32, hid, HIDD_ATTRIBUTES, INVALID_HANDLE_VALUE, enum_paths

import ctypes
import ctypes.wintypes as wt

# hidapi's hid_write/hid_read are static-linked into the updater, not exported
# by Windows hid.dll.  Use WriteFile/ReadFile directly, the same way hidapi
# does.  The handle is opened with FILE_FLAG_OVERLAPPED so reads can time out.
kernel32.WriteFile.restype = wt.BOOL
kernel32.WriteFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                               ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
kernel32.ReadFile.restype = wt.BOOL
kernel32.ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                              ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
kernel32.CreateEventW.restype = wt.HANDLE
kernel32.CreateEventW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR]
kernel32.WaitForSingleObject.restype = wt.DWORD
kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
kernel32.GetOverlappedResult.restype = wt.BOOL
kernel32.GetOverlappedResult.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                         ctypes.POINTER(wt.DWORD), wt.BOOL]
kernel32.CancelIo.restype = wt.BOOL
kernel32.CancelIo.argtypes = [wt.HANDLE]

GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
OPEN_EXISTING, FILE_FLAG_OVERLAPPED = 3, 0x40000000


class _OV(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", wt.DWORD), ("OffsetHigh", wt.DWORD),
                ("hEvent", wt.HANDLE)]


VID, PID = 0x0483, 0x572B


class Device:
    def __init__(self, handle):
        self.h = handle
        self.ov = _OV()
        self.ov.hEvent = kernel32.CreateEventW(None, True, False, None)

    def write(self, buf65):
        b = ctypes.create_string_buffer(bytes(buf65), 65)
        n = wt.DWORD(0)
        if not kernel32.WriteFile(self.h, b, 65, ctypes.byref(n), ctypes.byref(self.ov)):
            err = kernel32.GetLastError()
            if err != 997:  # ERROR_IO_PENDING
                raise OSError(f"WriteFile err {err}")
            if not kernel32.GetOverlappedResult(self.h, ctypes.byref(self.ov),
                                                ctypes.byref(n), True):
                raise OSError("GetOverlappedResult write failed")
        return n.value

    def read(self, timeout_ms=800):
        b = ctypes.create_string_buffer(65)
        n = wt.DWORD(0)
        kernel32.ResetEvent(self.ov.hEvent)
        ok = kernel32.ReadFile(self.h, b, 65, ctypes.byref(n), ctypes.byref(self.ov))
        if not ok:
            err = kernel32.GetLastError()
            if err != 997:
                return None
            w = kernel32.WaitForSingleObject(self.ov.hEvent, timeout_ms)
            if w != 0:  # not WAIT_OBJECT_0
                kernel32.CancelIo(self.h)
                kernel32.GetOverlappedResult(self.h, ctypes.byref(self.ov),
                                             ctypes.byref(n), False)
                return None
            if not kernel32.GetOverlappedResult(self.h, ctypes.byref(self.ov),
                                                ctypes.byref(n), False):
                return None
        return bytes(b.raw[:n.value])


def open_device():
    for path in enum_paths():
        h = kernel32.CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 3, None,
                                 OPEN_EXISTING, FILE_FLAG_OVERLAPPED, None)
        if h in (None, INVALID_HANDLE_VALUE, -1):
            continue
        attr = HIDD_ATTRIBUTES()
        attr.Size = ctypes.sizeof(attr)
        hid.HidD_GetAttributes(h, ctypes.byref(attr))
        if (attr.VendorID, attr.ProductID) == (VID, PID):
            return Device(h)
        kernel32.CloseHandle(h)
    return None


def cmd_report(cmd, payload=b""):
    # VERIFIED against device: builder writes 0xffffaa00 LE, so
    # buf[0]=0x00 report-id placeholder, buf[1]=0xAA buf[2]=0x55 buf[3]=CMD
    buf = bytearray(65)
    buf[0] = 0x00
    buf[1] = 0xAA
    buf[2] = 0x55
    buf[3] = cmd & 0xFF
    buf[4:4 + len(payload)] = payload
    for i in range(4 + len(payload), 61):
        buf[i] = 0xFF
    chk = sum(buf[1:61]) & 0xFFFFFFFF
    buf[61:65] = struct.pack(">I", chk)
    return bytes(buf)


def data_report(chunk64):
    # data continuation report: id placeholder then 64 raw bytes
    buf = bytearray(65)
    buf[0] = 0x00
    buf[1:65] = chunk64
    return bytes(buf)


def write(h, buf):
    return h.write(buf)


def read(h, timeout_ms=800):
    return h.read(timeout_ms)


def drain(h, seconds=1.0, log=None):
    end = time.time() + seconds
    out = []
    while time.time() < end:
        r = read(h, 250)
        if r is None:
            continue
        out.append(r)
        if log:
            log("  <-", r.hex(" "))
    return out


def query(h, tries=6):
    """cmd 0 -> (status, body) or (None, None). Wire: 00 AA 55 <st> <body>."""
    for _ in range(tries):
        write(h, cmd_report(0))
        r = read(h, 800)
        if r is not None and r[1] == 0xAA and r[2] == 0x55:
            return r[3], bytes(r[4:60])
        time.sleep(0.3)
    return None, None


def name_str(b):
    return b.split(b"\x00")[0].decode("ascii", "replace")


def wait_status(h, seconds, expect=None):
    """Wait for any response; returns list of (status, body)."""
    end = time.time() + seconds
    seen = []
    while time.time() < end:
        r = read(h, 300)
        if r is not None and r[1] == 0xAA and r[2] == 0x55:
            seen.append((r[3], bytes(r[4:60])))
            if expect is None or r[3] in expect:
                return seen
        time.sleep(0.02)
    return seen


def flash(h, binpath, log=print, dry=False):
    """Erase + write, replicating the official updater's sequence exactly."""
    data = open(binpath, "rb").read()
    if len(data) < 0x30:
        log("file too small")
        return False
    # trailer = MD5(16) + name(28) + u16(2) + magic(8) = 54 bytes
    if len(data) <= 54 or data[-8:] != bytes.fromhex("AA55669977882233"):
        log("trailer magic missing -- not a Godox G3 file")
        return False
    img_size = len(data) - 54
    log(f"file {binpath}: {len(data)} bytes, image 0x{img_size:X}")
    log("trailer name:", name_str(data[img_size + 16:img_size + 44]))
    md5 = hashlib.md5(data[:img_size]).digest()
    if md5 != data[img_size:img_size + 16]:
        log("internal MD5 mismatch -- refusing")
        return False
    log("internal MD5 ok:", md5.hex())

    total = len(data)
    nblocks = (total + 0x3FF) >> 10

    # sanity: device must answer cmd 0 before we erase anything
    if not dry:
        st, nm = query(h, tries=3)
        if nm is None:
            log("cmd 0 query failed -- device not in IAP mode? aborting")
            return False
        log("IAP identity:", name_str(nm))
        log("erase (cmd 2)...")
        write(h, cmd_report(2))
        acks = wait_status(h, 20.0)
        log("erase acks:", [(hex(s), len(b)) for s, b in acks] or "NONE")
        if not acks:
            log("no erase ack -- aborting")
            return False

    log(f"writing {total} bytes in {nblocks} blocks")
    for b in range(nblocks):
        chunk = data[b << 10:(b + 1) << 10]
        chunk += b"\xff" * ((-len(chunk)) % 1024)
        chk = sum(chunk) & 0xFFFFFFFF
        # connected mode ([0x9a]!=0 -> 0x408a2c): every block uses cmd 8 with
        # an 8-byte payload = [block_index BE32][chk32 BE]  (len=8 at 0x408a2f,
        # chk stored at payload+4 by 0x408a49)
        cmd = 8
        payload = struct.pack(">II", b, chk)
        if not dry:
            write(h, cmd_report(cmd, payload))
            for i in range(16):
                write(h, data_report(chunk[i << 6:(i + 1) << 6]))
        if b % 32 == 0 or b == nblocks - 1:
            log(f"  block {b + 1}/{nblocks}")
        if not dry:
            # the updater treats ANY non-0xA1 response as stage-ack; mirror that
            acks = wait_status(h, 4.0)
            if not acks:
                log(f"  NO ACK after block {b + 1} -- aborting before damage")
                return False
            if b < 3 or b % 128 == 0:
                log(f"  block {b + 1} ack status: {[hex(s) for s, _ in acks]}")
            time.sleep(0.02)  # device needs a moment to program flash

    # NOTE: the official updater sends NOTHING after the last block.
    # Any extra packet may reset the device's end-of-update timeout logic.
    log("done -- staying silent so the device can finalize on its own")
    return True


def readback(h, addr, count, log=print):
    """cmd 3 best-effort; prints raw responses for protocol confirmation."""
    payload = struct.pack(">II", addr, count)
    log(f"read-back request addr={addr:#x} count={count:#x}")
    write(h, cmd_report(3, payload))
    got = drain(h, 4.0, log=lambda *a: log(*a))
    return got


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--query", action="store_true", help="read device identity (default)")
    ap.add_argument("--read", nargs=2, metavar=("ADDR", "COUNT"),
                    help="read-back probe, e.g. --read 0x08000000 64")
    ap.add_argument("--flash", metavar="BIN", help="erase+write firmware (destructive)")
    ap.add_argument("--i-know-this-bricks", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="flash: build packets only")
    args, _ = ap.parse_known_args()

    dev = open_device()
    h = dev
    if h is None:
        print("No Godox IAP HID device (VID 0483 PID 572B) found.")
        print("Plug USB; if absent, enter upgrade mode: power off, hold MENU, plug USB.")
        return 1
    print("device opened")

    st, name = query(h)
    if name is None:
        print("query: NO RESPONSE (device may be in normal-op mode, not IAP)")
    else:
        print(f"status: {st:#04x}")
        print(f"name raw : {name.hex(' ')}")
        print(f"name text: {name_str(name)!r}")

    if args.read:
        addr = int(args.read[0], 0)
        count = int(args.read[1], 0)
        readback(h, addr, count)

    if args.flash:
        if not args.i_know_this_bricks:
            print("refusing: --flash needs --i-know-this-bricks")
        else:
            flash(h, args.flash, dry=args.dry_run)

    kernel32.CloseHandle(dev.h)
    return 0


if __name__ == "__main__":
    sys.exit(main())
