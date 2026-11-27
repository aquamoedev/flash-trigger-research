"""hid_scan.py -- enumerate HID devices and (optionally) dump feature reports.

Pure ctypes.  64-bit safe: every pointer argument gets an explicit argtype so
handles are not truncated to 32 bits.

usage:  python hid_scan.py
        python hid_scan.py --dump
        python hid_scan.py --dump --vid 0x1234
"""
import ctypes
import ctypes.wintypes as wt
import sys

hid = ctypes.WinDLL("hid.dll")
setupapi = ctypes.WinDLL("setupapi.dll")
kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

DIGCF_PRESENT = 0x02
DIGCF_DEVICEINTERFACE = 0x10
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [("cbSize", wt.DWORD), ("InterfaceClassGuid", GUID),
                ("Flags", wt.DWORD), ("Reserved", ctypes.c_void_p)]


class HIDD_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Size", wt.ULONG), ("VendorID", wt.USHORT),
                ("ProductID", wt.USHORT), ("VersionNumber", wt.USHORT)]


setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), wt.LPCWSTR,
                                          ctypes.c_void_p, wt.DWORD]
setupapi.SetupDiEnumDeviceInterfaces.restype = wt.BOOL
setupapi.SetupDiEnumDeviceInterfaces.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(GUID), wt.DWORD,
    ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)]
setupapi.SetupDiGetDeviceInterfaceDetailW.restype = wt.BOOL
setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA), ctypes.c_void_p,
    wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
setupapi.SetupDiDestroyDeviceInfoList.restype = wt.BOOL
setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]

kernel32.CreateFileW.restype = ctypes.c_void_p
kernel32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                                 wt.DWORD, wt.DWORD, ctypes.c_void_p]
kernel32.CloseHandle.restype = wt.BOOL
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

hid.HidD_GetHidGuid.restype = None
hid.HidD_GetHidGuid.argtypes = [ctypes.POINTER(GUID)]
hid.HidD_GetAttributes.restype = wt.BOOL
hid.HidD_GetAttributes.argtypes = [ctypes.c_void_p, ctypes.POINTER(HIDD_ATTRIBUTES)]
hid.HidD_GetProductString.restype = wt.BOOL
hid.HidD_GetProductString.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.ULONG]
hid.HidD_GetSerialNumberString.restype = wt.BOOL
hid.HidD_GetSerialNumberString.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.ULONG]
hid.HidD_GetFeature.restype = wt.BOOL
hid.HidD_GetFeature.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.ULONG]
hid.HidD_GetPreparsedData.restype = wt.BOOL
hid.HidD_GetPreparsedData.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
hid.HidD_FreePreparsedData.restype = wt.BOOL
hid.HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]


def enum_paths():
    g = GUID()
    hid.HidD_GetHidGuid(ctypes.byref(g))
    hdev = setupapi.SetupDiGetClassDevsW(ctypes.byref(g), None, None,
                                         DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
    if hdev in (None, INVALID_HANDLE_VALUE):
        raise OSError(f"SetupDiGetClassDevs failed: {ctypes.get_last_error()}")
    out = []
    idx = 0
    while True:
        did = SP_DEVICE_INTERFACE_DATA()
        did.cbSize = ctypes.sizeof(did)
        if not setupapi.SetupDiEnumDeviceInterfaces(hdev, None, ctypes.byref(g), idx,
                                                    ctypes.byref(did)):
            break
        idx += 1
        req = wt.DWORD(0)
        setupapi.SetupDiGetDeviceInterfaceDetailW(hdev, ctypes.byref(did), None, 0,
                                                  ctypes.byref(req), None)
        buf = ctypes.create_string_buffer(req.value + 8)
        ctypes.cast(buf, ctypes.POINTER(wt.DWORD))[0] = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 6
        if not setupapi.SetupDiGetDeviceInterfaceDetailW(hdev, ctypes.byref(did), buf,
                                                        req.value, ctypes.byref(req), None):
            continue
        out.append(ctypes.wstring_at(ctypes.addressof(buf) + 4))
    setupapi.SetupDiDestroyDeviceInfoList(hdev)
    return out


def main():
    dump = "--dump" in sys.argv
    want_vid = None
    if "--vid" in sys.argv:
        want_vid = int(sys.argv[sys.argv.index("--vid") + 1], 0)
    paths = enum_paths()
    print(f"{len(paths)} HID interfaces")
    shown = 0
    for p in paths:
        h = kernel32.CreateFileW(p, GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, None,
                                 OPEN_EXISTING, 0, None)
        if h in (None, INVALID_HANDLE_VALUE):
            continue
        attr = HIDD_ATTRIBUTES()
        attr.Size = ctypes.sizeof(attr)
        hid.HidD_GetAttributes(h, ctypes.byref(attr))
        if want_vid is not None and attr.VendorID != want_vid:
            kernel32.CloseHandle(h)
            continue
        shown += 1
        prod = ctypes.create_unicode_buffer(256)
        hid.HidD_GetProductString(h, ctypes.byref(prod), 512)
        ser = ctypes.create_unicode_buffer(256)
        hid.HidD_GetSerialNumberString(h, ctypes.byref(ser), 512)
        print(f"\nVID {attr.VendorID:04X} PID {attr.ProductID:04X} rev {attr.VersionNumber:04X}")
        print(f"  product: {prod.value!r}")
        print(f"  serial : {ser.value!r}")
        print(f"  path   : {p}")
        if dump:
            buf = ctypes.create_string_buffer(64)
            for rid in range(16):
                ctypes.memset(buf, 0, 64)
                buf[0] = bytes([rid])
                if hid.HidD_GetFeature(h, ctypes.byref(buf), 64):
                    print(f"  feature[{rid:2d}] = {bytes(buf)[:24].hex(' ')}")
        kernel32.CloseHandle(h)
    print(f"\nshown: {shown}")


if __name__ == "__main__":
    main()
