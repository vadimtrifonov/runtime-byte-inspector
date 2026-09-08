"""Owned, non-executing AMD64 memory fixture for live read tests."""

import ctypes
import json
import os
import struct
import sys

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.VirtualProtect.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32),
]
kernel32.VirtualProtect.restype = ctypes.c_int
kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
kernel32.VirtualFree.restype = ctypes.c_int


def main():
    base = kernel32.VirtualAlloc(None, 0x5000, 0x3000, 0x40)
    if not base:
        raise ctypes.WinError(ctypes.get_last_error())
    try:

        def put(offset, blob):
            ctypes.memmove(base + offset, blob, len(blob))

        ctypes.memset(base, 0xCC, 0x5000)
        put(0x100, bytes.fromhex("E9FB000000"))
        put(0x200, bytes.fromhex("FF2500000000") + struct.pack("<Q", base + 0x300))
        put(0x300, bytes.fromhex("B82A000000C3"))
        put(0x400, bytes.fromhex("E9FBFFFFFF"))
        put(0x500, bytes.fromhex("488B01FF9090010000C3"))
        put(0x600, bytes.fromhex("488D05") + struct.pack("<i", 0x3110 - 0x607) + b"\xc3")
        put(0x700, bytes.fromhex("FF25") + struct.pack("<i", 0x2000 - 0x706))
        put(0x800, bytes.fromhex("FF2500000000") + struct.pack("<Q", (1 << 64) - 1))
        put(0x900, bytes.fromhex("488D05F7503E019090C3"))
        put(0xA00, bytes.fromhex("488BC45741544155415641574883EC40C3"))
        put(0xB00, bytes.fromhex("E8") + struct.pack("<i", 0x300 - 0xB05) + b"\xc3")
        put(0xC00, bytes.fromhex("EB00"))  # Jump whose destination window crosses into no-access memory.
        put(0xC02, bytes.fromhex("E9") + struct.pack("<i", 0x1FF8 - 0xC07))
        put(0xD00, bytes.fromhex("FFE0"))
        put(0xE00, bytes.fromhex("75FE"))
        put(0xF00, bytes.fromhex("3EFF2500000000") + struct.pack("<Q", base + 0x300))
        put(0x1000, bytes.fromhex("48FF2D00000000") + b"\0" * 10)
        put(0x1FF8, bytes.fromhex("0102030405060708"))
        put(0x3100, struct.pack("<Q", base + 0x100))
        put(0x3108, struct.pack("<Q", base + 0x3110))
        put(0x3110, b"\0not part of the empty string\0")
        for offset, size, protection in (
            (0, 0x2000, 0x20),
            (0x2000, 0x1000, 1),
            (0x3000, 0x1000, 2),
            (0x4000, 0x1000, 0x104),
        ):
            old = ctypes.c_uint32()
            if not kernel32.VirtualProtect(base + offset, size, protection, ctypes.byref(old)):
                raise ctypes.WinError(ctypes.get_last_error())
        print(json.dumps({"pid": os.getpid(), "base": base}), flush=True)
        sys.stdin.read()
    finally:
        if not kernel32.VirtualFree(base, 0, 0x8000):
            raise ctypes.WinError(ctypes.get_last_error())


if __name__ == "__main__":
    main()
