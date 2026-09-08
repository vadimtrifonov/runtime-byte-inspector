from __future__ import annotations

import ctypes
import struct
import sys
from contextlib import contextmanager
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .pe import Module, parse_nt_headers

if sys.platform != "win32" or ctypes.sizeof(ctypes.c_void_p) != 8:
    raise OSError("Live inspection requires 64-bit Python on Windows")

TH32CS_SNAPPROCESS = 0x2
TH32CS_SNAPMODULE = 0x8
TH32CS_SNAPMODULE32 = 0x10
PROCESS_VM_READ = 0x10
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
ERROR_NO_MORE_FILES = 18
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class ProcessEntry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class ModuleEntry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * 260),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
kernel32.GetProcessTimes.restype = wintypes.BOOL
for name, entry_type in (("Process32", ProcessEntry), ("Module32", ModuleEntry)):
    for step in ("FirstW", "NextW"):
        function = getattr(kernel32, name + step)
        function.argtypes = [wintypes.HANDLE, ctypes.POINTER(entry_type)]
        function.restype = wintypes.BOOL


def check(result, operation: str) -> None:
    if not result:
        error = ctypes.get_last_error()
        message = f"{operation}: {ctypes.FormatError(error).strip()}"
        if error == 5:
            message += " Live inspection may require an elevated terminal."
        raise ctypes.WinError(error, message)


@contextmanager
def snapshot(flags: int, pid: int):
    handle = kernel32.CreateToolhelp32Snapshot(flags, pid)
    check(handle != INVALID_HANDLE_VALUE, f"CreateToolhelp32Snapshot(pid={pid})")
    try:
        yield handle
    finally:
        check(kernel32.CloseHandle(handle), "CloseHandle(snapshot)")


def find_pid(name: str) -> int:
    matches = []
    with snapshot(TH32CS_SNAPPROCESS, 0) as handle:
        entry = ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        found = kernel32.Process32FirstW(handle, ctypes.byref(entry))
        while found:
            if entry.szExeFile.casefold() == name.casefold():
                matches.append(int(entry.th32ProcessID))
            found = kernel32.Process32NextW(handle, ctypes.byref(entry))
        if ctypes.get_last_error() != ERROR_NO_MORE_FILES:
            check(found, "Enumerate processes")
    if not matches:
        raise ValueError(f"Process '{name}' is not running")
    if len(matches) != 1:
        raise ValueError(f"Process '{name}' matches PIDs {matches}; select one with --pid")
    return matches[0]


class LiveProcess:
    """Hold one read-only process handle for a batch of module-relative reads."""

    def __init__(self, *, pid: int | None = None, name: str | None = None, module_name: str | None = None):
        if (pid is None) == (name is None):
            raise ValueError("Select exactly one PID or process name")
        self.pid = find_pid(name) if pid is None else pid
        if not 0 < self.pid <= 0xFFFFFFFF:
            raise ValueError("PID must be a positive 32-bit integer")
        self.handle = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, self.pid
        )
        check(self.handle, f"OpenProcess(pid={self.pid})")
        try:
            buffer = ctypes.create_unicode_buffer(32768)
            length = wintypes.DWORD(len(buffer))
            check(
                kernel32.QueryFullProcessImageNameW(self.handle, 0, buffer, ctypes.byref(length)),
                f"QueryFullProcessImageNameW(pid={self.pid})",
            )
            self.path = buffer.value
            self.name = Path(self.path).name
            if name is not None and name.casefold() != self.name.casefold():
                raise ValueError(f"PID {self.pid} now belongs to '{self.name}', not '{name}'")
            times = [wintypes.FILETIME() for _ in range(4)]
            check(
                kernel32.GetProcessTimes(self.handle, *(ctypes.byref(time) for time in times)),
                "GetProcessTimes",
            )
            ticks = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            self.started_at = (
                datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
            ).isoformat()
            self.module = self._find_module(self.name if module_name is None else module_name)
        except BaseException:
            self.__exit__()
            raise

    def __enter__(self) -> LiveProcess:
        return self

    def __exit__(self, *_):
        check(kernel32.CloseHandle(self.handle), f"CloseHandle(pid={self.pid})")

    def _find_module(self, name: str) -> Module:
        with snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid) as handle:
            entry = ModuleEntry()
            entry.dwSize = ctypes.sizeof(entry)
            found = kernel32.Module32FirstW(handle, ctypes.byref(entry))
            while found:
                if entry.szModule.casefold() == name.casefold():
                    base, size = entry.modBaseAddr, int(entry.modBaseSize)
                    dos = self._read_address(base, 64)
                    if dos[:2] != b"MZ":
                        raise ValueError(f"Module '{name}' has no DOS header")
                    nt_offset = struct.unpack_from("<I", dos, 60)[0]
                    if nt_offset < 64 or nt_offset + 88 > size:
                        raise ValueError(f"Module '{name}' has invalid NT header bounds")
                    _, image_size, timestamp = parse_nt_headers(self._read_address(base + nt_offset, 88))
                    if image_size != size:
                        raise ValueError(f"Module '{name}' size disagrees with its loaded PE headers")
                    return Module(entry.szModule, entry.szExePath, base, size, timestamp)
                found = kernel32.Module32NextW(handle, ctypes.byref(entry))
            if ctypes.get_last_error() != ERROR_NO_MORE_FILES:
                check(found, f"Enumerate modules(pid={self.pid})")
        raise ValueError(f"Module '{name}' is not loaded in PID {self.pid}")

    def _read_address(self, address: int, size: int) -> bytes:
        buffer = ctypes.create_string_buffer(size)
        count = ctypes.c_size_t()
        check(
            kernel32.ReadProcessMemory(self.handle, address, buffer, size, ctypes.byref(count)),
            f"ReadProcessMemory(pid={self.pid}, address={address:#x}, size={size})",
        )
        if count.value != size:
            raise OSError(f"Short memory read at {address:#x}: wanted {size}, read {count.value} bytes")
        return buffer.raw

    def read(self, rva: int, size: int) -> bytes:
        if rva < 0 or size <= 0 or rva + size > self.module.size:
            raise ValueError("Read is outside the selected module")
        return self._read_address(self.module.base + rva, size)

    def metadata(self) -> dict:
        return {
            "kind": "live_process",
            "process": {"name": self.name, "path": self.path, "pid": self.pid, "started_at": self.started_at},
            "module": self.module.metadata(),
        }
