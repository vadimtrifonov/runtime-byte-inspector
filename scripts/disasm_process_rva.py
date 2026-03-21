from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import dataclass

from capstone import Cs, CS_ARCH_X86, CS_MODE_64


TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MAX_PATH = 260
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * MAX_PATH),
    ]


kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wintypes.BOOL
kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wintypes.BOOL
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
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


@dataclass
class ProcessInfo:
    pid: int
    exe_name: str


@dataclass
class ModuleInfo:
    name: str
    path: str
    base_address: int
    size: int


def parse_int(value: str) -> int:
    return int(value, 0)


def format_bytes(data: bytes) -> str:
    return " ".join(f"{byte:02X}" for byte in data)


def checked_bool(result: int, function_name: str) -> None:
    if not result:
        raise ctypes.WinError(ctypes.get_last_error(), f"{function_name} failed")


def snapshot(flags: int, pid: int) -> wintypes.HANDLE:
    handle = kernel32.CreateToolhelp32Snapshot(flags, pid)
    if handle == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    return handle


def find_process_by_name(name: str) -> ProcessInfo:
    handle = snapshot(TH32CS_SNAPPROCESS, 0)
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        checked_bool(kernel32.Process32FirstW(handle, ctypes.byref(entry)), "Process32FirstW")

        wanted = name.casefold()
        while True:
            if entry.szExeFile.casefold() == wanted:
                return ProcessInfo(pid=int(entry.th32ProcessID), exe_name=entry.szExeFile)
            if not kernel32.Process32NextW(handle, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(handle)

    raise SystemExit(f"Process '{name}' is not running")


def find_module(pid: int, module_name: str) -> ModuleInfo:
    handle = snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        checked_bool(kernel32.Module32FirstW(handle, ctypes.byref(entry)), "Module32FirstW")

        wanted = module_name.casefold()
        while True:
            if entry.szModule.casefold() == wanted:
                return ModuleInfo(
                    name=entry.szModule,
                    path=entry.szExePath,
                    base_address=ctypes.addressof(entry.modBaseAddr.contents),
                    size=int(entry.modBaseSize),
                )
            if not kernel32.Module32NextW(handle, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(handle)

    raise SystemExit(f"Module '{module_name}' was not found in process {pid}")


def read_process_bytes(pid: int, address: int, size: int) -> bytes:
    process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not process:
        raise ctypes.WinError(ctypes.get_last_error(), "OpenProcess failed")

    try:
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        checked_bool(
            kernel32.ReadProcessMemory(
                process,
                ctypes.c_void_p(address),
                buffer,
                size,
                ctypes.byref(bytes_read),
            ),
            "ReadProcessMemory",
        )
        return buffer.raw[: bytes_read.value]
    finally:
        kernel32.CloseHandle(process)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Disassemble a window around a live-process RVA or VA")
    parser.add_argument("--process", default="SkyrimVR.exe", help="Process name to attach to")
    parser.add_argument("--module", default="SkyrimVR.exe", help="Module name to read from")
    parser.add_argument("--pid", type=int, help="Explicit PID to attach to")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--rva", type=parse_int, help="Target RVA, for example 0x1DA6B6")
    group.add_argument("--va", type=parse_int, help="Target virtual address")
    parser.add_argument("--before", type=parse_int, default=32, help="Bytes to include before the target")
    parser.add_argument("--after", type=parse_int, default=64, help="Bytes to include after the target")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    process = ProcessInfo(pid=args.pid, exe_name=args.process) if args.pid is not None else find_process_by_name(args.process)
    module = find_module(process.pid, args.module)

    target_rva = args.rva if args.rva is not None else args.va - module.base_address
    if target_rva < 0:
        raise SystemExit("Computed RVA is negative")

    window_start_rva = max(0, target_rva - args.before)
    window_size = args.before + args.after
    if args.rva is not None:
        window_size += 1

    window_address = module.base_address + window_start_rva
    blob = read_process_bytes(process.pid, window_address, window_size)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    md.skipdata = True

    target_va = module.base_address + target_rva

    print(f"process   : {process.exe_name} (pid={process.pid})")
    print(f"module    : {module.name}")
    print(f"path      : {module.path}")
    print(f"base addr : 0x{module.base_address:X}")
    print(f"module sz : 0x{module.size:X}")
    print(f"target rva: 0x{target_rva:X}")
    print(f"target va : 0x{target_va:X}")
    print()

    for insn in md.disasm(blob, window_address):
        marker = ">>" if insn.address == target_va else "  "
        if insn.address < target_va < insn.address + insn.size:
            marker = "*>"
        print(f"{marker} {insn.address:016X}  {format_bytes(insn.bytes):<32} {insn.mnemonic} {insn.op_str}".rstrip())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
