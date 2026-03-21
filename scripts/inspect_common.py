from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass


TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

ERROR_ACCESS_DENIED = 5
ERROR_NO_MORE_FILES = 18
MAX_PATH = 260
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
MAX_WINDOW_BYTES = 0x1000


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


@dataclass
class DisassemblyLine:
    address: int
    size: int
    bytes_hex: str
    mnemonic: str
    op_str: str
    marker: str


@dataclass
class CaptureWindow:
    target_rva: int
    target_va: int
    start_rva: int
    start_va: int
    end_rva_exclusive: int
    end_va_exclusive: int
    requested_before: int
    requested_after: int
    actual_before: int
    actual_after: int
    size: int


def parse_int(value: str) -> int:
    return int(value, 0)


def format_bytes(data: bytes) -> str:
    return " ".join(f"{byte:02X}" for byte in data)


def format_hex(value: int) -> str:
    return f"0x{value:X}"


def _raise_last_winerror(function_name: str, extra_hint: str | None = None) -> None:
    error = ctypes.get_last_error()
    message = f"{function_name} failed"
    if error == ERROR_ACCESS_DENIED:
        message += ". Access denied. Live-process inspection may require an elevated terminal."
    if extra_hint is not None:
        message += f" {extra_hint}"
    raise ctypes.WinError(error, message)


def checked_bool(result: int, function_name: str, extra_hint: str | None = None) -> None:
    if not result:
        _raise_last_winerror(function_name, extra_hint=extra_hint)


def snapshot(flags: int, pid: int) -> wintypes.HANDLE:
    handle = kernel32.CreateToolhelp32Snapshot(flags, pid)
    if handle == INVALID_HANDLE_VALUE:
        _raise_last_winerror("CreateToolhelp32Snapshot")
    return handle


def close_handle(handle: wintypes.HANDLE) -> None:
    if handle:
        kernel32.CloseHandle(handle)


def _advance_snapshot(result: int, function_name: str) -> bool:
    if result:
        return True
    error = ctypes.get_last_error()
    if error == ERROR_NO_MORE_FILES:
        return False
    _raise_last_winerror(function_name)
    return False


def find_process_by_name(name: str) -> ProcessInfo:
    handle = snapshot(TH32CS_SNAPPROCESS, 0)
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        checked_bool(kernel32.Process32FirstW(handle, ctypes.byref(entry)), "Process32FirstW")

        wanted = name.casefold()
        matches: list[ProcessInfo] = []
        while True:
            if entry.szExeFile.casefold() == wanted:
                matches.append(ProcessInfo(pid=int(entry.th32ProcessID), exe_name=entry.szExeFile))
            ctypes.set_last_error(0)
            if not _advance_snapshot(kernel32.Process32NextW(handle, ctypes.byref(entry)), "Process32NextW"):
                break
    finally:
        close_handle(handle)

    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        pids = ", ".join(str(match.pid) for match in matches)
        raise SystemExit(f"Process name '{name}' matched multiple running PIDs ({pids}). Re-run with --pid.")
    raise SystemExit(f"Process '{name}' is not running")


def find_process_by_pid(pid: int) -> ProcessInfo:
    handle = snapshot(TH32CS_SNAPPROCESS, 0)
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        checked_bool(kernel32.Process32FirstW(handle, ctypes.byref(entry)), "Process32FirstW")

        while True:
            if int(entry.th32ProcessID) == pid:
                return ProcessInfo(pid=pid, exe_name=entry.szExeFile)
            ctypes.set_last_error(0)
            if not _advance_snapshot(kernel32.Process32NextW(handle, ctypes.byref(entry)), "Process32NextW"):
                break
    finally:
        close_handle(handle)

    raise SystemExit(f"Process with pid {pid} is not running")


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
            ctypes.set_last_error(0)
            if not _advance_snapshot(kernel32.Module32NextW(handle, ctypes.byref(entry)), "Module32NextW"):
                break
    finally:
        close_handle(handle)

    raise SystemExit(f"Module '{module_name}' was not found in process {pid}")


def resolve_process_and_module(process_name: str, module_name: str, pid: int | None) -> tuple[ProcessInfo, ModuleInfo]:
    if pid is None:
        process = find_process_by_name(process_name)
    else:
        process = find_process_by_pid(pid)
        if process.exe_name.casefold() != process_name.casefold():
            raise SystemExit(f"PID {pid} is running '{process.exe_name}', not '{process_name}'")
    module = find_module(process.pid, module_name)
    return process, module


def open_process_for_reading(pid: int) -> wintypes.HANDLE:
    process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not process:
        _raise_last_winerror(
            "OpenProcess",
            extra_hint="The target process may be protected, owned by another integrity level, or require elevation.",
        )
    return process


def read_process_bytes_from_handle(process: wintypes.HANDLE, address: int, size: int) -> bytes:
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
        extra_hint="The requested memory window may be unreadable, or the current terminal may need elevation.",
    )
    return buffer.raw[: bytes_read.value]


def read_process_bytes(pid: int, address: int, size: int) -> bytes:
    process = open_process_for_reading(pid)
    try:
        return read_process_bytes_from_handle(process, address, size)
    finally:
        close_handle(process)


def require_capstone() -> tuple[object, int, int]:
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except (ModuleNotFoundError, ImportError) as exc:
        raise SystemExit(
            "Missing dependency 'capstone'. Run .\\setup.ps1 or install requirements.txt into the active environment."
        ) from exc
    return Cs, CS_ARCH_X86, CS_MODE_64


def validate_window_size(name: str, value: int) -> None:
    if value < 0:
        raise SystemExit(f"{name} must be non-negative")
    if value >= MAX_WINDOW_BYTES:
        raise SystemExit(f"{name} must be smaller than {format_hex(MAX_WINDOW_BYTES)} bytes")


def validate_window_request(before: int, after: int) -> None:
    validate_window_size("--before", before)
    validate_window_size("--after", after)

    requested_size = before + after + 1
    if requested_size > MAX_WINDOW_BYTES:
        raise SystemExit(
            f"Requested capture window {format_hex(requested_size)} exceeds maximum {format_hex(MAX_WINDOW_BYTES)}"
        )


def build_capture_window(module: ModuleInfo, target_rva: int, before: int, after: int) -> CaptureWindow:
    if target_rva < 0:
        raise SystemExit("Computed RVA is negative")
    if target_rva >= module.size:
        raise SystemExit(
            f"Target RVA {format_hex(target_rva)} is outside module '{module.name}' size {format_hex(module.size)}"
        )

    start_rva = max(0, target_rva - before)
    end_rva_exclusive = min(module.size, target_rva + after + 1)
    size = end_rva_exclusive - start_rva

    return CaptureWindow(
        target_rva=target_rva,
        target_va=module.base_address + target_rva,
        start_rva=start_rva,
        start_va=module.base_address + start_rva,
        end_rva_exclusive=end_rva_exclusive,
        end_va_exclusive=module.base_address + end_rva_exclusive,
        requested_before=before,
        requested_after=after,
        actual_before=target_rva - start_rva,
        actual_after=end_rva_exclusive - target_rva - 1,
        size=size,
    )


def disassemble_window(blob: bytes, start_address: int, target_address: int) -> list[DisassemblyLine]:
    Cs, CS_ARCH_X86, CS_MODE_64 = require_capstone()

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    md.skipdata = True

    lines: list[DisassemblyLine] = []
    for insn in md.disasm(blob, start_address):
        marker = ">>" if insn.address == target_address else "  "
        if insn.address < target_address < insn.address + insn.size:
            marker = "*>"
        lines.append(
            DisassemblyLine(
                address=insn.address,
                size=insn.size,
                bytes_hex=format_bytes(insn.bytes),
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                marker=marker,
            )
        )
    return lines


def disassembly_to_jsonable(lines: list[DisassemblyLine]) -> list[dict[str, object]]:
    payload: list[dict[str, object]] = []
    for line in lines:
        payload.append(asdict(line))
    return payload
