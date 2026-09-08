import struct
from pathlib import Path

BASE = 0x140000000


def write_pe(path: Path, code: bytes = b"\x90\xc3", *, machine: int = 0x8664) -> Path:
    """A PE with headers, one raw .text section, and an unbacked virtual tail."""
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 1, 0x65A00001, 0, 0, 240, 0x2022)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B if machine == 0x8664 else 0x10B)
    struct.pack_into("<I", data, optional + 4, 0x200)
    struct.pack_into("<IIQII", data, optional + 16, 0x1000, 0x1000, BASE, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, optional + 108, 16)
    section = optional + 240
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x300, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200 : 0x200 + len(code)] = code
    path.write_bytes(data)
    return path


def ok_result(label: str, raw: bytes, rva: int = 0x1000, before: int = 0) -> dict:
    return {
        "target": {"label": label, "group": "code", "rva": hex(rva)},
        "read": {"status": "ok", "start_rva": hex(rva - before), "bytes_hex": raw.hex()},
    }


def saved_capture(results: list[dict], before: int = 0, after: int = 1) -> dict:
    return {
        "started_at": "2026-03-21T00:00:00Z",
        "finished_at": "2026-03-21T00:00:01Z",
        "source": {
            "kind": "live_process",
            "process": {"name": "Example.exe", "pid": 12345},
            "module": {"path": "C:\\Game\\Example.exe", "base_address": hex(BASE), "image_size": 0x2000},
        },
        "annotations": {"patch_state": "unknown"},
        "request": {"window": {"before": before, "after": after}},
        "results": results,
    }
