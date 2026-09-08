from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

import pefile


@dataclass(frozen=True)
class Module:
    name: str
    path: str
    base: int
    size: int
    timestamp: int

    def metadata(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "base_address": hex(self.base),
            "image_size": self.size,
            "machine": "AMD64",
            "pe_timestamp": hex(self.timestamp),
        }


def parse_nt_headers(data: bytes) -> tuple[int, int, int]:
    """Read the preferred image base, image size, and timestamp from PE32+ headers."""
    if len(data) < 88 or data[:4] != b"PE\0\0":
        raise ValueError("Invalid PE signature or truncated NT headers")
    machine, _, timestamp = struct.unpack_from("<HHI", data, 4)
    optional_size = struct.unpack_from("<H", data, 20)[0]
    magic = struct.unpack_from("<H", data, 24)[0]
    if machine != 0x8664 or magic != 0x20B:
        raise ValueError(f"Only AMD64 PE32+ images are supported (machine={machine:#x}, magic={magic:#x})")
    if optional_size < 240:
        raise ValueError("Truncated PE32+ optional header")
    base = struct.unpack_from("<Q", data, 48)[0]
    size = struct.unpack_from("<I", data, 80)[0]
    if size == 0:
        raise ValueError("PE SizeOfImage must be positive")
    return base, size, timestamp


class PeImage:
    """Read file-backed RVA windows without constructing a runtime image."""

    kind = "pe_file"

    def __init__(self, path: Path):
        self.path = path.resolve()
        self.data = self.path.read_bytes()
        try:
            self.pe = pefile.PE(data=self.data, fast_load=True)
        except pefile.PEFormatError as exc:
            raise ValueError(f"Invalid PE file '{self.path}': {exc}") from exc
        try:
            offset = self.pe.DOS_HEADER.e_lfanew
            base, size, timestamp = parse_nt_headers(self.data[offset : offset + 88])
            self.module = Module(self.path.name, str(self.path), base, size, timestamp)
        except BaseException:
            self.pe.close()
            raise

    def __enter__(self) -> PeImage:
        return self

    def __exit__(self, *_):
        self.pe.close()

    def metadata(self) -> dict:
        return {
            "kind": self.kind,
            "module": self.module.metadata(),
            "file_sha256": hashlib.sha256(self.data).hexdigest(),
        }

    def describe(self, va: int) -> dict:
        if not self.module.base <= va < self.module.base + self.module.size:
            raise ValueError("Address is outside the selected PE image")
        return {"va": hex(va), "rva": hex(va - self.module.base), "module": self.module.metadata()}

    def read_va(self, va: int, size: int) -> bytes:
        return self.read(va - self.module.base, size)

    def read(self, rva: int, size: int) -> bytes:
        if rva < 0 or size <= 0 or rva + size > self.module.size:
            raise ValueError("Read is outside the PE image")
        if rva + size <= self.pe.OPTIONAL_HEADER.SizeOfHeaders:
            offset = rva
        else:
            section = self.pe.get_section_by_rva(rva)
            if section is None:
                raise ValueError(f"RVA {rva:#x} has no file-backed PE section")
            section_start = section.get_VirtualAddress_adj()
            if rva + size > section_start + section.SizeOfRawData:
                raise ValueError("PE window crosses a section's raw data boundary; narrow the window")
            offset = section.get_PointerToRawData_adj() + rva - section_start
        blob = self.data[offset : offset + size]
        if len(blob) != size:
            raise OSError(
                f"Truncated PE file at file offset {offset:#x}: wanted {size}, read {len(blob)} bytes"
            )
        return blob
