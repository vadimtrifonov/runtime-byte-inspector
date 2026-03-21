from __future__ import annotations

import argparse
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


def parse_int(value: str) -> int:
    return int(value, 0)


def format_bytes(data: bytes) -> str:
    return " ".join(f"{byte:02X}" for byte in data)


def resolve_rva(pe: pefile.PE, rva: int) -> tuple[int, pefile.SectionStructure]:
    for section in pe.sections:
        start = section.VirtualAddress
        end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
        if start <= rva < end:
            offset = section.PointerToRawData + (rva - start)
            return offset, section
    raise ValueError(f"RVA 0x{rva:X} is not inside a mapped section")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Disassemble a window around a PE RVA or VA")
    parser.add_argument("--exe", required=True, help="Path to the PE file")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--rva", type=parse_int, help="Target RVA, for example 0x1DA6B6")
    group.add_argument("--va", type=parse_int, help="Target virtual address")
    parser.add_argument("--before", type=parse_int, default=32, help="Bytes to include before the target")
    parser.add_argument("--after", type=parse_int, default=64, help="Bytes to include after the target")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    exe_path = Path(args.exe)
    pe = pefile.PE(str(exe_path), fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    target_rva = args.rva if args.rva is not None else args.va - image_base

    file_offset, section = resolve_rva(pe, target_rva)
    window_start_rva = max(0, target_rva - args.before)
    window_end_rva = target_rva + args.after
    window_offset, _ = resolve_rva(pe, window_start_rva)
    window_size = window_end_rva - window_start_rva

    with exe_path.open("rb") as handle:
        handle.seek(window_offset)
        blob = handle.read(window_size)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    md.skipdata = True

    print(f"file      : {exe_path}")
    print(f"image base: 0x{image_base:X}")
    section_name = bytes(section.Name).split(b"\x00", 1)[0].decode(errors="replace")
    print(f"section   : {section_name}")
    print(f"target rva: 0x{target_rva:X}")
    print(f"target va : 0x{image_base + target_rva:X}")
    print(f"file offs : 0x{file_offset:X}")
    print()

    target_va = image_base + target_rva
    for insn in md.disasm(blob, image_base + window_start_rva):
        marker = ">>" if insn.address == target_va else "  "
        if insn.address < target_va < insn.address + insn.size:
            marker = "*>"
        print(f"{marker} {insn.address:016X}  {format_bytes(insn.bytes):<32} {insn.mnemonic} {insn.op_str}".rstrip())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
