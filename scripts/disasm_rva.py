from __future__ import annotations

import argparse
from pathlib import Path

try:
    from .inspect_common import (
        ModuleInfo,
        build_capture_window,
        disassemble_window,
        format_hex,
        parse_int,
        require_capstone,
        validate_window_request,
    )
except ImportError:
    from inspect_common import (
        ModuleInfo,
        build_capture_window,
        disassemble_window,
        format_hex,
        parse_int,
        require_capstone,
        validate_window_request,
    )


def require_pefile() -> object:
    try:
        import pefile
    except (ModuleNotFoundError, ImportError) as exc:
        raise SystemExit(
            "Missing dependency 'pefile'. Run .\\setup.ps1 or install requirements.txt into the active environment."
        ) from exc
    return pefile


def resolve_section(pe: object, rva: int) -> object:
    for section in pe.sections:
        start = section.VirtualAddress
        end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
        if start <= rva < end:
            return section
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

    validate_window_request(args.before, args.after)
    pefile = require_pefile()
    require_capstone()

    exe_path = Path(args.exe)
    try:
        pe = pefile.PE(str(exe_path), fast_load=False)
    except (OSError, pefile.PEFormatError) as exc:
        raise SystemExit(f"Failed to open PE '{exe_path}': {exc}") from exc
    image_base = pe.OPTIONAL_HEADER.ImageBase
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    target_rva = args.rva if args.rva is not None else args.va - image_base

    module = ModuleInfo(
        name=exe_path.name,
        path=str(exe_path.resolve()),
        base_address=image_base,
        size=size_of_image,
    )
    window = build_capture_window(module, target_rva, args.before, args.after)
    try:
        section = resolve_section(pe, window.target_rva)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    blob = pe.get_memory_mapped_image()[window.start_rva : window.end_rva_exclusive]
    if len(blob) != window.size:
        raise SystemExit(
            f"Failed to read full PE window at {format_hex(window.start_rva)} size {format_hex(window.size)}"
        )

    print(f"file      : {exe_path}")
    print(f"image base: {format_hex(image_base)}")
    section_name = bytes(section.Name).split(b"\x00", 1)[0].decode(errors="replace")
    print(f"section   : {section_name}")
    print(f"target rva: {format_hex(window.target_rva)}")
    print(f"target va : {format_hex(window.target_va)}")
    print()

    for line in disassemble_window(blob, window.start_va, window.target_va):
        print(
            f"{line.marker} {line.address:016X}  "
            f"{line.bytes_hex:<32} {line.mnemonic} {line.op_str}".rstrip()
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
