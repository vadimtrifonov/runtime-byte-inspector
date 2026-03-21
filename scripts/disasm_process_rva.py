from __future__ import annotations

import argparse

try:
    from .inspect_common import (
        build_capture_window,
        close_handle,
        disassemble_window,
        format_hex,
        open_process_for_reading,
        parse_int,
        read_process_bytes_from_handle,
        require_capstone,
        resolve_process_and_module,
        validate_window_request,
    )
except ImportError:
    from inspect_common import (
        build_capture_window,
        close_handle,
        disassemble_window,
        format_hex,
        open_process_for_reading,
        parse_int,
        read_process_bytes_from_handle,
        require_capstone,
        resolve_process_and_module,
        validate_window_request,
    )


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

    validate_window_request(args.before, args.after)
    require_capstone()
    process, module = resolve_process_and_module(args.process, args.module, args.pid)

    target_rva = args.rva if args.rva is not None else args.va - module.base_address
    window = build_capture_window(module, target_rva, args.before, args.after)
    process_handle = open_process_for_reading(process.pid)
    try:
        blob = read_process_bytes_from_handle(process_handle, window.start_va, window.size)
    finally:
        close_handle(process_handle)

    print(f"process   : {process.exe_name} (pid={process.pid})")
    print(f"module    : {module.name}")
    print(f"path      : {module.path}")
    print(f"base addr : {format_hex(module.base_address)}")
    print(f"module sz : {format_hex(module.size)}")
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
