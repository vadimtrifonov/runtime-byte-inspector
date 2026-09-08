from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .capture import (
    PATCH_STATES,
    Target,
    capture_targets,
    integer,
    load_target_list,
    validate_window,
    write_capture,
)
from .compare import compare_captures, render_report
from .pe import PeImage


def address(value: str) -> int:
    return integer(value, "address/byte count")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="runtime-byte-inspector", description="Inspect and compare bounded AMD64 byte captures"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="Print one PE or live-process byte window")
    capture = commands.add_parser("capture", help="Read a target list and save one JSON capture")
    for command in (inspect, capture):
        source = command.add_mutually_exclusive_group(required=True)
        source.add_argument("--file", type=Path, help="PE file (disk bytes, not a live image)")
        source.add_argument("--pid", type=int, help="PID to read; no process-name default")
        source.add_argument("--process", help="Exact executable name; must match one running process")
        command.add_argument("--module", help="Loaded module name (default: the process executable)")
        command.add_argument("--before", type=address, default=32, help="Bytes before target (default: 32)")
        command.add_argument("--after", type=address, default=64, help="Bytes after target (default: 64)")
        command.add_argument(
            "--patch-state", choices=PATCH_STATES, help="Live-target annotation (default: unknown)"
        )
        command.add_argument("--runtime", help="Optional operator-supplied runtime/build description")
    target = inspect.add_mutually_exclusive_group(required=True)
    target.add_argument("--rva", type=address, help="Target module-relative address")
    target.add_argument("--va", type=address, help="Live VA, or preferred-image VA for a file")
    inspect.add_argument(
        "--decode-rva", type=address, help="Assumed instruction start within the window (default: target)"
    )
    inspect.add_argument("--format", choices=("text", "json"), default="text")
    capture.add_argument("--targets", type=Path, required=True, help="Target-list JSON file")
    capture.add_argument(
        "--group", action="append", help="Select an exact target group; repeat for multiple groups"
    )
    capture.add_argument("--output", type=Path, required=True, help="Destination JSON capture")
    capture.add_argument("--overwrite", action="store_true", help="Replace an existing destination")

    compare = commands.add_parser("compare", help="Compare two saved captures")
    compare.add_argument("left", type=Path)
    compare.add_argument("right", type=Path)
    compare.add_argument("--left-label", help="Select one left result instead of pairing equal labels")
    compare.add_argument("--right-label", help="Select one right result; required with --left-label")
    compare.add_argument(
        "--alignment",
        choices=("rva", "target"),
        default="rva",
        help="Align module RVAs or offsets from each target (default: rva)",
    )
    compare.add_argument("--format", choices=("text", "json"), default="json")
    return parser


def open_source(args):
    if args.file is not None:
        return PeImage(args.file)
    from .windows import LiveProcess

    return LiveProcess(pid=args.pid, name=args.process, module_name=args.module)


def render_inspection(capture: dict) -> str:
    source = capture["source"]
    module = source["module"]
    base = int(module["base_address"], 0)
    lines = [f"source: {source['kind']} {module['path']}", f"base: {module['base_address']}"]
    if "process" in source:
        lines.append(f"pid: {source['process']['pid']}")
        lines.append(f"patch state (annotation): {capture['annotations']['patch_state']}")
    result = capture["results"][0]
    target_rva = int(result["target"]["rva"], 0)
    lines.append(f"target RVA: {target_rva:#x} VA: {base + target_rva:#x}")
    if result["read"]["status"] == "error":
        return "\n".join(lines)
    blob = bytes.fromhex(result["read"]["bytes_hex"])
    start = int(result["read"]["start_rva"], 0)
    lines.append("\nCaptured bytes (RVA):")
    for offset in range(0, len(blob), 16):
        lines.append(f"  {start + offset:08X}  {blob[offset : offset + 16].hex(' ').upper()}")
    decoded = result["decode"]
    lines.append(f"\nDecode from assumed instruction start {decoded['start_rva']}: {decoded['status']}")
    end = int(decoded["start_rva"], 0)
    for instruction in decoded.get("instructions", []):
        rva = int(instruction["rva"], 0)
        end = rva + len(bytes.fromhex(instruction["bytes_hex"]))
        marker = ">>" if rva == target_rva else ("*>" if rva < target_rva < end else "  ")
        lines.append(
            f"{marker} {base + rva:016X}  "
            f"{instruction['bytes_hex']:<30} {instruction['mnemonic']} {instruction['operands']}".rstrip()
        )
    if decoded["status"] == "incomplete":
        lines.append(f"undecoded from {end:#x}: {blob[end - start :].hex().upper()}")
    return "\n".join(lines)


def report_capture_errors(capture: dict) -> bool:
    failed = False
    for result in capture["results"]:
        error = result["read"].get("error") or result.get("decode", {}).get("error")
        if error is not None:
            failed = True
            print(f"error [{result['target']['label']}]: {error['message']}", file=sys.stderr)
    return failed


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "compare":
            report = compare_captures(
                args.left,
                args.right,
                left_label=args.left_label,
                right_label=args.right_label,
                alignment=args.alignment,
            )
            print(json.dumps(report, indent=2) if args.format == "json" else render_report(report))
            return 0

        validate_window(args.before, args.after)
        if args.file is not None and (args.module is not None or args.patch_state is not None):
            raise ValueError("--module and --patch-state apply only to live processes")
        if args.runtime is not None and not args.runtime.strip():
            raise ValueError("--runtime must not be empty")
        target_list, targets = (
            load_target_list(args.targets, args.group) if args.command == "capture" else (None, [])
        )
        with open_source(args) as source:
            if args.command == "inspect":
                rva = args.rva if args.rva is not None else args.va - source.module.base
                if rva < 0:
                    raise ValueError("Target VA is below the selected image base")
                targets = [Target("site", rva, decode_rva=args.decode_rva)]
            capture = capture_targets(
                source,
                targets,
                args.before,
                args.after,
                target_list=target_list,
                groups=args.group if args.command == "capture" else None,
                patch_state=args.patch_state or "unknown",
                runtime=args.runtime,
            )
        if args.command == "capture":
            write_capture(args.output, capture, args.overwrite)
            print(args.output.resolve())
        else:
            print(json.dumps(capture, indent=2) if args.format == "json" else render_inspection(capture))
        return int(report_capture_errors(capture))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
