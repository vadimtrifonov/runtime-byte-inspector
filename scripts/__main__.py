from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .capture import capture_targets, iter_errors, write_capture
from .compare import compare_captures, render_report
from .pe import PeImage
from .render import render_inspection
from .targets import MAX_FOLLOW_HOPS, PATCH_STATES, Target, integer, load_target_list, validate_window


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
        command.add_argument(
            "--module", help="Loaded module for RVA targets (default: the process executable)"
        )
        command.add_argument(
            "--before", type=address, default=32, help="Code bytes before target (default: 32)"
        )
        command.add_argument(
            "--after",
            type=address,
            default=64,
            help="Code bytes after target, including followed windows (default: 64)",
        )
        command.add_argument(
            "--follow",
            type=address,
            default=0,
            help=f"Follow up to N live jump/pointer hops (0..{MAX_FOLLOW_HOPS}, default: 0)",
        )
        command.add_argument(
            "--patch-state", choices=PATCH_STATES, help="Live-target annotation (default: unknown)"
        )
        command.add_argument("--runtime", help="Optional operator-supplied runtime/build description")
    target = inspect.add_mutually_exclusive_group(required=True)
    target.add_argument("--rva", type=address, help="Target address relative to the selected module")
    target.add_argument(
        "--va", type=address, help="Absolute live-process address, or preferred-image VA for a file"
    )
    origin = inspect.add_mutually_exclusive_group()
    origin.add_argument("--decode-rva", type=address, help="Assumed decoding start for an RVA target")
    origin.add_argument("--decode-va", type=address, help="Assumed decoding start for a VA target")
    inspect.add_argument(
        "--pointer",
        action="store_true",
        help="Read exactly one 8-byte live pointer cell instead of decoding code",
    )
    inspect.add_argument(
        "--span", type=address, help="Summarize the first N target bytes using the captured decoding"
    )
    inspect.add_argument("--format", choices=("text", "json"), default="text")
    capture.add_argument("--targets", type=Path, required=True, help="Target-list JSON file")
    capture.add_argument(
        "--group", action="append", help="Select an exact target group; repeat for multiple groups"
    )
    capture.add_argument("--output", type=Path, required=True, help="Destination JSON capture")
    capture.add_argument("--overwrite", action="store_true", help="Replace an existing destination")
    compare = commands.add_parser("compare", help="Compare primary target windows in two saved captures")
    compare.add_argument("left", type=Path)
    compare.add_argument("right", type=Path)
    compare.add_argument("--left-label", help="Select one left result instead of pairing equal labels")
    compare.add_argument("--right-label", help="Select one right result; required with --left-label")
    compare.add_argument(
        "--alignment",
        choices=("rva", "target"),
        default="rva",
        help="Align module RVAs or offsets from targets; VA targets require target alignment",
    )
    compare.add_argument("--format", choices=("text", "json"), default="json")
    return parser


def open_source(args):
    if args.file is not None:
        return PeImage(args.file)
    from .windows import LiveProcess

    return LiveProcess(pid=args.pid, name=args.process, module_name=args.module)


def report_capture_errors(capture: dict) -> bool:
    failed = False
    for result in capture["results"]:
        for path, error in iter_errors(result):
            failed = True
            print(f"error [{result['target']['label']} {path}]: {error['message']}", file=sys.stderr)
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
        if not 0 <= args.follow <= MAX_FOLLOW_HOPS:
            raise ValueError(f"--follow must be 0..{MAX_FOLLOW_HOPS}")
        if args.file is not None and (
            args.module is not None
            or args.patch_state is not None
            or args.follow
            or getattr(args, "pointer", False)
        ):
            raise ValueError("--module, --patch-state, --follow, and --pointer apply only to live processes")
        if args.runtime is not None and not args.runtime.strip():
            raise ValueError("--runtime must not be empty")
        target_list, targets = (
            load_target_list(args.targets, args.group) if args.command == "capture" else (None, [])
        )
        with open_source(args) as source:
            if args.command == "inspect":
                rva, va = args.rva, args.va
                decode_rva, decode_va = args.decode_rva, args.decode_va
                if args.file is not None and va is not None:
                    rva, va = va - source.module.base, None
                    if rva < 0:
                        raise ValueError("Target VA is below the selected image base")
                    if decode_va is not None:
                        decode_rva, decode_va = decode_va - source.module.base, None
                targets = [
                    Target(
                        "site",
                        rva,
                        va=va,
                        decode_rva=decode_rva,
                        decode_va=decode_va,
                        kind="pointer" if args.pointer else "code",
                        span=args.span,
                    )
                ]
            capture = capture_targets(
                source,
                targets,
                args.before,
                args.after,
                target_list=target_list,
                groups=args.group if args.command == "capture" else None,
                patch_state=args.patch_state or "unknown",
                runtime=args.runtime,
                follow=args.follow,
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
