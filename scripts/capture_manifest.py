from __future__ import annotations

import argparse
import json
import re
import sys
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

try:
    from .inspect_common import (
        build_capture_window,
        close_handle,
        disassembly_to_jsonable,
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
        disassembly_to_jsonable,
        disassemble_window,
        format_hex,
        open_process_for_reading,
        parse_int,
        read_process_bytes_from_handle,
        require_capstone,
        resolve_process_and_module,
        validate_window_request,
    )

VALID_CANDIDATE_GROUPS = frozenset({"current_validated", "discarded_guess", "legacy_ng"})


@dataclass
class Candidate:
    label: str
    rva: int
    group: str
    notes: str | None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Capture a labeled candidate manifest from a live process")
    parser.add_argument("--manifest", required=True, help="Path to a JSON manifest of labeled candidates")
    parser.add_argument("--process", default="SkyrimVR.exe", help="Process name to attach to")
    parser.add_argument("--module", default="SkyrimVR.exe", help="Module name to read from")
    parser.add_argument("--pid", type=int, help="Explicit PID to attach to")
    parser.add_argument("--group", action="append", help="Restrict capture to one or more candidate groups")
    parser.add_argument(
        "--process-state",
        choices=["unpatched", "patched", "unknown"],
        default="unknown",
        help="Operator annotation for the current target process state",
    )
    parser.add_argument("--before", type=parse_int, default=32, help="Bytes to include before each target")
    parser.add_argument("--after", type=parse_int, default=64, help="Bytes to include after each target")
    parser.add_argument(
        "--output-path",
        help="Optional output path for the evidence bundle. Defaults under evidence\\ when omitted",
    )
    parser.add_argument("--overwrite", action="store_true", help="Allow overwriting an existing output file")
    return parser


def parse_rva(value: object, label: str) -> int:
    rva: int
    if isinstance(value, bool):
        raise ValueError(f"Candidate '{label}' has an invalid rva value: {value!r}")
    if isinstance(value, int):
        rva = value
    elif isinstance(value, str):
        rva = parse_int(value)
    else:
        raise ValueError(f"Candidate '{label}' has an invalid rva value: {value!r}")

    if rva < 0:
        raise ValueError(f"Candidate '{label}' has a negative rva: {value!r}")
    return rva


def load_manifest(path: Path) -> tuple[dict[str, object], list[Candidate]]:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except UnicodeError as exc:
        raise SystemExit(f"Failed to decode manifest '{path}' as UTF-8: {exc}") from exc
    except OSError as exc:
        reason = exc.strerror or str(exc)
        raise SystemExit(f"Failed to read manifest '{path}': {reason}") from exc

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"Failed to parse manifest '{path}': line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc

    if not isinstance(payload, dict):
        raise SystemExit(f"Manifest '{path}' must be a JSON object at the top level")

    raw_candidates = payload.get("candidates")
    if not isinstance(raw_candidates, list):
        raise SystemExit("Manifest must contain a 'candidates' array")

    candidates: list[Candidate] = []
    for index, raw in enumerate(raw_candidates, start=1):
        if not isinstance(raw, dict):
            raise SystemExit(f"Manifest candidate #{index} is not an object")

        label = raw.get("label")
        group = raw.get("group")
        if not isinstance(label, str) or not label:
            raise SystemExit(f"Manifest candidate #{index} is missing a non-empty 'label'")
        if not isinstance(group, str) or not group:
            raise SystemExit(f"Candidate '{label}' is missing a non-empty 'group'")
        if group not in VALID_CANDIDATE_GROUPS:
            expected = ", ".join(sorted(VALID_CANDIDATE_GROUPS))
            raise SystemExit(f"Candidate '{label}' has unknown group '{group}'. Expected one of: {expected}")

        notes = raw.get("notes")
        if notes is not None and not isinstance(notes, str):
            raise SystemExit(f"Candidate '{label}' has a non-string 'notes' field")

        try:
            rva = parse_rva(raw.get("rva"), label)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc

        candidates.append(Candidate(label=label, rva=rva, group=group, notes=notes))

    return payload, candidates


def filter_candidates(candidates: list[Candidate], groups: list[str] | None) -> list[Candidate]:
    if not groups:
        return candidates
    valid_casefold = {name.casefold() for name in VALID_CANDIDATE_GROUPS}
    invalid = sorted({group for group in groups if group.casefold() not in valid_casefold})
    if invalid:
        expected = ", ".join(sorted(VALID_CANDIDATE_GROUPS))
        requested = ", ".join(invalid)
        raise SystemExit(f"Unknown --group value(s): {requested}. Expected one of: {expected}")
    wanted = {group.casefold() for group in groups}
    return [candidate for candidate in candidates if candidate.group.casefold() in wanted]


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def compact_timestamp(timestamp: str) -> str:
    return re.sub(r"[^0-9]", "", timestamp)


def serialize_error(exc: BaseException, *, traceback_text: str | None = None) -> dict[str, object]:
    payload: dict[str, object] = {
        "type": type(exc).__name__,
        "message": str(exc),
    }
    for attribute in ("errno", "winerror", "strerror"):
        value = getattr(exc, attribute, None)
        if value is not None:
            payload[attribute] = value
    if traceback_text is not None:
        payload["traceback"] = traceback_text
    return payload


def manifest_slug(path: Path) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", path.stem).strip("-")
    return slug or "manifest"


def build_output_path(
    output_path: str | None,
    timestamp: str,
    process_state: str,
    pid: int,
    manifest_path: Path,
) -> Path:
    if output_path is not None:
        return Path(output_path)
    return Path("evidence") / (
        f"capture_{compact_timestamp(timestamp)}_{process_state}_pid{pid}_{manifest_slug(manifest_path)}.json"
    )


def write_json_atomic(path: Path, payload: dict[str, object], overwrite: bool) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        reason = exc.strerror or str(exc)
        raise SystemExit(f"Failed to prepare output directory for '{path}': {reason}") from exc

    lock_path = path.with_name(f"{path.name}.lock")
    temp_path = path.with_name(f"{path.name}.tmp.{uuid4().hex}")
    owns_lock = False
    try:
        try:
            with lock_path.open("x", encoding="utf-8"):
                pass
            owns_lock = True
        except FileExistsError as exc:
            raise SystemExit(
                f"Refusing to write evidence bundle because a writer is already active for: {path}"
            ) from exc

        if not overwrite:
            if path.exists():
                raise SystemExit(f"Refusing to overwrite existing evidence bundle: {path}")

        try:
            temp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            temp_path.replace(path)
        except OSError as exc:
            reason = exc.strerror or str(exc)
            raise SystemExit(f"Failed to write evidence bundle '{path}': {reason}") from exc
    finally:
        try:
            if temp_path.exists():
                temp_path.unlink()
        except OSError:
            pass
        try:
            if owns_lock and lock_path.exists():
                lock_path.unlink()
        except OSError:
            pass


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    manifest_payload, candidates = load_manifest(manifest_path)
    selected = filter_candidates(candidates, args.group)
    if not selected:
        raise SystemExit("No manifest candidates matched the requested group filter")

    validate_window_request(args.before, args.after)
    require_capstone()
    process, module = resolve_process_and_module(args.process, args.module, args.pid)
    timestamp = utc_timestamp()
    output_path = build_output_path(
        args.output_path,
        timestamp,
        args.process_state,
        process.pid,
        manifest_path,
    )

    bundle: dict[str, object] = {
        "capture_timestamp": timestamp,
        "capture_mode": "live_process",
        "process_state": args.process_state,
        "manifest": {
            "path": str(manifest_path.resolve()),
            "version": manifest_payload.get("version"),
            "group_filter": args.group or [],
        },
        "process": {
            "name": process.exe_name,
            "pid": process.pid,
        },
        "module": {
            "name": module.name,
            "path": module.path,
            "base_address": format_hex(module.base_address),
            "size": format_hex(module.size),
        },
        "window": {
            "before": args.before,
            "after": args.after,
            "requested_size": args.before + args.after + 1,
        },
        "results": [],
    }

    ok_count = 0
    error_count = 0
    unexpected_error_count = 0

    process_handle = open_process_for_reading(process.pid)
    try:
        for candidate in selected:
            result: dict[str, object] = {
                "label": candidate.label,
                "group": candidate.group,
                "notes": candidate.notes,
                "target_rva": format_hex(candidate.rva),
            }

            try:
                window = build_capture_window(module, candidate.rva, args.before, args.after)
                window_payload = {
                    "start_rva": format_hex(window.start_rva),
                    "start_va": format_hex(window.start_va),
                    "end_rva_exclusive": format_hex(window.end_rva_exclusive),
                    "end_va_exclusive": format_hex(window.end_va_exclusive),
                    "requested_before": window.requested_before,
                    "requested_after": window.requested_after,
                    "actual_before": window.actual_before,
                    "actual_after": window.actual_after,
                    "size": window.size,
                }
                blob = read_process_bytes_from_handle(process_handle, window.start_va, window.size)
                disassembly = disassembly_to_jsonable(disassemble_window(blob, window.start_va, window.target_va))
                result["target_va"] = format_hex(window.target_va)
                result["window"] = window_payload
                result["status"] = "ok"
                result["raw_bytes_hex"] = blob.hex().upper()
                result["raw_bytes_len"] = len(blob)
                result["disassembly"] = disassembly
                ok_count += 1
            except SystemExit as exc:
                result["status"] = "error"
                result["error_kind"] = "validation"
                result["error"] = serialize_error(exc)
                error_count += 1
                print(f"capture validation error [{candidate.label}] {exc}", file=sys.stderr)
            except OSError as exc:
                result["status"] = "error"
                result["error_kind"] = "operational"
                result["error"] = serialize_error(exc)
                error_count += 1
                print(f"capture error [{candidate.label}] {exc}", file=sys.stderr)
            except Exception as exc:
                traceback_text = traceback.format_exc()
                result["status"] = "error"
                result["error_kind"] = "internal"
                result["error"] = serialize_error(exc, traceback_text=traceback_text)
                error_count += 1
                unexpected_error_count += 1
                print(f"capture internal error [{candidate.label}] {exc}", file=sys.stderr)
                print(traceback_text, file=sys.stderr, end="")

            bundle["results"].append(result)
    finally:
        close_handle(process_handle)

    bundle["summary"] = {
        "candidate_count": len(selected),
        "captured_ok": ok_count,
        "captured_error": error_count,
        "captured_unexpected_error": unexpected_error_count,
    }

    write_json_atomic(output_path, bundle, overwrite=args.overwrite)

    print(f"manifest   : {manifest_path.resolve()}")
    print(f"process    : {process.exe_name} (pid={process.pid})")
    print(f"module     : {module.name}")
    print(f"state      : {args.process_state}")
    print(f"candidates : {len(selected)}")
    print(f"captured   : {ok_count} ok, {error_count} error")
    print(f"output     : {output_path.resolve()}")

    if error_count:
        print(f"errors     : {error_count} capture error(s) recorded; see bundle for details", file=sys.stderr)
    if unexpected_error_count:
        print(
            f"unexpected : {unexpected_error_count} internal error(s) recorded; see bundle for details",
            file=sys.stderr,
        )
        return 1
    if error_count:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
