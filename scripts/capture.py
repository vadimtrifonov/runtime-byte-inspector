from __future__ import annotations

import hashlib
import json
import os
import platform
import tempfile
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

from .instructions import decode, span_facts
from .targets import MAX_FOLLOW_HOPS, PATCH_STATES, Target, absolute_window, validate_window, window_bounds


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def error_details(exc: Exception) -> dict:
    return {
        "type": type(exc).__name__,
        "message": str(exc),
        **{key: getattr(exc, key) for key in ("errno", "winerror") if getattr(exc, key, None) is not None},
    }


def locate(source, va: int) -> dict:
    try:
        return source.describe(va)
    except (OSError, ValueError) as exc:
        return {"va": hex(va), "error": error_details(exc)}


def read_memory(source, va: int, size: int, *, start_rva: int | None = None) -> dict:
    read = {"start_va": hex(va), "requested_bytes": size, "started_at": now()}
    if start_rva is not None:
        read["start_rva"] = hex(start_rva)
    try:
        absolute_window(va, 0, size - 1)
        blob = source.read_va(va, size)
        if len(blob) != size:
            raise OSError(f"Short read at VA {va:#x}: wanted {size}, read {len(blob)} bytes")
        read.update(status="ok", bytes_hex=blob.hex().upper())
    except (OSError, ValueError) as exc:
        read.update(status="error", error=error_details(exc))
    read["finished_at"] = now()
    return read


def pointer_value(source, read: dict) -> dict:
    value = int.from_bytes(bytes.fromhex(read["bytes_hex"]), "little")
    return {"target_va": hex(value), "destination": locate(source, value)}


def resolve_relationships(source, decoded: dict) -> None:
    for instruction in decoded["instructions"]:
        flow = instruction["flow"]
        for operand in instruction["operand_details"]:
            address = operand.get("address_va")
            if address is not None and address != flow.get("pointer_va"):
                operand["location"] = locate(source, int(address, 0))
        if flow.get("resolution") == "pointer":
            slot = int(flow["pointer_va"], 0)
            pointer = {"location": locate(source, slot), "read": read_memory(source, slot, 8)}
            flow["pointer"] = pointer
            if pointer["read"]["status"] == "ok":
                flow.update(pointer_value(source, pointer["read"]))
        elif "target_va" in flow:
            flow["destination"] = locate(source, int(flow["target_va"], 0))


def capture_target(target: Target, source, before: int, after: int) -> dict:
    result = {"target": target.to_dict()}
    base = source.module.base
    try:
        if target.rva is not None:
            va = base + target.rva
            if target.kind == "pointer":
                if not 0 <= target.rva < target.rva + 8 <= source.module.size:
                    raise ValueError("Pointer cell is outside the selected module")
                start, end = target.rva, target.rva + 8
            else:
                start, end = window_bounds(source.module.size, target.rva, before, after)
            start_va, end_va = base + start, base + end
        else:
            va = target.va
            start_va, end_va = (
                absolute_window(va, 0, 7) if target.kind == "pointer" else absolute_window(va, before, after)
            )
        result["location"] = locate(source, va)
        result["read"] = read_memory(
            source,
            start_va,
            end_va - start_va,
            start_rva=start_va - base if target.rva is not None else None,
        )
    except (OSError, ValueError) as exc:
        result["read"] = {"status": "error", "error": error_details(exc)}
    if result["read"]["status"] == "error":
        return result
    if target.kind == "pointer":
        result["pointer"] = pointer_value(source, result["read"])
        return result
    origin = (
        base + target.decode_rva
        if target.decode_rva is not None
        else (target.decode_va if target.decode_va is not None else va)
    )
    try:
        if not start_va <= origin <= va:
            raise ValueError(
                "decode_rva/decode_va must be inside the captured window, at or before the target"
            )
        blob = bytes.fromhex(result["read"]["bytes_hex"])
        owner = result["location"].get("module")
        owner_base = int(owner["base_address"], 0) if owner is not None else None
        # Only emit module RVAs when the entire decoding window is inside that image.
        if owner_base is not None and not owner_base <= origin < end_va <= owner_base + owner["image_size"]:
            owner_base = None
        decoded = decode(blob[origin - start_va :], origin, owner_base)
        result["decode"] = decoded
        decoded["origin_basis"] = (
            "target_assumed"
            if target.decode_rva is None and target.decode_va is None
            else "operator_supplied"
        )
        starts = any(int(instruction["va"], 0) == va for instruction in decoded["instructions"])
        inside = any(
            int(instruction["va"], 0) < va < int(instruction["va"], 0) + instruction["size"]
            for instruction in decoded["instructions"]
        )
        decoded["target_position"] = (
            "instruction_start" if starts else ("inside_instruction" if inside else "not_decoded")
        )
        if target.span is not None:
            result["span"] = span_facts(decoded, va, target.span)
        if source.kind == "live_process":
            resolve_relationships(source, decoded)
    except Exception as exc:
        # Acquisition remains available even if decoding or enrichment fails.
        result["decode"] = {
            **result.get("decode", {}),
            "status": "error",
            "start_va": hex(origin),
            "error": error_details(exc),
        }
    return result


def next_transfer(result: dict) -> tuple[int | None, str]:
    if result["read"]["status"] != "ok":
        return None, "read_error"
    if result["target"].get("kind") == "pointer":
        return int(result["pointer"]["target_va"], 0), "pointer"
    decoded = result["decode"]
    if decoded["status"] == "error":
        return None, "decode_error"
    if decoded["target_position"] != "instruction_start":
        return None, "target_not_instruction_start"
    instructions = decoded["instructions"]
    if not instructions or instructions[-1]["flow"]["kind"] != "jump":
        return None, decoded["stop_reason"]
    flow = instructions[-1]["flow"]
    if "target_va" not in flow:
        return None, "pointer_read_error" if "pointer" in flow else "unresolved"
    return int(flow["target_va"], 0), "jump"


def follow_transfers(source, result: dict, after: int, limit: int) -> dict:
    follow = {"limit": limit, "hops": [], "stop_reason": "hop_limit"}
    current = result
    seen = set()
    if result["target"].get("kind", "code") == "code" and "location" in result:
        seen.add(int(result["location"]["va"], 0))
    for index in range(limit):
        va, reason = next_transfer(current)
        if va is None:
            follow["stop_reason"] = reason
            break
        if va in seen:
            follow["stop_reason"] = "cycle"
            follow["stopped_at_va"] = hex(va)
            break
        seen.add(va)
        location = locate(source, va)
        region = location.get("region", {})
        if "error" in location or not region.get("readable") or not region.get("executable"):
            follow["stopped_at"] = location
            follow["stop_reason"] = (
                "destination_error"
                if "error" in location
                else ("not_readable" if not region.get("readable") else "not_executable")
            )
            break
        target = Target(f"{result['target']['label']}/hop-{index + 1}", va=va)
        current = capture_target(target, source, 0, after)
        follow["hops"].append(current)
    else:
        # Report a natural endpoint reached on the last permitted window, rather than a false limit hit.
        va, reason = next_transfer(current)
        if va is None:
            follow["stop_reason"] = reason
        elif va in seen:
            follow.update(stop_reason="cycle", stopped_at_va=hex(va))
    return follow


def iter_errors(value, path: str = ""):
    if isinstance(value, dict):
        if isinstance(value.get("error"), dict):
            yield path, value["error"]
        for key, child in value.items():
            if key != "error":
                yield from iter_errors(child, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_errors(child, f"{path}[{index}]")


def tool_metadata() -> dict:
    digest = hashlib.sha256()
    for path in sorted(Path(__file__).parent.glob("*.py")):
        digest.update(path.name.encode("utf-8") + b"\0" + path.read_bytes() + b"\0")
    return {
        "name": "runtime-byte-inspector",
        "source_sha256": digest.hexdigest(),
        "python": platform.python_version(),
    }


def capture_targets(
    source,
    targets: list[Target],
    before: int,
    after: int,
    *,
    target_list: dict | None = None,
    groups: list[str] | None = None,
    patch_state: str = "unknown",
    runtime: str | None = None,
    follow: int = 0,
) -> dict:
    validate_window(before, after)
    if not 0 <= follow <= MAX_FOLLOW_HOPS:
        raise ValueError(f"follow must be 0..{MAX_FOLLOW_HOPS}")
    if source.kind != "live_process" and (
        follow or any(t.va is not None or t.kind == "pointer" for t in targets)
    ):
        raise ValueError("VA target lists, pointer reads, and jump following require a live process")
    if any(t.span is not None and t.span > after + 1 for t in targets):
        raise ValueError("Instruction span must fit after + 1 bytes; increase --after")
    capture = {
        "started_at": now(),
        "source": source.metadata(),
        "request": {"window": {"before": before, "after": after}, "follow": follow},
        "annotations": {},
        "tool": tool_metadata(),
        "atomic": False,
        "decoder": {"name": "capstone", "version": version("capstone"), "architecture": "x86_64"},
    }
    if source.kind == "live_process":
        if patch_state not in PATCH_STATES:
            raise ValueError(f"Invalid patch state: {patch_state!r}")
        capture["annotations"]["patch_state"] = patch_state
    if runtime is not None:
        capture["annotations"]["runtime"] = runtime
    if target_list is not None:
        capture["request"]["target_list"] = target_list
    if groups:
        capture["request"]["groups"] = groups
    results = []
    for target in targets:
        result = capture_target(target, source, before, after)
        if follow:
            result["follow"] = follow_transfers(source, result, after, follow)
        results.append(result)
    capture["results"] = results
    capture["finished_at"] = now()
    capture["summary"] = {
        "target_count": len(results),
        "captured_ok": sum(result["read"]["status"] == "ok" for result in results),
        "captured_error": sum(result["read"]["status"] == "error" for result in results),
        "decode_error": sum(result.get("decode", {}).get("status") == "error" for result in results),
        "error_count": sum(1 for _ in iter_errors(results)),
    }
    return capture


def write_capture(path: Path, capture: dict, overwrite: bool = False) -> None:
    # Windows rename refuses an existing destination; POSIX rename would clobber it.
    if os.name != "nt":
        raise OSError("Saving captures requires Windows no-clobber rename semantics")
    path.parent.mkdir(parents=True, exist_ok=True)
    file = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
    )
    temporary = Path(file.name)
    try:
        with file:
            json.dump(capture, file, indent=2, allow_nan=False)
            file.write("\n")
        if overwrite:
            temporary.replace(path)
        else:
            temporary.rename(path)
    except BaseException as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError as cleanup:
            raise OSError(f"{exc}; also failed to remove temporary file '{temporary}': {cleanup}") from exc
        raise
