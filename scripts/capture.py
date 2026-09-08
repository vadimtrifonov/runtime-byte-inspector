from __future__ import annotations

import hashlib
import json
import os
import platform
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

import capstone

from .pe import Module

MAX_WINDOW_BYTES = 4096
PATCH_STATES = ("unpatched", "patched", "unknown")


def integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{field} must be an integer or a decimal/0x-prefixed string")
    try:
        number = int(value, 0) if isinstance(value, str) else value
    except ValueError as exc:
        raise ValueError(f"Invalid {field}: {value!r}") from exc
    if number < 0:
        raise ValueError(f"{field} must be non-negative")
    return number


def text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


@dataclass(frozen=True)
class Target:
    label: str
    rva: int
    group: str | None = None
    notes: str | None = None
    decode_rva: int | None = None

    def to_dict(self) -> dict:
        result = {"label": self.label, "rva": hex(self.rva)}
        if self.group is not None:
            result["group"] = self.group
        if self.notes is not None:
            result["notes"] = self.notes
        if self.decode_rva is not None:
            result["decode_rva"] = hex(self.decode_rva)
        return result


def load_target_list(path: Path, groups: list[str] | None = None) -> tuple[dict, list[Target]]:
    raw = path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("targets"), list):
        raise ValueError("Target list must be an object containing a targets array")
    targets = []
    labels = set()
    for index, entry in enumerate(payload["targets"]):
        if not isinstance(entry, dict):
            raise ValueError(f"Target {index} must be an object")
        label = text(entry.get("label"), f"target {index} label")
        if label in labels:
            raise ValueError(f"Duplicate target label: {label!r}")
        labels.add(label)
        group = entry.get("group")
        if group is not None:
            text(group, f"{label} group")
        notes = entry.get("notes")
        if notes is not None and not isinstance(notes, str):
            raise ValueError(f"{label} notes must be a string")
        decode_rva = entry.get("decode_rva")
        targets.append(
            Target(
                label,
                integer(entry.get("rva"), f"{label} rva"),
                group,
                notes,
                integer(decode_rva, f"{label} decode_rva") if decode_rva is not None else None,
            )
        )
    if groups:
        unknown = set(groups) - {target.group for target in targets}
        if unknown:
            raise ValueError(f"Unknown target group(s): {', '.join(sorted(unknown))}")
        targets = [target for target in targets if target.group in groups]
    if not targets:
        raise ValueError("Target list contains no targets matching the selection")
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        **({"description": payload["description"]} if "description" in payload else {}),
    }, targets


def validate_window(before: int, after: int) -> None:
    if before < 0 or after < 0 or before + after + 1 > MAX_WINDOW_BYTES:
        raise ValueError(
            f"before/after must be non-negative and the window must be at most {MAX_WINDOW_BYTES} bytes"
        )


def window_bounds(module_size: int, rva: int, before: int, after: int) -> tuple[int, int]:
    validate_window(before, after)
    if not 0 <= rva < module_size:
        raise ValueError(f"Target RVA {rva:#x} is outside module size {module_size:#x}")
    return max(0, rva - before), min(module_size, rva + after + 1)


def error_details(exc: Exception) -> dict:
    return {
        "type": type(exc).__name__,
        "message": str(exc),
        **{key: getattr(exc, key) for key in ("errno", "winerror") if getattr(exc, key, None) is not None},
    }


def decode(blob: bytes, base: int, start_rva: int) -> dict:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    # Invalid/truncated bytes remain bytes, rather than being skipped as pseudo-instructions.
    instructions = []
    consumed = 0
    for instruction in decoder.disasm(blob, base + start_rva):
        instructions.append(
            {
                "rva": hex(instruction.address - base),
                "bytes_hex": instruction.bytes.hex().upper(),
                "mnemonic": instruction.mnemonic,
                "operands": instruction.op_str,
            }
        )
        consumed += instruction.size
    return {
        "status": "complete" if consumed == len(blob) else "incomplete",
        "start_rva": hex(start_rva),
        "instructions": instructions,
    }


def capture_target(
    target: Target,
    module: Module,
    read: Callable[[int, int], bytes],
    before: int,
    after: int,
) -> dict:
    result = {"target": target.to_dict()}
    try:
        start, end = window_bounds(module.size, target.rva, before, after)
        blob = read(start, end - start)
        if len(blob) != end - start:
            raise OSError(f"Short read at RVA {start:#x}: wanted {end - start}, read {len(blob)} bytes")
    except (OSError, ValueError) as exc:
        return {**result, "read": {"status": "error", "error": error_details(exc)}}

    result["read"] = {"status": "ok", "start_rva": hex(start), "bytes_hex": blob.hex().upper()}
    decode_rva = target.rva if target.decode_rva is None else target.decode_rva
    try:
        if not start <= decode_rva <= target.rva:
            raise ValueError("decode_rva must be inside the captured window, at or before the target")
        result["decode"] = decode(blob[decode_rva - start :], module.base, decode_rva)
    except Exception as exc:
        # Retain captured bytes even when the decoder fails.
        result["decode"] = {"status": "error", "start_rva": hex(decode_rva), "error": error_details(exc)}
    return result


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
) -> dict:
    validate_window(before, after)
    capture = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "source": source.metadata(),
        "request": {"window": {"before": before, "after": after}},
        "annotations": {},
        "tool": tool_metadata(),
        # The installed distribution version can differ from capstone.__version__.
        "decoder": {"name": "capstone", "version": version("capstone"), "architecture": "x86_64"},
    }
    if capture["source"]["kind"] == "live_process":
        if patch_state not in PATCH_STATES:
            raise ValueError(f"Invalid patch state: {patch_state!r}")
        capture["annotations"]["patch_state"] = patch_state
    if runtime is not None:
        capture["annotations"]["runtime"] = runtime
    if target_list is not None:
        capture["request"]["target_list"] = target_list
    if groups:
        capture["request"]["groups"] = groups
    results = [capture_target(target, source.module, source.read, before, after) for target in targets]
    capture["results"] = results
    capture["finished_at"] = datetime.now(timezone.utc).isoformat()
    capture["summary"] = {
        "target_count": len(results),
        "captured_ok": sum(result["read"]["status"] == "ok" for result in results),
        "captured_error": sum(result["read"]["status"] == "error" for result in results),
        "decode_error": sum(result.get("decode", {}).get("status") == "error" for result in results),
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
