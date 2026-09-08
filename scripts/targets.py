from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

MAX_WINDOW_BYTES = 4096
MAX_FOLLOW_HOPS = 8
ADDRESS_LIMIT = 1 << 64
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
    rva: int | None = None
    group: str | None = None
    notes: str | None = None
    decode_rva: int | None = None
    va: int | None = None
    decode_va: int | None = None
    kind: str = "code"
    span: int | None = None

    def __post_init__(self):
        text(self.label, "target label")
        if (self.rva is None) == (self.va is None):
            raise ValueError(f"{self.label}: select exactly one rva or va")
        for key in ("rva", "va", "decode_rva", "decode_va"):
            value = getattr(self, key)
            if value is not None and integer(value, key) >= ADDRESS_LIMIT:
                raise ValueError(f"{key} must be an unsigned 64-bit address")
        if (self.rva is None and self.decode_rva is not None) or (
            self.va is None and self.decode_va is not None
        ):
            raise ValueError("Use decode_rva with rva targets, or decode_va with va targets")
        if self.kind not in ("code", "pointer"):
            raise ValueError("Target kind must be code or pointer")
        if self.span is not None and not 1 <= integer(self.span, "span") <= MAX_WINDOW_BYTES:
            raise ValueError(f"span must be 1..{MAX_WINDOW_BYTES} bytes")
        if self.kind == "pointer" and any(
            value is not None for value in (self.decode_rva, self.decode_va, self.span)
        ):
            raise ValueError("Pointer targets cannot have a decoding origin or instruction span")

    def to_dict(self) -> dict:
        result = {"label": self.label}
        for key in ("rva", "va", "decode_rva", "decode_va"):
            value = getattr(self, key)
            if value is not None:
                result[key] = hex(value)
        for key in ("group", "notes", "span"):
            value = getattr(self, key)
            if value is not None:
                result[key] = value
        if self.kind != "code":
            result["kind"] = self.kind
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
        fields = {
            key: integer(entry[key], f"{label} {key}")
            for key in ("rva", "va", "decode_rva", "decode_va", "span")
            if entry.get(key) is not None
        }
        targets.append(Target(label, group=group, notes=notes, kind=entry.get("kind", "code"), **fields))
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


def absolute_window(va: int, before: int, after: int) -> tuple[int, int]:
    validate_window(before, after)
    start, end = va - before, va + after + 1
    if not 0 <= start <= va < end <= ADDRESS_LIMIT:
        raise ValueError("Requested window exceeds the unsigned 64-bit address range")
    return start, end
