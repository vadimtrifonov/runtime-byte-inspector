from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .targets import PATCH_STATES, Target, absolute_window, integer, text, validate_window, window_bounds


@dataclass(frozen=True)
class Record:
    label: str
    rva: int | None
    before: int
    raw: bytes | None
    error: dict | None
    group: str | None = None
    va: int | None = None

    def start(self, alignment: str) -> int:
        if alignment == "rva" and self.rva is None:
            raise ValueError("VA targets require --alignment target; absolute addresses are process-specific")
        return (self.rva if alignment == "rva" else 0) - self.before

    def metadata(self) -> dict:
        coordinate, address = ("rva", self.rva) if self.rva is not None else ("va", self.va)
        result = {"label": self.label, "group": self.group, f"target_{coordinate}": hex(address)}
        if self.raw is None:
            result["error"] = self.error
        else:
            result.update({f"start_{coordinate}": hex(address - self.before), "byte_count": len(self.raw)})
        return result


def load_capture(path: Path) -> tuple[dict, list[Record]]:
    """Read captured bytes without relying on disassembly or summary counts."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Top-level capture must be a JSON object")
        source = payload.get("source")
        annotations = payload.get("annotations", {})
        times = {key: text(payload.get(key), key) for key in ("started_at", "finished_at")}
        request = payload.get("request")
        if not isinstance(request, dict) or not isinstance(request.get("window"), dict):
            raise ValueError("request.window must be an object")
        before = integer(request["window"].get("before"), "request.window.before")
        after = integer(request["window"].get("after"), "request.window.after")
        validate_window(before, after)
        if not isinstance(source, dict):
            raise ValueError("source must be an object")
        kind = source.get("kind")
        if kind not in ("live_process", "pe_file"):
            raise ValueError(f"Invalid source.kind: {kind!r}")
        if not isinstance(annotations, dict):
            raise ValueError("annotations must be an object")
        module = source.get("module")
        if not isinstance(module, dict):
            raise ValueError("source.module must be an object")
        text(module.get("path"), "source.module.path")
        base = integer(module.get("base_address"), "source.module.base_address")
        size = integer(module.get("image_size"), "source.module.image_size")
        if size == 0:
            raise ValueError("source.module.image_size must be positive")
        if kind == "live_process":
            process = source.get("process")
            if not isinstance(process, dict):
                raise ValueError("source.process must be an object")
            text(process.get("name"), "source.process.name")
            if integer(process.get("pid"), "source.process.pid") == 0:
                raise ValueError("source.process.pid must be positive")
            if annotations.get("patch_state") not in PATCH_STATES:
                raise ValueError("Invalid annotations.patch_state")
        results = payload.get("results")
        if not isinstance(results, list) or not results:
            raise ValueError("results must be a non-empty array")
        records = []
        labels = set()
        for result in results:
            record = parse_record(result, size, before, after, module_base=base, kind=kind)
            if record.label in labels:
                raise ValueError(f"Duplicate result label: {record.label!r}")
            labels.add(record.label)
            records.append(record)
    except ValueError as exc:
        raise ValueError(f"Invalid capture '{path}': {exc}") from exc

    metadata = {
        "path": str(path.resolve()),
        **times,
        "source": source,
        "request": request,
        "annotations": annotations,
        **{key: payload[key] for key in ("tool", "decoder") if key in payload},
    }
    return metadata, records


def parse_record(
    result: object,
    module_size: int,
    before: int,
    after: int,
    *,
    module_base: int,
    kind: str,
) -> Record:
    if not isinstance(result, dict) or not isinstance(result.get("target"), dict):
        raise ValueError("Each result must contain a target object")
    target = result["target"]
    label = text(target.get("label"), "target.label")
    address_fields = {
        key: integer(target[key], f"{label} target.{key}") for key in ("rva", "va") if key in target
    }
    selected = Target(label, kind=target.get("kind", "code"), **address_fields)
    rva, va = selected.rva, selected.va
    if kind != "live_process" and (va is not None or selected.kind == "pointer"):
        raise ValueError("VA targets and pointer cells require a live-process capture")
    group = target.get("group")
    if group is not None:
        text(group, f"{label} target.group")
    read = result.get("read")
    if not isinstance(read, dict):
        raise ValueError(f"{label} read must be an object")
    if read.get("status") == "error":
        error = read.get("error")
        if not isinstance(error, dict):
            raise ValueError(f"{label} read.error must be an object")
        text(error.get("message"), f"{label} read.error.message")
        if "bytes_hex" in read:
            raise ValueError(f"{label} read failure must not contain captured bytes")
        return Record(label, rva, 0, None, error, group, va)
    if read.get("status") != "ok" or "error" in read:
        raise ValueError(f"{label} has an invalid read status")
    coordinate, address = ("rva", rva) if rva is not None else ("va", va)
    start = integer(read.get(f"start_{coordinate}"), f"{label} read.start_{coordinate}")
    raw = bytes.fromhex(text(read.get("bytes_hex"), f"{label} read.bytes_hex"))
    if selected.kind == "pointer":
        expected_start, expected_end = absolute_window(address, 0, 7)
        if rva is not None and expected_end > module_size:
            raise ValueError(f"{label} pointer cell exceeds the selected module")
    elif rva is not None:
        expected_start, expected_end = window_bounds(module_size, rva, before, after)
    else:
        expected_start, expected_end = absolute_window(va, before, after)
    if start != expected_start or len(raw) != expected_end - expected_start:
        raise ValueError(f"{label} captured byte range disagrees with its requested window")
    if (
        rva is not None
        and "start_va" in read
        and integer(read["start_va"], "read.start_va") != module_base + start
    ):
        raise ValueError(f"{label} read VA disagrees with its RVA and module base")
    if va is not None and "start_rva" in read:
        raise ValueError(f"{label} VA read must not claim a selected-module RVA")
    if "requested_bytes" in read and integer(read["requested_bytes"], "read.requested_bytes") != len(raw):
        raise ValueError(f"{label} requested byte count disagrees with captured bytes")
    return Record(label, rva, address - start, raw, None, group, va)


def compare_records(left: Record, right: Record, alignment: str) -> dict:
    # Require explicit target alignment even when a VA target's read failed.
    left_start, right_start = left.start(alignment), right.start(alignment)
    result = {"left": left.metadata(), "right": right.metadata()}
    if left.raw is None or right.raw is None:
        return {**result, "status": "unreadable"}
    start = max(left_start, right_start)
    end = min(left_start + len(left.raw), right_start + len(right.raw))
    count = max(0, end - start)
    result.update(
        status="compared" if count else "no_overlap",
        compared_bytes=count,
        left_only_bytes=len(left.raw) - count,
        right_only_bytes=len(right.raw) - count,
        windows_equal=False,
    )
    if not count:
        return result
    left_bytes = left.raw[start - left_start : end - left_start]
    right_bytes = right.raw[start - right_start : end - right_start]
    differences = []
    index = 0
    while index < count:
        if left_bytes[index] == right_bytes[index]:
            index += 1
            continue
        first = index
        while index < count and left_bytes[index] != right_bytes[index]:
            index += 1
        differences.append(
            {
                "offset": start + first,
                "left_hex": left_bytes[first:index].hex().upper(),
                "right_hex": right_bytes[first:index].hex().upper(),
            }
        )
    different = sum(len(entry["left_hex"]) // 2 for entry in differences)
    result.update(
        overlap={"start": start, "end_exclusive": end},
        equal_bytes=count - different,
        different_bytes=different,
        windows_equal=not different and count == len(left.raw) == len(right.raw),
        differences=differences,
    )
    return result


def compare_captures(
    left_path: Path,
    right_path: Path,
    *,
    left_label: str | None = None,
    right_label: str | None = None,
    alignment: str = "rva",
) -> dict:
    if alignment not in ("rva", "target"):
        raise ValueError("alignment must be rva or target")
    if (left_label is None) != (right_label is None):
        raise ValueError("Select both --left-label and --right-label, or neither")
    left_meta, left_records = load_capture(left_path)
    right_meta, right_records = load_capture(right_path)
    left = {record.label: record for record in left_records}
    right = {record.label: record for record in right_records}
    if left_label is not None:
        if left_label not in left:
            raise ValueError(f"Label {left_label!r} not found in '{left_path}'")
        if right_label not in right:
            raise ValueError(f"Label {right_label!r} not found in '{right_path}'")
        pairs = [(left[left_label], right[right_label])]
        unmatched_left, unmatched_right = [], []
    else:
        pairs = [(record, right[record.label]) for record in left_records if record.label in right]
        unmatched_left = [record.metadata() for record in left_records if record.label not in right]
        unmatched_right = [record.metadata() for record in right_records if record.label not in left]
    return {
        "left": left_meta,
        "right": right_meta,
        "alignment": alignment,
        "comparisons": [compare_records(a, b, alignment) for a, b in pairs],
        "unmatched_left": unmatched_left,
        "unmatched_right": unmatched_right,
    }


def render_report(report: dict) -> str:
    lines = [
        f"left : {report['left']['path']}",
        f"right: {report['right']['path']}",
        f"alignment: {report['alignment']} (byte equality only, not site equivalence)",
    ]
    for side in ("left", "right"):
        meta = report[side]
        lines.append(
            f"{side} source: {meta['source']['module']['path']} | {meta['started_at']} | {meta['source']['kind']}"
        )
        if "patch_state" in meta["annotations"]:
            lines.append(f"  patch state (annotation): {meta['annotations']['patch_state']}")
    for pair in report["comparisons"]:
        lines.append(f"\n{pair['left']['label']} / {pair['right']['label']}: {pair['status']}")
        if pair["status"] == "unreadable":
            for side in ("left", "right"):
                if "error" in pair[side]:
                    lines.append(f"  {side}: {pair[side]['error']['message']}")
            continue
        lines.append(
            f"  compared={pair['compared_bytes']} left_only={pair['left_only_bytes']} "
            f"right_only={pair['right_only_bytes']} windows_equal={pair['windows_equal']}"
        )
        for difference in pair.get("differences", []):
            lines.append(
                f"  {difference['offset']:#x}: {difference['left_hex']} -> {difference['right_hex']}"
            )
    for side in ("left", "right"):
        for record in report[f"unmatched_{side}"]:
            detail = f" — {record['error']['message']}" if "error" in record else ""
            lines.append(f"unmatched {side}: {record['label']}{detail}")
    return "\n".join(lines)
