from __future__ import annotations

"""Compare the comparison-required subset of workspace evidence bundles."""

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


VALID_GROUPS = ("current_validated", "legacy_ng", "discarded_guess")
VALID_PROCESS_STATES = frozenset({"unpatched", "patched", "unknown"})
VALID_ERROR_KINDS = frozenset({"validation", "operational", "internal"})


@dataclass(frozen=True)
class BundleMeta:
    source_path: str
    capture_timestamp: str
    capture_mode: str
    process_state: str
    process_name: str
    pid: int
    module_path: str
    module_base: int


@dataclass(frozen=True)
class CandidateRecord:
    source_path: str
    source_index: int
    label: str
    label_key: str
    label_address_key: str | None
    group: str
    notes: str | None
    capture_timestamp: str
    capture_mode: str
    process_state: str
    process_name: str
    pid: int
    module_path: str
    module_base: int
    target_rva: int
    target_va: int | None


@dataclass(frozen=True)
class EvidenceRecord(CandidateRecord):
    before: int
    after: int
    raw_bytes: bytes
    raw_bytes_hex: str


@dataclass(frozen=True)
class CaptureFailureRecord(CandidateRecord):
    status: str
    error_kind: str
    error_message: str
    error_traceback: str | None
    error_code: str | None
    error_payload_json: str


ComparisonRecord = EvidenceRecord | CaptureFailureRecord


@dataclass(frozen=True)
class Pairing:
    current: ComparisonRecord
    legacy: ComparisonRecord
    relation: str
    score: float
    best_shift: int | None
    rva_delta: int | None
    reason: str


@dataclass(frozen=True)
class SkippedInput:
    source_path: str
    reason: str


class BundleParseError(ValueError):
    """Raised when a bundle does not match the workspace schema."""


class RecordParseError(ValueError):
    """Raised when a result entry does not match the workspace schema."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare the comparison-required subset of workspace evidence bundles"
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="One or more JSON evidence bundle files or directories containing bundle files",
    )
    parser.add_argument(
        "--current-group",
        choices=VALID_GROUPS,
        default="current_validated",
        help="Workspace group to treat as the current candidate set",
    )
    parser.add_argument(
        "--legacy-group",
        choices=VALID_GROUPS,
        default="legacy_ng",
        help="Workspace group to treat as the legacy candidate set",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--min-same-block-score",
        type=float,
        default=0.85,
        help="Minimum normalized similarity score for same_block_shifted_anchor (default: 0.85)",
    )
    parser.add_argument(
        "--min-different-score",
        type=float,
        default=0.45,
        help="Minimum normalized similarity score for different_candidate (default: 0.45)",
    )
    parser.add_argument(
        "--max-anchor-shift",
        type=int,
        default=64,
        help="Maximum byte shift to consider when matching shifted anchors (default: 64)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    bundle_paths = discover_bundle_paths(args.inputs)
    if not bundle_paths:
        raise SystemExit("No JSON evidence bundles were found in the provided inputs")

    records, skipped_inputs = load_records(bundle_paths)
    if not records:
        if skipped_inputs:
            if args.format == "json":
                json.dump(build_no_records_payload(bundle_paths, skipped_inputs), sys.stdout, indent=2, sort_keys=True)
                sys.stdout.write("\n")
                return 1
            raise SystemExit(render_no_records_message(skipped_inputs))
        raise SystemExit("No workspace evidence records were found in the provided JSON bundles")

    current_records = select_group(records, args.current_group)
    legacy_records = select_group(records, args.legacy_group)
    if not current_records:
        raise SystemExit(f"No records matched current group '{args.current_group}'")
    if not legacy_records:
        raise SystemExit(f"No records matched legacy group '{args.legacy_group}'")

    pairings, unmatched_current, unmatched_legacy = build_pairings(
        current_records=current_records,
        legacy_records=legacy_records,
        min_same_block_score=args.min_same_block_score,
        min_different_score=args.min_different_score,
        max_anchor_shift=args.max_anchor_shift,
    )

    payload = build_output_payload(
        inputs=bundle_paths,
        all_records=records,
        current_selector=args.current_group,
        legacy_selector=args.legacy_group,
        pairings=pairings,
        unmatched_current=unmatched_current,
        unmatched_legacy=unmatched_legacy,
        skipped_inputs=skipped_inputs,
        thresholds={
            "min_same_block_score": args.min_same_block_score,
            "min_different_score": args.min_different_score,
            "max_anchor_shift": args.max_anchor_shift,
        },
    )

    if args.format == "json":
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(render_text_report(payload))

    return 0


def discover_bundle_paths(raw_inputs: Iterable[str]) -> list[Path]:
    bundle_paths: list[Path] = []
    seen: set[Path] = set()

    for raw_input in raw_inputs:
        path = Path(raw_input)
        if not path.exists():
            raise SystemExit(f"Input path does not exist: {path}")
        candidates = [path] if path.is_file() else sorted(path.rglob("*.json"))
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved not in seen:
                seen.add(resolved)
                bundle_paths.append(resolved)

    return sorted(bundle_paths)


def load_records(bundle_paths: Iterable[Path]) -> tuple[list[ComparisonRecord], list[SkippedInput]]:
    records: list[ComparisonRecord] = []
    skipped_inputs: list[SkippedInput] = []

    for bundle_path in bundle_paths:
        try:
            with bundle_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except UnicodeDecodeError as exc:
            skipped_inputs.append(
                SkippedInput(
                    source_path=str(bundle_path),
                    reason=f"Input is not valid UTF-8 JSON: {exc}",
                )
            )
            continue
        except json.JSONDecodeError as exc:
            skipped_inputs.append(
                SkippedInput(
                    source_path=str(bundle_path),
                    reason=f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}",
                )
            )
            continue
        except OSError as exc:
            skipped_inputs.append(
                SkippedInput(
                    source_path=str(bundle_path),
                    reason=f"Could not read input: {exc}",
                )
            )
            continue

        try:
            bundle_meta, results = load_bundle(bundle_path, payload)
        except BundleParseError as exc:
            skipped_inputs.append(
                SkippedInput(
                    source_path=str(bundle_path),
                    reason=f"Bundle schema error: {exc}",
                )
            )
            continue

        for source_index, result in enumerate(results):
            try:
                records.append(parse_result(bundle_meta, source_index, result))
            except RecordParseError as exc:
                label_hint = result_label_hint(result, source_index)
                skipped_inputs.append(
                    SkippedInput(
                        source_path=str(bundle_path),
                        reason=f"Result {source_index} ({label_hint}): {exc}",
                    )
                )

    return records, skipped_inputs


def load_bundle(bundle_path: Path, payload: Any) -> tuple[BundleMeta, list[Any]]:
    root = require_mapping(payload, "top-level JSON")
    capture_timestamp = require_bundle_string(root, "capture_timestamp")
    capture_mode = require_bundle_string(root, "capture_mode")
    if capture_mode != "live_process":
        raise BundleParseError(f"field 'capture_mode' must be 'live_process', got {capture_mode!r}")

    process_state = require_bundle_string(root, "process_state")
    if process_state not in VALID_PROCESS_STATES:
        expected = ", ".join(sorted(VALID_PROCESS_STATES))
        raise BundleParseError(f"field 'process_state' must be one of: {expected}")

    process = require_mapping_field(root, "process")
    process_name = require_bundle_string(process, "name", "process.name")
    pid = require_bundle_int(process, "pid", "process.pid")
    if pid <= 0:
        raise BundleParseError(f"field 'process.pid' must be positive, got {pid!r}")

    module = require_mapping_field(root, "module")
    module_path = require_bundle_string(module, "path", "module.path")
    module_base = require_bundle_int(module, "base_address", "module.base_address")

    window = require_mapping_field(root, "window")
    require_bundle_int(window, "before", "window.before")
    require_bundle_int(window, "after", "window.after")

    results = require_list(root, "results")

    return (
        BundleMeta(
            source_path=str(bundle_path),
            capture_timestamp=capture_timestamp,
            capture_mode=capture_mode,
            process_state=process_state,
            process_name=process_name,
            pid=pid,
            module_path=module_path,
            module_base=module_base,
        ),
        results,
    )


def parse_result(bundle_meta: BundleMeta, source_index: int, payload: Any) -> ComparisonRecord:
    if not isinstance(payload, dict):
        raise RecordParseError("result must be an object")
    result = payload
    label = require_record_string(result, "label")
    group = require_record_string(result, "group")
    if group not in VALID_GROUPS:
        expected = ", ".join(VALID_GROUPS)
        raise RecordParseError(f"field 'group' must be one of: {expected}")

    notes = optional_string(result.get("notes"), "notes")
    target_rva = require_record_int(result, "target_rva")
    target_va = optional_int(result.get("target_va"), "target_va")
    status = require_record_string(result, "status")
    if status not in {"ok", "error"}:
        raise RecordParseError(f"field 'status' must be 'ok' or 'error', got {status!r}")

    common_fields = {
        "source_path": bundle_meta.source_path,
        "source_index": source_index,
        "label": label,
        "label_key": normalize_token(label),
        "label_address_key": label_address_suffix(label),
        "group": group,
        "notes": notes,
        "capture_timestamp": bundle_meta.capture_timestamp,
        "capture_mode": bundle_meta.capture_mode,
        "process_state": bundle_meta.process_state,
        "process_name": bundle_meta.process_name,
        "pid": bundle_meta.pid,
        "module_path": bundle_meta.module_path,
        "module_base": bundle_meta.module_base,
        "target_rva": target_rva,
        "target_va": target_va,
    }

    if status == "ok":
        window = require_record_mapping_field(result, "window")
        before = require_record_int(window, "actual_before", "window.actual_before")
        after = require_record_int(window, "actual_after", "window.actual_after")
        if before < 0 or after < 0:
            raise RecordParseError("fields 'window.actual_before' and 'window.actual_after' must be non-negative")
        if "error_kind" in result or "error" in result:
            raise RecordParseError("status 'ok' result must not include failure fields")
        raw_bytes_hex = require_record_string(result, "raw_bytes_hex")
        raw_bytes = parse_raw_bytes_hex(raw_bytes_hex)
        raw_bytes_len = require_record_int(result, "raw_bytes_len", "raw_bytes_len")
        if raw_bytes_len != len(raw_bytes):
            raise RecordParseError(
                f"field 'raw_bytes_len' does not match decoded raw_bytes_hex length ({raw_bytes_len} != {len(raw_bytes)})"
            )
        expected_raw_bytes_len = before + after + 1
        if expected_raw_bytes_len != raw_bytes_len:
            raise RecordParseError(
                "fields 'window.actual_before' and 'window.actual_after' are inconsistent with 'raw_bytes_len' "
                f"({before} + {after} + 1 != {raw_bytes_len})"
            )
        disassembly = result.get("disassembly")
        if not isinstance(disassembly, list):
            raise RecordParseError("field 'disassembly' must be a list for status 'ok'")
        if target_va is None:
            raise RecordParseError("field 'target_va' is required for status 'ok'")
        return EvidenceRecord(
            **common_fields,
            before=before,
            after=after,
            raw_bytes=raw_bytes,
            raw_bytes_hex=raw_bytes.hex(),
        )

    error_kind = require_record_string(result, "error_kind")
    if error_kind not in VALID_ERROR_KINDS:
        expected = ", ".join(sorted(VALID_ERROR_KINDS))
        raise RecordParseError(f"field 'error_kind' must be one of: {expected}")
    error_payload = require_record_mapping_field(result, "error")
    error_message = require_record_string(error_payload, "message", "error.message")
    error_traceback = optional_string(error_payload.get("traceback"), "error.traceback")
    error_code = optional_error_code(error_payload)

    if "raw_bytes_hex" in result or "raw_bytes_len" in result or "disassembly" in result:
        raise RecordParseError("status 'error' result must not include readable evidence fields")

    return CaptureFailureRecord(
        **common_fields,
        status=status,
        error_kind=error_kind,
        error_message=error_message,
        error_traceback=error_traceback,
        error_code=error_code,
        error_payload_json=serialize_json(error_payload),
    )


def select_group(records: Iterable[ComparisonRecord], group: str) -> list[ComparisonRecord]:
    return sorted((record for record in records if record.group == group), key=sort_key)


def build_pairings(
    *,
    current_records: list[ComparisonRecord],
    legacy_records: list[ComparisonRecord],
    min_same_block_score: float,
    min_different_score: float,
    max_anchor_shift: int,
) -> tuple[list[Pairing], list[ComparisonRecord], list[ComparisonRecord]]:
    scored_candidates: list[tuple[tuple[float, ...], Pairing]] = []
    for current in current_records:
        for legacy in legacy_records:
            pairing = compare_pair(current, legacy, min_same_block_score, min_different_score, max_anchor_shift)
            if not has_counterpart_signal(pairing, min_different_score, max_anchor_shift):
                continue
            scored_candidates.append(
                (
                    pair_priority(pairing.current, pairing.legacy, pairing.score, pairing.best_shift),
                    pairing,
                )
            )

    assigned_current: set[ComparisonRecord] = set()
    assigned_legacy: set[ComparisonRecord] = set()
    pairings: list[Pairing] = []
    for _, pairing in sorted(scored_candidates, key=lambda item: item[0], reverse=True):
        if pairing.current in assigned_current or pairing.legacy in assigned_legacy:
            continue
        assigned_current.add(pairing.current)
        assigned_legacy.add(pairing.legacy)
        pairings.append(pairing)

    pairings.sort(key=lambda pairing: sort_key(pairing.current))
    unmatched_current = [record for record in current_records if record not in assigned_current]
    unmatched_legacy = [record for record in legacy_records if record not in assigned_legacy]
    return pairings, unmatched_current, unmatched_legacy


def pair_priority(
    current: ComparisonRecord,
    legacy: ComparisonRecord,
    score: float,
    best_shift: int | None,
) -> tuple[float, ...]:
    rva_delta = current.target_rva - legacy.target_rva
    same_rva = 1.0 if rva_delta == 0 else 0.0
    shift_agreement = 1.0 if shift_matches_delta(best_shift, rva_delta) else 0.0
    same_label_address = 1.0 if current.label_address_key and current.label_address_key == legacy.label_address_key else 0.0
    rva_closeness = -float(abs(rva_delta))
    return (same_rva, shift_agreement, same_label_address, score, rva_closeness)


def compare_pair(
    current: ComparisonRecord,
    legacy: ComparisonRecord,
    min_same_block_score: float,
    min_different_score: float,
    max_anchor_shift: int,
) -> Pairing:
    if isinstance(current, CaptureFailureRecord) or isinstance(legacy, CaptureFailureRecord):
        score = 0.0
        best_shift = None
        reason = format_unreadable_reason(current, legacy)
        relation = "unreadable"
    else:
        score, best_shift, reason = compute_similarity(current, legacy, max_anchor_shift)
        rva_delta = current.target_rva - legacy.target_rva
        if current.target_rva == legacy.target_rva and score >= min_same_block_score:
            relation = "exact_match"
        elif best_shift not in (None, 0) and score >= min_same_block_score and shift_matches_delta(best_shift, rva_delta):
            relation = "same_block_shifted_anchor"
        elif score >= min_different_score:
            relation = "different_candidate"
        else:
            relation = "mismatch"

    return Pairing(
        current=current,
        legacy=legacy,
        relation=relation,
        score=score,
        best_shift=best_shift,
        rva_delta=current.target_rva - legacy.target_rva,
        reason=reason,
    )


def has_counterpart_signal(
    pairing: Pairing,
    min_different_score: float,
    max_anchor_shift: int,
) -> bool:
    if pairing.current.target_rva == pairing.legacy.target_rva:
        return True
    if (
        abs(pairing.rva_delta or 0) <= max_anchor_shift
        and shift_matches_delta(pairing.best_shift, pairing.rva_delta)
    ):
        return True
    if pairing.current.label_address_key and pairing.current.label_address_key == pairing.legacy.label_address_key:
        return True
    return pairing.score >= min_different_score


def compute_similarity(
    current: EvidenceRecord,
    legacy: EvidenceRecord,
    max_anchor_shift: int,
) -> tuple[float, int, str]:
    score, shift, compared_bytes, anchor_aware = best_byte_similarity(current, legacy, max_anchor_shift)
    reason = "anchor-aligned byte overlap" if anchor_aware else "byte-window overlap"
    return score, shift, f"{reason} ({compared_bytes} byte(s) compared)"


def format_unreadable_reason(current: ComparisonRecord, legacy: ComparisonRecord) -> str:
    details: list[str] = []
    current_error = capture_failure_detail(current)
    legacy_error = capture_failure_detail(legacy)
    if current_error is not None:
        details.append(f"current {current_error}")
    if legacy_error is not None:
        details.append(f"legacy {legacy_error}")
    if details:
        return "; ".join(details)
    return "missing readable evidence"


def capture_failure_detail(record: ComparisonRecord) -> str | None:
    if not isinstance(record, CaptureFailureRecord):
        return None
    return format_diagnostic_detail(
        record.status,
        record.error_kind,
        record.error_message,
        record.error_code,
    )


def format_diagnostic_detail(
    status: str,
    error_kind: str,
    error_message: str,
    error_code: str | None,
) -> str:
    detail = f"{status} [{error_kind}]: {error_message}"
    if error_code is not None:
        detail += f" (code={error_code})"
    return detail


def build_output_payload(
    *,
    inputs: list[Path],
    all_records: list[ComparisonRecord],
    current_selector: str,
    legacy_selector: str,
    pairings: list[Pairing],
    unmatched_current: list[ComparisonRecord],
    unmatched_legacy: list[ComparisonRecord],
    skipped_inputs: list[SkippedInput],
    thresholds: dict[str, float | int],
) -> dict[str, Any]:
    summary: dict[str, int] = {}
    for pairing in pairings:
        summary[pairing.relation] = summary.get(pairing.relation, 0) + 1

    return {
        "inputs": [str(path) for path in inputs],
        "selectors": {
            "current_group": current_selector,
            "legacy_group": legacy_selector,
        },
        "thresholds": thresholds,
        "record_count": len(all_records),
        "group_counts": summarize_groups(all_records),
        "summary": summary,
        "skipped_inputs": [serialize_skipped_input(entry) for entry in skipped_inputs],
        "unmatched_current": [serialize_record(record) for record in unmatched_current],
        "unmatched_legacy": [serialize_record(record) for record in unmatched_legacy],
        "comparisons": [serialize_pairing(pairing) for pairing in pairings],
    }


def build_no_records_payload(inputs: list[Path], skipped_inputs: list[SkippedInput]) -> dict[str, Any]:
    return {
        "inputs": [str(path) for path in inputs],
        "record_count": 0,
        "skipped_inputs": [serialize_skipped_input(entry) for entry in skipped_inputs],
    }


def render_no_records_message(skipped_inputs: list[SkippedInput]) -> str:
    lines = ["No workspace evidence records were found in the provided JSON bundles.", "", "Skipped Inputs"]
    for entry in skipped_inputs:
        lines.append(f"- {Path(entry.source_path).name}: {entry.reason}")
    return "\n".join(lines)


def summarize_groups(records: Iterable[ComparisonRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        counts[record.group] = counts.get(record.group, 0) + 1
    return counts


def serialize_record(record: ComparisonRecord | None) -> dict[str, Any] | None:
    if record is None:
        return None
    payload: dict[str, Any] = {
        "record_kind": "capture_failure" if isinstance(record, CaptureFailureRecord) else "evidence",
        "source_path": record.source_path,
        "source_index": record.source_index,
        "label": record.label,
        "group": record.group,
        "notes": record.notes,
        "capture_timestamp": record.capture_timestamp,
        "capture_mode": record.capture_mode,
        "process_state": record.process_state,
        "process_name": record.process_name,
        "pid": record.pid,
        "module_path": record.module_path,
        "module_base": record.module_base,
        "target_rva": record.target_rva,
        "target_va": record.target_va,
    }
    if isinstance(record, CaptureFailureRecord):
        payload["status"] = record.status
        payload["error_kind"] = record.error_kind
        payload["error_message"] = record.error_message
        payload["error_traceback"] = record.error_traceback
        payload["error_code"] = record.error_code
        payload["error_payload"] = deserialize_json(record.error_payload_json)
        payload["failure_detail"] = capture_failure_detail(record)
    else:
        payload["before"] = record.before
        payload["after"] = record.after
        payload["raw_bytes_hex"] = record.raw_bytes_hex
    return payload


def serialize_pairing(pairing: Pairing) -> dict[str, Any]:
    return {
        "relation": pairing.relation,
        "score": round(pairing.score, 4),
        "best_shift": pairing.best_shift,
        "rva_delta": pairing.rva_delta,
        "reason": pairing.reason,
        "current": serialize_record(pairing.current),
        "legacy": serialize_record(pairing.legacy),
    }


def serialize_skipped_input(entry: SkippedInput) -> dict[str, Any]:
    return {
        "source_path": entry.source_path,
        "reason": entry.reason,
    }


def render_text_report(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("Evidence Comparison Report")
    lines.append(f"inputs         : {len(payload['inputs'])} file(s)")
    lines.append(f"records        : {payload['record_count']}")
    lines.append(
        "selectors      : "
        f"current={payload['selectors']['current_group']} "
        f"legacy={payload['selectors']['legacy_group']}"
    )
    summary = payload["summary"]
    summary_text = ", ".join(f"{key}={summary[key]}" for key in sorted(summary))
    lines.append(f"classifications: {summary_text if summary_text else 'none'}")
    lines.append(f"skipped inputs : {len(payload['skipped_inputs'])}")
    lines.append(f"unmatched current: {len(payload['unmatched_current'])}")
    lines.append(f"unmatched legacy: {len(payload['unmatched_legacy'])}")
    lines.append("")

    for index, comparison in enumerate(payload["comparisons"], start=1):
        current = comparison["current"]
        legacy = comparison["legacy"]
        lines.append(f"[{index}] {comparison['relation']} score={comparison['score']:.4f}")
        lines.append(
            "current        : "
            f"{record_label_for_text(current)} "
            f"rva={format_int(current.get('target_rva') if current else None)} "
            f"group={current.get('group') if current else '-'}"
        )
        lines.append(
            "legacy         : "
            f"{record_label_for_text(legacy)} "
            f"rva={format_int(legacy.get('target_rva') if legacy else None)} "
            f"group={legacy.get('group') if legacy else '-'}"
        )
        lines.append(
            "details        : "
            f"shift={comparison['best_shift'] if comparison['best_shift'] is not None else '-'} "
            f"rva_delta={format_int(comparison['rva_delta'])} "
            f"via={comparison['reason']}"
        )
        lines.append(
            "sources        : "
            f"{Path(current['source_path']).name if current else '-'}"
            f"{' | ' + Path(legacy['source_path']).name if legacy else ''}"
        )
        lines.append("")

    if payload["unmatched_current"]:
        lines.append("Current Records Without A Legacy Pair")
        for record in payload["unmatched_current"]:
            lines.append(format_unmatched_record(record))
        lines.append("")

    if payload["unmatched_legacy"]:
        lines.append("Legacy Records Without A Current Pair")
        for record in payload["unmatched_legacy"]:
            lines.append(format_unmatched_record(record))
        lines.append("")

    if payload["skipped_inputs"]:
        lines.append("Skipped Inputs")
        for entry in payload["skipped_inputs"]:
            lines.append(f"- {Path(entry['source_path']).name}: {entry['reason']}")

    return "\n".join(lines).rstrip()


def record_label_for_text(record: dict[str, Any] | None) -> str:
    if record is None:
        return "-"
    return str(record["label"])


def format_unmatched_record(record: dict[str, Any]) -> str:
    line = (
        f"- {record['label']} rva={format_int(record.get('target_rva'))} "
        f"group={record['group']} source={Path(record['source_path']).name}"
    )
    if record.get("record_kind") == "capture_failure" and record.get("failure_detail"):
        line += f" error={record['failure_detail']}"
    return line


def best_byte_similarity(
    current: EvidenceRecord,
    legacy: EvidenceRecord,
    max_anchor_shift: int,
) -> tuple[float, int, int, bool]:
    if can_anchor_align(current) and can_anchor_align(legacy):
        return best_anchor_aligned_overlap(current, legacy, max_anchor_shift)
    score, shift, compared_bytes = best_linear_overlap(current.raw_bytes, legacy.raw_bytes, max_anchor_shift)
    return score, shift, compared_bytes, False


def best_anchor_aligned_overlap(
    current: EvidenceRecord,
    legacy: EvidenceRecord,
    max_anchor_shift: int,
) -> tuple[float, int, int, bool]:
    expected_shift = current.target_rva - legacy.target_rva

    best_score = -1.0
    best_shift = 0
    best_compared_bytes = 0
    for shift in iter_candidate_shifts(expected_shift, max_anchor_shift):
        score, compared_bytes = anchor_aligned_overlap(current, legacy, shift)
        if (
            score > best_score
            or (math.isclose(score, best_score) and compared_bytes > best_compared_bytes)
            or (
                math.isclose(score, best_score)
                and compared_bytes == best_compared_bytes
                and abs(shift - expected_shift) < abs(best_shift - expected_shift)
            )
        ):
            best_score = score
            best_shift = shift
            best_compared_bytes = compared_bytes

    if best_score < 0.0:
        return 0.0, 0, 0, True
    return best_score, best_shift, best_compared_bytes, True


def anchor_aligned_overlap(current: EvidenceRecord, legacy: EvidenceRecord, shift: int) -> tuple[float, int]:
    current_anchor = anchor_index(current)
    legacy_anchor = anchor_index(legacy)
    if current_anchor is None or legacy_anchor is None:
        return 0.0, 0

    current_start, current_end = relative_bounds(current)
    legacy_start, legacy_end = relative_bounds(legacy)

    overlap_start = max(current_start, legacy_start - shift)
    overlap_end = min(current_end, legacy_end - shift)
    if overlap_start > overlap_end:
        return 0.0, 0

    equal = 0
    compared_bytes = 0
    for offset in range(overlap_start, overlap_end + 1):
        current_index = current_anchor + offset
        legacy_index = legacy_anchor + offset + shift
        compared_bytes += 1
        if current.raw_bytes[current_index] == legacy.raw_bytes[legacy_index]:
            equal += 1
    return equal / compared_bytes, compared_bytes


def best_linear_overlap(current: bytes, legacy: bytes, max_anchor_shift: int) -> tuple[float, int, int]:
    best_score = -1.0
    best_shift = 0
    best_compared_bytes = 0
    for shift in range(-max_anchor_shift, max_anchor_shift + 1):
        start_current = max(0, shift)
        start_legacy = max(0, -shift)
        overlap = min(len(current) - start_current, len(legacy) - start_legacy)
        if overlap <= 0:
            continue
        equal = 0
        for offset in range(overlap):
            if current[start_current + offset] == legacy[start_legacy + offset]:
                equal += 1
        score = equal / overlap
        if score > best_score or (math.isclose(score, best_score) and overlap > best_compared_bytes):
            best_score = score
            best_shift = shift
            best_compared_bytes = overlap
    if best_score < 0.0:
        return 0.0, 0, 0
    return best_score, best_shift, best_compared_bytes


def iter_candidate_shifts(expected_shift: int, max_anchor_shift: int) -> Iterable[int]:
    seen: set[int] = set()
    if abs(expected_shift) <= max_anchor_shift:
        seen.add(expected_shift)
        yield expected_shift
    for shift in range(-max_anchor_shift, max_anchor_shift + 1):
        if shift not in seen:
            yield shift


def normalize_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def label_address_suffix(label: str) -> str | None:
    match = re.search(r"([0-9A-Fa-f]{4,})$", label)
    if match is None:
        return None
    return match.group(1).upper()


def can_anchor_align(record: EvidenceRecord) -> bool:
    return anchor_index(record) is not None


def anchor_index(record: EvidenceRecord) -> int | None:
    if 0 <= record.before < len(record.raw_bytes):
        return record.before
    return None


def relative_bounds(record: EvidenceRecord) -> tuple[int, int]:
    anchor = anchor_index(record)
    if anchor is None:
        return (0, -1)
    left_extent = min(anchor, record.before)
    right_extent = min(len(record.raw_bytes) - anchor - 1, record.after)
    return (-left_extent, right_extent)


def shift_matches_delta(best_shift: int | None, rva_delta: int | None) -> bool:
    if best_shift is None or rva_delta is None:
        return False
    return best_shift == rva_delta


def sort_key(record: ComparisonRecord) -> tuple[int, str, str]:
    return (record.target_rva, record.label_key, record.source_path)


def format_int(value: int | None) -> str:
    if value is None:
        return "-"
    sign = "-" if value < 0 else ""
    return f"{sign}0x{abs(value):X}"


def require_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BundleParseError(f"{field_name} must be an object")
    return value


def require_mapping_field(payload: dict[str, Any], field_name: str) -> dict[str, Any]:
    if field_name not in payload:
        raise BundleParseError(f"missing required top-level field '{field_name}'")
    value = payload[field_name]
    if not isinstance(value, dict):
        raise BundleParseError(f"field '{field_name}' must be an object")
    return value


def require_list(payload: dict[str, Any], field_name: str) -> list[Any]:
    if field_name not in payload:
        raise BundleParseError(f"missing required top-level field '{field_name}'")
    value = payload[field_name]
    if not isinstance(value, list):
        raise BundleParseError(f"field '{field_name}' must be a list")
    return value


def require_bundle_string(payload: dict[str, Any], key: str, field_name: str | None = None) -> str:
    field = field_name or key
    if key not in payload:
        raise BundleParseError(f"missing required top-level field '{field}'")
    value = payload[key]
    if not isinstance(value, str) or not value.strip():
        raise BundleParseError(f"field '{field}' must be a non-empty string")
    return value.strip()


def require_record_string(payload: dict[str, Any], key: str, field_name: str | None = None) -> str:
    field = field_name or key
    if key not in payload:
        raise RecordParseError(f"missing required field '{field}'")
    value = payload[key]
    if not isinstance(value, str) or not value.strip():
        raise RecordParseError(f"field '{field}' must be a non-empty string")
    return value.strip()


def require_bundle_int(payload: dict[str, Any], key: str, field_name: str | None = None) -> int:
    field = field_name or key
    if key not in payload:
        raise BundleParseError(f"missing required top-level field '{field}'")
    try:
        return parse_int_value(payload[key], field)
    except ValueError as exc:
        raise BundleParseError(str(exc)) from exc


def require_record_int(payload: dict[str, Any], key: str, field_name: str | None = None) -> int:
    field = field_name or key
    if key not in payload:
        raise RecordParseError(f"missing required field '{field}'")
    try:
        return parse_int_value(payload[key], field)
    except ValueError as exc:
        raise RecordParseError(str(exc)) from exc


def require_record_mapping_field(payload: dict[str, Any], key: str, field_name: str | None = None) -> dict[str, Any]:
    field = field_name or key
    if key not in payload:
        raise RecordParseError(f"missing required field '{field}'")
    value = payload[key]
    if not isinstance(value, dict):
        raise RecordParseError(f"field '{field}' must be an object")
    return value


def optional_int(value: Any, field_name: str) -> int | None:
    if value is None:
        return None
    try:
        return parse_int_value(value, field_name)
    except ValueError as exc:
        raise RecordParseError(str(exc)) from exc


def optional_string(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RecordParseError(f"field '{field_name}' must be a string when present")
    text = value.strip()
    return text or None


def optional_error_code(error_payload: dict[str, Any]) -> str | None:
    for key in ("code", "winerror", "errno"):
        if key not in error_payload:
            continue
        value = error_payload[key]
        if isinstance(value, bool):
            raise RecordParseError(f"field 'error.{key}' must not be boolean")
        if isinstance(value, (int, str)):
            text = str(value).strip()
            return text or None
        raise RecordParseError(f"field 'error.{key}' must be an int or string when present")
    return None


def parse_int_value(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"field '{field_name}' must not be boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError(f"field '{field_name}' must not be empty")
        try:
            return int(text, 0)
        except ValueError as exc:
            raise ValueError(f"field '{field_name}' has invalid integer value {value!r}") from exc
    raise ValueError(f"field '{field_name}' must be an int or string")


def parse_raw_bytes_hex(value: str) -> bytes:
    compact = "".join(value.split())
    if not compact:
        raise RecordParseError("field 'raw_bytes_hex' must not be empty")
    if not re.fullmatch(r"[0-9A-Fa-f]+", compact):
        raise RecordParseError("field 'raw_bytes_hex' must contain only hexadecimal digits")
    if len(compact) % 2 != 0:
        raise RecordParseError("field 'raw_bytes_hex' must contain an even number of hexadecimal digits")
    return bytes.fromhex(compact)


def result_label_hint(payload: Any, source_index: int) -> str:
    if isinstance(payload, dict):
        label = payload.get("label")
        if isinstance(label, str) and label.strip():
            return label.strip()
    return f"result#{source_index}"


def serialize_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


def deserialize_json(value: str) -> Any:
    return json.loads(value)


if __name__ == "__main__":
    raise SystemExit(main())
