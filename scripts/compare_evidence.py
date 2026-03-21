from __future__ import annotations

"""Compare saved evidence bundles for current-versus-legacy Skyrim VR candidates.

Assumptions kept intentionally loose for capture-side compatibility:
- Input JSON may be a single bundle object, a top-level list, or a container under
  `bundles`, `evidence`, `records`, `items`, or `candidates`.
- Candidate identity is discovered from common fields such as `label`, `group`,
  `target_rva`, `target_va`, `raw_bytes_hex`, and `disassembly`, including simple
  nested forms like `candidate.label` or `window.bytes_hex`.
- Relationship classification is review-oriented. It summarizes likely pairings but
  does not decide the final runtime patch table on its own.
"""

import argparse
import json
import math
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


CURRENT_GROUP_KIND = "current"
LEGACY_GROUP_KIND = "legacy"
DISCARDED_GROUP_KIND = "discarded"
OTHER_GROUP_KIND = "other"
WRAPPER_KEYS = ("bundles", "evidence", "records", "items", "candidates")
RECORD_ADDRESS_PATHS = (
    "target_rva",
    "rva",
    "target.rva",
    "candidate.rva",
    "provenance.target_rva",
    "target_va",
    "va",
    "target.va",
    "candidate.va",
    "provenance.target_va",
)
RECORD_EVIDENCE_PATHS = (
    "raw_bytes",
    "raw_bytes_hex",
    "bytes",
    "bytes_hex",
    "window.bytes",
    "window.bytes_hex",
    "capture.raw_bytes",
    "capture.raw_bytes_hex",
    "disassembly",
    "window.disassembly",
    "capture.disassembly",
    "instructions",
    "window.instructions",
)

GROUP_KIND_ALIASES = {
    CURRENT_GROUP_KIND: {
        "current",
        "currentvalidated",
        "currentvalidatedvrsites",
        "validated",
        "validatedcurrent",
        "validatedvrsites",
    },
    LEGACY_GROUP_KIND: {
        "legacy",
        "legacyng",
        "legacyngera",
        "ng",
        "ngera",
        "originalngera",
        "originalngeravrpatchaddresses",
    },
    DISCARDED_GROUP_KIND: {
        "discarded",
        "discardedcurrentrepoguesses",
        "discardedguess",
        "discardedguesses",
    },
}

HEX_TOKEN_RE = re.compile(r"[0-9A-Fa-f]{2}")


@dataclass(frozen=True)
class EvidenceRecord:
    source_path: str
    source_index: int
    label: str
    label_key: str
    group: str
    group_kind: str
    notes: str | None
    capture_timestamp: str | None
    capture_mode: str | None
    process_state: str | None
    process_name: str | None
    pid: int | None
    module_path: str | None
    module_base: int | None
    target_rva: int | None
    target_va: int | None
    before: int | None
    after: int | None
    raw_bytes: bytes | None
    raw_bytes_hex: str | None
    disassembly_text: str | None


@dataclass(frozen=True)
class Pairing:
    current: EvidenceRecord
    legacy: EvidenceRecord | None
    relation: str
    score: float
    best_shift: int | None
    rva_delta: int | None
    reason: str


@dataclass(frozen=True)
class SkippedInput:
    source_path: str
    reason: str


class RecordParseError(ValueError):
    """Raised when a record-like payload contains an invalid field value."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare saved evidence bundles from disk and summarize current-versus-legacy "
            "candidate relationships for review."
        )
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="One or more JSON evidence bundle files or directories containing JSON bundles",
    )
    parser.add_argument(
        "--current-group",
        default=CURRENT_GROUP_KIND,
        help="Group kind or literal group name to treat as the current candidate set (default: current)",
    )
    parser.add_argument(
        "--legacy-group",
        default=LEGACY_GROUP_KIND,
        help="Group kind or literal group name to treat as the legacy candidate set (default: legacy)",
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
        raise SystemExit("No evidence records were found in the provided JSON bundles")

    current_records = select_group(records, args.current_group)
    legacy_records = select_group(records, args.legacy_group)
    if not current_records:
        raise SystemExit(f"No records matched current group selector '{args.current_group}'")
    if not legacy_records:
        raise SystemExit(f"No records matched legacy group selector '{args.legacy_group}'")

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


def load_records(bundle_paths: Iterable[Path]) -> tuple[list[EvidenceRecord], list[SkippedInput]]:
    records: list[EvidenceRecord] = []
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

        entries, skip_reason = iter_bundle_entries(payload)
        if skip_reason is not None:
            skipped_inputs.append(SkippedInput(source_path=str(bundle_path), reason=skip_reason))
            continue
        for source_index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            try:
                records.append(build_record(bundle_path, source_index, entry))
            except RecordParseError as exc:
                skipped_inputs.append(
                    SkippedInput(
                        source_path=str(bundle_path),
                        reason=f"Record {source_index}: {exc}",
                    )
                )
    return records, skipped_inputs


def iter_bundle_entries(payload: Any) -> tuple[list[dict[str, Any]], str | None]:
    if isinstance(payload, list):
        entries = [item for item in payload if isinstance(item, dict) and is_probable_evidence_record(item)]
        if entries or not payload:
            return entries, None
        return [], "Top-level JSON list does not contain evidence records"
    if not isinstance(payload, dict):
        return [], "Top-level JSON must be an object or list"

    saw_empty_wrapper = False
    last_wrapper_skip_reason: str | None = None
    for key in WRAPPER_KEYS:
        value = payload.get(key)
        if not isinstance(value, list):
            continue
        if not value:
            saw_empty_wrapper = True
            continue

        parent_context = {name: item for name, item in payload.items() if name not in WRAPPER_KEYS}
        entries = [
            merge_parent_context(parent_context, item)
            for item in value
            if isinstance(item, dict)
        ]
        entries = [entry for entry in entries if is_probable_evidence_record(entry)]
        if entries:
            return entries, None
        last_wrapper_skip_reason = f"Wrapper '{key}' does not contain evidence records"

    if last_wrapper_skip_reason is not None:
        return [], last_wrapper_skip_reason
    if saw_empty_wrapper:
        return [], None

    if is_probable_evidence_record(payload):
        return [payload], None
    return [], "Top-level JSON object does not look like an evidence bundle"


def build_record(bundle_path: Path, source_index: int, payload: dict[str, Any]) -> EvidenceRecord:
    label = stringify(
        first_value(
            payload,
            "label",
            "name",
            "candidate.label",
            "candidate.name",
            "target.label",
            default=f"{bundle_path.stem}#{source_index}",
        )
    )
    group = stringify(
        first_value(
            payload,
            "group",
            "candidate.group",
            "target.group",
            default="unknown",
        )
    )
    label_key = normalize_token(label)
    group_kind = classify_group(group)

    module_base = parse_int_field(
        payload,
        "module base",
        "module_base",
        "module.base_address",
        "provenance.module_base_address",
    )
    target_rva = parse_int_field(
        payload,
        "target RVA",
        "target_rva",
        "rva",
        "target.rva",
        "candidate.rva",
        "provenance.target_rva",
    )
    target_va = parse_int_field(
        payload,
        "target VA",
        "target_va",
        "va",
        "target.va",
        "candidate.va",
        "provenance.target_va",
    )
    if target_rva is None and target_va is not None and module_base is not None:
        target_rva = target_va - module_base

    raw_bytes = parse_raw_bytes(
        first_value(
            payload,
            "raw_bytes",
            "raw_bytes_hex",
            "bytes",
            "bytes_hex",
            "window.bytes",
            "window.bytes_hex",
            "capture.raw_bytes",
            "capture.raw_bytes_hex",
        )
    )

    return EvidenceRecord(
        source_path=str(bundle_path),
        source_index=source_index,
        label=label,
        label_key=label_key,
        group=group,
        group_kind=group_kind,
        notes=optional_string(first_value(payload, "notes", "candidate.notes", "target.notes")),
        capture_timestamp=optional_string(first_value(payload, "capture_timestamp", "timestamp", "captured_at")),
        capture_mode=optional_string(first_value(payload, "capture_mode", "mode")),
        process_state=optional_string(first_value(payload, "process_state", "annotation.process_state")),
        process_name=optional_string(first_value(payload, "process_name", "process.name")),
        pid=parse_int_field(payload, "PID", "pid", "process.pid"),
        module_path=optional_string(first_value(payload, "module_path", "module.path")),
        module_base=module_base,
        target_rva=target_rva,
        target_va=target_va,
        before=parse_int_field(payload, "window.before", "before", "window.before", "window_size.before"),
        after=parse_int_field(payload, "window.after", "after", "window.after", "window_size.after"),
        raw_bytes=raw_bytes,
        raw_bytes_hex=raw_bytes.hex() if raw_bytes is not None else None,
        disassembly_text=parse_disassembly_text(
            first_value(
                payload,
                "disassembly",
                "window.disassembly",
                "capture.disassembly",
                "instructions",
                "window.instructions",
            )
        ),
    )


def select_group(records: Iterable[EvidenceRecord], selector: str) -> list[EvidenceRecord]:
    normalized_selector = normalize_token(selector)
    canonical_selector = canonical_group_kind(selector)
    matches = [
        record
        for record in records
        if record.group_kind == canonical_selector or normalize_token(record.group) == normalized_selector
    ]
    return sorted(matches, key=sort_key)


def build_pairings(
    *,
    current_records: list[EvidenceRecord],
    legacy_records: list[EvidenceRecord],
    min_same_block_score: float,
    min_different_score: float,
    max_anchor_shift: int,
) -> tuple[list[Pairing], list[EvidenceRecord], list[EvidenceRecord]]:
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

    assigned_current: set[EvidenceRecord] = set()
    assigned_legacy: set[EvidenceRecord] = set()
    pairings: list[Pairing] = []
    for _, pairing in sorted(scored_candidates, key=lambda item: item[0], reverse=True):
        current = pairing.current
        legacy = pairing.legacy
        if current in assigned_current or legacy in assigned_legacy:
            continue
        assigned_current.add(current)
        assigned_legacy.add(legacy)
        pairings.append(pairing)

    pairings.sort(key=lambda pairing: sort_key(pairing.current))
    unmatched_current = [record for record in current_records if record not in assigned_current]
    unmatched_legacy = [record for record in legacy_records if record not in assigned_legacy]
    return pairings, unmatched_current, unmatched_legacy


def pair_priority(
    current: EvidenceRecord,
    legacy: EvidenceRecord,
    score: float,
    best_shift: int | None,
) -> tuple[float, ...]:
    exact_label = 1.0 if current.label_key and current.label_key == legacy.label_key else 0.0
    partial_label = 1.0 if has_partial_label_match(current.label_key, legacy.label_key) else 0.0
    rva_delta = None
    if current.target_rva is not None and legacy.target_rva is not None:
        rva_delta = current.target_rva - legacy.target_rva
    shift_agreement = 1.0 if shift_matches_delta(best_shift, rva_delta) else 0.0
    rva_closeness = 0.0 if rva_delta is None else -float(abs(rva_delta))
    return (exact_label, shift_agreement, score, partial_label, rva_closeness)


def has_partial_label_match(current_label: str, legacy_label: str) -> bool:
    if not current_label or not legacy_label:
        return False
    return current_label in legacy_label or legacy_label in current_label


def compare_pair(
    current: EvidenceRecord,
    legacy: EvidenceRecord,
    min_same_block_score: float,
    min_different_score: float,
    max_anchor_shift: int,
) -> Pairing:
    score, best_shift, reason = compute_similarity(current, legacy, max_anchor_shift)
    rva_delta = None
    if current.target_rva is not None and legacy.target_rva is not None:
        rva_delta = current.target_rva - legacy.target_rva

    if not is_readable(current) or not is_readable(legacy):
        relation = "unreadable"
    elif current.target_rva == legacy.target_rva and score >= min_same_block_score:
        relation = "exact_match"
    elif (
        best_shift not in (None, 0)
        and score >= min_same_block_score
        and shift_matches_delta(best_shift, rva_delta)
    ):
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
        rva_delta=rva_delta,
        reason=reason,
    )


def has_counterpart_signal(
    pairing: Pairing,
    min_different_score: float,
    max_anchor_shift: int,
) -> bool:
    current = pairing.current
    legacy = pairing.legacy

    if current.target_rva is not None and legacy.target_rva is not None:
        if current.target_rva == legacy.target_rva:
            return True
        if (
            pairing.rva_delta is not None
            and abs(pairing.rva_delta) <= max_anchor_shift
            and shift_matches_delta(pairing.best_shift, pairing.rva_delta)
        ):
            return True

    if current.label_key and legacy.label_key:
        if current.label_key == legacy.label_key or has_partial_label_match(current.label_key, legacy.label_key):
            return True

    return pairing.score >= min_different_score


def compute_similarity(
    current: EvidenceRecord,
    legacy: EvidenceRecord,
    max_anchor_shift: int,
) -> tuple[float, int | None, str]:
    if current.raw_bytes and legacy.raw_bytes:
        score, shift, compared_bytes, anchor_aware = best_byte_similarity(current, legacy, max_anchor_shift)
        reason = "anchor-aligned byte overlap" if anchor_aware else "byte-window overlap"
        return score, shift, f"{reason} ({compared_bytes} byte(s) compared)"
    if current.disassembly_text and legacy.disassembly_text:
        return text_similarity(current.disassembly_text, legacy.disassembly_text), None, "disassembly text similarity"
    return 0.0, None, "missing comparable raw bytes and disassembly"


def build_output_payload(
    *,
    inputs: list[Path],
    all_records: list[EvidenceRecord],
    current_selector: str,
    legacy_selector: str,
    pairings: list[Pairing],
    unmatched_current: list[EvidenceRecord],
    unmatched_legacy: list[EvidenceRecord],
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
        "skipped_inputs": [asdict(entry) for entry in skipped_inputs],
        "unmatched_current": [summarize_record(record) for record in unmatched_current],
        "unmatched_legacy": [summarize_record(record) for record in unmatched_legacy],
        "comparisons": [
            {
                "relation": pairing.relation,
                "score": round(pairing.score, 4),
                "best_shift": pairing.best_shift,
                "rva_delta": pairing.rva_delta,
                "reason": pairing.reason,
                "current": summarize_record(pairing.current),
                "legacy": summarize_record(pairing.legacy),
            }
            for pairing in pairings
        ],
    }


def summarize_groups(records: Iterable[EvidenceRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        counts[record.group] = counts.get(record.group, 0) + 1
    return counts


def summarize_record(record: EvidenceRecord | None) -> dict[str, Any] | None:
    if record is None:
        return None
    payload = asdict(record)
    payload.pop("raw_bytes")
    return payload


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
    skipped_inputs = payload["skipped_inputs"]
    lines.append(f"skipped inputs : {len(skipped_inputs)}")
    unmatched_current = payload["unmatched_current"]
    lines.append(f"unmatched current: {len(unmatched_current)}")
    unmatched_legacy = payload["unmatched_legacy"]
    lines.append(f"unmatched legacy: {len(unmatched_legacy)}")
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

    if unmatched_current:
        lines.append("Current Records Without A Legacy Pair")
        for record in unmatched_current:
            lines.append(
                f"- {record['label']} rva={format_int(record.get('target_rva'))} "
                f"group={record['group']} source={Path(record['source_path']).name}"
            )
        lines.append("")

    if unmatched_legacy:
        lines.append("Legacy Records Without A Current Pair")
        for record in unmatched_legacy:
            lines.append(
                f"- {record['label']} rva={format_int(record.get('target_rva'))} "
                f"group={record['group']} source={Path(record['source_path']).name}"
            )
        lines.append("")

    if skipped_inputs:
        lines.append("Skipped Inputs")
        for entry in skipped_inputs:
            lines.append(f"- {Path(entry['source_path']).name}: {entry['reason']}")

    return "\n".join(lines).rstrip()


def record_label_for_text(record: dict[str, Any] | None) -> str:
    if record is None:
        return "-"
    return str(record["label"])


def best_byte_similarity(
    current: EvidenceRecord,
    legacy: EvidenceRecord,
    max_anchor_shift: int,
) -> tuple[float, int, int, bool]:
    if can_anchor_align(current) and can_anchor_align(legacy):
        return best_anchor_aligned_overlap(current, legacy, max_anchor_shift)
    score, shift, compared_bytes = best_linear_overlap(current.raw_bytes or b"", legacy.raw_bytes or b"", max_anchor_shift)
    return score, shift, compared_bytes, False


def best_anchor_aligned_overlap(
    current: EvidenceRecord,
    legacy: EvidenceRecord,
    max_anchor_shift: int,
) -> tuple[float, int, int, bool]:
    expected_shift = None
    if current.target_rva is not None and legacy.target_rva is not None:
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
                and expected_shift is not None
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
    current_bytes = current.raw_bytes or b""
    legacy_bytes = legacy.raw_bytes or b""
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
        if current_bytes[current_index] == legacy_bytes[legacy_index]:
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


def iter_candidate_shifts(expected_shift: int | None, max_anchor_shift: int) -> Iterable[int]:
    seen: set[int] = set()
    if expected_shift is not None and abs(expected_shift) <= max_anchor_shift:
        seen.add(expected_shift)
        yield expected_shift
    for shift in range(-max_anchor_shift, max_anchor_shift + 1):
        if shift not in seen:
            yield shift


def text_similarity(left: str, right: str) -> float:
    left_tokens = left.split()
    right_tokens = right.split()
    if not left_tokens or not right_tokens:
        return 0.0
    overlap = sum(1 for index, token in enumerate(left_tokens[: len(right_tokens)]) if token == right_tokens[index])
    return overlap / max(len(left_tokens), len(right_tokens))


def is_readable(record: EvidenceRecord) -> bool:
    return bool(record.raw_bytes or record.disassembly_text)


def classify_group(group: str) -> str:
    token = normalize_token(group)
    for group_kind, aliases in GROUP_KIND_ALIASES.items():
        if token in aliases:
            return group_kind
    return OTHER_GROUP_KIND


def canonical_group_kind(selector: str) -> str:
    token = normalize_token(selector)
    for group_kind, aliases in GROUP_KIND_ALIASES.items():
        if token == group_kind or token in aliases:
            return group_kind
    return token


def first_value(payload: dict[str, Any], *paths: str, default: Any = None) -> Any:
    for path in paths:
        value = get_path(payload, path)
        if value is not None:
            return value
    return default


def get_path(payload: dict[str, Any], path: str) -> Any:
    current: Any = payload
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current[segment]
    return current


def merge_parent_context(parent: dict[str, Any], child: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for key, value in parent.items():
        if key in WRAPPER_KEYS:
            continue
        merged[key] = value
    for key, value in child.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_parent_context(merged[key], value)
        else:
            merged[key] = value
    return merged


def is_probable_evidence_record(payload: dict[str, Any]) -> bool:
    has_address = any(has_meaningful_value(get_path(payload, path)) for path in RECORD_ADDRESS_PATHS)
    has_evidence = any(has_meaningful_value(get_path(payload, path)) for path in RECORD_EVIDENCE_PATHS)
    return has_address and has_evidence


def has_meaningful_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def stringify(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_int_value(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        return int(text, 0)
    return None


def parse_int_field(payload: dict[str, Any], field_name: str, *paths: str) -> int | None:
    value = first_value(payload, *paths)
    if value is None:
        return None
    try:
        return parse_int_value(value)
    except ValueError as exc:
        raise RecordParseError(f"invalid {field_name} value {value!r}") from exc


def parse_raw_bytes(value: Any) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, list):
        try:
            return bytes(int(item) & 0xFF for item in value)
        except (TypeError, ValueError):
            return None
    if isinstance(value, str):
        tokens = HEX_TOKEN_RE.findall(value)
        if not tokens:
            return None
        return bytes(int(token, 16) for token in tokens)
    return None


def parse_disassembly_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if isinstance(value, list):
        lines: list[str] = []
        for item in value:
            if isinstance(item, str):
                stripped = item.strip()
                if stripped:
                    lines.append(stripped)
                continue
            if isinstance(item, dict):
                mnemonic = optional_string(item.get("mnemonic")) or "?"
                op_str = optional_string(item.get("op_str")) or ""
                address = parse_int_value(item.get("address"))
                prefix = f"{address:016X}: " if address is not None else ""
                lines.append(f"{prefix}{mnemonic} {op_str}".rstrip())
        if lines:
            return "\n".join(lines)
    return None


def normalize_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def can_anchor_align(record: EvidenceRecord) -> bool:
    return record.raw_bytes is not None and anchor_index(record) is not None


def anchor_index(record: EvidenceRecord) -> int | None:
    if record.raw_bytes is None or record.before is None:
        return None
    if 0 <= record.before < len(record.raw_bytes):
        return record.before
    return None


def relative_bounds(record: EvidenceRecord) -> tuple[int, int]:
    raw_bytes = record.raw_bytes or b""
    anchor = anchor_index(record)
    if anchor is None:
        return (0, -1)
    left_extent = anchor
    right_extent = len(raw_bytes) - anchor - 1
    if record.before is not None:
        left_extent = min(left_extent, record.before)
    if record.after is not None:
        right_extent = min(right_extent, record.after)
    return (-left_extent, right_extent)


def shift_matches_delta(best_shift: int | None, rva_delta: int | None) -> bool:
    if best_shift is None:
        return False
    if rva_delta is None:
        return True
    return best_shift == rva_delta


def sort_key(record: EvidenceRecord) -> tuple[int, str, str]:
    rva = record.target_rva if record.target_rva is not None else sys.maxsize
    return (rva, record.label_key, record.source_path)


def format_int(value: int | None) -> str:
    if value is None:
        return "-"
    sign = "-" if value < 0 else ""
    return f"{sign}0x{abs(value):X}"


if __name__ == "__main__":
    raise SystemExit(main())
