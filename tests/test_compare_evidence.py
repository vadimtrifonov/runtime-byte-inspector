from __future__ import annotations

import importlib.util
import io
import json
import shutil
import sys
import unittest
from argparse import Namespace
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest import mock
from uuid import uuid4


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "compare_evidence.py"
TEST_TMP_ROOT = Path(__file__).resolve().parents[1] / ".tmp" / "tests"
SPEC = importlib.util.spec_from_file_location("compare_evidence", MODULE_PATH)
assert SPEC is not None
assert SPEC.loader is not None
compare_evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = compare_evidence
SPEC.loader.exec_module(compare_evidence)


@contextmanager
def workspace_temp_dir() -> Path:
    TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)
    temp_dir = TEST_TMP_ROOT / f"case-{uuid4().hex}"
    temp_dir.mkdir()
    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        try:
            TEST_TMP_ROOT.rmdir()
        except OSError:
            pass
        try:
            TEST_TMP_ROOT.parent.rmdir()
        except OSError:
            pass


def make_bundle(*, results: list[dict[str, object]]) -> dict[str, object]:
    return {
        "capture_timestamp": "2026-03-21T00:00:00Z",
        "capture_mode": "live_process",
        "process_state": "unknown",
        "manifest": {
            "path": str((Path(__file__).resolve().parents[1] / "manifests" / "seeded_candidates.json").resolve()),
            "version": 1,
            "group_filter": [],
        },
        "process": {
            "name": "SkyrimVR.exe",
            "pid": 12345,
        },
        "module": {
            "name": "SkyrimVR.exe",
            "path": "C:\\Games\\Skyrim\\SkyrimVR.exe",
            "base_address": "0x140000000",
            "size": "0x4000000",
        },
        "window": {
            "before": 32,
            "after": 64,
            "requested_size": 97,
        },
        "results": results,
        "summary": {
            "candidate_count": len(results),
            "captured_ok": sum(1 for result in results if result.get("status") == "ok"),
            "captured_error": sum(1 for result in results if result.get("status") == "error"),
            "captured_unexpected_error": 0,
        },
    }


def make_ok_result(*, label: str, group: str, target_rva: str, raw_bytes_hex: str) -> dict[str, object]:
    compact = "".join(raw_bytes_hex.split())
    return {
        "label": label,
        "group": group,
        "notes": None,
        "target_rva": target_rva,
        "target_va": "0x140001000",
        "window": {
            "start_rva": "0x1000",
            "start_va": "0x140001000",
            "end_rva_exclusive": "0x1003",
            "end_va_exclusive": "0x140001003",
            "requested_before": 1,
            "requested_after": 1,
            "actual_before": 1,
            "actual_after": 1,
            "size": 3,
        },
        "status": "ok",
        "raw_bytes_hex": compact,
        "raw_bytes_len": len(bytes.fromhex(compact)),
        "disassembly": [
            {
                "address": "0x140001000",
                "size": 1,
                "bytes_hex": compact[:2],
                "mnemonic": "nop",
                "op_str": "",
                "marker": ">>",
            }
        ],
    }


def make_error_result(*, label: str, group: str, target_rva: str) -> dict[str, object]:
    return {
        "label": label,
        "group": group,
        "notes": None,
        "target_rva": target_rva,
        "status": "error",
        "error_kind": "operational",
        "error": {
            "type": "PermissionError",
            "message": "access denied",
            "traceback": "stack",
            "winerror": 5,
        },
    }


class CompareEvidenceLoadTests(unittest.TestCase):
    def test_load_bundle_accepts_capture_manifest_schema(self) -> None:
        bundle = make_bundle(
            results=[
                make_ok_result(
                    label="current_1D7B6B",
                    group="current_validated",
                    target_rva="0x1D7B6B",
                    raw_bytes_hex="90 90 90",
                )
            ]
        )

        bundle_meta, results = compare_evidence.load_bundle(Path("capture.json"), bundle)

        self.assertEqual(bundle_meta.capture_mode, "live_process")
        self.assertEqual(bundle_meta.process_name, "SkyrimVR.exe")
        self.assertEqual(bundle_meta.module_base, 0x140000000)
        self.assertEqual(len(results), 1)

    def test_load_records_rejects_non_workspace_wrapper_bundle(self) -> None:
        with workspace_temp_dir() as temp_dir:
            (temp_dir / "legacy.json").write_text(
                json.dumps({"records": [{"label": "cur"}]}),
                encoding="utf-8",
            )

            bundle_paths = compare_evidence.discover_bundle_paths([str(temp_dir)])
            records, skipped_inputs = compare_evidence.load_records(bundle_paths)

            self.assertEqual(records, [])
            self.assertEqual(len(skipped_inputs), 1)
            self.assertIn("Bundle schema error", skipped_inputs[0].reason)
            self.assertIn("capture_timestamp", skipped_inputs[0].reason)

    def test_parse_result_preserves_structured_capture_error_fields(self) -> None:
        bundle_meta, _ = compare_evidence.load_bundle(
            Path("capture.json"),
            make_bundle(results=[]),
        )

        record = compare_evidence.parse_result(
            bundle_meta,
            0,
            make_error_result(
                label="current_1D7B6B",
                group="current_validated",
                target_rva="0x1D7B6B",
            ),
        )

        self.assertIsInstance(record, compare_evidence.CaptureFailureRecord)
        self.assertEqual(record.error_message, "access denied")
        self.assertEqual(record.error_traceback, "stack")
        self.assertEqual(record.error_code, "5")

    def test_parse_result_rejects_missing_raw_bytes_hex_for_ok_record(self) -> None:
        bundle_meta, _ = compare_evidence.load_bundle(
            Path("capture.json"),
            make_bundle(results=[]),
        )
        payload = make_ok_result(
            label="current_1D7B6B",
            group="current_validated",
            target_rva="0x1D7B6B",
            raw_bytes_hex="90 90 90",
        )
        del payload["raw_bytes_hex"]

        with self.assertRaises(compare_evidence.RecordParseError):
            compare_evidence.parse_result(bundle_meta, 0, payload)

    def test_parse_result_wraps_invalid_optional_target_va_as_record_error(self) -> None:
        bundle_meta, _ = compare_evidence.load_bundle(
            Path("capture.json"),
            make_bundle(results=[]),
        )
        payload = make_ok_result(
            label="current_1D7B6B",
            group="current_validated",
            target_rva="0x1D7B6B",
            raw_bytes_hex="90 90 90",
        )
        payload["target_va"] = "n/a"

        with self.assertRaises(compare_evidence.RecordParseError):
            compare_evidence.parse_result(bundle_meta, 0, payload)

    def test_parse_result_rejects_inconsistent_window_offsets(self) -> None:
        bundle_meta, _ = compare_evidence.load_bundle(
            Path("capture.json"),
            make_bundle(results=[]),
        )
        payload = make_ok_result(
            label="current_1D7B6B",
            group="current_validated",
            target_rva="0x1D7B6B",
            raw_bytes_hex="90 90 90",
        )
        payload["window"]["actual_before"] = 10
        payload["window"]["actual_after"] = 1

        with self.assertRaises(compare_evidence.RecordParseError):
            compare_evidence.parse_result(bundle_meta, 0, payload)

    def test_parse_result_rejects_failure_fields_on_ok_record(self) -> None:
        bundle_meta, _ = compare_evidence.load_bundle(
            Path("capture.json"),
            make_bundle(results=[]),
        )
        payload = make_ok_result(
            label="current_1D7B6B",
            group="current_validated",
            target_rva="0x1D7B6B",
            raw_bytes_hex="90 90 90",
        )
        payload["error_kind"] = "operational"
        payload["error"] = {"message": "should not be here"}

        with self.assertRaises(compare_evidence.RecordParseError):
            compare_evidence.parse_result(bundle_meta, 0, payload)

    def test_load_records_skips_invalid_json_and_keeps_valid_bundle(self) -> None:
        with workspace_temp_dir() as temp_dir:
            (temp_dir / "valid.json").write_text(
                json.dumps(
                    make_bundle(
                        results=[
                            make_ok_result(
                                label="current_1D7B6B",
                                group="current_validated",
                                target_rva="0x1D7B6B",
                                raw_bytes_hex="90 90 90",
                            ),
                            make_ok_result(
                                label="legacy_1D7B6B",
                                group="legacy_ng",
                                target_rva="0x1D7B6B",
                                raw_bytes_hex="90 90 90",
                            ),
                        ]
                    )
                ),
                encoding="utf-8",
            )
            (temp_dir / "broken.json").write_text('{"results":[', encoding="utf-8")

            bundle_paths = compare_evidence.discover_bundle_paths([str(temp_dir)])
            records, skipped_inputs = compare_evidence.load_records(bundle_paths)

            self.assertEqual(len(records), 2)
            self.assertEqual(len(skipped_inputs), 1)
            self.assertIn("Invalid JSON", skipped_inputs[0].reason)

    def test_load_records_keeps_valid_results_when_required_int_field_is_invalid(self) -> None:
        with workspace_temp_dir() as temp_dir:
            valid_bundle = make_bundle(
                results=[
                    make_ok_result(
                        label="current_1D7B6B",
                        group="current_validated",
                        target_rva="0x1D7B6B",
                        raw_bytes_hex="90 90 90",
                    ),
                    make_ok_result(
                        label="legacy_1D7B6B",
                        group="legacy_ng",
                        target_rva="0x1D7B6B",
                        raw_bytes_hex="90 90 90",
                    ),
                ]
            )
            invalid_bundle = make_bundle(
                results=[
                    make_ok_result(
                        label="current_bad",
                        group="current_validated",
                        target_rva="0x1D7B6B",
                        raw_bytes_hex="90 90 90",
                    )
                ]
            )
            invalid_bundle["results"][0]["target_rva"] = True

            (temp_dir / "valid.json").write_text(json.dumps(valid_bundle), encoding="utf-8")
            (temp_dir / "invalid-required-int.json").write_text(json.dumps(invalid_bundle), encoding="utf-8")

            bundle_paths = compare_evidence.discover_bundle_paths([str(temp_dir)])
            records, skipped_inputs = compare_evidence.load_records(bundle_paths)

            self.assertEqual(len(records), 2)
            self.assertEqual(len(skipped_inputs), 1)
            self.assertIn("target_rva", skipped_inputs[0].reason)
            self.assertIn("must not be boolean", skipped_inputs[0].reason)

    def test_main_reports_skip_reasons_when_all_inputs_are_invalid(self) -> None:
        args = Namespace(
            inputs=["broken"],
            current_group="current_validated",
            legacy_group="legacy_ng",
            format="text",
            min_same_block_score=0.85,
            min_different_score=0.45,
            max_anchor_shift=64,
        )

        with mock.patch.object(compare_evidence, "parse_args", return_value=args):
            with mock.patch.object(compare_evidence, "discover_bundle_paths", return_value=[Path("broken.json")]):
                with mock.patch.object(
                    compare_evidence,
                    "load_records",
                    return_value=([], [compare_evidence.SkippedInput("broken.json", "Bundle schema error: bad field")]),
                ):
                    with self.assertRaises(SystemExit) as exc:
                        compare_evidence.main()

        self.assertIn("Skipped Inputs", str(exc.exception))
        self.assertIn("bad field", str(exc.exception))

    def test_main_writes_skip_reasons_as_json_when_all_inputs_are_invalid(self) -> None:
        args = Namespace(
            inputs=["broken"],
            current_group="current_validated",
            legacy_group="legacy_ng",
            format="json",
            min_same_block_score=0.85,
            min_different_score=0.45,
            max_anchor_shift=64,
        )
        stdout = io.StringIO()

        with mock.patch.object(compare_evidence, "parse_args", return_value=args):
            with mock.patch.object(compare_evidence, "discover_bundle_paths", return_value=[Path("broken.json")]):
                with mock.patch.object(
                    compare_evidence,
                    "load_records",
                    return_value=([], [compare_evidence.SkippedInput("broken.json", "Bundle schema error: bad field")]),
                ):
                    with redirect_stdout(stdout):
                        exit_code = compare_evidence.main()

        self.assertEqual(exit_code, 1)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["record_count"], 0)
        self.assertEqual(len(payload["skipped_inputs"]), 1)
        self.assertIn("bad field", payload["skipped_inputs"][0]["reason"])


class CompareEvidencePairingTests(unittest.TestCase):
    def make_record(
        self,
        *,
        label: str,
        group: str,
        target_rva: int,
        raw_bytes_hex: str,
    ) -> compare_evidence.EvidenceRecord:
        raw_bytes = compare_evidence.parse_raw_bytes_hex(raw_bytes_hex)
        return compare_evidence.EvidenceRecord(
            source_path=f"{label}.json",
            source_index=0,
            label=label,
            label_key=compare_evidence.normalize_token(label),
            label_address_key=compare_evidence.label_address_suffix(label),
            group=group,
            notes=None,
            capture_timestamp="2026-03-21T00:00:00Z",
            capture_mode="live_process",
            process_state="unknown",
            process_name="SkyrimVR.exe",
            pid=12345,
            module_path="C:\\Games\\Skyrim\\SkyrimVR.exe",
            module_base=0x140000000,
            target_rva=target_rva,
            target_va=0x140000000 + target_rva,
            before=1,
            after=1,
            raw_bytes=raw_bytes,
            raw_bytes_hex=raw_bytes.hex(),
        )

    def test_build_pairings_leaves_unrelated_records_unmatched(self) -> None:
        current = self.make_record(
            label="current_1D7B6B",
            group="current_validated",
            target_rva=0x1D7B6B,
            raw_bytes_hex="AA BB CC",
        )
        legacy = self.make_record(
            label="legacy_1DA6B6",
            group="legacy_ng",
            target_rva=0x1DA6B6,
            raw_bytes_hex="11 22 33",
        )

        pairings, unmatched_current, unmatched_legacy = compare_evidence.build_pairings(
            current_records=[current],
            legacy_records=[legacy],
            min_same_block_score=0.85,
            min_different_score=0.45,
            max_anchor_shift=64,
        )

        self.assertEqual(pairings, [])
        self.assertEqual(unmatched_current, [current])
        self.assertEqual(unmatched_legacy, [legacy])

    def test_build_pairings_keeps_error_record_as_unreadable_pair(self) -> None:
        current = compare_evidence.CaptureFailureRecord(
            source_path="cur.json",
            source_index=0,
            label="current_1D7B6B",
            label_key=compare_evidence.normalize_token("current_1D7B6B"),
            label_address_key=compare_evidence.label_address_suffix("current_1D7B6B"),
            group="current_validated",
            notes=None,
            capture_timestamp="2026-03-21T00:00:00Z",
            capture_mode="live_process",
            process_state="unknown",
            process_name="SkyrimVR.exe",
            pid=12345,
            module_path="C:\\Games\\Skyrim\\SkyrimVR.exe",
            module_base=0x140000000,
            target_rva=0x1D7B6B,
            target_va=None,
            status="error",
            error_kind="operational",
            error_message="access denied",
            error_traceback="stack",
            error_code="5",
            error_payload_json=json.dumps({"message": "access denied", "winerror": 5}),
        )
        legacy = self.make_record(
            label="legacy_1D7B6B",
            group="legacy_ng",
            target_rva=0x1D7B6B,
            raw_bytes_hex="11 22 33",
        )

        pairings, unmatched_current, unmatched_legacy = compare_evidence.build_pairings(
            current_records=[current],
            legacy_records=[legacy],
            min_same_block_score=0.85,
            min_different_score=0.45,
            max_anchor_shift=64,
        )

        self.assertEqual(len(pairings), 1)
        self.assertEqual(pairings[0].relation, "unreadable")
        self.assertIn("access denied", pairings[0].reason)
        self.assertEqual(unmatched_current, [])
        self.assertEqual(unmatched_legacy, [])

    def test_render_text_report_surfaces_unmatched_capture_error_details(self) -> None:
        current = compare_evidence.CaptureFailureRecord(
            source_path="cur.json",
            source_index=0,
            label="current_1D7B6B",
            label_key=compare_evidence.normalize_token("current_1D7B6B"),
            label_address_key=compare_evidence.label_address_suffix("current_1D7B6B"),
            group="current_validated",
            notes=None,
            capture_timestamp="2026-03-21T00:00:00Z",
            capture_mode="live_process",
            process_state="unknown",
            process_name="SkyrimVR.exe",
            pid=12345,
            module_path="C:\\Games\\Skyrim\\SkyrimVR.exe",
            module_base=0x140000000,
            target_rva=0x1D7B6B,
            target_va=None,
            status="error",
            error_kind="operational",
            error_message="access denied",
            error_traceback="stack",
            error_code="5",
            error_payload_json=json.dumps({"message": "access denied", "winerror": 5}),
        )

        payload = compare_evidence.build_output_payload(
            inputs=[Path("capture.json")],
            all_records=[current],
            current_selector="current_validated",
            legacy_selector="legacy_ng",
            pairings=[],
            unmatched_current=[current],
            unmatched_legacy=[],
            skipped_inputs=[],
            thresholds={
                "min_same_block_score": 0.85,
                "min_different_score": 0.45,
                "max_anchor_shift": 64,
            },
        )

        report = compare_evidence.render_text_report(payload)

        self.assertIn("access denied", report)


if __name__ == "__main__":
    unittest.main()
