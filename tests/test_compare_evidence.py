from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "compare_evidence.py"
SPEC = importlib.util.spec_from_file_location("compare_evidence", MODULE_PATH)
assert SPEC is not None
assert SPEC.loader is not None
compare_evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = compare_evidence
SPEC.loader.exec_module(compare_evidence)


class CompareEvidenceLoadTests(unittest.TestCase):
    def test_iter_bundle_entries_ignores_unrelated_object(self) -> None:
        entries, reason = compare_evidence.iter_bundle_entries({"instructions": []})

        self.assertEqual(entries, [])
        self.assertEqual(reason, "Top-level JSON object does not look like an evidence bundle")

    def test_iter_bundle_entries_checks_later_wrapper_after_empty_one(self) -> None:
        payload = {
            "bundles": [],
            "records": [
                {
                    "label": "cur",
                    "group": "current",
                    "target_rva": "0x10",
                    "raw_bytes_hex": "90",
                    "before": 0,
                    "after": 0,
                },
                {
                    "label": "leg",
                    "group": "legacy",
                    "target_rva": "0x10",
                    "raw_bytes_hex": "90",
                    "before": 0,
                    "after": 0,
                },
            ],
        }

        entries, reason = compare_evidence.iter_bundle_entries(payload)

        self.assertIsNone(reason)
        self.assertEqual(len(entries), 2)

    def test_load_records_skips_invalid_json_and_keeps_valid_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            (temp_dir / "valid.json").write_text(
                (
                    '{"records":['
                    '{"label":"cur","group":"current","target_rva":"0x10","raw_bytes_hex":"90","before":0,"after":0},'
                    '{"label":"leg","group":"legacy","target_rva":"0x10","raw_bytes_hex":"90","before":0,"after":0}'
                    "]}"
                ),
                encoding="utf-8",
            )
            (temp_dir / "broken.json").write_text('{"records":[', encoding="utf-8")

            bundle_paths = compare_evidence.discover_bundle_paths([str(temp_dir)])
            records, skipped_inputs = compare_evidence.load_records(bundle_paths)

            self.assertEqual(len(records), 2)
            self.assertEqual(len(skipped_inputs), 1)
            self.assertEqual(Path(skipped_inputs[0].source_path).name, "broken.json")
            self.assertIn("Invalid JSON", skipped_inputs[0].reason)

    def test_load_records_skips_record_with_invalid_rva_and_keeps_other_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            temp_dir = Path(temp_dir_name)
            (temp_dir / "valid.json").write_text(
                (
                    '{"records":['
                    '{"label":"cur","group":"current","target_rva":"0x10","raw_bytes_hex":"90","before":0,"after":0},'
                    '{"label":"leg","group":"legacy","target_rva":"0x10","raw_bytes_hex":"90","before":0,"after":0}'
                    "]}"
                ),
                encoding="utf-8",
            )
            (temp_dir / "bad-rva.json").write_text(
                '{"records":[{"label":"noise","group":"metadata","rva":"n/a","raw_bytes_hex":"90"}]}',
                encoding="utf-8",
            )

            bundle_paths = compare_evidence.discover_bundle_paths([str(temp_dir)])
            records, skipped_inputs = compare_evidence.load_records(bundle_paths)

            self.assertEqual(len(records), 2)
            self.assertEqual(len(skipped_inputs), 1)
            self.assertEqual(Path(skipped_inputs[0].source_path).name, "bad-rva.json")
            self.assertIn("Record 0: invalid target RVA value 'n/a'", skipped_inputs[0].reason)


class CompareEvidencePairingTests(unittest.TestCase):
    def make_record(
        self,
        *,
        label: str,
        group: str,
        target_rva: int,
        raw_bytes_hex: str,
    ) -> compare_evidence.EvidenceRecord:
        raw_bytes = compare_evidence.parse_raw_bytes(raw_bytes_hex)
        return compare_evidence.EvidenceRecord(
            source_path=f"{label}.json",
            source_index=0,
            label=label,
            label_key=compare_evidence.normalize_token(label),
            group=group,
            group_kind=compare_evidence.classify_group(group),
            notes=None,
            capture_timestamp=None,
            capture_mode=None,
            process_state=None,
            process_name=None,
            pid=None,
            module_path=None,
            module_base=None,
            target_rva=target_rva,
            target_va=None,
            before=1,
            after=1,
            raw_bytes=raw_bytes,
            raw_bytes_hex=raw_bytes.hex() if raw_bytes is not None else None,
            disassembly_text=None,
        )

    def test_build_pairings_leaves_unrelated_records_unmatched(self) -> None:
        current = self.make_record(label="cur-only", group="current", target_rva=0x1000, raw_bytes_hex="AA BB CC")
        legacy = self.make_record(label="leg-only", group="legacy", target_rva=0x9000, raw_bytes_hex="11 22 33")

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

    def test_build_pairings_keeps_low_score_mismatch_when_counterpart_is_plausible(self) -> None:
        current = self.make_record(label="site-a", group="current", target_rva=0x1000, raw_bytes_hex="AA BB CC")
        legacy = self.make_record(label="site-a", group="legacy", target_rva=0x1000, raw_bytes_hex="11 22 33")

        pairings, unmatched_current, unmatched_legacy = compare_evidence.build_pairings(
            current_records=[current],
            legacy_records=[legacy],
            min_same_block_score=0.85,
            min_different_score=0.45,
            max_anchor_shift=64,
        )

        self.assertEqual(len(pairings), 1)
        self.assertEqual(pairings[0].relation, "mismatch")
        self.assertEqual(unmatched_current, [])
        self.assertEqual(unmatched_legacy, [])


if __name__ == "__main__":
    unittest.main()
