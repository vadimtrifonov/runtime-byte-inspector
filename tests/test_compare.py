import copy
import json
import tempfile
import unittest
from pathlib import Path

from support import ok_result, saved_capture

from scripts.compare import Record, compare_captures, compare_records, load_capture, render_report


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def save(self, name, payload):
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_nine_changed_bytes_cannot_be_an_exact_match(self):
        original = bytes(range(97))
        changed = original[:32] + b"\xff" * 9 + original[41:]
        pair = compare_records(
            Record("site", 0x1000, 32, original, None), Record("site", 0x1000, 32, changed, None), "rva"
        )
        self.assertFalse(pair["windows_equal"])
        self.assertEqual(pair["compared_bytes"], 97)
        self.assertEqual(pair["different_bytes"], 9)
        self.assertEqual(pair["equal_bytes"], 88)
        self.assertEqual(
            pair["differences"],
            [{"offset": 0x1000, "left_hex": original[32:41].hex().upper(), "right_hex": "FF" * 9}],
        )

    def test_no_shift_search_and_tiny_overlap_does_not_mean_equal_windows(self):
        left = Record("left", 0x1000, 0, bytes.fromhex("AA BB CC"), None)
        right = Record("right", 0x1000, 0, bytes.fromhex("CC DD EE"), None)
        pair = compare_records(left, right, "rva")
        self.assertEqual(pair["different_bytes"], 3)
        self.assertFalse(pair["windows_equal"])
        shifted = Record("right", 0x1002, 0, right.raw, None)
        overlap = compare_records(left, shifted, "rva")
        self.assertEqual(overlap["compared_bytes"], 1)
        self.assertEqual(overlap["equal_bytes"], 1)
        self.assertEqual((overlap["left_only_bytes"], overlap["right_only_bytes"]), (2, 2))
        self.assertFalse(overlap["windows_equal"])

    def test_alignment_is_explicit_and_target_relative_offsets_can_be_negative(self):
        left = Record("site", 0x1000, 1, b"\x90\x90\xc3", None)
        right = Record("site", 0x1200, 1, b"\x90\x90\xc3", None)
        self.assertEqual(compare_records(left, right, "rva")["status"], "no_overlap")
        relative = compare_records(left, right, "target")
        self.assertTrue(relative["windows_equal"])
        self.assertEqual(relative["overlap"], {"start": -1, "end_exclusive": 2})

    def test_captures_pair_only_equal_labels_and_allow_explicit_pair_selection(self):
        left_path = self.save(
            "left.json",
            saved_capture(
                [
                    ok_result("current", b"\x90\xc3"),
                    ok_result("common", b"\x90\xc3"),
                ]
            ),
        )
        right_capture = saved_capture([ok_result("legacy", b"\x90\xc3"), ok_result("common", b"\x90\xc3")])
        right_capture["source"]["module"]["path"] = "C:\\Other\\Different.exe"
        right_capture["annotations"]["patch_state"] = "patched"
        right_path = self.save("right.json", right_capture)
        report = compare_captures(left_path, right_path)
        self.assertEqual(len(report["comparisons"]), 1)
        self.assertEqual(report["comparisons"][0]["left"]["label"], "common")
        self.assertEqual([entry["label"] for entry in report["unmatched_left"]], ["current"])
        self.assertEqual([entry["label"] for entry in report["unmatched_right"]], ["legacy"])
        self.assertEqual(report["right"]["source"]["module"]["path"], "C:\\Other\\Different.exe")
        self.assertEqual(report["right"]["annotations"]["patch_state"], "patched")
        selected = compare_captures(left_path, right_path, left_label="current", right_label="legacy")
        self.assertTrue(selected["comparisons"][0]["windows_equal"])
        with self.assertRaises(ValueError):
            compare_captures(left_path, right_path, left_label="current")

    def test_capture_errors_are_reported_not_classified_as_byte_differences(self):
        error = {"type": "PermissionError", "message": "Access denied", "winerror": 5}
        left_path = self.save(
            "left.json",
            saved_capture(
                [
                    {
                        "target": {"label": "site", "group": "historical", "rva": "0x1000"},
                        "read": {"status": "error", "error": error},
                    }
                ]
            ),
        )
        right_path = self.save("right.json", saved_capture([ok_result("site", b"\x90")], after=0))
        pair = compare_captures(left_path, right_path)["comparisons"][0]
        self.assertEqual(pair["status"], "unreadable")
        self.assertEqual(pair["left"]["error"], error)
        self.assertNotIn("different_bytes", pair)
        report = compare_captures(left_path, right_path)
        report["comparisons"] = []
        report["unmatched_left"] = [pair["left"]]
        self.assertIn("Access denied", render_report(report))

    def test_invalid_captures_are_rejected_without_dropping_results(self):
        original = saved_capture([ok_result("site", b"\x90\xc3")])
        cases = []
        for section, key, value in (
            ("read", "bytes_hex", "90"),
            ("read", "bytes_hex", "ZZ"),
            ("read", "start_rva", "0x1001"),
            ("target", "rva", True),
        ):
            case = copy.deepcopy(original)
            case["results"][0][section][key] = value
            cases.append(case)
        duplicate = copy.deepcopy(original)
        duplicate["results"].append(duplicate["results"][0])
        cases.extend([duplicate, {"records": []}])
        for case in cases:
            with self.subTest(case=case):
                path = self.save("bad.json", case)
                with self.assertRaisesRegex(ValueError, "Invalid capture"):
                    load_capture(path)

    def test_decoding_and_summary_do_not_determine_byte_equality(self):
        capture = saved_capture([ok_result("site", b"\x90\xc3")])
        left = self.save("raw-only.json", capture)
        capture["results"][0]["decode"] = {"status": "error", "error": {"message": "decoder failed"}}
        capture["summary"] = {"captured_ok": 0, "captured_error": 99}
        right = self.save("capture.json", capture)
        report = compare_captures(left, right)
        self.assertTrue(report["comparisons"][0]["windows_equal"])

    def test_requested_windows_can_be_clipped_at_module_boundaries(self):
        path = self.save(
            "clipped.json",
            saved_capture(
                [ok_result("first", b"\x90" * 65, 0), ok_result("last", b"\x90" * 33, 0x1FFF, 32)],
                before=32,
                after=64,
            ),
        )
        report = compare_captures(path, path)
        self.assertEqual([pair["compared_bytes"] for pair in report["comparisons"]], [65, 33])
        self.assertTrue(all(pair["windows_equal"] for pair in report["comparisons"]))
