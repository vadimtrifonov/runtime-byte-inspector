import json
import os
import tempfile
import unittest
from datetime import datetime
from importlib.metadata import version
from pathlib import Path
from unittest import mock

from support import BASE, write_pe

from scripts.capture import (
    Target,
    capture_target,
    capture_targets,
    load_target_list,
    validate_window,
    window_bounds,
    write_capture,
)
from scripts.pe import Module, PeImage


class CaptureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_windows_are_bounded_and_clipped_at_module_edges(self):
        self.assertEqual(window_bounds(100, 0, 32, 64), (0, 65))
        self.assertEqual(window_bounds(100, 99, 32, 64), (67, 100))
        self.assertEqual(window_bounds(100, 20, 0, 0), (20, 21))
        for before, after in ((-1, 0), (0, -1), (4095, 1), (4096, 0)):
            with self.subTest(before=before, after=after), self.assertRaises(ValueError):
                validate_window(before, after)
        validate_window(4095, 0)
        with self.assertRaises(ValueError):
            window_bounds(100, 100, 0, 0)

    def test_target_list_preserves_labels_and_accepts_optional_arbitrary_groups(self):
        path = self.root / "targets.json"
        path.write_text(
            json.dumps(
                {
                    "purpose": "extra investigation context",
                    "targets": [
                        {
                            "label": "one",
                            "rva": "0x1000",
                            "group": "probe",
                            "decode_rva": "0xfff",
                            "notes": "context",
                            "reference": "extra target context",
                        },
                        {"label": "two", "rva": 8192},
                    ],
                }
            ),
            encoding="utf-8",
        )
        metadata, targets = load_target_list(path)
        self.assertEqual([target.label for target in targets], ["one", "two"])
        self.assertEqual(targets[0], Target("one", 4096, "probe", "context", 4095))
        self.assertIsNone(targets[1].group)
        self.assertEqual(len(metadata["sha256"]), 64)
        self.assertEqual(load_target_list(path, ["probe"])[1], targets[:1])
        for groups in (["typo"], ["probe", "typo"]):
            with self.subTest(groups=groups), self.assertRaises(ValueError):
                load_target_list(path, groups)

    def test_target_list_rejects_ambiguous_labels_and_invalid_addresses(self):
        path = self.root / "targets.json"
        for entries in (
            [{"label": "a", "rva": 1}, {"label": "a", "rva": 2}],
            [{"label": "a", "rva": True}],
            [{"label": "a", "rva": -1}],
            [{"label": "a", "rva": "bad"}],
            [{"label": "", "rva": 1}],
            [],
        ):
            with self.subTest(entries=entries):
                path.write_text(json.dumps({"targets": entries}), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_target_list(path)

    def test_example_target_list_can_be_captured(self):
        metadata, targets = load_target_list(
            Path(__file__).resolve().parents[1] / "examples" / "targets.json"
        )
        with PeImage(write_pe(self.root / "fixture.exe")) as source:
            capture = capture_targets(source, targets, 0, 1, target_list=metadata)
        self.assertEqual(capture["summary"]["captured_ok"], len(targets))
        self.assertEqual(capture["request"]["target_list"], metadata)

    def test_decode_starts_at_target_not_arbitrary_context(self):
        # A prefix byte consumed the FF opcode in a historical formatting capture.
        blob = bytes.fromhex("01 FF 15 E0 67 ED FF 45 33 C0")
        module = Module("fixture", "fixture", BASE, len(blob), 1)
        result = capture_target(
            Target("call", 1), module, lambda start, size: blob[start : start + size], 1, 8
        )
        self.assertEqual(
            result["read"], {"status": "ok", "start_rva": "0x0", "bytes_hex": blob.hex().upper()}
        )
        instruction = result["decode"]["instructions"][0]
        self.assertEqual((instruction["mnemonic"], instruction["rva"]), ("call", "0x1"))
        self.assertEqual(instruction["bytes_hex"], "FF15E067EDFF")
        self.assertIn("operands", instruction)
        self.assertEqual(result["decode"]["start_rva"], "0x1")
        explicit = capture_target(
            Target("call", 1, decode_rva=0), module, lambda start, size: blob[start : start + size], 1, 8
        )
        self.assertEqual(explicit["decode"]["instructions"][0]["bytes_hex"], "01FF")
        self.assertEqual(explicit["decode"]["start_rva"], "0x0")
        self.assertEqual(explicit["target"]["decode_rva"], "0x0")

    def test_decoder_failure_preserves_successful_bytes(self):
        module = Module("fixture", "fixture", BASE, 3, 1)
        with mock.patch("scripts.capture.decode", side_effect=RuntimeError("decoder failed")):
            result = capture_target(Target("site", 0), module, lambda *_: b"\x90\x90\xc3", 0, 2)
        self.assertEqual(result["read"]["status"], "ok")
        self.assertEqual(result["read"]["bytes_hex"], "9090C3")
        self.assertEqual(result["decode"]["status"], "error")
        self.assertEqual(result["decode"]["error"]["message"], "decoder failed")

    def test_failed_reads_and_decoding_preserve_target_definitions(self):
        module = Module("fixture", "fixture", BASE, 100, 1)
        target = Target("site", 10, "code", "assumed boundary", decode_rva=0)
        result = capture_target(target, module, lambda *_: b"\x90", 1, 2)
        self.assertEqual(result["target"], target.to_dict())
        self.assertEqual(result["read"]["status"], "error")
        self.assertIn("Short read", result["read"]["error"]["message"])
        self.assertNotIn("bytes_hex", result["read"])
        self.assertNotIn("decode", result)
        result = capture_target(target, module, lambda *_: b"\x90" * 4, 1, 2)
        self.assertEqual(result["target"], target.to_dict())
        self.assertEqual(result["read"]["status"], "ok")
        self.assertEqual(result["decode"]["status"], "error")
        self.assertIn("decode_rva", result["decode"]["error"]["message"])

    def test_pe_capture_keeps_partial_failures_and_reports_undecoded_tail(self):
        path = write_pe(self.root / "fixture.exe", b"\xc3\x0f")
        with PeImage(path) as source:
            capture = capture_targets(
                source, [Target("code", 0x1000), Target("outside", 0x2000)], 0, 1, runtime="fixture build"
            )
        self.assertEqual(
            capture["summary"],
            {"target_count": 2, "captured_ok": 1, "captured_error": 1, "decode_error": 0},
        )
        self.assertLessEqual(
            datetime.fromisoformat(capture["started_at"]), datetime.fromisoformat(capture["finished_at"])
        )
        self.assertEqual(capture["request"], {"window": {"before": 0, "after": 1}})
        self.assertEqual(capture["annotations"], {"runtime": "fixture build"})
        self.assertEqual(capture["results"][0]["read"]["bytes_hex"], "C30F")
        self.assertEqual(capture["results"][0]["decode"]["status"], "incomplete")
        self.assertEqual(capture["results"][0]["decode"]["instructions"][0]["bytes_hex"], "C3")
        self.assertEqual(capture["source"]["module"]["pe_timestamp"], "0x65a00001")
        self.assertEqual(capture["source"]["module"]["image_size"], 0x2000)
        self.assertEqual(capture["source"]["kind"], "pe_file")
        self.assertEqual(len(capture["source"]["file_sha256"]), 64)
        self.assertEqual(len(capture["tool"]["source_sha256"]), 64)
        self.assertEqual(capture["decoder"]["version"], version("capstone"))

    def test_pe_reader_rejects_wrong_architecture_and_unbacked_windows(self):
        with self.assertRaisesRegex(ValueError, "AMD64"):
            PeImage(write_pe(self.root / "x86.exe", machine=0x14C))
        with PeImage(write_pe(self.root / "x64.exe")) as source:
            self.assertEqual(source.read(0, 2), b"MZ")
            self.assertEqual(source.read(0x1000, 2), b"\x90\xc3")
            with self.assertRaisesRegex(ValueError, "raw data boundary"):
                source.read(0x11FF, 2)
            with self.assertRaisesRegex(ValueError, "file-backed"):
                source.read(0x400, 4)


@unittest.skipUnless(os.name == "nt", "Windows publication semantics")
class PublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_publish_never_replaces_an_intervening_writer(self):
        path = self.root / "capture.json"
        rename = Path.rename

        def other_writer(temporary, destination):
            destination.write_text("other capture", encoding="utf-8")
            return rename(temporary, destination)

        with mock.patch.object(Path, "rename", other_writer), self.assertRaises(FileExistsError):
            write_capture(path, {"ours": True})
        self.assertEqual(path.read_text(encoding="utf-8"), "other capture")
        self.assertEqual(list(self.root.iterdir()), [path])

    def test_existing_output_requires_explicit_overwrite(self):
        path = self.root / "capture.json"
        write_capture(path, {"capture": 1})
        with self.assertRaises(FileExistsError):
            write_capture(path, {"capture": 2})
        self.assertEqual(json.loads(path.read_text()), {"capture": 1})
        write_capture(path, {"capture": 2}, overwrite=True)
        self.assertEqual(json.loads(path.read_text()), {"capture": 2})
        self.assertEqual(list(self.root.iterdir()), [path])

    def test_write_failure_cleans_temporary_file_and_cleanup_failure_is_reported(self):
        path = self.root / "capture.json"
        with self.assertRaises(TypeError):
            write_capture(path, {"not_json": object()})
        self.assertEqual(list(self.root.iterdir()), [])
        with mock.patch.object(Path, "unlink", side_effect=PermissionError("cleanup denied")):
            with self.assertRaisesRegex(OSError, "also failed to remove temporary file"):
                write_capture(path, {"not_json": object()})
        self.assertFalse(path.exists())
