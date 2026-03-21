from __future__ import annotations

import importlib.util
import io
import sys
import unittest
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "capture_manifest.py"
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("capture_manifest", MODULE_PATH)
assert SPEC is not None
assert SPEC.loader is not None
capture_manifest = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = capture_manifest
SPEC.loader.exec_module(capture_manifest)


class FakeParser:
    def __init__(self, args: Namespace):
        self._args = args

    def parse_args(self) -> Namespace:
        return self._args


class CaptureManifestTests(unittest.TestCase):
    def test_late_failure_does_not_leave_readable_evidence_fields_on_error_result(self) -> None:
        args = Namespace(
            manifest="manifests\\seeded_candidates.json",
            process="SkyrimVR.exe",
            module="SkyrimVR.exe",
            pid=None,
            group=None,
            process_state="unknown",
            before=32,
            after=64,
            output_path="bundle.json",
            overwrite=False,
        )
        candidate = capture_manifest.Candidate(
            label="current_1D7B6B",
            rva=0x1D7B6B,
            group="current_validated",
            notes=None,
        )
        process = SimpleNamespace(pid=12345, exe_name="SkyrimVR.exe")
        module = SimpleNamespace(name="SkyrimVR.exe", path="C:\\Games\\Skyrim\\SkyrimVR.exe", base_address=0x140000000, size=0x4000000)
        window = SimpleNamespace(
            target_va=0x141D7B6B,
            start_rva=0x1D7B6A,
            start_va=0x141D7B6A,
            end_rva_exclusive=0x1D7B6D,
            end_va_exclusive=0x141D7B6D,
            requested_before=1,
            requested_after=1,
            actual_before=1,
            actual_after=1,
            size=3,
        )
        captured: dict[str, object] = {}

        def record_bundle(path: Path, payload: dict[str, object], overwrite: bool) -> None:
            captured["path"] = path
            captured["payload"] = payload
            captured["overwrite"] = overwrite

        with mock.patch.object(capture_manifest, "build_parser", return_value=FakeParser(args)):
            with mock.patch.object(capture_manifest, "load_manifest", return_value=({"version": 1}, [candidate])):
                with mock.patch.object(capture_manifest, "filter_candidates", return_value=[candidate]):
                    with mock.patch.object(capture_manifest, "validate_window_request"):
                        with mock.patch.object(capture_manifest, "require_capstone"):
                            with mock.patch.object(
                                capture_manifest,
                                "resolve_process_and_module",
                                return_value=(process, module),
                            ):
                                with mock.patch.object(capture_manifest, "build_output_path", return_value=Path("bundle.json")):
                                    with mock.patch.object(capture_manifest, "open_process_for_reading", return_value=object()):
                                        with mock.patch.object(capture_manifest, "close_handle"):
                                            with mock.patch.object(capture_manifest, "build_capture_window", return_value=window):
                                                with mock.patch.object(
                                                    capture_manifest,
                                                    "read_process_bytes_from_handle",
                                                    return_value=b"\x90\x90\x90",
                                                ):
                                                    with mock.patch.object(
                                                        capture_manifest,
                                                        "disassemble_window",
                                                        side_effect=RuntimeError("late failure"),
                                                    ):
                                                        with mock.patch.object(
                                                            capture_manifest,
                                                            "write_json_atomic",
                                                            side_effect=record_bundle,
                                                        ):
                                                            with redirect_stdout(io.StringIO()):
                                                                with redirect_stderr(io.StringIO()):
                                                                    exit_code = capture_manifest.main()

        self.assertEqual(exit_code, 1)
        bundle = captured["payload"]
        results = bundle["results"]
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error_kind"], "internal")
        self.assertNotIn("raw_bytes_hex", result)
        self.assertNotIn("raw_bytes_len", result)
        self.assertNotIn("disassembly", result)


if __name__ == "__main__":
    unittest.main()
