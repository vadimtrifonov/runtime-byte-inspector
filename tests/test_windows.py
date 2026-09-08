import ctypes
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.capture import capture_targets, write_capture
from scripts.compare import load_capture
from scripts.targets import Target


@unittest.skipUnless(sys.platform == "win32", "Windows process access")
class WindowsTests(unittest.TestCase):
    def test_live_child_capture_preserves_process_identity_and_partial_failure(self):
        from scripts.windows import LiveProcess, find_pid

        child = subprocess.Popen(
            [sys.executable, "-I", "-c", "import sys; print('ready', flush=True); sys.stdin.read()"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(child.stdout.readline().strip(), "ready")
            with LiveProcess(pid=child.pid) as source:
                self.assertEqual(source.pid, child.pid)
                self.assertEqual(source.read(0, 2), b"MZ")
                capture = capture_targets(
                    source,
                    [Target("header", 0), Target("outside", source.module.size)],
                    0,
                    15,
                    patch_state="unpatched",
                    runtime="controlled Python child",
                )
                self.assertEqual(capture["source"]["process"]["pid"], child.pid)
                self.assertIn("started_at", capture["source"]["process"])
                self.assertEqual(
                    capture["annotations"], {"patch_state": "unpatched", "runtime": "controlled Python child"}
                )
                self.assertEqual(capture["source"]["module"]["machine"], "AMD64")
                self.assertEqual(capture["summary"]["captured_error"], 1)
                with self.assertRaises(OSError) as error:
                    source._read_address(0, 4)
                self.assertIn("ReadProcessMemory", str(error.exception))
                self.assertIsNotNone(error.exception.winerror)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "capture.json"
                write_capture(path, capture)
                metadata, records = load_capture(path)
                self.assertEqual(metadata["source"]["process"]["pid"], child.pid)
                self.assertEqual(records[0].raw[:2], b"MZ")
                self.assertIsNone(records[1].raw)
            # Both this test interpreter and its child have the same executable name.
            with self.assertRaisesRegex(ValueError, "select one with --pid"):
                find_pid(Path(sys.executable).name)
            with self.assertRaises(ValueError):
                LiveProcess(pid=0)
            with self.assertRaisesRegex(ValueError, "not loaded"):
                LiveProcess(pid=child.pid, module_name="missing-test-module.dll")
        finally:
            child.terminate()
            child.communicate(timeout=10)

    def test_access_denied_preserves_native_error_and_elevation_hint(self):
        from scripts.windows import check

        ctypes.set_last_error(5)
        with self.assertRaises(OSError) as error:
            check(False, f"OpenProcess(pid={os.getpid()})")
        self.assertEqual(error.exception.winerror, 5)
        self.assertIn(ctypes.FormatError(5).strip(), str(error.exception))
        self.assertIn("elevated terminal", str(error.exception))
