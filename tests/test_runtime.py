import ctypes
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from scripts.__main__ import main
from scripts.capture import capture_targets, iter_errors, write_capture
from scripts.compare import compare_captures
from scripts.targets import Target


@unittest.skipUnless(sys.platform == "win32", "Windows runtime memory")
class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.child = subprocess.Popen(
            [sys.executable, "-I", str(Path(__file__).with_name("memory_child.py"))],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        cls.addClassCleanup(cls.stop_child)
        cls.info = json.loads(cls.child.stdout.readline())
        cls.base = cls.info["base"]

    @classmethod
    def stop_child(cls):
        try:
            _, errors = cls.child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            cls.child.kill()
            cls.child.communicate(timeout=5)
            raise
        if cls.child.returncode:
            raise AssertionError(errors)

    def source(self):
        from scripts.windows import LiveProcess

        # A Windows venv launcher can have a different PID from the interpreter holding the allocation.
        return LiveProcess(pid=self.info["pid"])

    def test_private_jump_chain_records_every_code_and_pointer_read(self):
        with self.source() as source:
            result = capture_targets(source, [Target("entry", va=self.base + 0x100)], 0, 31, follow=3)
            block = result["results"][0]
            self.assertEqual(block["location"]["region"]["kind"], "private")
            self.assertIsNone(block["location"]["module"])
            self.assertNotIn("rva", block["decode"]["instructions"][0])
            self.assertEqual(block["follow"]["stop_reason"], "return")
            hops = block["follow"]["hops"]
            self.assertEqual(
                [int(h["target"]["va"], 0) for h in hops], [self.base + 0x200, self.base + 0x300]
            )
            flow = hops[0]["decode"]["instructions"][0]["flow"]
            self.assertEqual(len(hops[0]["decode"]["instructions"]), 1)
            self.assertEqual(flow["pointer_va"], hex(self.base + 0x206))
            pointer = flow["pointer"]["read"]
            self.assertEqual(int.from_bytes(bytes.fromhex(pointer["bytes_hex"]), "little"), self.base + 0x300)
            for read in (block["read"], pointer, *(h["read"] for h in hops)):
                self.assertLessEqual(read["started_at"], read["finished_at"])
                self.assertEqual(read["requested_bytes"], len(bytes.fromhex(read["bytes_hex"])))
            self.assertEqual(result["summary"]["error_count"], 0)
            self.assertFalse(result["atomic"])
            # Neither a debugger attachment nor remote writes are needed.
            from scripts.windows import kernel32

            attached = ctypes.c_int()
            kernel32.CheckRemoteDebuggerPresent.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
            kernel32.CheckRemoteDebuggerPresent.restype = ctypes.c_int
            self.assertTrue(kernel32.CheckRemoteDebuggerPresent(source.handle, ctypes.byref(attached)))
            self.assertFalse(attached.value)
            other = next(m for m in source._modules if m["name"].casefold() == "kernel32.dll")
            self.assertEqual(source.read_va(other["base"], 2), b"MZ")
            location = source.describe(other["base"])
            self.assertEqual(location["module"]["name"].casefold(), "kernel32.dll")
            self.assertEqual(location["rva"], "0x0")

    def test_follow_limits_cycles_dynamic_targets_calls_and_data_destinations(self):
        with self.source() as source:
            cases = (
                (0x100, 0, None, 0),
                (0x100, 1, "hop_limit", 1),
                (0x400, 8, "cycle", 0),
                (0x500, 8, "return", 0),
                (0xB00, 8, "return", 0),
                (0x3108, 2, "not_executable", 0),
                (0xD00, 8, "unresolved", 0),
                (0xE00, 8, "conditional_branch", 0),
                (0xF00, 3, "return", 1),
                (0x1000, 3, "unresolved", 0),
            )
            for offset, limit, reason, count in cases:
                with self.subTest(offset=offset, limit=limit):
                    target = Target(
                        "case", va=self.base + offset, kind="pointer" if offset == 0x3108 else "code"
                    )
                    result = capture_targets(source, [target], 0, 31, follow=limit)["results"][0]
                    if limit == 0:
                        self.assertNotIn("follow", result)
                    else:
                        self.assertEqual(result["follow"]["stop_reason"], reason)
                        self.assertEqual(len(result["follow"]["hops"]), count)
            for limit in (-1, 9):
                with self.assertRaises(ValueError):
                    capture_targets(source, [Target("case", va=self.base + 0x100)], 0, 31, follow=limit)

    def test_failed_reads_keep_no_bytes_and_do_not_consume_guard_pages(self):
        with self.source() as source:
            for va in (1, self.base + 0x2000, self.base + 0x1FF8, self.base + 0x4000):
                with self.subTest(va=hex(va)):
                    result = capture_targets(source, [Target("bad", va=va)], 0, 15)
                    read = result["results"][0]["read"]
                    self.assertEqual(read["status"], "error")
                    self.assertNotIn("bytes_hex", read)
                    self.assertGreater(result["summary"]["error_count"], 0)
            self.assertTrue(source.query(self.base + 0x4000).Protect & 0x100)

            # An API reporting success with a short byte count must also fail closed.
            def short_read(handle, va, buffer, size, count):
                ctypes.memmove(buffer, b"\xff", 1)
                count._obj.value = 1
                return True

            with mock.patch("scripts.windows.kernel32.ReadProcessMemory", side_effect=short_read):
                result = capture_targets(source, [Target("short", va=self.base + 0x100)], 0, 15)
            self.assertNotIn("bytes_hex", result["results"][0]["read"])
            self.assertIn("Short memory read", result["results"][0]["read"]["error"]["message"])

    def test_related_read_failure_preserves_primary_code_and_reports_nonzero(self):
        for offset, expected in (
            (0x700, "pointer_read_error"),
            (0x800, "destination_error"),
            (0xC00, "read_error"),
        ):
            with self.subTest(offset=offset), self.source() as source:
                capture = capture_targets(source, [Target("entry", va=self.base + offset)], 0, 31, follow=3)
                result = capture["results"][0]
                self.assertEqual(result["read"]["status"], "ok")
                self.assertIn("bytes_hex", result["read"])
                self.assertEqual(result["follow"]["stop_reason"], expected)
                self.assertTrue(list(iter_errors(result)))
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(
                [
                    "inspect",
                    "--pid",
                    str(self.info["pid"]),
                    "--va",
                    hex(self.base + 0x700),
                    "--before",
                    "0",
                    "--after",
                    "31",
                    "--follow",
                    "3",
                    "--format",
                    "json",
                ]
            )
        self.assertEqual(status, 1)
        self.assertIn("pointer.read", stderr.getvalue())
        self.assertIn("bytes_hex", json.loads(stdout.getvalue())["results"][0]["read"])

    def test_explicit_pointer_and_span_capture_survive_serialization(self):
        with self.source() as source:
            capture = capture_targets(
                source,
                [
                    Target("slot", va=self.base + 0x3100, kind="pointer"),
                    Target("prologue", va=self.base + 0xA00, span=16),
                    Target("old-call", va=self.base + 0x903, decode_va=self.base + 0x900, span=4),
                    Target("lea", va=self.base + 0x600),
                ],
                3,
                31,
                follow=3,
            )
        slot, prologue, old_call, lea = capture["results"]
        self.assertNotIn("decode", slot)
        self.assertEqual(len(bytes.fromhex(slot["read"]["bytes_hex"])), 8)
        self.assertEqual(len(slot["follow"]["hops"]), 3)
        self.assertEqual(prologue["span"]["end_status"], "boundary")
        self.assertEqual(prologue["span"]["relative_instructions"], [])
        self.assertEqual(old_call["decode"]["target_position"], "inside_instruction")
        self.assertEqual(old_call["follow"]["stop_reason"], "target_not_instruction_start")
        self.assertEqual(
            lea["decode"]["instructions"][0]["operand_details"][1]["address_va"], hex(self.base + 0x3110)
        )
        self.assertNotIn("pointer", lea["decode"]["instructions"][0]["flow"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.json"
            write_capture(path, capture)
            self.assertEqual(json.loads(path.read_text()), capture)
            with self.assertRaisesRegex(ValueError, "alignment target"):
                compare_captures(path, path)
            report = compare_captures(path, path, alignment="target")
            self.assertEqual(len(report["comparisons"]), 4)
            self.assertTrue(all(pair["windows_equal"] for pair in report["comparisons"]))
