import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from support import write_pe

from scripts.__main__ import main


@unittest.skipUnless(os.name == "nt", "Windows capture publication")
class CliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.image = write_pe(self.root / "image.exe")

    def run_cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main([str(arg) for arg in args])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_inspect_and_target_list_capture_round_trip_through_comparison(self):
        status, output, errors = self.run_cli(
            "inspect",
            "--file",
            self.image,
            "--rva",
            "0x1000",
            "--before",
            0,
            "--after",
            1,
            "--format",
            "json",
        )
        self.assertEqual((status, errors), (0, ""))
        inspected = json.loads(output)
        self.assertEqual(inspected["results"][0]["read"]["bytes_hex"], "90C3")
        self.assertEqual(inspected["tool"]["name"], "runtime-byte-inspector")
        target_list = self.root / "targets.json"
        target_list.write_text(
            json.dumps(
                {
                    "targets": [
                        {"label": "site", "rva": "0x1000", "group": "code"},
                        {"label": "header", "rva": 0, "group": "headers"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        destination = self.root / "capture.json"
        status, output, errors = self.run_cli(
            "capture",
            "--file",
            self.image,
            "--targets",
            target_list,
            "--group",
            "code",
            "--before",
            0,
            "--after",
            1,
            "--output",
            destination,
        )
        self.assertEqual((status, errors), (0, ""))
        self.assertEqual(output.strip(), str(destination.resolve()))
        captured = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(captured["request"]["target_list"]["path"], str(target_list.resolve()))
        self.assertEqual(len(captured["request"]["target_list"]["sha256"]), 64)
        self.assertEqual(captured["request"]["groups"], ["code"])
        self.assertEqual(captured["summary"]["target_count"], 1)
        left = self.root / "inspected.json"
        left.write_text(json.dumps(inspected), encoding="utf-8")
        status, output, errors = self.run_cli("compare", left, destination)
        self.assertEqual((status, errors), (0, ""))
        self.assertTrue(json.loads(output)["comparisons"][0]["windows_equal"])

    def test_capture_saves_bytes_but_returns_nonzero_when_decoder_fails(self):
        target_list = self.root / "targets.json"
        target_list.write_text(
            json.dumps({"targets": [{"label": "site", "rva": "0x1000"}]}),
            encoding="utf-8",
        )
        destination = self.root / "capture.json"
        with mock.patch("scripts.capture.decode", side_effect=RuntimeError("decoder failed")):
            status, output, errors = self.run_cli(
                "capture",
                "--file",
                self.image,
                "--targets",
                target_list,
                "--before",
                0,
                "--after",
                1,
                "--output",
                destination,
            )
        self.assertEqual(status, 1)
        self.assertIn("decoder failed", errors)
        self.assertEqual(output.strip(), str(destination.resolve()))
        self.assertEqual(json.loads(destination.read_text())["results"][0]["read"]["bytes_hex"], "90C3")

    def test_text_inspection_derives_instruction_markers_and_undecoded_tail(self):
        write_pe(self.image, bytes.fromhex("01 FF 15 E0 67 ED FF 45 33 C0"))
        for decode_args, marker in (((), ">>"), (("--decode-rva", "0x1000"), "*>")):
            with self.subTest(decode_args=decode_args):
                status, output, errors = self.run_cli(
                    "inspect",
                    "--file",
                    self.image,
                    "--rva",
                    "0x1001",
                    "--before",
                    1,
                    "--after",
                    8,
                    *decode_args,
                )
                self.assertEqual((status, errors), (0, ""))
                self.assertTrue(any(line.startswith(marker) for line in output.splitlines()))
        write_pe(self.image, b"\xc3\x0f")
        status, output, errors = self.run_cli(
            "inspect", "--file", self.image, "--rva", "0x1000", "--before", 0, "--after", 1
        )
        self.assertEqual((status, errors), (0, ""))
        self.assertIn("raw context after block from 0x140001001: 0F", output)
        write_pe(self.image, b"\x90\x0f")
        status, output, errors = self.run_cli(
            "inspect", "--file", self.image, "--rva", "0x1000", "--before", 0, "--after", 1
        )
        self.assertEqual((status, errors), (0, ""))
        self.assertIn("undecoded from 0x140001001: 0F", output)

    def test_file_va_and_decoding_origin_remain_preferred_image_relative(self):
        write_pe(self.image, bytes.fromhex("488BC45741544155415641574883EC40C3"))
        status, output, errors = self.run_cli(
            "inspect",
            "--file",
            self.image,
            "--va",
            "0x140001000",
            "--decode-va",
            "0x140001000",
            "--before",
            0,
            "--after",
            16,
            "--span",
            16,
            "--format",
            "json",
        )
        self.assertEqual((status, errors), (0, ""))
        result = json.loads(output)["results"][0]
        self.assertEqual(result["target"]["rva"], "0x1000")
        self.assertEqual(result["span"]["end_status"], "boundary")
        self.assertEqual(result["span"]["relative_instructions"], [])

    def test_invalid_source_options_and_invalid_captures_have_no_stdout(self):
        for args in (
            ("inspect", "--file", self.image, "--module", "other.dll", "--rva", 0),
            ("inspect", "--file", self.image, "--patch-state", "unpatched", "--rva", 0),
            ("inspect", "--file", self.image, "--va", 1),
            ("inspect", "--file", self.image, "--rva", "0x1000", "--pointer"),
            ("inspect", "--file", self.image, "--rva", "0x1000", "--follow", 1),
            ("inspect", "--file", self.image, "--rva", "0x1000", "--span", 0),
            ("inspect", "--file", self.image, "--rva", "0x1000", "--span", 66),
            ("inspect", "--file", self.image, "--rva", "0x1000", "--decode-va", "0x140001000"),
            ("compare", self.image, self.image),
            ("compare", self.root, self.root),
        ):
            with self.subTest(args=args):
                status, output, errors = self.run_cli(*args)
                self.assertEqual((status, output), (1, ""))
                self.assertIn("error:", errors)
