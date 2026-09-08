import struct
import unittest

from scripts.instructions import decode, span_facts


class InstructionTests(unittest.TestCase):
    def test_absolute_jump_stops_before_its_embedded_pointer(self):
        blob = bytes.fromhex("FF2500000000") + struct.pack("<Q", 0x7FFF12345678) + b"\x90\x90"
        decoded = decode(blob, 0x1000)
        self.assertEqual(decoded["status"], "stopped")
        self.assertEqual(decoded["stop_reason"], "jump")
        self.assertEqual(decoded["decoded_bytes"], 6)
        self.assertEqual(len(decoded["instructions"]), 1)
        flow = decoded["instructions"][0]["flow"]
        self.assertEqual(flow["pointer_va"], "0x1006")
        self.assertNotIn("target_va", flow)
        self.assertNotIn("fallthrough_va", flow)
        self.assertEqual(span_facts(decoded, 0x1000, 16)["end_status"], "not_decoded")

    def test_calls_have_fallthrough_but_register_based_targets_are_unresolved(self):
        decoded = decode(bytes.fromhex("488B01FF9090010000FFD0C3"), 0x1000)
        first, second = decoded["instructions"][1:3]
        for instruction in (first, second):
            self.assertEqual(instruction["flow"]["resolution"], "unresolved")
            self.assertNotIn("target_va", instruction["flow"])
        self.assertEqual(first["flow"]["fallthrough_va"], "0x1009")
        self.assertEqual(first["operand_details"][0]["base"], "rax")
        self.assertEqual(first["operand_details"][0]["displacement"], 0x190)
        self.assertEqual(second["operand_details"][0]["register"], "rax")
        self.assertEqual(decoded["stop_reason"], "return")

    def test_direct_transfers_and_loop_instructions_have_structured_relative_fields(self):
        for blob, kind in (
            ("E9FBFFFFFF", "jump"),
            ("75FE", "conditional_branch"),
            ("E2FE", "conditional_branch"),
        ):
            with self.subTest(blob=blob):
                decoded = decode(bytes.fromhex(blob), 0x1000)
                instruction = decoded["instructions"][0]
                self.assertEqual(instruction["flow"]["kind"], kind)
                self.assertEqual(instruction["flow"]["target_va"], "0x1000")
                self.assertEqual(instruction["relative_fields"][0]["kind"], "pc_relative_branch")
                self.assertEqual(instruction["relative_fields"][0]["offset"], 1)
        call = decode(bytes.fromhex("E80000000090C3"), 0x1000)
        self.assertEqual(call["instructions"][0]["flow"]["target_va"], "0x1005")
        self.assertEqual(len(call["instructions"]), 3)

    def test_lea_computes_an_address_not_a_pointer_value(self):
        decoded = decode(bytes.fromhex("488D05F7503E019090"), 0x1D7B84)
        instruction = decoded["instructions"][0]
        self.assertEqual(instruction["operand_details"][1]["address_va"], "0x15bcc82")
        self.assertEqual(instruction["flow"]["kind"], "ordinary")
        self.assertNotIn("pointer_va", instruction["flow"])
        self.assertEqual(
            instruction["relative_fields"][0], {"kind": "rip_relative_memory", "offset": 3, "size": 4}
        )
        self.assertEqual(span_facts(decoded, 0x1D7B87, 4)["start_status"], "splits_instruction")

    def test_address_size_override_keeps_eip_relative_addressing_facts(self):
        instruction = decode(bytes.fromhex("67488D0510000000"), 0x140001000)["instructions"][0]
        self.assertEqual(instruction["operand_details"][1]["address_va"], "0x40001018")
        self.assertEqual(instruction["relative_fields"][0]["kind"], "eip_relative_memory")

    def test_absolute_displacement_respects_address_size(self):
        for blob, address in (
            ("67FF242500000080", "0x80000000"),
            ("FF242500000080", "0xffffffff80000000"),
        ):
            with self.subTest(blob=blob):
                instruction = decode(bytes.fromhex(blob), 0x140001000)["instructions"][0]
                self.assertEqual(instruction["operand_details"][0]["address_va"], address)
                self.assertEqual(instruction["flow"]["pointer_va"], address)

    def test_ignored_segment_prefixes_preserve_rip_relative_jump_resolution(self):
        for prefix, segment in (("26", "es"), ("2E", "cs"), ("36", "ss"), ("3E", "ds")):
            with self.subTest(segment=segment):
                instruction = decode(bytes.fromhex(prefix + "FF2500000000"), 0x1000)["instructions"][0]
                self.assertEqual(instruction["operand_details"][0]["segment"], segment)
                self.assertEqual(instruction["flow"]["kind"], "jump")
                self.assertEqual(instruction["flow"]["resolution"], "pointer")
                self.assertEqual(instruction["flow"]["pointer_va"], "0x1007")
                self.assertNotIn("fallthrough_va", instruction["flow"])

    def test_segment_based_pointer_cannot_be_resolved_from_rip_alone(self):
        for prefix, segment in (("64", "fs"), ("65", "gs")):
            with self.subTest(segment=segment):
                instruction = decode(bytes.fromhex(prefix + "FF2500000000"), 0x1000)["instructions"][0]
                self.assertEqual(instruction["operand_details"][0]["segment"], segment)
                self.assertNotIn("address_va", instruction["operand_details"][0])
                self.assertEqual(instruction["flow"]["resolution"], "unresolved")
                self.assertTrue(instruction["relative_fields"])

    def test_far_jump_is_unconditional_and_unresolved(self):
        decoded = decode(bytes.fromhex("48FF2D00000000") + b"\0" * 10, 0x1000)
        self.assertEqual(decoded["stop_reason"], "jump")
        self.assertEqual(decoded["decoded_bytes"], 7)
        self.assertEqual(len(decoded["instructions"]), 1)
        flow = decoded["instructions"][0]["flow"]
        self.assertEqual(flow["kind"], "jump")
        self.assertEqual(flow["resolution"], "unresolved")
        self.assertNotIn("fallthrough_va", flow)
        self.assertNotIn("pointer_va", flow)
        self.assertNotIn("target_va", flow)

    def test_span_boundary_split_and_unknown_are_distinct(self):
        decoded = decode(bytes.fromhex("488BC45741544155415641574883EC40C3"), 0x1000)
        whole = span_facts(decoded, 0x1000, 16)
        self.assertEqual(whole["end_status"], "boundary")
        self.assertEqual(whole["relative_instructions"], [])
        self.assertEqual(span_facts(decoded, 0x1000, 15)["end_status"], "splits_instruction")
        self.assertEqual(span_facts(decoded, 0x1000, 18)["end_status"], "not_decoded")
        truncated = decode(bytes.fromhex("4883EC"), 0x1000)
        self.assertEqual(truncated["status"], "incomplete")
        self.assertEqual(span_facts(truncated, 0x1000, 3)["end_status"], "not_decoded")
        getter = decode(bytes.fromhex("488D05B9F14801C3"), 0x107430)
        summary = span_facts(getter, 0x107430, 5)
        self.assertEqual(summary["end_status"], "splits_instruction")
        self.assertEqual(len(summary["relative_instructions"]), 1)
        self.assertNotIn("safe", summary)
