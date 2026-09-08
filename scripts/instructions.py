from __future__ import annotations

import capstone as cs
from capstone import x86

from .targets import ADDRESS_LIMIT


def instruction_details(instruction) -> dict:
    row = {
        "va": hex(instruction.address),
        "size": instruction.size,
        "bytes_hex": instruction.bytes.hex().upper(),
        "mnemonic": instruction.mnemonic,
        "operands": instruction.op_str,
        "operand_details": [],
        "relative_fields": [],
    }
    next_va = instruction.address + instruction.size
    relative_branch = instruction.group(cs.CS_GRP_BRANCH_RELATIVE)
    kind = "ordinary"
    if instruction.group(cs.CS_GRP_CALL):
        kind = "call"
    elif instruction.group(cs.CS_GRP_JUMP) or relative_branch:
        kind = "jump" if instruction.id in (x86.X86_INS_JMP, x86.X86_INS_LJMP) else "conditional_branch"
    elif instruction.group(cs.CS_GRP_RET) or instruction.group(cs.CS_GRP_IRET):
        kind = "return"
    elif instruction.mnemonic in ("int", "int1", "int3", "into", "ud2", "hlt", "sysret", "sysretq"):
        kind = "trap"
    flow = {"kind": kind}
    if kind in ("ordinary", "call", "conditional_branch"):
        flow["fallthrough_va"] = hex(next_va)
    for operand in instruction.operands:
        detail = {
            "size": operand.size,
            "access": [
                name
                for flag, name in ((cs.CS_AC_READ, "read"), (cs.CS_AC_WRITE, "write"))
                if operand.access & flag
            ],
        }
        if operand.type == x86.X86_OP_REG:
            detail.update(kind="register", register=instruction.reg_name(operand.reg))
        elif operand.type == x86.X86_OP_IMM:
            detail.update(kind="immediate", value=operand.imm)
        elif operand.type == x86.X86_OP_MEM:
            memory = operand.mem
            detail.update(
                kind="memory",
                base=instruction.reg_name(memory.base) or None,
                index=instruction.reg_name(memory.index) or None,
                scale=memory.scale,
                displacement=memory.disp,
                segment=instruction.reg_name(memory.segment) or None,
            )
            if memory.base in (x86.X86_REG_RIP, x86.X86_REG_EIP):
                row["relative_fields"].append(
                    {
                        "kind": "rip_relative_memory"
                        if memory.base == x86.X86_REG_RIP
                        else "eip_relative_memory",
                        "offset": instruction.disp_offset,
                        "size": instruction.disp_size,
                    }
                )
            # Only FS/GS contribute a segment base in 64-bit mode.
            if memory.segment not in (x86.X86_REG_FS, x86.X86_REG_GS) and not memory.index:
                if memory.base == x86.X86_REG_RIP:
                    detail["address_va"] = hex((next_va + memory.disp) % ADDRESS_LIMIT)
                elif memory.base == x86.X86_REG_EIP:
                    detail["address_va"] = hex((next_va + memory.disp) % (1 << 32))
                elif not memory.base:
                    detail["address_va"] = hex(memory.disp % (1 << (instruction.addr_size * 8)))
        else:
            detail["kind"] = "unsupported"
        row["operand_details"].append(detail)
    if relative_branch:
        row["relative_fields"].append(
            {
                "kind": "pc_relative_branch",
                "offset": instruction.imm_offset,
                "size": instruction.imm_size,
            }
        )
    if kind in ("call", "jump", "conditional_branch"):
        operands = row["operand_details"]
        operand = operands[0] if len(operands) == 1 else {}
        if operand.get("kind") == "immediate":
            flow.update(resolution="direct", target_va=hex(operand["value"] % ADDRESS_LIMIT))
        elif operand.get("kind") == "memory" and operand["size"] == 8 and "address_va" in operand:
            flow.update(resolution="pointer", pointer_va=operand["address_va"])
        else:
            flow.update(resolution="unresolved", reason="requires_execution_state")
    row["flow"] = flow
    return row


def decode(blob: bytes, va: int, module_base: int | None = None) -> dict:
    """Decode one straight-line block. Bytes after a control-flow boundary remain raw context."""
    decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    decoder.detail = True
    instructions = []
    consumed = 0
    reason = "window_end"
    for instruction in decoder.disasm(blob, va):
        row = instruction_details(instruction)
        if module_base is not None:
            row["rva"] = hex(instruction.address - module_base)
        instructions.append(row)
        consumed += instruction.size
        if row["flow"]["kind"] in ("jump", "conditional_branch", "return", "trap"):
            reason = row["flow"]["kind"]
            break
    else:
        if consumed != len(blob):
            reason = "invalid_or_truncated"
    result = {
        "status": "incomplete"
        if reason == "invalid_or_truncated"
        else ("complete" if consumed == len(blob) else "stopped"),
        "start_va": hex(va),
        "decoded_bytes": consumed,
        "stop_reason": reason,
        "instructions": instructions,
    }
    if module_base is not None:
        result["start_rva"] = hex(va - module_base)
    return result


def boundary_at(decoded: dict, va: int) -> str:
    for instruction in decoded["instructions"]:
        start = int(instruction["va"], 0)
        if va == start or va == start + instruction["size"]:
            return "boundary"
        if start < va < start + instruction["size"]:
            return "splits_instruction"
    return "not_decoded"


def span_facts(decoded: dict, va: int, size: int) -> dict:
    end = va + size
    instructions = [
        instruction
        for instruction in decoded["instructions"]
        if int(instruction["va"], 0) < end and int(instruction["va"], 0) + instruction["size"] > va
    ]
    return {
        "start_va": hex(va),
        "size": size,
        "end_va": hex(end),
        "start_status": boundary_at(decoded, va),
        "end_status": boundary_at(decoded, end),
        "relative_instructions": [
            {"va": instruction["va"], "fields": instruction["relative_fields"]}
            for instruction in instructions
            if instruction["relative_fields"]
        ],
        "meaning": "Encoding facts from the selected decoding origin, not a relocation or patch-safety verdict",
    }
