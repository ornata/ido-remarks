"""Small optional observer for Unicorn fixture adapters; no execution policy."""

import json
from .common import ROOT


class ObservationWriter:
    def __init__(self, path):
        path = path.resolve()
        if path == ROOT or ROOT in path.parents:
            raise ValueError("Observations must be outside repository")
        self.file = path.open("x")

    def write(
        self, *, case_id, inputs, artifact_sha256, observations, completed, scope
    ):
        self.file.write(
            json.dumps(
                {
                    "schema": 1,
                    "case_id": str(case_id),
                    "inputs": inputs,
                    "artifact_sha256": artifact_sha256,
                    "observations": observations,
                    "completed": completed,
                    "scope": scope,
                },
                sort_keys=True,
            )
            + "\n"
        )
        self.file.flush()

    def close(self):
        self.file.close()


def capture_instruction(uc, address, word):
    """Record pre-instruction GPR operands and load bytes; no CPU state mutation.

    A signed-load 'result' is derived from observed bytes under the decoded load
    semantics. Execution completion is recorded separately by the fixture.
    """
    from unicorn import mips_const
    from .machine import REGS

    values = {
        name: uc.reg_read(
            getattr(
                mips_const, "UC_MIPS_REG_" + ("FP" if name == "s8" else name.upper())
            )
        )
        for name in REGS
    }
    opcode, rs, rt = word >> 26, (word >> 21) & 31, (word >> 16) & 31
    operands = {REGS[rs]: values[REGS[rs]], REGS[rt]: values[REGS[rt]]}
    if opcode in (32, 33, 35, 36, 37, 39):
        width = {32: 1, 33: 2, 35: 4, 36: 1, 37: 2, 39: 4}[opcode]
        displacement = word & 0xFFFF
        if displacement & 0x8000:
            displacement -= 0x10000
        pointer = (values[REGS[rs]] + displacement) & 0xFFFFFFFF
        value = int.from_bytes(uc.mem_read(pointer & 0x1FFFFFFF, width), "big")
        if opcode in (32, 33, 35) and value & (1 << (width * 8 - 1)):
            value -= 1 << (width * 8)
        operands["result"] = value
    result = {
        "instruction": f"{address:08x}",
        "operands": operands,
        "scope": "executed",
    }
    lhs, rhs = values[REGS[rs]], values[REGS[rt]]
    signed_lhs = (lhs & 0xFFFFFFFF) - (0x100000000 if lhs & 0x80000000 else 0)
    if opcode in (4, 20):
        result["branch_taken"] = lhs == rhs
    elif opcode in (5, 21):
        result["branch_taken"] = lhs != rhs
    elif opcode in (6, 22):
        result["branch_taken"] = signed_lhs <= 0
    elif opcode in (7, 23):
        result["branch_taken"] = signed_lhs > 0
    elif opcode == 1 and rt in (0, 1, 2, 3):
        result["branch_taken"] = signed_lhs < 0 if rt in (0, 2) else signed_lhs >= 0
    if "branch_taken" in result:
        operands["branch_taken"] = int(result["branch_taken"])
    return result
