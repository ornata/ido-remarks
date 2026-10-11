"""Complete ELF function extraction and conservative MIPS instruction effects."""

from dataclasses import dataclass
import re
import struct
import subprocess
from pathlib import Path
from .common import artifact

REGS = (
    "zero at v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 s0 s1 s2 s3 s4 s5 s6 s7 t8 t9 k0 k1 gp sp s8 ra"
).split()
VOLATILE = set(
    REGS[1:16] + REGS[24:29] + ["ra", "hi", "lo", "fcc0", "fcsr"] + [f"f{i}" for i in range(20)]
)
LOADS = {
    "lb": (1, True),
    "lbu": (1, False),
    "lh": (2, True),
    "lhu": (2, False),
    "lw": (4, True),
    "lwu": (4, False),
    "ld": (8, False),
    "lwc1": (4, False),
    "ldc1": (8, False),
}
STORES = {"sb": 1, "sh": 2, "sw": 4, "sd": 8, "swc1": 4, "sdc1": 8}
BRANCHES = set(
    "beq bne beqz bnez bgez bgtz blez bltz beql bnel beqzl bnezl bgezl bgtzl blezl bltzl bc1t bc1f bc1tl bc1fl".split()
)
BINARY = set(
    "add addu dadd daddu sub subu dsub dsubu and or xor nor slt sltu sllv srlv srav dsllv dsrlv dsrav".split()
)
IMMEDIATE = set(
    "addi addiu daddi daddiu andi ori xori slti sltiu sll srl sra dsll dsrl dsra dsll32 dsrl32 dsra32".split()
)


def reg(value):
    value = value.strip().lstrip("$")
    if value in ("fp", "s8"):
        return "s8"
    return REGS[int(value)] if value.isdecimal() and int(value) < 32 else value


def number(value):
    return int(value, 0) if value.startswith(("0x", "-0x")) else int(value, 10)


@dataclass(frozen=True)
class Instruction:
    address: int
    word: int
    opcode: str
    operands: tuple

    @property
    def key(self):
        return f"{self.address:08x}"

    def record(self):
        return {
            "address": self.key,
            "word": f"{self.word:08x}",
            "opcode": self.opcode,
            "operands": list(self.operands),
        }


def parse_disassembly(text):
    result = []
    for line in text.splitlines():
        match = re.match(
            r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{8})\s+(\S+)(?:\s+(.*))?$", line
        )
        if not match:
            continue
        operands = (match[4] or "").split("#")[0].strip()
        result.append(
            Instruction(
                int(match[1], 16),
                int(match[2], 16),
                match[3],
                tuple(x.strip() for x in operands.split(",") if x.strip()),
            )
        )
    return result


def extract(path, function, *, start=None, size=None):
    path = Path(path)
    raw = path.read_bytes()
    if (
        raw[:6] != b"\x7fELF\x01\x02"
        or len(raw) < 52
        or struct.unpack_from(">H", raw, 18)[0] != 8
    ):
        raise ValueError("Requires ELF32 big-endian MIPS")
    if struct.unpack_from(">H", raw, 16)[0] != 2:
        raise ValueError(
            "Requires linked ET_EXEC; unresolved object addresses are not instruction identities"
        )
    table = subprocess.check_output(
        ["mips-linux-gnu-nm", "-S", "--defined-only", str(path)], text=True
    )
    matches = [
        line.split()
        for line in table.splitlines()
        if line.split() and line.split()[-1] == function
    ]
    if start is None:
        if len(matches) != 1 or len(matches[0]) != 4:
            raise ValueError(
                "Function needs one sized symbol or explicit start and size"
            )
        start, size = int(matches[0][0], 16), int(matches[0][1], 16)
    if size is None or size <= 0 or size % 4 or start % 4:
        raise ValueError("Function span must be nonempty and instruction aligned")
    text = subprocess.check_output(
        [
            "mips-linux-gnu-objdump",
            "-d",
            "-z",
            "-M",
            "no-aliases",
            f"--start-address={start}",
            f"--stop-address={start + size}",
            str(path),
        ],
        text=True,
    )
    instructions = parse_disassembly(text)
    if [i.address for i in instructions] != list(range(start, start + size, 4)):
        raise ValueError("Disassembly does not cover the exact function span")
    relocs = subprocess.check_output(
        ["mips-linux-gnu-readelf", "-r", str(path)], text=True
    )
    undefined = subprocess.check_output(
        ["mips-linux-gnu-nm", "-u", str(path)], text=True
    )
    if undefined.strip():
        raise ValueError("Linked input retains undefined symbols")
    if re.search(r"R_MIPS_", relocs):
        raise ValueError("Linked analysis input must not retain relocations")
    return instructions, {
        "artifact": artifact(path),
        "function": function,
        "start": f"{start:08x}",
        "size": size,
        "objdump_version": subprocess.check_output(
            ["mips-linux-gnu-objdump", "--version"], text=True
        ).splitlines()[0],
    }


def target(i):
    # Decode target from instruction bits, not an objdump symbol annotation.
    if i.opcode in ("j", "jal"):
        return ((i.address + 4) & 0xF0000000) | ((i.word & 0x3FFFFFF) << 2)
    immediate = i.word & 0xFFFF
    return (
        i.address
        + 4
        + ((immediate - 0x10000 if immediate & 0x8000 else immediate) << 2)
    )


def memory(i):
    if i.opcode not in LOADS and i.opcode not in STORES:
        return None
    match = re.fullmatch(r"(-?(?:0x[0-9a-fA-F]+|\d+))\(([^)]+)\)", i.operands[-1])
    if not match:
        raise ValueError("Unrecognized memory operand")
    return (
        reg(match[2]),
        number(match[1]),
        LOADS[i.opcode][0] if i.opcode in LOADS else STORES[i.opcode],
    )


def effects(i, contract=None):
    op, a = i.opcode, [reg(x) for x in i.operands]
    uses, defs, issue = set(), set(), None

    def fp(r, pair=False):
        return {r, f"f{int(r[1:]) + 1}"} if pair else {r}

    if (
        op == "dli"
        and len(a) == 2
        and i.word >> 26 in (0x09, 0x0D, 0x19)
        and (i.word >> 21) & 31 == 0
        and a[0] == REGS[(i.word >> 16) & 31]
    ):
        # GNU objdump can retain this alias even with -M no-aliases.
        # Only accept an encoded ADDIU/ORI/DADDIU from zero, not an
        # arbitrary assembler macro. Each writes one architectural GPR:
        # ORI zero-extends its immediate; ADDIU/DADDIU sign-extend it.
        defs.add(a[0])
    elif op in BINARY:
        defs.add(a[0])
        uses.update(a[1:3])
    elif op in IMMEDIATE:
        defs.add(a[0])
        uses.add(a[1])
    elif op == "lui":
        defs.add(a[0])
    elif op in LOADS or op in STORES:
        uses.add(memory(i)[0])
        registers = fp(a[0], op in ("ldc1", "sdc1"))
        (defs if op in LOADS else uses).update(registers)
    elif op in ("mult", "multu", "div", "divu", "dmult", "dmultu", "ddiv", "ddivu"):
        uses.update(a[-2:])
        defs.update(("hi", "lo"))
    elif op in ("mfhi", "mflo"):
        defs.add(a[0])
        uses.add(op[2:])
    elif op in ("mthi", "mtlo"):
        uses.add(a[0])
        defs.add(op[2:])
    elif op in ("mfc1", "dmfc1"):
        defs.add(a[0])
        uses.update(fp(a[1], op == "dmfc1"))
    elif op in ("mtc1", "dmtc1"):
        uses.add(a[0])
        defs.update(fp(a[1], op == "dmtc1"))
    elif op in ("cfc1", "ctc1") and i.word >> 26 == 17 and (i.word >> 11 & 31) == 31:
        # Model FCSR dependencies, not floating-point exception/rounding semantics.
        # FCC0 aliases FCSR bit 23, so an FCSR write also kills that condition.
        if op == "cfc1" and (i.word >> 21 & 31) == 2:
            uses.update(("fcsr", "fcc0"))
            defs.add(a[0])
        elif op == "ctc1" and (i.word >> 21 & 31) == 6:
            uses.add(a[0])
            defs.update(("fcsr", "fcc0"))
        else:
            issue = "unsupported COP1 control encoding"
    elif op in BRANCHES:
        uses.update(["fcc0"] if op.startswith("bc1") else a[:-1])
    elif op in ("jal", "jalr"):
        defs.add(a[0] if op == "jalr" and len(a) == 2 else "ra")
        if op == "jalr":
            uses.add(a[-1])
    elif op == "jr":
        uses.add(a[0])
        if a[0] == "ra":
            uses.update((contract or {}).get("returns", ["v0", "v1", "f0", "f1"]))
    elif op in ("j", "nop") or (op == "sll" and i.word == 0):
        pass
    elif "." in op and op.split(".")[0] in (
        "add",
        "sub",
        "mul",
        "div",
        "sqrt",
        "abs",
        "mov",
        "neg",
        "cvt",
        "trunc",
        "round",
        "ceil",
        "floor",
        "c",
    ):
        parts = op.split(".")
        uses.add("fcsr")
        defs.add("fcsr")
        if parts[0] == "c":
            defs.add("fcc0")
            for r in a:
                uses.update(fp(r, parts[-1] == "d"))
        else:
            defs.update(fp(a[0], parts[1] in ("d", "l")))
            for r in a[1:]:
                uses.update(fp(r, parts[-1] in ("d", "l")))
    else:
        issue = "unsupported opcode: " + op
        # Conservatively keep all architectural state live across an unknown instruction.
        uses.update(REGS + ["hi", "lo", "fcc0", "fcsr"] + [f"f{x}" for x in range(32)])
    return uses - {"zero"}, defs - {"zero"}, issue
