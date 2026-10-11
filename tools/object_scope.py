#!/usr/bin/env python3
"""Report declared MIPS object-function bounds independently of asm-differ scores.

This checks symbol coverage, not semantic equivalence or correctness of inferred
function boundaries. Relocations remain visible in the saved disassembly.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


def function_span(path, function):
    data = Path(path).read_bytes()
    if len(data) < 52 or data[:7] != b"\x7fELF\x01\x02\x01":
        raise ValueError("expected big-endian ELF32")
    h = struct.unpack_from(">16sHHIIIIIHHHHHH", data)
    if h[1:3] != (1, 8):
        raise ValueError("expected relocatable EM_MIPS object")
    offset, stride, count, names_index = h[6], h[11], h[12], h[13]
    if stride != 40 or not count or names_index >= count or offset + count * stride > len(data):
        raise ValueError("invalid section table")
    sections = [struct.unpack_from(">10I", data, offset + i * stride) for i in range(count)]

    def section_bytes(index):
        if not 0 <= index < count:
            raise ValueError("invalid section index")
        s = sections[index]
        if s[4] + s[5] > len(data):
            raise ValueError("section extends past object")
        return data[s[4]:s[4] + s[5]]

    def string(table, index):
        end = table.find(b"\0", index)
        if index >= len(table) or end < 0:
            raise ValueError("invalid string offset")
        return table[index:end].decode("ascii")

    names = section_bytes(names_index)
    found = []
    for i, section in enumerate(sections):
        if section[1] != 2:  # SHT_SYMTAB
            continue
        symbols, strings = section_bytes(i), section_bytes(section[6])
        if section[9] != 16 or len(symbols) % 16:
            raise ValueError("invalid symbol table")
        for pos in range(0, len(symbols), 16):
            name, start, size, info, _, index = struct.unpack_from(">IIIBBH", symbols, pos)
            if string(strings, name) == function and info & 15 == 2:
                found.append((start, size, index))
    if len(found) != 1:
        raise ValueError("expected exactly one named STT_FUNC")
    start, size, index = found[0]
    contents = section_bytes(index)
    if sections[index][1] != 1 or not sections[index][2] & 4:
        raise ValueError("function is not in executable PROGBITS")
    if not size or start % 4 or size % 4 or start + size > len(contents):
        raise ValueError("invalid or unknown function extent")
    return {"function": function, "section": string(names, sections[index][0]),
            "start": start, "size": size, "instructions": size // 4,
            "object_sha256": hashlib.sha256(data).hexdigest(),
            "span_sha256": hashlib.sha256(contents[start:start + size]).hexdigest()}


def inspect(path, function, max_lines, disassembly):
    result = function_span(path, function)
    text = subprocess.check_output([
        "mips-linux-gnu-objdump", "-dr", "-z", "-j", result["section"],
        "--start-address", str(result["start"]),
        "--stop-address", str(result["start"] + result["size"]), str(path)], text=True)
    Path(disassembly).write_text(text)
    addresses = [int(m[1], 16) for m in re.finditer(
        r"^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s", text, re.M | re.I)]
    expected = list(range(result["start"], result["start"] + result["size"], 4))
    if addresses != expected:
        raise ValueError("objdump did not cover complete declared instruction span")
    result.update(disassembly=str(disassembly),
                  disassembly_sha256=hashlib.sha256(text.encode()).hexdigest(),
                  declared_span_disassembled=True,
                  diff_bound_covers_symbol=max_lines >= result["instructions"],
                  limits="Symbol bounds may need provenance review; unrelocated span hashes do not establish equality. asm-differ may also include neighboring functions.")
    return result


def pair(original, candidate, function, max_lines, output):
    result = {"function": function, "max_lines": max_lines}
    for label, path in (("original", original), ("candidate", candidate)):
        try:
            result[label] = inspect(path, function, max_lines, Path(output) / (label + "-function.dis"))
        except (OSError, ValueError, UnicodeError, struct.error, subprocess.SubprocessError) as error:
            result[label] = {"error": str(error)}
    result["status"] = ("unknown" if any("error" in result[s] for s in ("original", "candidate"))
                        else "bound_covers_declared_symbols" if all(result[s]["diff_bound_covers_symbol"] for s in ("original", "candidate"))
                        else "bound_too_small")
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("original", type=Path)
    p.add_argument("candidate", type=Path)
    p.add_argument("function")
    p.add_argument("--max-lines", type=int, default=1024)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    if a.max_lines <= 0:
        p.error("--max-lines must be positive")
    a.output.mkdir(parents=True, exist_ok=False)
    result = pair(a.original, a.candidate, a.function, a.max_lines, a.output)
    (a.output / "scope.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "bound_covers_declared_symbols" else 1


if __name__ == "__main__":
    raise SystemExit(main())
