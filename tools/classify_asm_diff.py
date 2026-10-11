#!/usr/bin/env python3
"""Conservatively classify saved MIPS asm-differ TARGET/CURRENT text tables."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
HEADER = re.compile(r"^TARGET\s+CURRENT \((\d+)\)(?:\s+PREVIOUS \(\d+\))?\s*$")
INSN = re.compile(r"^([0-9a-fA-F]+):\s*(?:~>\s*)?([a-zA-Z][\w.]*)\s*(.*?)\s*$")
REGISTER = re.compile(r"(?<![\w])\$?(?:zero|at|[av][01]|a[23]|t[0-9]|s[0-8]|k[01]|gp|sp|fp|ra|f[0-9]+)(?![\w])")
STACK = re.compile(r"(-?(?:0x[0-9a-f]+|\d+))\(\$?sp\)")
FAILURE = re.compile(r"(?:\berror:|\bfatal error\b|^make(?:\[\d+\])?: \*\*\*|^Traceback \(most recent call last\):|^FAILED:|cfe:\s*(?:Error|Fatal)\b)", re.I)
WARNING = re.compile(r"(?:\bwarning(?:\s+\d+)?:|^cfe: Warning)", re.I)
REFERENCE = re.compile(r"^\.[\w.]+(?:[+-]0x[0-9a-fA-F]+(?:,0x[0-9a-fA-F]+)*)?$")
CATEGORIES = ("stack_frame", "register_only", "scheduling_order", "opcode_control_flow", "other_operands", "insert_delete")


def instruction(cell):
    """Addresses and visual branch arrows are display metadata, not operands."""
    if not cell.strip():
        return None
    match = INSN.fullmatch(cell.strip())
    if not match:
        raise ValueError("unsupported instruction cell")
    opcode = match[2].lower()
    operands = re.sub(r"\s*~>.*$", "", match[3]).strip()
    operands = re.sub(r"\s+", "", operands)
    return (opcode, operands)


def canonical(insn):
    return " ".join(insn)


def is_control(opcode):
    return opcode in {"j", "jal", "jr", "jalr", "break", "syscall", "eret"} or opcode.startswith("b")


def stack_form(insn):
    opcode, operands = insn
    form, count = STACK.subn("<stack>(sp)", operands)
    if opcode in {"addiu", "addi", "daddiu"} and re.fullmatch(r"\$?sp,\$?sp,-?(?:0x[0-9a-f]+|\d+)", operands):
        form, count = "sp,sp,<frame>", 1
    return (opcode, form), count


def classify(text, evidence_limit=5):
    lines = ANSI.sub("", text).splitlines()
    result = {"status": "ok", "current_score": None, "instruction_rows": 0,
              "changed_rows": 0, "counts": dict.fromkeys(CATEGORIES, 0),
              "evidence": {key: [] for key in CATEGORIES}, "diagnostics": [],
              "instruction_multisets_equal": None, "ignored_warning_lines": 0, "reference_rows": 0,
              "caveat": "Textual evidence only; no claim of semantic equivalence, successful compilation, or ROM match."}
    errors = [{"line": i + 1, "text": line} for i, line in enumerate(lines) if FAILURE.search(line)]
    headers = [(i, HEADER.fullmatch(line)) for i, line in enumerate(lines) if HEADER.fullmatch(line)]
    if len(headers) != 1:
        result["status"] = "compile_failure" if errors else "malformed"
        result["diagnostics"] = errors + [{"reason": "Expected exactly one TARGET/CURRENT scored table", "found": len(headers)}]
        return result
    start, header = headers[0]
    result["current_score"] = int(header[1])
    current_at = lines[start].index("CURRENT")
    previous_at = lines[start].find("PREVIOUS")
    body = lines[start + 1:]
    # asm-differ emits a marker, optional five-character source line, then space.
    prefix = 2
    for line in body:
        region = line[max(0, current_at - 7):current_at]
        if len(region) == 7 and (re.fullmatch(r"[ rRis<>|][ 0-9]{5} ", region) and
                                (any(c.isdigit() for c in region) or region[0] != " ")):
            prefix = 7
            break
    boundary = current_at - prefix
    previous_boundary = previous_at - prefix if previous_at >= 0 else None
    rows, malformed = [], []
    partial = False
    warning_tail = False
    for number, line in enumerate(body, start + 2):
        if WARNING.search(line):
            warning_tail = True
            result["ignored_warning_lines"] += 1
            continue
        if warning_tail and (not line.strip() or line[:1].isspace()) and not re.match(r"^\s+[<>]", line):
            result["ignored_warning_lines"] += 1
            continue
        warning_tail = False
        if not line.strip():
            continue
        if line.lstrip().startswith("..."):
            partial = True
            continue
        refs = re.split(r"\s{2,}", line.strip())
        if refs and all(REFERENCE.fullmatch(ref) for ref in refs):
            result["reference_rows"] += 1
            if len(refs) < 2 or refs[0] != refs[1]:
                partial = True
                result["diagnostics"].append({"line": number, "reason": "Unclassified relocation annotation change", "text": line})
            continue
        left = line[:boundary]
        right = line[boundary:previous_boundary]
        try:
            marker = right[:1]
            expected_prefix = r"[ rRis<>|][ 0-9]{5} " if prefix == 7 else r"[ rRis<>|] "
            if right.strip() and not re.fullmatch(expected_prefix, right[:prefix]):
                raise ValueError("unsupported CURRENT prefix or column overflow")
            # Relocation annotations use the same alignment/marker columns as
            # instructions, including an `i` marker for changed section offsets.
            # Match complete cells: a section-like prefix must never hide a bad
            # instruction, extra text, or a mixed annotation/instruction row.
            cells = (left.strip(), right[prefix:].strip())
            if any(cells) and all(not cell or REFERENCE.fullmatch(cell) for cell in cells):
                result["reference_rows"] += 1
                if cells[0] != cells[1]:
                    partial = True
                    result["diagnostics"].append({"line": number, "reason": "Unclassified relocation annotation change", "text": line})
                continue
            a = instruction(left)
            b = instruction(right[prefix:])
            if a is None and b is None:
                # A three-way row may concern PREVIOUS only.
                if previous_boundary is not None:
                    continue
                raise ValueError("empty instruction row")
            rows.append((number, line, a, b, marker))
        except ValueError as exc:
            malformed.append({"line": number, "reason": str(exc), "text": line})
    result["instruction_rows"] = len(rows)
    result["diagnostics"] += errors + malformed[:evidence_limit]
    if errors:
        result["status"] = "compile_failure"
    elif malformed or not rows:
        result["status"] = "malformed"
    elif partial:
        result["status"] = "partial"
        result["diagnostics"].append({"reason": "Incomplete visible table or unclassified relocation annotation; unseen instructions cannot be classified"})

    def add(category, number, line, reason):
        result["counts"][category] += 1
        if len(result["evidence"][category]) < evidence_limit:
            result["evidence"][category].append({"line": number, "reason": reason, "text": line.rstrip()})

    target, current = [], []
    for number, line, a, b, marker in rows:
        if a: target.append(canonical(a))
        if b: current.append(canonical(b))
        if a == b:
            continue
        result["changed_rows"] += 1
        if a is None or b is None:
            add("insert_delete", number, line, "One aligned instruction is absent")
            continue
        if a[0] != b[0] or is_control(a[0]):
            add("opcode_control_flow", number, line, "Opcode or control-transfer operands differ; branch address shifts may be layout-only")
            continue
        sa, has_a = stack_form(a)
        sb, has_b = stack_form(b)
        stack_changed = has_a and has_b and a != b and sa == sb
        # Permit combined stack offset/register changes, but do not call these register-only.
        mixed_stack = has_a and has_b and sa != sb and REGISTER.sub("<reg>", canonical(sa)) == REGISTER.sub("<reg>", canonical(sb))
        if stack_changed or (mixed_stack and STACK.findall(a[1]) != STACK.findall(b[1])):
            add("stack_frame", number, line, "Stack displacement/frame adjustment differs (possibly with register changes)")
        elif REGISTER.sub("<reg>", canonical(a)) == REGISTER.sub("<reg>", canonical(b)):
            add("register_only", number, line, "Same opcode/non-register text; register tokens differ, without a global register mapping proof")
        else:
            add("other_operands", number, line, "Immediate, symbol, relocation, or unsupported operand difference")
    if result["status"] == "ok":
        equal = Counter(target) == Counter(current)
        result["instruction_multisets_equal"] = equal
        if equal and target != current:
            first = next(row for row in rows if row[2] != row[3])
            add("scheduling_order", first[0], first[1], "Visible TARGET/CURRENT instruction multisets are identical but sequences differ; ordering candidate only, not dependency or equivalence proof")
        if result["current_score"] and not result["changed_rows"]:
            result["diagnostics"].append({"reason": "Nonzero score without parsed textual changes; inspect metadata/scorer output manually"})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="+", type=Path)
    parser.add_argument("--format", choices=("json", "text"), default="json")
    parser.add_argument("--evidence-limit", type=int, default=5)
    args = parser.parse_args(argv)
    if args.evidence_limit < 1:
        parser.error("--evidence-limit must be positive")
    results = []
    for path in args.logs:
        try:
            result = classify(path.read_text(), args.evidence_limit)
        except (OSError, UnicodeError) as exc:
            result = {"status": "io_error", "diagnostics": [{"reason": str(exc)}]}
        results.append({"path": str(path), **result})
    if args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            print(f"{result['path']}: {result['status']}, score={result.get('current_score')}")
            for category, count in result.get("counts", {}).items():
                if count:
                    print(f"  {category}: {count}")
                    for item in result["evidence"][category]:
                        print(f"    L{item['line']}: {item['text']}")
            for diagnostic in result.get("diagnostics", []):
                print(f"  diagnostic: {diagnostic}")
            print("  Textual evidence only; not semantic-equivalence or build verification.")
    return 0 if all(r["status"] == "ok" for r in results) else 2


if __name__ == "__main__":
    sys.exit(main())
