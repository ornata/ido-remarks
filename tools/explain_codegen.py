#!/usr/bin/env python3
"""Compare complete function code against transparent, saved IDO diagnostics.

Reference objects must come from independently reviewed ROM/expected evidence.
This report localizes differences; it never accepts a C match.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import subprocess

from dataflow.common import digest
from dataflow.ido import correlate
from object_scope import inspect
from paired_near_match import instruction_rows, compare_rows
from explain_allocation_decisions import explain as explain_allocation

MEMORY_OPS = {
    32: ("lb", "load", 1), 33: ("lh", "load", 2),
    34: ("lwl", "load", None), 35: ("lw", "load", 4),
    36: ("lbu", "load", 1), 37: ("lhu", "load", 2),
    38: ("lwr", "load", None), 49: ("lwc1", "load", 4),
    53: ("ldc1", "load", 8), 55: ("ld", "load", 8),
    40: ("sb", "store", 1), 41: ("sh", "store", 2),
    42: ("swl", "store", None), 43: ("sw", "store", 4),
    46: ("swr", "store", None), 57: ("swc1", "store", 4),
    61: ("sdc1", "store", 8), 63: ("sd", "store", 8),
}
REGISTERS = ("zero at v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 "
             "s0 s1 s2 s3 s4 s5 s6 s7 t8 t9 k0 k1 gp sp fp ra").split()


def row_key(row):
    return row["word"], tuple(tuple(r) for r in row["relocations"])


def signed16(word):
    val = word & 0xffff
    return val - 0x10000 if val & 0x8000 else val


def machine_facts(rows):
    memory, calls, empty, frames = [], [], [], []
    for i, row in enumerate(rows):
        word = int(row["word"], 16)
        op, base, reg = word >> 26, word >> 21 & 31, word >> 16 & 31
        evidence = {"offset": row["offset"], "assembly": row["assembly"],
                    "word": row["word"], "relocations": row["relocations"]}
        if op in MEMORY_OPS:
            mnemonic, kind, width = MEMORY_OPS[op]
            memory.append(dict(evidence, opcode=mnemonic, kind=kind, width=width,
                               base=REGISTERS[base], displacement=signed16(word),
                               value_register=("f" + str(reg) if op in (49, 53, 57, 61)
                                               else REGISTERS[reg])))
        # Ordinary conditional branch to its own post-delay fallthrough, with nop.
        # Branch-likely is excluded because it annuls the untaken delay slot.
        if op in (4, 5, 6, 7) and signed16(word) == 1 and i + 1 < len(rows) and rows[i+1]["word"] == "00000000":
            empty.append(dict(evidence, delay_slot_offset=rows[i+1]["offset"],
                              target_offset=row["offset"] + 8))
        if op == 3 or (op == 0 and word & 63 == 9 and word >> 11 & 31):
            symbols = [r[1] for r in row["relocations"] if r[0] == "R_MIPS_26"]
            calls.append(dict(evidence, symbol=symbols[0] if len(symbols) == 1 else None,
                              kind="jal" if op == 3 else "jalr"))
        if op in (9, 25) and base == reg == 29:
            frames.append(dict(evidence, sp_delta=signed16(word)))
    return {"memory": memory, "calls": calls, "empty_branches": empty,
            "sp_adjustments": frames}


def memory_order(left, right):
    """Storage operands only: base-register equality does not prove value identity."""
    groups = defaultdict(lambda: {"reference": [], "candidate": []})
    for side, facts in (("reference", left), ("candidate", right)):
        for row in facts["memory"]:
            groups[(row["base"], row["kind"])][side].append(row)
    result = []
    def key(row):
        return row["opcode"], row["displacement"], tuple(tuple(r) for r in row["relocations"])
    for (base, kind), sides in sorted(groups.items()):
        a, b = [key(r) for r in sides["reference"]], [key(r) for r in sides["candidate"]]
        if a != b:
            result.append(dict(sides, base=base, kind=kind,
                               same_operand_multiset=Counter(a) == Counter(b)))
    return result


def retained_memory_order(retained, final):
    """Unique anchors with verified single-word encodings, not macro expansion guesses."""
    encodings = {spec[0]: op for op, spec in MEMORY_OPS.items()}
    encodings.update({"l.s": 49, "s.s": 57, "l.d": 53, "s.d": 61})
    anchors = []
    def register(token, floating=False):
        if floating:
            match = re.fullmatch(r"\$f(\d+)", token)
            return int(match[1]) if match and int(match[1]) < 32 else None
        token = token.removeprefix("$")
        return int(token) if token.isdecimal() and int(token) < 32 else (
            REGISTERS.index(token) if token in REGISTERS else None)
    for row in retained:
        match = re.fullmatch(r"\s*(\S+)\s+(\$\w+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))\((\$\w+)\)\s*", row["text"])
        if not match or match[1] not in encodings:
            continue
        op = encodings[match[1]]
        reg = register(match[2], op in (49, 53, 57, 61))
        base = register(match[4])
        disp = int(match[3], 16 if "0x" in match[3] else 10)
        if reg is None or base is None or not -32768 <= disp <= 32767:
            continue
        word = f"{(op << 26 | base << 21 | reg << 16 | disp & 0xffff):08x}"
        anchors.append(dict(row, word=word))
    counts = Counter(r["word"] for r in anchors)
    final_counts = Counter(r["word"] for r in final if not r["relocations"])
    selected = {word for word, count in counts.items() if count == final_counts[word] == 1}
    before = [r for r in anchors if r["word"] in selected]
    after = [r for r in final if r["word"] in selected and not r["relocations"]]
    return {"unique_anchor_count": len(selected), "retained": before, "final": after,
            "order_changed": [r["word"] for r in before] != [r["word"] for r in after],
            "limit": "Only numeric-displacement memory instructions whose single-word encoding occurs exactly once in each stage; symbolic, expanded, ambiguous and relocated instructions are excluded. Order is observed; scheduler reasons and alias independence are not inferred."}


def phase_leads(phase, comparison):
    """Bound the investigation using observed retained instructions and anchors."""
    retained = phase["retained"]
    phase["comparison_forms"] = [r for r in retained
                                 if re.match(r"\s*(?:sne|seq|sltu)\s", r["text"])]
    phase["extra_call_sites"] = {symbol: [r for r in retained
        if re.fullmatch(r"\s*jal\s+" + re.escape(symbol) + r"\s*", r["text"])]
        for symbol in comparison["extra_direct_calls"]}
    anchors = phase["memory_order"]
    for group in comparison["memory_operand_changes"]:
        # Limit to the already verified unique anchors for this base/kind group.
        words = {r["word"] for r in group["candidate"] if not r["relocations"]}
        before = [r for r in anchors["retained"] if r["word"] in words]
        after = [r for r in anchors["final"] if r["word"] in words]
        group["retained_unique_anchors"] = before
        group["retained_to_final_order_changed"] = [r["word"] for r in before] != [r["word"] for r in after]
        group["candidate_access_group_fully_anchored"] = len(before) == len(group["candidate"]) == len(after)


def compare_functions(reference, candidate):
    left, right = [row_key(r) for r in reference], [row_key(r) for r in candidate]
    prefix = 0
    while prefix < min(len(left), len(right)) and left[prefix] == right[prefix]:
        prefix += 1
    suffix = 0
    while suffix < min(len(left), len(right)) - prefix and left[-1-suffix] == right[-1-suffix]:
        suffix += 1
    changes = compare_rows(reference, candidate)
    for change in changes:
        change["same_word_relocation_multiset"] = (
            Counter(row_key(r) for r in change["left"]) == Counter(row_key(r) for r in change["right"]))
    original, current = machine_facts(reference), machine_facts(candidate)
    def call_counts(facts):
        return Counter(r["symbol"] for r in facts["calls"] if r["symbol"] is not None)
    a, b = call_counts(original), call_counts(current)
    stack_loads = defaultdict(lambda: {"reference": [], "candidate": []})
    for side, facts in (("reference", original), ("candidate", current)):
        for r in facts["memory"]:
            if r["base"] == "sp" and r["kind"] == "load":
                stack_loads[(r["opcode"], r["displacement"], r["value_register"])][side].append(r["offset"])
    home_changes = [dict(sides, opcode=key[0], displacement=key[1], value_register=key[2])
                    for key, sides in sorted(stack_loads.items())
                    if len(sides["reference"]) != len(sides["candidate"])]
    return {"reference_words": len(left), "candidate_words": len(right),
            "word_delta": len(right) - len(left), "exact_function": left == right,
            "common_prefix_words": prefix, "common_suffix_words": suffix,
            "suffix_offsets": {"reference": (len(left)-suffix)*4,
                               "candidate": (len(right)-suffix)*4} if suffix else None,
            "instruction_changes": changes, "reference_facts": original,
            "candidate_facts": current,
            "extra_direct_calls": dict(b-a), "missing_direct_calls": dict(a-b),
            "stack_load_changes": home_changes,
            "memory_operand_changes": memory_order(original, current)}


def allocation_summary(records, parsed):
    records = [r for r in records if r.get("pass", "ido-regalloc") == "ido-regalloc"]
    selected = [r for r in records if r.get("name") == "RangeColor"]
    raw = {(r["expression"], r["range"], r["internal_color"]) for r in parsed["ranges"]}
    snapshots = {(f'{r["expression"]["table"]}|{r["expression"]["chain"]}',
                  r["range"], r["internal_color"]) for r in selected}
    if selected and snapshots != raw:
        raise ValueError("Final color remarks disagree with the separately collected uopt listing")
    by_expression = defaultdict(list)
    for row in parsed["ranges"]:
        by_expression[row["expression"]].append(row)
    colors = []
    for record in selected:
        item = dict(record)
        key = f'{record["expression"]["table"]}|{record["expression"]["chain"]}'
        matches = [r for r in by_expression[key] if r["range"] == record["range"]]
        if len(matches) != 1:
            raise ValueError("Ambiguous range identity in optimizer listing")
        item["uopt_line"] = matches[0]["line"]
        item["expression_record"] = matches[0].get("expression_record")
        colors.append(item)
    accesses = []
    homes = defaultdict(Counter)
    for record in records:
        if record["name"] != "SpillAccess":
            continue
        # IDO ucode enum (both shipped 5.3 headers and recovered source):
        # Ulod=82, Ustr=123. Preserve unknown opcodes without classifying them.
        op, kind = {82: ("Ulod", "load"), 123: ("Ustr", "store")}.get(
            record["ucode_opcode"], (None, "unknown"))
        accesses.append(dict(record, ucode_name=op, kind=kind))
        homes[(record["m_offset"], record["size"])][kind] += 1
    return {"event_counts": dict(Counter(r["name"] for r in records)),
            "final_colors_verified_against_uopt": bool(selected),
            "final_colors": colors,
            "uncolored_ranges": [r["range"] for r in selected if r["internal_color"] == -1],
            "live_units": [r for r in records if r["name"] == "LiveUnit"],
            "spill_slots": [r for r in records if r["name"] == "SpillSlot"],
            "spill_accesses": accesses,
            "spill_home_counts": [dict(m_offset=offset, size=size, accesses=dict(counts))
                                  for (offset, size), counts in sorted(homes.items())],
             "decision_explanations": explain_allocation(records),
             "splits": [r for r in records if r["name"] == "SplitAttempt"],
            "frame_extents": [r for r in records if r["name"] == "FrameExtent"]}


def decision_summary(records, pass_name):
    selected = [r for r in records if r.get("pass") == pass_name]
    return {"event_counts": dict(Counter(r["name"] for r in selected)), "records": selected}


def load_diagnostics(directory):
    report = json.loads((directory / "report.json").read_text())
    function = report["function"]
    # Existing evidence reader rechecks all hashes and recorded transparency bytes.
    compiler = correlate(directory, {"provenance": {"function": function}}, [])
    required = {"ordinary.obj", "ordinary.text", "ordinary.dis", "candidate.c", "uopt.txt"}
    if not required <= report["artifacts"].keys():
        raise ValueError("Missing authenticated ordinary object/source/optimizer artifacts")
    if digest(directory / "candidate.c") != report.get("candidate_sha256"):
        raise ValueError("Candidate source hash differs from producer report")
    dis = subprocess.check_output(["mips-linux-gnu-objdump", "-dr", str(directory / "ordinary.obj")], text=True)
    dis = "\n".join(line for line in dis.splitlines() if "file format" not in line)
    if dis != (directory / "ordinary.dis").read_text():
        raise ValueError("Ordinary object does not reproduce authenticated disassembly")
    records = []
    run = report.get("runs", {}).get("remarks", {})
    if run:
        if run.get("transparent") is not True:
            raise ValueError("Remarks run is not transparent")
        for suffix in ("text", "dis"):
            if (directory / ("remarks." + suffix)).read_bytes() != (directory / ("ordinary." + suffix)).read_bytes():
                raise ValueError("Remarks run transparency bytes differ")
        if run.get("format") == "json":
            if not {"remarks.json", "remarks.log"} <= report["artifacts"].keys():
                raise ValueError("Missing authenticated remarks")
            records = json.loads((directory / "remarks.json").read_text())
            if not isinstance(records, list) or any(
                not isinstance(r, dict) or r.get("schema") != 1 or
                r.get("pass") not in ("ido-regalloc", "ido-cse", "ido-scheduler") or not isinstance(r.get("name"), str)
                for r in records):
                raise ValueError("Unsupported remarks schema")
            logged = [json.loads(line) for line in (directory / "remarks.log").read_text().splitlines()
                      if line.startswith('{"schema":1,')]
            logged = [r for r in logged if r.get("pass") in ("ido-regalloc", "ido-cse", "ido-scheduler")]
            if records != logged:
                raise ValueError("Extracted remarks differ from compiler log")
            # Legacy ordinal-only records cannot be scoped to a named function.
            if any("function" not in r for r in records):
                records = []
            else:
                records = [r for r in records if r["function"] == function]
                if any(len({r["procedure_ordinal"] for r in records if r["pass"] == p}) > 1
                       for p in {r["pass"] for r in records}):
                    raise ValueError("Named remarks span multiple procedures")
    return report, compiler["runs"]["level5"], records


def make_report(directory, reference, output):
    producer, optimizer, records = load_diagnostics(directory)
    function = producer["function"]
    sides = {}
    for name, obj in (("reference", reference), ("candidate", directory / "ordinary.obj")):
        listing = output / (name + ".dis")
        scope = inspect(obj, function, 2**31, listing)
        sides[name] = {"scope": scope, "instructions": instruction_rows(listing.read_text(), scope)}
    comparison = compare_functions(sides["reference"]["instructions"], sides["candidate"]["instructions"])
    phase = None
    path = directory / "assembler-phase.json"
    if path.exists():
        if path.name not in producer["artifacts"] or not producer.get("runs", {}).get("retained", {}).get("transparent"):
            raise ValueError("Retained phase is not authenticated/transparent")
        phase = json.loads(path.read_text())
        if phase.get("function") != function or phase.get("status") != "transparent":
            raise ValueError("Retained phase function/status differs")
        # Ensure the phase artifact actually names the current ordinary object.
        if phase["artifacts"]["ordinary"]["sha256"] != digest(directory / "ordinary.obj"):
            raise ValueError("Retained phase belongs to another object")
        for artifact in phase["artifacts"].values():
            if digest(Path(artifact["path"])) != artifact["sha256"]:
                raise ValueError("Retained phase artifact hash differs")
        expected = sides["candidate"]["instructions"]
        if len(phase["final"]) != len(expected) or any(
            r["word"] != s["word"] or r["address"] != sides["candidate"]["scope"]["start"] + s["offset"]
            for r, s in zip(phase["final"], expected)):
            raise ValueError("Retained phase final words differ from scoped object")
        phase = {"retained": phase["retained"], "ordering": phase["ordering"],
                 "memory_order": retained_memory_order(phase["retained"], sides["candidate"]["instructions"]),
                 "interpretation": "Candidate assembly before assembler passes, verbatim; pseudo-instructions are not matched automatically to machine words."}
        phase_leads(phase, comparison)
    return {"schema": 1, "function": function, "status": "complete_scoped_comparison",
            "provenance": {"diagnostics": str(directory), "producer_sha256": digest(directory / "report.json"),
                           "reference_object": str(reference), "reference_sha256": digest(reference),
                           "candidate_sha256": producer["candidate_sha256"],
                           "reference_authority": "caller-selected object; ROM identity not established by this tool"},
            "sides": sides, "comparison": comparison,
            "allocation": allocation_summary(records, optimizer), "assembler_phase": phase,
            "cse": decision_summary(records, "ido-cse"),
            "scheduler": decision_summary(records, "ido-scheduler"),
            "limits": ["Complete declared STT_FUNC extents, including zero/unreachable words; symbol bounds still require review.",
                       "Exact comparison includes words and relocation type/symbol. Alignment is a sequence heuristic, not semantic correspondence.",
                       "Memory groups compare raw base-register/displacement operands. Base names and offsets do not establish pointer identity, alias independence or C-variable homes.",
                       "M offsets and compiler extents are not final SP offsets/frame sizes. Uncolored ranges do not alone prove a spill.",
                       "Remarks describe the candidate only; the original optimizer state is unavailable. Cross-build range/expression pairing is not inferred.",
                       "Neither diagnostic transparency nor reference-object comparison replaces semantic review and the formatted clean-ROM gate."]}


def render_markdown(report):
    c, a = report["comparison"], report["allocation"]
    lines = ["# Code-generation evidence: " + report["function"], "",
             f"Complete reference/candidate spans: {c['reference_words']}/{c['candidate_words']} words; delta {c['word_delta']:+d}.", "",
             f"Exact prefix: {c['common_prefix_words']} words. Exact suffix: {c['common_suffix_words']} words (including relocations).", "",
             "Extra direct calls: " + repr(c["extra_direct_calls"]) + ". Missing direct calls: " + repr(c["missing_direct_calls"]) + ".", "",
             "Empty branch + nop offsets: reference " + repr([r["offset"] for r in c["reference_facts"]["empty_branches"]])
             + "; candidate " + repr([r["offset"] for r in c["candidate_facts"]["empty_branches"]]) + ".", "",
             "## Allocation observations", "", "Event counts: " + repr(a["event_counts"]) + ".", "",
             "Final colors cross-checked against uopt: " + str(a["final_colors_verified_against_uopt"]) + ".", "",
             "Uncolored ranges: " + repr(a["uncolored_ranges"]) + ".", "",
             f"Spill slots/accesses: {len(a['spill_slots'])}/{len(a['spill_accesses'])}. Split attempts: {len(a['splits'])}.", "",
             "Compiler M extents: " + repr([{k: v for k, v in r.items() if k in ('temp_displacement', 'highest_m_definition', 'stack_reversed')}
                                           for r in a["frame_extents"]]) + ".", "",
             "Encoded SP adjustments: reference " + repr([r["sp_delta"] for r in c["reference_facts"]["sp_adjustments"]])
             + "; candidate " + repr([r["sp_delta"] for r in c["candidate_facts"]["sp_adjustments"]]) + ".", "",
             "## Memory operand changes", ""]
    for group in c["memory_operand_changes"]:
        lines.append(f"- {group['base']} {group['kind']}: {len(group['reference'])}/{len(group['candidate'])} accesses; same operand multiset: {group['same_operand_multiset']}.")
        if group.get("candidate_access_group_fully_anchored"):
            lines.append(f"  All candidate accesses have unique retained anchors; their order changed during assembler passes: {group['retained_to_final_order_changed']}.")
    if c["stack_load_changes"]:
        lines.extend(["", f"Changed direct SP-load operand/register counts ({len(c['stack_load_changes'])} groups; first 12):", ""])
        lines.extend(f"- {r['opcode']} {r['value_register']}, {r['displacement']}(sp): reference {len(r['reference'])}, candidate {len(r['candidate'])}."
                     for r in c["stack_load_changes"][:12])
    if a["spill_home_counts"]:
        lines.extend(["", f"Emitted temporary-home accesses ({len(a['spill_home_counts'])} homes; first 12):", ""])
        lines.extend(f"- M {r['m_offset']}, size {r['size']}: {r['accesses']}." for r in a["spill_home_counts"][:12])
    for key, title in (("cse", "CSE observations"), ("scheduler", "Scheduler observations")):
        summary = report.get(key, {"event_counts": {}, "records": []})
        lines.extend(["", "## " + title, "", "Event counts: " + repr(summary["event_counts"]) + ".", ""])
        if key == "cse":
            cleared = [r for r in summary["records"] if r["name"] == "AnticipationAvailability" and
                       ((r["anticipated_before"] and not r["anticipated_after"]) or
                        (r["available_before"] and not r["available_after"]))]
            lines.append(f"Anticipation/availability checks clearing a candidate bit: {len(cleared)}. These are gate observations, not inferred alias reasons.")
        else:
            delayed = [r for r in summary["records"] if r["name"] == "StartTime" and r["resource_delay"]]
            lines.append(f"Start-time queries delayed beyond requested/dependency-ready cycle: {len(delayed)}. Queries can repeat; they are not all issued instructions.")
        lines.append("All records, node/input identities and decision operands are in codegen.json.")
    lines.extend(["", "## First differing instruction windows", ""])
    for change in c["instruction_changes"][:6]:
        lines.extend(["```text"])
        for side, label in (("left", "reference"), ("right", "candidate")):
            for row in change[side][:12]:
                lines.append(f"{label:9s} +0x{row['offset']:04x} {row['word']} {row['assembly']} {row['relocations']}")
        lines.extend(["```", ""])
    lines.extend(["The JSON report contains every instruction and every differing window. This Markdown view limits displayed windows/rows.", ""])
    if report["assembler_phase"]:
        phase = report["assembler_phase"]
        order = phase["memory_order"]
        lines.extend(["## Retained assembler input", "",
                      f"Retained-to-final memory order: {order['unique_anchor_count']} unique encoded anchors; order changed: {order['order_changed']}.", ""])
        for symbol, sites in phase["extra_call_sites"].items():
            for site in sites:
                lines.append(f"- Extra call `{symbol}` already appears at retained line {site['line']}: `{site['text'].strip()}`.")
        forms = phase["comparison_forms"]
        if forms:
            lines.extend(["", f"Retained Boolean/comparison forms ({len(forms)} total; first 6):", ""])
            lines.extend(f"- Line {r['line']}: `{r['text'].strip()}`." for r in forms[:6])
        lines.append("")
    lines.extend(["## Interpretation limits", ""])
    lines.extend("- " + limit for limit in report["limits"])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("diagnostics", type=Path)
    parser.add_argument("reference", type=Path, help="Reviewed expected/reference object containing FUNCTION")
    parser.add_argument("--output", type=Path, required=True, help="New external evidence directory")
    args = parser.parse_args()
    output = args.output.resolve()
    repo = Path(__file__).resolve().parent.parent
    if output == repo or repo in output.parents:
        parser.error("Output must be outside the repository")
    output.mkdir(parents=True, exist_ok=False)
    try:
        report = make_report(args.diagnostics.resolve(), args.reference.resolve(), output)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        (output / "error.json").write_text(json.dumps({"status": "error", "error": str(error)}, indent=2) + "\n")
        parser.exit(2, str(error) + "\n")
    (output / "codegen.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "codegen.md").write_text(render_markdown(report))
    print(output / "codegen.md")


if __name__ == "__main__":
    main()
