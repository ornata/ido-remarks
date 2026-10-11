"""Procedure-scoped IDO evidence, with explicit machine-value correlations."""

import re
from pathlib import Path
from .common import read_json, artifact, digest
from .machine import REGS


def parse_uopt(text, function):
    procedure, current = None, None
    ranges, expressions, allocation_events = [], {}, []
    for line_no, line in enumerate(text.splitlines(), 1):
        scope = re.search(r"SECONDS IN .* OF (\w+)", line)
        if scope:
            procedure = scope[1]
            current = None
        if procedure != function:
            continue
        expression = re.match(r"\{\s*(\d+\|\d+)\}\s+(\d+)\s+(isvar|isop)\s+(.*)", line)
        if expression:
            expressions[expression[1]] = {
                "bit": int(expression[2]),
                "description": expression[4],
                "line": line_no,
            }
        active = re.match(r">>>active<<<\{\s*(\d+\|\d+)\}\s+(\d+)\s+(-?\d+)", line)
        if active:
            current = {
                "expression": active[1],
                "range": int(active[2]),
                "internal_color": int(active[3]),
                "uncolored": int(active[3]) == -1,
                "line": line_no,
                "raw": [],
            }
            ranges.append(current)
        if current:
            current["raw"].append({"line": line_no, "text": line})
            savings = re.search(r"adjsave, hasstore:\s*(\S+)\s+(true|false)", line)
            if savings:
                current.update(
                    adjusted_savings=float(savings[1]), has_store=savings[2] == "true"
                )
            if line.startswith("forbidden:"):
                current["forbidden_internal_registers"] = [
                    int(x) for x in re.findall(r"\d+", line)
                ]
            flags = re.match(
                r"firstisstr deadout needreglod needregsave\s+(true|false)\s+(true|false)\s+(true|false)\s+(true|false)",
                line,
            )
            if flags:
                current.setdefault("block_requirements", []).append(
                    {
                        "first_store": flags[1] == "true",
                        "dead_out": flags[2] == "true",
                        "reload": flags[3] == "true",
                        "save": flags[4] == "true",
                        "line": line_no,
                    }
                )
        if re.search(r"live range|not colored|split out", line):
            allocation_events.append({"line": line_no, "text": line})
    for row in ranges:
        row["expression_record"] = expressions.get(row["expression"])
    return {"ranges": ranges, "events": allocation_events}


def correlate(directory, candidate, pairs):
    report = read_json(directory / "report.json")
    if (
        report.get("status") != "transparent"
        or not report.get("text_equal")
        or not report.get("disassembly_and_relocations_equal")
    ):
        raise ValueError("IDO evidence is not transparent")
    if not report.get("artifacts"):
        raise ValueError(
            "Diagnostic report lacks artifact hashes; recollect with the current runner"
        )
    for name, fingerprint in report["artifacts"].items():
        if Path(name).name != name or digest(directory / name) != fingerprint:
            raise ValueError("Diagnostic artifact hash mismatch: " + name)
    # Independently verify the retained transparency evidence, not just a boolean.
    if (directory / "ordinary.text").read_bytes() != (
        directory / "diagnostic.text"
    ).read_bytes() or (directory / "ordinary.dis").read_bytes() != (
        directory / "diagnostic.dis"
    ).read_bytes():
        raise ValueError("IDO evidence bytes disagree with transparency report")
    if report["function"] != candidate["provenance"]["function"]:
        raise ValueError("IDO procedure differs from candidate function")
    for name in ("level6", "ugen"):
        if report.get("runs", {}).get(name, {}).get("transparent"):
            for suffix in ("text", "dis"):
                if (directory / (name + "." + suffix)).read_bytes() != (
                    directory / ("ordinary." + suffix)
                ).read_bytes():
                    raise ValueError(
                        "Additional trace transparency evidence differs: " + name
                    )
    result = {
        "provenance": artifact(directory / "report.json"),
        "function": report["function"],
        "runs": {},
        "correlations": [],
        "uncertainties": [
            "Compiler source/object evidence does not by itself authenticate the separately linked candidate ELF. Correlations require the recorded link provenance."
        ],
    }
    for name, file in [("level5", "uopt.txt"), ("level6", "uopt6.txt")]:
        path = directory / file
        if path.exists():
            if name == "level6" and not report.get("runs", {}).get("level6", {}).get(
                "transparent"
            ):
                raise ValueError("Level-6 run lacks transparency verification")
            result["runs"][name] = {
                "artifact": artifact(path),
                **parse_uopt(path.read_text(), report["function"]),
            }
    # -Wc,-d emits architectural xrN trace lines to the captured log;
    # -Wc,-e writes a separate IR tree to ugen.tree.txt, not these line anchors.
    ugen = directory / "ugen.log"
    ugen_lines = (
        ugen.read_text().splitlines()
        if ugen.exists() and report.get("runs", {}).get("ugen", {}).get("transparent")
        else []
    )
    for pair in pairs:
        values = [v for v in candidate["values"] if v["id"] == pair["value"]]
        ranges = [
            r for r in result["runs"]["level5"]["ranges"] if r["range"] == pair["range"]
        ]
        if len(values) != 1 or len(ranges) != 1:
            raise ValueError("Ambiguous or missing IDO/value anchor")
        evidence = {
            "value": pair["value"],
            "range": pair["range"],
            "basis": "explicit storage/expression anchor",
            "allocation": ranges[0],
        }
        if "ugen_line" in pair:
            line = pair["ugen_line"]
            if not 1 <= line <= len(ugen_lines):
                raise ValueError("Missing verified ugen evidence line")
            match = re.search(r"reg = xr(\d+)\b", ugen_lines[line - 1])
            if (
                not match
                or int(match[1]) >= len(REGS)
                or REGS[int(match[1])] != values[0]["register"]
            ):
                raise ValueError(
                    "ugen architectural register does not corroborate the anchor"
                )
            evidence["ugen"] = {"line": line, "text": ugen_lines[line - 1]}
        result["correlations"].append(evidence)
    return result
