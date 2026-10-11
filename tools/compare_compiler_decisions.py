#!/usr/bin/env python3
"""Compare transparent saved IDO runs through explicit analyst-selected anchors."""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import tempfile

from dataflow.common import artifact, digest, write_report
from dataflow.ido import correlate
from object_scope import inspect
from paired_near_match import compare_rows, instruction_rows

PASSES = ("ido-cse", "ido-regalloc", "ido-scheduler", "ido-ugen", "ido-xbb")


def load_side(directory, function, scratch):
    producer = json.loads((directory / "report.json").read_text())
    required = {"ordinary.obj", "ordinary.text", "ordinary.dis", "candidate.c", "uopt.txt",
                "diagnostic.text", "diagnostic.dis"}
    if not required <= producer.get("artifacts", {}).keys():
        raise ValueError("Missing hashed compiler artifacts")
    compiler = correlate(directory, {"provenance": {"function": function}}, [])
    if digest(directory / "candidate.c") != producer.get("candidate_sha256"):
        raise ValueError("Candidate source hash mismatch")
    dis = subprocess.check_output(["mips-linux-gnu-objdump", "-dr", str(directory / "ordinary.obj")], text=True)
    dis = "\n".join(line for line in dis.splitlines() if "file format" not in line)
    if dis != (directory / "ordinary.dis").read_text():
        raise ValueError("Object disagrees with hashed disassembly")
    listing = scratch / (directory.name + ".dis")
    scope = inspect(directory / "ordinary.obj", function, 2**31, listing)
    rows = instruction_rows(listing.read_text(), scope)
    scope.pop("disassembly", None)
    events = []
    run = producer.get("runs", {}).get("remarks", {})
    if run:
        if run.get("transparent") is not True or run.get("format") != "json":
            raise ValueError("Require transparent named JSON remarks")
        if not {"remarks.json", "remarks.log", "remarks.text", "remarks.dis"} <= producer["artifacts"].keys():
            raise ValueError("Remarks artifacts are not authenticated")
        for suffix in ("text", "dis"):
            if (directory / ("remarks." + suffix)).read_bytes() != (directory / ("ordinary." + suffix)).read_bytes():
                raise ValueError("Remarks transparency mismatch")
        events = json.loads((directory / "remarks.json").read_text())
        logged = [json.loads(line) for line in (directory / "remarks.log").read_text().splitlines()
                  if line.startswith('{"schema":1,')]
        logged = [r for r in logged if r.get("pass") in PASSES]
        if events != logged or not events:
            raise ValueError("Missing remarks or remarks/log mismatch")
        for event in events:
            if event.get("schema") != 1 or event.get("function") != function or event.get("pass") not in PASSES:
                raise ValueError("Unsupported/unscoped remark")
        for pass_name in PASSES:
            selected = [r for r in events if r["pass"] == pass_name]
            if len({r.get("procedure_ordinal") for r in selected}) > 1:
                raise ValueError("Multiple procedures in named remarks")
        colors = [r for r in events if r["pass"] == "ido-regalloc" and r["name"] == "RangeColor"]
        if colors:
            observed = {(f'{r["expression"]["table"]}|{r["expression"]["chain"]}', r["range"], r["internal_color"]) for r in colors}
            dumped = {(r["expression"], r["range"], r["internal_color"]) for r in compiler["runs"]["level5"]["ranges"]}
            if observed != dumped:
                raise ValueError("Final color snapshots disagree with independent uopt dump")
    retained = None
    ugen_run = producer.get("runs", {}).get("ugen-remarks")
    if ugen_run:
        if ugen_run.get("transparent") is not True or not {"ugen-remarks.json", "ugen-remarks.log", "ugen-remarks.text", "ugen-remarks.dis"} <= producer["artifacts"].keys():
            raise ValueError("Require authenticated transparent ugen remarks")
        for suffix in ("text", "dis"):
            if (directory / ("ugen-remarks." + suffix)).read_bytes() != (directory / ("ordinary." + suffix)).read_bytes():
                raise ValueError("ugen remarks transparency mismatch")
        records = json.loads((directory / "ugen-remarks.json").read_text())
        logged = [json.loads(line) for line in (directory / "ugen-remarks.log").read_text().splitlines() if line.startswith('{"schema":1,')]
        if not records or records != logged or any(r.get("function") != function or r.get("pass") != "ido-ugen" or r.get("procedure_ordinal") != ugen_run.get("symbol") for r in records):
            raise ValueError("ugen remarks scope/log mismatch")
        events.extend(records)
    phase_path = directory / "assembler-phase.json"
    if phase_path.exists():
        if phase_path.name not in producer["artifacts"] or producer.get("runs", {}).get("retained", {}).get("transparent") is not True:
            raise ValueError("Unauthenticated retained assembly")
        phase = json.loads(phase_path.read_text())
        if phase.get("status") != "transparent" or phase.get("function") != function:
            raise ValueError("Retained phase function/transparency mismatch")
        if phase["artifacts"]["ordinary"]["sha256"] != digest(directory / "ordinary.obj"):
            raise ValueError("Retained phase belongs to a different object")
        for item in phase["artifacts"].values():
            if digest(item["path"]) != item["sha256"]:
                raise ValueError("Retained artifact hash mismatch")
        if [(r["address"] - scope["start"], r["word"]) for r in phase["final"]] != [(r["offset"], r["word"]) for r in rows]:
            raise ValueError("Retained final stream differs from complete object")
        retained = phase["retained"]
    if producer.get("runs", {}).get("xbb"):
        if producer["runs"]["xbb"].get("transparent") is not True or not {"xbb.json", "xbb.log", "xbb.text", "xbb.dis"} <= producer["artifacts"].keys():
            raise ValueError("Require transparent authenticated xbb capture")
        for suffix in ("text", "dis"):
            if (directory / ("xbb." + suffix)).read_bytes() != (directory / ("ordinary." + suffix)).read_bytes():
                raise ValueError("xbb transparency mismatch")
        from explain_xbb import parse_xbb
        parsed = parse_xbb((directory / "xbb.log").read_text(), function)
        saved = json.loads((directory / "xbb.json").read_text())
        keys = {"function", "blocks", "moves", "raw"} | ({"events", "cfg_changes"} & saved.keys())
        if any(parsed.get(key) != saved.get(key) for key in keys):
            raise ValueError("xbb structured report differs from authenticated log")
        events.extend(parsed["events"])
    return {"producer": producer, "provenance": artifact(directory / "report.json"), "scope": scope,
            "instructions": rows, "ranges": compiler["runs"]["level5"]["ranges"],
            "events": events, "retained": retained}


def select(side, selector):
    if set(selector) == {"range"}:
        rows = [r for r in side["ranges"] if r["range"] == selector["range"]]
        if len(rows) != 1:
            raise ValueError("Missing/ambiguous explicit range")
        row = rows[0]
        expression = row["expression"]
        observations = [r for r in side["events"] if r.get("pass") == "ido-regalloc" and
                        r.get("expression") == {"table": int(expression.split("|")[0]), "chain": int(expression.split("|")[1])}]
        return {"stage": "allocation", "allocation_record": row, "events": observations}
    if set(selector) == {"pass", "name", "sequence"}:
        # The emitted JSON field is `event`; the manifest calls it a sequence
        # to distinguish this ordinal from the selected remark payload.
        rows = [r for r in side["events"] if r.get("pass") == selector["pass"] and
                r.get("name") == selector["name"] and r.get("event") == selector["sequence"]]
        if len(rows) != 1:
            raise ValueError("Missing/ambiguous explicit event")
        return {"stage": {"ido-cse": "expression", "ido-regalloc": "allocation", "ido-scheduler": "scheduler"}[selector["pass"]], "remark": rows[0]}
    raise ValueError("Anchor must select one range or pass/name/sequence event")


def decision_fields(value):
    """Discard local identities, not decision operands; never automatically pair nodes."""
    if isinstance(value, list):
        return [decision_fields(x) for x in value]
    if not isinstance(value, dict):
        return value
    local = {"expression", "range", "line", "raw", "uopt_line", "expression_record", "sequence",
             "event", "procedure_ordinal", "procedure_symbol", "function", "block_address", "address", "block"}
    return {k: decision_fields(v) for k, v in value.items() if k not in local}


def compare(left, right, anchors):
    pairs = []
    for anchor in anchors:
        if not isinstance(anchor.get("basis"), str) or not anchor["basis"].strip():
            raise ValueError("Every cross-build anchor needs an explicit identity basis")
        a, b = select(left, anchor["left"]), select(right, anchor["right"])
        if a["stage"] != b["stage"]:
            raise ValueError("Anchor stages differ")
        pa, pb = decision_fields(a), decision_fields(b)
        pairs.append({"label": anchor.get("label", ""), "basis": anchor["basis"], "stage": a["stage"],
                      "left": a, "right": b, "decision_fields_differ": pa != pb,
                      "left_decision_fields": pa, "right_decision_fields": pb})
    differences = compare_rows(left["instructions"], right["instructions"])
    retained = None
    if left["retained"] is not None and right["retained"] is not None:
        a, b = [[r["text"] for r in s["retained"]] for s in (left, right)]
        first = next((i for i in range(min(len(a), len(b))) if a[i] != b[i]), min(len(a), len(b)))
        retained = {"equal": a == b, "first_differing_index": first if a != b else None,
                    "left": a, "right": b, "limit": "Text sequence only; no pseudo-instruction expansion or source identity inference."}
    differing = [p for p in pairs if p["decision_fields_differ"]]
    order = {"expression": 0, "allocation": 1, "scheduler": 2}
    earliest = min(differing, key=lambda p: order[p["stage"]])["stage"] if differing else None
    return {"anchors": pairs, "earliest_observed_anchored_stage": earliest,
            "instruction_changes": differences, "retained_comparison": retained,
            "coverage": {name: {p: dict(Counter(r["name"] for r in s["events"] if r["pass"] == p)) for p in PASSES}
                         for name, s in (("left", left), ("right", right))},
            "limit": "Earliest is among supplied anchors, not a causal first compiler divergence. Local IDs are never paired automatically."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="function, left/right diagnostic directories, anchors")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    config = json.loads(args.manifest.read_text())
    with tempfile.TemporaryDirectory(dir=args.output.resolve().parent, prefix="compiler-pair-") as tmp:
        sides = {name: load_side((args.manifest.parent / config[name]).resolve(), config["function"], Path(tmp)) for name in ("left", "right")}
    report = {"schema": 1, "analysis": "paired_compiler_decisions", "status": "complete",
              "manifest": artifact(args.manifest), "function": config["function"],
              "sides": {n: {**{k: s[k] for k in ("provenance", "scope")},
                            "compiler_context": {k: s["producer"].get(k) for k in
                                ("runtime_uopt_sha256", "runtime_as1_sha256", "candidate_sha256", "commands")}}
                        for n, s in sides.items()},
              **compare(sides["left"], sides["right"], config.get("anchors", [])),
              "limits": ["Explicit anchors are analyst hypotheses, not proven value equivalence.",
                         "Scheduler input indices are invocation-local; equal indices across builds prove nothing.",
                         "Colors/M offsets are not physical registers/SP homes; absent events are coverage gaps.",
                         "No original compiler state, compilation, semantic proof or match acceptance."]}
    report["findings"] = [{"earliest_observed_anchored_stage": report["earliest_observed_anchored_stage"],
                           "instruction_difference_windows": len(report["instruction_changes"])}]
    write_report(report, args.output)


if __name__ == "__main__":
    main()
