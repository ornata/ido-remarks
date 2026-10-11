#!/usr/bin/env python3
"""Explain observed allocation decisions from authenticated transparent diagnostics."""
import argparse
import json
from pathlib import Path
import tempfile

from compare_compiler_decisions import load_side
from dataflow.common import write_report


def explain(events):
    findings = []
    for event in events:
        if event.get("name") == "SplitAdjacency":
            left, right = 2 * event["colors_left"], event["interferences"] + event["shared"]
            expected = (event["shared"] < event["previous_colors_left"] and left >= right
                        if event["heuristic"] else event["colors_left"] != 0)
            if expected != event["accepted"]:
                raise ValueError("Split predicate disagrees with captured decision")
            findings.append(dict(event, capacity=left, required=right,
                                 reason="accepted" if expected else "shared limit" if event["heuristic"] and
                                 event["shared"] >= event["previous_colors_left"] else "capacity" if event["heuristic"] else "no colors"))
        elif event.get("name") in ("ForbiddenContribution", "ForbiddenOrigin"):
            added = [f"{int(b, 16) & ~int(a, 16):08x}" for a, b in zip(event["before"], event["after"])]
            findings.append(dict(event, added_words=added))
        elif event.get("name") in ("ColorChoice", "ColorPhase", "SplitLineage", "SplitSeedSelected", "InterferenceEdge", "BenefitBefore", "AllocationBenefit", "SplitAttempt"):
            findings.append(event)
    names = {e.get("name") for e in events}
    missing = sorted({"SplitAdjacency", "ColorChoice", "ForbiddenContribution", "InterferenceEdge"} - names)
    return {"analysis": "IDO allocation decisions", "status": "observed" if findings else "unknown",
            "findings": findings, "uncertainties": ["Uncaptured event families: " + ", ".join(missing)] if missing else [],
            "limits": "Candidate-only. Choice order is event order; internal colors are not physical registers. Block contributors do not identify the range that originally occupied a register. No original optimizer state or match acceptance."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("diagnostics", type=Path)
    parser.add_argument("--range", type=int, action="append", default=[], help="Explicit invocation-local range filters (includes its split ancestry and direct interferers)")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    function = json.loads((args.diagnostics / "report.json").read_text())["function"]
    with tempfile.TemporaryDirectory() as scratch:
        side = load_side(args.diagnostics, function, Path(scratch))
    report = explain(side["events"])
    if args.range:
        selected = set(args.range)
        report["findings"] = [e for e in report["findings"] if any(e.get(key) in selected for key in
                             ("range", "parent_range", "kept_range", "remainder_range", "owner_range", "other_range", "new_range", "remaining_range"))]
        report["selected_ranges"] = args.range
        report["uncertainties"].append("Filtered view excludes block-only return reservations; review the unfiltered origin records as well.")
    report.update(function=function, provenance=side["provenance"])
    write_report(report, args.output)


if __name__ == "__main__":
    main()
