#!/usr/bin/env python3
"""Report captured narrowing, PRE plans and ugen translation without inferred history."""
import argparse
from collections import Counter
import json
from pathlib import Path
import tempfile
from compare_compiler_decisions import load_side
from dataflow.common import write_report


NAMES = {"ConversionInput", "ConversionDecision", "ConversionEmitted", "PREPlan", "TranslateBegin", "TranslateEnd", "TemporaryAssigned", "RegisterRequest", "EvaluationBegin", "EvaluationEnd"}


def summarize(events):
    selected = [e for e in events if e.get("name") in NAMES]
    return {"analysis": "Conversion/PRE/ugen decision frontier", "status": "observed" if selected else "unknown",
            "event_counts": dict(Counter(e["name"] for e in selected)), "findings": selected,
            "uncertainties": ["PREPlan is an insert/delete plan, not proof of the realized replacement or memory independence.",
                              "ConversionDecision observes add_cvtl's operand/result; allocation of a fresh versus hash-reused expression is not inferred.",
                              "Ugen symbols are reviewed Uent anchors. Unknown widths use zero; candidate-register rejection history is not captured by TemporaryAssigned."],
            "limits": "Candidate-only invocation-local observations. No original C or match acceptance."}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("diagnostics", type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    function = json.loads((args.diagnostics / "report.json").read_text())["function"]
    with tempfile.TemporaryDirectory() as scratch:
        side = load_side(args.diagnostics, function, Path(scratch))
    report = summarize(side["events"])
    report.update(provenance=side["provenance"], function=function)
    write_report(report, args.output)


if __name__ == "__main__":
    main()
