#!/usr/bin/env python3
"""Compare observed definition, bit/range-creation and scheduler ordering frontiers."""
import argparse
import json
from pathlib import Path
import tempfile
from compare_compiler_decisions import load_side
from dataflow.common import write_report


def summarize(events):
    first, seen = [], set()
    for event in events:
        if event.get("name") != "DefinitionInput": continue
        key=tuple(event.get(k) for k in ("memtype","symbol_block","storage_offset","width","dtype"))
        if key not in seen:
            seen.add(key)
            first.append(event)
    names={"RangeCreated","BitAllocated","DefinitionLiveUnit","ColorPhase","SchedulerScore","ReadyComparison","PriorityComparison","InstructionIssue"}
    selected=[e for e in events if e.get("name") in names]
    missing=sorted({"DefinitionInput","BitAllocated","RangeCreated","DefinitionLiveUnit","ReadyComparison","SchedulerScore"}-{e.get("name") for e in events})
    return {"analysis":"Definition/range/schedule ordering", "status":"observed" if first or selected else "unknown",
            "first_storage_definitions":first,"range_creation_order":[e for e in selected if e["name"]=="RangeCreated"],
            "slot_decisions":[e for e in selected if e["name"]=="SchedulerScore" and e["slot_decides"]],
            "ready_comparisons":[e for e in selected if e["name"]=="ReadyComparison"],
            "findings":first+selected,
            "uncertainties":(["Uncaptured frontier families: "+", ".join(missing)] if missing else [])+["First definitions identify compiler storage keys, not original C variables; reused homes may represent different source lifetimes.",
                             "Creation order and scheduler order are separate process-local observations. Correspondences require reviewed anchors.",
                             "SchedulerScore captures the final native integer score and pool-slot component. Other score components and ready-queue insertion history are not inferred."],
            "limits":"Candidate-only diagnostics; no source equivalence or match acceptance."}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("diagnostics",type=Path)
    p.add_argument("--output",required=True,type=Path)
    args=p.parse_args()
    function=json.loads((args.diagnostics/"report.json").read_text())["function"]
    with tempfile.TemporaryDirectory() as scratch:
        side=load_side(args.diagnostics,function,Path(scratch))
    result=summarize(side["events"])
    result.update(function=function,provenance=side["provenance"])
    write_report(result,args.output)


if __name__=="__main__": main()
