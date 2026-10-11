#!/usr/bin/env python3
"""Read named, transparent as1 cross-basic-block scheduling captures."""
import argparse
import json
from pathlib import Path
import re
import tempfile

from compare_compiler_decisions import load_side
from dataflow.common import write_report


def parse_xbb(text, function):
    scopes, active = [], None
    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith('{"schema":1,"pass":"ido-xbb",'):
            event = json.loads(line)
            if event["name"] == "Begin":
                if active is not None:
                    raise ValueError("Nested xbb scopes")
                active = {"function": event["function"], "lines": [], "events": []}
            elif event["name"] == "End":
                if active is None or active["function"] != event["function"]:
                    raise ValueError("Unpaired xbb scope")
                if active["function"] == function:
                    scopes.append(active)
                active = None
            else:
                if active is None or event.get("function") != active["function"] or event.get("schema") != 1:
                    raise ValueError("Unscoped xbb observation")
                if event.get("truncated"):
                    raise ValueError("Truncated xbb observation")
                active["events"].append(event)
        elif active is not None:
            active["lines"].append({"line": number, "text": line})
    if active is not None or len(scopes) != 1:
        raise ValueError("Require exactly one complete named xbb invocation")
    blocks, moves, section, pending, current = {}, [], None, None, None
    for row in scopes[0]["lines"]:
        line = row["text"]
        weight = re.fullmatch(r"\s*bb: (\d+)\s+weight: (\d+)\s*", line)
        dom = re.fullmatch(r"BB (\d+) (dominated|postdominated) by:\s*([\d ]*)", line)
        head = re.fullmatch(r"current bb (\d+), weight = (\d+), stalls = (\d+)", line)
        move = re.fullmatch(r"(MOVETO|MOVEFROM) bb (\d+),? inst (\d+)\s+time: old (\d+), new (\d+)", line)
        if weight:
            blocks.setdefault(int(weight[1]), {})["weight"] = int(weight[2])
        elif dom:
            blocks.setdefault(int(dom[1]), {})[dom[2]] = list(map(int, dom[3].split()))
        elif head:
            current = {"block": int(head[1]), "weight": int(head[2]), "stalls": int(head[3])}
        elif move:
            point = dict(row, block=int(move[2]), instruction=int(move[3]), old_time=int(move[4]), new_time=int(move[5]))
            if move[1] == "MOVETO":
                if pending is not None:
                    raise ValueError("Unpaired MOVETO")
                pending = {"to": point, "context": current, "to_listing": [], "from_listing": []}
            else:
                if pending is None:
                    raise ValueError("Unpaired MOVEFROM")
                pending["from"] = point
                moves.append(pending)
                pending = None
                section = None
        elif line.startswith("----- basic block instruction moved to"):
            section = "to_listing"
        elif line.startswith("----- basic block instruction moved from"):
            section = "from_listing"
        elif section and re.match(r"\s*INST \d+:", line) and moves:
            moves[-1][section].append(row)
    if pending is not None or not blocks:
        raise ValueError("Incomplete or absent xbb debug records")
    for move in moves:
        destination, source = blocks.get(move["to"]["block"], {}), blocks.get(move["from"]["block"], {})
        move["observed_eligibility"] = {
            "destination_in_source_dominators": move["to"]["block"] in source.get("dominated", []),
            "source_weight": source.get("weight"), "destination_weight": destination.get("weight")}
        # The destination listing is after the move, not the original source stream.
        point = move["to"]["instruction"]
        matches = [r for r in move["to_listing"] if re.match(r"\s*INST " + str(point) + r":", r["text"])]
        move["moved_instruction"] = matches[0] if len(matches) == 1 else None
    observed = scopes[0]["events"]
    changes = cfg_changes(observed)
    return {"function": function, "blocks": [{"block": k, **v} for k, v in sorted(blocks.items())],
            "events": observed, "cfg_changes": changes,
            "moves": moves, "raw": scopes[0]["lines"],
            "limits": "Named candidate invocation. Listings are post-move snapshots; IDs are invocation-local. Root classification uses captured predecessor lists, not self-dominance. Snapshot deltas identify phase intervals, not original C or a unique instruction cause. Raw flags are not guessed volatile semantics. Uninstrumented rejection and liveness predicates remain unknown."}


def cfg_changes(events):
    previous, result = {}, []
    for event in events:
        if event.get("name") != "CFGSnapshot":
            continue
        rows = event["instructions"]
        if len(rows) != event["instruction_count"] or {r["index"] for r in rows} != set(range(1,len(rows)+1)):
            raise ValueError("Incomplete CFG instruction snapshot")
        if event["is_root"] != (not event["predecessors"]):
            raise ValueError("Root flag disagrees with predecessors")
        block = event["block"]
        prior = previous.get(block)
        nonzero = sum(r["word"] not in {"00000000", "7fffffff"} for r in rows)
        result.append({"name": "RootClassified", "block": block, "phase": event["phase"],
                       "is_root": event["is_root"], "nonzero_word_count": nonzero,
                       "basis": "captured predecessor list and raw instruction slots"})
        if prior:
            interval = {"block": block, "before_event": prior["event"], "after_event": event["event"],
                        "before_phase": prior["phase"], "after_phase": event["phase"]}
            for key in ("predecessors", "successors"):
                before, after = set(prior[key]), set(event[key])
                for kind, peers in (("added", after-before), ("removed", before-after)):
                    for peer in sorted(peers):
                        result.append({**interval, "name": "CFGEdgeChanged", "projection": key, "action": kind, "peer": peer})
            if nonzero == 0 and any(r["word"] not in {"00000000", "7fffffff"} for r in prior["instructions"]):
                result.append({**interval, "name": "BlockEmptied", "basis": "nonzero instruction slots; nops/label markers excluded"})
            before = {r["index"]: r["word"] for r in prior["instructions"]}
            after = {r["index"]: r["word"] for r in rows}
            from collections import Counter
            ca, cb = Counter(before.values()), Counter(after.values())
            for index, word in before.items():
                opcode = int(word,16) >> 26
                branch = opcode in {1,2,3,4,5,6,7,20,21,22,23} or opcode == 0 and int(word,16)&63 in {8,9}
                if branch and word == after.get(index) and ca[word] == cb[word] == 1 and index+1 in before and index+1 in after and before[index+1] != after[index+1]:
                    result.append({**interval, "name": "DelaySlotChanged", "branch_index": index,
                                   "before_word": before[index+1], "after_word": after[index+1]})
        previous[block] = event
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("diagnostics", type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    producer = json.loads((args.diagnostics / "report.json").read_text())
    function = producer["function"]
    with tempfile.TemporaryDirectory() as scratch:
        side = load_side(args.diagnostics, function, Path(scratch))
    if producer.get("runs", {}).get("xbb", {}).get("transparent") is not True:
        p.error("Require transparent xbb run")
    for suffix in ("text", "dis"):
        if (args.diagnostics / ("xbb." + suffix)).read_bytes() != (args.diagnostics / ("ordinary." + suffix)).read_bytes():
            p.error("xbb transparency bytes disagree")
    report = parse_xbb((args.diagnostics / "xbb.log").read_text(), function)
    write_report({"analysis": "as1 cross-block scheduling", "status": "observed", "provenance": side["provenance"],
                  **report, "findings": report["moves"] + report["cfg_changes"] + [e for e in report["events"] if e["name"] != "CFGSnapshot"],
                  "uncertainties": [report["limits"]]}, args.output)


if __name__ == "__main__":
    main()
