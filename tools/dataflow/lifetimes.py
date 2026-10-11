"""Instruction-event CFG, reaching definitions, liveness, and stack evidence."""

from .machine import (
    BRANCHES,
    LOADS,
    STORES,
    VOLATILE,
    REGS,
    effects,
    memory,
    number,
    reg,
    target,
)


def analyze(instructions, contracts=None):
    contracts = contracts or {}
    listing = {i.address: i for i in instructions}
    events, issues = {}, []

    def event(key, ins, successors, *, call=False):
        contract = contracts.get(ins.key)
        uses, defs, issue = effects(ins, contract)
        if call:
            uses = set(
                (contract or {}).get(
                    "arguments",
                    ["a0", "a1", "a2", "a3"] + [f"f{x}" for x in range(12, 16)],
                )
            )
            defs = VOLATILE.copy()
            if contract is None:
                issues.append(
                    {
                        "instruction": ins.key,
                        "reason": "unknown call contract; conservative register arguments, unknown memory effects",
                    }
                )
        if issue:
            issues.append(
                {
                    "instruction": ins.key,
                    "reason": issue + "; successor state is unmodeled",
                }
            )
            successors = []
        events[key] = {
            "instruction": ins,
            "uses": uses,
            "defs": defs,
            "successors": successors,
            "call": call,
        }

    for i in instructions:
        op, addr = i.opcode, i.address
        key = i.key
        following = f"{addr + 4:08x}"
        if op in BRANCHES or op in ("j", "jal", "jr", "jalr"):
            delay = listing.get(addr + 4)
            if delay is None:
                issues.append({"instruction": key, "reason": "missing delay slot"})
                event(key, i, [])
                continue
            if delay.opcode in BRANCHES or delay.opcode in ("j", "jal", "jr", "jalr"):
                issues.append(
                    {
                        "instruction": delay.key,
                        "reason": "control transfer in delay slot",
                    }
                )
                # This transfer/slot bundle has no modeled execution semantics.
                # Keep the physical instructions as evidence, but do not invent
                # delay, call, return, or successor state for this path.
                event(key, i, [])
                continue
            delayed = key + ":delay"
            after = f"{addr + 8:08x}"
            if op in ("jal", "jalr"):
                event(key, i, [delayed])
                event(delayed, delay, [key + ":call"])
                event(key + ":call", i, [after], call=True)
            elif op == "jr":
                event(key, i, [delayed])
                event(delayed, delay, [])
                # Return values are consumed after the delay instruction.
                events[key]["uses"] = {reg(i.operands[0])}
                if reg(i.operands[0]) == "ra":
                    event(key + ":return", i, [])
                    events[key + ":return"]["uses"] = set(
                        contracts.get(key, {}).get("returns", ["v0", "v1", "f0", "f1"])
                    )
                    events[key + ":return"]["defs"] = set()
                    events[delayed]["successors"] = [key + ":return"]
                else:
                    issues.append(
                        {"instruction": key, "reason": "unresolved indirect successor"}
                    )
            else:
                destination = f"{target(i):08x}"
                likely = op in BRANCHES and op.endswith("l")
                event(key, i, [delayed, after] if likely else [delayed])
                event(
                    delayed,
                    delay,
                    [destination] if op == "j" or likely else [destination, after],
                )
        else:
            event(key, i, [following])
    # Keep only events reachable from entry; standalone delay instructions remain available
    # for branches that intentionally target those physical addresses.
    reachable, pending = set(), [instructions[0].key]
    while pending:
        key = pending.pop()
        if key in reachable:
            continue
        if key not in events:
            issues.append(
                {"instruction": key, "reason": "successor outside function span"}
            )
            continue
        reachable.add(key)
        pending.extend(events[key]["successors"])
    events = {k: v for k, v in events.items() if k in reachable}
    for e in events.values():
        e["successors"] = [k for k in e["successors"] if k in events]
    predecessors = {k: [] for k in events}
    for key, e in events.items():
        for successor in e["successors"]:
            predecessors[successor].append(key)
    registers = set().union(*(e["uses"] | e["defs"] for e in events.values()))
    incoming = {k: {} for k in events}
    outgoing = {k: {} for k in events}
    live_in = {k: set() for k in events}
    live_out = {k: set() for k in events}
    entry = instructions[0].key
    for iteration in range(10000):
        changed = False
        for key, e in events.items():
            merged = {r: {f"entry:{r}"} for r in registers} if key == entry else {}
            for predecessor in predecessors[key]:
                for r, values in outgoing[predecessor].items():
                    merged.setdefault(r, set()).update(values)
            result = {r: values.copy() for r, values in merged.items()}
            result.update({r: {f"{key}:{r}"} for r in e["defs"]})
            if incoming[key] != merged or outgoing[key] != result:
                incoming[key], outgoing[key] = merged, result
                changed = True
        for key, e in reversed(list(events.items())):
            out = (
                set().union(*(live_in[s] for s in e["successors"]))
                if e["successors"]
                else set()
            )
            inside = e["uses"] | (out - e["defs"])
            if out != live_out[key] or inside != live_in[key]:
                live_out[key], live_in[key] = out, inside
                changed = True
        if not changed:
            break
    else:
        issues.append({"reason": "dataflow iteration budget exhausted"})
    values = {}
    for key, e in events.items():
        for r in e["defs"]:
            values[f"{key}:{r}"] = {
                "id": f"{key}:{r}",
                "register": r,
                "definition": key,
                "uses": [],
                "last_uses": [],
                "calls_crossed": [],
                "copies_from": [],
            }
    for r in registers:
        values[f"entry:{r}"] = {
            "id": f"entry:{r}",
            "register": r,
            "definition": "entry",
            "uses": [],
            "last_uses": [],
            "calls_crossed": [],
            "copies_from": [],
        }
    for key, e in events.items():
        for r in e["uses"]:
            for ident in incoming[key].get(r, []):
                values[ident]["uses"].append(key)
                # Last-use candidates on at least one outgoing edge; loops can also
                # have a later dynamic use, so never claim a unique chronological last use.
                if not e["successors"] or any(
                    r not in live_in[s] or r in e["defs"] for s in e["successors"]
                ):
                    values[ident]["last_uses"].append(key)
        if e["call"]:
            for r in live_out[key] - e["defs"]:
                for ident in incoming[key].get(r, []):
                    values[ident]["calls_crossed"].append(key)
        i = e["instruction"]
        if (
            not e["call"]
            and i.opcode in ("or", "addu", "daddu")
            and "zero" in [reg(x) for x in i.operands[1:]]
        ):
            source = next((reg(x) for x in i.operands[1:] if reg(x) != "zero"), "zero")
            ident = f"{key}:{reg(i.operands[0])}"
            if ident in values:
                values[ident]["copies_from"] = sorted(incoming[key].get(source, []))
    stack, stack_issues = stack_accesses(events, predecessors, entry, incoming)
    issues.extend(stack_issues)
    for access in stack:
        for ident in access.get("stored_values", []):
            if ident in values:
                values[ident].setdefault("stack_locations", []).append(
                    {
                        "event": access["event"],
                        "offset": access["offset"],
                        "width": access["width"],
                        "kind": access["kind"],
                        "relation": access["relation"],
                        "calls_crossed": access.get("memory_calls_crossed", []),
                    }
                )
    return {
        "status": "incomplete" if issues else "complete",
        "uncertainties": issues,
        "values": [
            values[k]
            for k in sorted(values)
            if values[k]["uses"] or values[k]["definition"] != "entry"
        ],
        "blocks": [
            {
                "id": k,
                "instruction": e["instruction"].key,
                "successors": e["successors"],
                "live_in": sorted(live_in[k]),
                "live_out": sorted(live_out[k]),
            }
            for k, e in events.items()
        ],
        "stack_accesses": stack,
        "instructions": [i.record() for i in instructions],
    }


def stack_accesses(events, predecessors, entry, reaching):
    # Abstract register addresses: exact offset from entry SP or unknown.
    outs = {k: None for k in events}
    ins = {}
    issues = []
    for iteration in range(10000):
        changed = False
        for key, e in events.items():
            sources = [outs[p] for p in predecessors[key] if outs[p] is not None]
            if key == entry:
                sources.append({"sp": 0})
            if not sources:
                continue
            state = {
                r: v
                for r, v in sources[0].items()
                if all(s.get(r) == v for s in sources)
            }
            ins[key] = state
            result = {r: v for r, v in state.items() if r not in e["defs"]}
            i = e["instruction"]
            a = i.operands
            if (
                not e["call"]
                and i.opcode in ("addiu", "addi", "daddiu")
                and reg(a[1]) in state
            ):
                result[reg(a[0])] = state[reg(a[1])] + number(a[2])
            if not e["call"] and i.opcode in ("addu", "or", "daddu"):
                other = next((reg(r) for r in a[1:] if reg(r) != "zero"), None)
                if "zero" in a[1:] and other in state:
                    result[reg(a[0])] = state[other]
            if outs[key] != result:
                outs[key] = result
                changed = True
        if not changed:
            break
    else:
        issues.append({"reason": "stack address iteration budget exhausted"})
    accesses = []
    # A reload is established only along a unique predecessor chain, stopping at
    # calls, unknown stores, overlapping writes, or cycles. No alias-complete claim.
    for key, e in events.items():
        i = e["instruction"]
        if e["call"] or i.opcode not in LOADS and i.opcode not in STORES:
            continue
        base, displacement, width = memory(i)
        offset = ins.get(key, {}).get(base)
        if offset is None:
            if base in ("sp", "s8"):
                issues.append({"instruction": key, "reason": "unknown stack base"})
            continue
        offset += displacement
        row = {
            "event": key,
            "instruction": i.key,
            "offset": offset,
            "width": width,
            "kind": "load" if i.opcode in LOADS else "store",
            "register": reg(i.operands[0]),
            "role": "argument-area-or-home" if offset >= 0 else "frame-access",
            "relation": "unclassified",
        }
        if row["kind"] == "store":
            row["stored_values"] = sorted(reaching[key].get(row["register"], []))
            if row["stored_values"] == ["entry:" + row["register"]] and row[
                "register"
            ] in REGS[16:24] + ["s8", "ra"]:
                row["role"] = "saved-register"
        else:
            cursor, seen = key, set()
            barriers = []
            calls = []
            while len(predecessors[cursor]) == 1:
                cursor = predecessors[cursor][0]
                if cursor in seen:
                    break
                seen.add(cursor)
                prev = events[cursor]
                pi = prev["instruction"]
                if prev["call"]:
                    barriers.append(
                        {"event": cursor, "reason": "unknown call memory effects"}
                    )
                    calls.append(cursor)
                    continue
                if pi.opcode in STORES:
                    pb, pd, pw = memory(pi)
                    po = ins.get(cursor, {}).get(pb)
                    if po is None:
                        barriers.append(
                            {"event": cursor, "reason": "possibly aliasing store"}
                        )
                        continue
                    po += pd
                    if po < offset + width and offset < po + pw:
                        if po == offset and pw == width:
                            row["relation"] = (
                                "possible-reload-of-store"
                                if barriers
                                else "reload-of-store"
                            )
                            row["barriers"] = barriers
                            row["memory_calls_crossed"] = list(reversed(calls))
                            row["store_event"] = cursor
                            row["stored_values"] = sorted(
                                reaching[cursor].get(reg(pi.operands[0]), [])
                            )
                        break
                elif effects(pi)[2]:
                    break
        accesses.append(row)
    return accesses, issues
