"""Conservative structural comparison of schema-2 Ghidra slices."""

import re
import copy

OPAQUE = {
    "memory_load",
    "memory_live_in",
    "opaque_call",
    "indirect_call",
    "indirect_effect",
    "user_operation",
}


def normalize(report):
    """Lower Ghidra pointer syntax using width-preserving integer operations.

    Original reports remain intact as evidence. Only constant placement in
    commutative integer ADD/MULT is normalized; no floating reassociation.
    """
    report = copy.deepcopy(report)
    nodes = {n["id"]: n for n in report["nodes"]}
    fresh = max(nodes, default=-1) + 1
    for n in list(nodes.values()):
        inputs = n.get("inputs", [])
        if n.get("opcode") == "PTRSUB":
            n["opcode"] = "INT_ADD"
        if (
            n.get("opcode") == "PTRADD"
            and len(inputs) == 3
            and all("node" in e for e in inputs)
        ):
            index, scale = [nodes[e["node"]] for e in inputs[1:]]
            if (
                index["varnode"]["size"] != n["varnode"]["size"]
                or scale["varnode"]["size"] != n["varnode"]["size"]
            ):
                continue
            product = {
                "id": fresh,
                "opcode": "INT_MULT",
                "varnode": dict(n["varnode"]),
                "inputs": [dict(inputs[1], input=0), dict(inputs[2], input=1)],
            }
            nodes[fresh] = product
            n["opcode"] = "INT_ADD"
            n["inputs"] = [dict(inputs[0], input=0), {"input": 1, "node": fresh}]
            fresh += 1

    def constant(edge):
        if "node" not in edge:
            return None
        node = nodes[edge["node"]]
        return (
            int(node["varnode"]["offset"], 16)
            if node.get("frontier") == "constant"
            else None
        )

    # Fixed-point removal of +0 and *1, then put constants last. Preserve sizes.
    for _ in range(len(nodes) + 1):
        changed = False
        for n in nodes.values():
            inputs = n.get("inputs", [])
            for j, e in enumerate(inputs):
                if "node" in e and nodes[e["node"]].get("opcode") == "COPY":
                    child = nodes[e["node"]]
                    if (
                        child["varnode"]["size"] == n["varnode"]["size"]
                        and child.get("inputs")
                        and child["inputs"][0].get("node") != e["node"]
                    ):
                        inputs[j] = dict(child["inputs"][0], input=e["input"])
                        changed = True
            if n.get("opcode") in ("INT_ADD", "INT_MULT") and len(inputs) == 2:
                neutral = 0 if n["opcode"] == "INT_ADD" else 1
                for j in (0, 1):
                    other = inputs[1 - j]
                    if (
                        constant(inputs[j]) == neutral
                        and "node" in other
                        and nodes[other["node"]]["varnode"]["size"]
                        == n["varnode"]["size"]
                    ):
                        n["opcode"] = "COPY"
                        n["inputs"] = [dict(other, input=0)]
                        changed = True
                        break
                else:
                    if constant(inputs[0]) is not None and constant(inputs[1]) is None:
                        n["inputs"] = [
                            dict(inputs[1], input=0),
                            dict(inputs[0], input=1),
                        ]
                        changed = True
        if not changed:
            break
    report["nodes"] = list(nodes.values())
    return report


def compare(left, right, mappings=None):
    mappings = mappings or {}
    for report in (left, right):
        if (
            report.get("schema") != 2
            or report.get("analysis") != "backward_value_dependencies"
        ):
            raise ValueError("Requires schema-2 backward dependency slices")
        ids = [n["id"] for n in report["nodes"]]
        if len(set(ids)) != len(ids):
            raise ValueError("Duplicate node IDs")
        known = set(ids)
        for edge in [report["root"]] + [
            e for n in report["nodes"] for e in n.get("inputs", [])
        ]:
            if "node" in edge and edge["node"] not in known:
                raise ValueError("Dangling dependency edge")
    left, right = normalize(left), normalize(right)
    nodes = [{n["id"]: n for n in r["nodes"]} for r in (left, right)]
    findings, uncertainties, seen = [], [], set()

    def identity(side, node):
        storage = node["varnode"]
        ident = f"{storage['space']}:{storage['offset']}:{storage['size']}"
        return mappings.get(
            "original_storage" if side == 0 else "candidate_storage", {}
        ).get(ident)

    def strip(side, edge):
        visited = set()
        while "node" in edge and edge["node"] not in visited:
            visited.add(edge["node"])
            n = nodes[side][edge["node"]]
            inputs = n.get("inputs", [])
            if n.get("opcode") != "COPY" or len(inputs) != 1 or "node" not in inputs[0]:
                break
            child = nodes[side][inputs[0]["node"]]
            if n["varnode"]["size"] != child["varnode"]["size"]:
                break
            edge = inputs[0]
        return edge

    def issue(path, reason, a=None, b=None):
        uncertainties.append(
            {"path": path, "reason": reason, "original": a, "candidate": b}
        )

    def difference(path, reason, a, b):
        findings.append({"path": path, "reason": reason, "original": a, "candidate": b})

    def walk(a, b, path):
        a, b = strip(0, a), strip(1, b)
        if "node" not in a or "node" not in b:
            issue(path, "traversal frontier", a, b)
            return
        pair = (a["node"], b["node"])
        if pair in seen:
            if a.get("cycle") or b.get("cycle"):
                issue(path, "loop-carried cycle")
            return
        seen.add(pair)
        x, y = nodes[0][pair[0]], nodes[1][pair[1]]
        sx, sy = x["varnode"]["size"], y["varnode"]["size"]
        if sx != sy:
            difference(path, "value/access width", sx, sy)
        fx, fy = x.get("frontier"), y.get("frontier")
        if fx != fy:
            difference(path, "frontier kind", fx, fy)
        ox, oy = x.get("opcode"), y.get("opcode")
        if ox != oy:
            difference(path, "operation (including signedness/conversion)", ox, oy)

            def load_contract(side, node):
                extension = None
                if (
                    node.get("opcode") in ("INT_SEXT", "INT_ZEXT")
                    and len(node.get("inputs", [])) == 1
                    and "node" in node["inputs"][0]
                ):
                    extension = node["opcode"]
                    node = nodes[side][node["inputs"][0]["node"]]
                if node.get("opcode") == "LOAD":
                    return {"bytes": node["varnode"]["size"], "extension": extension}

            lx, ly = load_contract(0, x), load_contract(1, y)
            if lx and ly and lx != ly:
                difference(path, "load contract", lx, ly)
            # Different operators have different operand roles. Do not manufacture
            # deeper differences by zipping unrelated operands.
            return
        if fx == fy == "constant":
            vx, vy = int(x["varnode"]["offset"], 16), int(y["varnode"]["offset"], 16)
            mx, my = identity(0, x), identity(1, y)
            if vx != vy and not (mx is not None and mx == my):
                difference(path, "constant bit pattern", hex(vx), hex(vy))
        elif fx == fy == "parameter_or_live_in":
            mx, my = identity(0, x), identity(1, y)
            if mx is None or my is None:
                issue(
                    path,
                    "live-in correspondence requires an explicit mapping",
                    x["varnode"],
                    y["varnode"],
                )
            elif mx != my:
                difference(path, "mapped input", mx, my)
        if fx in OPAQUE or fy in OPAQUE:
            issue(path, "unknown contents/effects remain unresolved", fx, fy)
            if fx == fy == "memory_live_in":
                mx, my = identity(0, x), identity(1, y)
                if mx is None or my is None:
                    issue(path, "global correspondence requires an explicit mapping")
                elif mx != my:
                    difference(path, "mapped global", mx, my)
        if ox == "MULTIEQUAL" or oy == "MULTIEQUAL":
            issue(
                path,
                "branch predicates and predecessor correspondence are not verified",
                x.get("predecessors"),
                y.get("predecessors"),
            )
            # Operand order need not match across CFGs; do not invent divergences.
            return
        # Physical load widths provide a cross-check when the bundle identifies one load.
        for node in (x, y):
            loads = []
            for ins in node.get("physical_evidence", []):
                match = re.match(r"(lb|lbu|lh|lhu|lw|lwu|ld)\b", ins["assembly"])
                if match:
                    loads.append(match[1])
            if node.get("opcode") == "LOAD" and len(loads) == 1:
                width = {
                    "lb": 1,
                    "lbu": 1,
                    "lh": 2,
                    "lhu": 2,
                    "lw": 4,
                    "lwu": 4,
                    "ld": 8,
                }[loads[0]]
                if width != node["varnode"]["size"]:
                    issue(
                        path,
                        "physical load and p-code width disagree",
                        loads[0],
                        node["varnode"]["size"],
                    )
        ix, iy = x.get("inputs", []), y.get("inputs", [])
        if len(ix) != len(iy):
            difference(path, "dependency count", len(ix), len(iy))
            return
        for a1, b1 in zip(ix, iy):
            walk(a1, b1, path + "/" + str(a1["input"]))

    walk(left["root"], right["root"], "root")
    if left.get("truncated") or right.get("truncated"):
        issue("root", "slice budget exhausted")
    structural = (
        "different dependency structure"
        if findings
        else ("inconclusive" if uncertainties else "same dependency structure")
    )
    return {
        "schema": 1,
        "analysis": "dependency_comparison",
        "status": structural,
        "findings": findings,
        "uncertainties": uncertainties,
        "scope": "Data dependencies at selected roots; no memory-value or semantic equivalence proof.",
    }
