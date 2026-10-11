"""Boundary suggestions and explicit per-site observation auditing."""

from .machine import LOADS, BRANCHES, number, reg


def suggestions(instructions, fixture=None):
    fixture = fixture or {}
    results = []

    def add(i, operand, bits, conditions, reason):
        site = fixture.get("sites", {}).get(i.key, {})
        for condition, value in conditions:
            results.append(
                {
                    "id": f"{i.key}:{operand}:{condition}",
                    "instruction": i.key,
                    "assembly": i.record(),
                    "operand": operand,
                    "bits": bits,
                    "condition": condition,
                    "proposed_value": value,
                    "input": site.get("inputs", {}).get(operand),
                    "reason": reason,
                    "coverage": "unknown",
                    "case_ids": [],
                }
            )

    for i in instructions:
        op, a = i.opcode, i.operands
        if op in LOADS:
            width, signed = LOADS[op]
            if signed and width <= 4:
                bits = width * 8
                add(
                    i,
                    "result",
                    bits,
                    [
                        ("negative", -1),
                        ("zero", 0),
                        ("positive", 1),
                        (f"eq:{-(1 << (bits - 1))}", -(1 << (bits - 1))),
                        (f"eq:{(1 << (bits - 1)) - 1}", (1 << (bits - 1)) - 1),
                    ],
                    "signed load boundary",
                )
        elif op in ("andi", "sll", "srl", "sra"):
            operand = reg(a[1])
            amount = number(a[2])
            conditions = [
                ("zero", 0),
                ("high-bit", 0x80000000),
                ("odd", 1),
                ("even-nonzero", 2),
            ]
            if op == "andi":
                for bit in range(16):
                    if amount & (1 << bit):
                        conditions.append((f"bit:{bit}", 1 << bit))
                if amount < 0xFFFF:
                    conditions.append((f"eq:{amount + 1}", amount + 1))
            elif 0 < amount < 32:
                conditions += [
                    (f"eq:{(1 << amount) - 1}", (1 << amount) - 1),
                    (f"eq:{1 << amount}", 1 << amount),
                    (f"eq:{(1 << amount) + 1}", (1 << amount) + 1),
                ]
            add(
                i,
                operand,
                32,
                conditions,
                "mask/shift boundary; preserve surrounding operation order",
            )
        elif op in (
            "slt",
            "sltu",
            "slti",
            "sltiu",
            "beq",
            "bne",
            "bgez",
            "bltz",
            "blez",
            "bgtz",
            "beql",
            "bnel",
        ):
            if op in ("slti", "sltiu"):
                operand, threshold = reg(a[1]), number(a[2])
            elif op in ("slt", "sltu"):
                operand, threshold = reg(a[1]), None
            else:
                operand = reg(a[0])
                threshold = 0 if len(a) == 2 or reg(a[1]) == "zero" else None
            conditions = [
                ("negative", -1),
                ("zero", 0),
                ("positive", 1),
                ("high-bit", 0x80000000),
            ]
            if threshold is not None:
                conditions += [
                    (f"eq:{threshold + d}", threshold + d) for d in (-1, 0, 1)
                ]
            add(
                i,
                operand,
                32,
                conditions,
                "comparison boundary"
                if threshold is not None
                else "comparison operand; counterpart and input provenance required",
            )
        elif op in ("div", "divu") or op.startswith(
            ("cvt.", "trunc.", "round.", "floor.", "ceil.")
        ):
            operand = reg(a[-2] if op in ("div", "divu") else a[-1])
            # Integer-source conversions can be classified as bit patterns; floating
            # inputs require a rounding-mode-aware adapter, not integer guesses.
            if op.endswith((".s", ".d")):
                add(
                    i,
                    operand,
                    32,
                    [("adapter-required", None)],
                    "floating conversion requires numeric values and rounding-mode observations",
                )
            else:
                add(
                    i,
                    operand,
                    32,
                    [
                        ("negative", -1),
                        ("zero", 0),
                        ("odd", 1),
                        ("even-nonzero", 2),
                        ("high-bit", 0x80000000),
                    ],
                    "integer division/conversion boundary; do not replace truncation with rounding",
                )
        if op in BRANCHES and not op.startswith("bc1"):
            add(
                i,
                "branch_taken",
                1,
                [("eq:0", 0), ("eq:1", 1)],
                "both conditional branch outcomes",
            )
    for result in results:
        domain = fixture.get("inputs", {}).get(result.get("input"), {})
        if domain:
            result["input_domain"] = domain
            value = result["proposed_value"]
            result["outside_declared_domain"] = isinstance(value, int) and (
                value < domain.get("min", value) or value > domain.get("max", value)
            )
    # Fixtures may name a compound operation requirement after auditing its dataflow.
    for requirement in fixture.get("requirements", []):
        results.append({**requirement, "coverage": "unknown", "case_ids": []})
    return results


def matches(value, condition, bits):
    if not isinstance(value, int):
        return False
    raw = value & ((1 << bits) - 1)
    signed = raw - (1 << bits) if raw & (1 << (bits - 1)) else raw
    if condition == "negative":
        return signed < 0
    if condition == "positive":
        return signed > 0
    if condition == "zero":
        return raw == 0
    if condition == "odd":
        return bool(raw & 1)
    if condition == "even-nonzero":
        return raw != 0 and not raw & 1
    if condition == "high-bit":
        return bool(raw & (1 << (bits - 1)))
    if condition.startswith("eq:"):
        return raw == (int(condition[3:]) & ((1 << bits) - 1))
    if condition.startswith("bit:"):
        return bool(raw & (1 << int(condition[4:])))
    return False


def audit(requirements, observations, artifact_sha256, fixture):
    issues = []
    for case in observations:
        if case.get("schema") != 1 or case.get("artifact_sha256") != artifact_sha256:
            raise ValueError(
                "Observation schema or artifact identity does not match analysis input"
            )
        if not isinstance(case.get("case_id"), str) or not isinstance(
            case.get("inputs"), dict
        ):
            raise ValueError("Observation requires case_id and inputs")
        if not case.get("completed"):
            issues.append(
                {
                    "case_id": case["case_id"],
                    "reason": "partial execution cannot satisfy coverage",
                }
            )
    for r in requirements:
        observed, supplied, available = [], [], False
        for case in observations:
            if r.get("input") and matches(
                case["inputs"].get(r["input"]), r["condition"], r["bits"]
            ):
                supplied.append(case["case_id"])
            if not case.get("completed"):
                continue
            for observation in case.get("observations", []):
                if (
                    observation.get("instruction") != r["instruction"]
                    or observation.get("scope") != "executed"
                ):
                    continue
                operands = observation.get("operands", {})
                if r["operand"] not in operands:
                    continue
                available = True
                if matches(operands[r["operand"]], r["condition"], r["bits"]):
                    observed.append(case["case_id"])
        r["coverage"] = (
            "condition observed"
            if observed
            else (
                "input supplied"
                if supplied
                else ("not observed" if available else "unknown")
            )
        )
        r["case_ids"] = sorted(set(observed or supplied))
        r["observation_available"] = available
        r["scope"] = (
            fixture.get("sites", {})
            .get(r["instruction"], {})
            .get("scope", "unspecified")
        )
    return issues
