"""Shared artifacts and deterministic reports."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text())


def artifact(path):
    return {"path": str(Path(path).resolve()), "sha256": digest(path)}


def write_report(report, output):
    output = Path(output).resolve()
    if output == ROOT or ROOT in output.parents:
        raise ValueError("Evidence output must be outside the repository")
    output.mkdir(parents=True, exist_ok=False)
    (output / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    (output / "report.txt").write_text(render(report))
    print(render(report), end="")


def render(report):
    lines = [report["analysis"], "Status: " + report["status"]]
    for key in ("findings", "uncertainties", "suggestions"):
        for item in report.get(key, []):
            lines.append(f"{key}: {json.dumps(item, sort_keys=True)}")
    for side in ("original", "candidate"):
        body = report.get(side, {})
        if isinstance(body, dict) and "values" in body:
            lines.append(
                f"{side}: {len(body['values'])} definitions, {len(body['stack_accesses'])} stack accesses"
            )
            for value in body["values"]:
                lines.append(
                    f"  {value['id']}: uses={value['uses']} last={value['last_uses']} calls={value['calls_crossed']}"
                )
            for access in body["stack_accesses"]:
                lines.append(
                    f"  stack {access['instruction']}: {access['kind']} entrySP{access['offset']:+#x}/{access['width']} {access['register']} {access['role']} {access['relation']}"
                )
            for issue in body.get("uncertainties", []):
                lines.append(f"  uncertainty: {json.dumps(issue, sort_keys=True)}")
    for pair in report.get("pairs", []):
        lines.append(
            f"pair: {pair['original']} -> {pair['candidate']} ({pair['basis']})"
        )
    for pair in report.get("ido", {}).get("correlations", []):
        lines.append(
            f"IDO: {pair['value']} -> range {pair['range']}, uncolored={pair['allocation']['uncolored']}"
        )
    for issue in report.get("ido", {}).get("uncertainties", []):
        lines.append(f"IDO uncertainty: {issue}")
    lines.append(
        "Investigative evidence only; not semantic equivalence or byte-match acceptance."
    )
    return "\n".join(lines) + "\n"
