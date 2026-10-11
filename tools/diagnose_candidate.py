#!/usr/bin/env python3
"""Inspect a saved candidate with IDO uopt, verifying diagnostic transparency.

Use unit.c and diff.log from verify_candidates.py. No working source, Makefile,
expected object, or compiler installation is modified. This diagnoses candidate
allocation; it does not prove a match or recover the original source.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
PREFIX = ["python3", "tools/asm-processor/build.py"]


def compile_command(log):
    for line in log.read_text().splitlines():
        if line.startswith("python3 tools/asm-processor/build.py "):
            command = shlex.split(line)
            if command[:2] != PREFIX or "tools/ido-5.3/cc" not in command:
                raise ValueError("Expected the repository IDO 5.3 build command")
            if command.count("-o") != 1 or not command[-1].endswith(".c"):
                raise ValueError("Ambiguous output or source in compile command")
            return command
    raise ValueError("No fresh asm-processor compile command found in log")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path, help="Saved whole-unit unit.c")
    parser.add_argument(
        "compile_log", type=Path, help="Saved diff.log containing the compile command"
    )
    parser.add_argument("function", help="Exact function symbol for uopt listing")
    parser.add_argument("--remarks", choices=("text", "json"),
                        help="Collect and verify opt-in remarks from a patched runtime")
    parser.add_argument(
        "--extra-traces",
        action="store_true",
        help="Also collect separately verified level-6 and ugen traces",
    )
    parser.add_argument("--assembler-phase", action="store_true",
                         help="Collect authenticated retained ugen assembly versus final object")
    parser.add_argument("--xbb-trace", action="store_true",
                        help="Separately verify as1 -xbbdbg 10 cross-block diagnostics")
    parser.add_argument("--ugen-symbol", type=int, help="Reviewed Uent blockno for separately transparent ugen remarks; requires --extra-traces")
    parser.add_argument("--phase-anchors", type=Path,
                        help="JSON list of explicit name/retained/final regex anchors")
    parser.add_argument(
        "--runtime",
        required=True,
        type=Path,
        help="Directory containing separately repaired IDO 5.3 uopt",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="New evidence directory outside the repository",
    )
    args = parser.parse_args()
    if args.phase_anchors and not args.assembler_phase:
        parser.error("--phase-anchors requires --assembler-phase")
    if args.ugen_symbol is not None and (args.ugen_symbol < 0 or not args.extra_traces):
        parser.error("--ugen-symbol requires a nonnegative reviewed symbol and --extra-traces")
    out = args.output.resolve()
    runtime = args.runtime.resolve()
    if ROOT == out or ROOT in out.parents:
        parser.error("Output must be outside the repository")
    if "," in str(out) or "," in str(runtime):
        parser.error("IDO pass options cannot represent paths containing commas")
    if not args.function.isidentifier():
        parser.error("Function must be an identifier")
    if not (runtime / "uopt").is_file():
        parser.error("Runtime directory must contain the repaired uopt executable")
    if args.xbb_trace and not (runtime / "as1").is_file():
        parser.error("--xbb-trace requires an as1 runtime built with --xbb-traces")
    if args.ugen_symbol is not None and not (runtime / "ugen").is_file():
        parser.error("--ugen-symbol requires a runtime built with --ugen-traces")
    try:
        command = compile_command(args.compile_log)
    except ValueError as error:
        parser.error(str(error))
    if args.remarks and (runtime / "as1").is_file():
        scheduler_hash = hashlib.sha256((runtime / "as1").read_bytes()).hexdigest()
    else:
        scheduler_hash = None
    out.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(args.candidate, out / "candidate.c")
    report = {
        "function": args.function,
        "runtime": str(runtime),
        "runtime_as1_sha256": scheduler_hash,
        "runtime_uopt_sha256": hashlib.sha256((runtime / "uopt").read_bytes()).hexdigest(),
        "candidate_sha256": hashlib.sha256(
            (out / "candidate.c").read_bytes()
        ).hexdigest(),
        "compile_log_sha256": hashlib.sha256(args.compile_log.read_bytes()).hexdigest(),
        "commands": {},
        "working_directories": {},
        "status": "incomplete",
        "runs": {},
    }
    try:
        runs = [
            ("ordinary", []),
            (
                "diagnostic",
                [
                    "-to",
                    "-h" + str(runtime) + "/",
                    "-B",
                    "-Wo,-l," + str(out / "uopt.txt") + ",-zdbug:5,-p," + args.function,
                ],
            ),
        ]
        if args.extra_traces:
            runs += [
                (
                    "level6",
                    [
                        "-to",
                        "-h" + str(runtime) + "/",
                        "-B",
                        "-Wo,-l,"
                        + str(out / "uopt6.txt")
                        + ",-zdbug:6,-p,"
                        + args.function,
                    ],
                ),
                ("ugen", ["-Wc,-d", "-Wc,-e," + str(out / "ugen.tree.txt")]),
            ]
        if args.assembler_phase:
            runs.append(("retained", ["-K"]))
        if args.xbb_trace:
            runs.append(("xbb", ["-tb", "-h" + str(runtime) + "/", "-B", "-Wb,-xbbdbg,10"]))
        if args.remarks:
            runs.append(("remarks", ["-tob" if scheduler_hash else "-to", "-h" + str(runtime) + "/", "-B"]))
        if args.ugen_symbol is not None:
            runs.append(("ugen-remarks", ["-tc", "-h" + str(runtime) + "/", "-B"]))
        for name, extra in runs:
            cmd = command.copy()
            index = cmd.index("-o")
            cmd[index + 1] = str(out / (name + ".obj"))
            cmd[-1] = str(out / "candidate.c")
            cmd[index:index] = extra
            run_cwd = ROOT
            if name == "retained":
                run_cwd = out / "retained-files"
                run_cwd.mkdir()
                # IDO -K retains files in cwd, not beside the temporary input.
                # Resolve repository paths and GLOBAL_ASM before changing cwd.
                cmd = [str(ROOT / x) if x.startswith("tools/") else
                       "-I" + str(ROOT / x[2:]) if x.startswith("-I") and not Path(x[2:]).is_absolute() else x
                       for x in cmd]
                cmd[2:2] = ["--base-dir", str(ROOT)]
            report["commands"][name] = cmd
            report["working_directories"][name] = str(run_cwd)
            env = os.environ.copy()
            env.pop("IDO_REMARKS", None)
            env.pop("IDO_REMARKS_FUNCTION", None)
            env.pop("IDO_XBB_CAPTURE", None)
            env.pop("IDO_XBB_FUNCTION", None)
            env.pop("IDO_UGEN_SYMBOL", None)
            if name == "ugen-remarks":
                env.update(IDO_REMARKS="json", IDO_REMARKS_FUNCTION=args.function, IDO_UGEN_SYMBOL=str(args.ugen_symbol))
            if name == "xbb":
                env["IDO_XBB_CAPTURE"] = "1"
                env["IDO_XBB_FUNCTION"] = args.function
            if name == "remarks":
                env["IDO_REMARKS"] = args.remarks
                env["IDO_REMARKS_FUNCTION"] = args.function
            with (out / (name + ".log")).open("w") as log:
                subprocess.run(cmd, cwd=run_cwd, env=env, stdout=log, stderr=log, check=True)
            # Some IDO passes can fail with exit zero; require the new ELF output.
            obj = out / (name + ".obj")
            if not obj.is_file() or obj.read_bytes()[:4] != b"\x7fELF":
                raise RuntimeError(
                    "Compiler did not produce a fresh ELF object: " + name
                )
            subprocess.run(
                [
                    "mips-linux-gnu-objcopy",
                    "-O",
                    "binary",
                    "-j",
                    ".text",
                    str(obj),
                    str(out / (name + ".text")),
                ],
                check=True,
            )
            dis = subprocess.check_output(
                ["mips-linux-gnu-objdump", "-dr", str(obj)], text=True
            )
            # Only the file-identification line depends on the output filename.
            normalized = "\n".join(
                line for line in dis.splitlines() if "file format" not in line
            )
            (out / (name + ".dis")).write_text(normalized)
        listing = out / "uopt.txt"
        if not listing.is_file() or args.function not in listing.read_text():
            raise RuntimeError(
                "Requested function is absent from the diagnostic listing"
            )
        # Compatibility with consumers of the standalone listing hash.
        report["uopt_sha256"] = hashlib.sha256(listing.read_bytes()).hexdigest()
        report["text_equal"] = (out / "ordinary.text").read_bytes() == (
            out / "diagnostic.text"
        ).read_bytes()
        report["disassembly_and_relocations_equal"] = (
            out / "ordinary.dis"
        ).read_bytes() == (out / "diagnostic.dis").read_bytes()
        for name, _ in runs[1:]:
            equal = (out / "ordinary.text").read_bytes() == (
                out / (name + ".text")
            ).read_bytes() and (out / "ordinary.dis").read_bytes() == (
                out / (name + ".dis")
            ).read_bytes()
            report["runs"][name] = {
                "transparent": equal,
                "object_sha256": hashlib.sha256(
                    (out / (name + ".obj")).read_bytes()
                ).hexdigest(),
            }
        if args.extra_traces and (
            not (out / "uopt6.txt").is_file() or not (out / "ugen.tree.txt").is_file()
        ):
            raise RuntimeError(
                "Additional diagnostics did not produce required fresh artifacts"
            )
        if args.remarks:
            lines = (out / "remarks.log").read_text().splitlines()
            if args.remarks == "json":
                records = [json.loads(line) for line in lines if line.startswith('{"schema":1,')]
                records = [r for r in records if r.get("pass") in ("ido-regalloc", "ido-cse", "ido-scheduler")]
                (out / "remarks.json").write_text(json.dumps(records, indent=2) + "\n")
            else:
                records = [line for line in lines if line.startswith("remark:")]
            if not records:
                raise RuntimeError("Patched runtime did not emit compiler remarks")
            named = args.remarks == "json" and all(r.get("function") == args.function for r in records)
            report["runs"]["remarks"].update(format=args.remarks, count=len(records),
                                              scope="function" if named else "legacy_or_text",
                                              function_filter=args.function)
        if args.assembler_phase:
            from diagnostics.assembler_phase.report import make_report, render_markdown

            assemblies = list((out / "retained-files").glob("*.s"))
            if len(assemblies) != 1:
                raise RuntimeError("Expected exactly one freshly retained assembly file")
            anchors = json.loads(args.phase_anchors.read_text()) if args.phase_anchors else []
            phase = make_report(out / "ordinary.obj", out / "retained.obj",
                                assemblies[0], args.function, anchors)
            (out / "assembler-phase.json").write_text(json.dumps(phase, indent=2) + "\n")
            (out / "assembler-phase.md").write_text(render_markdown(phase))
        if args.xbb_trace:
            from explain_xbb import parse_xbb
            captured = parse_xbb((out / "xbb.log").read_text(), args.function)
            (out / "xbb.json").write_text(json.dumps(captured, indent=2) + "\n")
        if args.ugen_symbol is not None:
            from diagnostics.ugen_compare.compare import parse, select
            section, _, entry = select(parse((out / "ugen.tree.txt").read_text()), "op=ent,blockno=" + str(args.ugen_symbol))
            lines = (out / "ugen-remarks.log").read_text().splitlines()
            events = [json.loads(line) for line in lines if line.startswith('{"schema":1,')]
            if not events or any(e.get("pass") != "ido-ugen" or e.get("function") != args.function or e.get("procedure_ordinal") != args.ugen_symbol for e in events):
                raise RuntimeError("Missing or unscoped ugen remarks")
            (out / "ugen-remarks.json").write_text(json.dumps(events, indent=2) + "\n")
            report["runs"]["ugen-remarks"].update(format="json", scope="reviewed_Uent_symbol", symbol=args.ugen_symbol, section=section, entry=entry)
        report["status"] = (
            "transparent"
            if all(r["transparent"] for r in report["runs"].values())
            else "changed"
        )
        report["artifacts"] = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(out.iterdir())
            if p.is_file() and p.name != "report.json"
        }
    finally:
        (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "transparent" else 1


if __name__ == "__main__":
    raise SystemExit(main())
