#!/usr/bin/env python3
"""Build isolated IDO 5.3 uopt/as1 and optional ugen decision-observation runtimes.

Requires the v1.2 static-recomp tree with its ecvt repair already built.
Does not edit that tree or the repository's pinned compiler.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess

GUEST_SHA256 = "a4dc9b9b20845889f60d9c0dda307569f9f66fd44419aab33693f0d5430aaaf2"

HOOK_PATH = Path(__file__).resolve().parent / "diagnostics/ido_remarks_hooks.c"
HOOK_FUNCTIONS = (
    ("oneproc", "uint8_t *mem, uint32_t sp"),
    ("compute_save", "uint8_t *mem, uint32_t sp, uint32_t a0"),
    ("globalcolor", "uint8_t *mem, uint32_t sp"),
    ("spilltemps", "uint8_t *mem, uint32_t sp"),
    ("spilltemplodstr", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2"),
    ("split", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3"),
    ("reemit", "uint8_t *mem, uint32_t sp"),
    ("increasecount", "uint8_t *mem, uint32_t sp, uint32_t a0"),
    ("checkexp_ant_av", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1"),
    ("updateforbidden", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3"),
    ("codemotion", "uint8_t *mem, uint32_t sp"),
    ("gen_cvtl", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1"),
    ("createcvtl", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1"),
    ("readnxtinst", "uint8_t *mem, uint32_t sp"),
)

AS1_GUEST_SHA256 = "c5da7675f8d15f5e4f2400fad89778a586f10ec0996c637b9b87b7fe5c86310a"
SCHEDULER_HOOK_PATH = HOOK_PATH.with_name("ido_scheduler_hooks.c")
SCHEDULER_FUNCTIONS = (
    ("f_reorganize_bb", "reorganize_bb", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1"),
    ("f_start_time", "start_time", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3"),
    ("f_start_instruction", "start_instruction", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3"),
    ("f_is_node_better", "is_node_better", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3"),
    ("func_42d698", "dependency", "uint8_t *mem, uint32_t sp, uint32_t v0, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3"),
)
UGEN_GUEST_SHA256 = "4d6ae5a5ea8a6ee77bfcc4c95195800823d4b1217e757cc516e219d05bbf5345"
UGEN_FUNCTIONS = (
    ("build_tree", "uint8_t *mem, uint32_t sp, uint32_t a0", "uint32_t"),
    ("translate_tree", "uint8_t *mem, uint32_t sp, uint32_t a0", "uint32_t"),
    ("translate", "uint8_t *mem, uint32_t sp, uint32_t a0", "uint32_t"),
    ("get_reg", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2", "void"),
    ("eval", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1", "void"),
    ("fill_reg", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3", "void"),
)
XBB_FUNCTIONS = (
    ("func_4287c8", "xbb_sets", "uint8_t *mem, uint32_t sp, uint32_t a0", "void"),
    ("func_428fc4", "xbb_weights", "uint8_t *mem, uint32_t sp, uint32_t a0", "void"),
    ("func_428a2c", "xbb_dominators", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1", "void"),
    ("func_429534", "xbb_postdominators", "uint8_t *mem, uint32_t sp", "void"),
    ("func_42aa0c", "xbb_moves", "uint8_t *mem, uint32_t sp", "void"),
    ("func_42b51c", "xbb_cleanup", "uint8_t *mem, uint32_t sp", "void"),
    ("func_42a028", "xbb_proposal", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3", "uint32_t"),
    ("f_reschedule", "xbb_reschedule", "uint8_t *mem, uint32_t sp, uint32_t a0", "uint32_t"),
)
DEFINITION_FUNCTIONS = (
    ("codeimage", "uint8_t *mem, uint32_t sp", "void"),
    ("makelivranges", "uint8_t *mem, uint32_t sp", "void"),
    ("formlivbb", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2", "void"),
    ("newbit", "uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1", "uint32_t"),
)


def score_sites(source):
    start = source.index("static uint32_t f_is_node_better(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3) {")
    end = source.index("\nstatic ", start + 1)
    body = source[start:end]
    old = "L424a94:\nt9 = lo;\nt1 = t7 + t9;\nv0 = (int)t1 < (int)t0;"
    if body.count(old) != 1:
        raise ValueError("Unsupported scheduler score comparison site")
    body = body.replace(old, old.replace("v0 =", "ido_scheduler_score(mem, MEM_U32(sp + 48), MEM_U32(sp + 52), t0, t1);\nv0 ="))
    source = source[:start] + body + source[end:]
    old = "L4342dc:\nif (s4 == 0) {"
    if source.count(old) != 1:
        raise ValueError("Unsupported ready-list comparison site")
    source = source.replace(old, "L4342dc:\nido_ready_comparison(mem, s2, s4, s3, fp, s0, MEM_U32(sp + 124), s1, MEM_U32(sp + 128));\nif (s4 == 0) {")
    return ("#include <stdint.h>\nstatic void ido_scheduler_score(uint8_t *, uint32_t, uint32_t, uint32_t, uint32_t);\n"
            "static void ido_ready_comparison(uint8_t *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);\n" + source)


def xbb_sites(source):
    """Observe exact pinned branch tests without changing guest control flow."""
    start = source.index("static void func_42aa0c(uint8_t *mem, uint32_t sp) {")
    end = source.index("\nstatic ", start + 1)
    body = source[start:end]
    old = "s3 = MEM_U32(t2 + 0);\n//nop;\nt3 = MEM_U32(s3 + 68);"
    if body.count(old) != 1:
        raise ValueError("Unsupported xbb block candidate site")
    body = body.replace(old, "s3 = MEM_U32(t2 + 0);\nido_xbb_block_check(mem, s3, s4);\n//nop;\nt3 = MEM_U32(s3 + 68);")
    for old, reason in (
        ("if ((int)t6 < 0) {\nt4 = MEM_U32(sp + 164);\ngoto L42b220;}", "source_flag_0x20_set"),
        ("at = (int)t7 < (int)t1;\nif (at == 0) {\nt1 = 0x1;\ngoto L42b23c;}", "weight_limit"),
        ("if (t3 == 0) {\nt9 = v0 << 2;\ngoto L42b21c;}", "dominator_filter"),
    ):
        if body.count(old) != 1:
            raise ValueError("Unsupported xbb block rejection site")
        body = body.replace(old, old.replace("{\n", '{\nido_xbb_instruction_reject(mem, s3, s4, 0, 0, "' + reason + '");\n', 1))
    source = source[:start] + body + source[end:]
    start = source.index("static uint32_t func_42a028(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3) {")
    end = source.index("\nstatic ", start + 1)
    body = source[start:end]
    for old, reason in (("t1 = MEM_U8(s0 + 34);\n//nop;\nif (t1 == 0) {\n//nop;\ngoto L42a378;}", "instruction_flag_34_clear"),
                        ("t9 = MEM_U8(s0 + 33);\na3 = sp + 0x70;\nif (t9 != 0) {\n//nop;\ngoto L42a378;}", "instruction_flag_33_set")):
        if body.count(old) != 1:
            raise ValueError("Unsupported xbb instruction rejection site")
        body = body.replace(old, old.replace("goto L42a378;}", 'ido_xbb_instruction_reject(mem, s1, s6, s2, MEM_U32(s0), "' + reason + '");\ngoto L42a378;}'))
    declarations = ("#include <stdint.h>\nstatic void ido_xbb_block_check(uint8_t *, uint32_t, uint32_t);\n"
                    "static void ido_xbb_instruction_reject(uint8_t *, uint32_t, uint32_t, uint32_t, uint32_t, const char *);\n")
    return declarations + source[:start] + body + source[end:]


def instrument_ugen(source):
    if "ido_ugen_begin" in source:
        raise ValueError("Source is already instrumented")
    for name, parameters, result in UGEN_FUNCTIONS:
        signature = f"static {result} f_{name}({parameters}) {{"
        if source.count(signature) != 1:
            raise ValueError("Unsupported ugen function: " + name)
        source = source.replace(signature, signature.replace("f_" + name, "ido_original_" + name))
    return source + HOOK_PATH.with_name("ido_ugen_hooks.c").read_text()


def instrument_scheduler(source, xbb=False, scores=False):
    if "ido_scheduler_begin" in source:
        raise ValueError("Source is already instrumented")
    if scores:
        source = score_sites(source)
    for name, original, parameters in SCHEDULER_FUNCTIONS:
        signature = f"static uint32_t {name}({parameters}) {{"
        if source.count(signature) != 1:
            raise ValueError("Unexpected generated scheduler function: " + name)
        source = source.replace(signature, signature.replace(name, "ido_original_" + original))
    if xbb:
        source = xbb_sites(source)
        for name, original, params, result in XBB_FUNCTIONS:
            signature = f"static {result} {name}({params}) {{"
            if source.count(signature) != 1:
                raise ValueError("Unsupported xbb function: " + name)
            source = source.replace(signature, signature.replace(name, "ido_original_" + original))
        signature = "static void f_do_xbb_opt(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1) {"
        if source.count(signature) != 1:
            raise ValueError("Unsupported xbb function")
        source = source.replace(signature, signature.replace("f_do_xbb_opt", "ido_original_xbb"))
        source += SCHEDULER_HOOK_PATH.read_text()
        return source + SCHEDULER_HOOK_PATH.with_name("ido_xbb_hooks.c").read_text()
    return source + SCHEDULER_HOOK_PATH.read_text()


def decision_sites(source):
    """Pinned generated-code sites. Reject drift rather than guess local registers."""
    start = source.index("static void f_addadjacents(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3) {")
    end = source.index("\nstatic ", start + 1)
    body = source[start:end]
    anchor = "L46e2e0:\n"
    if body.count(anchor) != 1:
        raise ValueError("Unsupported addadjacents decision site")
    body = body.replace(anchor, anchor + "ido_adjacency(mem, s5, s2, MEM_U32(s1), s6, s4);\n")
    source = source[:start] + body + source[end:]
    start = source.index("static void f_globalcolor(uint8_t *mem, uint32_t sp) {")
    end = source.index("\nstatic ", start + 1)
    body = source[start:end]
    phases = {"6": "discard_nonpositive", "5": "constrained", "8": "unconstrained"}
    body, count = re.subn(r"(MEM_U8\(s5 \+ 32\) = \(uint8_t\)t([568]);)",
                         lambda m: m[1] + '\nido_choice(mem, s5, "' + phases[m[2]] + '");', body)
    if count != 6:
        raise ValueError("Unsupported globalcolor assignment sites")
    for old, new in (
        ("MEM_U32(s1 + 44) = t5;\nMEM_U32(s1 + 40) = t6;", "ido_interference_origin(mem, s5, s1, t9, t4, t6, t5);"),
        ("MEM_U32(s1 + 44) = t6;\nMEM_U32(s1 + 40) = t3;", "ido_interference_origin(mem, s5, s1, t7, t0, t3, t6);"),
    ):
        if body.count(old) != 1:
            raise ValueError("Unsupported interference forbidden site")
        body = body.replace(old, old + "\n" + new)
    source = source[:start] + body + source[end:]
    start = source.index("static void f_localcolor(uint8_t *mem, uint32_t sp) {")
    end = source.index("\nstatic ", start + 1)
    body = source[start:end]
    old = "MEM_U32(v0 + 48) = t8;\nMEM_U32(v0 + 44) = t4;\nL46cc34:"
    if body.count(old) != 1:
        raise ValueError("Unsupported return-range reservation site")
    body = body.replace(old, "MEM_U32(v0 + 48) = t8;\nMEM_U32(v0 + 44) = t4;\nido_return_origin(mem, t7, s6, s5, t9, t0, t4, t8);\nL46cc34:")
    source = source[:start] + body + source[end:]
    start = source.index("static void f_split(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3) {")
    end = source.index("\nstatic ", start + 1)
    body = source[start:end]
    old = "MEM_U32(t1 + 36) = v0;\na2 = 0x100226a8;"
    if body.count(old) != 1:
        raise ValueError("Unsupported split seed site")
    body = body.replace(old, "MEM_U32(t1 + 36) = v0;\nido_seed_selected(mem, MEM_U32(s2), MEM_U32(s1), s0);\na2 = 0x100226a8;")
    declarations = ("#include <stdint.h>\nstatic void ido_adjacency(uint8_t *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);\n"
                    "static void ido_choice(uint8_t *, uint32_t, const char *);\n"
                    "static void ido_interference_origin(uint8_t *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);\n"
                    "static void ido_return_origin(uint8_t *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);\n"
                    "static void ido_seed_selected(uint8_t *, uint32_t, uint32_t, uint32_t);\n")
    return declarations + source[:start] + body + source[end:]


def instrument(source, decisions=False, definitions=False):
    if "ido_allocation_remark" in source:
        raise ValueError("Source is already instrumented")
    if decisions:
        source = decision_sites(source)
    for name, parameters in HOOK_FUNCTIONS:
        signature = f"static void f_{name}({parameters}) {{"
        if source.count(signature) != 1:
            raise ValueError("Unexpected generated function: " + name)
        source = source.replace(signature, signature.replace("f_" + name, "ido_original_" + name))
    signature = "static uint32_t f_treekilled(uint8_t *mem, uint32_t sp, uint32_t a0) {"
    if source.count(signature) != 1:
        raise ValueError("Unexpected generated function: treekilled")
    source = source.replace(signature, signature.replace("f_treekilled", "ido_original_treekilled"))
    signature = "static uint32_t func_415f9c(uint8_t *mem, uint32_t sp, uint32_t v0, uint32_t a0, uint32_t a1, uint32_t a2) {"
    if source.count(signature) != 1:
        raise ValueError("Unsupported add_cvtl ABI")
    source = source.replace(signature, signature.replace("func_415f9c", "ido_original_add_cvtl"))
    if definitions:
        for name, params, result in DEFINITION_FUNCTIONS:
            signature = f"static {result} f_{name}({params}) {{"
            if source.count(signature) != 1:
                raise ValueError("Unsupported definition hook: " + name)
            source = source.replace(signature, signature.replace("f_" + name, "ido_original_" + name))
        return "#define IDO_DEFINITION_TRACES 1\n" + source + HOOK_PATH.read_text() + HOOK_PATH.with_name("ido_definition_hooks.c").read_text()
    return source + HOOK_PATH.read_text()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("recomp", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="New external directory")
    parser.add_argument("--decision-traces", action="store_true", help="Pinned split BFS and coloring sites; fail on generated-source drift")
    parser.add_argument("--xbb-traces", action="store_true", help="Add named scope boundaries for as1's xbb debug stream")
    parser.add_argument("--ugen-traces", action="store_true", help="Build read-only translation/conversion/register observations")
    parser.add_argument("--definition-traces", action="store_true", help="Observe ucode definitions, bit/range creation and actual scheduler scores")
    args = parser.parse_args()
    root, out = args.recomp.resolve(), args.output.resolve()
    repo = Path(__file__).resolve().parent.parent
    if out == repo or repo in out.parents or out == root or root in out.parents:
        parser.error("Output must be outside the repository and recomp tree")
    guest = root / "ido/5.3/usr/lib/uopt"
    if hashlib.sha256(guest.read_bytes()).hexdigest() != GUEST_SHA256:
        parser.error("Unsupported guest uopt; field offsets are specific to IDO 5.3")
    if hashlib.sha256((root / "ido/5.3/usr/lib/as1").read_bytes()).hexdigest() != AS1_GUEST_SHA256:
        parser.error("Unsupported guest as1; scheduler offsets are specific to IDO 5.3")
    generated = root / "build/5.3/uopt.c"
    source = instrument(generated.read_text(), decisions=args.decision_traces, definitions=args.definition_traces)
    scheduler_generated = root / "build/5.3/as1.c"
    scheduler_source = instrument_scheduler(scheduler_generated.read_text(), xbb=args.xbb_traces, scores=args.definition_traces)
    ugen_metadata = None
    if args.ugen_traces:
        if hashlib.sha256((root / "ido/5.3/usr/lib/ugen").read_bytes()).hexdigest() != UGEN_GUEST_SHA256:
            parser.error("Unsupported guest ugen")
        ugen_generated = root / "build/5.3/ugen.c"
        ugen_source = instrument_ugen(ugen_generated.read_text())
    out.mkdir(parents=True, exist_ok=False)
    (out / "uopt.c").write_text(source)
    command = ["cc", "-std=c11", "-Og", "-fno-strict-aliasing", "-I" + str(root),
               str(out / "uopt.c"),
               str(root / "build/5.3/libc_impl.o"),
               str(root / "build/5.3/version_info.o"), "-lm", "-o", str(out / "uopt")]
    subprocess.run(command, check=True)
    (out / "as1.c").write_text(scheduler_source)
    scheduler_command = [str(out / "as1.c") if x == str(out / "uopt.c") else
                         str(out / "as1") if x == str(out / "uopt") else x for x in command]
    subprocess.run(scheduler_command, check=True)
    if args.ugen_traces:
        (out / "ugen.c").write_text(ugen_source)
        ugen_command = [str(out / "ugen.c") if x == str(out / "uopt.c") else str(out / "ugen") if x == str(out / "uopt") else x for x in command]
        subprocess.run(ugen_command, check=True)
        ugen_metadata = {"guest_sha256": UGEN_GUEST_SHA256, "generated_source_sha256": hashlib.sha256(ugen_generated.read_bytes()).hexdigest(),
                         "hooks_sha256": hashlib.sha256(HOOK_PATH.with_name("ido_ugen_hooks.c").read_bytes()).hexdigest(),
                         "instrumented_source_sha256": hashlib.sha256(ugen_source.encode()).hexdigest(),
                         "runtime_sha256": hashlib.sha256((out / "ugen").read_bytes()).hexdigest(), "command": ugen_command}
    (out / "build.json").write_text(json.dumps({
        "ugen": ugen_metadata,
        "assembler": {
            "score_traces": args.definition_traces,
            "xbb_traces": args.xbb_traces,
            "xbb_hooks_sha256": hashlib.sha256(SCHEDULER_HOOK_PATH.with_name("ido_xbb_hooks.c").read_bytes()).hexdigest() if args.xbb_traces else None,
            "guest_sha256": AS1_GUEST_SHA256,
            "hooks_sha256": hashlib.sha256(SCHEDULER_HOOK_PATH.read_bytes()).hexdigest(),
            "generated_source_sha256": hashlib.sha256(scheduler_generated.read_bytes()).hexdigest(),
            "instrumented_source_sha256": hashlib.sha256(scheduler_source.encode()).hexdigest(),
            "runtime_sha256": hashlib.sha256((out / "as1").read_bytes()).hexdigest(),
            "command": scheduler_command,
        },
        "guest_sha256": GUEST_SHA256,
        "decision_traces": args.decision_traces,
        "definition_traces": args.definition_traces,
        "definition_hooks_sha256": hashlib.sha256(HOOK_PATH.with_name("ido_definition_hooks.c").read_bytes()).hexdigest() if args.definition_traces else None,
        "hooks_sha256": hashlib.sha256(HOOK_PATH.read_bytes()).hexdigest(),
        "linked_objects": {name: hashlib.sha256((root / "build/5.3" / name).read_bytes()).hexdigest()
                           for name in ("libc_impl.o", "version_info.o")},
        "generated_source_sha256": hashlib.sha256(generated.read_bytes()).hexdigest(),
        "instrumented_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "runtime_sha256": hashlib.sha256((out / "uopt").read_bytes()).hexdigest(),
        "command": command,
    }, indent=2) + "\n")
    print(out / "uopt")


if __name__ == "__main__":
    main()
