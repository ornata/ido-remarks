"""Synthetic instruction text only: no ROM-derived fixtures."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).resolve().parents[1] / "tools/classify_asm_diff.py"
spec = importlib.util.spec_from_file_location("classifier", TOOL)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def table(rows, score=10, source=True, previous=False):
    prefix = 7 if source else 2
    header = "TARGET".ljust(50) + (" " * prefix + f"CURRENT ({score})").ljust(50)
    if previous:
        header += " " * prefix + "PREVIOUS (999)"
    lines = [header]
    for a, b in rows:
        marker = ">" if not a else "<" if not b else " "
        cell = marker + ("   42" if source else "") + " " + b
        lines.append(a.ljust(50) + cell.ljust(50) + ("       0: nop" if previous else ""))
    return "\n".join(lines)


class ClassifierTests(unittest.TestCase):
    def test_stack_and_mixed_register(self):
        r = module.classify(table([("0: addiu sp,sp,-0x20", "0: addiu sp,sp,-0x28"),
                                   ("4: sw t0,0x18(sp)", "4: sw t1,0x1c(sp)")]))
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["counts"]["stack_frame"], 2)
        self.assertEqual(r["counts"]["register_only"], 0)

    def test_register_not_symbol_substrings(self):
        r = module.classify(table([("0: lw t0,4(a0)", "0: lw t1,4(a1)"),
                                   ("4: lui a0,%hi(data0)", "4: lui a0,%hi(data1)")]))
        self.assertEqual(r["counts"]["register_only"], 1)
        self.assertEqual(r["counts"]["other_operands"], 1)

    def test_control_flow_is_not_register_only(self):
        r = module.classify(table([("0: beq t0,t1,30 ~>", "0: beq t1,t2,34 ~>")]))
        self.assertEqual(r["counts"]["opcode_control_flow"], 1)

    def test_order_requires_identical_multisets(self):
        r = module.classify(table([("0: li t0,1", "0: li t1,2"),
                                   ("4: li t1,2", "4: li t0,1")]))
        self.assertTrue(r["instruction_multisets_equal"])
        self.assertEqual(r["counts"]["scheduling_order"], 1)
        changed = module.classify(table([("0: li t0,1", "0: li t1,2"),
                                         ("4: li t1,2", "4: li t0,3")]))
        self.assertFalse(changed["instruction_multisets_equal"])
        self.assertEqual(changed["counts"]["scheduling_order"], 0)

    def test_multiplicity_matters(self):
        r = module.classify(table([("0: nop", "0: nop"), ("4: nop", "4: li t0,1"),
                                   ("8: li t0,1", "8: li t0,1")]))
        self.assertFalse(r["instruction_multisets_equal"])

    def test_insert_delete_and_no_source_lines(self):
        r = module.classify(table([("0: nop", ""), ("", "4: li t0,1")], source=False))
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["counts"]["insert_delete"], 2)

    def test_ansi_and_previous_ignored(self):
        t = table([("0: nop", "0: nop")], score=0, previous=True)
        r = module.classify(t.replace("nop", "\x1b[31mnop\x1b[0m"))
        self.assertEqual(r["current_score"], 0)
        self.assertEqual(r["changed_rows"], 0)
        self.assertEqual(r["status"], "ok")

    def test_warning_tail_and_long_relocation(self):
        ref = ".rodata+" + ",".join(hex(i) for i in range(100))
        t = table([("0: nop", "0: nop")], score=0) + "\n" + ref + "       " + ref
        t += "\ncfe: Warning 513: header.h\n text\n ^\n"
        r = module.classify(t)
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["reference_rows"], 1)
        self.assertEqual(r["ignored_warning_lines"], 3)

    def test_changed_relocation_is_partial(self):
        t = table([("0: nop", "0: nop")]) + "\n.rodata+0x10       .rodata+0x14"
        r = module.classify(t)
        self.assertEqual(r["status"], "partial")
        self.assertIsNone(r["instruction_multisets_equal"])
        self.assertEqual(r["reference_rows"], 1)

    def test_aligned_marked_relocations_among_instructions(self):
        # Synthetic addresses, actual plain-output shape: marker i, blank
        # source line, and comma-separated section offsets after a jump table.
        t = table([("0: jr t0", "0: jr t1"), ("4: nop", "4: nop")])
        for left, right in [(".rodata+0x10,0x20", ".rodata+0x30,0x40"),
                            (".rodata+0x14", ".rodata+0x34")]:
            t += "\n" + left.ljust(50) + "i      " + right
        t += "\n" + table([("8: nop", "8: nop")]).splitlines()[1]
        r = module.classify(t)
        self.assertEqual(r["status"], "partial")
        self.assertEqual(r["reference_rows"], 2)
        self.assertEqual(r["instruction_rows"], 3)
        self.assertEqual(r["changed_rows"], 1)
        self.assertIsNone(r["instruction_multisets_equal"])
        self.assertEqual(sum(d.get("reason") == "Unclassified relocation annotation change"
                             for d in r["diagnostics"]), 2)

    def test_aligned_reference_insert_delete_and_equal(self):
        for source in (True, False):
            r = module.classify(table([("0: nop", "0: nop"),
                                      (".rodata+0x10", ".rodata+0x10")], source=source, score=0))
            self.assertEqual(r["status"], "ok")
            self.assertEqual(r["reference_rows"], 1)
            for row in [(".rodata+0x10", ""), ("", ".rodata+0x10")]:
                r = module.classify(table([("0: nop", "0: nop"), row], source=source))
                self.assertEqual(r["status"], "partial")
                self.assertEqual(r["reference_rows"], 1)

    def test_relocation_shape_does_not_hide_malformed_instruction(self):
        for row in [(".rodata+0x10", "8: nop"),
                    (".rodata+0x10", "8: ???"),
                    (".rodata+0x10 junk", ".rodata+0x20"),
                    (".rodata+0x10", ".rodata+bad")]:
            r = module.classify(table([("0: nop", "0: nop"), row]))
            self.assertEqual(r["status"], "malformed", row)
            self.assertEqual(r["reference_rows"], 0)
            self.assertTrue(any(d.get("reason") == "unsupported instruction cell"
                                for d in r["diagnostics"]))
        r = module.classify(table([("0: nop", "0: nop"),
                                   (".rodata+0x10", ".rodata+0x20"),
                                   ("8: ???", "8: nop")]))
        self.assertEqual(r["status"], "malformed")
        self.assertEqual(r["reference_rows"], 1)
        self.assertTrue(any(d.get("reason") == "unsupported instruction cell"
                            for d in r["diagnostics"]))

    def test_error_even_after_good_table(self):
        r = module.classify(table([("0: nop", "0: nop")], score=0) + "\ncfe: Error 101: bad code")
        self.assertEqual(r["status"], "compile_failure")
        self.assertIsNone(r["instruction_multisets_equal"])

    def test_missing_table_and_compile_failure(self):
        self.assertEqual(module.classify("random output")["status"], "malformed")
        self.assertEqual(module.classify("make: *** [file.o] Error 1")["status"], "compile_failure")

    def test_repeated_table_rejected(self):
        t = table([("0: nop", "0: nop")])
        self.assertEqual(module.classify(t + "\n" + t)["status"], "malformed")

    def test_partial_never_suggests_order(self):
        t = table([("0: li t0,1", "0: li t1,2"), ("4: li t1,2", "4: li t0,1")]) + "\n..."
        r = module.classify(t)
        self.assertEqual(r["status"], "partial")
        self.assertIsNone(r["instruction_multisets_equal"])
        self.assertEqual(r["counts"]["scheduling_order"], 0)

    def test_malformed_rows_not_silently_ignored(self):
        t = table([("0: nop", "0: nop")]) + "\nnot an instruction"
        self.assertEqual(module.classify(t)["status"], "malformed")
        t += "\ncfe: Warning 10: text\nmore bad text"
        self.assertEqual(module.classify(t)["status"], "malformed")

    def test_cli_multiple_inputs_and_exit_status(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "diff.log"
            p.write_text(table([("0: nop", "0: nop")], score=0))
            run = subprocess.run([sys.executable, str(TOOL), str(p), str(p)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0)
            self.assertEqual(len(json.loads(run.stdout)), 2)
            run = subprocess.run([sys.executable, str(TOOL), str(p), d + "/missing"], capture_output=True, text=True)
            self.assertEqual(run.returncode, 2)
            self.assertEqual(json.loads(run.stdout)[1]["status"], "io_error")


if __name__ == "__main__":
    unittest.main()
