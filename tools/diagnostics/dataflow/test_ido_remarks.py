"""ROM-free checks for the isolated recomp patch generator."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from patch_ido_remarks import (instrument, HOOK_FUNCTIONS, instrument_scheduler, SCHEDULER_FUNCTIONS)


class RemarksPatch(unittest.TestCase):
    def test_preserves_calls_and_wraps_definitions(self):
        source = "\n".join(
            f"static void f_{name}({params});\nstatic void f_{name}({params}) {{ "
            + ("f_compute_save(mem, sp, 1); }" if name == "oneproc" else "return; }")
            for name, params in HOOK_FUNCTIONS)
        source += "\nstatic uint32_t f_treekilled(uint8_t *mem, uint32_t sp, uint32_t a0) { return a0; }"
        source += "\nstatic uint32_t func_415f9c(uint8_t *mem, uint32_t sp, uint32_t v0, uint32_t a0, uint32_t a1, uint32_t a2) { return a0; }"
        patched = instrument(source)
        self.assertIn("{ f_compute_save(mem, sp, 1); }", patched)
        self.assertIn("ido_original_compute_save(mem, sp, a0);\n    ido_allocation_remark", patched)
        with self.assertRaisesRegex(ValueError, "already instrumented"):
            instrument(patched)

    def test_scheduler_preserves_abi_and_calls(self):
        source = "\n".join(f"static uint32_t {name}({params}) {{ return 9; }}"
                           for name, original, params in SCHEDULER_FUNCTIONS)
        source += "\n f_start_instruction(mem, sp, 1, 2, 3, 4);"
        patched = instrument_scheduler(source)
        self.assertIn("f_start_instruction(mem, sp, 1, 2, 3, 4);", patched)
        self.assertIn("ido_original_dependency(mem, sp, v0, a0, a1, a2, a3)", patched)
        with self.assertRaisesRegex(ValueError, "already instrumented"):
            instrument_scheduler(patched)
        with self.assertRaises(ValueError):
            instrument_scheduler(source + source)

    def test_rejects_missing_or_duplicate_definition(self):
        one = "static void f_oneproc(uint8_t *mem, uint32_t sp) { }\n"
        for source in ("", one, one * 2):
            with self.subTest(source=source), self.assertRaises(ValueError):
                instrument(source)

    def test_decision_sites_reject_generated_drift(self):
        with self.assertRaises(ValueError):
            instrument("", decisions=True)


if __name__ == "__main__":
    unittest.main()
