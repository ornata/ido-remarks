import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from object_scope import function_span, pair


@unittest.skipUnless(shutil.which("mips-linux-gnu-as") and shutil.which("mips-linux-gnu-objdump"), "MIPS binutils required")
class ObjectScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.obj = self.assemble("control", "nop")

    def assemble(self, name, instruction):
        src = self.root / (name + ".s")
        obj = src.with_suffix(".o")
        src.write_text(".set noreorder\n.text\n.word 0,0\n.globl target\n.type target,@function\n"
                       "target:\n" + instruction + "\njr $ra\nnop\n.size target,.-target\n"
                       ".globl neighbor\n.type neighbor,@function\nneighbor:\njr $ra\nnop\n.size neighbor,.-neighbor\n")
        subprocess.run(["mips-linux-gnu-as", "-mabi=32", "-march=vr4300", "-o", str(obj), str(src)], check=True)
        return obj

    def test_declared_size_not_neighbors_or_padding(self):
        span = function_span(self.obj, "target")
        self.assertEqual((span["start"], span["size"], span["instructions"]), (8, 12, 3))

    def test_short_bound_is_not_complete(self):
        report = pair(self.obj, self.obj, "target", 2, self.root)
        self.assertEqual(report["status"], "bound_too_small")
        self.assertTrue(report["original"]["declared_span_disassembled"])

    def test_complete_zero_words_and_changed_candidate(self):
        candidate = self.assemble("candidate", "addiu $v0,$zero,1")
        report = pair(self.obj, candidate, "target", 3, self.root)
        self.assertEqual(report["status"], "bound_covers_declared_symbols")
        self.assertNotEqual(report["original"]["span_sha256"], report["candidate"]["span_sha256"])
        self.assertNotIn("<neighbor>", (self.root / "original-function.dis").read_text())

    def test_unknown_missing_symbol(self):
        report = pair(self.obj, self.obj, "absent", 1024, self.root)
        self.assertEqual(report["status"], "unknown")

    def test_truncated_elf_rejected(self):
        broken = self.root / "broken.o"
        broken.write_bytes(self.obj.read_bytes()[:60])
        with self.assertRaises(ValueError):
            function_span(broken, "target")


if __name__ == "__main__":
    unittest.main()
