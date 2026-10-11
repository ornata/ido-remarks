"""ROM-free diagnostics regressions."""

import sys
import tempfile
import json
import hashlib
import unittest
import contextlib
import io
from itertools import product
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dataflow.ido import parse_uopt, correlate
import diagnose_candidate


class Ido(unittest.TestCase):
    def test_runner_hashes_support_both_diagnostic_consumers(self):
        for extra, remarks, scheduler in product((False, True), (None, "text", "json"), (False, True)):
            with self.subTest(extra_traces=extra, remarks=remarks, scheduler=scheduler), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                candidate, log = root / "unit.c", root / "diff.log"
                runtime, out = root / "runtime", root / "out"
                candidate.write_text("void target(void) {}")
                log.write_text(
                    "python3 tools/asm-processor/build.py -O2 tools/ido-5.3/cc "
                    "-- as -- -O2 -mips2 -o build/test.o src/test.c\n"
                )
                runtime.mkdir()
                (runtime / "uopt").write_text("fixture")
                if scheduler:
                    (runtime / "as1").write_text("assembler fixture")
                listing = b" * * 0.1 SECONDS IN global coloring OF target\n>>>active<<<{602|0} 37 -1\n"

                def run(command, **kwargs):
                    if command[0] == "python3":
                        obj = Path(command[command.index("-o") + 1])
                        obj.write_bytes(b"\x7fELFfixture")
                        if obj.stem == "diagnostic":
                            (out / "uopt.txt").write_bytes(listing)
                        elif obj.stem == "level6":
                            (out / "uopt6.txt").write_bytes(listing)
                        elif obj.stem == "ugen":
                            (out / "ugen.tree.txt").write_text("fixture")
                        elif obj.stem == "remarks":
                            self.assertEqual(kwargs["env"]["IDO_REMARKS"], remarks)
                            self.assertEqual(kwargs["env"]["IDO_REMARKS_FUNCTION"], "target")
                            kwargs["stdout"].write(
                                '{"schema":1,"pass":"ido-regalloc","function":"target"}\n' if remarks == "json"
                                else "remark: procedure #1 range 37\n"
                            )
                        if obj.stem != "remarks":
                            self.assertNotIn("IDO_REMARKS", kwargs["env"])
                            self.assertNotIn("IDO_REMARKS_FUNCTION", kwargs["env"])
                    else:
                        Path(command[-1]).write_bytes(b"identical text")

                argv = ["diagnose", str(candidate), str(log), "target",
                        "--runtime", str(runtime), "--output", str(out)]
                if extra:
                    argv.append("--extra-traces")
                if remarks:
                    argv.extend(["--remarks", remarks])
                with patch("sys.argv", argv), patch.object(
                    diagnose_candidate.subprocess, "run", side_effect=run
                ), patch.object(
                    diagnose_candidate.subprocess, "check_output", return_value="same disassembly"
                ), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(diagnose_candidate.main(), 0)
                report = json.loads((out / "report.json").read_text())
                self.assertEqual(report["uopt_sha256"], hashlib.sha256(listing).hexdigest())
                self.assertEqual(report["uopt_sha256"], report["artifacts"]["uopt.txt"])
                self.assertNotIn("-to", report["commands"]["ordinary"])
                self.assertIn("-mips2", report["commands"]["ordinary"])
                result = correlate(out, {"provenance": {"function": "target"}}, [])
                self.assertEqual(result["runs"]["level5"]["ranges"][0]["range"], 37)
                self.assertEqual("level6" in result["runs"], extra)
                if remarks:
                    self.assertEqual(report["runs"]["remarks"]["count"], 1)
                    self.assertIn("-tob" if scheduler else "-to", report["commands"]["remarks"])
                    self.assertEqual(bool(report["runtime_as1_sha256"]), scheduler)
                    if remarks == "json":
                        self.assertEqual(report["runs"]["remarks"]["scope"], "function")

    def test_procedure_scoping(self):
        text = """ * * 0.1 SECONDS IN global coloring OF target
{ 602|0} 2 isvar P 108 4vreg
>>>active<<<{602|0} 37 -1
adjsave, hasstore: 0.00000000e+00 false
firstisstr deadout needreglod needregsave false true true false
 * * 0.1 SECONDS IN global coloring OF other
>>>active<<<{602|0} 38 4
"""
        rows = parse_uopt(text, "target")["ranges"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["range"], 37)
        self.assertTrue(rows[0]["uncolored"])
        self.assertTrue(rows[0]["block_requirements"][0]["reload"])

    def test_reject_changed_or_stale_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in (
                "ordinary.text",
                "diagnostic.text",
                "ordinary.dis",
                "diagnostic.dis",
            ):
                (root / name).write_text("identical")
            (root / "uopt.txt").write_text(
                " * * 0.1 SECONDS IN global coloring OF target\n>>>active<<<{602|0} 37 -1\n"
            )
            report = {
                "status": "transparent",
                "function": "target",
                "text_equal": True,
                "disassembly_and_relocations_equal": True,
                "artifacts": {
                    p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in root.iterdir()
                },
            }
            (root / "report.json").write_text(json.dumps(report))
            candidate = {
                "provenance": {"function": "target"},
                "values": [{"id": "1000:t2", "register": "t2"}],
            }
            result = correlate(root, candidate, [{"value": "1000:t2", "range": 37}])
            self.assertTrue(result["correlations"][0]["allocation"]["uncolored"])
            with self.assertRaisesRegex(ValueError, "missing"):
                correlate(root, candidate, [{"value": "absent", "range": 37}])
            (root / "uopt.txt").write_text("changed")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                correlate(root, candidate, [])
            report["status"] = "changed"
            (root / "report.json").write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "not transparent"):
                correlate(root, candidate, [])

    def test_ugen_anchor_reads_authenticated_architectural_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("ordinary", "diagnostic", "ugen"):
                for suffix in ("text", "dis"):
                    (root / f"{name}.{suffix}").write_text("identical")
            (root / "uopt.txt").write_text(
                " * * 0.1 SECONDS IN global coloring OF target\n>>>active<<<{602|0} 37 -1\n"
            )
            trace = "current_line = 8 opc = ulod reg = xr10 ref_count = 1\n"
            (root / "ugen.log").write_text("compiler warning\n" + trace)
            # The separately emitted IR tree is deliberately not a register log.
            (root / "ugen.tree.txt").write_text("Tree dump after Build\nIR node\n")
            report = {
                "status": "transparent",
                "function": "target",
                "text_equal": True,
                "disassembly_and_relocations_equal": True,
                "runs": {"ugen": {"transparent": True}},
                "artifacts": {
                    p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in root.iterdir()
                },
            }
            (root / "report.json").write_text(json.dumps(report))
            candidate = {
                "provenance": {"function": "target"},
                "values": [{"id": "1000:t2", "register": "t2"}],
            }
            pairs = [{"value": "1000:t2", "range": 37, "ugen_line": 2}]
            result = correlate(root, candidate, pairs)
            self.assertEqual(result["correlations"][0]["ugen"], {"line": 2, "text": trace.rstrip()})
            with self.assertRaisesRegex(ValueError, "does not corroborate"):
                correlate(root, candidate, [dict(pairs[0], ugen_line=1)])
            (root / "ugen.log").write_text("compiler warning\n" + trace.replace("xr10", "xr11"))
            with self.assertRaisesRegex(ValueError, "hash mismatch: ugen.log"):
                correlate(root, candidate, pairs)


if __name__ == "__main__":
    unittest.main()
