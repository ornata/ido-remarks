"""ROM-free diagnostic producer test with modeled compiler/tool outputs."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('diagnose', Path(__file__).resolve().parents[1] / 'tools/diagnose_candidate.py')
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


class ProducerTests(unittest.TestCase):
    def test_generated_listing_hash_saved_without_changing_flags(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate, log, runtime, out = root / 'unit.c', root / 'diff.log', root / 'runtime', root / 'out'
            candidate.write_text('void demo(void) {}')
            log.write_text('python3 tools/asm-processor/build.py -O2 tools/ido-5.3/cc -- as -- -O2 -mips2 -o build/test.o src/test.c\n')
            runtime.mkdir()
            (runtime / 'uopt').write_text('fixture')
            listing = b'generated demo listing\n'
            def run(command, **kwargs):
                if command[0] == 'python3':
                    Path(command[command.index('-o') + 1]).write_bytes(b'\x7fELFfixture')
                    if '-to' in command:
                        (out / 'uopt.txt').write_bytes(listing)
                else:
                    Path(command[-1]).write_bytes(b'identical text')
            argv = ['diagnose', str(candidate), str(log), 'demo', '--runtime', str(runtime), '--output', str(out)]
            with patch('sys.argv', argv), patch.object(tool.subprocess, 'run', side_effect=run), \
                 patch.object(tool.subprocess, 'check_output', return_value='same disassembly'), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(tool.main(), 0)
            report = json.loads((out / 'report.json').read_text())
            self.assertEqual(report['uopt_sha256'], tool.hashlib.sha256(listing).hexdigest())
            self.assertEqual(report['status'], 'transparent')
            self.assertNotIn('-to', report['commands']['ordinary'])
            self.assertIn('-mips2', report['commands']['ordinary'])


if __name__ == '__main__':
    unittest.main()
