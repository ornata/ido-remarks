"""ROM-free evidence consistency and bounded-format parser tests."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import explain_near_match as tool

LISTING = ''' * * 0.1 SECONDS IN LOCAL OPTIMIZATION OF demo
{ 12|0} 3 isvar M 2 -16vreg
 * * 0.1 SECONDS IN global coloring OF demo
>>>active<<<{12|0} 3 14
adjsave, hasstore: 2.000000e+00 true
>>>active<<<{12|0} 10 -1
adjsave, hasstore:-5.000000e-01 false
 * * 0.1 SECONDS IN REEMISSION OF demo
 * * 0.1 SECONDS IN LOCAL OPTIMIZATION OF neighbor
>>>active<<<{22|0} 4 20
 * * 0.1 SECONDS IN REEMISSION OF neighbor
'''
DIFF = 'TARGET'.ljust(50) + '  CURRENT (10)\n' + '0: addiu sp,sp,-0x20'.ljust(50) + '  0: addiu sp,sp,-0x28\n'


class ExplainTests(unittest.TestCase):
    def test_scoping_and_split_identity(self):
        rows = tool.allocations(LISTING, 'demo')['ranges']
        self.assertEqual([r['range_bit'] for r in rows], [3, 10])
        self.assertEqual(rows[0]['recorded_variable']['offset'], -16)
        self.assertEqual(rows[1]['internal_register'], -1)
        self.assertEqual(rows[1]['adjusted_saving'], -.5)

    def test_missing_duplicate_and_interleaved_scope(self):
        for text, name in [(LISTING, 'absent'), (LISTING + LISTING, 'demo'),
                           (LISTING.replace('global coloring OF demo', 'global coloring OF other'), 'demo')]:
            with self.subTest(name=name, text=text), self.assertRaises(ValueError):
                tool.allocations(text, name)

    def test_unsupported_or_missing_allocation(self):
        for text in [LISTING.replace('>>>active<<<{12|0}', '>>>active<<<bad'),
                     LISTING.replace('>>>active<<<', 'inactive')]:
            with self.assertRaises(ValueError):
                tool.allocations(text, 'demo')

    def test_conflicting_identity(self):
        text = LISTING.replace(' * * 0.1 SECONDS IN global', '{12|0} 3 isvar M 2 -20\n * * 0.1 SECONDS IN global')
        with self.assertRaises(ValueError):
            tool.allocations(text, 'demo')

    def fixture(self, directory, legacy=False):
        diff = directory / 'diff.log'
        diff.write_text(DIFF)
        (directory / 'candidate.c').write_text('void demo(void) {}')
        (directory / 'uopt.txt').write_text(LISTING)
        for suffix in ('text', 'dis'):
            for mode in ('ordinary', 'diagnostic'):
                (directory / (mode + '.' + suffix)).write_text('same')
        report = dict(function='demo', status='transparent', text_equal=True,
                      disassembly_and_relocations_equal=True,
                      candidate_sha256=tool.sha(directory / 'candidate.c'),
                      compile_log_sha256=tool.sha(diff))
        if not legacy:
            report['uopt_sha256'] = tool.sha(directory / 'uopt.txt')
        (directory / 'report.json').write_text(json.dumps(report))
        return diff

    def test_valid_and_no_invented_mapping(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            result = tool.explain(self.fixture(directory), directory, 'demo')
            self.assertEqual(result['provenance']['uopt_association'], 'hash_verified_against_report')
            self.assertEqual(result['assembly']['counts']['stack_frame'], 1)
            self.assertEqual(len(result['connections']), 1)
            self.assertEqual(result['target_function_scope'], 'uopt_only')
            self.assertTrue(result['connections'][0].startswith('Visible-table'))
            self.assertNotIn('source_name', result['candidate_allocations']['ranges'][0])

    def test_changed_artifacts_rejected(self):
        for name in ('candidate.c', 'diff.log', 'diagnostic.text', 'diagnostic.dis', 'uopt.txt'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                diff = self.fixture(directory)
                (directory / name).write_text('changed')
                with self.assertRaises(ValueError):
                    tool.explain(diff, directory, 'demo')

    def test_changed_parseable_listing_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            diff = self.fixture(directory)
            (directory / 'uopt.txt').write_text(LISTING.replace('3 14', '3 15'))
            with self.assertRaisesRegex(ValueError, 'Uopt listing hash differs'):
                tool.explain(diff, directory, 'demo')

    def test_legacy_listing_provenance_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            result = tool.explain(self.fixture(directory, legacy=True), directory, 'demo')
            self.assertEqual(result['provenance']['uopt_association'], 'legacy_unauthenticated')
            self.assertIn('unauthenticated', result['limits'][-1])

    def test_report_gate(self):
        for key, value in [('status', 'changed'), ('text_equal', False), ('function', 'wrong'), ('uopt_sha256', None)]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                diff = self.fixture(directory)
                path = directory / 'report.json'
                report = json.loads(path.read_text())
                report[key] = value
                path.write_text(json.dumps(report))
                with self.assertRaises(ValueError):
                    tool.explain(diff, directory, 'demo')

    def test_compile_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            diff = self.fixture(directory)
            diff.write_text('make: *** compile failed\n')
            path = directory / 'report.json'
            report = json.loads(path.read_text())
            report['compile_log_sha256'] = tool.sha(diff)
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, 'compile_failure'):
                tool.explain(diff, directory, 'demo')


if __name__ == '__main__':
    unittest.main()
