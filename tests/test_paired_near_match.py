"""ROM-free fail-closed saved comparison tests."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import paired_near_match as tool


class PairedTests(unittest.TestCase):
    def test_complete_scope_and_relocations(self):
        rows = tool.instruction_rows(' 10: 00000000 nop\n 14: 0c000000 jal 0\n 14: R_MIPS_26 helper\n', {'start': 16, 'size': 8})
        self.assertEqual(rows[1]['relocations'], [['R_MIPS_26', 'helper']])
        self.assertEqual(rows[1]['offset'], 4)

    def test_missing_duplicate_and_outside_scope(self):
        for text in [' 10: 00000000 nop\n', ' 10: 00000000 nop\n 10: 00000000 nop\n', ' 10: 00000000 nop\n 18: 00000000 nop\n']:
            with self.assertRaises(ValueError):
                tool.instruction_rows(text, {'start': 16, 'size': 8})

    def test_unassociated_relocation(self):
        with self.assertRaises(ValueError):
            tool.instruction_rows(' 10: R_MIPS_26 helper\n', {'start': 16, 'size': 4})

    def test_relocation_change_with_same_word(self):
        left = [{'word': '0c000000', 'relocations': [['R_MIPS_26', 'a']]}]
        right = [{'word': '0c000000', 'relocations': [['R_MIPS_26', 'b']]}]
        self.assertEqual(tool.compare_rows(left, right)[0]['kind'], 'replace')
        self.assertEqual(tool.compare_rows(left, left), [])

    def test_stack_accesses_no_nonsp_guess(self):
        rows = [{'assembly': x} for x in ['sw t0,8(sp)', 'addiu sp,sp,-80', 'lw t0,8(s0)']]
        self.assertEqual(tool.stack_accesses(rows), rows[:2])

    def fixture(self, p):
        artifacts = {}
        for name in ['ordinary.obj', 'ordinary.text', 'ordinary.dis', 'diagnostic.text', 'diagnostic.dis', 'candidate.c', 'uopt.txt']:
            (p/name).write_text('evidence')
            artifacts[name] = hashlib.sha256(b'evidence').hexdigest()
        report = {'artifacts': artifacts, 'uopt_sha256': artifacts['uopt.txt']}
        (p/'report.json').write_text(json.dumps(report))
        return report

    def test_hash_tamper_and_missing_authentication(self):
        for variant in ['tamper', 'missing', 'path']:
            with tempfile.TemporaryDirectory() as tmp:
                p = Path(tmp); report = self.fixture(p)
                if variant == 'tamper': (p/'ordinary.obj').write_text('different')
                elif variant == 'missing': del report['artifacts']['ordinary.obj']
                else: report['artifacts']['../external'] = 'x'
                (p/'report.json').write_text(json.dumps(report))
                with self.assertRaises(ValueError): tool.saved_side(p/'diff', p, 'demo')

    def test_procedure_scope_refusal_propagates(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); self.fixture(p)
            with patch('explain_near_match.explain', side_effect=ValueError('Missing procedure')):
                with self.assertRaisesRegex(ValueError, 'procedure'):
                    tool.saved_side(p/'diff', p, 'demo')

    def test_object_disassembly_disagreement(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); self.fixture(p)
            with patch('explain_near_match.explain', return_value={}), patch(
                    'paired_near_match.subprocess.check_output', return_value='wrong object'):
                with self.assertRaisesRegex(ValueError, 'object differs'):
                    tool.saved_side(p/'diff', p, 'demo')

    def test_record_signatures_do_not_pair_ids(self):
        def side(identity):
            return {'optimizer': {'ranges': [{'expression': identity, 'internal_color': 25, 'adjusted_savings': 3, 'expression_record': {'description': 'M 2 -16'}}]}}
        self.assertEqual(tool.range_signatures(side('1|0')), tool.range_signatures(side('22|0')))

if __name__ == '__main__': unittest.main()
