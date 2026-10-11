import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.diagnostics.assembler_phase.report import (
    anchor_order, final_function, make_report, retained_function, symbol_scope,
)


class ScopeTests(unittest.TestCase):
    def test_preserves_directives_and_line_numbers(self):
        rows = retained_function('prefix\n.ent f 2\nf:\n.noalias $2,$sp\nj $31\n.end f\n', 'f')
        self.assertEqual(rows[0]['line'], 2)
        self.assertEqual(rows[2]['text'], '.noalias $2,$sp')
        self.assertEqual(rows[-1]['line'], 6)

    def test_missing_duplicate_or_unterminated_scope_rejected(self):
        for text in ('', '.ent f\n.ent f\n.end f', '.ent f\n.ent g\n.end f'):
            with self.assertRaises(ValueError):
                retained_function(text, 'f')

    def test_positive_unique_size(self):
        self.assertEqual(symbol_scope('00000010 g F .text 00000008 f', 'f'), (16, 8))
        for table in ('', '0 g F .text 0 f', '0 g F .text 4 f\n4 g F .text 4 f'):
            with self.assertRaises(ValueError):
                symbol_scope(table, 'f')

    def test_requires_complete_instructions_including_delay_slot(self):
        text = ' 10: 03e00008 jr ra\n 14: 00000000 nop\n 18: 00000000 nop'
        self.assertEqual(len(final_function(text, 16, 8)), 2)
        with self.assertRaises(ValueError):
            final_function(' 10: 03e00008 jr ra', 16, 8)

    def test_explicit_anchor_reversal(self):
        a = [{'line': 10, 'text': 'first'}, {'line': 20, 'text': 'second'}]
        b = [{'line': 30, 'text': 'second'}, {'line': 40, 'text': 'first'}]
        anchors = [{'name': x, 'retained': x, 'final': x} for x in ('first', 'second')]
        r = anchor_order(a, b, anchors)
        self.assertEqual(r['retained_order'], ['first', 'second'])
        self.assertEqual(r['final_order'], ['second', 'first'])

    def test_ambiguous_missing_and_duplicate_anchors_rejected(self):
        rows = [{'line': 1, 'text': 'x'}, {'line': 2, 'text': 'x'}]
        for anchors in ([{'name': 'x', 'retained': 'x', 'final': 'x'}],
                        [{'name': 'y', 'retained': 'y', 'final': 'y'}]):
            with self.assertRaises(ValueError):
                anchor_order(rows, rows, anchors)
        one = [{'line': 1, 'text': 'x'}]
        with self.assertRaises(ValueError):
            anchor_order(one, one, [{'name': 'x', 'retained': 'x', 'final': 'x'}] * 2)


@unittest.skipUnless(shutil.which('mips-linux-gnu-as') and shutil.which('mips-linux-gnu-objcopy'), 'MIPS binutils required')
class ObjectAuthenticationTests(unittest.TestCase):
    def test_full_unit_and_relocations_authenticated(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            def assemble(name, tail='nop', external='external'):
                source = base / (name + '.s')
                source.write_text('.text\n.set noreorder\n.globl f\n.ent f\nf:\njr $31\nnop\n.end f\n.globl g\n.ent g\ng:\njal ' + external + '\n' + tail + '\n.end g\n')
                obj = source.with_suffix('.o')
                subprocess.run(['mips-linux-gnu-as', '-32', '-o', str(obj), str(source)], check=True)
                return obj, source
            normal, asm = assemble('normal')
            kept, _ = assemble('kept')
            self.assertEqual(make_report(normal, kept, asm, 'f')['scope']['instructions'], 2)
            changed, _ = assemble('changed', 'addiu $2,$0,1')
            reloc, _ = assemble('reloc', external='different_external')
            for obj in (changed, reloc):
                with self.assertRaisesRegex(ValueError, 'complete text'):
                    make_report(normal, obj, asm, 'f')


if __name__ == '__main__':
    unittest.main()
