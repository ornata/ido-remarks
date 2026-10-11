"""ROM-free validation tests; real calibrations are documented separately."""
import unittest
from .replay import relocation_scope, validate_edit, validate_flags


class ReplayValidation(unittest.TestCase):
    source = '.text\n.ent f\nf:\n move $2,$3\n.end f\n.ent neighbor\n.end neighbor\n'

    def test_target_edit_allowed(self):
        validate_edit(self.source, self.source.replace('move $2,$3', 'move $2,$4'), 'f')

    def test_neighbor_edit_rejected(self):
        with self.assertRaises(ValueError):
            validate_edit(self.source, self.source.replace('neighbor', 'other'), 'f')

    def test_prefix_edit_rejected(self):
        with self.assertRaises(ValueError):
            validate_edit(self.source, self.source.replace('.text', '.data'), 'f')

    def test_duplicate_target_rejected(self):
        with self.assertRaises(ValueError):
            validate_edit(self.source, self.source + '.ent f\n.end f\n', 'f')

    def test_noglobal_rejected(self):
        with self.assertRaises(ValueError):
            validate_flags({'as0': [], 'as1': ['-noglobal']})

    def test_output_override_rejected(self):
        with self.assertRaises(ValueError):
            validate_flags({'as0': ['-o', 'other'], 'as1': []})

    def test_scope_relocations_keep_identity(self):
        text = '  10: R_MIPS_HI16 outside\n  20: R_MIPS_LO16 target\n  24: R_MIPS_26 helper\n  30: R_MIPS_LO16 next'
        self.assertEqual(relocation_scope(text, 0x20, 0x10),
                         [(0x20, 'R_MIPS_LO16', 'target'), (0x24, 'R_MIPS_26', 'helper')])


if __name__ == '__main__':
    unittest.main()
