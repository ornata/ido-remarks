import unittest
from explain_definition_order import summarize
from patch_ido_remarks import instrument, instrument_scheduler


class DefinitionOrder(unittest.TestCase):
    def test_storage_first_definition_is_not_variable_identity(self):
        row=dict(name="DefinitionInput",memtype=1,symbol_block=2,storage_offset=-4,width=4,dtype=3)
        result=summarize([dict(row,event=1),dict(row,event=2),dict(row,event=3,storage_offset=-8)])
        self.assertEqual(len(result["first_storage_definitions"]),2)
        self.assertTrue(any("not original C variables" in text for text in result["uncertainties"]))

    def test_absence_and_generated_drift_fail_closed(self):
        self.assertEqual(summarize([])["status"],"unknown")
        with self.assertRaises(ValueError): instrument("",definitions=True)
        with self.assertRaises(ValueError): instrument_scheduler("",scores=True)
