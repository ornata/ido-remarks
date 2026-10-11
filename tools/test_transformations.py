import unittest
from explain_transformations import summarize
from patch_ido_remarks import instrument_ugen, UGEN_FUNCTIONS


class Transformations(unittest.TestCase):
    def test_missing_is_unknown_and_plans_not_replacements(self):
        self.assertEqual(summarize([])["status"], "unknown")
        result = summarize([dict(name="PREPlan", planned_insert=True, planned_delete=False)])
        self.assertEqual(result["event_counts"], {"PREPlan": 1})
        self.assertIn("not proof", result["uncertainties"][0])

    def test_ugen_patch_preserves_calls_and_rejects_abi_drift(self):
        source = "\n".join(f"static {result} f_{name}({params}) {{ " + ("return a0;" if result != "void" else "return;") + " }" for name, params, result in UGEN_FUNCTIONS)
        instrument_ugen(source)
        for malformed in (source + source, "", instrument_ugen(source)):
            with self.assertRaises(ValueError):
                instrument_ugen(malformed)
