import copy
import json
from pathlib import Path
import tempfile
import unittest
from compare_compiler_decisions import compare, load_side, select


def side(color=2):
    return {"ranges": [{"range": 7, "expression": "1|2", "internal_color": color, "line": 10}],
            "events": [{"schema": 1, "pass": "ido-scheduler", "name": "StartTime", "event": 8,
                        "node": {"address": 123, "input_index": 2, "word": "12345678"}, "resource_delay": 0}],
            "instructions": [{"word": "00000000", "relocations": [], "offset": 0}], "retained": None}


class DecisionsTests(unittest.TestCase):
    def test_explicit_range_divergence(self):
        report = compare(side(), side(3), [{"left": {"range": 7}, "right": {"range": 7}, "basis": "audited pointer home"}])
        self.assertEqual(report["earliest_observed_anchored_stage"], "allocation")
        self.assertEqual(report["instruction_changes"], [])

    def test_local_ids_not_decisions(self):
        a = side()
        b = copy.deepcopy(a)
        b["events"][0]["node"]["address"] = 999
        anchor = {"pass": "ido-scheduler", "name": "StartTime", "sequence": 8}
        report = compare(a, b, [{"left": anchor, "right": anchor, "basis": "reviewed matching instruction word"}])
        self.assertIsNone(report["earliest_observed_anchored_stage"])
        b["events"][0]["resource_delay"] = 1
        self.assertEqual(compare(a, b, [{"left": anchor, "right": anchor, "basis": "word"}])["earliest_observed_anchored_stage"], "scheduler")
        b["events"][0]["resource_delay"] = 0
        b["events"][0]["event"] = 9
        right_anchor = dict(anchor, sequence=9)
        self.assertIsNone(compare(a, b, [{"left": anchor, "right": right_anchor, "basis": "word"}])["earliest_observed_anchored_stage"])

    def test_no_automatic_pairing(self):
        self.assertIsNone(compare(side(), side(3), [])["earliest_observed_anchored_stage"])
        with self.assertRaises(ValueError):
            compare(side(), side(), [{"left": {"range": 7}, "right": {"range": 7}}])
        with self.assertRaises(ValueError):
            select(side(), {"range": 8})
        duplicated = side()
        duplicated["ranges"] *= 2
        with self.assertRaises(ValueError):
            select(duplicated, {"range": 7})

    def test_retained_and_word_negative(self):
        a, b = side(), side()
        a["retained"] = [{"text": "lw $4,0($5)"}]
        b["retained"] = [{"text": "lw $4,4($5)"}]
        b["instructions"][0]["word"] = "00000001"
        result = compare(a, b, [])
        self.assertEqual(result["retained_comparison"]["first_differing_index"], 0)
        self.assertTrue(result["instruction_changes"])

    def test_nontransparent_producer_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            names = ["ordinary.obj", "ordinary.text", "ordinary.dis", "candidate.c", "uopt.txt", "diagnostic.text", "diagnostic.dis"]
            (path / "report.json").write_text(json.dumps({"artifacts": dict.fromkeys(names, "bogus"), "status": "not_transparent"}))
            with self.assertRaisesRegex(ValueError, "not transparent"):
                load_side(path, "f", path)


if __name__ == "__main__":
    unittest.main()
