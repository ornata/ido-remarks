import unittest
from explain_allocation_decisions import explain


class Decisions(unittest.TestCase):
    def test_capacity_barrier(self):
        event = dict(name="SplitAdjacency", colors_left=11, interferences=13, shared=10,
                     previous_colors_left=11, heuristic=True, accepted=False)
        row = explain([event])["findings"][0]
        self.assertEqual((row["capacity"], row["required"], row["reason"]), (22, 23, "capacity"))
        with self.assertRaises(ValueError):
            explain([dict(event, accepted=True)])

    def test_missing_is_unknown(self):
        self.assertEqual(explain([])["status"], "unknown")

    def test_forbidden_delta(self):
        row = explain([dict(name="ForbiddenContribution", before=["00000000", "00000001"],
                            after=["40000000", "00000003"])])["findings"][0]
        self.assertEqual(row["added_words"], ["40000000", "00000002"])

    def test_explicit_origins_and_ancestry_are_retained(self):
        events = [dict(name="ForbiddenOrigin", cause="return_range", before=["0", "0"], after=["40000000", "0"]),
                  dict(name="SplitLineage", parent_range=1, kept_range=1, remainder_range=2),
                  dict(name="SplitSeedSelected", kept_range=1, block=7), dict(name="ColorPhase", phase="constrained", range=1)]
        result = explain(events)
        self.assertEqual(len(result["findings"]), 4)
        self.assertEqual(result["findings"][0]["added_words"][0], "40000000")
