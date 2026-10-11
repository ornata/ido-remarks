import unittest
from explain_xbb import parse_xbb, cfg_changes


class Xbb(unittest.TestCase):
    def capture(self, body):
        return ('{"schema":1,"pass":"ido-xbb","name":"Begin","function":"target"}\n' + body +
                '\n{"schema":1,"pass":"ido-xbb","name":"End","function":"target"}\n')

    def test_named_move_and_dominance(self):
        body = ''' bb: 7 weight: 4
 bb: 8 weight: 7
BB 8 dominated by: 1 7 8
BB 8 postdominated by: 8
current bb 7, weight = 4, stalls = 3
MOVETO bb 7 inst 2  time: old 5, new 5
MOVEFROM bb 8, inst 1  time: old 5, new 4
----- basic block instruction moved to -----
 INST 2: Line 1: 0x8fa800b8 lw $8,184($sp)
----- basic block instruction moved from -----
 INST 1: Line 1: 0000000000 nop'''
        result = parse_xbb(self.capture(body), "target")
        self.assertTrue(result["moves"][0]["observed_eligibility"]["destination_in_source_dominators"])
        self.assertIn("lw $8", result["moves"][0]["moved_instruction"]["text"])

    def test_unscoped_truncated_duplicate_and_unpaired_fail(self):
        for text in ("bb: 7 weight: 4", self.capture("bb: 7 weight: 4") * 2,
                     self.capture("MOVETO bb 7 inst 2 time: old 1, new 1")):
            with self.assertRaises(ValueError):
                parse_xbb(text, "target")

    def snapshot(self, event, preds, words):
        return dict(name="CFGSnapshot", block=8, phase="stage", event=event, predecessors=preds, successors=[9],
                    is_root=not preds, instruction_count=len(words), instructions=[dict(index=i+1, word=w) for i,w in enumerate(words)])

    def test_edges_roots_emptying_and_delay_slot_change(self):
        before=self.snapshot(1,[7],["10000001","00000000"])
        after=self.snapshot(2,[],["10000001","8fa800b8"])
        changes=cfg_changes([before,after])
        self.assertTrue(any(c["name"]=="CFGEdgeChanged" and c["action"]=="removed" for c in changes))
        self.assertTrue(any(c["name"]=="DelaySlotChanged" for c in changes))
        self.assertTrue(any(c["name"]=="BlockEmptied" for c in cfg_changes([after,self.snapshot(3,[],["00000000"])])))
        self.assertTrue([c for c in changes if c["name"]=="RootClassified"][-1]["is_root"])

    def test_incomplete_or_inconsistent_snapshot_rejected(self):
        for snapshot in (dict(self.snapshot(1,[],[]),is_root=False),dict(self.snapshot(1,[],[]),instruction_count=2)):
            with self.assertRaises(ValueError):
                cfg_changes([snapshot])
