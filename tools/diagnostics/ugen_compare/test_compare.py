import unittest
from compare import TraceError, compare, parse, select

BASE = '''Tree dump after Build
1 istr dtype=R length=4 offset=24 op1=2 op2=3 next=9
2 lod dtype=A mtype=R offset=16
3 add dtype=R op1=4 op2=5
4 lod dtype=R mtype=R offset=128
5 ilod dtype=R length=4 offset=0 op1=6
6 lda mtype=S blockno=32 offset=0
Tree dump after Translate
1 ignored unrelated=1
'''


class CompareTests(unittest.TestCase):
    def test_equal_ignores_ids_and_statement_links(self):
        other = BASE.replace('1 istr', '10 istr').replace('next=9', 'next=999')
        result = compare(BASE, other, 'id=1', 'id=10')
        self.assertEqual(result['differences'], [])

    def test_order_is_preserved(self):
        other = BASE.replace('op1=4 op2=5', 'op1=5 op2=4')
        result = compare(BASE, other, 'id=1', 'id=1')
        self.assertEqual([(d['path'], d['kind']) for d in result['differences']],
                         [('root.op2', 'operand_order_reversed')])

    def test_register_identity(self):
        result = compare(BASE, BASE.replace('offset=128', 'offset=136'), 'id=1', 'id=1')
        self.assertEqual(result['differences'][0]['path'], 'root.op2.op1')

    def test_memory_and_constant_identity(self):
        for old, new in [('blockno=32', 'blockno=33'), ('offset=24', 'offset=28'),
                         ('dtype=R', 'dtype=Q')]:
            self.assertTrue(compare(BASE, BASE.replace(old, new), 'id=1', 'id=1')['differences'])
        constant = 'Tree dump after Build\n1 ldc dtype=R length=4 ival=3\n'
        self.assertTrue(compare(constant, constant.replace('ival=3', 'ival=4'),
                                'id=1', 'id=1')['differences'])

    def test_select_missing_or_ambiguous(self):
        for selector in ('id=99', 'op=lod', 'id=1,id=1', 'id'):
            with self.assertRaises(TraceError):
                select(parse(BASE), selector)

    def test_sections_disambiguate_reused_ids(self):
        two = BASE + BASE
        with self.assertRaises(TraceError):
            select(parse(two), 'id=1')
        self.assertEqual(select(parse(two), 'id=1', 2)[0], 2)
        with self.assertRaises(TraceError):
            select(parse(two), 'id=1', 0)

    def test_missing_child_cycle_unknown_operand(self):
        for bad in (BASE.replace('op1=2', 'op1=999'),
                    BASE.replace('op1=2', 'op1=1'), BASE.replace('op1=2', 'op3=2')):
            with self.assertRaises(TraceError):
                compare(bad, BASE, 'id=1', 'id=1')

    def test_malformed_and_conflicting_nodes(self):
        for bad in ('compiler failed', BASE.replace('offset=128', 'offset=128 mystery'),
                    BASE.replace('Tree dump after Translate', '4 lod offset=999\nTree dump after Translate')):
            with self.assertRaises(TraceError):
                parse(bad)

    def test_shared_children_not_cycles(self):
        shared = BASE.replace('op1=4 op2=5', 'op1=4 op2=4')
        self.assertEqual(compare(shared, shared, 'id=1', 'id=1')['differences'], [])

    def test_distinct_identical_loads_are_not_shared_identity(self):
        shared = BASE.replace('op1=4 op2=5', 'op1=4 op2=4')
        distinct = shared.replace('op1=4 op2=4', 'op1=4 op2=7').replace(
            'Tree dump after Translate', '7 lod dtype=R mtype=R offset=128\nTree dump after Translate')
        result = compare(shared, distinct, 'id=1', 'id=1')
        self.assertEqual(result['differences'][0]['kind'], 'dependency_sharing')

    def test_shared_dag_expansion_budget(self):
        # Only 25 input nodes, but 2**25-1 expanded occurrences.
        lines = ['Tree dump after Build', '1 lod mtype=R offset=16']
        for node in range(2, 26):
            lines.append(f'{node} add op1={node-1} op2={node-1}')
        dag = '\n'.join(lines)
        with self.assertRaisesRegex(TraceError, 'Expanded operand tree exceeds 4096'):
            compare(dag, dag, 'id=25', 'id=25')

    def test_call_scope_does_not_infer_arguments(self):
        call = 'Tree dump after Build\n1 cup dtype=P blockno=23 pop=4 prior=2\n2 par op1=3\n3 lod mtype=R offset=16\n'
        result = compare(call, call, 'op=cup', 'op=cup')
        self.assertEqual(result['left']['tree']['operands'], {})
        self.assertTrue(any('call argument' in s for s in result['limitations']))


if __name__ == '__main__':
    unittest.main()
