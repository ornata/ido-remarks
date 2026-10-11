# Compare selected ugen Build operand trees

Use this read-only tool after `tools/diagnose_candidate.py` and a transparent
ugen dump have localized a discrepancy before machine emission. It compares
ordered `op1`/`op2` dependencies of one explicitly selected node per file.
It does not build a candidate or modify production source.

First verify **each diagnostic object's entire text and relocation-bearing
code against its ordinary object**. `diagnose_candidate.py`'s uopt comparison
alone does not certify an additional `-Wc,-e,...` ugen build. The comparator
cannot infer transparency from a text dump. See `docs/IDO_DIAGNOSTICS.md`.

```sh
python3 tools/diagnostics/ugen_compare/compare.py LEFT/ugen.txt RIGHT/ugen.txt \
  --left-select id=10690 --right-select id=10690 > /tmp/tree-comparison.json
python3 -m unittest discover -s tools/diagnostics/ugen_compare -v
```

Selectors are comma-separated exact attribute matches, for example
`op=istr,offset=24,dtype=R`. Every selector must match exactly one node.
Use `id=...` and, when needed, `--left-section N` / `--right-section N`
(one-based Build section indices). IDs and section indices are compilation
artifacts, not stable function names. Inspect the selected evidence lines and
procedure boundaries yourself before accepting an alignment. The tool does not
automatically map symbols, registers or procedures across different compilations.

JSON includes input hashes, section indices, complete selected operand trees,
source line numbers, original evidence lines and differences by operand path.
Exit0 means comparison completed, even with differences. Exit2 and `status:error`
mean missing/ambiguous selector, malformed input, unsupported syntax, missing
operand reference, cyclic/deep operand graph, or I/O failure. Compiler failure
logs without Build sections are rejected. Only exact `Tree dump after Build`
sections are parsed; Translate and later dumps are excluded.

Interpretation:

- `operand_order_reversed`: the two complete child descriptions exchange places.
  This is ordered-tree evidence, not a claim of evaluation order, commutativity,
  safe reassociation or semantic equivalence.
- `operation_or_identity`: opcode or recorded attributes differ. Memory type,
  block number, offset, width, dtype and virtual-register offset remain intact.
  Register offsets are not physical register names or original C variables.
- `operand_presence`: one operand edge is absent on one side.
- `dependency_sharing`: repeated references to a single node differ from separate
  node instances, even if their printed load descriptions are identical.

Node numbers and `next`/`prior` links do not participate in expression equality;
sharing within each selected graph does. All other printed attributes do.
Constant-pool indices (`ival`) remain indices: equal indices across builds do
not prove equal literal values. Memory identity here means recorded addressing
attributes, not alias analysis or reaching definitions. Equal trees likewise
prove neither equal generated code nor runtime behavior.

Call nodes can be selected, but their preceding parameter statements are **not**
followed through `prior`/`next`. A call-only comparison cannot establish equal
arguments, intervening stores or call memory effects. Select relevant parameter
or store roots separately. Branch/control children are not interpreted as CFG;
cycles are rejected rather than guessed. Each selected tree is capped at4096
expanded node occurrences across all recursive branches (and200 levels deep).
Repeated shared children consume the same budget, preventing exponential DAG
expansion from exhausting memory; exceeding either cap produces an error. This deliberately narrow scope keeps
expression differences separate from scheduling and control-flow claims.

## Reviewed 12138 pilot (external artifacts)

The existing transparent score20 and exact dumps are respectively
`/tmp/12138-direct-diagnostics/ugen.txt` and
`/tmp/12138-zero-diagnostics/ugen.txt`. Selecting node10690 on each produces
one `operand_order_reversed` at `root.op2`: the field store's addition exchanges
its multiplication subtree and `lod mtype=R offset=128` subtree. Their addressing
attributes remain equal. This independently reproduces the observation in
`docs/12138_MATCHING.md`; it does not recover the differing earlier uopt expression
identities from equal R128 loads. Report saved externally as
`/tmp/12138-ugen-comparison.json`. No compiler dumps, ROM data or generated objects
are included here; tests use hand-written, ROM-free traces.
