# IDO diagnostics for code-generation blockers

Use these tools after a complete-function mismatch suggests allocation, CSE,
instruction-order, or scheduling behavior. They explain the candidate compiler
run; they do not recover original C or accept a match.

## Run

Build an isolated runtime from an ecvt-repaired v1.2 static-recomp tree. The
builder verifies pinned IDO 5.3 guest hashes and does not modify the tree or
production compiler:

```sh
python3 tools/patch_ido_remarks.py /external/counter-uopt-recomp \
  --output /external/ido-remarks-runtime
```

Use a whole-unit candidate and compile log saved by `verify_candidates.py`.
Use the reviewed `expected.o` from that verifier transaction as the reference:

```sh
python3 tools/diagnose_candidate.py /external/unit.c /external/diff.log FUNCTION \
  --runtime /external/ido-remarks-runtime --remarks json --assembler-phase \
  --output /external/diagnostics
python3 tools/explain_codegen.py /external/diagnostics /external/expected.o \
  --output /external/codegen-report
```

All outputs must be new directories outside Git. The diagnostic runner
independently checks whole-unit text, disassembly, and relocations. Do not
interpret remarks unless the report says the run is transparent. `explain_codegen.py`
rechecks recorded hashes and transparency, then compares complete declared
function extents, including relocations. Review `codegen.md`; `codegen.json`
contains full instruction and event records.

## Evidence and limits

Conversion/PRE and optional ugen decision hooks, their explicit symbol-scoping
workflow and DE00 search gates are documented in
[`DECISION_FRONTIERS.md`](DECISION_FRONTIERS.md#de00-conversion-pre-and-temporary-observations).
For kept/remainder ancestry, coloring phase and actual return/interference
forbidden-set origins, see the guide's
[E1C4 section](DECISION_FRONTIERS.md#e1c4-split-ancestry-and-forbidden-register-origins).
For phase-bounded CFG changes and instrumented xbb rejection predicates, see
the [23788 section](DECISION_FRONTIERS.md#23788-cfg-snapshots-and-actual-xbb-rejections).
For `--definition-traces`, source/storage definition and range-creation records,
and actual ready-list/score tie decisions, see the
[1F318 section](DECISION_FRONTIERS.md#1f318-definition-creation-versus-ready-list-order).

Use `patch_ido_remarks.py --decision-traces` for pinned generated-code split
adjacency and coloring sites. Unsupported site layouts fail closed. The default
runtime also captures before/after savings and block forbidden-set contributions.
`explain_allocation_decisions.py DIAGNOSTICS --output /external/decisions`
authenticates the capture and reports each BFS candidate's capacity, required
interference, decision and queue position, plus color choices and interference
edges. For example, 11 colors, 13 existing interferers and 10 shared interferers
reports **23 > 22: capacity rejected**. Missing event families remain unknown.
Priority divisors and savings bits are captured, not recomputed in guest FP.
Edges identify ranges at choice time; their original construction history and
register occupants responsible for each block's regsused are not inferred.

The runtime emits named JSON events when `IDO_REMARKS=json`. The runner filters
by exact `FUNCTION`; older optimizer-only runtimes may lack function names and
cannot be safely scoped. If `as1` exists in the runtime, the runner records its
hash and collects scheduler remarks with `--assembler-phase`.

| Pass / event | What it records | Do not infer |
| --- | --- | --- |
| `ido-regalloc`: `AllocationBenefit`, `RangeColor`, `LiveUnit` | Benefit/status, final color, block loads/stores, reload/save requirements. | Positive benefit is not final allocation; internal colors are not MIPS registers. |
| `ido-regalloc`: `SpillSlot`, `SpillAccess`, `SplitAttempt`, `FrameExtent` | Reserved M slots, emitted temporary accesses, split results, compiler M extents. | Reserved slots need not be accessed; M offsets/extents are not final SP homes/frame size. |
| `ido-cse`: `LocalReuse` | Existing operator expression reuse and operand metadata. | Reuse accounting is not a count of removed final instructions. |
| `ido-cse`: `TreeKilledCheck`, `AnticipationAvailability` | Actual killed-tree result and local anticipation/availability bit transitions. | Does not identify the invalidating store/call or explain every CSE decision. |
| `ido-scheduler`: `BlockStart`, `BlockEnd` | Scheduling invocation, input count, reschedule flag, returned cycle value. | Repeated block scheduling is not final function cycle count. |
| `ido-scheduler`: `DependencyRequest`, `PriorityComparison`, `StartTime`, `InstructionIssue` | Requested edge, comparator operands/result, cycle query, issue update. | A request may merge or be ignored; a query may be for a trial schedule, not the emitted order. |

Procedure ordinals and event sequences are local to one compiler process. Range,
expression, block, and scheduler node identities are also local; never pair them
across builds without independent anchors. Scheduler node input indices apply
only to that scheduling invocation. Records describe the candidate only; the
original optimizer state is unavailable.

`codegen.md` reports word counts, exact prefix/suffix, differing windows, direct
calls, empty branches, stack loads, memory operand order, and separate allocation,
CSE, and scheduler summaries. Retained assembly anchors include only unambiguous
numeric-displacement memory instructions with unique single-word encodings; the
tool does not guess pseudo-instruction expansion or alias independence. Memory
bases/displacements do not prove pointer or C-variable identity. Color snapshots
are cross-checked against the separately captured `uopt.txt` listing.

No CSE events means no relevant hook fired, not proof CSE was absent. Missing
events, unsupported behavior, raw compiler offsets, or a near-match score are not
grounds to change source without separate semantic evidence.

## Tests and acceptance

### Cross-basic-block scheduling

Build with `patch_ido_remarks.py --xbb-traces` and collect with
`diagnose_candidate.py --xbb-trace --assembler-phase`. This runs the patched
as1 separately with `-xbbdbg 10`, surrounds the shipped debug output with exact
function-name boundaries, and verifies whole-unit text and relocations. The
boundary hook flushes runtime IRIX IO buffers (preserving errno) so buffered
debug output cannot leak across procedure scopes. No compiler CFG is changed.

`explain_xbb.py DIAGNOSTICS --output /external/xbb` authenticates the capture
and reports weights, dominator/postdominator sets, paired MOVETO/MOVEFROM
events and the post-move instruction snapshots. Ambiguous/truncated scopes
fail closed. The shipped stream does **not** record every rejected proposal,
predecessor list, liveness transition or volatile rejection: those reasons stay
unknown. Self-dominated blocks are not automatically classified as CFG roots.
The 23788 pilot reproduces the reload move from block 8 to block 7 without
changing the compiled unit. Use calibrated assembler replay for causal edits;
neither the capture nor an edited replay establishes original C or acceptance.

### Expression-to-instruction provenance

Collect `--extra-traces --assembler-phase --remarks json`, then run
`trace_codegen_provenance.py /external/anchors.json --output /external/path`.
Schema 1 names `function`, `diagnostics`, `anchors` and `edges`. Each anchor has
unique `id` and `stage`: `allocation` selects `range` plus `expression`;
`ugen_tree` selects `section`, `entry_blockno` and an exact `selector`;
`ugen_log` selects a one-based `line` and full-line `expected` regex;
`retained` selects a unique full-line `expected` regex; `final` selects `offset`
and `word`; `remark` selects `pass`, `name`, `event`. Every edge names `from`,
`to` and a nonempty reviewed `basis`. Relative diagnostic paths resolve beside
the manifest. All capture artifacts and extra-run transparency are rechecked.

Build trees preserve ordered operands; log anchors expose recorded registers and
reference counts. Missing stages are reported, ambiguous/drifted anchors and
cyclic/dangling paths fail closed. The tool does not guess expression identity
across passes, node creation order or pseudo-op expansion. A path is a durable
reviewed correspondence, not proof of copy propagation or register retargeting.

```sh
python3 -m unittest discover -s tools/diagnostics/dataflow -v
```

These tests validate hooks and report integrity, not a game-function match. Keep
only semantically reviewed, formatted C after complete object comparison and the
clean-ROM gate in [`AGENT_WORKFLOW.md`](../../docs/AGENT_WORKFLOW.md).
