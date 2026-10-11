# Targeted compiler decision frontiers

These tools bound hypotheses, not original C or match acceptance. Use external
evidence directories, pinned compiler inputs and transparent whole-unit captures.
Start with `python3 tools/work_queue.py --handoffs`; do not reopen closed source
families without a new observed compiler decision.

E1C4, 1F318 and 120AC matched while these tools were being developed. Their
sections below describe historical pilots and reusable decision frontiers, not
live assignments. The current handoff queue is authoritative.

## 120AC: recalibrate return-register experiments (historical)

Matched (see `docs/MATCHING_BLOCKERS.json`, `historical`). The resolution is
a register-lifetime split of one value across two variables: store1 through
`state`, a copy `script = state`, a dead `state = NULL` that uopt removes but
that kills the previous `state` expression (so neither the input-stage forward
substitution nor `find_replacements` folds the copy back), store2 and the
return through `script`, and an empty `if` that ends the block before the R2
definition. `state` then has three raw references and splits (t6 head spill;
tail piece v0, live only in the store block); `script` is v1 in the return
block; as1 forward-propagates `move $3,$2` into `addu $2,$3,344`. The
sections below record how the lead was narrowed; the recipe audits they cite
were removed at acceptance and remain in Git history.

Do not compile edited `.s` through `cc`: its assembly-input pipeline can add
`-noglobal`. Capture `diagnose_candidate.py --assembler-phase`, and review the
actual C driver's as0/as1 flags (the measured example is
`assembler_phase/examples/ido53-c-pipeline.json`).

Run `python3 tools/replay_compiler_cases.py /external/cases.json --output
/external/replays`. Schema 1 names `function`, `phase`, `compiler`, `flags`, and
1..32 `cases`. Each case supplies a unique `id`, causal `question`, and `edited`
whole retained assembly. Optional `probes` contain `id`, `pattern` and
`expected_count` over final assembly text. Paths resolve beside the manifest.
Every case authenticates and recalibrates the unedited whole unit before the
target-local edit. Output records commands, hashes, full final scopes and probe
results. A probe failure is a finding, not a calibration failure. Edited
assembly is never production input or a source-equivalence claim.

For 120AC use the no-return control as its own ordinary C capture. Add the three
reviewed return sequences only inside its retained function. This separates
assembler folding evidence from uopt's R2 reservation. Do not infer return type
from callers that ignore v0.

The calibrated pilot confirms a new lead: `move $3,$2; addu $2,$3,344`
folds to the target's in-place `addiu v0,v0,344` in the C pipeline. Its entire
17-word function and relocations equal the reviewed reference object. The older
assembly-input replay retained the copy. See
`tools/experiment_recipes/120AC/calibrated_return_replay_audit.json`; the raw
inputs, outputs and calibration reports remain external. This is a diagnostic
assembly result only, not a C match.

A second calibrated case (`shared_temp_audit_20261010.json`) also matches. It
uses memory_copy_rejected.c's own ugen stream with the shared reload in `$2`
instead of `$15`. In ugen remarks the temporaries come from a FIFO
(14,15,24,25,8..13,...,2,3), and shared nodes never get a register request.
uopt splits connect through memory, not register moves. The open question is
now narrower: what puts a shared post-call value in `$2` without a uopt v0
colour in the R2 block. Do not repeat copy-propagation, split-boundary or
FIFO-position probes.

A precedent scan (`precedent_scan_audit_20261010.json`) covered every matched
object and the `cc -S` ugen text of all 254 units. The target's tail (stores
through v0, then `addiu v0,v0,N; jr ra; nop`) appears in only one matched
function, n_alMainBusPull. There the base is the call result, which uopt
copy-propagates as R2 itself. The corpus's `move $R,$2 ... addu $2,$R,N`
streams also copy a call result. No matched function shares a post-call stack
reload in `$2` with an R2 add. 120AC's callees are void, so the corpus gives
no idiom to copy.

The U-code input audit (`ucode_input_audit_20261010.json`) uses
`tools/ucode_binary.py` on `cc -K` intermediates. Both callees do leave state
in v0. Using a callee result as the base drops the ROM's head spill and stack
reload. Using it only for the return makes R2 live in the store block, so the
reload takes v1. At the IR level, the void control's uopt output plus
`lod R2; ldc 344; add; str R2` is exact through the real ugen and as1. Edited
uopt inputs (R2 as the variable, return through R2, R2 datatype or volatile
store, fall-through label, temp-intact calls) keep state in v1. Search for a
uopt input or compiler pin, not another C spelling or ugen form.

## DE00: conversion, PRE and temporary observations

Build with `patch_ido_remarks.py --ugen-traces` (plus the existing decision/xbb
options). Uopt now emits `ConversionInput` (including compiler-generated local
narrowing requests), `ConversionDecision` at add_cvtl, `ConversionEmitted`
at ucode narrowing emission and `PREPlan` after codemotion. The latter records
per-expression/block insert/delete plans, not a realized memory replacement.
Widths are reported only for reviewed variable/load/narrowing layouts; zero
means unknown. Datatypes retain the compiler's numeric enum.

First collect `diagnose_candidate.py --extra-traces --remarks json`. Review the
target's `Uent blockno` in `ugen.tree.txt`, then recollect with `--ugen-symbol N`.
That explicit symbol anchor selects ugen's procedure; it is not guessed from
node numbers or compilation order. The separate ugen-remarks build must match
whole-unit text/relocations. It records `TranslateBegin/End` (operand addresses,
opcode, datatype, visited flag, register, reference count) and `TemporaryAssigned`
at fill_reg, plus evaluation snapshots and get_reg requests. Node IDs/addresses
and symbols remain invocation-local.

Run `explain_transformations.py DIAGNOSTICS --output /external/transforms`.
The hypothesis screen accepts the observed conversion/PRE/register fields.
No fresh-versus-hash-reused creation or register-candidate rejection reason
is inferred from these hooks; such uncaptured history stays unknown.

DE00 is now matched (see `docs/3DE00_MATCHING.md`). The deciding observation
came from the allocation remarks, not from PRE. uopt divides a range's savings
by `n` blocks when `n < 3`, otherwise by `((n - 2) >> 2) + 2`, and a
compiled-out `TRACE` still ends a uopt block. A dead trace between a
same-block copy's definition and its use halves that copy's priority, and as1
still deletes the copy. Check `AllocationBenefit` savings and the colouring order
before searching for extra references.

## E1C4: split ancestry and forbidden-register origins

The `--decision-traces` runtime now records `SplitSeedSelected` (definition/use
flag and seed block), `SplitLineage` (before-split parent identity/color and
returned kept/remainder identities), and `ColorPhase` (constrained,
unconstrained, or discarded for nonpositive savings). It records
`ForbiddenOrigin` at the actual localcolor return-range reservation and at
globalcolor's colored-interferer updates, including before/after words and the
responsible expression/range. These supplement block-only
`ForbiddenContribution` events; uninstrumented formal/precolor origins remain
unknown. Parent IDs can persist across splits, so lineage is an event history,
not an acyclic graph of immutable range numbers.

Use `explain_allocation_decisions.py DIAGNOSTICS --range N --output /external/range`
for reviewed invocation-local range filters, or omit `--range` to include
block-only return reservations. The transparent 145 E1C4 pilot records 11 seed/
lineage pairs, 50 color-phase events and 57 forbidden origins. Keep the resource
index's earlier genuine uses as the bounded source frontier. Require both an
entry v0 exclusion and an index t0 allocation before the entry, without invented
return data or a new cross-call lifetime. The hypothesis screen accepts phase,
cause, parent-color, distinct-piece and seed-definition observations; IDs are
selectors only, never fingerprint fields.

## 23788: CFG snapshots and actual xbb rejections

The `--xbb-traces` runtime now captures BB predecessors/successors, instruction
slots/flags and weights at pinned xbb phase boundaries and around rescheduling.
The phases name native routines where semantics are not independently recovered.
`XbbBlockCandidate` records weight and dominance predicates; actual branch-site
`XbbBlockRejected` records weight-limit, dominator-filter and source-flag rejects.
`XbbProposalResult` records the tested instruction-selection result, and
`XbbInstructionRejected` exposes the two instrumented instruction-flag checks.
Other instruction/liveness rejections stay explicitly unlogged; raw flag names
are not relabeled as volatile semantics without further evidence.

Collect `diagnose_candidate.py --xbb-trace --assembler-phase --remarks json`
and use `explain_xbb.py`. The report derives edge changes, predecessor-less root
classification, block emptying and uniquely anchored delay-slot changes from
successive captured snapshots. Root here means no captured predecessors, not
every possible effective dominator root. Emptying counts nonzero slots, excluding
nops/label markers. Changes identify a phase interval, not an original-C cause.
Incomplete/truncated snapshots fail closed. The transparent 23788 pilot captures
240 block candidates, 201 block rejections, 45 proposal results and the same
eight moves. It observes the default block becoming empty after its reload moves.

The hypothesis screen can now select authenticated `ido-xbb` events and
fingerprint weight/dominance/root/count/reason observations. Bound source probes
to actual case-tail/delay-slot structural changes while preserving the 426-word
scope and FP frame/allocation. Do not repeat unused labels, address-taken volatile
views or direct ASM steering. A missing rejection event is unknown, not approval.

uopt's alias base table (`f_base_in_reg`, reset in `func_4247a4`) explains the
`.alias` directive that the replays need. An instrumented copy of the runtime's
`uopt.c`, with stderr hooks only and identical `-S` text, shows that s0 (the
live range of `l`) is the only entry still present at case 5's end. uopt clears
it there, before `$60:`, but prints nothing: s0's flags were set at its first,
variable-based registration in the head, and uopt sets gp/sp flags only for LDA
bases (isilda never occurs in the 108-unit corpus). Replays that set a `$16`,
`$4` or dead-load noalias match exactly; as1 deletes dead loads but keeps
volatile ones. See `23788/uopt_base_table_audit_20261010.json`.

The U-code input audit (`23788/ucode_input_audit_20261010.json`) edits the
carry's `cc -K` unit.B with `tools/diagnostics/ucode_binary/ucode.py` and replays
it through uopt, ugen and as1 (an empty edit list is byte-identical). Before
ugen, uopt deletes every non-volatile dead load, dead LDA and unreachable
statement. The directive is printed only for two or more volatile or mixed-type
accesses through one LDA, or a volatile `ADD(LDA, l)` as s0's first use. Each
of these leaves extra words or register-based addressing (best: 426 words,
9 diffs). The function is recorded as an as1/uopt exception. Reopen it only with
new compiler-input evidence, not with more C spellings.

The 120AC dead-kill ingredient was searched at the source level
(`23788/source_search_audit_20261010.json`, generators in
`23788/source_search/`): 61,672 whole-unit compiles produced no directive before
the default label. A kill blocks propagation of a variable's value, but the
replays need an LDA base. uopt constant-propagates stack addresses whatever kill
follows (uoptemit.c prints directives only for islda bases in C). Every case-5
copy gives ugen identical to the carry, and empty checks collapse the FP
allocation.

The as1 side was then closed at the record level
(`23788/binasm_record_audit_20261010.json`). Inserting each binary-assembly
record op between case 5's `b $61` and `$60:` in the carry's `cc -K` unit.G
shows which as1 inputs keep the ROM's default block: `.align 2`/`.align 3`,
`.bgnb`/`.endb`, zero-size data records, `.frame` and the alias directives, all
with the ROM's 426 words and the other 39 functions unchanged. as0 drops
`.bgnb`/`.endb` from text, so the earlier text replays of them were vacuous.
The ugen emitter map (recomp `f_emit_dir*` sites joined to `f_eval`'s U-code
dispatch) and a 264-listing census show that inside a procedure ugen emits
only `.loc`, `.livereg`, `.set`, alias directives, switch-table
`.rdata`/`.word`/`.text`, and `.align 5` before a dead epilogue; cfe emits
`bgnb`/`endb` only with `-g`. A recomp libc that fills malloc blocks and the
guest stack with patterns leaves uopt, ugen and as1 output identical, so
uninitialized memory is not the cause either. The function is carried as C
plus one declared `.align 2` record inserted by `tools/ido_binasm_patch.py`
(`tools/binasm_patches/unk_23D30.json`) under the clean-ROM gate.

## 1F318: definition creation versus ready-list order

Build `patch_ido_remarks.py --definition-traces` alongside the other options:

```sh
python3 tools/patch_ido_remarks.py /external/recomp --decision-traces \
  --xbb-traces --ugen-traces --definition-traces --output /external/runtime
python3 tools/diagnose_candidate.py saved/unit.c saved/diff.log FUNCTION \
  --runtime /external/runtime --remarks json --assembler-phase --output /external/diagnostics
python3 tools/explain_definition_order.py /external/diagnostics --output /external/order
```

`DefinitionInput` captures real Ustr input storage/type/width and the current
Uloc source coordinates. `BitAllocated` captures newbit's returned identity and
whether it attaches a range. `RangeCreated` observes a formerly absent
formlivbb range becoming present, with its representative expression and storage
metadata. `DefinitionLiveUnit` records first-store units after range building.
The `codeimage` and `range_build` phase labels identify actual call scopes, not
guessed source provenance. The report's first-definition list groups observed
storage keys, not C variable names or unchanging source lifetimes.

`ReadyComparison` observes the actual native selector at its comparison point:
start cycle, priority height, dependency context, unsigned source-line ordering,
then its signed secondary instruction-order key. Nodes now retain source-line
and secondary-order metadata in scheduler reports. Weighted comparisons have
unknown preferred outcomes in this event; the separate `SchedulerScore` captures
that path's native final integer scores and pool-slot contribution. Its
`slot_decides` field means the non-slot score components are equal. No guest
floating arithmetic is recomputed, and ready-queue insertion history remains
unknown. Captured null outcomes remain unknown to the hypothesis screen.

The transparent canonical 1F318 pilot records 21 definition inputs, 105 bit
allocations, 18 range creations and 67 ready comparisons. The six snapshot FP
ranges retain bits 6,13,17,21,25,29; the new report separates that creation order
from the two observed source-line and three secondary-order comparisons.

The subsequent accepted source (`c6db03a2`) supplies a positive control: separate
real dx/dz locals raise z/cz/y/cy to the constrained class, where priority rather
than bit order assigns their colors. x/cx remain unconstrained, so natural XYZ
reads recover the target's issue order. The old all-unconstrained-order bound
was representation-specific, not an impossibility proof.

Bound further probes to genuine compiler movement across existing control/data
boundaries that changes this relationship while preserving the exact floating
operations and output scope. Do not repeat the closed straight-line assignment,
macro/comma or line-break grids; do not inject #line directives to steer as1.
The hypothesis screen can compare reviewed creation events with `before`, and
fingerprint deciding keys, source-line equality and priority observations rather
than absolute node/range/line numbers. These are source-family gates, not proof
that all other C representations are impossible.

`run_idiom_corpus.py --hypotheses ... --runtime ...` now collects patched as1
remarks as well as uopt when the runtime supplies as1, and records its hash.
Use this for bounded authored source families; use `report_hypothesis_states.py`
for saved whole-unit game captures. Neither substitutes standalone corpus
behavior for actual game-unit verification.
