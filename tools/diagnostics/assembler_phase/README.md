# Retained assembly and final object

Use this view when a small remaining instruction-order difference may come from
IDO's assembler scheduling, especially around calls or epilogues. First establish
a complete scoped candidate comparison. This view explains the candidate's
compiler phases; it does not identify the original C or certify a match.

```sh
python3 tools/diagnose_candidate.py saved/unit.c saved/diff.log func_EXAMPLE_A \
  --runtime /tmp/ido-remarks/recomp-ecvt/build/5.3/out \
  --output /tmp/new-phase-evidence --assembler-phase \
  --phase-anchors tools/diagnostics/assembler_phase/examples/example_a.json
```

The compile log must contain the repository's fresh asm-processor IDO command.
The ordinary and `-K` builds use the saved whole unit. The retained build runs in
a fresh evidence subdirectory because IDO writes intermediates into its working
directory. Include paths and GLOBAL_ASM base paths are resolved to the repository.
No working source, expected object, compiler, or Makefile is changed.

`assembler-phase.md` shows the exact `.ent`/`.end` range with original line
numbers, including `.alias`, `.noalias`, `.livereg` and other directives. The
complete final function follows, including delay slots and zero words. The JSON
also includes the entire final object disassembly and relocation records, symbol
scope, and hashes of both objects and retained assembly. Before producing a view,
the tool requires equality of complete normal/retained `.text` bytes and normalized
full disassembly/relocations. Missing, duplicate or incomplete function ranges
fail closed. The top-level report remains incomplete if phase extraction fails.

Optional anchors are a JSON list of `name`, `retained` and `final` regexes. Each
must match exactly one line in each function scope. The tool reports their order
independently in both phases. The user chooses the correspondence: there is no
automatic pseudo-instruction expansion mapping, ABI/register mapping, equivalence
proof, or inferred original-variable identity. Ambiguous anchors fail rather
than selecting a convenient match. The examples apply to these specific saved
candidates; do not assume they match a changed source.

Two real pilots reproduce observed stage differences:

* `func_EXAMPLE_A`: 27 instructions /108 bytes. Retained a0 slot setup precedes
  a2 style setup; final a2 setup precedes a0. Both complete objects agree under
  `-K`. Evidence: `/tmp/276-phase-final`.
* `func_EXAMPLE_B`: 40 instructions /160 bytes. Retained clear-member-4 precedes
  the ra restore; final ra restore precedes the clear. The retained `.noalias`
  remains visible. Evidence: `/tmp/282-phase-final`. A prior manually edited
  assembly replay was calibrated only for its final nine words, not the entire
  function; this view makes no stronger replay claim.

These observations support examining assembler effects before another C argument
or local-declaration sweep. They do not show that the original compiler received
identical input. Retained assembly is diagnostic evidence, never a replacement
production source or an acceptance shortcut.

```sh
python3 -m unittest tools.diagnostics.assembler_phase.test_report -v
```

The ROM-free tests include changed neighboring function bytes and changed external
relocations, ensuring that target-only equality cannot bypass authentication.

## Calibrated assembler replay

When retained input and final scheduling differ, isolate a specific assembler
input before searching more C spellings. The IDO driver uses a different pipeline
for assembly inputs: its `as1` invocation adds `-noglobal`, whereas the measured
C pipeline does not. Compiling retained `.s` with `cc -c` is therefore **not** a
calibrated replay of C compilation. Do not infer scheduler behavior from it.

```sh
python3 -m tools.diagnostics.assembler_phase.replay \
  --phase /tmp/saved-phase/assembler-phase.json \
  --compiler tools/ido-5.3 \
  --flags tools/diagnostics/assembler_phase/examples/ido53-c-pipeline.json \
  --output /tmp/new-replay
```

The example flags were measured for IDO5.3 `-O2 -mips2 -G0` C units, including
the driver's repeated `-r4300_mul`. They are not universal toolchain settings.
Compare a verbose C driver invocation and a verbose assembly invocation before
using a different configuration. The tool invokes `as0` and `as1` directly;
`-noglobal` is rejected. Inputs are the authenticated retained `.s` and its
same-capture sibling `.G`/`.T`, before asm-processor patches. No working source,
expected object or build configuration is modified.

The calibration rechecks the phase report's original object and assembly
hashes and full text/disassembly/relocation equality. It then requires:

1. Original `.G`/`.T` through `as1` and retained `.s` through `as0`/`as1` have
   identical whole-unit text and normalized complete disassembly/relocations.
2. The entire positive-sized target symbol, every instruction word and its
   relocations agree with the authenticated compiled phase target. Neighboring
   GLOBAL_ASM placeholders remain raw; they are not compared against patched
   production assembly.

`replay.json` records input/tool hashes, explicit argument arrays, subprocess
output and complete baseline evidence. Failure after assembly begins records
`failed`; no experiment proceeds past a failed calibration. Input provenance is
bounded by the supplied phase capture and its sibling intermediates; the tool
does not recover or assert an original compiler input.

For a specific causal experiment, copy the retained whole `.s`, edit only the
chosen function body, and pass `--edited /tmp/edited.s`. The `.ent`/`.end` and
all outside text must remain identical. The baseline is calibrated again first.
The report retains the edited object's complete disassembly, exact symbol scope,
and changed words when the scope is unchanged. This establishes the effect of
the supplied text edit; it does not prove source equivalence, infer instruction
identities or authorize an assembly replacement. Review possible changes outside
the target in the saved full disassembly too. Production keepers still require C
and the formatted clean-ROM gate.

Real pilots:

- 10C0C:307 words/1228 bytes; `/tmp/control-replay-10c-auth`.
- EXAMPLE_B:40 words/160 bytes; `/tmp/control-replay-282-auth`.

Both match the entire raw unit's text and relocation-bearing disassembly.
In `/tmp/control-replay-282-alias-edit`, deleting only the final retained
`.noalias $16,$sp` moves the ra restore after both singleton stores and swaps
the s0/s1 restore ordering. Five words change; baseline and edited target sizes
remain160 bytes. This is direct assembler-directive evidence, not a new C match.

```sh
python3 -m unittest tools.diagnostics.assembler_phase.test_report \
  tools.diagnostics.assembler_phase.test_replay -v
```


Root independent review reproduces the307-word10C0C and40-wordEXAMPLE_B baseline
calibrations in `/tmp/root-replay-tool-{10c,282}-review`; all14 phase/replay tests
pass. The10C0C edited-format experiment changes four words: it fixes one relative
order and breaks another. This is useful evidence against calling a single
instruction-order improvement a match; only C source plus normal acceptance
can complete the function.
