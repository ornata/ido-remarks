# ido-remarks

This an AI assisted PoC that adds a limited set of Clang-style optimization
remarks to code compiled with IDO-5.3.

This is raw Claude generated to see if optimization remarks provide better
outcomes when inspecting compiled code. This code has been tested for
"generally seems right"ness via use in personal projects. Use at your own risk.
:)

Tools like Ghidra help a ton in decompilation, but eventually it seems like
AI agents spin a lot on regalloc, CSE, etc. I figured that adding some remarks
that allow you to do things like

- Introspect live ranges
- Look at hoisted instructions
- Inspect scheduler decisions

would result in better behaviour. I observed a lot of

- Agent gets a function that almost matches
- Agent spends a zillion tokens/hours permuting functions in weird ways

So, at that point, the vibe is basically "this thing is just brute forcing the
problem". If we're just brute forcing the problem, then trimming the search
space is a decent enough way to save some work.

* **`tools/patch_ido_remarks.py`** builds an isolated runtime from *your* recompiled tree with hook
  calls inserted at pinned points in `uopt`, `ugen` and `as1`. It does not modify your tree.
* **`tools/diagnostics/ido_*_hooks.c`** are the hook implementations (allocation, spilling,
  conversion/PRE, cross-block motion, scheduler and ugen decisions, definition ordering).
* **`tools/diagnose_candidate.py`** runs a candidate through the instrumented compiler and records
  the events; **`tools/explain_*.py`** and `compare_compiler_decisions.py` turn them into reports
  ("capacity rejected: 23 > 22").
* **`tools/ido_binasm_patch.py`** inserts records into ugen's binary assembly before `as1` for the
  cases where the original source cannot be expressed in C.
* **`tools/patches/ido-v1.2-ecvt.patch`** repairs `ecvt` in ido-static-recomp's libc shim, which the
  instrumented compiler needs.
* **`tools/diagnostics/IDO_REMARKS.md`** contains the agent workflow prompt.
* **`tools/diagnostics/DECISION_FRONTIERS.md`** contains a prompt to help agents understand what to do with the remarks.

## Example

Compile one function with the instrumented compiler (`-h` points at the runtime you built, `-to`
selects the instrumented `uopt`), asking for text remarks about `sum_pairs`:

E.g.

```c
int sum_pairs(int *a, int n, int k) {
    int i, s = 0;
    for (i = 0; i < n; i++) {
        s += a[i] * k + a[i + 1];
    }
    return s;
}
```

```sh
IDO_REMARKS=text IDO_REMARKS_FUNCTION=sum_pairs \
  cc -c -O2 -mips2 -32 -G0 -to -h$RUNTIME/ -B -o ex.o ex.c
```

The instrumented compiler will produce remarks to stderr when passes do
interesting things, Clang-style. E.g.:

```
sum_pairs: AllocationBenefit (procedure #1, event 213): range=0 expression={944|0} type=3 color=0 benefit-status=1 savings-f32=0x41cc0000 interferences=13 colors-left=18 [-Rpass-analysis=ido-regalloc]
sum_pairs: AllocationBenefit (procedure #1, event 312): range=13 expression={343|0} type=4 color=0 benefit-status=1 savings-f32=0x42500000 interferences=13 colors-left=18 [-Rpass-analysis=ido-regalloc]
sum_pairs: SpillSlot (procedure #1, event 147): expression={343|0} slot=0 M-offset=-16 size=4 [-Rpass-analysis=ido-regalloc]
sum_pairs: LocalReuse (procedure #1, event 13): expression={9066|0} block=2 ucode_opcode=65 count_before=1 count_after=2 [-Rpass-analysis=ido-cse]
```

In this case, `AllocationBenefit` is the register allocator weighing a live range:

* `savings-f32` - benefit as float bits
* `interferences` - how many other ranges overlap it
* `colors-left` - how many registers it could still take

`SpillSlot` says which value got a stack slot.

`LocalReuse` is the optimizer reusing an existing expression.

Setting `IDO_REMARKS=json` gives the same events as JSON, which `tools/explain_*.py` turn into reports.

See [`tools/diagnostics/IDO_REMARKS.md`](tools/diagnostics/IDO_REMARKS.md) for the full workflow.

## Bring Your Own Compiler

No compiler binary or recompiled source is included. (see [NOTICE.md](NOTICE.md)).

Assuming you have a copy of IDO, then you may

- Build [ido-static-recomp](https://github.com/decompals/ido-static-recomp)
- Apply the evct patch
- Point `patch_ido_remarks.py` at that tree.

Check that project's own license and terms for the binaries it expects.

## Tests

Requires Python 3:

```sh
./run_tests.sh
```

## License

MIT, see [LICENSE](LICENSE).
