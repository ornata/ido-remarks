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
