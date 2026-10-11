# What this repository contains and does not contain

**Contains:** our own source code (Python tools, C hook functions, one diff against
`ido-static-recomp`), notes, and unit tests with synthetic fixtures. MIT licensed.

**Does not contain, and must not be given:**

* any SGI IDO compiler binary (`cc`, `cfe`, `uopt`, `ugen`, `as1`, `libc`, ...);
* any C source generated from those binaries by a static recompiler;
* any object or assembly produced by them, or anything extracted from a game.

You supply the compiler yourself. The pinned SHA-256 values in `tools/patch_ido_remarks.py` only
verify that the tree you built is the one the hooks were written for.

`tools/patches/ido-v1.2-ecvt.patch` is a unified diff against
[`decompals/ido-static-recomp`](https://github.com/decompals/ido-static-recomp). The added lines
are ours (MIT); the context lines come from that project, whose repository does not state a license
on its front page, so check it before redistributing anything beyond this small diff.

IDO is a trademark/product of its owners; this is an unofficial interoperability and research tool.
