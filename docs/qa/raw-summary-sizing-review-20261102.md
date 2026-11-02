# Independent raw summary sizing review — 2026-11-02

No blocking findings in `b4ed3a221a342ea57e70791d46acdcc7096aacd1`, tree `3ceedaabfdaa4ff44b9d10e20be131d7b696ea3f`, from `6a37e488`. Worktree clean. Adjacent JSON binds exact base, changed files and evidence hashes.

The change makes current wrapped label height a minimum, clears the previous minimum before measuring, and reallocates existing layouts. The two-pass loop handles a width change; synchronous reentry is guarded and `finally` releases the guard. Resize/font/style events recompute geometry. PlainLabel sanitization and Copy/job logic are unchanged.

Independent validation: **84 existing tests passed in 24.55 s**, plus **4 disjoint controls passed in 2.22 s**. Actual QFont and width changes cover 12 repeated combinations and short-text release; a padded/bordered style also fits at 960px. Original result/context/generation/Copy bytes remain unchanged. Guard reentry, exception recovery and sanitized bounded plain text were checked. The saved narrow screenshot was inspected and the EOF summary is fully visible.

One initial reviewer assertion failed because it incorrectly counted all Qt height queries during setText as one allocator invocation. The corrected control tests active reentry directly; initial script/log remain retained. The saved Windows trace contains the actual 68px versus96/82 failures. Author baseline passed on Linux, so no local red reproduction is claimed.

Native Windows CI remains required. No full/native/performance job, repository edit or remote action was performed.
