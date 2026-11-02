# Paired raw summary allocation — November 2, 2026

Original Windows job125172583133 at51a9 failed both existing summary tests: actual68px, required96/82px. Raw controller source matches base6a37e48. Linux baseline passed five summary controls; no local Windows reproduction claimed.

Use the current wrapped height as a layout minimum, recomputing for resize/font/style and releasing it for shorter text. Existing layouts allocate the label; a reentrancy guard bounds recursive resize delivery. First candidate failed three shrink controls because the old minimum clamped heightForWidth (81 passed). Clearing it before measurement fixes them. Text/Copy/worker/caps/sanitization unchanged; no weaker assertion or timing wait.

Final UI/raw/tooltip/host-seam selection:84 passed22.80s; five summary controls passed3.58s. Ruff/diff clean. Earlier guessed filename collected zero tests; log retained. The initial log named red actually passed5 tests. Independent review and Windows rerun required; no full/DPI/screen-reader acceptance.
