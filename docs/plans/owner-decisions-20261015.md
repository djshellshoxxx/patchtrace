# Owner decisions (2026-10-15, given to instance D)

| # | Question | Decision |
|---|---|---|
| 1 | Record the two verified bundle pins (python-windows sigstore-verified, Ghidriff tarball git-rebuilt) | YES. Recorded in `tools/backend_pin.json` (commit 8fb3521). |
| 2 | Restore of `claude/instance-c-research` after C's accidental force-push | Owner to run (commands given in chat). |
| 3 | CORE-3: second import behaviour | KEEP BOTH (earlier runs' matches and overrides are kept) unless that causes a problem; a worker implements it additively. |
| 4 | Label-training corpus (about 38 lineages, about 48 needed) | GROW the corpus (ChatGPT prompt 2 plus worker verification of every SHA/licence). |
| 5 | Lock the C9 preregistration before the single locked run | YES, after the pre-lock audit (LBL-26). |
| 6 | Tier R compute, about 150-250 runner-hours | YES. |
| 7 | CLI exit codes | Recommendation adopted unless the owner objects: unify to one documented table (alpha, pre-1.0), partial=3 everywhere, usage/config errors=2, cancelled=5, empty/not-found=4; add `status` to the envelope; document in the CLI reference. |
| 8 | Unified engine O1/O2/O3 | Recommendations adopted: O1 licence-only review of the BinDiff port before the first public non-prerelease (the v8 notice already ships); O2 flag stays OFF until G-U1..G-U6 pass; O3 stay on Ghidra 12.0.4 through beta, compare 12.1 afterwards with the gates workflow. |
| 9 | Code signing | YES: alpha unsigned, apply to SignPath Foundation (OSS) in parallel. |
| 10 | Symbol-server downloads | Interpreted as: not on by default; explicit consent per operation (current design). |
| 11 | Close docs PRs #40, #41, #43 | YES, closed. |
| 12 | qbindiff / radiff2 / Diaphora specs | NOT dropped: integrate in v2 (kept in the outstanding-specs ledger as v2). |
| 13, 14 | Windows desktop pass; Tier W local runs | Owner will do; step-by-step instructions given in chat (docs/runbooks/tier-w-local-run.md, docs/windows.md, docs/research/qt-accessibility-windows.md). |
