# ASM diagnostic recovery — 2026-11-19

Partially unique donor: `4c96c483295e8a43ea58ab8c5689f8c9eb40de4d`, published
independently as `codex/asm-lexer-performance-20261119`. Its investigator
worked in a separate session; this integration did not edit that worktree.

Extracted four files: the lexer budget test, the investigation report, and
its two raw-evidence archives. Shared QA/todo edits were not copied over
the current engineering history. The source lexer is byte-identical
between the donor, PR #322, and this integration before extraction. The
existing test lacked failure samples; the extracted diff changes only
retention and formatting of its five measurements. Input length, timed
operation, sample count, minimum statistic, and strict 0.150-second bound
remain unchanged. No runtime optimization or performance repair is claimed.

The report preserves the original 0.156169465-second failure, controlled
experiments that did not justify changing production code, and exact hosted
Linux/Windows receipts for the older PR #322 merge commit. Its local
aggregate checkpoint was pending when authored. Those earlier receipts
must not be relabeled as tests of this larger integration. Current combined
validation is recorded separately in the latest engineering handoff.
