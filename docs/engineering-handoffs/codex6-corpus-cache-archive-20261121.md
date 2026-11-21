# CODEX-6 Tier R cache integrity — isolated executable handoff

Branch: `codex/patchtrace-corpus-archive-integrity-20261121`; branch
created directly from PR #348 head `6b6fcd3597a604212032ffc453477aeb6edc69ff`.
The separate CODEX-14 Linux frozen CLI branch is owned independently and is
**not** merged into this branch. This cycle's author work is complete;
no foreground reviewer/worker is running in the background.

## Completed source

1. Read `AGENTS.md`, SPEC-32 `docs/specs/known-answer-corpus.md` and
   original `docs/audits/codex-workflows-1.md`. SPEC was amended first.
2. `.github/workflows/corpus-tier-r.yml`: cache original pinned
   rizin/Ghidra archives, always checksum before extraction, remove
   extracted trees before fresh unpacking. Ghidra remains engine-conditional.
3. `tests/test_codex_pkg_workflows.py`: CODEX-6 strict xfail removed only
   after production repair, with positive cache archive/hash assertions;
   CODEX-1 and CODEX-5 strict xfails are retained.
4. `tests/test_corpus_cache_archive_integrity_20261121.py`: hermetic
   structural check plus ten individual negative mutation cases.
5. Evidence: `docs/engineering/evidence/codex6-archive-cache-controls-20261121.json`.
   Exact source static checks 12/12; negative JS mutations 10/10;
   synthetic shell archive verify + tamper refusal for both formats.
   This is author-side source review and shell-mechanism testing only.
6. Ledger: `docs/engineering/task-ledger.json`, authoritative.
   Scope report: `docs/engineering/codex6-corpus-cache-archive-20261121.md`.

## Next steps

- Re-read current PR #348 and CODEX-14 owners. At last inspection PR #348
  Linux QA, all five Qt and all five native jobs succeeded; Windows full QA
  was still in progress in run `44858504288`. PR #347's Linux smoke/jobs
  completed and PR #345's single failed-job retry completed successfully.
  Do not mistake these source-specific receipts for new-branch acceptance.
- Checkout branch exactly into a dedicated source-bound environment, then
  run `python -m pytest -q tests/test_corpus_cache_archive_integrity_20261121.py
  tests/test_codex_pkg_workflows.py`; `python -m ruff check src tests tools`;
  `python -m pip check`; full offscreen and hosted QA once parent is terminal.
  No full local checkout existed in the author runtime.
- Assign a genuinely separate independent reviewer to confirm that no
  unverified cached extracted trees are trusted, exact SHA pinned archives
  are checked on hit and miss, both unpackers consume the checked bytes,
  and cache corruption fails closed. Inspect archive-key conflict and
  protected repo event/resource permissions.
- Source-bound hosted Tier R must exercise rizin-only and a Ghidriff
  configuration (when supported); the cache-hit path needs a repeated run
  at identical source/archive pin, not a new cache key. Existing PR
  workflows path-filter and may not provide this automatically. Do not
  run unverified target samples; use controlled authored fixtures only.
- Publish stacked review only when no overlapping full CI is active. To
  merge, require new-source acceptance and a REST fresh expected-head
  guard; never force, rebase, release or deploy.

Still open: CODEX-1 immutable Action pins, CODEX-5 wheel hash locks,
CODEX-14 original Linux frozen CLI smoke on its separate branch,
full raw input/index provenance, Windows manual trust/screen-reader,
historical 181/16 branch dispositions, and distinct L1/L2/L3 accuracy.
