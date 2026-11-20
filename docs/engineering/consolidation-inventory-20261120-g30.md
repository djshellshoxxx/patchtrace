# PatchTrace repository discovery — 2026-11-20

## Verified baseline

- Repository: https://github.com/djshellshoxxx/PatchTrace
- Main: `fdc2696c23bdbfe7668348f25e3b336ce33039f7`, the reviewed foundation merge for PR #317.
- Latest observed development head: `6c8b33b851a22fb16d39b31693922359cd34ad12` on `codex/patchtrace-qa-ruff-imports-20261120-g29`, [PR #340](https://github.com/djshellshoxxx/patchtrace/pull/340).
- Candidate tree: `b4eb779a6e4ddc7082dc12e87aec850d9b3e213f`.
- The candidate is 85 commits ahead and zero behind main. It contains PR #322, #324, #325 and the generation 15–29 stack by ancestry.
- This is an engineering candidate, not a verified release. No remote repository state was changed during this discovery.

## Coverage and limits

The GitHub branch search was exhausted through five pages (100, 100, 100, 41, 0). The complete all-state PR collection was read through four REST pages (100, 100, 100, 30). Local Git enumeration independently found the same 341 branches and 59 tags.

| Record | Count |
| --- | ---: |
| Remote branches | 341 |
| All pull requests | 330 |
| Open pull requests | 74 |
| Closed, unmerged pull requests | 84 |
| Merged pull requests | 172 |
| Tags | 59 |
| Releases | 59 |
| PR heads available in the initial clone | 304 |

The other 26 PR heads are old merged heads, mostly rebased or replaced October work. Their metadata is retained, but ancestry cannot be computed until their objects are fetched. Missing PR head numbers: 62, 58, 57, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 42, 38, 34, 33, 32, 31, 30, 29, 28, 27, 8.

The machine-readable census records branch heads, merge bases, divergence, changed files, changed test files, open and historical PR relationships, and available workflow observations. Exact unchanged main/head Git comparisons were reused from the prior committed census with their provenance marked; ancestry and divergence were refreshed. This is complete enumeration, not exhaustive semantic review.

## Current classifications

| Classification | Branches | Meaning |
| --- | ---: | --- |
| Contained by candidate ancestry | 146 | History is present; no blanket claim of preserved behavior |
| Patch equivalent, semantics unreviewed | 16 | Git evidence only |
| Equivalent; skip | 1 | ASM diagnostic donor individually verified below |
| Unknown; investigate | 176 | Further semantic and behavioral review required |
| Current candidate | 1 | Generation 29 |
| Baseline | 1 | Main |

## ASM budget issue #322 and diagnostic PR #323

[PR #322](https://github.com/djshellshoxxx/patchtrace/pull/322) remains draft at `f2458aae22ea6177be64cfc2fb439a79950f00ff`. Its preserved ASM failure measured 0.156169465 seconds against the unchanged strict 0.150-second budget.

[PR #323](https://github.com/djshellshoxxx/patchtrace/pull/323) is still a separate history at `4c96c483295e8a43ea58ab8c5689f8c9eb40de4d`; it is not a candidate ancestor. However, its four valuable files are byte-identical in generation 29:

- `tests/test_codetext_tokens.py`
- `docs/consolidation/ASM_LEXER_PERFORMANCE_20261119.md`
- `docs/consolidation/evidence/asm-lexer-full-suite-checkpoint-20261119.zip`
- `docs/consolidation/evidence/asm-lexer-performance-20261119.zip`

The existing `docs/engineering/asm-diagnostics-recovery.md` describes that selective recovery. Applying the donor again would duplicate work or overwrite shared historical QA text. The donor records later hosted Linux/Windows passes on the older #322 merge ref and rejected optimization experiments. It does not establish the cause of the historical miss or a production performance fix. Keep the strict budget and original failure evidence.

## Current CI observations

Generation 29 [QA workflow 44763480171](https://github.com/djshellshoxxx/patchtrace/actions/runs/44763480171) was actively running at observation. Both Linux and Windows full pytest jobs, plus five Qt jobs, were in progress. The release gate was intentionally skipped. These pending checks are not passes.

Generation 28 [workflow 44752628480](https://github.com/djshellshoxxx/patchtrace/actions/runs/44752628480) failed strict Ruff after its Linux and Windows pytest passes. The two fixture import-format fixes in generation 29 address that exact reported issue. No prior success transfers automatically to the new head.

Main's check history includes both old failed/cancelled runs and later successful runs. The original main QA workflow includes a failed Linux packaging job despite successful QA/Qt/native checks. Refresh exact-head checks and applicable workflow evidence before integration; do not summarize the mixed history as all green.

## Remaining donor candidates and boundaries

- PR #319 and #321 are divergent from generation 29, although selected Profiles, saved Search, raw navigation and manifest work has already been recovered. Their source branches must remain preserved.
- PR #321 retains inventory, Strings composition and optional Search wiring modules whose file paths are absent from generation 29. Missing paths do not prove missing behavior; semantic uniqueness remains unverified. Its broad diff also lacks newer input, parser, publication, acquisition and test repairs. Review small independent seams; do not replace current files wholesale.
- PR #320 is a broad 337-commit divergent history from current main. It is unsuitable for automatic whole-branch adoption.
- The latest handoff still records forced-source publication visibility, official Qt disposition, Windows trust/manual acceptance, historical donor review and independently verified accuracy layers as unresolved.
- The older committed census describes gaps relative to #322; those historical claims need reconciliation against generation 29 before assigning work. Some listed missing files are already present.

## Reproducible evidence

- `patchtrace-remote-inventory.json`: API observations, recent CI, focused PR bodies and exact URLs.
- `patchtrace-all-prs.json`: all 330 PR metadata records.
- `consolidation-inventory-20261120-g30.json`: refreshed local graph census and per-branch Git evidence.
- `build-patchtrace-inventory.py`: standard-library inventory generator; it reads Git history and writes only its scratch output.
- No tests, product changes, merge, release, branch deletion or remote mutation were performed by this inventory worker.

## Coordinator object refresh

All 330 recorded PR heads were subsequently fetched into a separate `origin-pr/` namespace and verified as locally available Git commits. The initial 26-object gap above is closed. The JSON records the refresh time and recalculated ancestry. This does not turn unreviewed branch behavior into verified functionality.

## Durable replay inputs

The raw `patchtrace-remote-inventory.json`, complete `patchtrace-all-prs.json`, and original `build-patchtrace-inventory.py` are retained in [census-replay.zip](evidence/generation30/census-replay.zip), together with hashes. The raw snapshot contains all59 release records; the normalized census exposes the ten newest releases only. Read the generator's recorded paths before replaying in another checkout. The census is an observation of frozen refs, not a substitute for refreshing current remote state.
