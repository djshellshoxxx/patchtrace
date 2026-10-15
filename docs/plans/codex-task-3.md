# Task for ChatGPT Codex: guided reverse-engineering teacher core (GDE G1-G4)

Branch `codex/gde-core`. Same rules as `codex-task-1.md` (read it first): own branch, draft PR to `main`, product rules from `AGENTS.md`, no `[skip ci]`/`[release]` markers in commit messages, no network access in tests, no secrets, secret-shaped literals built from fragments, `.gitattributes` LF rule for any new fixture directory is listed in the allow-list. Keep Qt out of pure modules. Run focused tests and `ruff check` + `ruff format --check` on touched files before every push; CI is the full gate (only minimal QA locally, owner order 2026-10-15). One commit per work package; PR description lists test counts, open items, and anything not verified (Windows, frozen build). Do not edit files outside the allow-list; if a shared file needs a change, write it under "Integrator asks" in the PR description.

## Read first
`AGENTS.md`, `docs/specs/program-e/GDE-integration-plan.md` (sections 4-10 are the contract; section 10.2 slice table gives exact files), `docs/modules.md`, `docs/specs/INDEX.md`. The teacher is deterministic: no AI, no clock, no randomness, no network inside `guide/`.

## Work packages
1. **G1** models, limits, three-valued predicates, snapshot, generated schemas (`src/patchtrace/guide/{__init__,models,limits,predicates,snapshot}.py`, `docs/schemas/guide/*`, `tests/test_guide_models.py`, `tests/test_guide_predicates.py`). Red first: unknown field/op rejected, depth/node limits, NaN, unknown tri-state truth tables, schema drift check.
2. **G2** engine, hints, registry, validate, anchors port, store, review (`guide/{engine,hints,registry,anchors,validate,store,review}.py`, tests `test_guide_engine.py`, `test_guide_validate.py`, `test_guide_store.py`, `test_guide_review.py`, `tests/fixtures/guide/replay/*.json`). Replay fixtures: golden, hint, wrong-turn, reveal, blocked, reorder; determinism under shuffled keys; import lint (no time/random/net); store migration/corruption/reset; Leitner table with injected dates (`>=`, short parametrize ids).
3. **G3** CLI `guide ...` and `bootstrap.py` (`guide/cli.py`, `guide/bootstrap.py`, `tests/test_guide_cli.py`), envelope `enrichment-cli/1`, exits 0/2/3/4/5, subprocess test that Qt is never imported. Register through the `cli_commands` adapter pattern used by `cli_commands/kev.py` (add `src/patchtrace/cli_commands/guide.py`); do NOT edit `cli.py`.
4. **G4** first pack (`guide/packs/core-1.json`, `guide/data/pitfalls.json`, `tests/fixtures/guide/sample-expected.json`, `src/patchtrace/guide_hooks_core.py`, `tests/test_guide_pack_core.py`): lessons L01-L04 only; `guide validate --all` clean; every `tooltip_ids` entry exists in `tooltips.py` (read only); use only plan-sourced facts, cite none of the plan's `[unverified]` rows as fact.

## Allow-list
Files named above, `.gitattributes` line for `tests/fixtures/guide/** text eol=lf`, and `docs/modules.md` rows [G1:guide-models] .. [G4:guide-pack] appended at the end of the file. Nothing else.

## Done when
All four slices merged-ready, pure-domain tests green, the plan's slice status line updated in your PR description (not in the plan file).
