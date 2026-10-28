# Handoff: KB/KEV correlation follow-up (2026-10-28)

Branch `claude/quirky-curie-n5pxf5`, draft PR #103, based on `main` at `e093ade3e66eebf915d1c93c75cf18c033c2abb5`.
Owner of this branch: the Claude Code session that opened PR #103. No other branch was written to.

## Refs checked at start (20:12-20:20 UTC)
| ref | SHA | owner | state |
|---|---|---|---|
| `main` | `e093ade3e66e` | - | base |
| PR #102 `claude/patchtrace-haiku-agent-motpbx` | `9fddf99e2635` | another Claude session (not this one) | open draft, untouched |
| PR #100 `claude/patchtrace-features` | `66e9adc50fb1` | another Claude session (not this one) | open draft, untouched |
| PR #72 `chatgpt/panels-1` | `cfd7cfff52f4` | ChatGPT | open draft (panel specs), untouched |
| PR #69 `chatgpt/kb-fixtures-1` | `781b36fb60e7` | ChatGPT | open draft (KB patch-search fixtures), untouched |
| PR #64 `claude/instance-d-gui` | `2fa113889d1f` | another Claude session | open draft (unified code view, audits), untouched |

Overlap check: PR #100 and PR #102 change no source or test file that PR #103 changes (nothing under
`src/patchtrace/kbcorrelation/`, `src/patchtrace/kev/`, or `tests/conftest.py`). All three PRs edit the shared
ledgers `docs/modules.md` and `tasks/todo.md`. PR #103 only appends to the end of `docs/modules.md` and, in
`tasks/todo.md`, edits the K4a section and adds a K8a section, so expect text-only merge conflicts there at most.

## Done in PR #103
1. **K8 KEV part.** `kb leads` reads the local KEV catalog in use through `kbcorrelation/adapters/kev.py`, using the
   existing `KevStore.load_current` and `KevColumnProvider`. It also accepts `--kev-dir`. The four states are `loaded`,
   `not-loaded` (missing or empty folder), `unreadable` (stored catalogs exist but none could be read), and `stale`
   or `future`, which are shown as freshness of a loaded catalog. `LeadsReport.kev_source` holds the provenance.
   KEV is never counted as supporting evidence, and membership and order are unchanged with or without it (tested).
2. **Freshness.** Leads become stale with `stale_reasons=['advisory-revision']` when a newer imported revision has
   replaced a source document of the context. When a ranking is behind the analysis run, `load_default`'s reason is
   shown, never "not ranked yet". The stale text no longer claims an analysis-run check.

The red evidence on `main` was a probe that installs a catalog in the default folder and then runs `kb leads`. It got
`'no-snapshot' == 'listed'`. The freshness tests got `'ready' == 'stale'` and the "not been ranked" text.

## Test record (Linux container, Python 3.13.17)
The venv was `pip install -e '.[dev]'`, plus `rapidfuzz==3.14.6`, `yara-x==1.21.0` and `iced-x86==1.21.0`, which
matches CI's `.[dev,search,rules]`. `pytest-xdist` was installed locally only; it is not a repo dependency.
- `QT_QPA_PLATFORM=offscreen python -m pytest -q -p no:cacheprovider -n 4 --dist loadfile` on `5fa6d16`:
  **15,783 passed, 33 skipped, 4 xfailed, 1 failed** in 266 s.
  - The one failure is `tests/test_rules_worker.py::test_parent_never_imports_yara_x`. It also fails on unmodified
    `main` in this container: its subprocess runs `/usr/bin/python3.13`, which has no `yara_x`, not the venv. This
    is environmental and not caused by PR #103. It has not been re-checked on CI.
- An earlier run without the `search` and `rules` extras had 6 failures in `test_search_{synergy,capability}.py`
  (no rapidfuzz). The same 6 fail on `main`, and they pass once rapidfuzz is installed.
- `python -m ruff check src tests tools`: clean. `tools/generate_kbc_schemas.py`: no diff.
- CI on PR #103: not observed at the time of writing.
- Not run: Windows CI, frozen build, live probes.

## Ready queue (independent of other owners)
1. KEV in `kb explain`, `kb export` and the `kb search` edge rows. `service.py` still writes `kev: 'not-loaded'`, and
   `CveCard.kev` is persisted at attach time. Update the KB plan first, because the contract decision is open:
   either apply KEV when the card is read, with the snapshot named in the export, or record `kev_snapshot_sha` in the
   context key at attach (`context.py:context_key`, which is None today).
2. `pilot/collect.py` passes `NO_CATALOG`. It could use `adapters.kev.load_exploitation` through the pilot's
   `KevLookupPort` (`pilot/sources/kev.py`). Check the pilot owner's plan first.
3. Calibration and evaluation with labelled fixtures. Synthetic leads tests do not establish real-world attribution
   accuracy. Nothing in PR #103 changes that.
4. Whole-codebase bug and security audit. Not done in this session. PR #64 lists 10 earlier audits; reuse their scope
   records rather than repeat them. This session reviewed only its own diff and the paths it read:
   `kbcorrelation/{cli,cli_leads,leads,context,service (lines 125-150, 600-730),index (1-180)}.py`,
   `kev/{store (40-300),kb_adapter,ports,view_model (100-240),join (50-100),contracts (84-312)}.py` and
   `enrichment/pipeline.py:427-455`.

## Blocked queue
| item | blocked on | what unblocks it |
|---|---|---|
| KB/KEV GUI dock (K4b states KB0-KB17, showing `kev_source` and `stale_reasons`) | It needs GUI host registration and shared `ui.py` / `tooltips.py` surfaces that PR #100 and PR #102 change. PR #72's panel specs are an unmerged draft. | One named integrator for `ui.py`/`tooltips.py`, plus acceptance of PR #72's specs. PR #69's fixtures and PR #64's code view are inputs. |
| PR #100 / PR #102 reconciliation (Diaphora and tooltips in `ui.py`) | other owners; no ownership transfer recorded | the owner of either PR, or explicit reassignment |
| SPEC-37 newer patch search | PR #69 fixtures and plan amendments A-3 are not on `main` | merge or acceptance of PR #69 and the A-3 banner |
| Performance gates (10,000-item cache about 1.31 s against 500 ms; revalidation 0.65-0.8 s; Ghidriff 16 KB function limit) | historical figures from other branches; not re-measured here | a measurement on the branch that owns those paths |
| Release, tag and signing | the prior tag-push 403; no release authority in this handoff | owner action; do not retry |

## Commands
```bash
python -m pip install -e '.[dev,search,rules]'
QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_kbc_kev_wiring.py tests/test_kbc_leads_freshness.py
QT_QPA_PLATFORM=offscreen python -m pytest -q
python -m ruff check src tests tools
```
In a bare container, Qt needs `libegl1 libgl1 libxkbcommon0 libfontconfig1 libdbus-1-3`.

## Integration notes
- `tests/conftest.py` gains one autouse fixture. It patches `kbcorrelation.adapters.kev.default_kev_dir` and nothing
  else, so `tests/test_kev_store.py::test_default_kev_dir` still tests the real function.
- `kbcorrelation/cli.py` must not import sibling packages (`tests/test_kbc_contracts.py` import rule). KEV is bound
  in `adapters/kev.py`, as KB-integration-plan section 9 lays out for K8.
