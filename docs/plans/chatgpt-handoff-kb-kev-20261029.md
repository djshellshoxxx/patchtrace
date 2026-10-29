# Handoff for ChatGPT: KB/CVE/KEV correlation work (2026-10-29)

Read this first, then `AGENTS.md` (authoritative policy), `CLAUDE.md`, `docs/modules.md`, `tasks/todo.md` and
`docs/specs/program-e/{KB,KEV}-integration-plan.md`. Everything below was checked against GitHub on 2026-10-29
around 02:00 UTC. Re-check the live refs before you edit anything, because other agents work in this repository in parallel.

## 1. Where things are

| ref | SHA | owner | state |
|---|---|---|---|
| `main` | `e093ade3e66e` | - | default branch, unchanged since 2026-10-21 |
| PR #103 `claude/quirky-curie-n5pxf5` | see PR head (this file's commit) | Claude session `session_01KtKj8mWzRmpVYc1jQAMwe9` (author of this handoff) | draft; CI green on `40325cb`; mergeable |
| PR #102 `claude/patchtrace-haiku-agent-motpbx` | `9fddf99e2635` | another Claude session | draft, Windows alpha work; **not touched** |
| PR #100 `claude/patchtrace-features` | `66e9adc50fb1` | another Claude session | draft, SPEC-53 symbols + Diaphora import; **not touched** |
| PR #72 `chatgpt/panels-1` | `cfd7cfff52f4` | ChatGPT | draft, panel specs (based on an old `main`; its diff against `main` lists about 700 files) |
| PR #69 `chatgpt/kb-fixtures-1` | `781b36fb60e7` | ChatGPT | draft, KB patch-search fixtures (old base, about 730 files in its diff) |
| PR #64 `claude/instance-d-gui` | `2fa113889d1f` | another Claude session | draft, unified code view and 10 audits (old base, about 740 files in its diff) |

None of PR #100, #102 or #103 changes a source or test file that another of them changes. All three PRs append to
the shared ledgers `docs/modules.md` and `tasks/todo.md`, so expect text-only conflicts there.

No ownership of #100 or #102 was transferred. Do not push to their branches. Do not rebase or force-push anyone's
branch, and do not delete branches.

## 2. What PR #103 changes (commits on top of `e093ade`)

| commit | what |
|---|---|
| `a72b395` | **K8, KEV part.** `kb leads` reads the local KEV catalog in use. New `src/patchtrace/kbcorrelation/adapters/kev.py` (`load_exploitation`, `KevExploitation`, `clock_moment`, `default_kev_dir`); `kb leads --kev-dir DIR`; `LeadsReport.kev_source` (`KevSource`: state `loaded`, `not-loaded` or `unreadable`, plus snapshot id, catalog version, release and retrieval time, source, authenticity, freshness, age, banner and notes); the group KEV text names the catalog and its age, including stale and future; `exploitation` is no longer counted as supporting evidence (`leads._supporting`); `tests/conftest.py` gains an autouse fixture that points the default KEV folder at an empty temp folder |
| `3da7119` | **Freshness.** `LeadsReport.stale_reasons` (`file-pair`, `advisory-revision`). A bundle source that `ReverseIndex.active_ids` no longer holds active (a newer imported revision of the same month or CSAF tracking id) makes the leads stale: navigation is off, but the binary-identity chip still supports, because the files did not change. `RealEngine.note` carries `enrichment.pipeline.load_default`'s reason, so a ranking that falls behind the analysis run is no longer shown as "not ranked yet". The stale text names only the reasons that hold. |
| `5fa6d16` | KEV adapter: the "unreadable" probe looks only at `current.json`, `meta/` and `snapshots/`, never the whole `--kev-dir` tree |
| `6331817` | the first handoff doc (removed later) |
| `40325cb` | removed `tests/test_kbc_kev_wiring.py` and that handoff **at the owner's request** |
| this commit | removed `tests/test_kbc_leads_freshness.py` (owner approved), ledger references updated, this handoff |

**Important:** at the owner's request, the KEV adapter path and both freshness cases now have **no dedicated tests**.
The deleted files are still in git history: `git show 6331817:tests/test_kbc_kev_wiring.py` (17 tests) and
`git show 3da7119:tests/test_kbc_leads_freshness.py` (5 tests). Restore them only if the owner asks. They passed on
Linux, and CI (Windows and Ubuntu `qa`) was green on `5fa6d16` while they were present.

Files changed overall: `src/patchtrace/kbcorrelation/{adapters/__init__.py,adapters/kev.py,cli.py,cli_leads.py,leads.py}`,
`tests/conftest.py`, `docs/modules.md` (sections `[K8a:kbc-kev-adapter]` and `[K4a-fresh:kbc-leads-freshness]`),
`tasks/todo.md` (K4a and K8a items) and this file.

### Design invariants to preserve
- Correlation is not proof that a function fixes a CVE. The attention order is the engine's own and is not a
  calibrated probability. Banned words in leads text are listed in `tests/kbc_k4a_golden.py` (`BANNED`, e.g.
  "probab", "confidence", "safe", "patched", "exploitable"). Every new string must pass `banned_in(all_text(result))`.
- KEV is a CVE-level fact. It may move a CVE group through its own sort key, but it must never change group
  membership, function order or any other chip, and never count as supporting evidence. "Not listed" never means
  "not exploited".
- KEV access stays offline and read-only. A missing or damaged store reads as `not-loaded` or `unreadable` and never
  fails the command.
- `kbcorrelation/*.py` (top level) may not import sibling packages except as allowed in
  `tests/test_kbc_contracts.py::ALLOWED_SIBLINGS`. Bind siblings in `kbcorrelation/adapters/` or `wiring.py`.
- `leads.py` imports nothing from `kev`. It gets KEV only through the `ExploitationLookup` protocol plus the
  optional `source` attribute (a capability probe).
- Unknown applicability and anchor evidence stays `unknown` or `not-run`. Do not invent CSAF support or anchor facts.

## 3. Verified results (exact)

- **CI on `40325cb`** (GitHub Actions runs 40770108841 and 40770108677): `qa (ubuntu-latest)`, `qa (windows-latest)`
  (about 29 min), the 5 `native (*)` jobs, `linux-package` and `linux-smoke (ubuntu-22.04/24.04)` were all
  **success**. `release-gate` and `release` were **skipped**, which is not a pass.
- **CI on `5fa6d16`** (the code plus the tests now deleted): the check suite completed with no failures.
- **Local full suite**, Linux container, Python 3.13.17, `pip install -e '.[dev,search,rules]'`, local-only
  `pytest-xdist`, command `QT_QPA_PLATFORM=offscreen python -m pytest -q -p no:cacheprovider -n 4 --dist loadfile` on
  `5fa6d16`: 15,783 passed, 33 skipped, 4 xfailed, **1 failed**. The failure was
  `tests/test_rules_worker.py::test_parent_never_imports_yara_x`. It fails identically on unmodified `main` in that
  container, because its subprocess runs the system `/usr/bin/python3.13`, which has no `yara_x`. It is
  environmental and green on CI.
- **Local focused run** after this commit's cleanup: `tests/test_kbc_{leads,synergy,e0_e2e,view_model,contracts}.py`
  and `tests/test_kev_store.py` gave 232 passed. `python -m ruff check src tests tools` was clean.
  `tools/generate_kbc_schemas.py` showed no diff, because `LeadsReport` is not a generated schema.
- **Red evidence on `main`** before the fix: installing a catalog in the default folder and then running `kb leads`
  gave `'no-snapshot' == 'listed'`. The freshness probes gave `'ready' == 'stale'` and the "not been ranked" text.
- **Historical, not re-measured:** the alpha `79e6fea` had 12 CI jobs pass (QA run 40634102611, native run
  40634105367), with release jobs skipped. The 15,825-test total is an earlier author claim.

## 4. Ready queue (do in this order; each is independent of #100 and #102)

1. **Decide and wire KEV into `kb explain`, `kb export` and the `kb search` edge rows.**
   `kbcorrelation/service.py` still writes `'kev': 'not-loaded'` (`_edge_dict`, around line 142), and
   `CveCard.kev: Literal['listed','not-in-snapshot','not-loaded']` is **persisted at attach time** inside the
   `kb-context` bundle. `context.context_key` hard-codes `'kev_snapshot_sha': None`. Spec first (AGENTS.md): add an
   amendment to `KB-integration-plan.md` choosing one of two options.
   - (a) Apply KEV when cards are read (explain, export) and name the snapshot in the export. The bundle is unchanged
     and the context key stays None.
   - (b) Record `kev_snapshot_sha` at attach. This changes the context key and makes contexts stale whenever KEV
     updates.
   (a) is the smaller and safer change, and matches what `kb leads` now does. Reuse `adapters.kev.load_exploitation` and
   `Context.exploitation`. Add tests for missing, valid, stale, malformed, known and unknown CVEs. Escape Markdown
   in the export (`export.py` already escapes).
2. **Pilot KEV.** `pilot/collect.py` passes `NO_CATALOG` and `_NoCatalog()`. `pilot/sources/kev.py` already has a
   `KevLookupPort`-shaped adapter. Check the pilot owner's plan in `tasks/todo.md` (PIL-* sections) first.
3. **GUI view-model plumbing (no Qt).** `kbcorrelation/view_model.py` (`LeadsViewModel`) does not yet expose
   `kev_source` or `stale_reasons`. Adding them is pure and testable without touching `ui.py`.
4. **Calibration and evaluation.** This needs labelled fixtures with explicit ground truth. Synthetic leads tests do
   not establish real attribution accuracy. Look at `tools/calibration/` and the LBL-* PRs (#78, #79, #82, #85). Do
   not present synthetic results as accuracy.
5. **Whole-codebase bug and security audit.** Not done. Reuse PR #64's 10 audit records (`claude/instance-d-gui`) and
   record the files reviewed and not reviewed, the source SHA, findings with reproduction and confidence. This
   session reviewed only: `kbcorrelation/{cli,cli_leads,leads,context}.py`, `service.py` lines 125-150 and 600-730,
   `index.py` lines 1-180, `kev/{store (40-300),kb_adapter,ports,view_model (100-240),join (50-100),contracts
   (84-312)}.py`, and `enrichment/pipeline.py:427-455`.
   Minor known gaps in PR #103's code, not fixed:
   - A malformed KB clock string makes `clock_moment` raise `ValueError`. `load_exploitation` catches it and reports
     `unreadable` when the store has files, which is a mislabel. Production `SystemClock` is well formed.
   - `advisory-revision` staleness is computed only when an engine view exists. In `no-comparison` the replaced
     sources are not reported.

## 5. Blocked queue

| item | blocked on | unblocked by |
|---|---|---|
| KB/KEV GUI dock (K4b: states KB0-KB17, showing `kev_source`, `stale_reasons`) | It needs GUI host registration and shared `ui.py` (3,077 lines) and `tooltips.py` (1,090 lines), which #100 and #102 both change. The PR #72 panel specs are an unmerged draft. There is a known circular-import trap: `kev.tooltip_entries` imports `TooltipEntry` from `tooltips`, see `tasks/todo.md` [K1a:kev-core]. | One named integrator for `ui.py` and `tooltips.py`, plus acceptance of #72 (rebased onto current `main`) |
| Reconciling #100 and #102 (Diaphora and tooltips on `ui.py`) | other owners; no ownership transfer recorded | the PR owners or explicit reassignment by the repo owner |
| SPEC-37 newer patch search | the #69 fixtures and plan amendment A-3 are not on `main` | #69 rebased and accepted |
| Performance gates: 10,000-item cache about 1.31 s against a 500 ms target; revalidation 0.65-0.8 s; Ghidriff's roughly 16 KB function limit | historical figures from other branches; not re-measured | a measurement on the branch that owns those paths. **Do not lower thresholds.** |
| Offline relocatable packaging; manual Windows, DPI, SmartScreen and Defender checks; signing; release | Windows hardware and owner acceptance; the earlier tag push got 403 | owner action. **Do not retry the tag push.** No release, deployment, credentials or purchases are authorized. |

## 6. Environment and commands

```bash
python -m venv .venv && . .venv/bin/activate
python -m pip install -e '.[dev,search,rules]'      # what CI installs; without search, 6 rapidfuzz tests fail
# bare Linux container only: apt-get install -y libegl1 libgl1 libxkbcommon0 libfontconfig1 libdbus-1-3
QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_kbc_leads.py tests/test_kbc_synergy.py tests/test_kbc_e0_e2e.py
python -m ruff check src tests tools
QT_QPA_PLATFORM=offscreen python -m pytest -q -p no:cacheprovider > full.log 2>&1; grep -E '^(FAILED|ERROR)' full.log; tail -1 full.log
```
For a fast full run, `pip install pytest-xdist` (local only, not a repo dependency) and add `-n 4 --dist loadfile`.
That takes about 4.5 min on 4 cores; a serial run takes hours. The synergy golden regenerates with
`KBC_REGEN_GOLDEN=1 pytest tests/test_kbc_synergy.py -k golden`, but only when an intended change alters it, and the
diff must be reviewed.

To try the CLI by hand: install a catalog with `patchtrace kev import FILE`, then run
`patchtrace kb leads PROJECT [--kev-dir DIR] --json`.

## 7. Where the hard parts and the token costs are

### Hardest (needs careful reasoning; use a strong model)
1. **KEV in persisted contexts (Ready 1).** This is a contract decision about the `kb-context` bundle and the
   context key, and it touches export determinism and what "stale" means. A wrong choice silently invalidates every
   attached context, or silently freezes an old KEV state into exports.
2. **GUI KB dock (K4b).** 17 states, tooltips, shared `ui.py` and `tooltips.py` with two other active PRs, a host
   seam budget (#102 already moved code out of `ui.py` to stay under it), and the `tooltips` circular-import trap.
   Integration and ownership are harder than the code.
3. **Calibration and evaluation.** This needs real labelled ground truth and honest statistics. It is easy to
   overclaim, and the repo's language rules forbid probability wording.
4. **Freshness semantics.** Distinguish stale (inputs changed) from unknown (input missing) from "not run". The KB
   index keeps superseded revisions and computes `active_ids` per release month or CSAF tracking id. The enrichment
   pipeline guards rankings with `guard_for(project)`. Read both before adding any new invalidation case.
5. **Reconciling #100 and #102.** This is coordination, not coding. Do not do it without the owners.
6. **Performance gates.** Measuring and fixing the 1.31 s cache case without lowering the 500 ms target needs
   profiling on representative data.

### Most token-hungry (budget for it, or narrow it first)
- **Full test suite output:** 15,800+ tests in 531 test files over 518 source files. Always redirect to a file and
  grep `FAILED`/`ERROR`; never paste the full log.
- **CI logs**, especially `qa (windows-latest)` (about 29 min of output). Fetch only the failing job's log and grep
  the first error.
- **Diffs of the old-base PRs #64, #69 and #72**, each 700+ files against current `main` because their bases are
  stale. Diff each against its own merge-base (`git diff $(git merge-base origin/main FETCH_HEAD) FETCH_HEAD`), list
  the files first, then read only the relevant ones.
- **`src/patchtrace/ui.py`** (3,077 lines) and **`tooltips.py`** (1,090): grep for the symbol, then read line ranges.
- **`docs/modules.md`** (about 1,040 lines) and **`tasks/todo.md`** (about 700): grep for the section tag (e.g.
  `[K8a:`), never read them whole.
- **`kbcorrelation/service.py`** (747 lines) and the two integration plans (389 and 269 lines): read by section.
- **The whole-codebase audit** (Ready 5) is the largest token sink. Scope it per package, reuse #64's audit
  records, and record coverage as you go so the work can be resumed.

## 8. Rules that bind any continuation
- Spec first for contract changes. Use red/green regression tests. Keep pure domain code Qt-free. Preserve persisted
  contracts. Regenerate schemas after contract edits (`tools/generate_*_schemas.py`).
- Never execute target binaries, never fetch without explicit consent, keep credentials session-only, and keep KEV
  and KB lookups offline by default.
- Never skip, weaken or delete a test to get CI green. The deletions in PR #103 were an explicit owner decision.
- Do not claim release acceptance, merges or approvals that did not happen. Mark tests unexecuted until they have
  actually run.
