# KB / CVE / search / leads beta: budgets, limits, help text and acceptance gates (KBF-09)

Status: draft, developer-ready design. Date: 2026-10-15. Base commit: `54fd085`. Proposed alias: KBF-09. Owner: integrator for `docs/*`, `pyproject.toml`, `tools/frozen_smoke.py`, workflows. Reads with KBF-01 to KBF-08, `docs/handoff/beta/07-ci-reading-and-known-failures.md`, `docs/handoff/owner-actions.md`.

## 1. Purpose and non-goals
Purpose: the numbers a build must meet, the documents a user must be able to read, and the list of gates that separate "automated green" from "beta accepted". Non-goals: marketing text; signing; release creation (owner only, never automatic).

## 2. Budgets and limits (all provisional until measured on the Windows runner)
| Area | Limit | Source |
|---|---|---|
| CVRF document | 32 MiB, depth 64, 5,000,000 nodes, 500,000 edges; 24 documents per plan; 60-month index; 1 concurrent fetch; 60 s request; 15 min plan; 3 attempts | `kbcorrelation/limits.py` |
| KB lookup | <= 100 ms at 1M edges (measured 0.25-0.4 ms in SQL); import of a 32 MiB doc <= 20 s on a worker | KB plan s8 |
| CSAF | 16 MiB, 2,000,000 values, depth 64, 10,000 vulns | `csaf/validate.py` |
| SUG / NVD | 4 MiB each; NVD pacing 6.0 s / 0.6 s with key | `enrichment/intelligence.py` |
| Winbindex | 64 MiB compressed / 256 MiB decompressed; 256 probes; 4 concurrent HEAD | `acquisition/winbindex.py` |
| Download | 512 MiB per file; 1 h deadline | `acquisition/transport.py` |
| Search | index build per WB1 plan; `--anchors-from` 50 anchors <= 2 s with a built index; first paint 200 ms | KBF-05 |
| Leads | owner read <= 250 ms; compute 5,000 x 8 <= 5 s; filter 100k <= 100 ms | KBF-07 |
| Enrichment cache | 20 GiB default budget; quarantine counts toward it | `enrichment/cache.py` |
Perf test files to create: `tests/test_kbc_perf.py` (lookup at 100k and 1M edges, ratio-based `>=`), `tests/test_search_anchors_perf.py`, extend `tests/test_enrichment_perf.py`. Use `>=` on `time.monotonic`, no fixed sleeps, short `parametrize(ids=[...])` (Windows rules in `docs/handoff/00-how-we-work.md` s9).

## 3. Help and documentation to write (docs only; KBB-22)
Today `docs/user-guide.md`, `concepts.md`, `privacy.md`, `windows.md` and `cli-reference.md` contain no `kb`, `search` or `pilot` usage (grep counts 0; `cli-reference.md` mentions `pilot` 5 times, `kb` and `search` 0). Add:
1. `docs/user-guide.md`: sections "Find the updates for a KB or CVE", "Create a pair project", "Read the Leads", "Search a project", each with the exact command, the exit codes and the coverage sentence ("Checked N documents ... nothing else was checked").
2. `docs/cli-reference.md`: verbs `kb` (index import/status/verify/plan/sync, search, products, components, pairs, import-pair, plan, acquire, attach, explain, export, leads), `search` (all flags incl. `--anchors-from`), `pilot`, `intelligence`, with the `enrichment-cli/1` envelope and exit codes 0/2/3/4/5. Defect to fix with it: `kb index --help` lists `{import,status,verify,plan}` but omits `sync` although it works (`kbcorrelation/cli.py:109`).
3. `docs/privacy.md`: the host list of KBF-01 s3, "nothing is sent but the URL and two fixed headers", "environment proxies are ignored", "KEV and tool results never reorder functions", "no number is a likelihood".
4. `docs/concepts.md`: lead classes, tiers, "unknown is not negative", coverage words, anchors vs findings.
5. `docs/windows.md`: where the KB workspace lives (`%LOCALAPPDATA%\PatchTrace\kb`), how to import a saved CVRF month on an offline machine, SmartScreen note unchanged.
6. SPEC-42 update (rows 17 and KEV hosts), `docs/modules.md` rows for `search/anchors` binding, `docs/qa.md` rows per slice, `tasks/todo.md` blocks.
Help text rules: plain words; every limit says what was NOT checked; banned stems from KBF-04 s6.4 apply to docs too (tested by `tests/test_docs_claims.py`, NEW, scans the new sections).

## 4. Gates
Automated (CI; `qa-windows.yml`): `qa (ubuntu-latest)`, `qa (windows-latest)`, `qt-gate (ubuntu-latest, 20)`, `qt-gate (windows-latest, 5)`, linux-package, linux-smoke. Frozen smoke (`tools/frozen_smoke.py`) must import `patchtrace.kbcorrelation`, `patchtrace.search`, `patchtrace.pilot`, `patchtrace.intelligence` (today it imports none: grep) and run `kb index plan --months 2024-Aug --json`, `search --probe --json`. Marker `live_kbc` registered in `pyproject.toml` (today only `live_bindiff`).
Live (advisory, separate from pytest counts; PASSED / FAILED / BLOCKED recorded in `docs/qa.md`): `live-kbc.yml` (NEW, KBF-01 s7), `live-kev.yml`, `live-nvd.yml`, `live-capa.yml`, `live-intel-tools.yml` (+ `live-buildenv`), `tests/test_live_strings.py` (in no workflow).
Owner / manual (never inferred): Windows desktop pass M01-M28 (owner-actions O1) plus the new rows: KB dock Refresh on an open project; Prepare leads on a large pair keeps the window responsive; `kb index sync` on a real machine; NVDA/Narrator, 125/150/200% DPI, high contrast.
Beta accepted = all automated green on the CURRENT head of the PR + live rows recorded (BLOCKED listed as blocked) + owner rows returned. Not claimed: signed, air-gapped, accurate, complete.

## 5. Determinism, privacy, security
Perf tests and docs tests are hermetic: no network, no Microsoft bytes; fixtures synthetic (CVE-2099-*, KB5099*). Docs never include real MSRC text.

## 6. Test plan
New: perf tests above; `tests/test_frozen_smoke_imports.py` (asserts the smoke script lists the four packages); `tests/test_docs_claims.py`; `tests/test_cli_help_lists_sync.py` (`kb index --help` mentions `sync`).

## 7. Open questions
Q1 Is the Windows `qa` timeout (120 min) enough with the new perf tests? Default yes; keep perf tests under 60 s. Q2 Ship a sample CVRF month inside the app for the demo? Default no (O-9).

## 8. Acceptance
Section 4 sentence true for the current head, recorded in `docs/qa.md` with exact counts and run URLs.
