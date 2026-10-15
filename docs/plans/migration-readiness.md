# Migration readiness (Program E)

Maintained by instance D (see `docs/plans/program-e-execution-plan.md` section 6.4); method in `docs/plans/e4-audit-and-qa-plan.md`. Initial fill by W4 from `docs/modules.md`, `tasks/todo.md`, `docs/plans/ledger-A.md`, `ledger-B.md`, `ledger-C.md`, `docs/audits/*` and `src/patchtrace/` at `main`-based commit f7541a0 (2026-10-14). Cells that were not verified are `?`; nothing is marked ready from a spec status line alone.

## Definition: ready for migration
A feature is `ready` only when all of these hold (e4 plan sections 2 and 8): all its slices are built and merged to `main`; Linux and Windows CI are green on the audited SHA; an audit file exists in `docs/audits/` with no open High or Medium finding (Low may remain listed); tests, `docs/modules.md`/`tasks/todo.md`/`docs/qa.md` rows, tooltips and accessible names (when the feature has UI), the frozen-smoke import, schema drift and the performance budget are all in place or recorded. Status values: `building`, `audit`, `fixing`, `ready`, `blocked-external`. Owner-only acceptance (E6 plan section 7) is tracked separately and never counts here.

## Table
Columns "built" lists slice ids found in the code or ledgers; totals are in each track's plan section 9 and are `?` where not counted. "Merged" is to `main`; the ledgers show later waves merging in PRs, so re-check against `git log origin/main`.

| Feature | Slices built/total | Merged | CI green | Audit | Open High/Medium | Tests | Docs rows | Tooltips and accessible names | Frozen-smoke import | Schema drift | Perf | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| UE unified engine (`unified/`) | S0a, S0b, S1, S2, S3, S3b, S4a, S6a of ? (S4 UI, S5, S6b open) | S0a-S2 yes; later per ledger A | yes (live-unified green, per ledger A) | `20261014-C-unified-s0a.md` only | ? (S0a findings fixed as S0a-FIX) | yes | yes | no (panel after GUI F5) | ? | yes (`docs/schemas/unified`) | S6a bench exists, budget unpinned | building |
| KB (`kbcorrelation/`, KB patch search) | K0, K1 of ? (K2 store onward open) | K0 yes; K1 unmerged at ledger B date, `?` now | ? | none | ? | yes | yes | no | ? | yes (`kbcorrelation`) | n/a yet | building |
| PIL patch intent (`pilot/`, `intelligence/csaf`) | A1, A2, A3, B1, B2, T, K1, K2 of ? (C1, C2 panel, D1 open) | yes (PRs #46, #49, #53 and later) | yes | `20261014-C-intelligence-enrichment.md` (CSAF side) | ? (K-FIX applied) | yes | yes | no (C2 pending) | ? | yes (`pilot`, `intelligence`) | B2 5 s target test present | building |
| CAP capa / FLOSS adapters (`intelligence/tools`) | CAP-0..3 status ? | tools-core PR #47 per ledger B; ? | ? | `20261014-C-tool-adapters.md` (TA-1..TA-12) | ? (TA findings routed to tools-core) | yes | yes | no | ? | yes (`intel-tools`) | ? | audit |
| DIE Detect It Easy (`intelligence/tools/diec.py`) | D1 adapter present; D2+ ? | ? | ? | tool-adapters audit only | ? | yes | yes | no | ? | yes | ? | building |
| WB1 search | 0 built in `src/` (no package) | no | n/a | none | n/a | no | plan only | no | no | no | proposed budgets | building |
| WB2 call graph | 0 built in `src/` | no | n/a | none | n/a | no | plan only | no | no | no | proposed budgets | building |
| WB3 strings / FLOSS | 0 built in `src/` | no | n/a | none | n/a | no | plan only | no | no | no | proposed budgets | building |
| WBQ quick wins (`pe_overview/`, `codetext/`, `symbols/`) | S1, S2, S4, S7, S10 of ? (S5, S8, S13, UI S6/S9 open) | yes (PR #52, #53) | yes | none | ? | yes | yes | no (UI open) | ? | yes | ? | building |
| YRX YARA-X (`rules/`) | R0, R1, R2 of ? (R3-R8 open) | R0-R2 yes | ? | none | ? | yes | yes | no (R6b open) | ? | yes (`rules`) | ? | building |
| KEV (`kev/`) | K0, K1a, K1b, K4, K5 of ? (K2, K3 panel, K6 open) | yes (K4/K5 merge A38) | ? | none | ? | yes | yes | no (K3 pending) | ? | yes (`kev`) | ? | building |
| GUI framework (`gui/`, `cli_commands/`) | F0, F1, F1b of F0-F9 | F0, F1, F1b merged; F2+ on instance D | ? | none | ? | yes | yes (planned rows) | n/a until F5 | ? | n/a | ? | building |
| LBL labels and calibration (`calibration/`, `tools/calibration/`) | LBL-00, 01/09/11, 06, 10, 14, 17 built; 02-05, 07, 08, 12, 13, 15, 16, 18-25 open | partly (ledger C: held locally during bundle priority) | ? | `spec-gaps-20261014.md` (general) | ? | yes (synthetic only) | yes | n/a (no GUI; `display_level()` stays `ordinal`) | ? (no artifact ships) | yes (`calibration`, `corpus`) | n/a | building |
| BUNDLE offline runtime (`offline_bundle.py`, `backend_bundle.py`, `tools/*bundle*`) | B1, B2, B3, B3b, B4, B5a, B5b, B6, B7, B8 built; B9, B10 open | per ledger C ? | ? | none | ? | yes | yes | yes (`ui_bundle_setup.py`) | ? | n/a | n/a | blocked-external (live full builds, O8) |
| FAB anchor fabric (`fabric/`) | FAB-0, FAB-1, FAB-2, FAB-4 of ? | yes (A32 merge) | ? | none | ? | yes | yes | n/a | ? | yes (`fabric`) | ? | building |

## Rules for updating
- One edit per row per audit or merge; cite the audit file, PR or run id in the cell.
- `Merged` and `CI green` come from `git log origin/main` and `gh run list`, not from ledgers.
- Findings stay in `docs/audits/<date>-<feature>.md`; this table holds only counts of open High/Medium.
- A row moves to `ready` only per the definition above; features whose last slice lands first are audited first.
