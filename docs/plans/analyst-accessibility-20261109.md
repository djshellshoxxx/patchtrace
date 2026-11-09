# Analyst accessibility and first-run work — 2026-11-09

Base: `882d1ca0b4190bccddb6ce1f66b46c4db856703b` (`main`).
Branch: `codex/analyst-accessibility-20261109`, in a separate local worktree.
The accuracy Codespace, existing branches and their processes are untouched.

## Ownership checked before implementation

All 48 open PRs and their changed-file lists were inspected. PR numbers and
roadmap entries were treated as leads, then checked against current source.

| Candidate | Current disposition |
|---|---|
| Shared table keyboard sorting (master T4), header tips (T17), Evidence StateView announcer (T5) | Still missing on main, but proposed in open #176. Deferred to that owner; no duplicate implementation here. |
| Palette result-cap fix (T16) | Also in #176; excluded. |
| KB dialog label buddies and validation focus | Already implemented; source-pinned #226/#234 records in `docs/handoff/AUTONOMOUS-DEVELOPMENT-LATEST.md` and current source. No duplicate work. |
| Export keyboard workflow | Named controls exist. Audit visual versus tab order, label access and explicit export activation against SPEC-50. Package A. |
| Files inspection state announcements | Existing status labels are not wired to the shell announcer. Package B. |
| First-run help | Canonical `docs/help/` has 76 topics; some workspace claims and report export instructions are stale. Package C. |
| #98 | Open draft, README/wiki additions. Leave both README and wiki files alone. |
| #188 | Open stacked draft, manual-correction completeness; earlier help commits are already on main. No correctness changes. |
| #216 | Open draft, acquisition display-label sanitization. Excluded. |
| #70/#72 | Historical help/panel draft branches, with old topic filenames or panel specs. Do not port or claim ownership. |
| #279/#259/#268 | Active accuracy, correctness and runner lanes. Read-only ownership inspection only. |

Recent GUI/help history and the source-pinned product handoff were read; historical
"not built" wording was compared with source rather than taken as current status.

## File ownership

| Package | Owner | Exclusive files |
|---|---|---|
| A: Export keyboard operation | `export_keyboard` | `src/patchtrace/ui_export_v2.py`, `tests/test_ui_export_accessibility.py`, relevant label assertion in `tests/test_ui_export_v2.py`, scoped addition to `docs/specs/accessibility-baseline.md` |
| B: Files state announcements | `files_announcements` | `src/patchtrace/ui_inspection.py`, `tests/test_files_announcements.py`, scoped addition to `docs/specs/gui-framework.md` |
| C: First-run/analyst help | `first_run_help` | Existing `docs/help/*.md` and `docs/user-guide.md` |
| D: Independent review | `independent_review` | Read-only; findings reported to coordinator before integration |
| Integration and verification | Coordinator | This record and scoped `docs/qa.md`/`tasks/todo.md` entries; final diff, checks and PR |

No matching/diff/scoring, adapters, native setup, binary fixtures, accuracy handoff,
research manifests or CI workflows are in scope. No dependency or schema change
is planned. Tests use existing synthetic data.

## Acceptance

Reproduce selected gaps, add focused keyboard/state tests, run relevant GUI tests,
repository Ruff and panel checks, and attempt the full suite after integration.
Record exact results and platform in the final verification section. Offscreen
Qt checks are automated proxies; Windows screen-reader, DPI and high-contrast
acceptance remain human-only and are not implied by passing tests.
