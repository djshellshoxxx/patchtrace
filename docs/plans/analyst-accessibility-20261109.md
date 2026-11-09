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

## Implemented and independently reviewed

- Package A: Export keeps Enter/Return bound to the focused action; initial show,
  later focus moves and hide/show cannot leave Write report as the default for
  option fields. Contract/Profile/Sections have mnemonics and visual-order Tab
  traversal. Native editing, combo selection, Browse, Cancel and Escape remain.
- Package B: Files and Version and signing send deduplicated load/completion/error
  announcements through the existing shell. Errors retain an actionable visible
  message; passive refresh preserves failure, an active explicit retry stays
  loading, and panel focus targets the visible tab. Existing worker lifecycle
  and domain logic are unchanged.
- Package C: nine existing help/guide files now describe actual first-run tasks,
  synthetic sample limits, reviews, report v2 controls, keyboard operation, Files
  status, timeout diagnostics and empty-result filters. No parallel guide added.
- Package D independently reviewed all changes. Review found and drove fixes for
  initial Qt default-button assignment and stale error redisplay during retry.
  A separate parented modal ExportDialog probe also passed. No manual assistive
  technology verification was performed.

## Verification receipt

Platform: Linux 6.18.57 x86_64, glibc 2.41; Python 3.12.14, PySide6/shiboken6
6.12.0, pytest 9.2.0. Dependencies installed in a new worktree-local venv from
`.[dev,search,rules]`, with pytest-xdist 3.8.0 used only for local validation.
No dependency declaration changed.

Implementation tested: GitHub `2129879202a95ee3bdecfcebee7d2847956cf4cd`, local
`92058e2798d698e6915091a1185b5ccb006e483e`; both have tree
`5aa025e6d7c5d5012595d0bc097712240007ebe6`. Independent review verified an empty
diff between them. Publication used the GitHub API because shell push lacked
credentials; every published package tree was checked against its local tree.
The final receipt commit changes only documentation and logs.

All commands below ran at the worktree root. Counts overlap; do not add them.

| Check | Exact command | Result |
|---|---|---|
| Export author | `QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q tests/test_ui_export_accessibility.py tests/test_ui_export_v2.py` | 52 passed, 2 warnings, 16.20 s |
| Files author | `QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q tests/test_files_announcements.py tests/test_ui_inspection_signing.py tests/test_ui_pemeta.py tests/test_gui_host_seam.py tests/test_audit116_stale_inspection_failure.py` | 97 passed, 10.41 s |
| Help/specs | `QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q tests/test_help_docs.py tests/test_spec_registry.py` | 295 passed, 1.16 s |
| Integrated GUI/help | Command below | 1,589 passed, 2 warnings, 159.30 s; exit 0 |
| Lint | `.venv/bin/python -m ruff check src tests tools` | All checks passed |
| Dependency integrity | `.venv/bin/python -m pip check` | No broken requirements |
| Protobuf | `.venv/bin/python tools/check_protobuf_runtime.py` | pin/installed 7.36.2; upb backend |
| Panel registry | `.venv/bin/python -m patchtrace panels check` | Exit 0; 14 slots, 13 built, Guide not built, no conflicts. Existing unhandled import/advisory-anchor warnings retained. |
| Desktop smoke | `QT_QPA_PLATFORM=offscreen .venv/bin/python -m patchtrace --self-test` | Exit 0; synthetic sample and panel construction |
| Whitespace | `git diff --check` | Passed |
| Parallel full attempt | `QT_QPA_PLATFORM=offscreen timeout 900 .venv/bin/python -m pytest -q -n 4 --dist loadfile` | INCOMPLETE: all four workers reported Not properly terminated around 22–23%; no cause or test IDs retained. Coordinator interrupted this local attempt, exit 130. Not a full pass; not established as pre-existing. |
| Serial full attempt | `PYTHONFAULTHANDLER=1 QT_QPA_PLATFORM=offscreen timeout 600 .venv/bin/python -m pytest -q -x` | INCOMPLETE: exit 124 at the 600 s limit, progress 35%, no pytest final summary. No assertion failure was printed before the timeout; no aggregate pass count claimed. |

Integrated command:

```sh
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q tests/test_gui_*.py tests/test_ui_export*.py tests/test_ui_inspection_signing.py tests/test_ui_pemeta.py tests/test_ui_m3_docks.py tests/test_files_announcements.py tests/test_audit116_stale_inspection_failure.py tests/test_help_docs.py tests/test_spec_registry.py tests/test_tooltips.py
```

The two warnings are `QApplication.setActiveWindow` deprecations in the test-only
offscreen reshow helper. No production deprecation is introduced. Independent
review also ran 51 Export tests (before the final hide/show addition) and 33 Files
checks. The final integrated run includes those later tests. Forty-three changed
document links/anchors resolved; a real synthetic-sample/export smoke checked
profile switching and stable non-time content digests. An offscreen export render
was visually inspected; this is not native Windows or screen-reader acceptance.

[Retained raw logs and hashes](../qa/analyst-accessibility-20261109/) preserve the
completed GUI/help checks and incomplete full attempts. An earlier pair of local
runs was stopped before qualification while the last test-only reshow helper was
being finalized; no result is claimed for those superseded attempts. No external
workflow or another owner's process was cancelled or restarted.

## Remaining acceptance and scope guard

Full project acceptance is pending: diagnose the unexplained parallel worker
exits or obtain a complete serial/CI result. No unrelated test, algorithm or
runner fix was attempted. Windows NVDA/Narrator, Accessibility Insights, visible
focus, high contrast and DPI walks remain pending. No release, live backend or
accuracy acceptance is implied by these automated proxies.

Final implementation diff: only `ui_export_v2.py` and `ui_inspection.py` under
`src/`, their focused tests, existing help/spec pages and this coordination record.
The receipt adds only scoped QA/todo entries and logs. No intersection with the
changed files of #279/#259/#268, and no binary fixture or workflow edits. Shared
VirtualTable sorting and Engine evidence announcements remain with #176.
