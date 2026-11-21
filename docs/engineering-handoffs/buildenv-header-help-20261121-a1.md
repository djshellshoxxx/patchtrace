# Build environment column-header help — isolated handoff (2026-11-21)

**Ownership:** bounded Build environment accessibility author scope only.
Root837FE has the Search header, P2 storage, PR #349 integration and CODEX-1
lease through 2026-11-21T08:00:00Z (unless a newer handoff releases it).
Do not modify those worktrees/branches or advance PR #349 on this handoff's
authority. No parallel reviewer is claimed active.

**Starting source:** PR #349 immutable
`11f51c105bf63946f59373ae605b937c4fee607a`, tree
`4939056ceb0e02b419c820b9e5748c869c40a857`;
new independent branch `codex/patchtrace-buildenv-header-help-20261121-a1`.
Main remains outside this change.

## Source and tests

- Contract amended *before implementation*: section 12 of
  `docs/specs/program-e/DIE-integration-plan.md`.
- `src/patchtrace/buildenv/tooltip_entries.py`: five new panel-owned
  `build_env.col.fact/older/newer/status/basis` registered tooltips, with
  evidence-source and interpretation limits.
- `src/patchtrace/buildenv/panel_model.py`: five
  `ColumnSpec.tip_id` assignments only; existing keys, title strings,
  cell getters, width and `SPEC` search/key semantics preserved.
- `tests/test_buildenv_header_help_20261121.py`: actual
  `VirtualTable` model Qt roles for all five headers; unchanged
  prepared display values and row identities after filter; five
  single-header mutation controls.
- `docs/qa.md` records actual proof and acceptance limits.
- `docs/engineering/evidence/buildenv-header-help-20261121-a1.json`
  records exact before/after Git blob IDs, baseline failure, five
  successful bindings and 10 negative source mutations.

## Qualification discipline

**Executed:** checked immutable connector source; all 5 new bindings and
registrations present; baseline check fails; each of five absent bindings
and five absent registries independently detected; original non-header
source content recovered identically after removing scoped additions.
No source-visible state/query/row change observed in these two production
files.

**Not executed/qualified:** source-bound Python pytest, Ruff, dependency
check, supported Qt/offscreen host activation, whole-tree audit,
independent peer signoff, hosted QA/Windows/native/packaging, actual
NVDA/Narrator. There is no clone-backed checkout/network egress in this
runtime; source-controls are not substitutes for these gates.

Next fresh reviewer, with own checkout and environment:

```sh
git fetch origin codex/patchtrace-buildenv-header-help-20261121-a1
git worktree add /tmp/patchtrace-buildenv-header-peer FETCH_HEAD
cd /tmp/patchtrace-buildenv-header-peer
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_buildenv_header_help_20261121.py
QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_gui_table.py
python -m ruff check src tests tools
python -m pip check
```

Inspect whether the global registered-tip audit discovers Build environment
on an actual host, verify header tooltip strings are registered in real
QTableView sections, then run the relevant Build environment controller
and existing tooltip audit tests. Capture failures without editing tests
to make failures disappear. Review that only header metadata changes,
that no global exemption was added, and that untrusted values are still
sanitized. No native screen-reader claim from offscreen.

Only after Root837FE's hold is released, refresh exact PR #349/current
main and ledger owners, review changes against newer source, integrate
using guarded commits, and qualify that *new combined head*. Do not
interpret parent PR #349 runs as new-source acceptance. Do not merge to
main or publish/deploy/release absent all applicable acceptance and an
explicit guarded REST authorization with both `[no release]` and
`[no deploy]` in the resulting merge commit. CODEX-1/5, raw provenance,
Windows trust/accessibility and L1/L2/L3 remain open.
