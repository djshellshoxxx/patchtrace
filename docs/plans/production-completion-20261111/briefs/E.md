# WORKSTREAM E - GUI and analyst experience
Scope: src/patchtrace/ui.py (3065 lines) and ui_*.py, src/patchtrace/gui/** (framework: host, panel registry, VirtualTable,
StateView, TaskRunner/Lane in gui/qt/tasks.py, palette, GraphCanvas), panel_manifest.py, tooltips.py, ui_help.py, help/ and
docs/help/, sample.py (first-run sample).
Specs: ui.md, gui-framework.md, gui-preflight-inspection.md, accessibility-baseline.md, DOCKABLE-WORKSPACE-SPEC.md,
docs/specs/panels/*, multi-engine-evidence-panel.md, series-window.md, docs/specs/program-e/GUI-integration-plan.md,
GDE-integration-plan.md.
Audits/QA: docs/audits/20261015-gui-framework.md, 20261015-qa-gui-stress.md, 20261015-fixes-gui-ops.md,
20261104-unified-gui.md; docs/qa/investigation-accessibility-20261105.md, desktop-index-refresh-20261105.md.

Verify EACH item of docs/plans/master-todo-d.md sections T (T1..T19), G (G1..G8), Q (Q1..Q4) against current code:
done / open / obsolete, with file:line.
Then assess the directive list: binary selection and import; analysis configuration; adapter selection; comparison
execution; progress reporting; function comparison views; difference navigation; CVE correlation results; patch
recommendations; evidence inspection; manual corrections; analysis history; result filtering and searching; export; error
reporting; keyboard navigation; accessibility (master-todo Q4 says 54 controls lacked accessible names - re-measure by
grep/introspection if cheap); first-run onboarding; help and troubleshooting; long-running operations must not freeze the
GUI (which operations still run on the GUI thread?); cancellation correctness. List which panels in the manifest are built
versus stubbed.

L6 owns ui_export_v2.py, ui_inspection.py, docs/help/**. actionable_now: concrete small GUI fixes with pytest-qt offscreen
tests (e.g. T4 keyboard sort path, T5 StateView announcer, T15 TaskRunner teardown hardening, T16 palette cap, T17
ColumnSpec.tip_id headerData, T18) - only those you verified are still open. PR #176 (branch origin/claude/ws-p-20261104)
reportedly already implements column-header tooltips via ColumnSpec.tip_id and Alt+Up/Down keyboard header sort: check
`git -C <main checkout> diff origin/main...origin/claude/ws-p-20261104 --stat` and say which commits could be ported
instead of rewritten (name the commit ids).
