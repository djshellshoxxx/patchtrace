# Slice card GUI-C - announce panel state changes to assistive technology (E-D06; tracker T5, G5)

Evidence and design: `jq '.actionable_now[] | select(.id=="E-T03")' docs/status/inventory/E.json` and `jq '.features[].defects[]? | select(.id=="E-D06")' docs/status/inventory/E.json`.
Spec: docs/specs/gui-framework.md (StateView, announcer), docs/specs/accessibility-baseline.md (read-only).

Three panels change state (loading, empty, error, ready) without ever telling a screen reader: the evidence panel, the
Search panel and the KB dock. Commit 647502ce "fix(gui): announce evidence panel state changes (T5/G5)" on
origin/claude/ws-p-20261104 (PR #176) applies cleanly to main (the analyst checked with git apply --check): port it as
it is for the evidence panel (`git -C <worktree> show 647502ce`; say "ported from 647502ce (PR #176)" in the commit
body), then give the Search panel the same wiring.

1. Evidence panel: port 647502ce (src/patchtrace/ui_evidence.py, tests/test_evidence_host.py).
2. Search panel: src/patchtrace/search/qt_panel.py - wire the StateView announcer. The panel already announces result
   messages itself (about line 438): a state change must produce exactly ONE announcement, not two. Test in
   tests/test_ui_search_panel.py.
3. The KB dock (src/patchtrace/kbcorrelation/panel_qt.py) is being rewritten by slice K3 of this session right now: do
   not edit it; write the exact wiring needed there under "Integrator asks" (file, function, the two or three lines).
Acceptance: a forced error state in each of the two panels produces exactly one assertive announcement on a
RecordingAnnouncer (find the recording announcer the framework tests use); loading/ready transitions are polite; no
announcement repeats when the state is set to the same value twice.
Run each new test 10 times in a row.

## Owned files
src/patchtrace/ui_evidence.py, src/patchtrace/search/qt_panel.py, tests/test_evidence_host.py,
tests/test_ui_search_panel.py.
NOT yours: src/patchtrace/gui/qt/** (slice GUI-B), kbcorrelation/panel_qt.py (slice K3), search/saved.py (another
session), ui.py, tooltips.py.
