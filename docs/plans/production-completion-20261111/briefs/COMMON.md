# COMMON RULES (every inventory analyst)

ROLE: read-only repository analyst producing one section of an authoritative remaining-work inventory for PatchTrace
(binary patch-diffing desktop app + CLI; Python 3.12, PySide6; GitHub repo djshellshoxxx/patchtrace).

## Environment
- Checkout: <main checkout> on main @ 882d1ca0 (full history; every remote branch is readable as origin/<name> via
  `git -C <main checkout> show|log|diff`). STRICTLY READ-ONLY: never fetch, checkout, commit, stash or write inside the
  checkout (a full test run is using it). Your shell cwd is a DIFFERENT repository: always use absolute paths / `git -C`.
- First read <main checkout>/AGENTS.md (short engineering policy).
- Python: python (project deps installed). Allowed: quick read-only commands, e.g.
  `cd <main checkout> && PYTHONPATH=src QT_QPA_PLATFORM=offscreen python -m patchtrace --help`;
  one focused pytest file with `-q -p no:cacheprovider` only if it finishes in under 90 s. Never run the whole suite or anything
  CPU-heavy (4 cores shared with other agents and a running baseline suite).
- No external network. Native tools (Ghidra, Rizin, BinDiff) are NOT installed here; live data hosts (NVD, MSRC, Winbindex,
  CISA) are unreachable.
- GitHub reads (only if your brief asks): load tools with ToolSearch query
  "select:mcp__github__actions_list,mcp__github__pull_request_read,mcp__github__get_job_logs,mcp__github__issue_read";
  owner "djshellshoxxx", repo "patchtrace"; keep pages small (perPage <= 5); never post or modify anything.
- Trackers: tasks/todo.md (items), docs/qa.md (evidence), docs/modules.md (built slices), docs/specs/REGISTRY.md (spec
  statuses), docs/plans/master-todo-d.md. They can be stale: verify against code before trusting.
- Scratch space for your own temp files: <scratch>/inventory/tmp-<your key>/

## Active lanes owned by OTHER sessions today
Inventory these areas normally and set `active_lane_overlap`, but put NO `actionable_now` task inside their files.
- L1 unified-engine soundness (#259 follow-up: swap orientation, IR-only one-sided functions, DATA-MAP vote, reversal
  asymmetry) - branch claude/funny-feynman-d2m0b5 - src/patchtrace/unified/{sources,ladder,fusion,facts}/**,
  unified/registry.py, unified/keys.py, docs/specs/unified-engine/**.
- L2 unified live gates / native proof (#268, #174, #139-#141) - branches claude/live-proof-20261111,
  claude/live-harness-infra-20261111 - tools/unified/**, src/patchtrace/backend.py,
  .github/workflows/unified-live-gates.yml, tools/calibration/tier_r/**.
- L3 open-PR consolidation ledger (#179) - docs/plans/ledger-consolidation-20261104.md, tools/dev/branch_inventory.py.
- L4 release-job naming/pinning - .github/workflows/qa-windows.yml (release job), tests/test_release_gate.py.
- L5 SPEC-53 backend diagnose launcher (#280) - backend.py diagnose path, tests/test_backend_cli.py.
- L6 analyst accessibility (Codex, 2026-11-09, branch codex/analyst-accessibility-20261109) - src/patchtrace/ui_export_v2.py,
  src/patchtrace/ui_inspection.py, docs/help/**, tests/test_files_announcements.py, tests/test_ui_export_accessibility.py.
- L7 Codespaces bootstrap (#279) - .devcontainer/**.

## Evidence rules (repo policy)
Keep evidence classes separate: mocked | synthetic | fixture | live-native | none. Mocked or synthetic tests are never live
compatibility evidence. Never invent numbers, versions or results; write UNVERIFIED for anything you did not check. Every
defect needs file:line evidence and a concrete failure scenario. Percentages must be derived from counted acceptance items
(state the counts in `basis`), not intuition. Implementation completion and validation completion are different numbers.

## Output
1. Write the full inventory as JSON to your OUTFILE with this shape:
```
{"workstream": "<key>", "title": "...", "baseline": "main@882d1ca0",
 "features": [{"id": "<key>-F01", "name": "...", "spec": ["docs/specs/..."], "code": ["src/..."],
   "status": "implemented|partial|missing|blocked-external|deferred-by-design",
   "implementation_pct": 0, "validation_pct": 0,
   "verified_by": ["tests/test_x.py (fixture)"], "evidence_class": "mocked|synthetic|fixture|live-native|none",
   "remaining": ["..."],
   "defects": [{"id": "", "severity": "critical|high|medium|low", "summary": "", "evidence": "path:line",
                "failure_scenario": "", "proposed_fix": "", "regression_test": ""}],
   "blockers": [{"type": "external-tool|owner-decision|windows-only|live-network|other-lane|none", "detail": ""}],
   "effort_hours": 0, "confidence": "high|medium|low", "acceptance_tests": ["..."], "active_lane_overlap": "none|L1..L7"}],
 "actionable_now": [{"id": "<key>-T01", "title": "", "why": "", "files": [""], "tests": [""], "size": "S|M|L",
   "priority": 1, "risk": "", "depends_on": [], "lane_conflict": "none|L#", "acceptance": ""}],
 "notes": ""}
```
   `actionable_now` = bounded tasks that can be implemented AND verified in this sandbox (pure Python, offline, red/green
   testable), ordered by priority (1 = first; correctness / data integrity / security before features before polish). Be
   concrete: exact files and the test that would prove it. Prefer 5-15 well-evidenced tasks over a long speculative list.
   Verify each is still open on main before listing it.
2. Validate: `python -m json.tool OUTFILE > /dev/null`.
3. Return the structured summary: top_actionable (at most 8), critical_defects (at most 6, severity high or critical only),
   external_blockers (short strings), completion {implementation_pct, validation_pct, basis}, summary (<= 120 words).
