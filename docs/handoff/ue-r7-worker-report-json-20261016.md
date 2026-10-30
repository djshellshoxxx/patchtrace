# UE-R7 U7-11: strict worker-report JSON handoff (2026-10-16)

**Status: IMPLEMENTED, RED/GREEN REGRESSIONS AUTHORED, CI NOT YET VERIFIED.** Do not infer live-tool success from synthetic tests.

## Basis and ownership
- Source: `docs/handoff/unified-engine.md` UE-R7 U7-11 and `docs/specs/unified-engine/13-remaining-work-plan.md`; policy in `AGENTS.md`, `CLAUDE.md`.
- Isolated branch: `chatgpt/ue-r7-strict-worker-report-20261016-a` from integration head `53f366e8b50ac60a95bdb3734b815daac82cd63d`; does not touch the concurrent LBL-31/LBL-32 or UE-R3 work.
- Defect: `exchange.read_report` used Pydantic `model_validate_json` without the `strict_json` duplicate-key and non-finite-number gate used already by `read_request` and `read_refacts`. A report with `{"ok":true,"ok":false}` had an ambiguous status: parser choice could select one. Nested duplicate keys were similarly unguarded.

## Files and verification register
| Requirement | File | State | Verification |
|---|---|---|---|
| Strict report exchange policy | `docs/specs/unified-engine/02-data-model.md` | Spec updated | Review |
| Duplicate keys, nested duplicates, NaN/overflow rejected | `tests/test_unified_worker.py` new `test_read_worker_report_rejects_noncanonical_json` | Five parametrized regression cases committed before fix | Run focused on Linux/Windows |
| Report reader follows request/refacts strict parser; invalid returns None | `src/patchtrace/unified/exchange.py` | Implemented | Run focused tests and CI; check existing valid report round-trip |
| Live report compatibility, frozen worker | GitHub Windows QA/native tools | Unverified | Must not claim live acceptance |

No persisted schema version changed; the exchange is private and is not schema-generated. Existing valid `WorkerReport.model_dump_json()` output stays accepted. The owner sees `None` for invalid reports and applies its existing worker exit classification.

## Exact continuation
1. Run `PYTHONPATH=src:. QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_unified_worker.py tests/test_unified_import_dag.py` and `python -m ruff check src tests tools` on the PR head. Confirm the five hostile fixtures and valid worker report round-trip.
2. Read full Ubuntu/Windows QA results on the current commit. Resolve any failures test-first; no weakening of strict validation. Verify `git diff --check`.
3. Merge this small PR to `claude/instance-d-gui` only with green relevant checks, then verify merge ancestry. Another isolated UE-R7 PR (`chatgpt/ue-r7-p15-unresolved-20261016-a`, #83) is in flight and changes different code; do not overwrite it.
4. Continue UE-R7 U7-06..U7-18 by independent scoped slices or UE-R1/UE-R2 live gate work, remembering that G-U1..G-U8 are not proved live and the feature remains OFF.

## Notes
Regression tests exercise JSON parsing and synthetic outputs, not a real Ghidra worker. No target binary was executed or added.
