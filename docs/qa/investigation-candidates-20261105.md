# Saved-index desktop candidate inspection — 2026-11-05

Base: advisory-sync commit `bf46954ef2c6c9a278d9b78f5b4274242e617e09`. Isolated worktree `/tmp/pt-independent-candidate-wizard-20261105`, branch `work/investigation-candidates-20261105`. Coordinator approved the bounded internal facade additions before implementation; SPEC-31-F records them. Only the existing investigation facade/UI, a new focused test file, that spec addition and this receipt are owned. No serialized model, schema, provider, matching or ranking interface changed.

## Working vertical slice

After an advisory and explicit product selection, the analyst enters a component basename, inspects saved-index candidates, explicitly selects a pair and requests its metadata-only preview. Existing `KbService.pairs` and `KbService.plan` own candidate policy/order and the zero-request index plan. Validated IndexPort rows add per-side architecture, size, file version, observed builds and exact canonical record hashes. The UI labels these as unverified index claims, preserves reasons/grade/tier/window and never selects the first row automatically.

The immutable selection captures a full pair id, investigation revision and digest over the exact candidate/source claims, selected product and retained advisory-source metadata. The backend checks the captured KB/CVE against the stored investigation lead, checks scope ownership, re-resolves before selection, and rechecks after the pure domain plan. Source replacement with unchanged binary hashes, advisory metadata/revision changes, filename changes, partial pair ids and mutation during planning return stale. No project creation or network consent follows from this preview. The existing local/manual pair preview is the only route that enables creation; its reopened-project hashes remain exact.

Editing inputs, changing product/mode, starting another operation, cancelling or closing clears the candidate list. Changing selection during a pending preview cancels that generation; a late result cannot display a previous pair. All worker inputs are immutable plain values and backend/provider work remains outside Qt. Only the explicitly requested filename is rendered, even when older analyst component decisions cause the underlying domain lookup to return other files; domain-wide file-index warnings remain explicitly identified.

## Reproduction and focused verification

All advisory and Winbindex data are existing authored/synthetic fixtures. Tests deny socket creation/connection/DNS; no live evidence is claimed.

- Baseline: 2 failures in 2.86 s — the task request lacked `component_name` and the real dialog lacked its component/candidate controls. Raw log `/tmp/pt-independent-candidate-wizard-red.log`.
- Additional reproduced display defect: other previously entered filenames appeared in the explicit component's candidate text (1 failed, 24 deselected); filtered presentation now matches the exact component. Raw log `/tmp/pt-independent-candidate-wizard-component-red.log`.
- Final: **336 passed in 15.77 s**, raw log `/tmp/pt-independent-candidate-wizard-final-verified.log`.
- Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=$PWD/src python -m pytest -q tests/test_kb_candidate_journey_20261105.py tests/test_kb_online_investigation_20261105.py tests/test_kb_accessibility_20261105.py tests/test_ui_kb_investigation.py tests/test_kb_investigation_service.py tests/test_kb_binary_only_start.py tests/test_kb_current_project.py tests/test_kbc_pairs_index.py tests/test_kbc_resolver.py tests/test_kbc_contracts.py`.
- Whole-tree `python -m ruff check src tests tools` and `git diff --check` pass. `PYTHONPATH=$PWD/src` binds test imports to this worktree without a shared editable install.

The final selection covers real store/domain candidate provenance, unchanged investigation state after preview, explicit/no-automatic choice, a real local pair → create → reopen hash journey, missing index, ARM64/server blockers, invalid scope/path/lead, full-id enforcement, retained-source and revision drift, source mutation during plan, context invalidation, ignored late results and a changed selection between two real candidate rows. Earlier 325/332-pass development runs each had one authored server fixture failure: the fixture initially searched a client-only KB, then reused that KB with a server CVE investigation. The test now uses the correct CVE lead; no production guard or assertion was weakened. Intermediate passing selections overlap and are not additional unique acceptance.

## Remaining gates

Saved-index inspection/selection is complete for this slice. Actual Winbindex metadata retrieval, candidate binary acquisition, consented download/create and the full online acquisition wizard remain independent pending work. The zero-request domain index preview is not an acquisition consent plan. Index-reported architecture/lineage and candidate rank do not verify local bytes or establish a CVE fix. No native Windows, high-DPI, screen-reader, frozen-package or live-source acceptance is supplied. PR #205 and pinned-native builds/processes/worktrees/logs were untouched; no broad suite or GUI stress suite was started.
