# Desktop advisory sync vertical slice — 2026-11-05

Base: keyboard-accessibility commit `b5d4bceabdc34f520120d9dc336d975768e20483`, itself based on published PR #218 head `afc8a2967ba3dec6b1ac3351d20dd08c193ba9bc`. Isolated worktree `/tmp/pt-independent-online-wizard-20261105`, branch `work/online-investigation-20261105`. Scope approved by the coordinator before edits; SPEC-31-F updated before the internal task additions. No serialized model, schema or database shape changed.

## Implemented path and boundaries

An explicit CVE or KB plus explicit advisory-month scope now supports a source-download preview and a separate one-use fetch action. The preview uses the existing `sources.net_plan.IndexPlan`; it displays every URL, exact host set, fixed Accept/User-Agent headers, every cap, digest and existing live-endpoint limitation. The task request carries immutable strings/tuples. Backend orchestration strictly checks size and duplicate/nonfinite JSON, validates the existing IndexPlan JSON contract, rebuilds the current plan from the captured month scope, checks equality and exact consent, then calls the existing hardened CVRF transport. UI code owns no provider or network behavior.

Each accepted monthly document is independently committed through WorkspaceStore using `to_imported` provenance. Prior imported bytes/authenticity are retained; malformed or failed source responses do not replace valid sources. Cancellation reaches the transport and keeps completed documents. After sync the existing KbService local search supplies explicit product/architecture choices; the established local-pair preview/create/adopt route retains exact pair hashes. Editing inputs, changing mode, searching, cancelling or closing invalidates the preview; stale callbacks cannot restore consent. No source consent is persisted or carried to binary acquisition.

The new real-dialog journey initially failed on the baseline with `KeyError: months` (1 failed, 11 deselected). Implementation review additionally reproduced truncation of a valid 24-month exact consent preview by the shared 4,000-character SafeTextView default (1 failed, 33 deselected). Only this dialog's details view now has a bounded 64 KiB capacity; a maximum-scope test verifies the complete rendered plan and every URL remain visible before enabling fetch.

## Deterministic verification

All source responses are authored existing synthetic fixtures through an injected opener. The `no_sockets` fixture refuses socket creation, connection and DNS. Successful fake transport or Qt tests are not live MSRC compatibility evidence.

- Real UI missing-feature red log: `/tmp/pt-independent-online-wizard-red.log`.
- Maximum-plan truncation red log: `/tmp/pt-independent-online-wizard-truncation-red.log`.
- Intermediate integration: 245 passed in 29.59 s, then 254 passed in 24.49 s as negative/privacy controls expanded; selections overlap.
- Maximum-plan repair integration: 255 passed in 22.14 s across the new source journey plus existing accessibility, wizard, service, binary-only, current-project and KB import-boundary tests. Final verification after newline-rendering correction: **255 passed in 34.64 s**, raw log `/tmp/pt-independent-online-wizard-verified.log`.
- Exact source binding: `PYTHONPATH=$PWD/src python -c 'import patchtrace; print(patchtrace.__file__)'` resolves `/tmp/pt-independent-online-wizard-20261105/src/patchtrace/__init__.py`.
- Final command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=$PWD/src python -m pytest -q tests/test_kb_online_investigation_20261105.py tests/test_kb_accessibility_20261105.py tests/test_ui_kb_investigation.py tests/test_kb_investigation_service.py tests/test_kb_binary_only_start.py tests/test_kb_current_project.py tests/test_kbc_contracts.py`.
- Whole-tree `python -m ruff check src tests tools` and `git diff --check` pass.

Tests cover CVE and KB starts, no-network/no-workspace-write planning, full header/cap/URL/digest display, absent/wrong-host/wrong-digest/stale-month consent, duplicate/nonfinite/unknown/oversized plan JSON, invalid and future scopes, binary-only refusal, source failure/partial results, cancellation preserving committed data, prior source bytes/authenticity, plan revocation and stale callbacks, exact fixed outgoing headers, no local path/name/hash transmission, and the real preview → consent → product → pair preview → create → reopen journey with matching manual-pair hashes.

The first implementation's Python-dict Pydantic validation refused serialized tuple fields; the backend now runs the strict duplicate/nonfinite precheck and the existing `IndexPlan.model_validate_json` contract. An initial test used the nonexistent `ProjectService.state`; its reopened hash assertion now uses the actual `ProjectService.project` aggregate. Those failed development runs remain in the dedicated raw logs and are not represented as acceptance.

## Remaining gates

This is the advisory-sync plus local-pair vertical slice. Online candidate discovery/download, product-only start and the full online acquisition wizard remain partial. No real network request, target execution, native build, broad suite or GUI stress run was performed. PR #205's frozen candidate/process/logs and pinned-native worker ownership remain unchanged. Live endpoint qualification, clean/frozen Windows accessibility/high-DPI and release acceptance remain separate unverified gates. Internal dataclass additions do not change generated schemas.
