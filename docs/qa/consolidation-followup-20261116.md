# Consolidation follow-up — 2026-11-16

Base: PR #297 head `f64620f7771b205558871fe09448eb1dd6df715a`.
This follow-up is separate so the original integration's running checks are not restarted.

## Reviewed changes

- Recover PR #283's missing-tick and interrupted MD-dump repairs. Missing, Boolean,
  negative and noninteger work counts fail closed; zero denominators cannot pass.
  Independent review found float overflow on large counts; exact integer comparison
  and bounded informational formatting repair it, including threshold regressions.
  Timeout/cancellation/output-limit reasons override a zero child exit code.
- Recover PR #281's tag-aware release naming and immutable release action pin.
  Upstream v2.6.2 resolves to `3bb12739c298aeb8a4eeaf626c5b8d85266b0e65`.
  Both missing-behavior tests reproduced failure before the repair. QA gates remain intact.
- Complete PT-TIMEOUT-1 entry controls: Custom/1h/2h/4h presets, explicit integer
  validation, inline accessible errors, and Save/Diagnose refusal before settings or
  backend construction. Preserve the existing 10–86,400-second range and default.
  This does not repair performance or qualify the owner's Windows pair.
- Recover a missing backup-verification regression from #164: a failed second
  observation revokes cached trust, preserves bytes, and requires re-verification.
  Production backup behavior was already present.

Independent source review and focused tests found no remaining blocking issue in
these changes. Review is scoped; it does not certify the entire project.

## Verification

Combined offscreen Linux run: **480 passed, 3 xfailed** in 68.92 seconds:

```
tests/test_unified_bench.py tests/test_unified_parity.py
tests/test_unified_har_bench.py tests/test_unified_gates.py
tests/test_release_gate.py tests/test_milestone_notes.py
tests/test_workflows.py tests/test_codex_pkg_workflows.py
tests/test_ui_timeout.py tests/test_ui_setup_dialog.py
tests/test_ui_profiles.py tests/test_ui_symbol_local.py
tests/test_tooltips.py tests/test_ui_capabilities_panel.py
tests/test_gui_settings.py tests/test_ui_bundle_setup.py
tests/test_backend_progress.py tests/test_ui_backend_progress.py
```

`tests/test_verified_backup_byte_integrity.py`: **13 passed**.
Whole-tree Ruff and whitespace checks passed. No schema contracts changed.
Hosted Windows/Linux/Qt/package qualification remains required on the published head.
The original integration's incomplete local full-suite evidence and native/manual
release limitations remain documented in `continuation-20261116.md`.

## PR housekeeping

Closed #188, #192, #203, #206, #207, #208, #215, #216, #217 and #219 only after
confirming each current exact head is an ancestor of main `74010784`, and reviewing
retained source/tests or documentation. Branches remain intact. Closing #208's
historical evidence PR does not resolve the native blockers recorded in it.

PR #164 still contains a worthwhile separate Tier R provenance/label/receipt slice.
PR #222's additional native IO research controls remain separately reviewable;
historical artifact integrity is not fresh native qualification. Neither branch
should be merged wholesale. Original-pair timeout, clean-machine Windows and
manual assistive-technology acceptance remain open.
