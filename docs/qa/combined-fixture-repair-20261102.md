# Combined CI fixture repair — November 2, 2026

Base: `178fbea` on the recovered central branch. The exact eleven original Linux CI failed nodes reproduce locally: 11 failed. Raw JUnit and command record are retained in the adjacent archive.

No production, quarantine, pin, workflow, or assertion of native compatibility changed. Positive synthetic adapter/evidence/calibration fixtures now identify the unaffected synthetic 0.9.0 dialect. The header expectation follows that fixture. The desktop self-test failure assertion matches its actual frozen-journey error and retains resource-close assertions.

Added same-shape 0.9.1 negative controls: blocked production probe; failed fake-probe output parse with exact stdout SHA-256 in the diagnostic and original input ownership; calibration not-comparable/abstention without modifying stored source rows/digests. This synthetic training identity check is not real calibration acceptance.

The first expanded run found two incorrect new assertions (expecting profile G rather than not-comparable, and a run digest field rather than the retained error diagnostic). Both are retained in the initial-green log; corrections follow the existing stricter contract. Final related selection: **163 passed**. Whole-repository Ruff and whitespace checks passed. Independent review and combined full/Windows CI remain required.

Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests python -m pytest -q --tb=short tests/test_audit2_fixes.py tests/test_audit_desktop.py tests/test_calibration_tools.py tests/test_evidence_panel_service.py tests/test_evidence_ui.py tests/test_tier_r_eval_engines.py tests/test_rzdiff_orientation_20261101.py`.
