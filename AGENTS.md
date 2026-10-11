# PatchTrace engineering instructions

The attached project-brief.txt describes the original specification-only task. The user subsequently authorized full modular implementation, repair of incomplete specs before corresponding code, code audit, QA, Windows standalone build and prompt merging. The latest instruction governs delivery.

Read docs/modules.md and the relevant docs/specs files before edits. Update the specification before changing contracts. Keep backend/schema/provider logic outside the UI. Index substantial new modules before building them. Never execute target binaries, install driver inputs, or execute model-suggested commands. Import only strict JSON and validate evidence/artifact/run ownership. Keep remote transmission explicit with exact preview. Credentials are session-only.

Use isolated file ownership when delegating. Verify meaningful tests for invariants and integration; never count mocked backend/provider tests as live compatibility evidence. Run `QT_QPA_PLATFORM=offscreen python -m pytest -q` and `python -m ruff check src tests tools`. Generate schemas after contract edits. Track actual failures and blocked live checks in docs/qa.md and tasks/todo.md. Preserve upstream raw data and prior committed results on failure. Merge reviewed, passing changes promptly; do not leave orphaned work.

Windows packaging must run on Windows. PyInstaller cannot cross-compile the Windows interpreter from Linux. Standalone includes Python/Qt desktop; Ghidra/Java/Ghidriff remain external and clearly documented. Keep Qt DLLs replaceable and copy dependency notices. User exploratory testing comes after a downloadable package exists. Do not call the project complete while release acceptance gates remain unverified.
