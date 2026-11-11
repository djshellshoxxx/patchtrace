# Windows package preflight preparation — Linux authored fixtures

Base: PR #218 `afc8a2967ba3dec6b1ac3351d20dd08c193ba9bc`.
Worktree: `/tmp/pt-independent-coordinator-20261105`. Date: 2026-11-05.

Added a source-indexed, read-only desktop ZIP preflight and a clean Windows evidence
runbook. The preflight checks externally supplied digest/commit/label, bounded ZIP
directory/metadata, strict manifest/inventory, paths, current PyInstaller runtime
layout and Python/Qt notice presence. It does not extract or execute bytes. It does
not perform a Windows build or close any Windows/native/offline/manual gate.

Independent security review identified NUL-truncated names, overlong Windows path
components, misplaced runtime DLLs, a ZIP64 locator overriding an ordinary bounded
directory, malformed DEFLATE escaping failure JSON, nonregular input open behavior,
and unsupported LZMA compression. All are addressed with focused regression
controls. The ZIP64 bypass and malformed DEFLATE receipt controls explicitly failed
before repair (2 failed), then passed. Initial 51 checks, intermediate 55/58 checks,
and final **60 passed** overlap and are not cumulative coverage counts.

Completed: `PYTHONPATH=$PWD/src python -m pytest -q tests/test_windows_package_preflight.py`
(60 passed in 2.91 s); independent final security review **60 passed in 1.72 s**;
`python -m ruff check src tests tools`; `git diff --check`.
Fixtures contain authored strings in DLL/EXE-named ZIP members; none is an actual
runtime binary and none was executed. The archive mutation check uses observed
handle metadata; no hostile-filesystem sandbox or publisher-authenticity claim.

Not run: actual downloaded candidate inspection, native Windows PyInstaller build,
resource reader on a real package, Windows portable/installer smoke, screen reader,
high-DPI/manual M-gates and disconnected full-bundle/native analysis. Those require
their exact-head Windows/package evidence. PR #205's source and running full suite
and the native Rizin owner's worktrees/processes/logs remain untouched.
