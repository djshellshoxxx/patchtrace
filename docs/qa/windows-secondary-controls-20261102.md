# Windows secondary quarantine controls — 2026-11-02

Source test repair: `3731a8cfae1e5bed7f2311400586db831a606395`, tree
`2300c46ad0062f397b588ba1b4721826f39d2436`; base
`eccfb8d587f94e927f857fad248531a002ecc36c`. Author: `/root/msrc_recover`.

The exact Windows CI tracebacks in `reconciliation/ci-monitor-20261102/windows-51a9b4af-failure-tracebacks.txt`
identify two synthetic fixture assumptions. Production behavior is correct and unchanged:

- `test_synthetic_good_output_still_refuses_quarantined_version` expected LF bytes while its Python child used
  text `print`, which emitted CRLF on Windows. Local byte calculation reproduces both trace digests exactly:
  LF `39470673eacbf593cfe92bdde85835bb875ec7f5d2df5f7baf9f03f76197185b`; CRLF
  `7da3dbdc9e5e8d83f0bcc053c53ed5ac0ab69a62aa8b1372df42598c3c098033`. The latter is the actual digest in the
  quarantine error, as required by SPEC-11's exact-stdout evidence contract.
- `test_affected_probe_is_explicit_and_cannot_reuse_old_scheduler_cache` used `/historical/pinned/rz-diff`.
  `PureWindowsPath` correctly classifies it as lacking a drive and therefore not absolute. The registry refused
  this path before the injected probe; the absent observed version was not a quarantine regression.

The first test now binary-writes explicit LF and CRLF payloads and asserts each exact digest while retaining
failure/no-match-set/ordered-ownership assertions. The second uses actual temporary absolute paths containing
spaces with `rz-diff` and `rz-diff.exe` names. These inert placeholder files are never executed. A recording
probe runner verifies the exact `-v` invocation, and a fail-on-match runner proves quarantine stops before
matching. Existing cache nonuse, observed version and stored evidence assertions remain.

Fresh focused verification:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q tests/test_evidence_panel_service.py tests/test_rzdiff_orientation_20261101.py
```

**52 passed in 1.69 s**. Changed-test Ruff and `git diff --check` passed. An additional constructed Windows-path
control used the actual registry/probe with `PureWindowsPath` and a recording runner: the original root-relative
path was refused before probe, while `C:\synthetic tool path\rz-diff.exe` reached the observed 0.9.1 orientation
quarantine exactly once. No native process ran in that control.

Only tests and this receipt change. There is no producer-version downgrade, quarantine weakening, production
code or persisted contract change. This is local Linux verification of explicit cross-platform controls; fresh
Windows CI is still needed and remains coordinator-owned. No native/heavy/full-suite run was started.
