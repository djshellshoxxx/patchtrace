# Preserve the active Python environment in subprocess tests

Date: November 5, 2026 (America/Los_Angeles); receipt filename uses November 6 UTC.

## Confirmed failure

Base: main `d02b94bcedb29dae201941f01f2c94d42ebbb297`.
The two affected test files are byte-identical on the current #244 candidate
`f393bb68ddc11eabb95a6598aa6f86650bd9aa37`.

Both modules computed their subprocess launcher with
`str(Path(sys.executable).resolve())`. In a normal symlink-based virtual
environment this selects the base interpreter, which can have a different
dependency set. The child then cannot exercise the intended positive control.

The unchanged tests reproduced **2 failures in 2.61 seconds**:

- `test_pure_python_runtime_is_refused_in_a_fresh_interpreter` reported
  `protobuf_missing` rather than the required `protobuf_not_upb`.
- `test_parent_never_imports_yara_x` failed its positive-control import because
  the selected base interpreter lacked YARA-X, despite the parent environment
  having the pinned engine installed.

## Narrow correction

Use `sys.executable` unchanged for both test launchers, matching the existing
production `binexport_run.worker_argv()` and `rules.runner.worker_argv()` paths.
This retains the selected virtual environment. All assertions, child environment
filters, positive controls, process/memory limits and cleanup checks are unchanged.
No production, dependency, workflow, schema or acceptance threshold changes.

## Verification

Using the same original symlink-based environment, CPython 3.12.14, protobuf
7.36.2, YARA-X 1.21.0 and `QT_QPA_PLATFORM=offscreen`:

```sh
python -m pytest -q tests/test_binexport_isolation.py tests/test_rules_worker.py
```

Result: **116 passed in 42.16 seconds**, with no skips or expected failures.
Whole-repository Ruff, `pip check`, and `git diff --check` passed. Independent
review found no issue and confirmed that no assertions changed; the reviewer
separately reran the two original controls: **2 passed in 2.70 seconds**.

This focused result is not a full-suite, Windows or native-tool qualification.
The local AF_UNIX socket-construction restriction documented in #245's earlier
qualification receipt remains separate; this repair neither changes that test
nor introduces an exemption. Current-head hosted gates remain required before
merge.
