# Focused QA diagnosis: table call accounting and local Unix sockets

## Scope and disposition

Frozen source: `bffcfa99d6a5044024256edbc0457ab20c92cbae`.
Diagnosis branch: `codex/qa-diagnosis-20261120-4c8d`.

This change repairs an independently reproduced **test-harness ownership
error** in the lazy-table call counter. It changes no application code,
performance threshold, existing test assertion, network guard, or skip policy.
The original aggregate table failure is **not attributed** to this defect.
The frozen unsplit run ended at `2026-11-20T00:32:03.102136+00:00` with child
exit code **-9 (SIGKILL)** after **1,729.332 seconds**. It produced no terminal
failure traceback, result summary, or JUnit file. Its progress log and original
termination receipt are preserved; the termination cause is unestablished.
The full-suite qualification remains incomplete and owned by the integration
worker. The later read-only snapshot at `2026-11-20T00:36:36Z` is the same
22,085-byte final partial log, not evidence of continued execution.

The isolated local Unix-socket check fails at socket construction, before
the project guard is entered. A control without an active guard reproduces
the same operating-system denial. This is a local execution-environment
limitation; the Unix-socket acceptance assertion remains unqualified here.

All raw evidence, including unsuccessful diagnostic attempts, is preserved in
[the evidence archive](evidence/qa-diagnosis-20261120.zip).
[The manifest](evidence/qa-diagnosis-20261120.json) records exact commands,
source identities, outcomes, and per-file SHA-256 hashes. The archive preserves
original whitespace and bytes in failure tracebacks and JUnit files.

## Source comparison

The table model, table preparation, original test, and original measurement
helper are byte-identical at current main
`fdc2696c23bdbfe7668348f25e3b336ce33039f7`, prior PR #322
`f2458aae22ea6177be64cfc2fb439a79950f00ff`, and the frozen aggregate source.
The network helper and its test are also identical at all three commits.

| File | Git blob at all three commits |
|---|---|
| `src/patchtrace/gui/qt/table.py` | `94a97c73bb518e4d5c70b259bb9beafe3b399fb7` |
| `src/patchtrace/gui/table_spec.py` | `9617938d25fc9483f3c29b99c4371963d85be6c7` |
| `tests/qt_support.py` | `f3433aadd03fb80b42a466d4b71533afb921bd0e` |
| `tests/test_gui_table.py` | `85363e6522da990e02ea0e67217137dc1da0d356` |
| `tests/network_guard.py` | `f686e57af5a6f431f81ab7ecceab1e846cb6e4fd` |
| `tests/test_network_consent_guard.py` | `e83b23ae12bc53bc24acac8441e0dc3482a29996` |

The unchanged aggregate-mapped table test passes in isolation: **1 passed in
2.05 seconds**. This result does not identify which assertion failed in the
aggregate or establish a timing regression.

## Reproduced table-counter defect and correction

`_paint_counting_data` wraps `type(model).data`, then processes Qt events to
paint the selected view. Its original wrapper increments a shared counter
for every model instance of that class. Pending events for another instance
therefore inflate the selected model's reported cost.

An authored probe uses the actual `VirtualTableModel`, the existing six-column
fixture, and ordinary offscreen table views. It first measures the selected
model alone, then measures it while another instance has a first paint pending:

| Helper and pending work | Reported calls | Selected model calls | Other model calls | Existing ceiling |
|---|---:|---:|---:|---:|
| Original; selected model only | 546 | 546 | 0 | 672 |
| Original; another instance also paints | 1,092 | 546 | 546 | 672 |
| Corrected; selected model only | 546 | 546 | 0 | 672 |
| Corrected; another instance also paints | 546 | 546 | 546 | 672 |

The original probe fails its ownership equality assertion. The unchanged
probe passes after the correction. This establishes a measurement defect,
not excessive row access by the production model.

The repair adds `if self is model` around the wrapper's counter increment.
Every call still reaches the original method, including calls for unrelated
models. The helper's existing visible-cell ceiling, size-growth assertion,
five-times timing ratio plus 50 ms, and the original table test's additional
fixed ceiling are unchanged. GUI plan section 8.8 now states the measurement
ownership rule. No application or persisted-format contract changes, so schema
generation is not applicable.

The new regression uses two real model instances. It queues another view's
first paint and an additional zero-delay model request, verifies that the other
model received work, and checks the helper's result against the selected
model's own counter. With the exact frozen helper, it fails with **183 reported
calls versus 91 selected calls**; the other 92 calls belong to the other model.
With the corrected helper, it passes and retains the existing returned ceiling.

The first version of this regression reported a failure and then suffered a
segmentation fault in pytest-qt's teardown event processing, preventing a
terminal assertion traceback or JUnit output. That version and its raw crash
log are retained. The final regression detaches and hides its auxiliary view
in `finally` and imports the existing thread/deferred-delete fixture. Its
subsequent red run completes with the expected ownership assertion failure.
The exact native cause of the initial teardown crash was not established.

## Local Unix-socket failure

The unchanged test
`tests/test_network_consent_guard.py::test_a_local_unix_socket_is_not_network`
fails with `PermissionError: [Errno 1] Operation not permitted` at the first
`socket.socket(socket.AF_UNIX)` constructor. It has not reached `bind`,
`listen`, or `with NetworkGuard()`.

The separate unguarded probe records the same `EPERM` at `socket_creation`,
with both the guard-active flag and the guard-audit-hook-installed flag false
before and after the attempt. No socket endpoint or connection is created.
The evidence identifies a restriction outside the project's guard; it does
not identify the mechanism enforcing that restriction. The probe exits zero
because it successfully writes this diagnostic record, not because the socket
operation or acceptance test passed.

The first standalone Unix probe also contained an introspection error before
attempting socket creation. Its original source and error output are retained
separately. The corrected probe and the focused test are the socket evidence.
No network controls, permissions, dependencies, or checks were changed.

## Verification and remaining limits

Environment: Linux, CPython 3.12.14, PySide6/Shiboken6 6.12.0, pytest 9.2.0,
pytest-qt 4.5.0, Ruff 0.17.6. GUI checks use `QT_QPA_PLATFORM=offscreen`.
All Python commands use the existing dedicated interpreter
`/workspace/scratch/4c8dc848d760/venv/bin/python` with `PYTHONPATH=src:tests`
for test and probe imports.

| Check | Observed result | Archive entry |
|---|---|---|
| Original table test, unchanged source | 1 passed, 2.05 s | `gui-isolated.log` / `.xml` |
| Independent cross-instance probe, original helper | Ownership assertion failed | `gui-count-probe.log` |
| Initial new regression, original helper | Failure followed by teardown segmentation fault | `gui-counter-red.log` |
| Final regression, exact original helper | 1 failed, 2.57 s; 183 versus 91 | `gui-counter-red-clean.log` / `.xml` |
| Independent probe, corrected helper | Passed; selected count 546 in both scenarios | `gui-count-probe-green.log` |
| First corrected-helper selection, initial regression fixture | 186 passed, 58.54 s | `gui-counter-green.log` / `.xml` |
| Final regression and every existing helper caller | **186 passed, 97.65 s** | `gui-counter-final.log` / `.xml` |
| Unchanged AF_UNIX acceptance test | 1 failed, 0.50 s; constructor EPERM | `unix-focused.log` / `.xml` |
| Unguarded AF_UNIX control | Recorded constructor EPERM | `unix-unguarded-result.json` |
| Whole-tree configured Ruff | Passed | `ruff-source-final.log` |
| Corrected diagnostic probes, Ruff | Passed | `ruff-probes.log` |
| Successor verification of final regression | 1 passed, 1.01 s | `continuation-regression.xml` / `continuation-validation.json` |
| Successor whole-tree Ruff and whitespace check | Passed | `continuation-validation.json` |

The focused selection covers every current caller of `assert_lazy_model` or
`_paint_counting_data`:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=src:tests \
  /workspace/scratch/4c8dc848d760/venv/bin/python -m pytest -q \
  tests/test_gui_table_counter_scope.py tests/test_gui_table.py \
  tests/test_ui_leads.py tests/test_ui_unified.py tests/test_ui_related_panel.py
/workspace/scratch/4c8dc848d760/venv/bin/python -m ruff check src tests tools
```

These results qualify the bounded harness correction on this offscreen runner.
They do not replace the original aggregate result, establish the cause of its
table failure, or qualify native GUI, Windows, packaging, or local Unix-socket
acceptance. Because the original aggregate run never emitted a failure
traceback, its table failure cannot be classified as call accounting, timing,
or another assertion from the retained progress marker alone. A later
reproduction with a terminal traceback would be new evidence. Shared QA and
task tracking files remain owned by the integration worker.
