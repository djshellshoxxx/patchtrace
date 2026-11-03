# Isolated-import failure review and environment repair

## Result

**7 passed in 3.55 seconds; pytest exit 0.** The seven selected tests were rerun without source or assertion changes.

All seven original captured-stderr sections in `/tmp/patchtrace-consolidation-full-20261102.log` show:

```text
ModuleNotFoundError: No module named 'patchtrace'
```

The original subprocesses therefore failed before reaching their no-Qt/no-feature assertions. A separate direct import diagnostic with the original interpreter's `-I` option reproduced that exact exception for each of the seven modules. This is a package-visibility/setup diagnosis, not an observed unexpected Qt import.

## Frozen source and environment

- Source commit: `f2b7d981008dea25ac09ea82734da64a1dccb96d`.
- Source tree: `985078aed0feb4f909690d6082ec4940540cda17`.
- Shared candidate: `/tmp/patchtrace-final-20261102`, clean before and after.
- Virtual environment: `/tmp/patchtrace-isolated-imports-venv-20261102`.
- Interpreter: `/tmp/patchtrace-isolated-imports-venv-20261102/bin/python`.
- Editable source: `/tmp/patchtrace-isolated-imports-venv-20261102/source-f2b7d981`.
- Python: 3.12.14, from `/opt/codex/runtimes/codex-primary-runtime/dependencies/python`.
- Package: PatchTrace 0.1.0, installed editable into the virtual environment.

The editable source is an exact `git archive` extraction of the frozen commit. Its archive SHA256 is `9309c8baffeebb96436835a7acfba7aea62241542757ac9885bd35e89fbe9693`. All **3,413 original extracted files** retain their SHA256 after installation and testing. Editable-build metadata was confined to this temporary copy and the virtual environment; the shared repository was not edited.

Setup used:

```sh
python -m venv --system-site-packages /tmp/patchtrace-isolated-imports-venv-20261102
/tmp/patchtrace-isolated-imports-venv-20261102/bin/python -m pip install \
  --no-index --no-deps --no-build-isolation --no-cache-dir \
  --disable-pip-version-check \
  -e /tmp/patchtrace-isolated-imports-venv-20261102/source-f2b7d981
```

Installation was offline and successful. Pip explicitly left the pre-existing user-site installation outside this environment alone. No dependency packages or global runtime files were changed by this setup.

## Exact tests

| Node ID | Result |
|---|---|
| `tests/test_evidence_host.py::test_loading_the_spec_imports_no_qt` | Passed |
| `tests/test_evidence_table.py::test_the_module_imports_no_qt` | Passed |
| `tests/test_ui_leads.py::test_loading_the_declaration_imports_no_qt_and_no_feature` | Passed |
| `tests/test_ui_m3_docks.py::test_panel_specs_import_no_qt[series]` | Passed |
| `tests/test_ui_m3_docks.py::test_panel_specs_import_no_qt[files]` | Passed |
| `tests/test_unified_pair_text.py::test_the_module_has_no_qt` | Passed |
| `tests/test_unified_panel_spec.py::test_panel_module_imports_no_qt` | Passed |

The test command was `venv/bin/python -m pytest -q --tb=short -ra --junitxml=/tmp/patchtrace-isolated-imports-20261102.xml`, followed by exactly those seven node IDs. Working directory was the archived editable source. Exact argument arrays are retained in the JSON receipt.

Command-local environment settings:

| Setting | Value |
|---|---|
| `PYTHONPATH` | Removed from the inherited environment |
| `QT_QPA_PLATFORM` | `offscreen` |
| `PYTHONDONTWRITEBYTECODE` | `1` |
| `PIP_NO_INDEX` | `1` |
| `PIP_DISABLE_PIP_VERSION_CHECK` | `1` |

No skip conditions, assertions, source files, or pytest selections were weakened.

## Environment distinction and limits

Both ordinary and `-I` virtual-environment interpreters resolved `patchtrace` to the frozen archived source.

Ordinary Python retained user-site access, including pytest 9.2.0, PySide6 6.12.0, and Pydantic 2.13.5. Its `-I` child disabled user-site access, had no PySide6 module available, and resolved Pydantic 2.14.1 from the base runtime. The new virtual-environment editable installation remained visible in isolated mode. These details are captured in the JSON probes.

Accordingly, this result verifies the seven unchanged import assertions in this recorded environment. It is not a claim about a completely dependency-pinned isolated runtime or about Qt behavior in every installation. It does not replace the original failed full-suite result.

The environment was handed to the authorized dependency reviewer after this completed run. Later dependency additions belong to a separate receipt; the environment probes here describe this seven-test run.

## Preserved evidence

- Original failure report: `/tmp/patchtrace-consolidation-full-failures-20261102.json`.
- Original failure-report SHA256 before and after: `beb467136b9894cc215bc2f527f9af90661e7b193408c524059a76595252f973`.
- Rerun log: `/tmp/patchtrace-isolated-imports-20261102.log`.
- Rerun JUnit: `/tmp/patchtrace-isolated-imports-20261102.xml`.
- Exact environment, command, preservation checks: `/tmp/patchtrace-isolated-imports-20261102.json`.
- Editable-install log: `/tmp/patchtrace-isolated-imports-venv-20261102/editable-install.log`.
- Original source-file manifest: `/tmp/patchtrace-isolated-imports-venv-20261102/source-manifest-before.json`.

No full-suite rerun was performed.
