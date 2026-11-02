# Search/rules dependency restoration and targeted acceptance — 2026-11-02

## Result

Restoring the existing pyproject-pinned search/rules extras into the coordinator's isolated venv allowed the previously missing coverage to execute: **334 passed, 1 failed, 0 skipped in 42.58 seconds**. The remaining failure is the export guard correctly refusing a destination under the runner's existing ancestor Git marker. It is retained as a failed local test; no assertion, guard, consent flag or pin was changed.

Source: immutable archive of `f2b7d981008dea25ac09ea82734da64a1dccb96d`, tree `985078aed0feb4f909690d6082ec4940540cda17`, at `/tmp/patchtrace-isolated-imports-venv-20261102/source-f2b7d981`. All **3,413 source files** were hashed before and after and remain identical. The reviewer released this venv after its separate seven import controls passed. The shared candidate and global runtime were not changed.

| Original affected set | Targeted result |
|---|---|
| Six search failures | **6 passed** |
| Fifteen search-extra skips | **15 passed** |
| 261 individual YARA-X skips | **260 passed, 1 failed** |
| One collection-skipped YARA engine module | Expanded into **42 passed** |
| Eleven iced-x86 decoder skips | **11 passed** |

The exact list contains 294 selectors; one is a module selector, so these expand into 335 tests. These numbers are not added to the historical full-suite pass count as if a new full run had passed.

## Cached packages installed offline

Only the three pinned extras were installed, from existing cache bytes reverified against wheel RECORD hashes and sizes. Every payload entry also matched the earlier continuation environment. Cached HTTP responses identify the package/version/wheel type through PyPI headers; this is existing cache provenance, not fresh independent upstream verification.

| Package | Wheel tag | Bytes | SHA-256 |
|---|---|---:|---|
| RapidFuzz 3.14.6 | cp312-cp312-manylinux_2_27 / 2_28 x86_64 | 3,168,023 | `0debb5f43662ea84d2f0228a0c7407ff647f9c3d13f3b692efff0cde46eebce0` |
| YARA-X 1.21.0 | cp38-abi3-manylinux_2_28_x86_64 | 9,624,829 | `33bc3665170e640752fed275a7ad6551079696f00d698c9433607dfc6bdd7493` |
| iced-x86 1.21.0 | cp38-abi3-manylinux_2_17 / manylinux2014 x86_64 | 949,386 | `489789377bfc1fe432bd2a8a5780c9f3e7c35be2e6133b0de5432cd901cad32c` |

Verified wheel RECORD entries: RapidFuzz 66, YARA-X 7, iced-x86 47, with no mismatches. Full cache paths, response provenance, derived wheel filenames, command and output are in `/tmp/patchtrace-extra-install-20261102.json`. The named local wheel copies are under `/tmp/patchtrace-extra-wheels-20261102/`.

Installation used the isolated venv's Python, `pip install --no-index --no-deps --only-binary=:all: --disable-pip-version-check --no-cache-dir --no-compile`, and only those explicit verified wheel paths. Parent pytest started fresh with inherited `PYTHONPATH` removed, `QT_QPA_PLATFORM=offscreen`, bytecode writes disabled and pip network access disabled. Runtime origins confirm all three restored extras load from this venv; parent Pydantic 2.13.5 and PySide6 6.12.0 retain the reviewer's documented user-site origin.

## Remaining refusal

`tests/test_rules_actions.py::test_the_preview_is_exactly_the_file_and_never_replaces` fails at `actions.write_export` → `export.write` with `PT-RULE-EXPORT [git-tree]`. The run used `/tmp/pytest-of-root/pytest-289/test_the_preview_is_exactly_th0`; read-only inspection found the ancestor marker under `/tmp`. The output directory exists and the export file was not written. The production guard checks every ancestor and therefore takes its documented refusal path before the test can exercise successful writing/no-replacement.

The separate explicit Git-consent control passed, as did all 20 selected `test_rules_export` checks. Do not bypass or remove the guard to make this test green. Retain this failure and obtain the unchanged success-path result on the normal non-Git temporary directory used by hosted CI or another appropriately provisioned test environment.

## Evidence

- Exact grouped nodes: `/tmp/patchtrace-extra-affected-nodes-20261102.json`.
- Exact pytest selector list: `/tmp/patchtrace-extra-affected-nodes-20261102.txt`; separate search-failure/search-skip/YARA/decoder lists are saved alongside it.
- Run command, runtime origins and source integrity: `/tmp/patchtrace-extra-affected-20261102.json`.
- Full output/JUnit: `/tmp/patchtrace-extra-affected-20261102.log` and `/tmp/patchtrace-extra-affected-20261102.xml`.
- Group reconciliation: `/tmp/patchtrace-extra-affected-summary-20261102.json`.
- Read-only refusal inspection: `/tmp/patchtrace-extra-export-environment-20261102.json`.

No full suite, external native compiler, compared target execution, network operation, global package installation, source edit or pin change was performed. Real YARA-X rule compilation/scanning and iced-x86 decoding used the repository's synthetic byte fixtures. The results qualify this bounded Linux source selection; they do not establish frozen Windows or overall release acceptance.
