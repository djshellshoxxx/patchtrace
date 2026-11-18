# Independently reviewed paired raw-window integration — 2026-11-18

The focused candidate is based on published PR #307 `58fc130631f602b6e907bb054d30c21d810551d4`. Its tested source/QA tip is `21552835fe40c5e3bb7245ca7c64404d030e5fa0`, tree `d58eaecb0ef41b0d2690c9d640de2b36380c5a61`. The following evidence-only commit does not change application or test code. Publication uses an append-only branch and verifies each published Git tree against its reviewed local tree.

The original [author receipt](../raw-alignment-workflow-20261118.md) and all failures remain unchanged. The original implementation `e4506666edefbbc22419ff97874e3edc599f94e7` was independently reviewed before integration. Its raw review and exact source hashes are in `independent/review.md` and `independent/source-context.json` inside the [evidence archive](evidence.zip). [Manifest](manifest.json) binds every receipt.

## Actual outcomes and limits

| Scope | Actual result | Source |
|---|---|---|
| Independent affected selection | 183 passed in 32.97 s | Original source `e4506666` |
| Six additional adversarial controls | 6 passed in 3.06 s | Original source `e4506666`; exact physical copy/orientation, persisted revision and late cancelled errors |
| Combined source-pinned affected selection | 183 passed in 31.01 s | Combined `21552835` on published #307 |
| Ruff on required `src tests tools` scope | Passed | Combined `21552835` |
| Whitespace check | Passed | Combined `21552835` |
| Downloaded published #307 boundary selection | 355 passed, 3 skipped in 7.36 s | Actual published base `58fc1306`; three native Windows controls remain unverified |

The independent review found no blocking defect in the inspected scope. Root reviewed the controller and integration glue. The core pure row model and alignment implementation remain unchanged. The actual offscreen 960×740 image was inspected; it is not native accessibility/manual acceptance. The independent and combined selections overlap and must not be added together.

An exploratory `ruff check .` also scanned archived QA Python and help-copy snippets outside the repository-mandated scope and reported 1,089 findings. Its shell command's final exit status belonged to the following whitespace command, not to Ruff. That invocation is not a passing check. The required `ruff check src tests tools` was then executed separately and passed; no source, assertion or archived receipt was edited to suppress those broader findings.

## Reproduction

Use the manifest's interpreter and absolute `PYTHONPATH` from the `raw-integration` checkout, with `QT_QPA_PLATFORM=offscreen`:

```sh
python -m pytest -q tests/test_ui_raw_alignment.py \
  tests/test_raw_alignment_view.py tests/test_representation_alignment.py \
  tests/test_tooltips.py tests/test_gui_host_seam.py tests/test_ui.py \
  tests/test_preflight_overview.py tests/test_ui_inspection_signing.py \
  tests/test_audit116_stale_inspection_failure.py \
  tests/test_cli.py::test_headless_entry_never_imports_qt \
  --tb=short --junitxml=affected.xml
python -m ruff check src tests tools
git diff --check
```

The base's separate boundary selection covers `test_kbc_object_publication.py`, `test_owned_publication.py`, all `test_research_qualification_winpairs*.py`, `test_kbc_fixtures.py`, `test_tooltips.py` and `test_research_qualification_ghidriff_identity.py`, with `PYTHONPATH` pinned to the downloaded `qualify307/src` checkout. It is base verification, not evidence for unexecuted raw-view tests.

## Remaining gates

The focused PR must retain published #307 as its base until the authorized #304 → #307 chain qualifies and reaches `main`. Full exact-candidate Linux/Windows QA, repeated Qt, native/manual/platform, packaging and security requirements remain unverified. No merge, release, tag, deployment, target execution or statistical accuracy claim follows from these local results.
