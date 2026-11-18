# Slice card TR-A - test reliability: tests that can silently pass, order dependence, declared test dependencies

The worktree already holds one commit of this slice (K-T01: the pathguard test no longer depends on tmp_path depth).
Evidence and designs: `jq '.actionable_now[] | select(.id=="K-T02" or .id=="K-T05" or .id=="K-T06" or .id=="K-T07" or .id=="K-T08" or .id=="K-T13")' docs/status/inventory/K.json`,
`jq '.features[].defects[]? | select(.id|test("K-D0[1345678]"))' docs/status/inventory/K.json`, and `jq '.actionable_now[] | select(.id=="I1-T11")' docs/status/inventory/I1.json`.
Owner directive behind this slice: tests must not silently pass when an essential dependency is missing; skipped,
blocked, failed and passed must be distinguishable.

Items, one commit each, in this order:

1. K-T05 - one shared Hypothesis profile in tests/conftest.py (K-D04: 14 property tests use the 200 ms default deadline
   and random seeds). Register a profile with `deadline=None` (or a generous deadline) and `derandomize=True`... read the
   existing property tests first and choose settings that keep them deterministic in CI without hiding failures
   (print_blob on failure so a failing example can be replayed); explicit per-test settings must still win. New
   tests/test_hypothesis_profile.py proves the profile is loaded.
2. K-T06 - tests/test_unified_cor_pipeline.py: the shared-temp listing test races under parallel workers (K-D03); give
   it a private temp root (monkeypatch tempfile.tempdir / TMPDIR for that test) so it lists only its own files. Test file
   only; no product change. Prove with `-n 4` and `--count`-style repetition (loop 10 times).
3. K-T07 - blocked is not xfailed (K-D07): tests/test_tier_w_symbols.py, tests/test_cli_registry.py,
   tests/test_rzdiff_producer_patch.py. Two of the CI xfails are really "tool missing"; three opt-in groups claim a
   nightly/CI runner that no workflow provides. Use skip with a reason that starts with "BLOCKED:" and names the missing
   tool or the workflow that would run it (or says plainly that no workflow runs it) instead of xfail; never convert a
   real open-defect xfail. In tests/test_cli_registry.py touch only the lines the finding names.
4. K-T08 - add `raises=<ExpectedError>` to the strict xfail marks in tests/test_codex_pkg_workflows.py and
   tests/test_codex_pkg_packaging.py so an xfail cannot be satisfied by an unrelated crash. Do NOT edit
   tests/test_kbc_audit_20261107.py (slices K1/K2 are removing those xfails).
5. I1-T11 (WP-04) - tests/test_enrichment_intelligence.py lines ~297-299: the Qt-import test builds a set that can only
   ever contain "patchtrace", so it cannot fail. Replace it with a subprocess import check as tests/test_kbc_service.py
   does. Mutation check for your report: temporarily add `import PySide6` to the module under test in your worktree, see
   the test fail, remove it again (do not commit the mutation).
6. K-T02 + K-T13 (you are granted pyproject.toml for exactly these two edits):
   a. K-D01 (high): 39 workflow-contract tests are skipped on EVERY CI run because PyYAML is not installed by the QA
      install line and the tests use pytest.importorskip. Add `PyYAML>=6,<7` to the `dev` extra in pyproject.toml
      (test-only; never a runtime dependency; it is already installed in this venv) and add tests/test_ci_environment.py
      that FAILS (not skips) when a module the dev extra declares cannot be imported - derive the list from
      pyproject.toml so it cannot drift. Then run every test file that uses importorskip("yaml")
      (`grep -rln "importorskip..yaml" tests`) and fix real failures they expose only if the failure is in the TEST's
      assumptions; if a workflow file itself violates a contract the test checks, do not edit the workflow - report the
      exact failure under open_risks (workflow files belong to other slices/sessions).
   b. K-T13: pytest configuration hardening in [tool.pytest.ini_options]: `--strict-markers` (declare every marker
      the suite uses first: `grep -rhn "pytest.mark\." tests | sed ...` to enumerate), `--strict-config`,
      `faulthandler_timeout` so a hung test dumps stacks instead of burning the job limit silently (choose a value
      that the slowest legitimate test never reaches; say how you measured), `xfail_strict = true` only if every
      existing xfail already passes strictness (check; otherwise leave it and report). New tests/test_pytest_config.py
      pins these settings. Do not add pytest-timeout or pytest-xdist as dependencies.
   After 6, run the whole changed-config sanity check: `... -m pytest -q -p no:cacheprovider --collect-only -q | tail -3`
   must collect with zero errors and zero unknown-marker warnings.

## Owned files
tests/conftest.py (only the Hypothesis profile block), tests/test_hypothesis_profile.py (new),
tests/test_unified_cor_pipeline.py, tests/test_tier_w_symbols.py, tests/test_cli_registry.py (named lines only),
tests/test_rzdiff_producer_patch.py, tests/test_codex_pkg_workflows.py, tests/test_codex_pkg_packaging.py,
tests/test_enrichment_intelligence.py, pyproject.toml (dev extra + pytest ini options only),
tests/test_ci_environment.py (new), tests/test_pytest_config.py (new), tests/test_research_qualification_cli.py.
NOT yours: any file under src/, .github/workflows/**, tools/**.
