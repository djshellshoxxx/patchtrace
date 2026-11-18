# WORKSTREAM K - Testing and continuous integration
Scope: <main checkout>/.github/workflows/*.yml (25 files), pyproject.toml pytest config, tests/ layout (797 test
files, about 20.9k tests), tests/conftest.py, tools/qt_gate.py, tools/run_test_suite.py, tools/release_gate.py,
tools/check_live_status.py, tools/frozen_smoke.py, tools/build_linux.py, tools/build_windows.py, docs/release-process.md,
docs/handoff/qa-and-release.md, docs/audits/20261015-test-suite-hygiene.md, 20261015-fixes-test-hygiene.md,
20261015-tools-workflows.md.

Produce:
(1) a workflow table (one feature row each or a table in `notes`): file, triggers, jobs, timeout, concurrency group
    present?, permissions block present and minimal?, paths-ignore present?, third-party actions used and whether pinned by
    SHA, latest conclusion on main (GitHub read: actions_list method list_workflow_runs per workflow file, perPage 2 -
    record id / date / conclusion; 'never run' if none);
(2) skip/xfail inventory: `grep -rn 'xfail\|pytest.mark.skip\|skipif\|pytest.skip(' <main checkout>/tests | wc -l`,
    then classify by reason (platform, missing native tool, open defect, other) and flag tests that can silently pass when
    an essential dependency is missing (directive: prevent tests from silently passing when essential external
    dependencies are unavailable; distinguish skipped, blocked, failed and passed);
(3) coverage map versus the directive list: unit, integration, native adapter, CLI, GUI, database, migration, security
    regression, benchmark, end-to-end workflow, packaging, installation, cross-platform - which exist, which are missing;
(4) known flakes: tests/test_research_qualification_cli.py::test_paths_outside_allowed_roots_are_refused reportedly fails
    only under pytest-xdist `-n 4` - read the test and the code it exercises and explain the root cause precisely (shared
    state? cwd? tmp path? environment variable?) and propose the fix; look for other order- or parallelism-dependent tests
    (module-level globals, os.chdir, fixed tmp names, time.sleep-based waits, fixed ports);
(5) CI speed/cost findings under these owner rules: concurrency cancel-in-progress on push/PR workflows (never on
    release/publish workflows), paths-ignore for docs-only changes, build each artifact once and reuse it, explicit
    parallelism, fetch-depth 1, least-privilege `permissions:`, first-party actions only (actions/checkout, cache,
    upload-artifact, download-artifact).
The release job of qa-windows.yml is under L4 and unified-live-gates.yml under L2: do not propose changes there.
actionable_now: test-reliability fixes and workflow hygiene changes outside L4/L2 files.
