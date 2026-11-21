# CODEX-14 Linux frozen CLI smoke — executable handoff

Candidate branch `codex/patchtrace-linux-frozen-cli-smoke-20261121`, parent PR #348 head `6b6fcd3597a604212032ffc453477aeb6edc69ff` at start. This branch owns only the Linux acceptance spec/workflow, the narrow test, its task-ledger record and evidence/handoff documents. No PR #348 parent code was rewritten. No held foreground worker remains.

1. Read `AGENTS.md`, `docs/linux.md`, `docs/audits/codex-packaging-1.md`, `tests/test_codex_pkg_packaging.py`, `.github/workflows/qa-windows.yml`, task-ledger, and [scope report](../engineering/codex14-linux-frozen-cli-smoke-20261121.md).
2. Fetch live PR #348 QA run 44858504288, native run 44858504326 and PR #345's single failed-job-only retry run 44840721370. Parent PR #347 complete run 44843482603 now succeeded, including both Linux smoke jobs. Do not re-dispatch overlapping suites or assume ancestor checks qualify this new branch.
3. From a clean source-bound checkout run `python -m pytest -q tests/test_codex_pkg_packaging.py tests/test_acceptance_smoke.py tests/test_workflows.py` and `python -m ruff check src tests tools`; check `pip check` and exact `python -I` source identity. Preserve real failures and inspect runtime compatibility under supported Linux runners.
4. Obtain a genuinely separate reviewer for shell ordering, source-to-package identity, extracted executable provenance, Linux binexport child process, host-fixture/runtime boundaries and full stdout/exit codes. In particular, verify the `frozen_smoke` harness behaves correctly on both Ubuntu 22.04/24.04; do not silently skip failing checks.
5. After PR #348's original full/native workflows are terminal, open a stacked draft PR with base `codex/patchtrace-integration-20261121-2bad` for new exact-source hosted qualification. No main/release promotion while any applicable QA, Qt, native, package, full frozen smoke or independent acceptance is not green. Make any merge only with fresh expected head via REST and an explicit no-release message.
6. Retain CODEX-1/5/6, source-free historical 181/16 classification, raw index/entry membership, Linux overwrite refusal, Windows manual/trust/accessibility, and independent L1/L2/L3.

There is no authorization to force-push, rebase another worker, delete old branches, deploy, publish a release, execute target binaries or send notifications.

7. The source-only structural evidence includes seven negative mutation controls in `docs/engineering/evidence/codex14-linux-smoke-static-review-20261121.json`; all were detected. This is *not* an independent reviewer or actual checked-out-source test. Only the frozen-smoke harness docstring changed; its runtime code is unchanged.
