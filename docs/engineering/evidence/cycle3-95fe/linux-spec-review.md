# CODEX-14 independent spec review

Reviewed candidate `e4854b66ae37024d734e22ae978dedca90a7f3f7`, tree `2301e00645c6349e89b1d31a266e7aedac3baf30`, against baseline `6b6fcd3597a604212032ffc453477aeb6edc69ff`.

**Implementation findings: no blocking spec mismatch or unrequested runtime behavior found.**

- `docs/linux.md:16–24` requires the “extracted, checksum-verified onedir Linux archive” and says “only the frozen executable under test may satisfy the CLI checks.” The parsed workflow keeps both Ubuntu matrix entries, checks out before downloading the same-run package artifact, verifies/extracts it, and directly supplies `$PWD/PatchTrace/PatchTrace` to the helper. Host installation provides declared synthetic-fixture dependencies; it does not replace the frozen CLI launcher.
- `docs/linux.md:27–30` requires the harness to “fail the job” and retain both GUI modes. The full smoke step has no failure suppression; the helper returns 1 for accumulated failures, and both original offscreen/Xvfb probes remain. Its runtime AST is identical to baseline after removing the module docstring. Source inspection found no added submitted-target execution, live Ghidra analysis or remote acquisition.
- `docs/linux.md:31–36` forbids weakened static coverage or qualification from static success. The CODEX-14 xfail became positive, stronger assertions. Coverage remains top-level command help plus explicitly exercised nested paths.

**Partial acceptance remains:** `docs/linux.md:34–39` requires “passing source-specific hosted `linux-smoke` jobs on both distributions.” No exact-candidate frozen archive or hosted success was supplied or exercised in this review. This remains implemented-but-unqualified; predecessor results and source tests cannot satisfy that gate.

**Actual-source verification:** Dedicated Python 3.12.14 with `-I` resolved `linux-review/src/patchtrace/__init__.py`. The three requested files completed **91 passed in 23.84 seconds**, exit 0; JUnit confirms 91 tests, zero failures/errors/skips. Worktree was clean before and after. Eight independent parsed-YAML/AST controls passed. An initial reviewer-only GUI assertion incorrectly assumed YAML environment entries instead of the existing inline assignments; its failed receipt and original script are preserved, with the correction documented. No repository files or refs were changed.

Evidence in this directory: `targeted-tests.receipt.json`, `targeted-tests.log`, `targeted-tests.junit.xml`, `independent-spec-controls.receipt.json`, and `independent-spec-controls.initial-failure.receipt.json`; executable receipt scripts are retained alongside them.
