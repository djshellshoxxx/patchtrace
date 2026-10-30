---
name: patchtrace-test-and-release
description: Plan and report PatchTrace test, QA, packaging, CI and Windows release checks without confusing mocked, static, Linux or blocked checks with live acceptance.
---

# Correct verification boundaries

Read the feature's spec, `docs/specs/verification.md`, `docs/release-process.md`, `docs/qa.md`, `tasks/todo.md` and, for Windows work, `docs/specs/windows-acceptance-and-milestone-builds.md` and `docs/specs/windows-release-signing-policy.md`.

1. Derive focused positive and negative tests from the changed contract. Run focused checks early; run affected integration tests after fixes.
2. Standard project-wide gates where the environment supports them: `QT_QPA_PLATFORM=offscreen python -m pytest -q` and `python -m ruff check src tests tools`. Regenerate schemas after contract changes.
3. Record exact commands, exit codes, revision SHA, platform, skip reasons, and failed tests. Report `passed`, `failed`, `blocked` and `not run` separately. Never treat mocked providers, queued CI, skipped tests or static checks as live compatibility.
4. PyInstaller Windows packaging and native desktop acceptance must be checked on Windows; Linux verification cannot prove Windows deliverables. Review archive/dependency notices and forbidden payloads before release.
5. Do not bypass gates, claim an unavailable GitHub Release succeeded, or call a package production-ready before actual acceptance. Update QA/todo with precise outstanding tasks.

Use `verification-before-completion` or `verify-and-stop` to avoid irrelevant extra tests, never to omit required ones.
