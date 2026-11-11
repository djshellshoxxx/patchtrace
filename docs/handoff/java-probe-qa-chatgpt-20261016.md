# Java probe QA handoff (ChatGPT, 2026-10-16)

Status: **TEST CHANGES COMMITTED; CURRENT-HEAD LINUX/WINDOWS QA PENDING. NOT MERGED.**

## Scope and ownership

- Target: `djshellshoxxx/patchtrace`, PR #76 `codex/java-version-retry-20261015` -> `main`.
- Test-only follow-up: PR #80, `chatgpt/java-probe-qa-fix-20261016` -> PR #76 branch.
- The original Java-probe implementation in `src/patchtrace/backend.py` is unchanged by #80. It retries a timeout once with a 30-second bound after the initial 15-second attempt.
- Other contributors are active on `claude/instance-d-gui` (PR #64) and label-training PRs #78, #79 and #82. Those paths must not be overwritten.
- Duplicate PR #81 (same production patch) and stacked follow-up #84 were closed without merge in favor of #80. Do not resurrect competing merge paths.

## Confirmed issue

On PR #76 commit `8ee61c623fa37c5a219f912cf7870bfeddcb1f70`, QA workflow run `38802363214` ended with Ruff I001 on both Linux and Windows. It required changing the import order in `tests/test_backend_java_version.py`: `import threading` before `from types import SimpleNamespace`. The Linux/Windows run cannot be claimed green even if pytest finished.

## Implementation in PR #80

`tests/test_backend_java_version.py`:

1. Preserves the original timeout then success check (15 seconds, 30 seconds; parsed Java version).
2. Adds a second-timeout stop check; no third attempt.
3. Adds early-stop tests for cancellation, other process failure, nonzero exit and unparseable version output.
4. Adds cancellation during the timed-out first attempt; no retry once cancellation is set.
5. Adds `OSError` and missing-Java checks; no retry or unnecessary spawn.

All process interactions are injected fakes; no Java binary or comparison target is executed in these tests. No schema, API or persistence contract changes are introduced.

## Verification and merge gate

- Focused tests: `python -m pytest -q tests/test_backend_java_version.py`
- Lint: `python -m ruff check src tests tools`
- Full repo: `QT_QPA_PLATFORM=offscreen python -m pytest -q` on Linux and Windows; Windows PyInstaller/frozen smoke when CI proceeds.
- CI status: **NOT VERIFIED on the final commit when this note was written**. Check the PR #80 *current head*, not older run `38802363214`.
- Do not merge #80 until its current-head checks pass; when green, merge it into `codex/java-version-retry-20261015` and verify the resulting #76 head's own CI before merging #76 into `main`.
- After each merge, confirm SHA/ancestry. If #76 has been independently superseded or merged, reconcile before proceeding. Do not force-push or duplicate the backend fix.

## Other current project gates (separately owned)

PR #64's Windows QA at `53f366e` showed two mutation boundary failures; PR #78 addresses these on its own branch and still needs live/native QA. The N-way `EXTERNAL:<hex>` skip/count implementation and `test_nway_external_skips_are_counted` already exist on the integration branch, so the unchecked P2b tracker row is stale. No change to those areas was made here.
