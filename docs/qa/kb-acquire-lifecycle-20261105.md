# C1/A2 acquisition lifecycle dependency — 2026-11-05

Isolated branch `repair/kb-acquire-lifecycle-20261105`, worktree
`/tmp/pt-independent-acquire-lifecycle-20261105`, base integration
`7545667db3bf881f380ba8bafe1c633c128c7022`. Scope: `KbService.acquire`, one
private committed-ownership snapshot helper, eight new authored lifecycle
controls and the narrow SPEC-31-D amendment. Coordinator approved the optional
keywords and exact source-record snapshot guard before implementation.

## Reproduction and behavior

The acquisition bridge already accepted cancellation and the import service
already checked an expected investigation revision, but `KbService.acquire`
exposed/forwarded neither. Its import callback also omitted the revision
captured before staging. A normal investigation search during staged download
could therefore let the old acquisition adopt the later investigation. A source
snapshot added without changing investigation revision likewise passed through.

Baseline: **8 failed in 2.86 s**. Four failures demonstrated missing optional
keywords; four demonstrated unrefused revision/source changes around planning,
staging and the final import. Tests use the real store, acquisition/quarantine
and project/import paths over authored PE bytes with the existing fake
symbol-server opener. Socket creation/connection/DNS are denied; no live source
or backend acceptance is inferred.

The service now accepts optional `cancel` and `expected_revision` keywords.
Pre-cancel returns cancelled without staging; stale caller revision is refused
before networking. The original token reaches the existing bridge/transport.
The service captures exact committed revision JSON and ordered `SourceDoc`
records before resolution, checks that snapshot before staging and at final
import, and always calls `import_pair(expected_revision=captured_revision)`.
The latter in-store check also rejects a revision changed after the outer
admission check. Same source metadata with unchanged binary requests cannot
silently adopt new advisory ownership during staging.

`_resolve_pairs` does not advance committed revision, so existing authorized
CLI product/file selection remains compatible. The exact acquisition request
plan and consent content are unchanged. No persisted model/schema field,
module, dependency or GUI/provider file changed.

## Completed checks

`env -u PYTEST_ADDOPTS PYTHONPATH="$PWD/src" QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_kb_acquire_lifecycle_20261105.py tests/test_kbc_acquire_cli.py tests/test_kbc_service.py`

**55 passed in 3.26 s**, no skips. New tests cover pre-cancel, exact token
propagation/post-verification cancellation, explicit stale revision before
requests, revision change during stage, source-record change without revision,
source drift during pure planning, successful explicit-current acquisition
with reopened artifact hashes, and revision change between the outer guard
and import. Every refusal leaves no new project/staging; an existing completed
project's database bytes remain unchanged. Existing CLI exact-consent and
normal selection/import controls pass.

Whole-tree `python -m ruff check src tests tools` and `git diff --check` passed.
`PYTHONPATH="$PWD/src" python tools/generate_kbc_schemas.py` completed without
schema drift.

## Remaining gates and limits

Independent security/lifecycle review and publication remain coordinator-owned.
Snapshot admission is not an atomic transaction spanning download and import;
source-record comparison occurs immediately before import and the existing
in-store revision check remains authoritative. A cancellation after a project
commits does not undo it. This repair does not add candidate GUI acquisition,
re-rank Winbindex observations after download, or establish live transport,
binary matching accuracy, Windows/native or release acceptance. Existing
qualification/native processes, worktrees and logs were untouched; no broad
suite or target execution was started.
