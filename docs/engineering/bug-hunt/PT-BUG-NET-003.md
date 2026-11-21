# PT-BUG-NET-003 — abandoned worker count released before cleanup finishes

- **Date:** 2026-11-21 (UTC)
- **Classification:** CONFIRMED, P2 (concurrent network resource accounting)
- **Affected component:** `src/patchtrace/netutil.py::interruptible`
- **Baseline:** isolated draft PR #354 head `a41c7a0d594d1fe26c16da395e6f6f9b33b07eca`, source blob `2898798fe08eee87653db4b404f33bd24a069bd0`. The relevant `interruptible` function is unchanged from main `9023761a4066ac1c50c127ac09d0ba5f56cdc9e4`.
- **Fix branch:** `fix/netutil-abandoned-cleanup-cap-20261121-0318` (stacked on PR #354, not main)
- **Status:** Fixed on isolated branch; exact-head hosted QA, independent review, and integration remain pending

## Reproduction

`interruptible` increments `_abandoned` when a cancelled request leaves a running daemon. When that daemon eventually returns a response, the original implementation decremented `_abandoned` **before** invoking the late-response cleanup callback. If the cleanup blocks while closing the response, the count incorrectly returns to zero even though the daemon is still alive and holding network resources. Subsequent requests pass the nominal `MAX_ABANDONED` admission test.

A regression against the exact parent source started four synthetic cancelled calls whose `cleanup` functions remained blocked. The original counter reported **0** when **4** cleanup workers were still active. The deterministic test failed (`assert 0 == 4`) while a cleanup-failure release test passed: **1 failed, 1 passed**.

## Minimal repair

Keep the abandoned slot reserved until the cleanup callback has finished. Publish a successful response to the waiting caller as before; for abandoned calls, complete best-effort cleanup first and decrement exactly once in a `finally` block even if cleanup raises. No networking, cancellation API, cap value, or timeout changes; no feature development.

## Evidence

- Existing exact parent source blob `2898798fe08eee87653db4b404f33bd24a069bd0`.
- Fixed source blob `60b7e113607d88c26fe7cbcb772969c5af4619e4`.
- New test blob `9e88b76de08bacc43af9bfad856f1875699235f6`.
- New focused tests: **2 passed**, including cleanup error handling.
- Overlapping local mirror suite with PR #354 and independent optional-import #355 test sources: **15 passed**, zero failures/skips (Python 3.13, pytest 9.0.2; local exact-source mirror only). These 15 do **not** certify full repository acceptance.
- All test actions use synthetic events and localhost-only behavior; no external network.

## Integration blockers

- [x] Reproduction on original exact-parent implementation.
- [x] Fix on isolated stacked branch with byte-exact tested source.
- [ ] Complete repository test suite / Ruff on exact head.
- [ ] Hosted Windows and Linux QA, and relevant concurrency/transport tests.
- [ ] Independent review.
- [ ] PR #354 accepted/merged before this stack can be independently merged to main, or carefully reconcile exact sources.
- [ ] Fresh main/head ownership reconciliation and guarded qualified merge.

No main mutation, release or deployment.
