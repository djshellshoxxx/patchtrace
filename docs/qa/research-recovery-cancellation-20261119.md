# Research cleanup cancellation follow-up — November 19, 2026

Independent review of immutable recovery `68e937ee91dad7a905f2cac150c7d3a36259dfa2`
found that using `sys.exc_info()` in a `finally` block could see an unrelated
active exception in the caller. A cleanup `KeyboardInterrupt` was then attached
to that unrelated error and silently suppressed. The new actual orchestration
control reproduced the defect before the repair (1 failed, 38 deselected).

The runner now records only exceptions raised by its own operation in an explicit
local variable. Every owned side still receives cleanup; an owned primary failure
keeps its cause, and otherwise standalone cancellation propagates. The caller's
unrelated exception is unchanged. No cancellation is promoted to a successful
observation or final CLI receipt.

The same six-file author selection recorded in `research-recovery-20261119.md`
now reports **173 passed, 14 skipped in 5.70 seconds**. The skipped tests remain
native Windows-only controls. Real filesystem and substituted native orchestration
controls establish no native engine or Windows compatibility. Adjacent log and
JUnit files retain this exact gate. Scoped Ruff and `git diff --check` also passed.
Independent execution on the earlier commit was 52 passed and 14 native skips;
that overlapping selection is separate evidence, not an addition to this count.

Three tested files changed from the original recovery; every other source/test/
fixture file retains the SHA-256 recorded in the original QA receipt:

| Path | SHA-256 |
|---|---|
| `tools/calibration/tier_r/research_pilot.py` | `3ae558dc2433e3f84c0e8d88d6023f596f27bab7364d57ae7ef86d3cfd75a285` |
| `tests/test_tier_r_research_recovery.py` | `16cb20ed3b4e6fba962e309b2a721e321206c58d170df74f903126adead1f45a` |
| `docs/specs/research-pilot.md` | `3303fdec784677cb0bfe231776c4592a521405fd607108b9e8dba41118510847` |
