# PT-BUG-NET-001 — stalled HTTP body read exceeds the request deadline

- **Date:** 2026-11-21 (UTC)
- **Classification:** CONFIRMED, P2 (network reliability)
- **Affected component:** `src/patchtrace/netutil.py::read_bounded`
- **Source:** `main` at `9023761a4066ac1c50c127ac09d0ba5f56cdc9e4`; original module blob `9fff565fd59d3d3d23a7a9f4e0a894bd742f8432`
- **Fix branch:** `fix/netutil-read-deadline-20261121-0318`
- **Status:** Repaired on isolated branch; hosted full-suite, Windows, independent review, and merge are pending
- **Scope:** Existing behavior only; no new feature, release, or deployment

## Confirmed failures

`read_bounded` checked its total deadline only before starting a read. When `cancel=None`, `interruptible` ran the read inline; when `cancel` was an unset event, the worker had no deadline signal. A server that stalled mid-body could therefore exceed the deadline and still return an apparently successful body at EOF.

Two tests against a byte-identical copy of the original Git blob each failed with `DID NOT RAISE DeadlineExceeded` (2 failed in 1.47 s): a stalled read with no cancellation event, and the same with an unset event.

A separate real localhost HTTP probe revealed an additional cleanup issue in an intermediate repair: on `http.client.HTTPResponse`, a pending `read1` held the buffered stream lock, so calling `response.close()` from the transport's `finally` blocked even after the deadline signal had escaped. In the initial repaired version, the signal occurred at approximately 0.202 s but `close()` remained blocked for at least 0.3 s until the fixture released the server.

## Root cause and focused repair

1. Use a composite stop condition for `interruptible` which observes either the existing cancellation event or the request deadline. Preserve `Cancelled` when the event fired; otherwise raise `DeadlineExceeded`. Recheck both after each read to reject late EOF/success.
2. For CPython `http.client.HTTPResponse`, shorten (never lengthen) the underlying socket's existing per-operation timeout to the remaining deadline before the blocking read. This also allows `response.close()` to finish promptly if the read times out. Unknown/custom response transports continue to use the deadline watcher; their custom `close()` behavior is not covered by the socket-specific guarantee.
3. Convert socket `TimeoutError` to `DeadlineExceeded` only when the injected deadline clock actually expired; otherwise preserve the existing transport retry/error behavior.

## Regressions and evidence

- `tests/test_netutil_read_deadline.py`: **6 passed** against locally staged, blob-matched fixed source (Python 3.13, pytest 9.0.2).
- Tests cover no cancellation event, unset event, explicit cancellation, successful chunked reads, byte-cap refusal, late EOF, and native localhost `HTTPResponse` deadline/closure.
- Local native HTTP probe: `DeadlineExceeded` at approximately 0.151 s; `response.close()` complete by approximately 0.152 s; 0 abandoned reads afterward.
- Fixed module blob: `2898798fe08eee87653db4b404f33bd24a069bd0`; fixed test blob: `1a4ab63b68850f24c6e3a94ec5e7012c246b2eba`.
- Relevant consumers: `enrichment/intelligence.py`, `intelligence/csaf/transport.py`. This does **not** certify their full integration behavior.
- Existing related historical audit: `docs/audits/20261015-acquisition-enrichment.md` (ACQ-2).

## Verification / integration gates

- [x] Reproduction on byte-identical original implementation.
- [x] Failing regression before implementation.
- [x] Six focused local regression checks green after repair.
- [x] Real local HTTP read/close acceptance (CPython).
- [x] Exact local and published Git blob equality for fixed source and tests.
- [ ] Complete checkout-based PatchTrace pytest and Ruff.
- [ ] Hosted Linux and Windows exact-head workflow checks.
- [ ] Genuine independent code review.
- [ ] Qualified guarded merge into `main`.

Do not infer global release or product readiness from this bounded repair. Do not merge while any required gate or ownership conflict remains.
