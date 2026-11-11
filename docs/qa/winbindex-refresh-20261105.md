# Explicit Winbindex metadata refresh — 2026-11-05

Base/index checkpoint: `58cc60f752750a4455cd22f3b547db4a5b609c79`.
Branch: `work/consented-winbindex-refresh-20261105`.
Worktree: `/tmp/pt-independent-winbindex-refresh-20261105`.

The coordinator indexed the new module before implementation and approved its frozen internal plan/request/result API before code. The source-adapter specification was appended before implementation. No serialized application model/schema, existing UI, candidate logic, transport, parser or publisher changed in this slice.

## Implemented boundary

`sources.winbindex_fetch.build_plan` and `render_plan` preview exactly one existing Winbindex metadata GET, application headers, host, transport/parser caps and a domain-separated digest. `MetadataPlan.to_json` provides the captured payload. `RefreshRequest` binds that payload and explicit hosts/digest to one refresh invocation. `refresh` refuses offline, invalid, duplicate/nonfinite/oversized, altered or stale plan JSON before requests; exact canonical comparison distinguishes booleans, integers and floats, missing fields and extras. Callers remain responsible for one explicit consent action per invocation and must not persist/replay consent.

The new orchestrator reuses `Transport.fetch_metadata`, `winbindex.parse_rows` and `wiring.save_winbindex_record`. It verifies response URL, raw byte cap, real retrieval/source dates, no future Last-Modified, nonempty usable metadata and cancellation before the existing publication seam. An operation-private temporary source is cleaned on success/failure. The receipt records raw checksum/length, URL, retrieval time, date basis, parser counts/warnings and the exact relative stored path. Provenance remains third-party index over allowlisted HTTPS; no Microsoft authorship, per-binary authenticity, CVE attribution or freshness certification is invented. A missing usable Last-Modified explicitly falls back to retrieval date.

Invalid metadata, observed prepublication refusal and cancellation preserve existing saved records. Successful publication is a commit boundary; a late cancellation retains the committed result. This module makes no rollback promise after commit and implements no second publisher. Atomic publication hardening remains the separately owned `wiring.save_winbindex_record` follow-up.

## Deterministic evidence

- Initial missing-feature test collection failed with `ModuleNotFoundError` for the not-yet-created indexed module; `/tmp/pt-independent-winbindex-refresh-red.log`. No baseline test pass is inferred.
- Development checks exposed the existing identity helper's intentional rejection of float payloads; the plan digest now binds their exact canonical JSON representation as text. Another development run exposed passing text to the source loader's bytes-only API; the code now explicitly encodes UTF-8. These were implementation errors, not preexisting product defects. The retained second failed-development output is `/tmp/pt-independent-winbindex-refresh-green.log` (11 failed/12 passed); the first float failure was observed in tool output and has no separate retained local log.
- First complete new-module check: **23 passed** in 0.82 s, `/tmp/pt-independent-winbindex-refresh-green2.log`.
- Final focused command: `env -u PYTEST_ADDOPTS PYTHONPATH=$PWD/src QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_kb_winbindex_refresh_20261105.py tests/test_acquisition_winbindex.py tests/test_acquisition_winbindex_rows.py tests/test_kbc_pairs_index.py`: **91 passed in 3.52 s**, `/tmp/pt-independent-winbindex-refresh-focused.log`. Counts overlap.
- Whole-tree `python -m ruff check src tests tools` and `git diff --check` passed. Source binding resolves this worktree's `src/patchtrace/__init__.py`.

The new controls deny sockets/DNS and use authored existing Winbindex records, fake responses/clocks and real saved-index reads. They cover raw/gzip exact-byte persistence, malformed consent and JSON types, URL/date/byte-type refusal, compressed/decompressed caps, malformed/empty responses, prior record preservation, early/late cancellation, 404 response closure, date fallback, publisher failure and private-source cleanup.

## Required integration dependencies and unverified gates

A separate shared-transport defect was concretely reproduced here: with a monotonic clock starting at zero, repeated 429 responses carrying Retry-After 60 and injected sleeps advancing that clock, unmodified `Transport.fetch_metadata` opens requests at `[0,60,120]` despite its 120-second total deadline. It returns PT-ACQ-NETWORK only after the third request. The coordinator owns a separate narrow repair; this module's total-network-budget claim requires that independently reviewed dependency before integration/publication as a bounded end-to-end operation. No duplicate transport wrapper or shared-file edit was introduced.

No live source traffic, binary downloads/execution, model training, broad suite, Windows/native qualification or release acceptance occurred. PR #205/native ownership and evidence were untouched. The API unblocks a later independently reviewed desktop metadata action; UI wiring is deliberately outside this slice.
