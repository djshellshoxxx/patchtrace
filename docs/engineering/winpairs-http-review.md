# Independent WinPairs review and HTTP failure repair — 2026-11-19

Reviewed implementation: `40a1f9762801dfaa64ae44379927cda8b62e16f9`, retained
on `b763f4ab` and integrated at `1f18fb9aaf24cfc67b7515ae8c265a6c66e8a525`.
The reviewed and integrated helper has identical blob
`db2ef965526fb01d10d3e5b6a3be76aca3921128`. This follow-up is based on that
integration commit and does not include the separate Strings publication work.

## Confirmed finding

The URL repair correctly checks raw URLs before normalization, preserves signed
query bytes, validates each redirect before dispatch and closes acquired error
responses. Its transport boundary catches `http.client.InvalidURL` specifically,
but other protocol parsing exceptions inherit from `HTTPException` rather than
`OSError` or `ValueError`. `BadStatusLine`, `LineTooLong` and `IncompleteRead`
therefore escape the fetcher and its callers. A malformed server response can
abort acquisition instead of marking one side missing and allowing the healthy
side to continue. Some raw protocol exception messages contain status/header
text supplied by the server.

Nine independent tests reproduce the gap: each exception at request-open and
response-read boundaries, then each error during an older-side CLI download with
a healthy newer side. All nine fail on the reviewed source.

## Repair

Catch the common `http.client.HTTPException` base with the existing type-only
`WinpairsError` message. This includes `InvalidURL` and keeps all existing URL
checks and response lifetime management. An acquired response closes on a read
failure. Cancellation and unrelated programming exceptions are not broadly
swallowed. The output schema and CLI exit semantics are unchanged.

## Evidence

The [complete evidence archive](evidence/winpairs-http-errors-20261119.zip)
contains original red/green logs, JUnit, lint output and source SHA-256 hashes.

- Baseline independent controls: **9 failed in 0.84 s**.
- Final affected WinPairs suite: **162 passed, 2 skipped in 1.14 s**.
- Whole-tree configured Ruff and `git diff --check`: **passed**.

The two skips are native Windows publication/reparse acceptance. The HTTP tests
use the production urllib fetcher with an injected opener and real standard
library exception types; they do not contact services or execute downloaded
binaries. They establish error classification, redaction, response closure and
CLI continuation, not live service or native Windows qualification.

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_research_qualification_winpairs_http_errors.py \
  tests/test_research_qualification_winpairs_urls.py \
  tests/test_research_qualification_winpairs.py \
  tests/test_research_qualification_winpairs_integrity.py \
  tests/test_research_qualification_winpairs_publication.py
python -m ruff check src tests tools
```
