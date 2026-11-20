# WinPairs URL and request boundary repair — 2026-11-19

Baseline: `f2458aae22ea6177be64cfc2fb439a79950f00ff` (PR #322).
Scope: `tools/research_qualification/winpairs.py`, its existing contract in
`docs/research/winpairs.md`, and dedicated offline regression controls.

## Reproduced behavior

The unchanged baseline fails **39 of 45** new controls; six positive/previously
defensive controls pass. `urlsplit`/`urljoin` strip some raw controls before
validation. Empty userinfo passes the truthiness check. Malformed authority and
port errors escape the helper's typed boundary, and urllib request dispatch can
raise `InvalidURL` outside the CLI's exception boundary. HTTP error/redirect
responses remain unclosed. A malformed binary redirect can abort the acquisition
before the healthy side and pair receipt are completed.

The controls use authored URLs, gzip metadata, response bodies and an injected
urllib opener. They neither contact an unallowlisted destination nor execute a
downloaded target. No SSRF exploitation or live service result is claimed.

## Uniqueness evidence

The 325 locally fetched `origin` refs (including symbolic/snapshot aliases) were
inspected for this helper. It exists on 56 refs in three file versions:

- `d55f02578680f0234da6ebdbcd4b456182169d06`
- `c2f6c7d4d0dd64a4800a6f3c19f37c3fc08ad92f`
- `9b95324c2d6bd2b9bd1fed938615cbce18f9a65c`

All three have identical ASTs for `check_url`, `urllib_fetcher`, and
`fetch_checked`: SHA-256
`ed8d8a20783e3a70f32a734ff235c0e0bbebc3041a2dfa89d2bc5274b57cbb51`.
The historical versions differ in publication handling, not these request
boundaries. The later finding recorded in `SECURITY_AUDIT.md` therefore remains
present in the fetched sources; no remote implementation is silently recovered
or credited. Recheck current refs before integration if another worker publishes.

## Repair

Raw URL and Location text is validated before normalization. Empty userinfo,
malformed authorities, raw controls/whitespace and unencoded non-ASCII text are
refused with fixed errors. Every resolved redirect is checked before dispatch.
Allowed relative/query-only URLs and encoded signed query bytes retain their
existing behavior. The initial host restriction and redirect-only Azure suffix
remain unchanged.

The one-hop urllib fetcher validates its target before constructing the opener,
maps request/transport URL failures to redacted `WinpairsError`, and closes HTTP
error/redirect responses without reading their bodies. CLI controls verify that
a malformed older-binary redirect produces a missing side while the newer
artifact and pair manifest are retained. No schema, selection, byte identity,
publication or exit-code contract changed.

## Verification

- Baseline new controls: **39 failed, 6 passed**, 1.13 seconds.
- Repaired four-file WinPairs selection: **153 passed, 2 skipped**, 1.36 seconds.
  Both skips are existing native Windows publication controls.
- Final dedicated URL controls: **45 passed**, 0.66 seconds.
- Configured whole-tree `ruff check src tests tools`: passed.
- `git diff --check`: passed.

The focused counts overlap and must not be added. These results do not qualify
the repository's full suite, native Windows path, real remote services, or real
analysis producers. Independent review and aggregate final-head gates remain
required before promotion.

Original failed output, corrected selection output, final dedicated JUnit and
SHA-256 manifests are retained in
[the evidence archive](evidence/winpairs-url-boundary-20261119.zip).

Resume commands:

```sh
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_research_qualification_winpairs_urls.py \
  tests/test_research_qualification_winpairs.py \
  tests/test_research_qualification_winpairs_integrity.py \
  tests/test_research_qualification_winpairs_publication.py
python -m ruff check src tests tools
```

The test runtime was Python 3.12.14, pytest 9.2.0, PySide6 6.12.0 and Pydantic
2.14.2. The dedicated runtime initially lacked Ruff's executable despite its
package being present; the already provisioned independent runtime's Ruff
executable supplied the passing lint result. No dependency version was changed.
