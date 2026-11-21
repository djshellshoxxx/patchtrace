# Build-tool HTTPS redirect repair — 2026-11-19

## Reproduced boundary failure

The backend builder and pin-verification tool declared HTTPS-only downloads but
used urllib's automatic redirects. The builder checked the final URL only after
the redirected request had already occurred. The verifier did not check that
final scheme. Five redirect status codes could therefore send a request to an
HTTP target. Hash/signature verification remained a separate gate; these probes
do not demonstrate acceptance of an unverified component or execution of a target.

The regression transport replaces only the HTTP/HTTPS connection handlers and
retains urllib's actual request, error and redirect processors. All bodies,
destinations and credentials in these controls are authored test values. No
network request, vendor download or backend execution is used.

At original integration source `e430309a`, the first 28 controls recorded
**17 failed and 11 passed in 1.97 seconds**. The failures include HTTP dispatch,
untyped malformed redirects, unbounded redirect-body draining and verifier
response/error handling. Existing HTTPS success and initial HTTP-refusal
controls remain positive cases.

## Change and compatibility

`tools/verify_backend_pins.py` now supplies the shared stdlib `open_https`
boundary used by both tools. A no-redirect handler exposes the original HTTP
response before urllib parses or follows its Location. The boundary:

- Validates the initial and each joined URL before dispatch, requiring HTTPS,
  a host, a valid port and no decoded authority controls or whitespace.
- Accepts relative and cross-host HTTPS targets, retaining urllib's Latin-1
  header URL quoting, and follows at most ten redirects.
- Closes redirect and error responses without reading their bodies. The caller
  owns and closes the final successful response.
- Recomputes Host for each target. It copies intentional headers rather than
  urllib's generated unredirected Host, removes content/proxy-authorization
  headers, and drops Authorization/Cookie across an origin change.
- Normalizes malformed joins and concrete transport `InvalidURL` failures.
  The builder retains `PT-BUNDLE-FETCH`; the verifier uses `VerifyError`.

The existing callers supply only public User-Agent and Accept-Encoding headers.
Payload size limits, gzip expansion limits, pinned hashes, signature checks,
cache revalidation, source comparison and all committed component pins remain
unchanged. No distribution/version/vendor/licence change is part of this repair.

The relevant BUNDLE specification was amended before implementation. Historical
inspection found nine builder blobs with the same download-function AST and
four verifier blobs with two fetch-function ASTs; none contained a redirect
handler/opener repair. This is a compatible correction of the existing HTTPS
contract, not an unverified dependency upgrade.

## Independent review and preserved intermediate failures

The first helper passed 260 affected tests with one existing build-tool skip,
but independent review found two additional issues:

1. Copying `request.header_items()` after transport processing copied the
   generated origin Host into a cross-host request. The follow-up URL and Host
   could disagree.
2. A percent-encoded newline in an authority passed the initial URL check, then
   `Request` decoded it and the connection constructor raised raw `InvalidURL`.

Both were reproduced without sockets. Strengthened header and encoded-authority
controls then recorded **28 failed and 2 passed in 1.37 seconds** against that
intermediate helper. The corrected implementation preserves target-derived
Host and refuses those authorities before transport. The original probes,
intermediate results and source identities remain in the evidence archive.

The independent corrected-source review ran seven checks covering both original
cases, same-origin and cross-origin credentials, public headers, and typed errors
through both callers. All seven passed, with response closure and prior output
preservation. Reviewed runtime SHA-256 values:

- `tools/verify_backend_pins.py`:
  `b7bf3ddfcadd9ca5841ce8c9caba1f48bb582f20ba1912376a158c3e3ca68de7`.
- `tools/build_backend_bundle.py`:
  `db040d7e1ff2ec9694cc3f69c47f7439a84853d4b316563c4d7c09ce27b5a368`.

## Verification

| Check | Actual result |
| --- | --- |
| Original 28 controls, before runtime change | 17 failed, 11 passed; 1.97 seconds |
| Initial helper, five affected files | 260 passed, one existing skip; 6.17 seconds; later review findings remain explicit |
| Header/authority follow-up against initial helper | 28 failed, 2 passed; 1.37 seconds |
| Corrected helper and five affected files | 289 passed, one existing skip; 8.20 seconds |
| Exact final regression file after import-order correction | 57 passed in 1.85 seconds |
| Previously skipped real authored wheel-build case | 1 passed in 2.12 seconds after enabling already installed local build tools |
| Independent corrected-source controls | Seven passed; no sockets or target execution |
| Configured whole-tree Ruff and private-environment pip check | Passed |

The existing skipped case required setuptools and wheel. The private test
environment now reads runtime-owned setuptools 84.2.1 and wheel 0.48.0 through
explicit links; no package was fetched, no shared installation changed, and no
repository dependency or bundle pin changed. The real wheel-build follow-up uses
the test's tiny authored source tarball and offline pip invocation. It does not
rewrite the prior skipped outcome into a pass.

The existing `test_verify_without_inputs_records_nothing` fixture now injects
the already supported offline command-runner seam as well as the offline fetch
seam. Previously that nominally hermetic test could still attempt a Git fetch.
Its failure-report assertions remain unchanged. The gzip-body test now mocks
the shared opening seam; its content and decoding assertions are unchanged.
One final test import-order correction changes neither runtime nor assertions.

## Evidence and limits

[The evidence archive](evidence/backend-https-20261119.zip) contains original and
intermediate failures, corrected results, independent reviews/probes, historical
blob comparison, exact commands/source hashes and local build-tool provenance.
Each payload has a SHA-256 in the archive manifest.

This qualification is local and offline. It does not establish live vendor/CDN
compatibility, TLS/proxy behavior on every host, Windows packaging or aggregate
release acceptance. Timeouts remain per request; no total-chain wall-clock
deadline is claimed. Other build-tool and native dependency findings retain
their own dispositions. No main merge, tag, release or deployment is performed
by this repair. **[no release]**
