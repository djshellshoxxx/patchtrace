# Independent review of retained acquisition evidence

Reviewed implementation: `fd886e194d8bd2ee346162017a8f0939310053f3`.
Reviewer: integration coordinator, independently of the acquisition author and
completion worker. The earlier stopped review worker is not counted as a
completed review. This report covers the bounded acquisition persistence slice;
it does not qualify the entire application or the interrupted aggregate suite.

## Source review

The review covered the new strict evidence contract, capture and consent flow,
the attachment journal and recovery path, the project-port implementation,
enrichment-kind registration, generated schema, architecture guard and changed
specification/module index. The source proposal and inspected manual pair remain
separate. The captured proposal retains its pending-byte assessment and window;
the inspected pair remains grade B/tier E, user-asserted lineage, unverified fix
boundary and a manual window.

Source capture performs a bounded canonical JSON round trip before passing fresh
row mappings to provider ports. The consent digest includes that source identity
and the request plan. Receipt validation happens before investigation approval
and project creation. A valid byte hash alone cannot admit a receipt that names
another source entry or an unapproved download URL.

The review also checked that the journal operation key includes the evidence ID,
uses the original `base` revision after later attachment revisions advance, and
is recomputed before resume or interruption writes. This closes the previously
identified admission gap for an internally valid replacement record under an old
operation key. Existing tests exercise both changed source claims and changed
receipts with their own content hashes recomputed; refusal therefore does not
depend only on an intentionally stale digest.

The filesystem publisher is bound through the explicit project port in
`wiring.py`. Store/domain modules do not import the sibling publisher. The finite
architecture exception permits exactly the three selected publisher symbols in
that composition root. Actual project ID and ordered artifact ownership are
checked while the project owner is open. Sidecar creation is exclusive; an
existing unequal sidecar or row is retained and causes incomplete attachment.
Legacy requests and journals omit the optional evidence and keep their prior
operation identity. Acquisition rows are outside derived-data retention.

## Independent controls and observed outcomes

`tests/test_kbc_acquisition_peer_review.py` adds four controls using the public
CLI/service wiring, real project and workspace stores, authored PE byte fixtures,
and the existing socket-denied transport fixture. No target file was executed.

| Independent control | Observed result |
|---|---|
| Provider mutates headings and nested version lists in both plan and stage input mappings | The persisted source equals the approved preview as structured data; the mutations do not change its claims. |
| Downloaded bytes are valid but their receipt names another upstream entry hash | Typed `PT-KBC-VERIFY`, no project, no investigation/decision/attempt/journal mutation, staging removed. |
| Downloaded bytes are valid but their receipt names an unapproved URL | The same pre-attachment refusal and cleanup invariants hold. |
| Repeated preview and caller mutation of returned nested source lists | Later preview/digest are identical to the original, with no provider call or persistence change. |

The four new controls plus all 27 author acquisition-evidence cases pass:
**31 passed in 2.06 seconds** on the existing Linux/Python 3.12.14 environment.
Whole-file Ruff and whitespace checks pass. The author separately retained the
larger **1,547 passed / one native-Windows skip** affected run. These selections
overlap and must not be summed.

The first review run recorded **2 failed, 29 passed**. Both failures came from
the review test expecting CLI exit 2 for `PT-KBC-VERIFY`; the existing error map
and established acquisition regression specify exit 3. The control was corrected
to that existing contract without changing application code or the refusal,
state-preservation and cleanup assertions. The original test source, failure log
and JUnit are preserved in the review archive.

## Disposition and limits

Accepted for integration within the stated scope. No additional implementation
defect was reproduced by these controls. Source-entry hashes and normalized rows
are retained claims; they do not authenticate Winbindex or preserve complete raw
entries, a whole index, or every input needed to rerun the resolver. Historical
acquisitions receive no invented provenance. Advisory export and desktop display
are unchanged. Native Windows publication, live providers, full-suite acceptance
and release qualification remain separate gates.

Exact commands, source/test hashes, original and corrected receipts, and raw
JUnit/logs are preserved in
[`evidence/acquisition-provenance-peer-review-20261120.json`](evidence/acquisition-provenance-peer-review-20261120.json)
and its adjacent ZIP archive.
