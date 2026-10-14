# KB-CVE correlator fixtures (plan K0f)

**Every file here is SYNTHETIC and hand-written for PatchTrace tests.** No file is Microsoft-derived or copied, and no
file is live evidence. Identifiers are invented: `CVE-2099-*`, `KB5099*`, `PT-*` product ids, "Example" product
names, `example.invalid` hosts. The CVRF JSON dialect `cvrf-json/0` is a project placeholder; its real shape is
unverified until live probe L1 (plan s10.2).

`MANIFEST.json` lists every file with its SHA-256, creation time (UTC), origin, licence, generator and consumers.
Builder-made files come from `tests/kbc_helpers.py` (`generated_files()`), and `tests/test_kbc_fixtures.py` asserts
that the committed bytes still match. Edit the builder, then regenerate; never hand-edit a builder-made file.

## Files

| file | made by | what it holds |
|---|---|---|
| `cvrf-2099-Feb.json` | `baseline_cvrf()` | The two-CVE month. KB5099001 for CVE-2099-20001 on PT-CLIENT and PT-CLIENT-ARM (one row, two products). KB5099002 for CVE-2099-20001 and CVE-2099-20002 on PT-SERVER. CVE-2099-20003 has a Type 5 known-issue text that mentions KB5099001 (mention only). |
| `cvrf-2099-Feb-neg.json` | `neg_cvrf()` | Negative rows: duplicate pointers (S05), multi-product (S04), undefined ProductID (S06), Type 5 only (S07, NEG-06), contradicting status (S08), unrelated number (S09), control and slash (NEG-01), HTML and external URL as text (S19, NEG-24, NEG-25), one KB across three CVEs and two products (S03). |
| `cvrf-2099-Feb-reordered.json` | `reordered(baseline_cvrf())` | Same content with every array reversed. Parsing must not depend on order. |
| `cvrf-2099-Feb-empty.xml` | hand-written | Valid XML month with no vulnerabilities (S07: an empty index is `not_observed`, not "0 CVEs"). |
| `cvrf-2099-Feb-dialect-unknown.xml` | hand-written | Future dialect with renamed root and containers (S11: refuse with "dialect unknown"). |
| `cvrf-2099-Feb-duplicate-key.json` | hand-written | Duplicate keys on purpose (NEG-07). Strict parsing must refuse the source. |
| `csaf-kb.json` | `baseline_csaf()` | CSAF 2.0 shape. CVE-2099-20001 has a vendor_fix that names KB5099001 through a product group (S13). CVE-2099-20002 has a vendor_fix with no KB (S12). PT-SERVER-LEGACY is known_not_affected (S14, NEG-08). |
| `kev-synthetic.json` | `kev_snapshot()` | CVE-2099-20001 is listed (2099-02-12). CVE-2099-20002 is not listed. |
| `identifiers.json` | `identifier_matrix()` | KB and CVE syntax matrix (`kb-syntax/1`, edge normalisers, KB token finder). Each row names the expected result, checked against `patchtrace.kbcorrelation.ids`. |
| `MANIFEST.json` | recomputed by hand (see Regenerate) | Hashes and provenance of every file above. |

## Counts and the E0 script

Plan s10.1 step 1 reads "1 document, 4 edges, 1 mention-only". The baseline month has **five** edges: four
vendor-remediation edges (client, ARM64 for CVE-2099-20001; server for CVE-2099-20001 and CVE-2099-20002) and one
mention-only edge (CVE-2099-20003). The "-> 0/2/3/4" items in s10.1 are exit codes. The baseline shape (s5 (a)) is
used here; the K1 owner must reconcile the "4 edges" wording in the plan.

## Scenario coverage

| ids | covered by | note |
|---|---|---|
| S01 | `cvrf-2099-Feb.json` | KB in a product-scoped row |
| S02 | `cvrf-2099-Feb.json` (CVE-2099-20003) | mention only |
| S03 | `cvrf-2099-Feb-neg.json` (CVE-2099-20012..20014) | one KB, three CVEs, two products |
| S04 | `cvrf-2099-Feb.json`, `cvrf-2099-Feb-neg.json` | several product ids, one source row |
| S05 | `cvrf-2099-Feb-neg.json` (CVE-2099-20004) | duplicate rows, separate positions |
| S06 | `cvrf-2099-Feb-neg.json` (CVE-2099-20006) | undefined ProductID |
| S07 | `cvrf-2099-Feb-neg.json` (CVE-2099-20007), `cvrf-2099-Feb-empty.xml` | Type 5 and empty index |
| S08 | `cvrf-2099-Feb-neg.json` (CVE-2099-20008) | status contradicts fix |
| S09 | `cvrf-2099-Feb-neg.json` (CVE-2099-20009) | unrelated number, rejected |
| S11 | `cvrf-2099-Feb-dialect-unknown.xml` | unknown dialect |
| S12 | `csaf-kb.json` (CVE-2099-20002) | vendor_fix with no KB |
| S13 | `csaf-kb.json` | group expansion |
| S14 | `csaf-kb.json`, NEG-08 | known_not_affected |
| S19 | `cvrf-2099-Feb-neg.json` (CVE-2099-20011) | HTML as plain text |
| S20 | not here | needs a captured official response; live item |
| NEG-01 | `cvrf-2099-Feb-neg.json` (CVE-2099-20010), `identifiers.json` | slash and control |
| NEG-06 | `cvrf-2099-Feb-neg.json` (CVE-2099-20007) | Type 5 mistaken for KB |
| NEG-07 | `cvrf-2099-Feb-duplicate-key.json` | duplicate keys |
| NEG-08 | `csaf-kb.json` | known_not_affected |
| NEG-24, NEG-25 | `cvrf-2099-Feb-neg.json` (CVE-2099-20011) | text only, never fetched |

Not covered by a file: S10, S15-S18 (API, revisions, offline and redirect behaviour; tests build these), and the
pair (P, B) and enrichment matrices. The builders can derive them in code when a test needs them. Forged-publisher
cases (S16) are built in tests, never committed, so no fixture claims a real publisher.

## Regenerate

```
python -c "import sys; sys.path[:0]=['tests','src']; import kbc_helpers as h; [open(h.FIXTURE_DIR/n,'wb').write(b) for n,b in h.generated_files().items()]"
```

Then recompute `MANIFEST.json` (sha256 and bytes per file) and run `tests/test_kbc_fixtures.py`.

## K1 additions (slice K1, appended; K0f files above are unchanged)

| file | made by | what it holds |
|---|---|---|
| `csaf-kb-valid.json` | `tests/kbc_k1_support.py::valid_csaf()` | `csaf-kb.json` with CVE-2099-20001's contradiction removed (PT-CLIENT and PT-CLIENT-ARM only `fixed`, PT-SERVER `known_affected`). It passes the real CSAF validator; `tests/test_kbc_csaf_bridge.py` asserts the committed bytes still equal the builder. |

**Finding for the K0f owner.** `csaf-kb.json` lists PT-CLIENT and PT-CLIENT-ARM under both `fixed` and `known_affected` for
CVE-2099-20001, which the in-repo CSAF validator rejects (`PT-INTEL-VALIDATE`, test 6.1.6). It is kept unchanged (K0f owns it);
K1 tests that need a document the real validator accepts use `csaf-kb-valid.json`, and K1 bridge tests that only need
normalised facts build them in code.

**Count reconciliation (plan 10.1 step 1).** The baseline month yields 5 edge rows: 4 `vendor-remediation` edges plus 1
`mention-only` edge. "4 edges, 1 mention-only" in the plan counts the mention separately; `ImportedDocument.counts()` reports
`edges: 4`, `mention_only: 1`, `edge_rows: 5`.
