# Retained CVRF context → pilot — 2026-11-18

## Exact scope and source

| Identity | Commit |
| --- | --- |
| Published #307 baseline | `58fc130631f602b6e907bb054d30c21d810551d4` |
| Specification and failing-test precursor | `8dff2992` |
| Implementation | **`353902677e6d59961e808a90b2a3dd96d2b43269`** |

The collector now admits source-bound CVRF cards retained by the project's KB
import/attachment workflow when no retained CSAF document lists the CVE. This
closes the authored `kb import-pair → analysis → rank → pilot leads --cve` gap.
It adds no parser, acquisition, target execution, engine, schema or project opener.

`pilot/sources/kb_context.py` captures the existing owner's enrichment rows and
returns immutable context. It checks canonical body integrity, ownership and row
identity, successful/non-stale status, ordered hashes, current context-key formula,
source document IDs and complete original field bindings. Latest revisions are
selected separately within each investigation. Invalid or ambiguous retained state
withholds CVRF; it never chooses an older convenient context. Withdrawn CVEs remain
suppressed even when another investigation retains an older copy. A named withdrawn
CVE explicitly reports that its newer context withdrew the card and older records
remain historical.

Current `IntelligenceRules.interpret` recomputes CWE profiles and hypotheses from
admitted fields, preserving native pointers and recorded source hashes. The small
internal `AdvisoryRuleView` does not fabricate CSAF metadata. CVRF observations all
use `D_vendor_text`; agreeing repetitions add no independent origin or rule. The
existing `kb_link_digest` records context identity, and source SHA values join
`advisory_facts_ids` under its unchanged 64-source maximum.

CSAF negative, conflicting and withdrawing revisions take precedence. If its
store cannot be fully read, fallback is disabled because the overlap universe is
unknown. Independently usable CSAF remains available. Corrupt raw CSAF bytes alone
do not imply an unreadable universe when verified derived facts remain usable.

## Claim and lifecycle limits

The project stores **recorded import-time source bindings**, without raw source
objects or full retrieval provenance. Displayed Why text says raw source bytes and
upstream freshness were not reverified and import authenticity is not established.
Applicability and mapping stay unknown on both sides; the default gate is
`unverified`, with its tentative cap and no code-locality anchors. The explicit
analyst assumption stays labelled and recorded without changing those unknown facts.

Capture caps input at 1,000 rows and 16 MiB before body loading, then 100,000 nodes,
depth 32, 4,096 cards and 16,384 field references. A limit refuses fallback rather
than selecting a prefix. Cancellation is checked before reads and throughout
processing. A worker consumes the captured adapter without store access or another
project owner, Qt, network or external process.

The separate staleness work owns `current_inputs.py`, `pilot/store.py`,
`pilot/cli.py` and `ui_leads.py`; those files are unchanged here. **Freshness on read
and publication requires the separate combined hook and root's independent review.**
This standalone source does not claim to complete that gate.

## Recorded failures and qualification

| Stage | Observed result | Meaning |
| --- | --- | --- |
| Initial authored baseline | 31 failed in 2.98 s | Missing bridge and initial fixture API/dialect mistakes; original output retained. |
| Corrected fixture baseline | 31 failed in 2.48 s | Production source still unchanged; missing fallback/admission helpers and overlap behavior reproduced. |
| First implementation selection | 29 passed, 2 failed in 2.73 s | Selected KB fixture had only one CVE; added a separate source-bound authored context for the other CVE. |
| Existing-protocol selection | 389 passed, 1 failed in 18.49 s | New internal protocol added to the exact inventory; behavior-free and structural assertions retained. |
| Initial unreadable-CSAF control | 1 failed in 0.66 s | Damaged only raw bytes; intact verified facts correctly preserved CSAF. |
| Expanded initial selection | 395 passed, 1 failed in 17.99 s | Same control setup corrected to damage both layers and assert an actual unreadable universe. |
| Corrected guard-removal control | 1 expected failure in 0.65 s | Removing unreadable-CSAF guards reproduced unintended fallback; exact patch retained and fully restored. |
| Expanded suite before final wording repair | 1,533 passed in 38.72 s | Historical intermediate result. |
| Withdrawal wording control | 1 failed in 0.73 s | Generic absence message omitted historical cards; corrected without changing its not-found exit code. |
| **Final exact-source affected suite** | **1,533 passed in 35.49 s** | Source and tests committed as `35390267`. |
| Whole repository Ruff / whitespace | Passed / passed | Earlier two test-only E741 findings corrected. |

Selections overlap; their counts must not be added. Counts describe checks, not
product-completion percentages or real-engine accuracy.

The final selection contains every `test_pilot*.py`, original Leads presentation
and stored-read controls, CSAF CLI/explain, field provenance, shared-source lineage
and fabric integration. Forty new bridge cases cover native source reconstruction;
explicit, derived and missing CWE; recomputation after stored-rule tampering; CSAF
gates and withdrawal; invalid/legacy bindings; wrong owner and swapped pair;
stale/corrupt/newest invalid context; independent investigations; withdrawal/removal
identity; source limits; cancellation; no additional project open; worker purity;
and a named subset from a 65-CVE retained document.

## Retained CLI journey

The receipt script builds a fresh authored project through existing KB import/pair
helpers, applies synthetic stored analysis and invokes ranking. Two real guarded
Python children run production CLI dispatch for `pilot leads` and `pilot why`,
with this exact checkout in `PYTHONPATH`. Both refuse Qt/UI imports, sockets and
nested external process execution.

Both returned 0. Stored result:
`8ebeda7aefa27fb75191b19a01d9efabd840a7fd9ed361ba7c81f38a25720e8f`.
The authored `CVE-2099-20001` had gate `unverified`: two partial-fit leads and three
queue rows, with no FITS ADVISORY result. Why text includes retained-source,
freshness, authenticity, applicability and locality limitations. This is a mechanics
example, not accuracy evidence about a real CVE or binary.

The receipt wrapper initially assumed fields absent from the compact CLI CVE
summary (`source_ids`, then `limitations`). Both production commands had already
succeeded. The wrapper was corrected after inspecting the actual output; first
successful JSON and the formatting-failure record are retained. No production
change resulted from those wrapper failures.

The real desktop read path returns the same stored result ID, and existing Leads
widget tests are included. No widget or tooltip was added. Native/manual GUI
acceptance was not performed.

## Evidence and open gates

[Manifest](pilot-retained-cvrf-context-20261118/manifest.json) records source and
baseline, file hashes, unchanged files owned by other agents, selection, commands
and every receipt digest. [Raw evidence](pilot-retained-cvrf-context-20261118/raw-evidence.zip)
contains the authored red runs, failures, negative-control patch, final log/JUnit,
guarded CLI script and output. Two early direct tool checks are labelled as
transcript-derived summaries instead of raw logs.

Open gates: separate `current_inputs` hook and combined read/publication checks;
root's independent combined review; integration/full and hosted qualification;
native Windows/manual acceptance. Raw-source portability and upstream revalidation
remain separate work. This author made no remote change.
