# Vendor feeds, source lineage, CSAF import validation and the OSV decision (KBF-02)

Status: draft, developer-ready design. Date: 2026-10-15. Base commit: `54fd085`. Proposed alias: KBF-02. Owner packages: `intelligence/csaf/`, `enrichment/{cve,intelligence}.py`, `kev/`, `kbcorrelation/sources/`, `acquisition/winbindex.py`. Reads with SPEC-35 (`docs/specs/csaf-cve-interpretation-engine.md`), SPEC-07/07h, SPEC-46 (`docs/specs/kev-exploitation-context.md`), KBF-01.

## 1. Purpose and non-goals

Purpose: one table that says, for every external data source, what it may be used for, how it is counted (lineage), how it is validated on import, and what happens when it is absent. It also fixes the beta position on OSV and on non-Microsoft vendor feeds, and lists the CSAF validation tests that are and are not implemented.

Non-goals: new network sources for beta; a general vulnerability database; any numeric trust score per source; merging two sources into one claim.

## 2. Definitions

- Lineage: the family a claim belongs to. Independent corroboration is counted by lineage, never by document count. Existing: `msrc` (CVRF, SUG, CSAF), `winbindex`, `nvd`, `cisa`, `analyst` (`kbcorrelation/contracts.py:Lineage`); FAB origin tags (`fabric/origins.py`) are the cross-track equivalent.
- Claim kind: `advisory_fact` (a document states it, with a JSON pointer), `index_claim` (Winbindex states it), `binary_observation` (a verified hash/PE parse), `rule_hypothesis` (a curated rule), `analyst_statement`.

## 3. Source matrix

| Source | Role (what it may support) | Lineage | Offline import | Live (consent host) | Status at `54fd085` | Never used for |
|---|---|---|---|---|---|---|
| MSRC CVRF monthly | KB -> CVE -> product edges (`Remediations[Type==2]`), `FixedBuild`, stated CWE text | msrc | `kb index import FILE` BUILT | `kb index sync` BUILT, URL shape and real JSON UNVERIFIED (probe L1) | dialect `cvrf-json/0` is a SYNTHETIC placeholder (`cvrf.py:5-8`) | "the KB fixes this function"; any KB without a Type 2 line |
| MSRC SUG per CVE | description, CWE, CVSS context | msrc | `correlate --snapshot` BUILT | `correlate --fetch` BUILT, `tools/live_nvd_probe.py` + `live-nvd.yml` exist, first run not recorded here | UNVERIFIED live | KB lists (SUG has no KB rows, RK1 s1) |
| MSRC CSAF 2.0 | CVE-first facts, product status, applicability OLD/NEW, VEX | msrc | `intelligence import` BUILT | `intelligence fetch` BUILT, layout UNVERIFIED (probe L4) | validator BUILT | KB -> files (CSAF has no file list) |
| NVD API 2.0 | CPE applicability, CWE, CVSS vectors | nvd | `correlate --snapshot` BUILT | `correlate --fetch` BUILT (paced) | UNVERIFIED live | KB mapping; "not affected" proof |
| CISA KEV | CVE-level "exploited" listing; reading order of CVEs | cisa | `kev import FILE` BUILT | `kev fetch` BUILT; canonical URL unverified until `live-kev.yml` passes | adapters to KB/Leads NOT bound (KBF-06) | function order; "this function is exploited" |
| Winbindex | file builds, SHA-256, `(version, KB)` rows, symbol URL inputs | winbindex | `kb index import --winbindex FILE` BUILT | KB fetch NOT BUILT (KBF-01 s6); `acquire search` BUILT | Windows 10/11 client x64 only | KB -> all changed files; Server-only builds |
| Symbol server | the PE bytes of an approved pair | (bytes) | n/a | `kb acquire` BUILT | live unverified on Windows | anything but the two planned URLs |
| Update Catalog | package inventory | - | manual metadata only | none (no documented API) | NOT SUPPORTED | scraping, ever |
| OSV (`api.osv.dev`) | open-source ecosystem advisories | would be `osv` | none | none | NO CODE, NO SPEC (grep: no match in `src/`, `tests/`, `tools/`) | Windows PE servicing |
| Other CSAF vendors | CVE-first facts for non-Microsoft products | would be per vendor | `intelligence import` accepts any valid CSAF 2.0 file | none: `CONSENTABLE_HOSTS = {msrc.microsoft.com}` | out of beta | - |

### 3.1 OSV decision (proposed; owner confirms, see gameplan D-4)

OSV is not a source of Windows servicing data, its ecosystems (PyPI, npm, Go, ...) never name a Windows KB, and the beta workflow (KB -> product -> PE pair) cannot consume it. Decision: not in beta, no code, no consent host. If a later use appears (the Tier R corpus, `docs/specs/known-answer-corpus.md` mentions OSV only as an unreachable reference), the adapter contract is: provider id `osv` added to `enrichment.cve._PARSERS` (additive; `CveSnapshot.response_digests` gains the key `osv`, `snapshot_id` recomputes by the same `_snapshot_id` rule), host `api.osv.dev` with its own consent object and a SPEC-42 census row, 4 MiB cap, lineage `osv` that never counts toward `msrc` corroboration, and an import path that accepts only the OSV JSON schema fields `id`, `aliases`, `summary`, `details`, `affected[].ranges[]`, `database_specific.cwe_ids`. Test obligations: hostile-text, unknown-field and 4 MiB boundary tests, a "lineage counts once" test.

### 3.2 Non-Microsoft vendor feeds

Procedure to add a CSAF vendor host (documented, not built): a `CONSENTABLE_HOSTS` entry in `csaf/transport.py`, a path-prefix rule, a provider-metadata fixture, a SPEC-42 census row, a refusal-without-consent test, and a statement in `docs/privacy.md`. Until then a user may import any valid CSAF file offline.

## 4. CSAF import validation: what is checked

`intelligence/csaf/validate.py` (`VALIDATOR_VERSION = 1`) runs, in order: strict JSON parse with limits (16 MiB, depth 64, 2,000,000 JSON values, string 1 MiB, 10,000 vulnerabilities, 100,000 products, 200 findings), the vendored OASIS JSON Schema keywords, then mandatory tests 6.1.1-6.1.7, 6.1.14-6.1.33 (including 6.1.27.1-6.1.27.11) and optional tests 6.2.1 and 6.2.20 (warnings only). Not implemented: 6.1.8-6.1.13, 6.2.2-6.2.19, 6.3 (`TESTS_NOT_IMPLEMENTED`). From memory of the OASIS text (UNVERIFIED here, the host is unreachable) 6.1.8-6.1.13 concern CVSS validity and consistency, CWE ids, language codes and PURLs. Consequence: a document that violates one of those is accepted. `ValidationReport.tests_not_implemented` records the list (`validate.py:980`); whether `intelligence explain` and the Leads/KB context surface it as a visible limitation is UNVERIFIED (not read end to end); if it is not shown, that is a defect fixed in KBB-13. Any error rejects the whole document; nothing is partially accepted (`load_document`).

Import outcome codes: `PT-INTEL-FORMAT` (not strict JSON), `PT-INTEL-LIMIT`, `PT-INTEL-UNSUPPORTED` (real string: `csaf_version None is not supported; only 2.0`), `PT-INTEL-VALIDATE` (schema or mandatory test failed), `PT-INTEL-INPUT` (the `--cve` is not listed by the document), `PT-INTEL-STORAGE`, `PT-INTEL-INTEGRITY`, `PT-INTEL-CANCEL`.

Storage rule (BUILT, `intelligence/storage.py`): validate and normalize completely, then write the raw bytes (content-addressed sidecar), the facts sidecar, then two append-only pointer rows (`advisory-facts`, `advisory-source`). A rejected document leaves every earlier row untouched. Every sidecar read is SHA-256 verified; a facts file belonging to another source is recomputed from the verified source bytes (C-21 fixed).

## 5. Cross-source rules (binding)

1. One lineage counts once: MSRC CVRF + SUG + CSAF agreeing on a CWE is "1 source family", not three votes (KB plan s6 `test_lineage_counts_once`).
2. Conflicting sources stay conflicting: a CVE whose CWE sets disagree is `cwe:` conflict; only values reported by every CWE-reporting provider survive into ranking (`enrichment/cve.py:529-543`). NVD Primary+Secondary CWEs are one provider list today (audit C-23, OPEN): a conflict can be reported where the providers agree. Fix: compare per provider-and-type sets (KBB-04).
3. Missing is unknown: an absent source yields `unknown` / `not-run`, never `not-affected` / `not-listed` (KEV `no-snapshot`, KB `kev: not-loaded`).
4. Dates are provenance, not chronology: file version and timestamp never order builds (`lineage.py`).
5. Advisory, string and code text is untrusted data: stripped of controls and bidi marks, rendered with `PlainLabel`, never in error messages, never used to build a URL or a path.

## 6. Determinism

Every normalized record has an id derived by `domain_id` from canonical fields only (no clock, no path). Re-importing the same bytes yields the same ids and no new row. Parser, normalizer, lexicon and rules digests (`PARSER_VERSION`, `NORMALIZER_VERSION`, `lexicon_digest()`, `rules_digest()`) are part of every derived cache key.

## 7. Security and privacy invariants

No silent upload; offline-first; no fabricated evidence (a vendor statement is a statement); credentials session-only; no source is ever executed or rendered as markup; Microsoft-derived data (MSRC bytes, Winbindex records, binaries) is never committed (fixtures are synthetic with hash-only provenance, owner decision O-9).

## 8. Budgets

CVRF 32 MiB / 5,000,000 nodes / 500,000 edges per document (provisional until L1); CSAF as section 4; SUG and NVD 4 MiB; Winbindex 64 MiB compressed / 256 MiB decompressed; KEV per KEV plan. A 10x-over-cap document is refused before parse in under 100 ms.

## 9. Test plan

Existing: `tests/test_intel_validate.py`, `test_intel_discovery.py`, `test_intel_hostile_input.py`, `test_intel_storage.py`, `test_kbc_cvrf.py`, `test_kbc_csaf_bridge.py`, `test_enrichment_cve.py`, `test_enrichment_intelligence.py`. New (red first): `test_intel_limitations_list_untested_validation.py`, `test_enrichment_cwe_per_provider.py` (C-23), `test_source_lineage_counts_once.py` (CVRF+SUG+CSAF fixture gives 1), `test_osv_not_wired.py` (asserts no `osv` provider and no `api.osv.dev` string in `src/` until the decision changes).

## 10. Open questions

Q1 OSV in or out (default out). Q2 Implement 6.1.8-6.1.13 for beta or document the limitation (default document; cheap to add later because the validator is a list of independent tests). Q3 Is a second CSAF vendor wanted (default no).

## 11. Acceptance

The table in section 3 is true when the verification commands run: `grep -rn "api.osv.dev" src` is empty; `python -m patchtrace intelligence import` on a CSAF fixture prints the limitation line; a three-source fixture shows `1 source family`.
