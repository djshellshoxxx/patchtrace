# Additional reuse research: advisory metadata, provenance and static file identity

Research date: **2026-11-03 America/Vancouver (2026-11-04 UTC)**. Research only; no application changes, live advisory ingestion, target execution or dependency execution. Recommendations below are design judgments, not compatibility acceptance. Repository observations refer to main **`b77d84e5decf736b031f0a24094001274de41178`**. Active Claude PR #176 was inspected at **`db0a0b05d48e4c8fb394ec4e221677b5efb37954`**, not treated as merged. External source clones were read outside the checkout.

## 1. Decision and exact repository baseline

The highest-value reuse is a **development conformance oracle**, followed by a verifiable offline advisory import receipt. A replacement advisory database, full scanner, new provenance framework or broad PE parser would duplicate existing work. Keep MSRC's vendor product/KB assertions, locally measured file identity and the analyst's mapping as different records.

| Area | Already in this main snapshot | Remaining gap / ownership implication |
| --- | --- | --- |
| CSAF validation | `intelligence/csaf/validate.py` performs strict bounded JSON, official-schema-derived checks and a documented mandatory-test subset. `TESTS_NOT_IMPLEMENTED` explicitly includes 6.1.8–6.1.13, optional 6.2.2–6.2.19 and informative tests. | Compare the declared subset against independent implementations; do not relabel a successful subset result as complete conformance. |
| Advisory retrieval/storage | `csaf/{transport,discovery}.py`: exact host/path policy, optional offline content-addressed cache, optional `.sha256` comparison. `intelligence/storage.py` and `kbcorrelation/store.py`: immutable raw objects and derived facts/revisions. | `discovery.py` explicitly does **not** check OpenPGP; authenticity states describe transport/hash checks. Add cryptographic receipts only after defining trust roots and failure semantics. |
| Native MSRC | `sources/cvrf_msrc.py`, `index.py`, `card_provenance.py` retain source positions, product-scoped remediation and conflicts. Main includes `3bd48a7`, `9ae5731`, `6f92375`, `d03a7d4`, `d99cd77`: missing-field parent pointers, consensus/provenance and ambiguous native/mixed revision quarantine. | Earlier R4 claims that only synthetic CVRF exists are obsolete. Native XML support and general source authenticity remain separate acceptance questions. Never replace unavailable revision order with digest order. |
| File identity | `csaf/identity.py` already uses verified handles, bounded VS_FIXEDFILEINFO parsing, and CodeView name/GUID/age. `pe_overview` provides static headers/directories; `symbols/{pdbid,staging}.py` and staging tests already reject mismatched GUID/age. `tools/calibration/tier_w/symbols_llvm.py` already compares LLVM symbols. | Extend resource-string parity and independent LLVM GUID/age checks at these existing seams. The LLVM symbol adapter currently takes identity from the local `msf.read_identity`, so its symbol comparison does not independently validate that identity. |
| Investigation workflow | PR #176 adds offline desktop investigation, saved-scope propagation, architecture contradiction checks and captured-revision/acquisition-plan binding. | Coordinate with that branch; do not start another investigation service or independently rewrite its attachment/preview contracts. |

Internal evidence: [module index](../../modules.md), [advisory identity specification](../../specs/kb/advisory-revision-and-snapshot-identity-spec.md), [current CVRF contract](../../specs/kb-cve/31-B-msrc-reverse-index.md), [PE metadata specification](../../specs/pe-version-authenticode.md), and the MSRC reviews under `docs/qa/msrc-*20261102*`. The old identity specification is a design/history document; its open-defect statements must be checked against current code before becoming tasks. PR #130's R4 research was inspected at `ff570bdd784d02f745e4ad21d8aa7b4f1f776344`; retain its source/servicing analysis while correcting its stale parser inventory.

## 2. Reusable implementations and verified license pins

These are observed source snapshots, not claims that HEAD is a release or that a package was installed. License evidence was read in cloned files, not inferred from a catalog badge. No transitive-dependency license audit was performed.

| Candidate / observed identity | License proof | Reuse mode and concrete value |
| --- | --- | --- |
| **Secvisogram validator**, `6b03f603653fe0be05152805d7c8f01bb6ebffde`; `package.json` 3.0.1 | [Pinned LICENSE][S3] and package metadata: **Apache-2.0**; LICENSE SHA-256 `d50c013501db52a8bf72243b2dcdac4eff7f05c0cede073f706e922e4c8a34fb` | **Adopt for development**: run a fixed CSAF 2.0 schema/mandatory test set on synthetic or permitted fixtures with outbound network denied; compare findings with PatchTrace's declared subset. No Node runtime requirement in the desktop. |
| **gocsaf**, `2c2095b7ce531db080d95f6d45c2dcf98c7e0eb7`; module `/v3`; exact release unknown | [Pinned license][S5], `3rdpartylicenses.md`, schema headers: **Apache-2.0** for project code | **Adapt/reference** its discovery, hash/signature, incremental download and checker behaviors for an external staging experiment. Retain PatchTrace's consent and import boundary. |
| **CSAF Perl Toolkit**, CPAN distribution **0.26**; commit unknown | [Distribution LICENSE][S8]: **Artistic-2.0**; module POD also says Perl terms, so review file-level discrepancies before copying code | **Reference** mandatory-test logic and downloader cases as an independent implementation; no reason to ship Perl. Source and release artifact are available through MetaCPAN/CPAN, outside GitHub. |
| **packageurl-python**, `c7c7b46346eebcd86ec61d4ee7c6a84c3fe5fcc4`; setup.cfg 0.17.6 | [Pinned `mit.LICENSE`][S11]: **MIT**; SHA-256 `8e442c79545ac0c0a1a2cf0cf213312a45826acd6cdc6af223447dd5f708ee5d` | **Adopt when needed** for explicit package-URL parsing/normalization; preserve raw input and qualifiers. Do not invent PURLs for Windows binaries. |
| **CVE schema**, `ce5f5c865f14dc40a6548d36b74751abca1c588a`; schema default 5.2.0 | [Pinned LICENSE.txt][S13]: **CC0-1.0**, source schema separately inspectable | **Adopt schema/reference** for a future local CVE-record adapter. Pin schema bytes and distinguish CNA/ADP containers. This license concerns the schema, not every imported advisory. |
| **pefile**, `e829dd9e51240b4b264118553a38f4d38c811c07`; `__version__` 2024.8.26 | [Pinned LICENSE][S16]: **MIT**; SHA-256 `b44409c067c6da52bfb54bb6624fb11a7b52157c3a13ae1400232f8196e86ad3` | **Adopt for development/reference**: resource/debug-directory comparison using selected directories. Preserve current bounded production parser unless a measured gap warrants an adapter. |
| **LLVM llvm-pdbutil / PDB reader**; version/commit unpinned in this investigation | [LLVM LICENSE][S18]: **Apache-2.0 WITH LLVM-exception** | **Reference/development tool**: local PDB summary and GUID/age comparison. Pin a released executable before accepting output; do not add the entire toolchain to the desktop for one identity field. |
| **python-tuf**, `ec01d81644a64540b1f61d3255eef178a3665f26`; `tuf.__version__` 7.0.1 | [Pinned LICENSE and LICENSE-MIT][S22]: **Apache-2.0 OR MIT** | **Defer runtime adoption** until PatchTrace distributes its own maintained update/rule/advisory bundle repository. Stronger fit there than retrofitting authenticity onto unsigned vendor content. |
| **LIEF core**, `9b4bf9617d5a8661cbac3b2420c3d3f778ac22da` | [Pinned core LICENSE][S25]: **Apache-2.0** | **Reference** for extended static PE coverage. **Defer Extended PDB integration**: separately gated packages and nonpublic changes require their own availability, redistribution and reproducibility review. |

**License drift discovered:** the current Secvisogram source is Apache-2.0, although the OASIS tools catalog still labels the library MIT. Its README/search snapshots are also older than the cloned implementation. Pin source files and lockfiles; do not propagate a stale license label. The clone's OASIS submodule pointer is `29b1e27aa126b820cbd6eee1830ca27ef02793d1`; it was not initialized or executed. [S3], [S4]

## 3. Validation reuse without changing advisory meaning

CSAF **2.0 is an OASIS Standard dated 2022-11-18**. The current 2.1 latest-stage URL resolves to **Committee Specification Draft 04, 2026-10-21**. A moving latest-stage URL is unsuitable as a validation identity: record version, fixed stage URI, schema SHA-256 and validator commit. Support 2.1 only through an explicit future dialect contract, not a permissive fallback. [S1], [S2]

The Secvisogram source exposes strict validation, individual tests, basic/extended/full presets and separate experimental 2.1 support. Its error/warning/info separation matters: optional warnings do not necessarily make `isValid` false. Use a fixed 2.0 schema/mandatory test list; compare stable test IDs and normalized source pointers rather than rendered messages. Do not substitute the full preset: `full.js` exports informative tests, and `lib/informativeTests/shared/testURL.js` calls `fetch` on advisory-contained URLs, including tests 6.3.6/6.3.7. Deny outbound network and fail the oracle run on any unexpected request. Keep PatchTrace's pre-parser limits, duplicate-key refusal and cancellation checks even if a third-party validator accepts the JSON. [S4], [S32]

**Proposed experiment:** build a small checked-in synthetic conformance corpus covering each implemented mandatory test and each openly missing one, plus group cycles, contradictory product statuses, revision history, invalid PURLs and malformed Unicode. Run the pinned external validator offline in development; report `agree`, `PatchTrace-declared-unsupported`, or `unexpected-disagreement`. An unsupported test is visible coverage, not a false pass. Resolve disagreements against the fixed standard and test intent; do not automatically treat either implementation as truth.

The Perl distribution supplies `CSAF::Validator::MandatoryTests` with numbered routines and distinct downloader/ROLIE modules. This is useful implementation diversity. Its downloader source allows HTTP and configurable TLS relaxation, derives local paths from remote URLs, and checks sidecars when present; those defaults are not PatchTrace's import policy. Reference the cases, not the transport wholesale. Its release page has inconsistent year displays, so this note pins **0.26**, not an inferred publication date. [S7], [S9], [S10]

CVRF is a separate issue. OASIS CVRF 1.2 provides XML schemas/namespaces; Microsoft's native JSON projection is not proven valid merely by validating a converted XML document or a CSAF translation. Keep `msrc-cvrf-json/1` as an observed adapter contract, retain original positions, and test absent/unknown native fields. Microsoft's current published OpenAPI still documents monthly CVRF and update-summary retrieval, including current/initial release date filtering. Do not copy the older research's exact path count: today's OpenAPI includes metadata routes absent from that description. [S14], [S15]

## 4. Product/build identity and source revision ambiguity

Package URL and CPE solve different identity problems. `packageurl-python` supplies parsers/builders with type-specific normalization and qualifier handling; CPE 2.3 describes product **classes**, not an exact installed file. Keep a vendor ProductID, Windows release/edition/architecture/build tuple, package URL, CPE and artifact SHA-256 in separate typed fields. A normalized string match can propose an association; it does not prove the binary's product lineage. [S11], [S12]

**Adaptation seam:** attach optional raw/canonical package identifiers to an existing product assertion with source document and pointer. Cache parsed results by `(raw-value-digest, parser-version, normalization-policy)`. Unknown or contradictory architecture stays unknown/contradictory; avoid generic fuzzy matching. A PURL qualifier such as architecture or distribution must survive normalization. Add round-trip cases with escaped namespace characters, qualifier order, missing version and unsupported type; cross-check the library's fixtures before extending the product catalog.

OSV 1.9.2 describes open-source package vulnerabilities using ecosystem/name/PURL and explicit ranges or versions. It is useful for identified third-party packages and future dependency context. It is not a general replacement for MSRC's Windows ProductID→remediation/FixedBuild relationship. Mapping a file-version string to an OSV package version is an inference requiring explicit package identity. Preserve `aliases`, `upstream`, `related`, withdrawn state and source attribution instead of treating repeated CVE aliases as independent confirmation. [S19]

For CVE-record imports, pin the 5.2.0 schema and preserve provider containers, version type, default status and inclusive/exclusive bounds. Do not normalize away separate CNA and ADP assertions. The schema's CC0 status does not answer the terms for every upstream record or linked document. R4 already discusses this adapter; the additional contribution here is a verified source/license pin and a validation experiment, not a second competing ingestion architecture. [S13]

Main now deliberately quarantines native monthly snapshots with missing comparable timestamps or tied distinct latest timestamps; mixed-format edge disagreement is also retained. **Do not undo this by adopting a downloader's newest-file heuristic.** Same bytes at another retrieval time are the same raw evidence, while two different bodies with the same upstream revision are a conflict. Preserve all bodies, attempts, raw revision labels and partial ordering; do not fabricate chronology. This recommendation follows the actual `index.py` behavior, not an assumption about MSRC numbering.

The documented Graph beta `FindByKbNumber` remains an optional research path from R4: authenticated `WindowsUpdates.Read.All`, Int32 KB argument, product-revision results, and no production support promise for beta. The public documentation was rechecked; no tenant call occurred. Its product build can provide vendor metadata but does not establish package membership or exact file identity. Defer this adapter behind existing offline completion and source acceptance. [S20]

## 5. Offline import: separate reproducibility, authenticity and freshness

The useful new seam is a receipt alongside existing immutable objects. Proposed receipt fields: raw hash/length; source URI and final URI; media/encoding; upstream tracking ID/version/dates; retrieval attempt identity; parser/schema/policy digests; validation coverage; signature bytes/hash; verifier identity; accepted key fingerprint and trust-policy digest; verification result/time; import origin and coverage scope. Preserve both compressed transfer identity and decoded advisory identity when both exist. Store verification as an append-only observation, not a rewrite of source truth.

gocsaf supplies a concrete downloader/checker implementation with signature handling, provider metadata and incremental time ranges. Its `trusted_only` behavior and configurable signature/validation options demonstrate why a directory of downloaded files is insufficient evidence by itself: the invocation policy is part of the result. Use an external staging experiment to produce files plus a receipt, then import through PatchTrace's bounded parser. Its own source identifies separate third-party/schema licenses. [S5], [S6]

**Acceptance experiment:** import the same advisory online-origin and removable-media-origin, then compare raw/source identity and keep distinct acquisition/verification receipts. Exercise missing signature, malformed signature, valid signature from an unaccepted key, altered body, stale signature, unavailable key, conflicting same-revision bytes, cache corruption and interrupted commit. A failure must retain the previous current view and the rejected attempt. Verify zero network during replay with an opener that fails on every call; a filesystem path named after a provider must never grant vendor authenticity.

Microsoft's public security.txt still points to CSAF provider metadata and an OpenPGP key URL, but declares expiry **2026-09-23**. The metadata endpoint was inaccessible through the research browser. This verifies the pointer, not current provider content, signature availability or accepted signing identity. The `Encryption:` label alone is not proof that the key signs advisories. Keep live MSRC signature acceptance **unknown/blocked**, and check it with the existing explicit request/consent mechanism before changing authenticity labels. [S21]

TUF 1.0.37 provides roles, thresholds, version/expiry checks and coherent signed metadata; python-tuf's `ngclient` offers a client and a fetcher seam. It fits **PatchTrace-owned distribution**, where someone operates keys and signs target metadata. A PatchTrace signature on a mirrored MSRC document attests that PatchTrace distributed those bytes, not that Microsoft signed them. Offline historical replay also needs a visible distinction between valid-at-capture and fresh-now; never disable expiry globally to make replay appear current. [S22], [S23]

in-toto records intended supply-chain steps, actors and order. It may later attest a normalization or bundle-build pipeline, but does not resolve truth of an advisory or a Windows product mapping. Defer it here; first make the existing raw/facts/receipt chain replayable and bounded. Build/release attestations belong with the separate corpus/build research. [S24]

## 6. Static PE/PDB checks and non-GitHub implementation evidence

Use `pefile` as a development comparator for selected debug/resource directories. The current source exposes fast loading, explicit directory parsing, version-information parsing and RSDS/older CodeView handling. Compare numeric file/product versions, architecture, GUID/age and malformed-input outcomes against PatchTrace; preserve the verified input hash and parser version in the report. Do not execute a file to read its version, import target code or promote a filename string to an identity fact. [S16]

Microsoft's symbol API uses the CodeView PDB signature and age to locate a PDB; LLVM documents corresponding GUID/age in the PDB info stream and provides `llvm-pdbutil` for static inspection. Main already handles identity in `symbols/pdbid.py`, including DBI age, and `tests/test_symbols_staging.py::test_decoy_pdb_is_not_staged` covers `guid_mismatch` and `age_mismatch`. Preserve those regressions. `tests/test_tier_w_symbols.py` also compares function name/RVA/size against LLVM, but the adapter takes identity from `msf.read_identity`. The narrower remaining experiment independently parses LLVM's GUID/age and checks the existing identity reader against it. Separate PDB format/producer differences and absent debug data from malformed data. Do not require every metadata field to be available in every supplied PDB. [S17], [S31]

LIEF's ordinary PE parser and Extended PDB features must not be conflated. Its current Extended documentation describes OAuth-gated downloads, versions based on main plus internal changes, and LLVM-backed PDB support. Core Apache-2.0 evidence does not license an unexamined Extended artifact. Prefer the existing minimal reader plus pinned open LLVM tooling for this seam; measure LIEF only if future static format coverage justifies its packaging cost. [S25], [S26]

**Sourceware is a substantive additional reference:** GNU Binutils' official `objdump` documentation supplies static file/private-header inspection and explicitly lists no-follow-links and no-debuginfod controls. A development comparison should select metadata-only output and disable external debug retrieval. This can independently check section/header interpretations; it cannot prove Authenticode trust or replace a PDB identity check. Current source/commit/license was not successfully retrieved here, so no code-copy or bundling recommendation is made. Sourceware publishes source access and releases; its official historical PDB patch carries GPL-3.0-or-later notices, which are evidence about that patch, not a current whole-distribution audit. Process separation is not a license exemption. [S27], [S28]

**Heptapod candidate disposition:** OASIS links Intevation's provider-index implementation there, describing a listing/submission service and Apache-2.0. Direct source inspection hit an Anubis denial; version, commit and actual license file remain unverified. Defer reuse. A provider listing would be a discovery hint requiring publisher verification, never an automatic trust root. This avoids quietly substituting a catalog listing for inspected source. [S29]

Authenticode remains a distinct Windows policy check. Microsoft's `WinVerifyTrust` succeeds only when its LONG return equals zero; a certificate table or portable parser's successful PKCS#7 parse is not that policy result. Keep existing Windows trust acceptance, revocation/network mode and environment provenance visible. [S30]

## 7. Concrete Claude work cards

1. **META-01, validation coverage, first:** specify a dev-only oracle format and pin Secvisogram source/schema/test preset. Build synthetic cases for supported and declared unsupported tests; pass when all disagreements are explained and no unsupported test is represented as validated. Keep Node outside frozen runtime. Estimated bounded slice: fixture manifest, runner, report and documentation.
2. **META-02, receipt design before crypto:** extend the existing advisory-source/store contract additively with verification observations and trust-policy identity. Round-trip raw objects plus receipts offline; demonstrate same raw identity across retrievals and different verification observations without rewriting history. Do not change active-revision selection.
3. **META-03, MSRC authenticity probe:** through an approved exact-host plan, inspect provider metadata, one advisory and sidecars, key fingerprint, revocation/expiry and advertised roles. Publish passed/failed/blocked with raw digests. Until a valid signature is bound to an accepted publisher key, retain existing transport-only states.
4. **META-04, optional package identity:** use packageurl-python only when a source explicitly supplies a package URL. Preserve raw/canonical forms, product pointer and qualifiers; no Windows-name-to-PURL generator. Validate unknown type and conflicting architecture cases before using identifiers for joins.
5. **META-05, extend PE/PDB comparison:** extend the existing staging regressions and Tier W LLVM symbol comparator with independently parsed LLVM GUID/age and selected pefile metadata parity on a small licensed/synthetic local corpus. Capture metadata differences, rejection reasons, time/memory and no-network evidence. Ship no new parser until this shows a concrete production gap.
6. **META-06, continuity gate:** rebase task assumptions on current main and PR #176 before implementation. Retain its scope/CAS/architecture safeguards and existing MSRC ambiguity tests. A metadata enhancement must leave an independently replayable source trail; no implied CVE-to-file/function proof.

Software licenses, vendor API/data terms, schema notices and redistributed fixture terms require separate entries. Microsoft's sample repository being MIT does not grant a blanket license for all API content; the current API data terms were not established in this investigation. Prefer synthetic fixtures or local acquisition with hash-only published provenance until redistribution rights are confirmed. [S15]

## Primary sources and inspection record

All web references below were consulted 2026-11-04; pinned GitHub source files were read from shallow local clones where web blob rendering failed. This is source inspection, not a build/test result.

[S1]: https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html
[S2]: https://docs.oasis-open.org/csaf/csaf/v2.1/csd04/csaf-v2.1-csd04.html
[S3]: https://github.com/secvisogram/csaf-validator-lib/blob/6b03f603653fe0be05152805d7c8f01bb6ebffde/LICENSE
[S4]: https://github.com/secvisogram/csaf-validator-lib/blob/6b03f603653fe0be05152805d7c8f01bb6ebffde/README.md
[S5]: https://github.com/gocsaf/csaf/blob/2c2095b7ce531db080d95f6d45c2dcf98c7e0eb7/LICENSE-Apache-2.0.txt
[S6]: https://github.com/gocsaf/csaf/blob/2c2095b7ce531db080d95f6d45c2dcf98c7e0eb7/docs/csaf_downloader.md
[S7]: https://metacpan.org/release/GDT/CSAF-0.26
[S8]: https://metacpan.org/release/GDT/CSAF-0.26/source/LICENSE
[S9]: https://metacpan.org/release/GDT/CSAF-0.26/source/lib/CSAF/Validator/MandatoryTests.pm
[S10]: https://metacpan.org/release/GDT/CSAF-0.26/source/lib/CSAF/Downloader.pm
[S11]: https://github.com/package-url/packageurl-python/tree/c7c7b46346eebcd86ec61d4ee7c6a84c3fe5fcc4
[S12]: https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe
[S13]: https://github.com/CVEProject/cve-schema/tree/ce5f5c865f14dc40a6548d36b74751abca1c588a
[S14]: https://docs.oasis-open.org/csaf/csaf-cvrf/v1.2/csaf-cvrf-v1.2.html
[S15]: https://api.msrc.microsoft.com/cvrf/v3.0/swagger/v3/swagger.json
[S16]: https://github.com/erocarrera/pefile/tree/e829dd9e51240b4b264118553a38f4d38c811c07
[S17]: https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symfindfileinpath
[S18]: https://llvm.org/LICENSE.txt
[S19]: https://ossf.github.io/osv-schema/
[S20]: https://learn.microsoft.com/en-us/graph/api/windowsupdates-product-findbykbnumber?view=graph-rest-beta
[S21]: https://www.microsoft.com/.well-known/security.txt
[S22]: https://github.com/theupdateframework/python-tuf/tree/ec01d81644a64540b1f61d3255eef178a3665f26
[S23]: https://theupdateframework.github.io/specification/latest/
[S24]: https://in-toto.io/docs/what-is-in-toto/
[S25]: https://github.com/lief-project/LIEF/blob/9b4bf9617d5a8661cbac3b2420c3d3f778ac22da/LICENSE
[S26]: https://lief.re/doc/latest/extended/intro.html
[S27]: https://sourceware.org/binutils/docs/binutils/objdump.html
[S28]: https://sourceware.org/pipermail/binutils/2022-October/123465.html
[S29]: https://www.csaf.io/tools/
[S30]: https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust
[S31]: https://llvm.org/docs/PDB/PdbStream.html
[S32]: https://github.com/secvisogram/csaf-validator-lib/blob/6b03f603653fe0be05152805d7c8f01bb6ebffde/lib/informativeTests/shared/testURL.js

Additional primary checks: [llvm-pdbutil command reference](https://llvm.org/docs/CommandGuide/llvm-pdbutil.html), [LLVM license](https://llvm.org/LICENSE.txt), [python-tuf fetcher seam](https://theupdateframework.readthedocs.io/en/stable/api/tuf.ngclient.html), [Sourceware Binutils source/release access](https://www.sourceware.org/binutils/), [Heptapod source attempted](https://heptapod.host/intevation/csaf-provider-index), [MSRC API sample source](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API). Codeberg discovery returned a robots denial; Salsa pefile source and Sourceware current source views were inaccessible. These access failures are not evidence that implementations are absent.
