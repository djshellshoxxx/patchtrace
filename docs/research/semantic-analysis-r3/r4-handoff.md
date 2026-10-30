# R4 handoff — vulnerability-to-build-to-binary correlation, not semantic conjecture

**Date:** 2026-10-30. **R3 state:** research checkpoint with static experiments and one focused proof-contract fix proposed in this PR; **no full R3 statistical acceptance claim**. R4 research may proceed on separate, disjoint documentation/ingestion ownership, but it must not depend on an unverified assertion that all L2 benign classifications are correct.

## 1. The evidence chain to be constructed

The product objective is **CVE ↔ KB ↔ product/edition/build ↔ binary file/version/hash ↔ older/newer pair ↔ function delta ↔ analyst hypothesis**. Each link is independently provenance-checked, may be one-to-many or unknown, and must never be invented by a language model:

1. **Advisory/CVE**: authoritative publisher identifier and published version of the document, date, revision, product/build applicability and mitigations; separate NVD/CISA metadata from the vendor's own advisory.
2. **KB/update**: verified Microsoft MSRC update entry and KB applicability for the exact operating system branch, architecture, product channel and update type; track supersedence and cumulative updates, including checkpoint prerequisites.
3. **Binary identity**: exact filename and SHA-256, PE machine/header, image version and optional PDB signature, path/package membership and source provenance; a similar filename alone is never enough.
4. **Acquisition**: Winbindex index metadata, Microsoft public symbol server source, expected hashes/sizes, HTTP provenance and explicit user consent. Quarantine first; never execute downloaded binaries. Verify exact size/hash and promote only supported AMD64 PE through the ordinary ingestion path.
5. **Pairing**: explicitly ordered older and newer binary identities; equal product/build/channel/architecture and validated lineages, not just numeric file version. Preserve missing/ambiguous candidate states.
6. **Correspondence (L1)**: selected older/newer functions, tier and independent evidence components, alternatives/conflicts, one-sided cases. An L1 match is not a semantic proof.
7. **Change classification (L2)**: actual `ChangeFacts` with `UNCH/1`, structural cosmetic, decompiler-relative cosmetic, material, review or unknown; include changed operands, target mapping, EH, caps, missing channels, proof implementation version and provenance.
8. **Vulnerability hypothesis**: analyst-reviewed description of how the changed logic *might* address the advisory. No automatic claim that a given function is vulnerable, that a patch is exploitable or that a changed threshold is a CVE fix.

A KB can address multiple CVEs; a CVE can affect several builds and binaries; cumulative updates can include unrelated changes. Therefore the graph is **many-to-many** with typed relationships and provenance, not a chain of forced one-to-one joins.

## 2. Available product foundation — reuse instead of rebuild

- PatchTrace already has `enrichment/cve.py`, `enrichment/intelligence.py`, `acquisition/`, `docs/research/kbcve/msrc-sources.md`, `docs/research/kbcve/winbindex-servicing-catalog.md` and existing SPEC-31 KB/CVE research.
- The R3 scope is specifically `unified/facts/`, `unified/ir/`, and the derived unified result, not a replacement MSRC or Winbindex service.
- Keep existing `enrichment/1`, `unified-result/1` and project/store ownership and do not silently modify Ghidriff raw outputs. Schema changes must be spec-first and additive with versioned reader compatibility.
- Advisory text, decompiler labels, CVE descriptions, PE metadata and downloaded content are untrusted inputs. Network off by default, source-preview/consent, bounded fetches, no credential persistence or target execution.

## 3. Primary source and caution ledger

| Source | Primary material | Supports | Doesn't prove |
|---|---|---|---|
| Microsoft MSRC Security Update Guide / API | https://msrc.microsoft.com/update-guide ; https://api.msrc.microsoft.com/ | Vendor product/KB/CVE applicability where available | A specific changed instruction caused a CVE fix |
| Microsoft Windows servicing-stack & cumulative-update guidance | https://learn.microsoft.com/en-us/windows/deployment/update/servicing-stack-updates | Combined SSUs, LCUs and supersedence/cumulative semantics | That every KB delivers a changed copy of a given file |
| Microsoft checkpoint cumulative updates | https://learn.microsoft.com/en-us/windows/deployment/update/catalog-checkpoint-cumulative-updates | Windows 11 24H2+ and Server 2025+ checkpoint prerequisites | Arbitrary binary-version monotonicity |
| Winbindex maintainer | https://github.com/m417z/winbindex/blob/main/README.md | Indexed Windows binary metadata, download links to Microsoft symbol server | Official Microsoft authenticity merely by index presence; verify hash/size and source |
| NVD developer APIs | https://nvd.nist.gov/developers | Supplemental CVE/CPE configurations, descriptions, references | Conclusive KB→file→binary relation; beware CPE granularity |
| CISA KEV catalog | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | CISA-reported known exploited CVEs, external enrichment | Causal identification of changed function or automatic proof of exploitability |
| PE/COFF format | https://learn.microsoft.com/en-us/windows/win32/debug/pe-format | Machine type, imports, relocations, exceptions, file identity cues | Definitive file-version→KB mapping without servicing evidence |

Source details and access permissions require live verification at R4 implementation time. Avoid inferring an undocumented download or API endpoint from a project README.

## 4. Acceptance properties for R4

- **No false join by appearance:** two different builds sharing the same `file_version`, filename or time stamp must not be merged when SHA-256 differs.
- **Provenance graph is auditable:** every CVE–KB/product–build–binary–pair link stores issuer, URL/source ID, observation time, schema/version, exact filters and state (`confirmed`, `candidate`, `conflicting`, `unknown`).
- **Negative applicability tests:** product family/version mismatch, different architecture, language variant, checkpoint chain, superseded update, wrong PDB GUID+age, candidate from a sibling OS channel, ambiguous MSRC/CPE record.
- **Many-to-many preserved:** no arbitrary “first CVE” selection, KB may patch multiple CVEs and binaries. Return all valid candidates with provenance.
- **Delta provenance retained:** L2 `material` is evidence of change under explicit observation, not a CVE assignment. `review` remains inspectable. Never hide change based only on similar C/decompiler text or equal raw bytes.
- **Deterministic offline replay:** cached signed/pinned snapshots and verified binary hashes permit deterministic reruns without network access. No silent later mutation to prior adjudicated data.
- **Human explanatory workflow:** show “CVE association confidence” separately from L1 match tier and L2 proof; distinguish verified relationship vs inferred relevance vs AI-written explanation.
- **Security:** strict JSON validation and source bounds, consented downloads, never execute binaries, sandbox child analyzers, separate local and remote operations.
- **Performance and false correlation:** precision/recall on an expert-adjudicated held-out build/advisory corpus; report unknown/abstain rates, and false-link rates by platform and KB lineage. No unsupported numerical scores.

## 5. Suggested R4 executable sequence

1. Refresh live `main`, open PRs, owners, instructions, R1/R2/R3 outcomes and current data schemas. Do not wait on this PR if independent source research can progress.
2. Add fixtures for a *known* MSRC advisory, a KB that supersedes another, an LCU/checkpoint update chain and a binary version observed under multiple builds. All facts must be attributed and time-stamped; if no legitimate case source can be verified use **synthetic fixtures** plainly labeled.
3. Build a read-only join-audit report first: CVE→product→KB coverage, confirmed vs missing endpoints, contradictions, and why a binary candidate is excluded. This prevents the UI from presenting a guessed chain as fact.
4. Reuse existing Winbindex acquisition and hash-verification code; extend only where a reproducible mismatch is demonstrated. No new unverified scraper or direct content download in standard offline mode.
5. Pair binary versions via full file identity and lineage, then present SPEC-31 unified change facts and side-by-side evidence. Preserve run history and failure isolation.
6. Evaluate on a locked corpus and report **false correlation** and **unknown** rates separately. Failing links never cause automatic “not vulnerable.”
7. Coordinate GUI additions with the current unified dock owner, update docs/QA and a draft PR, run Linux/Windows acceptance as required; merge only after source-integrity and review checks.

## 6. R3-to-R4 input contract / unresolved gates

Required R3 data: `old/new artifact SHA256`, `run_id`, `L1 row + evidence components`, `L2 verdict + proof/version`, changed instruction RVAs, `Delta.cls`, original operands and mapped targets, decompiler anchor and its source, exception state and `limits_hit`. Do not make R4 reject `review`; lack of proof is not lack of change.

R3 external gates before a “verified semantic fix” tag is permitted: G-U2 planted mutations on **linked PE**, pending moved-callee and SEH fixtures, exact-head Linux+Windows runs, independent reviewer adjudication, and a measured zero material→cosmetic/unchanged finding on the locked corpus. If unavailable, R4 can still show **candidate security-relevant deltas**, clearly marked as unverified.

The single most important R4 design decision: a secure patch-analysis application must present **observed code differences**, **advisory applicability** and **an analyst's causal hypothesis** as three distinguishable claims.
