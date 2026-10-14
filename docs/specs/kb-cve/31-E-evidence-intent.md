# SPEC-31-E: Correlation Evidence Graph, Patch-Intent Rules, Confounders and Calibration

Status: developer-ready plan; optional full semantic mechanisms depend on SPEC-28/30. Parent [SPEC-31](../kb-cve-correlation-and-acquisition.md). Requires 31-A/B/C and validated PatchTrace run. Owner: correlation worker.

## E1. Two independent deliverables

E0 is available immediately: attach product-specific KB/CVE provenance to an existing project's verified pair, reuse current enrichment.cve and enrichment.pipeline contextual ranking and show documentary links, source pointers, limitations and candidate changed functions. It can display results without additional evidence engines.

E1 extends E0 only when SPEC-28 (CSAF validation/CWE rules) and SPEC-30 (patch intent localization) are installed, tested and declared capable. Do not import nonexistent src/patchtrace/intelligence modules on module import. Optional dependency returns UNSUPPORTED_FEATURE, not runtime failure. Never pretend CVE association is established by a successful Ghidriff score or by the existence of a KB.

## E2. Evidence ontology and references

Nodes: VendorSource, AdvisoryRevision, ProductScope, RemediationLink, KBUpdateInstance, CVE, CWE, BinaryArtifact, BinaryPair, Function, BasicBlock, Instruction, FunctionMatch, Capability, String, RuleHypothesis, AnalystDecision.
Edges: asserts, applies_to, remediates, references, same_bytes_as, built_from, matches, changed_between, contains, flows_to, guards, corroborates, contradicts, derived_from. Every edge records raw evidence id, lineage group, source category and lifecycle state.

Exact code reference:
(project_uuid, project_revision, analysis_run_uuid, older_sha, newer_sha, side, engine_id, engine_version, function_record_id, RVA?, block_id?, instruction_addr?, line_range?, raw_evidence_digest).
RVA is artifact-local; absolute addresses from two engines cannot be joined without module base/section mapping and orientation. A shared function name never proves equality. Reject stale run hash or contested match for any automated higher-strength claim.

JSON source reference: (doc_id, doc_sha, parser_version, JSON pointer / CSV row / structured product id). JSON pointer must be RFC-6901 escaped, validated within the corresponding raw document and bounded in length. An observed additional error string, import or API name is an anchor, not data-flow evidence.

Lineage_group groups results derived from a common upstream Ghidra decompilation or same advisory/revision. Do not count Ghidriff, BinDiff and rz-diff as three independent proofs without verifying independent observations; some may share the same BinExport/Ghidra output. Deduplicate identical bytes, strings and function-level evidence by specific underlying observation.

## E3. Explicit gates and bands

Documentary: vendor-remediation / vendor-association / mention-only / disputed / unknown.
Applicability: exact-verified / candidate / unknown / not-applicable / disputed.
Binary-integrity: final-shas-verified / pending / mismatched / incompatible.
Function-identity: corroborated / single-engine / contested / unassessed.
Mechanism: strong / moderate / tentative / unexplained / contested.
Vulnerability-verification: not-evaluated / analyst-verified-with-method / disproven-for-tested-case / indeterminate. Default always not-evaluated.

Gate table:
- Product not-applicable => refuse CVE-specific attribution for this product. Documentary facts remain visible.
- Pair identity missing or incompatible => show advisory only, no code attribution.
- Pair compatible but wide/confounded update window => allow triage ranking, cap automatic mechanism assessment at tentative unless independent localization evidence isolates the target change.
- Function match contested => review-needed, cannot auto-upgrade.
- Independent verified source-to-sink guard relationship with counterpart old/new and matching CWE rule => eligible strong mechanism support, but still not "vulnerability verified".
- CWE absent or no corresponding relevant observations => unexplained, not contradicted.

No global numeric CVE confidence percentages. User-supplied assertions cannot produce vendor verification. Multiple CVEs can point to one function and one CVE can point to many; retain separate assessments and unattributed changed-function queue.

## E4. Rules as versioned data (no arbitrary code execution)

Ruleset schema: id, rev, CWE IDs, product scope, expected change predicates, supportive evidence classes, negative/alternative observations, required evidence combinations, unacceptable confounders, known blind spots, explanation template.
Predicates must be compiled from reviewed declarative vocabulary and bounded to a safe grammar; no exec/eval/dynamic Python expressions/LLM-provided rules. Version/rulepack SHA part of every outcome.

Mechanism families:
- Bounds read/write (CWE-125/787): changed check of index/size before read/store with register/value flow and control dependency; a new comparison instruction alone is tentative.
- Integer overflow/underflow (CWE-190/191): check arithmetic width/range and propagation into allocation/copy; changes in constants alone weak.
- Use-after-free (CWE-416): object lifetime/refcount/release and later use, alias limitations; lock or log changes not proof.
- Authentication/authorization (CWE-287/862): changed trust decision gating sensitive call; new error text alone anchor.
- Traversal/path (CWE-22/73): canonicalization plus check constraining file sink; importing a path API alone weak.
- Race/reentrancy: ordering/synchronization with proven shared state, lock operations context; lock name only tentative.

Rules must express positive observations, counterobservations and competing hypotheses. Pure rule output retains exact evidence links and a human-readable sentence explaining which obligations are met, unknown or contradicted. Neither text matching nor LLM narration can upgrade evidence strength.

## E5. Worked synthetic ranking

CVE-2099-10001 is marked CWE-787 for Client Release A, KB5000001, target driver exampledrv.sys. Both final PEs hash match, source-backed consecutive builds 100 and 101.

Function F001: added branch that checks (index < length) and branches around a copied-byte store; verified old/new CFG dataflow from same object and changed instruction evidence, no contested mapping => mechanism strong *if* source-to-sink proof is actually satisfied; vulnerability verification remains not-evaluated.
Function F002: newly added 'invalid length' string and import, no changed memory guard => tentative anchor only.
Function F003: changed compiler-prologue instruction but no source/sink relationship, correlated with toolchain churn => unexplained/noise candidate, still visible.
Function F004: matched differently by BinDiff vs Ghidriff => contested, no auto-promote.
If target KB simultaneously remediates CVE-2099-10002, all functions retain separate potential target links, and no automatic allocation assigns F001 exclusively to CVE-2099-10001.

## E6. Ranking and counterfactual integrity

Implement deterministic stable ordinal sorting by (verified-product, valid-pair, mechanism-specific evidence, matched structural evidence, vendor component hints, lower confounder count, stable function ID), but treat this as triage order, not vulnerability likelihood. Never add native engine percentage scores or count multiple rows copied from one underlying source as extra votes. Always keep an unmatched/unclassified queue.

Alternative hypotheses include code optimizer churn, debug/symbol changes, unrelated fixes in same cumulative update, compiler/library version changes, localized error handling without security fix, non-vulnerable code path and product-scope mismatch. Missing evidence = unknown, only directly conflicting evidence counts as contradiction. Any counterfactual claim must refer to a verified build window, not guessed chronology.

## E7. Export, cache, staleness

Store output keyed by input tuple (project ID/rev, old/new SHA, run ID, match-override revision, product_scope_id, KB/CVE edge-set digest, advisory SHA, rules SHA, engine/version/settings, source-coverage digest). An advisory or build lineage revision invalidates derived assessments; immutable raw runs and analyst notes persist. Persist transformed reports with source id plus JSON pointer and code location; default reports exclude raw binary, code and local paths. No user source is transmitted to remote AI without existing separate preview/consent and explicit user action. E0 can reuse existing report export extension; E1 may append optional PILOT/1 section, never replacing original Finding.

## E8. Calibration and negative test requirements

Golden negative fixtures: CWE text says 'not affected'; source contains generic 'memory' terms; introduced log string; tool disagreement; NVD-only CVE; wrong-product KB; Ghidra shared lineage; absent capa rule; blank function code; compiler-only rebuild; intervening nonsecurity LCU; missing signature; stale project revision. Outcomes must not become strong or claim vulnerability verified.

Evaluation requires labeled ground truth for (a) true same-function identity, (b) which functions actually contain the relevant patch, (c) block match correctness, (d) mechanism support and (e) real security verification. Split holdout by product/build family; compare Ghidriff baseline vs KB documentary context, SPEC-28 rules and optional engines. Report precision@K, recall, false leads, abstention rate, runtime and independent confidence intervals. Reuse SPEC-30 adoption gate (>=20% fewer false leads at nondecreasing recall under supported statistics); otherwise ship ordinal context only.

Implementation boundary: kbcorrelation/correlate.py is a thin facade/adapter, not a second structural matching engine. Connect through available enrichment and secondary/evidence facades after checking real signatures in current code.
