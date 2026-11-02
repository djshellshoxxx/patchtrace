# Advisory card field attribution — 2026-11-02

Frozen source: `724fea224920625563982889f7e2fd6d928dc96b`, tree `5bd5ce176394c40010e14cfd1ad1617c7a12d93f`, base `6f923758efb57e3f19a43b5b1d2c1ba8319e1823`.

A fresh authored-fixture probe reproduced a pre-existing attribution error at the exact published base: the CVRF card stated CWE-125, but context paired it with a CSAF edge source and `/vulnerabilities/1/cwe`, which contained CWE-787 in that source and unrelated CWE-476 in the CVRF source. Both raw documents were retained by the earlier source-identity repair. CweProfile stores pointers, not a source ID; the wrong SHA entered the real CVEFact call, while the persisted error was its field/pointer/basis relationship. No live advisory or binary analysis was involved.

The repair derives exact, value-checked JSON field references from accepted unique CVE rows. ImportedDocument stores these internally and workspace reload reparses the retained bytes. ContextBundle adds optional default-empty `card_facts` with CVE, source kind, field, document ID, raw SHA, pointer and accepted normalized value. The selected card binds every agreeing contributor from its source-kind group, including card-only sources. Missing locators withhold fields; XML remains importable but supplies no fabricated JSON field locations. Existing edge-association eligibility remains unchanged.

The real interpreter constructs a separate CVEFact per contributing document, using its actual title and CWE locations, and unions agreeing output references without counting sources as votes. Non-CSAF explicit fields use additive `explicit-advisory-cwe`; CSAF defaults and evidence strength remain unchanged. Pilot's shared enum and wording/ranking mirrors accept the new value without raising rank. Source conflicts and saved investigation scope retain their prior behavior.

Context key policy advances from 2 to 3 because identical source bytes now produce different provenance and hypothesis identities. Wire bundle generation remains 1 under the additive optional-field convention. New readers still load old bundles without inventing references or rekeying them; strict older readers may reject newly emitted fields or the new enum value. All affected schemas were regenerated, including an explicit ContextBundle schema.

Validation:

- 804 focused tests passed in 16.17 seconds across field provenance, context, import/index/store/service, intelligence and pilot contracts/ranking.
- 188 additional intelligence-schema, pilot-advisory and KB-scope tests passed in 1.83 seconds.
- The final 17 new controls failed on the exact unchanged base, using a copied external test file to avoid pytest injecting the implementation worktree. The original direct test-path baseline attempt did resolve the implementation and is not counted as baseline evidence.
- Clean cherry-pick onto central `14b5568f84aeadc62a2f8043860ee78bb891bd2c` produced combined snapshot `a3ec52ec2aa88bbe3db79594e1f46516e8e11679`. Its 73 focused tests passed in 2.84 seconds. Two extra actual service/SQLite/attachment controls save files/cached scopes, import a newer unselected same-month card-only conflict and a February same-CVE document, reopen, and prove unchanged context/key/field references and selected-only raw copies.
- Selected-file Ruff, diff checks, and all three affected schema-generator checks passed.

The archive contains authored raw sources, the original actual ContextBundle, source-bound reproduction receipt, final baseline failure output and extra combined controls. The JSON sibling binds all changed source files and the combined snapshot. No full suite, Windows, live advisory, target execution or native analysis is claimed. Independent review was requested against the frozen source before this QA-only receipt.
