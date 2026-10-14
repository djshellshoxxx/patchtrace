# PIL integration plan: patch-intent localization (SPEC-30 a-d), CSAF remainders and the Leads panel

Program E research output, 2026-10-14, base `prep/program-e` d972125 (builders re-check the default branch SHA and open PRs first, CLAUDE.md). Documents only, no source edited. The tier and ordering rules of sections 5 and 7 were run in a throwaway prototype (not committed); the rank numbers in section 5 come from it. Labels: [src] read in a primary text or the code today, [own] measured by this worker, [unverified] not confirmable here.

## 1. Verdict and scope
- Build PIL as the **judgment layer** over evidence that already exists or is specified: K advisory facts, CWE profile, hypotheses and anchors; B1 signals; SPEC-31 `ChangeFacts`; T capa/FLOSS/DiE deltas; PE import and call deltas; secondary/unified pairing verdicts; KEV status.
- Output: explained, **ordinal, tie-aware leads per CVE**, shown in a Leads dock (the front door of the single window). With no advisory it still lists code-evidence leads.
- New pure package `src/patchtrace/pilot/` (contract `pilot/1`, errors `PT-PILOT-*`, reserved row kind `patch-intent`), `ui_leads.py`, CLI actions `intelligence leads|why|review`, dev-only evaluation `tools/calibration/pilot/`. K remainders ship first: `intelligence/{explain,reports,cli}.py`.
- Not built: any probability, percentage or confidence; automatic suppression; SPEC-30's 13-node provenance graph (a flat observation ledger with ids replaces it); the `strong` tier (reserved, unreachable until a typed dominance/dataflow channel exists); KEV or MSRC prose as function evidence; network, upload or target execution inside PIL; a second anchor store (FAB owns it); cross-hop series leads (W5, after N-way pair projects have results); live Microsoft acceptance (blocked).
- Biggest risk: the SPEC-30d adoption gate cannot be passed on the committed corpus (about 8 locked-test lineages against a 30-lineage minimum, section 9 D1).

## 2. Sources and facts
| Claim | Source (URL or repo path) | Retrieved | Conf. |
|---|---|---|---|
| KEV entry has 12 properties; required: cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate; optional: knownRansomwareCampaignUse, forensicTriage, notes, cwes (array, `^CWE-([0-9])+$`) | https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities_schema.json | 2026-10-14 | high |
| kev-data is CC0 ("licensed under the CC0 license"; LICENSE "CC0 1.0 Universal"), publishes JSON, CSV and the schema, is updated after catalog changes (weekdays, US Eastern) and kept in sync with cisa.gov | https://raw.githubusercontent.com/cisagov/kev-data/develop/README.md and /LICENSE | 2026-10-14 | high |
| Current catalog: catalogVersion 2026.10.13, count 1741, about 1.78 M characters; Microsoft entries carry `cwes` (e.g. CWE-77) | https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json | 2026-10-14 | medium (summariser-extracted; the KEV track re-measures) |
| cisa.gov, cwe.mitre.org, doc.qt.io, learn.microsoft.com, w3.org, docs.oasis-open.org and msrc.microsoft.com do not resolve from this sandbox (ENOTFOUND; K spec s.A also recorded CONNECT 403). KEV inclusion criteria and CWE mapping-usage guidance are therefore [unverified]; GitHub-hosted sources of the same documents were used | tool results | 2026-10-14 | high (negative) |
| CSAF 2.0 `threats[].category` enum is exploit_status, impact, target_set; Microsoft's prose inside `details` ("Exploited:Yes") is not specified by CSAF and the MSRC API README documents only CVRF, no exploit-status wording, so PIL shows that text verbatim and never parses it | docs/schemas/intelligence/oasis-csaf-2.0/csaf_json_schema.json:1378; https://raw.githubusercontent.com/microsoft/MSRC-Microsoft-Security-Updates-API/master/README.md | 2026-10-14 | high / medium |
| Qt: `tabifyDockWidget` needs both docks added with `addDockWidget` and neither already tabbed; `saveState` identifies docks by unique objectName; "Do not call restoreState() with data of unknown or untrusted origin"; `activated` is platform dependent (click, double click, Return/Enter) | https://raw.githubusercontent.com/qt/qtbase/dev/src/widgets/widgets/qmainwindow.cpp and /src/widgets/itemviews/qabstractitemview.cpp | 2026-10-14 | high (dev branch; PySide6 is pinned 6.12.0, re-check the tag) |
| Measured PySide6 6.12.0 facts reused: model-owned sort/filter (100k rows 32-40 ms), `data()` ceiling 7 x visible cells, unparented QThreads plus registry, tooltip rich-text escaping, status-label accessible-name rule | docs/research/phase-c/multi-engine-evidence-ui.md items 1-19 (qtbase source plus own runs) | 2026-10-14 | high |
| WCAG: 2.1.1 intent "content can be operated through a keyboard"; 2.4.7 "know which element has the keyboard focus"; 1.4.1, 1.4.3, 1.4.11, 4.1.3 as validated for C6 | https://raw.githubusercontent.com/w3c/wcag/main/understanding/20/keyboard.html and /focus-visible.html | 2026-10-14 | high (Understanding docs; SC text is not on those pages) |
| UI Automation "is an accessibility framework for Windows" used by screen readers; Name is the common name property | https://raw.githubusercontent.com/MicrosoftDocs/win32/docs/desktop-src/WinAuto/uiauto-uiautomationoverview.md (source of learn.microsoft.com/windows/win32/winauto/uiauto-uiautomationoverview) | 2026-10-14 | high |
| capa 9.4.0 and FLOSS 3.1.1 (Apache-2.0), diec 3.21 (MIT): capa attributes function and basic-block scope only; FLOSS static strings have no function, decoded strings attach to the decoder; DiE is a quality flag (`value_gate: unvalidated`). T runner, store, CLI, schema generator and provisioning are not built yet; built are `common`, `process`, the three parsers, `normalize` and `delta` | docs/specs/three-tool-evidence-adapters.md T1-T6; docs/modules.md "[T:core] build status" | 2026-10-14 | high |
| B1 never exceeds `moderate` ("strong confidence requires typed IR"), `typed_evidence` is always False; B3 already maps 14 CWEs to detectors (including CWE-680, absent from K) and adds up to +30 points to the 0-100 index | src/patchtrace/enrichment/signals.py:958-977; enrichment/cve.py:70-76,484-521 | 2026-10-14 | high |
| K has 20 families and 20 rules; `Rule.required_observations` and `contradictions` are prose ("not evaluated in 28b"); `IntelligenceReport` exists only as a contract and in the schema generator, no builder; FAMILIES lacks CWE-134 and CWE-193; `AdvisoryStore` is thread-confined | src/patchtrace/intelligence/{lexicon,hypotheses,contracts,storage}.py | 2026-10-14 | high |
| Corpus [own]: 23 `cve-fix` cards over 20 projects; declared changed functions per card 1 (14 cards), 2 (5), 4 (1), 5 (2), 9 (1); 11 authored `cwe-patterns` suites (CWE 787, 125, 190, 416, 415, 862/287, 22, 362, 476, 134, 193) with v2c constant-only and v3 refactor controls | corpus/catalog/*.json; corpus/ours/cwe-patterns/README.md | 2026-10-14 | high |
| Lineage bootstrap flags intervals `anti_conservative` below 30 groups; roles dev 60 / locked 25 / shift 15 % by lineage; the locked test is single use | tools/calibration/bootstrap.py:13; docs/specs/calibration-corpus-and-model.md s2.1, s4.4 | 2026-10-14 | high |
| `ChangeFacts`, `UnifiedMatch`, `row_id` exist (S0a); material needs an anchored second channel, cosmetic and unchanged need a named proof | src/patchtrace/unified/contracts.py:136-223, keys.py:90; docs/specs/unified-engine/05 s2.5-2.6 | 2026-10-14 | high |
| Every argparse command must also be in `tools/frozen_smoke.py` COMMANDS | tests/test_acceptance_smoke.py:52-56 | 2026-10-14 | high |
| Install and provisioning: PIL adds no dependency (stdlib, pydantic==2.13.5, PySide6==6.12.0 for the GUI only); `pip --only-binary=:all:` is unaffected; Windows and Linux run the same pure Python; K fetch and T tool provisioning are unchanged; KEV data arrives by import or the KEV track's consented fetch | pyproject.toml:9 | 2026-10-14 | high |
| Licences (SPDX): pydantic MIT; PySide6 LGPL-3.0-only (upstream also offers GPL and commercial terms; re-check at packaging); KEV data CC0-1.0; capa and FLOSS Apache-2.0; diec MIT. CVE-record and NVD fixture licences are [unverified], so evaluation fixtures stay short excerpts with CVE id, CWE and one description | upstream terms, docs/specs/three-tool-evidence-adapters.md T1 | 2026-10-14 | medium / low |
| Resource use: PIL is pure Python over bounded inputs (limits P-01 to P-10 in s7, targets [inf]); existing bounds still apply: 32 MiB per enrichment row, 128 MiB total, B1 signal loading for 10k pairs; unified results are read from sidecar files by the worker, never held whole on the GUI thread | src/patchtrace/enrichment/storage.py:37-38; docs/specs/unified-engine/02 s6 | 2026-10-14 | high |
| Security: advisory text is untrusted and already bounded by K (16 MiB, depth 64, strict JSON); PIL stores excerpts of at most 300 characters with pointers, renders plain text, rules are declarative literals, nothing is executed or sent | intelligence/csaf/validate.py limits; this plan s7 | 2026-10-14 | high |

## 3. Standalone baseline versus PatchTrace value
- Alone: a CSAF/CVE reader says what and which product, never where in code; Ghidriff, BinDiff and rz-diff list hundreds to thousands of changed functions with no reason; capa, FLOSS and DiE are per-file inventories; KEV is one CVE-level flag.
- Shipped `rank` and `correlate` (B1/B3) give an attention index plus additive context points that blend text overlap into a number. They stay as they are; PIL reads B1 signals, never B3 points.
- In PatchTrace every input is already paired and oriented: `candidate_key` is `unified.keys.row_id` (older/newer SHA-256 plus sorted RVAs), stable across re-runs and different after an orientation swap.
- T deltas are delta-only; each result carries `result_id` over all input digests, so staleness is derived; pin, dismiss and notes never mutate evidence.
```
advisory (K): CVE -> CWE profile -> hypotheses -> expected changes         origin D_vendor_text
code: B1, ChangeFacts, call labels                       origin D_ghidra    \
tools: capa (vivisect), FLOSS static, DiE flags, PE imports                  >- observation ledger per candidate
pairing verdicts (gate), KEV (CVE context only)                             /   -> origin components -> gates -> tier + tie-aware order -> lead + "why"
```
Workflows:
- W1 Patch Tuesday module: import the CSAF (K), open the pair project, pick a CVE, Enter jumps to the old and new function.
- W2 No advisory yet: code-only leads (ChangeFacts severity order, tool chips); importing an advisory later re-ranks and marks the old result stale, never edits it.
- W3 Reverse lookup: a function's detail lists every CVE it fits (no exclusive allocation). W4 Noise check: DiE flags and the cosmetic proof explain why a "guard" is compiler churn. W5 (later) series: per-hop leads once N-way pairs have results.

Charter 1-9: (1) keys and explicit orientation; (2) delta channels only, absent kept apart from unknown; (3) section 4; (4) section 7 ordering without numbers; (5) every observation has `nav`; (6) `result_id`, digests, consent flags; (7) channel states, no network; (8) `teach_id` and `next_step` per expected change; (9) section 5.

## 4. Cross-feature links
| Anchor kind | PIL emits | PIL consumes | Used by | How |
|---|---|---|---|---|
| function | `fn:<candidate_key>` per assessed candidate (class, mechanism, CVEs) | unified rows, Ghidriff matches, secondary verdicts | WB1 badge on hits, WB2 node badge, unified UI row detail, GDE lesson target, KB "Open Leads" | key is `row_id`; navigation through the GUI `NavigationPort`. Amended by FAB-0 (2026-10-14): FAB owns no navigation |
| string | wanted strings (K quoted-string anchors) | T `StringChange` (value_hash), IR `str` rows | WB3 highlight, YRX seed | join on casefolded UTF-8 hash; static strings are never attributed to a function |
| import/API | wanted APIs (hypothesis `api_hints`) | PE import delta, IR call import keys, Ghidriff `called` labels | WB2 edge highlight, YRX | `dll!name` when known; label-only calls support at most `tentative` |
| capability | none | T `CapabilityChange` (function or basic-block attributed only) | CAP UI | context unless a data row maps its namespace (empty in v1) |
| rule | `patch-rule:<id>@<rev>` fit per lead | YRX hits (context only) | YRX, GDE | analyst-reviewed rules never become shape evidence automatically |
| build fact | none | DiE flags | DIE panel | nuisance flags only |
| advisory phrase | CWE term hits and component phrase with JSON pointers (K) | none | KB, WB1 | locality needs 2 or more distinct non-module tokens |
| CVE | CVE context: gate, CWE profile, counts, KEV state | KB links, B3 snapshots, KEV | KB, KEV panel, GDE | KEV orders CVEs, never functions; KB-linked CVEs appear in the picker before an advisory is imported |
| KB | none | `kb_project_links` (KB, CVE, product, file, intervening updates) | KB | feeds the confounded-window input |
| CWE | `CWE-n` plus family per hypothesis | KEV `cwes`, NVD and MSRC CWE (same origin as the advisory, tag `D_vendor_text`; an NVD analyst CWE that differs is a kept disagreement, not a second vote) | LBL labels, GDE | disagreement is kept, never voted |

**FAB versus PIL.** FAB owns vocabulary and plumbing:
1. the `Anchor` record, kinds and canonical keys; 2. the origin-tag registry and `components()` (generalising SPEC-31 05 s1.1 and `calibration.features.family_dependencies`, so "shared origin counts once" has one implementation); 3. anchor persistence, queries and staleness guards; 4. ~~`NavRef` and the `Navigator` port;~~ Amended by FAB-0 (2026-10-14): navigation stays in the GUI `NavigationPort`, so FAB does not own it; 5. a cross-feature insights feed that can list leads from any provider.

PIL owns judgment: CWE/rule expected changes, three-valued evaluation, gates, tiers, tie-aware order, "why" text, review events, evaluation. FAB must not rank, classify CWEs or phrase explanations.
Until FAB lands PIL ships `pilot/origins.py` and `pilot/ports.py` (`OriginRegistry`, `AnchorSink` plus the input ports `AdvisorySource`, `ChangeEvidenceSource`, `ToolEvidenceSource`, `KevSource`, `CallDeltaSource`, `PairingSource`). FAB adopts or replaces them by moving files and rebinding `ports.py` only. Amended by FAB-0 (2026-10-14): that rebinding is slice FAB-3 (FAB plan s9); navigation is not a PIL or FAB port (it stays the GUI `NavigationPort`), so `Navigator` is dropped from this list.

## 5. Synergy test
Scenario (synthetic, hand-built ledger plus a validator-clean CSAF, no binaries). Module `examplenet.sys`; the update window fixes two CVEs:
- CVE-2099-20001: CWE-787 stated, title "Example Net IPv6 Fragment Reassembly ...", description "heap-based buffer overflow". Three more sources repeat the CWE (NVD, MSRC entry, KEV `cwes`). KEV lists only this CVE. Truth is F1.
- CVE-2099-20002: CWE-125, "options parsing". Truth is F6.

| Id | Function (pair) | Evidence in the ledger |
|---|---|---|
| F1 | Ipv6pReassembleFragment | B1 BND, ChangeFacts comparison (material, C6-anchored), call added RtlSizeTAdd (label), names fragment+reassemble |
| F6 | Ipv6pParseOptions | same guard shape, names options+parse |
| F8 | Ipv6pFragmentListReassemble | same shape and names, pairing contested (Ghidriff versus BinDiff) |
| F9 | Ipv6pReassembleFragmentTail | B1 BND but ChangeFacts cosmetic COS-LAYOUT/1 (decompiler moved an old check), names match |
| F4 | Ipv6pFragmentInit | B1 SIZE (allocation 0x40 to 0x80), no guard |
| F5 | Ipv6pFragmentReassemblyStats | call added to a counter, names match, no shape |
| F2 | Ipv6pLogFragmentDrop | new string "Dropped oversize fragment" (FLOSS) and a ChangeFacts string delta |
| F3 | Ipv6pChecksumFragment | register-only and address-only churn, DiE toolchain-changed |
| F7 | Ipv6pDispatch | callee swapped (top ChangeFacts severity) |

Expected output for CVE-2099-20001 with the window confounded (2 CVEs fixed on the newer build), full arm:
- F1 rank 1, FITS ADVISORY (expected changes 2 of 3, components 2, locality 2, tie size 1).
- F9 and F8 NEEDS REVIEW. F6 PARTIAL FIT (cap `confounded-window-needs-locality`). F4 and F5 PARTIAL FIT. F7, F2, F3 CHANGED, NO FIT.
- For CVE-2099-20002, F6 is the only FITS lead and F1 is capped. KEV only places CVE-2099-20001 first in the picker.

Ranks of F1 per arm [prototype]:
| Arm | F1 rank (tie range) | FITS leads | Why it falls short |
|---|---|---|---|
| Full | 1 | F1 | none |
| Advisory text only | 1-3 (with F9, F5) | none | names cannot separate, no code evidence |
| B1 signals only | 1-5 | n/a | guard shape fits five pairs |
| ChangeFacts only | 3-5, top is F5/F7 | n/a | severity order favours callee changes |
| FLOSS strings only | 2-8, top is F2 | n/a | the new string is the logging decoy |
| Advisory + B1, no ChangeFacts | 1-2 (with F9) | F1, F9 | no cosmetic proof, decompiler churn passes as a fit |
| Advisory + ChangeFacts, no B1 | 1 | F1 | B1 shares `D_ghidra`, so it adds no independence |
| Full minus name locality | 1 | none | confounded window: shape alone cannot isolate; F1 still first on expected changes |
| Full, window unknown | 1 | F1, F6 | F6 listed second; the caption says the window is unknown |

Tests on the same ledger:
- `test_synergy_full_arm_isolates_truth`, `test_synergy_single_channel_arms_fall_short` (ids adv, b1, cf, floss, adv-b1, adv-cf, no-names, window-unknown), `test_second_cve_gets_its_own_fit_lead`.
- `test_more_advisory_sources_do_not_add_independence`, `test_b1_and_changefacts_are_one_component`, `test_unavailable_channel_is_unknown_not_unmet` (drop capa: only the unknown list changes), `test_kev_never_changes_function_order`.
- `test_die_flag_caps_lexical_only_lead`, `test_equal_evidence_forms_tie_group`, `test_removing_support_never_raises_a_tier`.
- End to end: `test_pilot_sample_project_end_to_end` on the committed sample project (`read_item` bounds check) with a CWE-125 CSAF fixture: `read_item` FITS (text evidence only), `get_version` CHANGED NO FIT, the added `report_invalid_index` is context on its caller. Corpus layer: section 9 D1.

"Why this function" for F1 (plain text):
- Summary: fits advisory; expected changes seen 2 of 3 (required 1 of 1); 2 independent groups; evidence depth typed.
- Expected changes (R-MEMORY-WRITE r1, CWE-787 as stated by the advisory): seen guard added (B1 BND, ChangeFacts comparison, go to newer line 14); seen checked arithmetic (RtlSizeTAdd call added, label only); not seen size recomputed; unknown capability delta (capa not run).
- Independent evidence: advisory text (CSAF note, NVD, MSRC: same origin, counted once); Ghidra-derived code (B1, ChangeFacts, call label: counted once).
- Against: none. Unknown: capa and FLOSS not run; window lists 2 CVEs, names matched fragment and reassemble. Alternatives: partial fit for CVE-2099-20002.

## 6. Traps and guards
| Trap | Guard (test) |
|---|---|
| Averaging or summing channels | no float anywhere, ordering from integer counts and classes (`test_assessment_has_no_floats`, `test_order_key_has_no_weights`) |
| Shared origin counted twice (3 advisory sources, B1 plus ChangeFacts) | origin tags and components over supporting shape observations only |
| Unknown read as negative (capa not run, no names, no IR) | three-valued expected changes and channel states; `not-observed` only from a complete channel |
| Conflict hidden (B1 guard versus COS-LAYOUT proof, engine disagreement) | mechanism `contested`, both observations shown (`test_b1_vs_cosmetic_proof_is_contested`) |
| False precision from stable sort | tie groups shown as "n-m (tie)"; RVA is never a ranking reason |
| Shape fit mistaken for attribution (many unrelated fixes fit) | confounded window needs locality, else `tentative` |
| Locality from placeholder or generic names | placeholder names never count; module and feature tokens removed; 2 distinct tokens minimum |
| Added string treated as a fix (SPEC-30 negative) | strings are context only (`test_added_string_alone_is_never_fit`) |
| DiE promotes or proves | flags only; heuristic-only ignored (`test_die_never_promotes`) |
| KEV treated as function evidence, or absence as safety | CVE context only; copy says absence says nothing about exploitation |
| Compiler-only rebuild yields a mechanism | cosmetic veto plus nuisance cap (`test_aa_rebuild_yields_no_fit`) |
| Lexical text evidence shown as typed | `depth` field and a visible "text evidence only" flag; Ghidriff-only projects say the noise check did not run |
| Product mismatch or orientation conflict | CVE gate table (`test_not_applicable_cve_produces_no_leads`) |
| Stale or swapped-orientation result shown as current | `result_id` includes orientation and all digests (`test_swapped_orientation_marks_stale`) |
| Advisory or function-name markup, bidi, huge text | `sanitize_text` at adapter time, plain-text widgets, tooltip escaping (`test_hostile_advisory_text_never_rich`) |
| Rule or lexicon drift | digests in `result_id`; a K rule without PIL expected changes fails closed to unexplained (`PT-PILOT-RULES`) |
| Duplicate truth between B3 `CWE_DETECTORS` and the rule table | generated from, or tested against, the table |
| Persisted-contract break (new `AnalystAnnotation` kind) | review events are separate `patch-intent` rows; old readers ignore them |
| Analyst note read as PatchTrace verification | notes render under "Analyst statement" and never change a class |
| `restoreState` fed untrusted data | dock layout only in per-user QSettings, never in a project |
| UI reads FITS as a probability; colour-only status | neutral wording, footer, banned-string sweep, word plus shape badges |
| Rules tuned on the corpus they are scored on | dev, locked and shift roles by lineage, pre-registration, single-use locked run |
| Underpowered gate reported as a pass | fewer than 30 held-out lineages gives `insufficient-data` |
| Silent truncation or a performance cliff | `limits_hit` shown in the UI; inverted index by leaf; virtualised 100k queue; call-count gates |

## 7. Contracts
`pilot/1`: strict, frozen, `extra=forbid`, no floats, tuples sorted, canonical JSON, additive changes only.
- Role = shape, local, counter, conflict, context (only shape and local can raise a tier; conflict forces contested). Verification = verified-bytes, tool-reported, label-only, advisory-claim, rule-hypothesis, analyst-assertion. Mechanism = strong (reserved), moderate, tentative, unexplained, contested, not-assessed.
- LeadClass = fit, review, partial, code, queue. Identity = corroborated, contested, unassessed. CveGate = applies, asserted, unverified, conflict, not-applicable, none. ChannelState = available, partial, not-run, unsupported, failed, stale. Depth = typed, lexical, none.

Records:
- `Observation`: obs_id, channel, kind (closed slug: `b1:BND`, `cf:comparison`, `call:added`, `capa:added`, `str:added`, `die:toolchain-changed`), role, verification, origins (sorted tags), evidence_class, obligations, anchor_ids, ref {kind, id, pointer?, sha256?}, nav {side, rva, start_line?, end_line?} or null, detail (300 characters, plain text).
- `ExpectedChange`: id, state (met, not-observed, unknown, contradicted), required, observation_ids, teach_id. `HypothesisFit`: hypothesis_id, rule_id, rule_revision, cwe_id, basis, expected_changes, met, total.
- `Lead`: candidate_key, cve or null, lead_class, mechanism, identity, gate, depth, fits, components {count, tags}, local_hits, caps (`confounded-window-needs-locality`, `toolchain-changed-lexical-only`, `cve-unverified`, `cve-conflict`), support/counter/unknown/alternative observation ids, rank, tie {size, first, last}, assessment (`rule-hypothesis` or `unknown`).
- `CveContext`: cve, source_ids, gate, applicability summary, cwe {status, ids}, kev {state: listed, not-in-snapshot, unknown; date_added?; snapshot_id?}, confounding {state: yes, no, unknown; cves}, counts {fit, review, partial, code, queue}, limitations.
- `PilotAssessment`: contract, result_id, project_id, revision, older_sha256, newer_sha256, orientation `older->newer`, inputs (the `result_id` payload, stored verbatim so the UI can name a changed input), channels [{channel, state, reason}], cves, leads, queue_count, observations (deduplicated pool), status (complete, partial, abstained), limitations, created_utc (never hashed).
- `ReviewEvent` (own rows): candidate_key, cve or null, action (pin, unpin, dismiss, restore, note), text up to 2 KiB, created_utc.
- Errors `PT-PILOT-`: INPUT, STALE, MISMATCH, ORIENTATION, UNSUPPORTED, RULES, LIMIT, STORAGE, INTEGRITY, NOTFOUND, CANCEL.

Store and keys:
- Kind `patch-intent` (reserved, not in DERIVED_KINDS): pointer row `pilot-result:<result_id>` (`pilot-ptr/1`, up to 128 KiB: result_id, relative_dir, manifest_sha256, status, counts, config_digest) and event rows `pilot-review:<uuid>`.
- Sidecar `intelligence/pilot/<result_id[:16]>/{manifest.json, assessment.json.gz}` (part hashes over decompressed JSON, gzip mtime 0, path 120 characters or fewer). Guard `(project_id, ghidriff_run_id, raw_sha256, result_id)`.
- Own retention: newest 3 per (pair, CVE set, config) after a verified backup (`pilot-retention`); review events and K/T rows are never deleted.
- `result_id = domain_id('pilot-result', 1, {older_sha256, newer_sha256, orientation, ghidriff_run_id, raw_sha256, unified_result_id or null, secondary_set_ids, tool cache keys per engine and side, advisory facts_ids, kev_snapshot_id or null, kb_link_digest or null, asserted_gates, lexicon_digest, rules_digest, pilot_rules_digest, origins_digest, tiers_version, config_digest})`. Reviews, timestamps and paths are never hashed.

Limits:
- P-01 250,000 candidates; P-02 256 observations per lead; P-03 64 CVEs per run; P-04 500 persisted leads per CVE plus the top 200 queue rows by severity (the rest counted, caption shown); P-05 300 characters and 64 explanation lines.
- P-06 sidecar 64 MiB, pointer 128 KiB; P-07 rule table 64 x 16 x 16; P-08 stage deadline 120 s (cooperative budget), 1 GiB at 250k; P-09 100,000 displayed rows; P-10 Markdown 2 MiB (200 leads per CVE), JSON 32 MiB.
- Targets [inf]: 5,000 pairs x 8 CVEs localized in 5 s; evidence base for 100k functions in 30 s; first paint 200 ms; filter 100 ms at 100k; detail 50 ms.

CVE gate (from K `ApplicabilityReport`):
| Gate | Condition | Effect |
|---|---|---|
| applies | older resolves affected, newer resolves fixed or not_affected, mappings verified or candidate | normal tiers |
| asserted | analyst passes `--assume-applies CVE` (or the GUI checkbox) for a snapshot-only advisory or a corpus case | as applies, labelled analyst assertion, part of `result_id` |
| unverified | a side has mapping unknown, or resolution unknown, ambiguous or under_investigation | cap tentative, banner |
| conflict | any contradiction, resolution contradictory, or an orientation contradiction | cap review (never fit), banner |
| not-applicable | both sides fixed or not_affected, older not_affected, or newer still affected | no leads for this CVE, banner |
| none | no advisory | code-only mode |

Identity map:
| Source state | Identity |
|---|---|
| unified matched; without a current unified result: secondary corroborated | corroborated |
| unified tentative, candidate, older-only, newer-only, unknown; secondary single-engine, insufficient; nothing | unassessed |
| unified contested, ambiguous; secondary contested | contested |
Never both sources at once (shared origin).

Rule data: Python literals validated at import (no files, no eval), keyed by K rule id and revision. Expected changes `{id, required, any_of: leaves, teach_id}` plus counter leaves from a closed vocabulary: `b1:<DETECTOR>@<min>`, `cf:<ChangeClass>`, `call:added|removed@api_hints`, `capa:ns=<prefix>`, `str:*`, `cf:cosmetic|unchanged` (conflict). First draft authored in B1, each line with a positive and a negative fixture:
| K rules | Expected changes (required first) | Machine evidence today |
|---|---|---|
| MEMORY-WRITE, MEMORY-READ, BOUNDS | guard added; size recomputed; checked arithmetic | B1 BND, SIZE, OVF; ChangeFacts comparison, condition, constant; call added from `api_hints` |
| INTEGER | overflow check added; range check | B1 OVF, INT, BND; checked helpers in `api_hints` |
| INFO, UNINIT | zeroing or initialization added | B1 SCRUB; call added RtlZeroMemory or memset |
| INPUT | validation added | B1 VAL, ERR; ChangeFacts comparison |
| LIFETIME | reference or release change; state check | call added or removed on `api_hints`; ChangeFacts condition |
| NULL-DEREF, POINTER, TYPE | check or probe added | ChangeFacts comparison, condition; Probe*/ObReference* calls |
| RACE, AUTHN, AUTHZ, PATH, RESOURCE, INJECTION, DESERIALIZATION, SEARCH-PATH, CRYPTO-VERIFY | API-level change on `api_hints` | call added or removed; ChangeFacts callee; constant on flag arguments |
Rows without a B1 detector stay `tentative` unless two components agree.

Tier derivation (first match wins; the best hypothesis is kept, all are listed):
1. Gate not-applicable gives no lead; unverified caps at tentative; conflict caps at review.
2. Expected changes come from role-shape observations. A channel in state not-run, unsupported, failed or stale gives unknown, never not-observed; contradicted only by an explicit counter leaf.
3. Components = connected components of origin tags over the supporting shape observations plus the advisory (D_vendor_text for the CWE; D_ghidra for B1, ChangeFacts and call labels; D_pe_tables; D_vivisect; D_bytes). Locality never counts.
4. moderate = all required met and components >= 2. Caps to tentative: confounded window (2 or more CVEs fixed on the newer build) with no locality; toolchain-changed or packed with no typed (material) support.
5. contested = identity contested or a conflict against a met required change, when the tier after the caps of step 4 would still be moderate. A capped lead keeps tentative and shows the contested flag, so contested pairings with weak evidence do not outrank clean partial leads.
6. tentative = any expected change met, or locality with change evidence; unexplained = change evidence and no fit; strong is never assigned.
Class: fit = moderate, review = contested, partial = tentative, code = no advisory plus change evidence, queue = the rest. Depth = typed when a supporting shape observation is ChangeFacts or IR based, else lexical.

Order key (ascending): class, mechanism, identity (contested last), -expected changes met, -components, basis rank (explicit CWE, CWE in text, vocabulary), -local_hits, no anchored second channel, ChangeFacts severity rank (SPEC-31 05 s2.6), nuisance count.
- Equal keys form a tie group; inside a tie the display order is attention/1 rank (read-only), then `candidate_key`. Code-only key: class, severity rank, -distinct shape kinds, no anchor, nuisance. Pinned leads sort first in a Pinned band without changing class.
- Locality: function-name tokens (`enrichment.cve.name_terms`, B3 stop and generic lists) sharing 2 or more distinct tokens with the component phrase after removing module and feature tokens, or a quoted advisory string equal to a string the function references (IR). Placeholder names never count.
- Teach hooks (E-5): every expected change and state has a `teach_id` (`pilot.change.guard-added`, `.size-recomputed`, `.checked-arithmetic`, `.ref-release`, `.zeroed`, `pilot.state.contested`, `.unknown-channel`, `.tie`, `.confounded-window`, `pilot.context.kev`) and a `next_step` sentence, for example "Open the newer function and check that the new comparison runs before the copy."

## 8. CLI and GUI
**CLI** (envelope `enrichment-cli/1`; exit 0 ok, 2 invalid input or consent, 3 runtime or partial, 4 legitimate no result, 5 cancelled; one JSON document with `--json`; no Qt import; offline except `fetch`).
- K, unchanged from spec J: `intelligence import PROJECT FILE.json --cve ID`; `intelligence fetch PROJECT --cve ID --consent-hosts msrc.microsoft.com [--provider-metadata URL] [--cache-dir DIR] [--offline]`; `intelligence explain PROJECT --cve ID [--older-product PID]... [--newer-product PID]... [--export FILE.json|FILE.md] [--json]`.
- PIL: `intelligence leads PROJECT [--cve ID]... [--assume-applies CVE]... [--class fit|review|partial|code|queue]... [--limit N] [--tools capa,floss,diec|none] [--no-unified] [--export FILE.json|FILE.md] [--dry-run] [--json]`.
- Result: result_id, status, channels, cves [{cve, gate, kev, counts}], leads [{rank, tie, candidate_key, older, newer, class, mechanism, identity, depth, expected_changes {met, total}, components, why[]}], queue_count, limitations, stale. Exit 4 for a not-applicable gate or no leads, 3 when an adapter failed (`status: partial`).
- It reuses stored default-profile signals when current, else runs the B1 pipeline in memory; `--dry-run` persists nothing.
- `intelligence why PROJECT --candidate KEY [--cve ID]` reads the stored result (exit 4 when none or unknown key); `intelligence review PROJECT --candidate KEY --action pin|unpin|dismiss|restore|note [--cve ID] [--text T]` appends an event.
- Hook: K2 adds `intelligence` to `COMMANDS`, `HANDLERS`, `_command_name` and `tools/frozen_smoke.py` in about 6 lines; this hook may merge first (the registry ignores it) and move later to the adapter `cli_commands/intelligence.py` (GUI plan 8.12); actions live in `intelligence/cli.py` with a guarded `ACTIONS.update(pilot.cli.ACTIONS)`.
- `pilot/report.py` reuses K's `escape_md` (HTML-escape, Markdown-escape, flatten cells, C0/C1 and bidi as `\uXXXX`, URLs as text).

**GUI** (`ui_leads.py` over Qt-free `pilot/read_model.py`).
- Placement: `QDockWidget` "Leads" (`leads.dock`) in the right area, tabified with "Engine evidence" ([src] both added first, neither already tabbed, unique objectName). Visible when a project opens (needs `default_visible` in the manifest, GUI plan open question 13), never steals focus. `View > Leads`, `Ctrl+Shift+L` (a test checks it against every MainWindow, C6, S4 and WB shortcut). Layout is stored by the host (no `leads/geometry` key), never in the project. No new top-level window.
- Header: context combo ("No advisory (code evidence only)" and rows "CVE-... KEV, 2 fit", KEV first), [Import advisory...], [Refresh]. Banner row: gate, window, orientation. Channel chips: Advisory, Code, Calls, Strings, Capa, Build, Pairing, each available, not run, unsupported, failed or stale. Then filter row (class, search, show dismissed), table, detail splitter, fixed footer.
- Table `LeadTableModel`: immutable slots rows, model-owned order and filter (index list plus one reset; no `QSortFilterProxyModel`, no ResizeToContents, row height from font metrics) so 100k queue rows stay in budget [src C6 items 3-9].
- Columns: `#` (rank or "n-m (tie)"), Lead (name, RVAs), Class badge (word plus shape, never colour alone), Expected changes seen ("2 of 3"), Channels ("Advisory + Code; unknown: Capa"), Pairing, Flags ("text evidence only", "contested", "toolchain changed"). `data()` returns precomputed DisplayRole text only; tooltips and accessible text are lazy.
- Detail "Why this function": plain text (`setPlainText`) with fixed headers Summary, Expected changes (seen, not seen, unknown), Independent evidence (grouped by origin, "same origin, counted once"), Against, Unknown, Alternatives, Pairing, Provenance, Limitations.
- Observations sit in a flat `ObservationTableModel` (256 rows or fewer); Enter on a row goes to its `nav`. Buttons: Go to function, Copy explanation, Pin, Dismiss..., Add analyst note... (rendered as "Analyst statement").
- Navigation (one click to the code): a row with a Ghidriff match uses `WindowPort.select_match`; an observation with a code location uses `reveal_location(match_id, side, start_line, end_line)` (`reveal_lines(function_id, s, e)` in the GUI plan); a unified-only row uses SPEC-31's planned `show_external_pair` (S4); otherwise the button is disabled and its tooltip names the reason. Nothing is fabricated.
- Keys: Up, Down, PageUp, PageDown, Home, End; Enter newer side (older if absent); Shift+Enter older; Ctrl+C copy explanation; P pin; Delete dismiss (reason prompt, deletes nothing); Space detail focus; F6 cycles panes. `activated` is platform dependent [src], so Enter is bound explicitly and no destructive action uses it.
- Accessible names: dock "Leads panel"; table "Ranked leads table"; context "Advisory context for leads"; filter "Filter leads by class"; search "Search leads by function name or address"; detail "Why this function: details of the selected lead".
- Button names: "Go to selected lead in the code panes", "Copy explanation of selected lead", "Pin selected lead", "Dismiss selected lead", "Add analyst note". Status text is announced through `ctx.announce` (GUI plan F6) [src C6 item 18]; real UIA/NVDA announcement is a manual gate.
- Tooltip ids (WHAT, WHY, EFFECT, SOURCE, Availability; no angle brackets): `leads.action`, `leads.dock`, `leads.table`, `leads.context`, `leads.filter_class`, `leads.search`, `leads.detail`, `leads.import`, `leads.refresh`, `leads.goto`, `leads.copy`, `leads.pin`, `leads.dismiss`, `leads.note`, `leads.show_dismissed`, `leads.chip.<channel>`; templates `leads.row`, `leads.badge`, `leads.expected`, `leads.tie`.
- Badges: "FITS ADVISORY", "NEEDS REVIEW", "PARTIAL FIT", "CODE CHANGE", "CHANGED, NO FIT". KEV chip: "CISA KEV: listed (added DATE)", "CISA KEV: not in the snapshot of DATE; absence says nothing about exploitation", "CISA KEV: unknown".
- Footer: "Leads are ordered by explainable rules, not by likelihood. A lead does not show that this function contains or fixes any CVE. Tied leads have equal evidence."

States (precedence L5 > L6 > L4 > L3; L2 only before the first table):
| ID | Exact text |
|---|---|
| L0 | "Open a project to see leads." |
| L1 | "No comparison result yet. Run the analysis first; leads are computed from stored results only." |
| L2 | "Preparing leads: STAGE DONE/TOTAL" (or "(no counts available)"), with Cancel |
| L3 | table and detail |
| L4 | banner "Some evidence was not available: CHANNELS. Missing evidence is unknown, not a negative result." |
| L5 | "Leads could not be prepared: CODE: MESSAGE. The stored comparison and earlier leads are unchanged." with Retry and Copy details |
| L6 | "These leads are out of date: CHANGED INPUT. They are shown for reference only." with Refresh |
| L7 | "No advisory is loaded. Leads use code evidence only and are not matched to a CVE. Import an advisory to rank by fit." |
| L8 | "Too many rows to display (N). Narrow the filter." |
| gate not-applicable | "The advisory says these builds are not affected by CVE, or the newer build is still affected. No leads are produced for it." |
| gate unverified | "This advisory could not be tied to these builds; the file name is never used. Leads for it are capped at Partial fit." |
| gate conflict | "The advisory conflicts with itself or with the build order. Leads for it are capped at Needs review." |
| window | "The advisory lists N CVEs fixed in this build. A change that fits the expected shape may belong to another CVE; only advisory-specific evidence can separate them." |

Threads:
- `LeadsLoadThread` is unparented and held in a module registry. An immutable `LeadsRequest` snapshot is built on the GUI thread (pointer rows, advisory facts, signal sets, tool evidence ids, unified result directory) exactly as C6 builds `EvidenceRequest`.
- The worker reads sidecar files only; SQLite stays on the GUI thread. A generation counter drops late results; rows and review events are published in GUI-thread slots; `shutdown()` cancels and waits, never `terminate()`.

Offscreen tests:
- One test per state; `data()` ceiling 7 x visible cells + 20 % at 10k and 100k rows; hostile text; names and tooltips audit; contrast as a pure function; 20 repeats with `PYTHONFAULTHANDLER=1`.
- Banned-string sweep over every producible string: `probab`, `likelihood`, `confidence`, `percent`, `vulnerab`, `exploit`, `proven`, `certain`, `verified`, `safe`, `secure`. Sanctioned phrases are removed first, as in `evidence_view.BANNED`: the footer, "absence says nothing about exploitation", "CISA KEV", "Analyst statement".
- Enum slugs never reach the UI: the read model maps each to words (for example `verified-bytes` to "read from the file bytes"), so the sweep also covers the mapping table.
- `test_no_new_top_level_window`, `test_leads_publish_runs_on_gui_thread`, `test_project_switch_during_compute_drops_result`, `test_close_while_computing_cancels_and_waits`.

Pitfalls: threads never parented (`~QThread` aborts); escape tooltips (`Qt.mightBeRichText`); labels PlainText; reselect by `candidate_key` after a reset; `tabifyDockWidget` preconditions; focus ring and badge contrast 3:1 (WCAG 1.4.11), colour never the only carrier (1.4.1), full keyboard use (2.1.1), visible focus (2.4.7), programmatic status (4.1.3).

## 9. Slice plan
Each slice: spec amendment rows first, red tests, code, focused tests, full gate twice, ruff, schema drift, Linux and Windows CI. Total about 30-45 developer-days, 6-10 M tokens [inf]. Order: A1, then A2, A3, B1 and T in parallel, then B2, C1, C2; D1 after B2; K1 then K2 can run at any time. Critical path A1, A3, B2, C1, C2 is about 17-25 days. Cross-track dependencies and fallbacks:
- SPEC-31 S0b/S3 (typed `ChangeFacts`): optional input; without it the ceiling is lexical B1 evidence and the "text evidence only" flag.
- T runner, store, CLI (not built): capa, FLOSS, DiE report `not-run` until they land; A3 is complete against the `ToolEvidenceSource` port with fakes.
- KEV and KB tracks: ports only; `confounding` falls back to the CSAF-derived CVE count. FAB: ports (section 4). GUI track: C2 uses the panel registry when present, else the direct seam. LBL: D1.

**Wave A (no dependencies outside the wave)**
- **PIL-K1** CSAF remainder 1 (`explain.py`, `reports.py`).
  - Files: `intelligence/explain.py` (`build_report(...) -> IntelligenceReport`, the missing builder), `intelligence/reports.py` (JSON; escaped Markdown per spec J), `tests/test_intel_{explain,reports}.py`, goldens in `tests/fixtures/csaf/expected/`. Deps: none.
  - Tier Sonnet (spec exact, escaping table-driven). Size S, 1-2 d.
  - Gate: injection fixtures (markup, bidi, C0/C1, long cells, `javascript:` URLs), byte-identical goldens on Linux and Windows. Fallback: JSON only.
- **PIL-K2** CSAF remainder 2 (CLI).
  - Files: `intelligence/cli.py` (`import`, `fetch`, `explain`, `ACTIONS`), the adapter `cli_commands/intelligence.py` (or the temporary `cli.py` hook until F1b), `tools/frozen_smoke.py`, `tests/test_intel_cli.py`. Deps: K1.
  - Tier Sonnet. Size S-M, 1.5-2 d.
  - Gate: exit codes 0/2/3/4/5 by subprocess, single JSON document, no Qt import, fake-opener consent test, `test_every_cli_command_is_covered_by_the_smoke_list`. Fallback: `import` and `explain` only.
- **PIL-A1** (30a) contracts.
  - Files: `pilot/{__init__,contracts,limits,keys,origins,ports}.py`, `tools/generate_pilot_schemas.py`, `docs/schemas/pilot/` with valid and invalid examples, `.gitattributes` LF lines, error codes, `tests/test_pilot_{contracts,keys}.py`. Deps: none.
  - Tier Sonnet (the text is in section 7). Size M, 2-3 d.
  - Gate: regenerate-and-compare, invalid examples rejected, `test_strong_is_unreachable`, `test_assessment_has_no_floats`, `test_old_reader_ignores_patch_intent`. Fallback: none (the freeze is mandatory).

**Wave B (after A1)**
- **PIL-T** oracle (written red against the A1 contracts, green when B2 lands).
  - Files: `tests/fixtures/pilot/synergy-1/*` (ledger, CSAF, expected), `tests/test_pilot_synergy.py`, `tests/test_pilot_sample_e2e.py`. Deps: A1.
  - Tier: Haiku for the fixture JSON (mechanical from the section 5 tables), Sonnet for the assertions (they need judgment). Size S, 1-2 d.
  - Gate: section 5 tables reproduced exactly. Fallback: ledger layer only.
- **PIL-A2** (30a) advisory-side adapters.
  - Files: `pilot/sources/{advisory,identity,kev,window,snapshot}.py` (K `IntelligenceReport`, applicability gate, KEV port, confounding count, pairing verdict map, B3 `CveSnapshot` or CVE-record excerpt to `CVEFact`, the path 30d also uses), `tests/test_pilot_sources_advisory.py`.
  - Tier Sonnet (public contracts). Size M, 2-3 d.
  - Gate: `test_cve_gate_table`, `test_kev_absence_is_unknown_context`, `test_unified_beats_secondary_for_identity`, `test_confounding_counts_cves_fixed_on_newer`, all `detail` pass `sanitize_text`. Fallback: no KEV, no snapshot adapter.
- **PIL-A3** (30a) code-side adapters.
  - Files: `pilot/sources/{code,unified,tools,pe,calls}.py` (B1 `SignalSet`; `UnifiedMatch` and `ChangeFacts` through `unified.store`; T `ToolDelta`; `pe_overview` import delta; Ghidriff call labels; candidate universe; nuisance flags), `tests/test_pilot_sources_code.py`.
  - Tier Sonnet. Size M-L, 3-4 d.
  - Gate: `test_cosmetic_proof_becomes_conflict`, `test_capa_unlocalized_never_attaches`, `test_floss_static_string_never_attributed`, `test_label_only_calls_cap_verification`. Fallback: Ghidriff and B1 only.
- **PIL-B1** (30b) rule table.
  - Files: `pilot/rules/{contracts,data,evaluate}.py` for the 20 K rules, plus additive K edits `lexicon.py` and `hypotheses.py` (family `format-string` for CWE-134; CWE-193 and "off by one" under `bounds`), `tests/test_pilot_rules.py`.
  - Tier Sonnet (data authoring, no algorithmic freedom). Size M, 2-3 d.
  - Gate: `test_every_k_rule_has_expected_changes`, per-family positive and negative fixtures (ids = family names), `test_cwe_detector_map_consistent_with_rules`. Fallback: the B1-backed families first.

**Wave C**
- **PIL-B2** (30b) fusion and ranking.
  - Files: `pilot/{fusion,tiers,ranking,why,quality,service}.py` with `localize(inputs, config, cancel) -> PilotAssessment`, `tests/test_pilot_{fusion,ranking,properties}.py`. Deps: A2, A3, B1, T.
  - Tier **Opus**: independence, ties, monotonicity and no-averaging are the product's core invariants, and the roadmap assigns localization to Opus. Size L, 4-6 d.
  - Gate: PIL-T green, properties (permutation, idempotence, monotone, unknown stays unknown), 5 s target. Fallback: ship classes without `moderate` (all partial) behind the same contract.
- **PIL-C1** (30c) store, report, CLI actions.
  - Files: `pilot/{store,report,cli,review}.py`, `tests/test_pilot_{store,report,cli}.py`. Deps: B2, K2, K1.
  - Tier Sonnet. Size M, 2-3 d.
  - Gate: `test_store_roundtrip_and_stale`, `test_retention_keeps_three_and_reviews`, `test_cli_leads_exit_codes`, `test_review_events_append_only`, `test_report_banned_strings`. Fallback: JSON export only.

**Wave D**
- **PIL-C2** (30c) read model and Leads dock.
  - Files: `pilot/read_model.py`, `ui_leads.py`, `tests/test_ui_leads.py`, `leads.*` tooltips, GUI panel registry (`PANEL`; the 20-line `ui.py` seam is retired), `reveal_location`, and the K `storage.py` split into `prepare` (pure, worker) and `commit` (owner thread) for GUI import. Deps: C1.
  - Tier Sonnet (Qt patterns copied from C6 and G; Opus only after two failed attempts on a threading crash). Size L, 6-8 d.
  - Gate: section 8 tests, 20 repeats without abort. Fallback: CLI and report only, dock after the GUI registry lands.
- **PIL-D1** (30d) evaluation.
  - Files: `tools/calibration/pilot/{contracts,cases,metrics,ablation,report,cli}.py`, advisory fixtures `tools/calibration/pilot/advisories/<CVE>.json`, `tests/test_pilot_eval_*.py`. Needs LBL M2/M5 and, for typed arms, SPEC-31 S3.
  - Case: pair label file, CVE, advisory excerpt, patch-bearing keys = `functions[].label == changed` and `check == ok` intersected with card `changed_functions`.
  - Arms: B0 Ghidriff `modified` in attention order; B1 unified material plus review in 05 s2.6 order; B2 attention plus B3 contextual; P-adv, P-code, P-full; leave-one-channel-out; each with symbols hidden and visible (locality exists only with names).
  - Metrics: hit@1/3/5/10, recall@K, false leads before the first hit, tie-aware worst-case rank, abstention coverage, runtime, memory. The median card has 1 patch-bearing function [own], so hit@1 and hit@3 headline.
  - Statistics: `tools.calibration.bootstrap.cluster_bootstrap` and `paired_delta` (B = 2000), roles from `lineage.assign_roles`, single-use locked run as in `run_locked_test.py`.
  - Gate (pre-registered): the lower 95 % bound of the relative reduction in false leads before the first hit (total over cases, resampled by lineage), P-full versus the best baseline, is at least 20 %, and the lower bound of the recall@10 difference is at least 0, on at least 30 held-out lineages; fewer gives `insufficient-data`.
  - The committed corpus [own] has about 31 lineages (20 projects plus 11 authored suites), about 8 locked, so the gate stays `insufficient-data` until LBL M1/M2 roughly quadruple the catalogue.
  - Tier Sonnet (the statistics utilities exist). Size L, 5-7 d. Fallback: unit and ablation tables without a gate claim.
- **PIL-D2** (30d) `docs/plans/pilot-preregistration-v1.md` (hashed into every report) and `.github/workflows/pilot-eval.yml` (dispatch, advisory, Linux first). Tier Haiku or Sonnet. Size S, 1-2 d.
- Tier W (local only): ntoskrnl 10.0.22621.1344 to 1413 (CVE-2023-23420) and afd.sys 10.0.22621.1028 to 1415 (CVE-2023-21768) as acceptance anchors from SPEC-31 08 s2; results stay on the owner's machine.

## 10. Amendments required and test and QA plan
**Where the drafts are wrong or thin** (checked against code):
- SPEC-30 names `PILOT/1`; the coordination doc freezes `pilot/1` and kind `patch-intent`. SPEC-30 places modules under `intelligence/`, which K and T own, and both SPEC-28 and SPEC-30 claim `reports.py`.
- The SPEC-30 graph (BasicBlock, Operation, produces-value, guards-sink) needs dataflow that no channel produces: B1 is lexical, ChangeFacts is operand-level. 31-E's "strong" needs a guard-to-sink proof nothing yields, so `strong` is unreachable today.
- K's `required_observations` are prose; SPEC-30's "predicate DAG" defines no leaves; B3 `CWE_DETECTORS` is the only executable CWE-to-evidence map and duplicates K's families.
- K lacks CWE-134 and CWE-193 (both in the corpus); `IntelligenceReport` has no builder; `AdvisoryStore` is thread-confined, so GUI import needs a prepare and commit split.
- "Evidence lineage deduplicates" has no calculus. SPEC-31 05 s1.1 requires both component and class to differ; PIL separates support (components) from locality instead, because name matches would otherwise merge advisory and code through `D_symbols`.
- The 30d gate ("20 % fewer false leads at non-decreasing recall") names no unit, K, estimator or minimum sample; the repo's own bootstrap flags fewer than 30 lineages.
- 31-E E6 sorts by "vendor component hints" without a locality definition and has no tie handling. KEV is specified nowhere; MSRC exploit-status prose is unverified.
- `docs/plans/csaf-patch-intelligence-implementation.md` Gate 0 and 1 are stale (BinDiff execution and BinExport2 are merged).

**Amendments** (file, section, change; the integration owner applies them):
1. `docs/specs/patch-intent-localization-engine.md`: status and "Pure modules" move to `pilot/`; `PILOT/1` becomes `pilot/1`; replace the provenance graph by the ledger; define origin components, tie groups, tiers, the CVE gate and the confounded window; mark `strong` reserved; restate the 30d gate (unit, K, estimator, 30-lineage minimum).
2. `docs/specs/csaf-cve-interpretation-engine.md` "Data schemas", "Modular structure", status: `Candidate`, `correlate.py`, `scoring.py` are superseded by `pilot/`; add `explain.py`; note that `required_observations` are prose and PIL owns the evaluable table.
3. `docs/plans/csaf-patch-intelligence-implementation.md`: replace the 30a-d checklist by section 9; drop the stale Gate 0 and 1 text.
4. `docs/modules.md`, `tasks/todo.md`, `docs/qa.md`: append rows for `pilot/*` and `ui_leads.py`; K "deferred" rows point at K1 and K2.
5. `docs/plans/phase-d-build-coordination.md` s2: `patch-intent` is not a derived kind; list `PT-PILOT-*`.
6. `src/patchtrace/enrichment/storage.py`: promote `backup_once(label)` and `delete_own(ids, kinds)` (now in `unified/store.py`, A-04) to additive public methods for unified, pilot, K and T; PIL must not import unified internals.
7. `src/patchtrace/cli.py`: superseded by the CLI-extension registry (GUI plan 8.12, slice F1b): verbs are adapter files in `cli_commands/`, so K, T, SPEC-31 and KB no longer compete for `cli.py` lines; K2 owns `cli_commands/intelligence.py` (its temporary hook until F1b).
8. `src/patchtrace/ui.py` and `tooltips.py`: the Leads seam (20 lines or fewer) is retired in favour of the GUI panel registry (`PANEL`, `PANEL.tips`); `reveal_location(match_id, side, start_line, end_line)` is `reveal_lines(function_id, start_line, end_line)` in the GUI plan and reuses `jump_signal`, so no second seam sits beside S4's 25 lines.
9. `docs/specs/known-answer-corpus.md` (LBL): consumer note for 30d; request an additive per-pair export of patch-bearing keys and a names-visible build condition per case. PIL owns the advisory fixtures so LBL files stay untouched.
10. `docs/specs/unified-engine/10-amendments.md` A-22: trigger fired; PIL reads rows and facts only through `unified.store.load_result/read_rows/read_facts`. `docs/specs/kb-cve/31-E-evidence-intent.md`: `correlate.py` is a thin facade over `pilot.service.localize`; shared gate vocabulary, PIL owns Function-identity and Mechanism, K owns Binary-integrity and Applicability.

**Test and QA plan.**
- Fixtures without Microsoft bytes: synthetic CSAF `synthetic-pilot-advisory.json` (CVE-2099-20001/20002, validator-clean, sample SHA-256 products), hand-built ledgers, B1 output from `signals.detect` on committed snippets, the sample project. `corpus/ours/cwe-patterns` and the zlib card are compiled by the LBL factory in CI only (BLOCKED, never silently skipped, without compilers).
- Goldens: expected leads per arm, report goldens, schema regenerate-and-compare, `.gitattributes` LF for fixtures and schemas.
- Properties (hypothesis): observation-order permutation invariance; duplicate observations idempotent; an observation whose origins already occur never raises components; removing support never raises a tier; unknown never becomes not-observed; canonical JSON round trip; hostile text never reaches a rich-text widget.
- Windows pitfalls (roadmap checklist): LF fixtures; short explicit parametrize ids (arm and family names); `>=` on `time.monotonic` budgets; sidecar paths 120 characters or fewer with an `os.replace` retry; wheels-only; no network in tests.
- Gates only CI or the owner can close (never counted as done): real MSRC CSAF through the K validator and PIL (host blocked); consented fetch on Linux and Windows; Tier W anchors; first corpus run with Ghidra; NVDA and Narrator on the status label; 125/150/200 % DPI; frozen `PatchTrace.exe intelligence --help` and `intelligence leads` on the sample project.

## 11. Open questions (defaults apply; nothing blocks)
1. Package location `pilot/` versus `intelligence/pilot/`: default `pilot/` (file ownership).
2. Top-level `leads` command versus `intelligence leads`: default nested (no extra hook lines).
3. Leads dock visible on project open: default yes, remembered per user.
4. Show tie ranges: default yes ("n-m (tie)").
5. Allow `moderate` from lexical B1 alone: default yes with the "text evidence only" flag and the toolchain cap (B3 already treats moderate as aligning).
6. Locality threshold of 2 distinct tokens: default 2, part of `config_digest`.
7. Confounded window = 2 or more CVEs fixed on the newer build: default; KB intervening-update counts may replace it later.
8. Persist the result on every compute: default yes (derived, retention-bounded); `--dry-run` and a GUI preference opt out.
9. MSRC exploit-status prose: default shown verbatim, never parsed, until a live sample is verified.
10. 30d gate size: default `insufficient-data` below 30 held-out lineages; the owner may fund more LBL cases or accept Tier W only.
