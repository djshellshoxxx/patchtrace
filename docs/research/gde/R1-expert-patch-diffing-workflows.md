# GDE R1: How expert reverse engineers perform patch diffing and binary triage

Worker: GDE R1. Written 2026-10-14. Documents only; feeds the guided-RE "deterministic teacher" (roadmap E-5).
Scope: ordered expert workflow, decision points, questions, evidence, pitfalls, each mapped to a PatchTrace feature or marked GAP.

## 0. Method and honesty statement

- The sandbox egress proxy denied `arxiv.org`, `cwe.mitre.org`, `www.cs.cmu.edu` and `www.ndss-symposium.org` (CONNECT 403), and `WebFetch` could not resolve them. Facts were confirmed through web-search result snippets only (retrieved 2026-10-14). Anything not confirmed carries `[unverified]`. Confidence: H = confirmed by an official or paper-hosting result; M = result snippet from a mirror or secondary page; L = from memory, host blocked.
- No blogs, videos, forums or AI summaries are used as sources. Existing in-repo research (`docs/research/unified-engine/04`, `05`, `docs/research/diaphora-feature-study-20261014.md`, `docs/research/kbcve/`) is cited as `[repo]`; those files carry their own source tables.
- Ghidriff, Diaphora, PatchDiff2 and Turbodiff are references only (GPL/AGPL rule); no code is taken.
- "Expert practice" below is a synthesis of what papers and tool documentation describe tools being used for, not an observed survey of people. Where a stage rests on practitioner folklore with no primary source it is labelled `[practice, unverified]`, and the teacher must not present it as established fact.
- Note: `docs/plans/program-e-research-brief.md`, `program-e-roadmap.md` and `docs/specs/REGISTRY.md` were read from the main checkout (they are not in this worktree's commit).

## 1. Sources

| ID | Claim used | Source (URL) | Retrieved | Conf. |
|---|---|---|---|---|
| S1 | Binary similarity surveyed over 61 approaches; applications include patch analysis and patch generation; compilation loses names and variable names, making the problem hard | Haq, Caballero, "A Survey of Binary Code Similarity", ACM CSUR 2019, https://arxiv.org/pdf/1909.11424 | 2026-10-14 | M |
| S2 | Several elementary features are robust across architectures, compilers, compiler versions and intra-procedural obfuscation; compilation choices and the correctness of underlying analysis tools significantly affect results | Kim et al., "Revisiting Binary Code Similarity Analysis using Interpretable Feature Engineering and Lessons Learned", IEEE TSE 2022, https://arxiv.org/pdf/2011.10749 | 2026-10-14 | H |
| S3 | Unsupervised block embeddings plus k-hop greedy matching; beats prior tools for cross-version and cross-optimisation diffing; OpenSSL vulnerability case study | Duan et al., "DeepBinDiff", NDSS 2020, DOI 10.14722/ndss.2020.24311, https://www.ndss-symposium.org/ndss-paper/deepbindiff-learning-program-wide-code-representations-for-binary-diffing | 2026-10-14 | H |
| S4 | Given original and patched program, diff finds the added input check, then generates failing inputs; five Microsoft programs; the patch itself leaks the bug | Brumley, Poosankam, Song, Zheng, "Automatic Patch-Based Exploit Generation is Possible", IEEE S&P 2008, DOI 10.1109/SP.2008.17, https://bitblaze.cs.berkeley.edu/apeg.html | 2026-10-14 | M |
| S5 | BinDiff manual chapter "Understanding BinDiff": general matching strategy, function matching, basic block matching, confidence/similarity; release notes add string-reference and edge-vector fixed-point seeding | https://www.zynamics.com/bindiff/manual/index.html | 2026-10-14 | M (TOC only; algorithm text not read) |
| S6 | BinDiff match records carry algorithm name, similarity and confidence; identical logic scores similarity 1.0 | BinDiff docs in https://github.com/google/bindiff (docs tree); exact page not fetched | 2026-10-14 | L |
| S7 | rz-diff offers byte, delta, code-analysis and import comparison; flags differ between versions, so read installed `-h` | https://book.rizin.re/src/tools/rz-diff/binary_diffing.html ; https://man.archlinux.org/man/rz-diff.1.en | 2026-10-14 | M |
| S8 | MSRC Exploitability Index: values 0-3 (detected, more likely, less likely, unlikely); not updated after initial publication; separate from CVSS; does not differentiate vulnerability types | https://www.microsoft.com/en-us/msrc/exploitability-index | 2026-10-14 | H |
| S9 | CISA KEV is the authoritative catalog of vulnerabilities exploited in the wild, intended as a prioritisation input | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | 2026-10-14 | H |
| S10 | CWE-416 (UAF) text read only via mirrors; authoritative page blocked | https://cwe.mitre.org/data/definitions/416.html | not reached | L [unverified] |
| S11 | capa reports capabilities of PE/ELF/.NET/shellcode with ATT&CK and MBC mappings; rules are YAML | https://github.com/mandiant/capa ; https://mandiant.github.io/capa/ ; vendor blog https://cloud.google.com/blog/topics/threat-intelligence/capa-harnesses-ghidra | 2026-10-14 | M |
| S12 | FLOSS (obfuscated-string extraction) and Detect It Easy (packer/compiler identification): not confirmed by this session | https://github.com/mandiant/flare-floss ; https://github.com/horsicq/Detect-It-Easy | not reached | L [unverified] |
| S13 | MSRC Security Update Guide, CSAF/CVRF providers, Winbindex servicing catalog | `docs/research/kbcve/msrc-sources.md`, `winbindex-servicing-catalog.md` [repo] | repo | per file |
| S14 | PE/COFF relocations, `/DYNAMICBASE` (ASLR), `/GS`, CFG, ICF, PGO behaviour | Microsoft Learn: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format ; https://learn.microsoft.com/en-us/cpp/build/reference/dynamicbase-use-address-space-layout-randomization ; https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check | not reached | L [unverified] |
| S15 | Noise-filter catalogue F1-F15, hard-evidence cascade R1-R14, canonical pseudo-code | `docs/research/unified-engine/05-fusion-and-noise-reduction.md` [repo] | repo | per file |
| S16 | Ordered matching heuristics, export cost, diff automation (Diaphora wiki, reference only) | `docs/research/diaphora-feature-study-20261014.md` [repo] | repo | per file |

## 2. PatchTrace features referenced

Names come from `docs/modules.md` and `docs/specs/REGISTRY.md` (snapshot 2026-10-14).

| Tag | Feature | Owner / spec |
|---|---|---|
| F-ING | Ingestion, PE AMD64 validation, immutable copies | ingestion.py, SPEC-01 |
| F-PEO | PE overview / preliminary inspection (headers, sections, imports, signature) | pe_overview/, SPEC-26-D |
| F-HEX | Byte representations and raw view | representations/, SPEC-26-B |
| F-GDF | Ghidriff run, normalisation, function pairs, deltas, hunks | backend.py, jobs.py, normalization.py, alignment.py, SPEC-01/02 |
| F-REV | Reviews, manual matches, notes, stale invalidation | service.py |
| F-ENR | Enrichment: signals, ranking, CVE hints, Winbindex, intelligence | enrichment/, SPEC-07 |
| F-ACQ | Acquisition: Winbindex, quarantine, delta (KB patch search planned) | acquisition/, SPEC-08, SPEC-37 |
| F-KB | KB-CVE correlation | SPEC-34 (PR #40, not on main) |
| F-CSAF | CSAF CVE interpretation / patch-intent localization | SPEC-35, SPEC-30 (draft) |
| F-NWAY | Series of builds, series window | nway/, SPEC-09/09b |
| F-BDF | BinDiff import/execution, BinExport2 | secondary/, SPEC-10/10b/29 |
| F-RZD | rz-diff secondary engine | SPEC-11 |
| F-REC | Multi-engine reconcile, evidence panel (states E0-E8), calibration | SPEC-27, SPEC-38 (proposed), SPEC-39 (proposed) |
| F-UNI | Unified diff engine and noise filters F1-F15 | SPEC-31 (draft; `unified/` S0a on main) |
| F-CAP | capa capability deltas | SPEC-36 (approved, not built) |
| F-FLO | FLOSS strings per side | SPEC-36, PT-WB-03 |
| F-DIE | Detect It Easy build fingerprint | SPEC-36 |
| F-WB | Workbench: search (WB1), call graph/xref (WB2), strings (WB3), quick wins (WBQ) | PT-WB-01..04 (PR #43) |
| F-YRX | YARA-X rule synthesis | no spec yet |
| F-KEV | CISA KEV context | no spec yet |
| F-AI | Evidence-cited interpretation | interpretation.py, providers.py |
| F-RPT | Reports and export | reports.py |
| F-UI | Single-window desktop, tooltips | ui.py, tooltips.py, SPEC-04/26 |

## 3. The expert workflow in ordered stages

Order: 0 frame -> 1 acquire pair -> 2 triage artefacts -> 3 normalise and align -> 4 narrow to changed functions -> 5 rank -> 6 read and explain a change -> 7 hypothesise -> 8 validate -> 9 record and report. Stages 4-8 loop; an expert returns to 3 whenever a matching assumption fails. Pitfall ids (P-nn) are indexed in section 5.

### Stage 0. Frame the question

- Questions: What is the target (component, file, version)? Is the goal "what did this patch fix" (advisory-driven), "what changed between two builds" (open-ended) or "is build X vulnerable" (presence)? What does the advisory claim?
- Evidence: advisory text, CVE id, affected product, severity, exploitability (S8, S13), KEV flag (S9), CWE class (S10), KB number.
- Decision: advisory-driven (a CWE-class prior exists) versus open-ended (start from ranking). S4 gives the canonical advisory-driven shape: the patch is the clue to the flaw.
- Pitfalls: P-01 advisory prose taken as function-level truth; P-02 Exploitability Index read as a code signal (S8: not vulnerability-type specific, never revised); P-03 one CVE assumed per patched file (cumulative updates bundle many).
- Mapping: F-KB (CVE-KB-file), F-ENR CVE hints, F-CSAF, F-KEV (GAP, no spec). Goal/mode field (advisory-driven vs open-ended): GAP G-01.

### Stage 1. Acquire a trustworthy older/newer pair

- Questions: Which exact files changed in the KB? Same architecture, same product line, adjacent servicing states? Is a PDB available for each? Do hashes and signing match the claim?
- Evidence: file version and timestamp, hashes, Authenticode, Winbindex/servicing catalog (S13), PDB match info.
- Decision: adjacent builds (least compiler and branch drift) versus the closest pair spanning the fix; add a third build to separate "this patch" from drift.
- Pitfalls: P-04 builds from different servicing branches (feature updates carry unrelated refactors); P-05 a distant base so everything differs; P-06 swapped orientation; P-07 packed versus unpacked mismatch; P-08 file accepted without recorded provenance.
- Mapping: F-ACQ (Winbindex, quarantine, delta), F-ING (immutable copy, hash), F-PEO (signature, version info), F-NWAY (third build). Orientation is an invariant. "Recommend an adjacent pair" from the servicing catalog: GAP G-02.

### Stage 2. Triage artefacts before diffing

- Questions: Packed or protected? Which compiler, linker and flags (toolset, PGO, CFG, /GS)? Do both builds share a toolchain? Do section layout, sizes, imports, exports, resources and version info differ?
- Evidence: PE headers, section table and entropy, imports/exports, debug directory, load-config tables, identifier output (S12 DiE), capa applicability (S11), signature state.
- Decision: proceed with function diff versus stop (packed or obfuscated: unpack under the analyst's own procedure; PatchTrace never executes targets).
- Pitfalls: P-09 diffing a packed file and concluding "everything changed"; P-10 ignoring a toolchain bump (S2: compilation choices materially change similarity); P-11 ignoring PGO/LTO reordering.
- Mapping: F-PEO (partial), F-DIE (spec only), F-HEX. A toolchain-drift verdict as a pre-diff gate: GAP G-03.

### Stage 3. Normalise and align (strip layout, ASLR and address noise)

- Questions: Were both analyses run with the same Ghidra build, analyzers, base address and symbol state? Do relocations, IAT slots, jump tables and thunks explain differences? Are function boundaries identical?
- Evidence: relocation table, image base, `.reloc`, load-config (CFG/GS) tables, IAT, analysis profile (S14 [unverified], S15 F1, F15).
- Technique: compare address-independently: mask relocated, RIP-relative and rel32 operands; canonicalise pseudo-code (alpha-rename locals, substitute FUN_/DAT_ labels with pair ids); order CFG blocks by canonical form to defeat reordering and hot/cold splitting; collapse thunks (S15 R1, R7, F2-F8).
- Decision: a difference is a "cosmetic candidate" only when a normalisation proves equality; otherwise it stays "review", never silently dropped.
- Pitfalls: P-12 raw address/offset flood; P-13 ASLR base mismatch; P-14 over-masking hides an edited immediate; P-15 symbol asymmetry; P-16 ICF folding and function splitting create phantom add/remove pairs; P-17 inlining shifts callee sets (S2: analysis-tool correctness matters).
- Mapping: F-GDF (hunks, `alignment.py`), F-UNI noise filters, F-BDF/F-RZD (second opinions), F-PEO. Project-level profile-symmetry check: GAP G-07 (specified only inside F-UNI).

### Stage 4. Narrow to changed functions

- Questions: Which functions are new, removed, modified, moved? Is the changed fraction small (security-patch shape) or large (drift)? Do engines agree?
- Evidence: per-function match kind and similarity, size delta, instruction/block/call deltas, engine agreement (S5/S6; Ghidriff diff types; rz-diff S7), unmatched residue.
- Technique: seed with exact or unique matches, expand through call-graph neighbours, then resolve ambiguity (S5 describes this class of strategy; S3 adds learned embeddings). Confidence is engine-local.
- Decision: accept high-confidence matches; inspect low-confidence and unmatched manually; use a second engine on disagreement; never average scores.
- Pitfalls: P-18 "unmatched" read as deleted or new; P-19 one engine's similarity read as vulnerability confidence; P-20 mis-pairing small similar functions; P-21 name matching on stripped files; P-22 similarity 1.0 yet behaviour changed through a callee or data (S15 R3, F6).
- Mapping: F-GDF, F-BDF, F-RZD, F-REC (engine-native values kept apart, states E0-E8), F-REV (manual match), F-WB WB2. Uncalibrated scores are shown ordinal, which matches expert caution.

### Stage 5. Rank by likely security relevance

- Questions: Which changed functions touch parsing, length arithmetic, bounds, allocation, lifetime, privilege or type checks? Do names, strings or imports match the advisory component? Is the function reachable from an attack surface the advisory names?
- Evidence: added comparisons or branches before memory operations (the S4 validation-fix signature), new calls to size or safe-string helpers, new error paths, changed constants and imports, advisory words, CWE class, change magnitude, rarity.
- Decision: a short top-K review list; prefer reproducible, explainable ordering over a black box (S2 argues for interpretable features).
- Pitfalls: P-23 ranking by diff size; P-24 an added error string mistaken for the fix (S15 F14); P-25 CFG/GS instrumentation counted as security checks; P-26 anchoring on the first plausible function.
- Mapping: F-ENR ranking and signals (built), F-CSAF intent localization (draft), F-KB, F-CAP, F-FLO, F-WB WB1 phrase search. Reachability from exports: GAP G-05 (WB2 call graph is the substrate).

### Stage 6. Read and explain one change

- Questions: What exactly differs (instruction, branch, call, constant, struct offset, new block)? Semantic or compiler-induced? Which values flow into the changed condition? Who calls it and with what input provenance?
- Evidence: side-by-side disassembly and decompiler output, aligned hunks, operand-delta classes, callee mapping, xrefs, strings and constants.
- Technique: read disassembly when pseudo-code is unstable; use pseudo-code for intent; align by canonical form first.
- Decision: classify as security fix, hardening, functional change, refactor or noise; record the reason, not a number.
- Pitfalls: P-27 decompiler artefacts (variable merges, type recovery) read as logic changes; P-28 different calling-convention inference; P-29 signed versus unsigned comparison misread; P-30 stopping at the first hunk; P-31 unsupported explanation (F-AI citations must resolve).
- Mapping: F-GDF hunks, F-UI diff and evidence navigation, F-HEX (function extents partial), F-WB WB2/WBQ, F-AI (citation validation built), F-UNI typed-change classes (spec). Teaching text per change class: GAP G-09.

### Stage 7. Form hypotheses

- Questions: Which bug class does the change close and what input or state reached it? Does it fit the advisory CWE and component? What is true in the old build and false in the new? What alternatives fit equally?
- Evidence: minimal diff, advisory, CWE class (S10 [unverified]), public source diffs for open-source components, engine disagreement list.
- Decision: keep several ranked hypotheses; record rejections with reasons.
- Pitfalls: P-32 single-hypothesis lock-in; P-33 advisory-fit bias; P-34 one inlined or macro edit counted as many fixes (S15 F10); P-35 hardening mistaken for the CVE fix.
- Mapping: F-REV notes (built), F-ENR hypotheses (`intelligence/hypotheses.py`), F-CSAF. Structured hypothesis record: GAP G-04.

### Stage 8. Validate

- Questions: Does the change recur consistently in a third build? Is it absent from earlier builds? Does a second engine agree? Does the old build lack the check on every path or only one? Do symbols or public source corroborate?
- Evidence: series presence/absence, second-engine result, source parity, boundary-value reasoning, KEV status (confirms CVE exploitation, not function identity).
- Technique: static reasoning on the old build. Dynamic confirmation is outside PatchTrace (never executes targets). S4 shows exploit generation as the strongest confirmation but it is out of scope.
- Decision: mark supported, open or rejected; disagreement stays visible.
- Pitfalls: P-36 same-origin evidence counted twice; P-37 validating on an unrelated pair; P-38 KEV read as proof for this function (S9 is CVE-level); P-39 stale evidence after a re-run.
- Mapping: F-NWAY, F-REC (independence, conflicts), F-BDF/F-RZD, F-REV stale invalidation, F-KEV (GAP G-08). Per-hypothesis validation checklist: GAP G-06.

### Stage 9. Record, report, hand off

- Questions: Can another analyst reproduce this from files and settings? Which claims are evidence-backed, which inferred, which unknown?
- Evidence: project revision, tool versions and arguments, hashes, run logs, citations.
- Pitfalls: P-40 certainty beyond evidence; P-41 lost provenance on re-run; P-42 overwritten prior results.
- Mapping: F-RPT (JSON/Markdown/HTML, manifests), persistence revisions and backups, F-REV, diagnostics. Strength wording: calibration `display_level()` is ordinal until gates pass.

## 4. Decision-point catalogue

| ID | Decision | Inputs experts weigh | Safe default for the teacher | Feature |
|---|---|---|---|---|
| D1 | Advisory-driven vs open-ended | CVE/KB known? | Ask once; record the goal | GAP G-01 |
| D2 | Which build pair | Adjacent state, same branch, symbols | Adjacent; offer a third build | F-ACQ, F-NWAY |
| D3 | Proceed vs unpack/stop | Entropy, imports, DiE verdict | Stop and say why | F-PEO, F-DIE |
| D4 | Trust auto matches? | Confidence, agreement, unmatched share | Spot-check low confidence and size-ratio outliers | F-GDF, F-REC |
| D5 | Is the diff noise? | Reloc, ASLR, layout, toolchain drift | Cosmetic only with proof, else review | F-UNI |
| D6 | Second engine needed? | Disagreement, unmatched share | Yes on conflict | F-BDF, F-RZD |
| D7 | Which functions first | Ranking, advisory words, CWE-shaped edits | Top-K with reasons shown | F-ENR, F-CSAF |
| D8 | Disassembly vs pseudo-code | Decompiler stability | Disassembly decides, pseudo-code explains | F-GDF view |
| D9 | Hypothesis accepted? | Third build, second engine, source parity | Require two independent supports | F-NWAY, F-REC |
| D10 | Ready to report? | Open conflicts, stale items | Block on stale evidence | F-REV, F-RPT |

## 5. Pitfall index (false leads and common mistakes)

| ID | Pitfall | Cause (source) | Guard in PatchTrace or teaching |
|---|---|---|---|
| P-01 | Advisory trusted as function-level truth | Component-level text (S8) | Advisory is untrusted data; evidence links only |
| P-02 | Exploitability rating read as code signal | S8 | Vendor-context chip; never in a score |
| P-03 | One CVE per file assumed | Cumulative updates | F-KB many-to-many |
| P-04/05 | Wrong or distant pair | Servicing branches | Pair advisor (G-02) |
| P-06 | Orientation swapped | Manual picking | Explicit older/newer (invariant) |
| P-07/09 | Packed or protected input | Entropy, few imports | F-PEO preflight, F-DIE |
| P-10/11 | Toolchain or PGO drift | S2 | Drift banner (G-03) |
| P-12 | Address/offset flood | Relocation, rebasing | Masked hash (F-UNI) |
| P-13 | ASLR base mismatch | `/DYNAMICBASE` (S14 [unverified]) | Same-base analysis profile |
| P-14 | Over-masking | Hides immediate edits | Mask only address-like operands |
| P-15 | Symbol asymmetry | PDB on one side | Record symbol provenance |
| P-16 | ICF/split phantom add-remove | Linker folding | Added/removed reconciliation (S15 F11) |
| P-17 | Inlining shifts callees | Optimiser | Containment test |
| P-18 | Unmatched read as deleted | Absence of evidence | "Unknown" state (invariant) |
| P-19 | Engine score as vulnerability confidence | Engine-local scale | Ordinal display; no cross-engine average |
| P-20 | Mis-pairing small functions | Low information | Size floor routes to review |
| P-21 | Name matching on stripped files | Names are the strongest identity signal when present | Record name provenance |
| P-22 | "Identical" yet behaviour changed | Callee or data changed | Callee map (S15 F6) |
| P-23 | Rank by diff size | Refactors | Rarity weights, typed change |
| P-24 | Added string taken as the fix | Logging | S15 F14 downgrade |
| P-25 | Instrumentation as security check | CFG/GS stubs | Idiom recognition (S15 F15) |
| P-26/32/33 | Anchoring, one hypothesis, advisory-fit bias | Human factors | Competing-hypothesis record (G-04) |
| P-27/28/29 | Decompiler artefacts | S2 tool correctness | Disassembly side by side |
| P-30 | Stopping at first hunk | Fatigue | Hunk checklist |
| P-31 | Unsupported explanation | Gap-filling | Citations must resolve (built) |
| P-34 | Duplicate edits counted independently | Macros, inlining | Edit-group dedup (S15 F10) |
| P-35 | Hardening mistaken for the fix | Bundled changes | Typed-change classes |
| P-36 | Same-origin evidence counted twice | Shared engine or data | Independence groups (invariant) |
| P-37/38 | Wrong validation target; KEV over-read | CVE-level only (S9) | KEV as context only |
| P-39 | Stale results after re-run | Preserved-prior policy | Stale invalidation (built) |
| P-40..42 | Overclaiming, lost provenance, overwrite | Process | Reports, revisions, backups |

## 6. Mapping summary and gaps

Legend: B built on main, P partial, S spec only, G gap (no spec).

| Need | Feature | State |
|---|---|---|
| Ingest pair, hash, immutable copy | F-ING | B |
| Header, section, import triage | F-PEO | P |
| Build fingerprint, packer/compiler | F-DIE | S |
| Acquire adjacent build | F-ACQ, F-KB | P / S (PR) |
| Function diff and hunks | F-GDF | B |
| Second and third engine | F-BDF, F-RZD | P |
| Evidence reconcile, conflicts kept | F-REC | P |
| Noise reduction | F-UNI | S (S0a only) |
| Ranking and CVE hints | F-ENR | P |
| Advisory intent localization | F-CSAF | S |
| Capability deltas | F-CAP | S |
| Strings per side | F-FLO, WB3 | S / PR |
| Search, call graph, xrefs | F-WB | S / PR |
| Multi-build validation | F-NWAY | B / P |
| Review notes, manual match | F-REV | B |
| Evidence-cited explanation | F-AI | B |
| Report and manifest | F-RPT | B |
| Rule synthesis | F-YRX | G |
| Exploitation context | F-KEV | G |

Gaps for the guide (E-5) and spec amendments:
1. G-01 Investigation goal and mode (advisory-driven vs open-ended) is not stored.
2. G-02 Pair advisor (adjacent build, same branch, drift warning).
3. G-03 Toolchain-drift verdict as a pre-diff gate.
4. G-04 Structured competing-hypothesis record with accept/reject reasons and evidence links.
5. G-05 Attack-surface reachability (exports to changed function) over the call graph.
6. G-06 Per-hypothesis validation checklist derived from available evidence (third build present, second engine run).
7. G-07 Analysis-profile symmetry check at project level, not only inside the unified engine.
8. G-08 KEV and Exploitability Index as context-only chips, never scores.
9. G-09 Teaching text per typed change class and per pitfall id.

## 7. Notes for the deterministic teacher (E-5)

- The stage order in section 3 is a candidate lesson spine; every step links to one mapped feature; stages mapped GAP say "not available yet" rather than inventing behaviour.
- The teacher asks the "Questions" lists as prompts and reads answers from project state where it exists (hashes, orientation, engine agreement), never from a model.
- Pitfall ids give a stable, testable catalogue; each can be a rule firing on observable project state (P-06 orientation not explicit; P-18 unmatched shown as removed; P-36 two views of one engine counted twice).
- Do not state `[practice, unverified]` material as established; cite S1-S9 where possible.

## 8. Open verification items

- Re-fetch S5 ("Understanding BinDiff" text), S6, S10, S12, S14 from an unrestricted host and replace L-confidence rows.
- Read S1 (patch-analysis taxonomy) and S2 (per-feature robustness numbers) in full before quoting any figure.
- Confirm whether S4's input-check technique generalises beyond input-validation bugs; the authors caveat its limits.
