# KB integration plan: one KB -> CVE -> product -> binaries workflow (track KB)

Status: Program E research plan, 2026-10-14, base `prep/program-e` d972125. Documents only; nothing here is built.
K2 (workspace store, attach, reducer, recovery) built 2026-10-14 in `kbcorrelation/{store,workflow,recovery}.py`.
Merges **SPEC-34** (KBC: `docs/specs/kb-cve-correlation-and-acquisition.md` + `kb-cve/31-A..H`, self-numbered "SPEC-31") and **SPEC-37** (KPS: `docs/specs/kb-patch-search-*.md` + `docs/plans/kb-patch-search-*.md`, self-numbered "SPEC-32"). The self-numbers collide with real SPEC-31 (unified engine) and SPEC-32 (known-answer corpus).
External-source facts are verified by worker KB2 in `docs/specs/program-e/KB2-source-facts.md` (parallel, not awaited) and earlier in `docs/research/kbcve/{msrc-sources,winbindex-servicing-catalog}.md` (RK1, RK2). Tags: [own] read or measured by me on 2026-10-14; [unverified] not confirmed (host blocked or not testable here).

## 1. Verdict and scope
1. Build ONE feature: pure package `patchtrace.kbcorrelation` + one dock `ui_kb.py`; contract `kbcorrelation/1`; errors `PT-KBC-*`; CLI group `patchtrace kb`; ONE store module and record schema (`kbc-store/1`) with two physical roots: a per-user workspace, and the project through the existing enrichment pointer-row mechanism. KBC is the base; KPS contributes finite `SearchScope` and coverage words, the CVRF Type-2 per-product join, two-phase attach, the fixture manifest and CLI verbs. SPEC-37 becomes a read-only annex (7.1 resolves 18 overlaps).
2. E0 first (offline): import locally saved MSRC CVRF / CSAF files, search a KB or CVE, pick a product, name a file, supply two PE files you already hold, create the project, read the documentary context, run the existing comparison, read CVE-grouped leads. No code that opens a socket exists until E1.
3. Value (measured, section 5): product scoping keeps the right change on top (`read_item` 36 vs `alloc_items` 25); the existing CVE-first `correlate`, fed the bulletin's CVE list that includes one CVE not applicable to the client, shows 36 vs 35. KEV, CWE hypotheses, advisory anchors and engine evidence sit on one lead row as independent channels, never summed.
4. Not built: a KB->files index (none exists), Update Catalog scraping, MSU/CAB/PSF/DISM reconstruction (E3, separately gated), catalog-signature trust, probability or "fixed/patched" wording, a new HTTP library or dependency, a second CSAF parser or rule engine, a separate window.

## 2. Sources and facts
| claim | source | retrieved | confidence |
|---|---|---|---|
| No documented query-by-KB route. CVRF v3: `GET /cvrf/v3.0/Updates?api-version=2023-11-01` (bare array, OData date `$filter`) and `/cvrf/{yyyy-Mmm}`; swagger has 9 paths, none takes a KB | `docs/research/kbcve/msrc-sources.md` s1,s3 (copy of the MSRC API repo `docs/swagger.json`, SHA-256 1632aa08...) | 2026-10-14 | high |
| KB appears as `Remediations[Type==2]` (`Description.Value`, may be multi-line; optional `FixedBuild`, `Supercedence`, `SubType`); Type 5 = known issue; real JSON shape unobserved | RK1 s3 (MIT PowerShell sources); KB2 pending | 2026-10-14 | medium; shape [unverified] |
| A revised CVE stays in its original monthly document (CVE-2024-38063: release 2024-Aug, revised 2024-09-10), so coverage needs two axes: document id and `currentReleaseDate` | RK1 s2,s3; `tests/fixtures/cve/msrc_CVE-2024-38063.json` | 2026-10-14 | medium |
| SUG v2 per CVE gives `releaseNumber`, `tag`, `cweList` but no KB or product rows | RK1 s1 #8 | 2026-10-14 | medium |
| CSAF file names carry the CVE id (`discovery.matches_cve`, discovery.py:121): CSAF is CVE-first; KB-first would scan the whole index. Microsoft's layout is unobserved | [own]; RK1 s1 #10-13 | 2026-10-14 | medium; layout [unverified] |
| Winbindex: no KB index; Windows 10/11 client x64 only (Server-only KBs absent); `windowsVersions.<ver>.<KB>`, `otherWindowsVersions`, `BASE`; file version equals the KB build in 152 of 1102 rows, timestamps unordered | RK2 s1-s2 (measured on afd.sys) | 2026-10-14 | high |
| The current parser flattens version<->KB pairing and skips entries without `fileInfo.sha256`: on the committed excerpt 3 of 6 entries are skipped, exactly the newest builds (KB5126651/53/57) | [own] winbindex.py:98-135, run on `tests/fixtures/kbcve/windows/afd.sys.excerpt.json` | 2026-10-14 | high |
| Winbindex data is GPL-3.0 (runtime fetch only; trimmed test excerpts). Update Catalog has no documented API and its terms were unread | RK2 s1.4, s3 | 2026-10-14 | high / medium |
| MSRC website terms restrict copying documents; API terms unread: commit synthetic fixtures with hash-only provenance, no real MSRC bytes | RK1 s2, s6 item 7 | 2026-10-14 | medium |
| `ProjectStore.backup` copies only `artifacts`, `runs`, `exports`: the `intelligence/csaf/*` sidecars are not backed up today | persistence.py:522 | 2026-10-14 | high [own] |
| `ProjectStore` needs `user_version==1`; additive tables at the same version are the established pattern; `KINDS` reserves 7 Phase-D kinds and none for KB; non-DERIVED kinds are never evicted; caps 32 MiB/row, 128 MiB/project | persistence.py:310; enrichment/storage.py:1-12,37-48 | 2026-10-14 | high [own] |
| Three transports with hard-coded allow-lists: acquisition {winbindex.m417z.com, msdl.microsoft.com}; enrichment {api.msrc.microsoft.com per-CVE template only, 4 MiB cap; NVD}; CSAF {msrc.microsoft.com, `/csaf/` paths, query strings refused}. A monthly CVRF fetch fits none | transport.py:28-31; intelligence.py:42,53-57; csaf/transport.py:31-32,72 | 2026-10-14 | high [own] |
| `intelligence/` (SPEC-28a/b) EXISTS: `AdvisoryStore.add`, `applicability.resolve`, `lexicon.classify(CVEFact)`, `hypotheses_for`, `anchors_for(AdvisoryFacts)`; KBC s0, `kb-cve/README.md` and 31-E E1 say it does not. `IntelligenceReport.sources` needs >=1 CSAF source and `Anchor.source` has no CVRF value (contracts.py:547,574): CVRF-only CVEs need KB-owned composition | intelligence/*.py; docs/modules.md [K:28a-28b] | 2026-10-14 | high [own] |
| `AcquisitionDialog` is one QDialog (ui.py:288-686): download closure 593-666, GUI-thread `quarantine.promote` 668-686. Reuse the service path, not the widgets. `ProjectService.create` removes its database on failure (service.py:48-56) and `promote` records provenance as prefixed notes (quarantine.py:115-136): the project step is atomic, the attach after it is a separate commit | ui.py; service.py; quarantine.py | 2026-10-14 | high [own] |
| Dock pattern: `EvidenceDock`, `EvidenceController`, `WindowPort`, `_LIVE_THREADS`, QSettings geometry, hooks at ui.py:1504, 1984, 2985, 3113 | ui_evidence.py:130,1192-1330 | 2026-10-14 | high [own] |
| `tests/test_tooltips.py:188-255` audits every focusable control and every registry id reachable from `MainWindow`: KB widgets must exist eagerly, with objectName, accessible description and `kb.*` tooltips | tests/test_tooltips.py | 2026-10-14 | high [own] |
| CLI contract: `COMMANDS`/`HANDLERS`/`_command_name`, envelope `enrichment-cli/1`, exit 0/2/3/4/5, `--consent-hosts` must equal the planned set | cli.py:16-18,490-493,817-822 | 2026-10-14 | high [own] |
| Measured reuse check: a CVRF-shaped `CVEFact` through `lexicon.classify` and `hypotheses_for` gives CWE-125 -> R-MEMORY-READ and CWE-190 -> R-INTEGER; negated text with no CWE gives status `vague` and no hypothesis (explicit unknown) | scratch script on `intelligence.*` | 2026-10-14 | high [own] |
| Measured, SQLite 3.45.1, 1M synthetic edges: dictionary-encoded 36 B/row vs text 192 B/row; KB lookup 0.25-0.4 ms; insert 8.8 s | scratch benchmark | 2026-10-14 | high on this machine |
| Measured: strict JSON parse costs 7.1x the raw size in memory, 0.025 s/MB (33.7 MB: +240 MB, 0.8 s). Cap 32 MiB raw in-process; larger needs a memory-capped child (C3 pattern) | scratch benchmark | 2026-10-14 | high on this machine |
| Install and provisioning: stdlib + pinned PySide6 6.12.0 (LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only), pydantic 2.13.5 (MIT), Python >=3.12; no new dependency, `--only-binary=:all:` unaffected; no data file to package (the product alias catalog is a Python module, digested with `identity.constants_digest`); no external executable; Windows and Linux identical | pyproject.toml:8-9; enrichment/identity.py:154; installed metadata | 2026-10-14 | high [own] |
| Security notes: advisory and index text is untrusted: strict JSON loader (duplicate keys, non-finite numbers, depth), size caps (7.4), plain-text rendering only, escaped exports; no target binary is executed; nothing is uploaded; no credential is stored | AGENTS.md; `persistence.strict_json` | 2026-10-14 | high [own] |
| Qt accessibility, QDockWidget, QAbstractTableModel, UI Automation, WCAG 2.2 (1.4.1, 1.4.11, 2.1.1, 2.4.3, 4.1.3): doc.qt.io/qt-6/accessible.html, learn.microsoft.com/en-us/windows/win32/winauto/uiauto-uiautomationoverview, w3.org/TR/WCAG22/ | hosts returned 403 to CONNECT (egress policy) | 2026-10-14 | [unverified]; behaviour corroborated by C6 measurements on PySide6 6.12.0 (`multi-engine-evidence-panel.md` s1.8, s5.1) |
| CISA KEV schema and terms; SQLite `BEGIN IMMEDIATE` docs (sqlite.org) | hosts blocked; KEV is owned by the KEV plan + KB2 | 2026-10-14 | [unverified] |
If KB2 contradicts a row above, the row and its dependent gate change (K1 dialect, K5 rules, 7.4 limits); the architecture does not rest on any single external field.

## 3. Standalone baseline versus PatchTrace value
| tool alone | gives | lacks (what the combined product adds) |
|---|---|---|
| MSRC SUG / CVRF / CSAF | vendor KB<->CVE<->product claims, CWE text, revisions | KB->file, build lineage, bytes, any statement of coverage |
| Winbindex | per-file builds, SHA-256, KBs, symbol-server availability | CVE meaning, KB->files, Server-only builds |
| Update Catalog | official packages by KB | API, full PE files, automation |
| Ghidriff / BinDiff / rz-diff / unified | matched function diffs | advisory meaning, priority, thousands of changes per cumulative update |
| CISA KEV | CVE-level exploitation flag | product, build, file, code |
| `patchtrace correlate` today | CVE text rerank, at most +30 | the right CVE set, product scoping, coverage, pair provenance |

Pipeline (each arrow is recorded and replayable; each box keeps its own state; nothing is merged into one score):
`Lead(KB/CVE/file/pair) -> SearchScope+Coverage -> KbCveEdge[product-scoped] -> ProductScope (analyst picks) -> ComponentHint[tier A-E] -> BuildRow[index claims] -> PairProposal[grade A/B/X] -> PairPlan[exact requests, consent] or local files -> verified bytes -> ProjectService.create -> attach -> ContextReport -> existing run/rank/evidence -> LeadRow[CVE groups]`

Workflows: **W1** KB-first with files at hand (E0). **W2** CVE-first (SUG/CSAF) -> KBs per product -> continue at Files. **W3** project-first: open a project, enter a CVE/KB, attach with an "applicability unverified" banner, never reorienting the pair. **W4** KB-first online (E1): sync months -> Winbindex rows -> "changed in this KB" -> download -> project. **W5** confounded window: list the intervening updates and point to the Series window; never auto-create projects. **W6** partial outcomes keep their value: metadata only, needs filename, needs older/newer, delta only, index gap.

### 3.1 From a KB number to ranked candidate pairs (synthetic: KB5099001, Example OS 24H2 amd64)
A KB number alone never yields files (no KB->file index exists), so candidates come from analyst names (tier E), explicit module names in advisory text (A/D), or later curated or package data (E3). A CVE lead first lists its KBs per product from the index (or CSAF), then continues the same way.
Tiers say how much file association is documented, never how likely a fix is: **A** explicit file name in a structured official field (essentially absent from MSRC data, RK1 s5); **B** package inventory (E3); **C** index row for a name already given; **D** advisory title or tag hint, a search suggestion that never selects a file; **E** analyst-entered. Ranking is lexicographic, never arithmetic: `(blocked last, changed_in_kb yes<unknown<no, grade A<B, tier A<B<C<D<E, known intervening updates ascending, availability local<direct<candidates<delta-only, basename, older_sha, newer_sha)`.
| # | file | tier | changed in KB5099001 (index claim) | pair | window | line shown |
|---|---|---|---|---|---|---|
| 1 | exampledrv.sys | E analyst | yes: SHA differs from the previous row (KB5098000) | A index-adjacent, bytes pending | 0 known, completeness unknown | "Index lists a new build in this update. A hash match proves the index record, not the vendor." |
| 2 | examplenet.sys | E | no: SHA unchanged since KB5097000 | B wider window | 2 known | "Did not change in this update; last changed in KB5097000. A wider comparison is yours to approve." |
| 3 | corepath.dll | E | unknown: no row for this version key | X no older build | - | "Not in the file index (Windows 10/11 client x64 only)." |

Coverage words (same in CLI and GUI): `complete_in_scope`, `partial_in_scope`, `stale_cache`, `unknown_scope`, `not_searched`, rendered "Checked N documents (first to last); F unreadable; nothing else was checked" and never "no CVEs for this KB".

## 4. Cross-feature links
Roadmap s3 charter: pair-aware (`PairProposal` keeps explicit older/newer); delta (`changed_in_kb`, window, unknown != absent); anchors in/out (below); triage (channels listed, never summed); one click to code (`LeadRow.nav` -> `WindowPort.select_match`); provenance (`SourceRef` pointers, `plan_sha`, parser and rules digests); offline-first (E0); teachable (`hooks`, 7.2); synergy test (section 5).
| anchor / evidence | KB emits | KB consumes | other tracks | how |
|---|---|---|---|---|
| KB (`kb:KB#######`, scope) | edges, investigation | - | FAB, WB1, GDE | typed pivot "CVEs and files of this KB" |
| CVE (lineage `msrc`) | documentary edge, card | SUG/NVD `CveSnapshot` via `correlate` | KEV (join key), PIL, FAB | KEV lookup key; contextual rerank input; PIL ruleset input |
| CWE (stated vs derived) | `lexicon.classify` of the CVRF adapter | CSAF `cwe` | CAP, YRX, FAB | hypothesis family; detector alignment `CWE_DETECTORS` (cve.py:70) |
| advisory phrase (pointer, sanitized excerpt <=200) | title and note excerpts | - | WB1 (field `advisory`), GDE, YRX provenance | indexed text; click returns to the Context pane |
| module / file (tier A-E) | `ComponentHint` | `pe_overview` names, imports | WB3, CAP, DIE | chip "module named in advisory equals artifact name" |
| API hint | from `hypotheses_for(...).api_hints` | import deltas (`pe_overview`), unified IR call refs | CAP, UE | chip "API hint present among new imports" (hint only) |
| string hint | quoted advisory text (quality derived) | WB3 per-side string delta | WB3 | chip "string appears only in newer" (hint only) |
| capability | - | CAP deltas | CAP | chip "capability delta consistent with family" if CAP publishes a family map |
| rule (`R-*@rev`, `rules_digest`) | selected hypotheses | - | YRX, GDE | stable ids in leads and exports |
| build fact (scope, version key, KB, build.UBR, SHA) | `BuildRow` claims, `BinaryRef` | `ArtifactIdentity` (VS_FIXEDFILEINFO) | nway, UE keys, DIE | lineage, window, Series hand-off |
| function pair (SHA, RVA) | - | unified rows, Ghidriff matches, secondary verdicts | UE, FAB | lead subject; contested stays contested |
| exploitation (`kev:CVE,date,snapshot_sha`) | - | `ExploitationLookup` port | KEV | group header chip only; never row order |
| pair (`pair:older,newer,scope`) | `PairProposal`, `ProjectLink` | series windows | nway, UE | open in Series; unified key inputs |

Lead assignment is rule-based: a function joins CVE group G when a detector signal of G's CWE family (aligned by `CWE_DETECTORS`) or a unified MAT-ANCHOR fact fires on it, or an anchor coincides; several groups are allowed; the rest go to "unattributed". Groups sort by (KEV listed, supporting channel set, CVE id); inside a group the engine's own order is kept.
The resolved pair is only an ordinary project: Ghidriff, BinDiff, rz-diff and the unified engine run through the existing project path and never learn KB ids. OLD/NEW applicability comes from `intelligence.csaf.applicability.resolve` over the project's two verified identities (`unknown` when no CSAF document exists); a CVRF `FixedBuild` is shown beside it and never merged into it.
Ports (Protocols in `kbcorrelation/ports.py`, bound only in `wiring.py`; each has a null implementation answering "not loaded", so no track blocks another):
- `AdvisoryFactsPort.facts_for(cve) -> tuple[AdvisoryFacts]` (workspace copy, or project `AdvisoryStore`).
- `ExploitationLookup.status(cve) -> KevFact | 'not-listed' | 'no-snapshot'`; `KevFact(cve, date_added, snapshot_sha256, snapshot_retrieved_at, vendor_product_text)` (KEV plan owns the real fields).
- `EngineEvidence.read(project) -> EngineView`: rows `(match_id, names, older_sha, newer_sha, rvas, attention_rank?, signals[(detector, confidence, group_key, lineage)], unified_decision?, secondary_verdict?)`, bound to `enrichment.pipeline.load_default`, `secondary.evidence_panel_service.load_evidence`, later `unified.read_model`.
- `AdvisoryTextSource.documents(project) -> Iterable[AdvisoryText(doc_id, title, body<=64 KiB, ref)]` (KB provides, WB1 consumes); `AnchorSink.publish(project_key, anchors)` (FAB); `WinbindexRows`, `Transport`, `ProjectCreator`, `Clock`.

## 5. Synergy test: `tests/test_kbc_synergy.py` (E0 form in K4a; KEV, WB1, FAB form in K8)
All inputs synthetic, test hermetic (socket denied).
- (a) `cvrf-2099-Feb.json` (dialect `cvrf-json/0`, shape per RK1 s3, unverified against a live capture): products PT-CLIENT "Example OS 24H2 x64", PT-CLIENT-ARM, PT-SERVER. CVE-2099-20001 (CWE-125 stated; note "out-of-bounds read in the item reader"): Type 2 "5099001" for PT-CLIENT and PT-CLIENT-ARM, "5099002" for PT-SERVER. CVE-2099-20002 (CWE-190): PT-SERVER only, "5099002". CVE-2099-20003: a Type 5 known-issue text that mentions KB5099001.
- (b) `kev-synthetic.json`: 20001 listed 2099-02-12; 20002 not listed.
- (c) `tests/kbc_helpers.two_cve_project()`: `synthetic_pe(0/1)` stored as `exampledrv.sys`; diff with `read_item` (null/index guard), `alloc_items` (`0xffffffff / count < size` guard before `ExAllocatePool2` and `memcpy`), `get_version` (1 to 2), added `report_invalid_index`, removed `debug_dump`.

Measured today on that project with existing tools only (the `tests/kbc_helpers.py` docstring records the commands: `python -m patchtrace rank P --dry-run` and `correlate P --cve ... --snapshot F --dry-run`, with one `CveSnapshot` per CVE carrying a single msrc CWE, retrieved 2099-02-14):
- `rank --dry-run`: read_item 26, alloc_items 25, report_invalid_index 0, get_version 0, debug_dump 0 (a one-point gap, no CVE meaning).
- `correlate --cve 20001`: read_item 36 (+10 via CWE-125), alloc_items 25.
- `correlate --cve 20001 --cve 20002` (what a user pastes from the bulletin): read_item 36, alloc_items 35 (+10 via CWE-190 of a CVE that does not apply to the client).
The test asserts the shape, not the integers (both aligned functions within 2 points, others 0); exact scores go to the golden as provenance, so a later engine re-tune fails only the golden.

| channel alone | result | missing |
|---|---|---|
| KB / CVRF only | KB5099001 -> 20001 for client and ARM64 (ARM64 is not analyzable); 20002 absent; 20003 "mention only"; coverage `complete_in_scope`, 1 document | file, code |
| engine only | the ranking above | CVE, priority, which change matters |
| CVE-first correlate | 36 vs 35 with the wrong CVE | product scope, coverage, KEV |
| KEV only | 20001 listed | product, code |

Expected combined `kb leads` (deterministic golden `tests/fixtures/kbcorrelation/expected/synergy-leads.json`):
```
GROUP CVE-2099-20001  KEV listed 2099-02-12 | CWE-125 stated by vendor | hypothesis R-MEMORY-READ
  1 read_item     supports: hypothesis alignment (BND), observed guard comparison | attention order 1 of 5 (native, not likelihood) | go to match <id>
GROUP unattributed (always visible)
  2 alloc_items   no applicable CVE: its aligned CWE-190 CVE-2099-20002 lists Example Server only | attention order 2
  3 report_invalid_index (added)   4 get_version   5 debug_dump (removed)
NOT APPLICABLE  CVE-2099-20002 (Example Server only)        MENTION ONLY  CVE-2099-20003
```
Assertions: no group for 20002 and no context contribution from it (the 35 above never appears); with KEV removed the header reads "KEV: not loaded" and row order is identical (`test_kev_never_changes_function_order`); inside-group order equals engine order; no number except the labelled attention order; banned-word sweep clean; coverage line on every view; `kb leads` leaves the project snapshot SHA unchanged.
Negative controls: swap orientation -> every lead stale, navigation off; add a contested BinDiff row for read_item -> chip "contradicts: engines disagree", membership kept; drop the run -> context only, state "no comparison yet"; drop CVRF -> engine order alone, state "no advisory loaded".

## 6. Traps and guards
| trap | guard | test |
|---|---|---|
| KB in prose becomes a remediation | only `Remediations[Type==2]` with a validated KB per line; else `mention-only` | `test_cvrf_type5_mention_never_edge` |
| explicit "not affected" for the same CVE and product | edge becomes `disputed`, left out of leads, both shown | `test_product_status_disputes_edge` |
| revision lag hides KBs shipped later for older CVEs | two-axis coverage + copy "revised CVEs may sit in earlier documents" | `test_coverage_two_axes` |
| empty partial scan reads "KB has no CVEs" | state `partial_in_scope`/`not_searched`; exit 3 not 4; wording "not found in N documents" | `test_partial_never_zero_cves` |
| bulletin-wide CVE list mixes products | edges are product-scoped; unselected scope excluded with a reason (measured 36 vs 35) | `test_synergy_two_cve_kb` |
| unknown dialect parsed as empty | unknown dialect = `PT-KBC-SOURCE`; parser version in the cache key | `test_cvrf_unknown_dialect_is_error` |
| index skips the newest builds | `parse_rows` uses the dict key; copy "N index rows skipped (newest builds may be missing)" | `test_md5_only_rows_kept` |
| file version or timestamp used as chronology | order by (version key, releaseDate, releaseVersion); show confounders | `test_order_ignores_file_version` |
| same SHA in several KBs read as "introduced here" | `changed_in_kb` needs the first row of the SHA run; else "last changed in X" | `test_unchanged_in_kb_is_not_a_pair` |
| client and server share a SHA, read as one product | scopes compared by `scope_id`; Server not covered by the index -> hard block | `test_pair_never_auto_across_scope` |
| hash match shown as authentic | only `hash-matched-to-index` / `signature-unknown`; never "trusted" or "signed" | banned-word sweep |
| KEV read as "this function is exploited" | CVE-level chip; product text informational; absence = "not in snapshot D" | `test_kev_never_changes_function_order` |
| hypothesis read as a fix | counterexamples always shown; banned set `probab, likelihood, confidence, proven, certain, safe, secure, is fixed, was fixed, patched, exploitable` | `test_kb_strings_banned_words` |
| SUG + CVRF + CSAF counted as three votes | one lineage `msrc`; "1 source family" | `test_lineage_counts_once` |
| local file claiming to be Microsoft | `unverified-local-file` on every derived row | `test_local_import_never_verified` |
| consent drift (URLs found later) | `plan_sha` binds consent; a new URL => needs additional consent | `test_consent_binds_plan_sha` |
| stale after swap orientation or new run | fingerprint holds ordered SHAs, project revision, run id; stale banner, navigation off | `test_leads_stale_on_swap` |
| backup misses KB or CSAF sidecars | amend `backup()`; verified round trip | `test_backup_includes_kb_sidecars` |
| UI deception: colour-only badges, tooltip-only limits, auto-run, auto-selected top pair, silent empty table | text+glyph badges; limits in body text; no auto-start; explicit selection; coverage line always | `test_ui_kb_no_color_only_state` |
| huge or hostile input: gzip bomb, depth, bidi, a 10-digit "KB" | caps (7.4), `strict_json`, `sanitize_text`, `PlainLabel`, escaped exports | `test_hostile_advisory_text_plain` |
| CLI and GUI write the workspace together | `BEGIN IMMEDIATE`, `busy_timeout=5000`, typed busy error | `test_two_writers_one_wins` |

## 7. Contracts
### 7.1 Reconciliation (what each spec said, and the decision)
| # | topic | KBC | KPS | decision |
|---|---|---|---|---|
| 1 | names | `kbcorrelation`, `kbcorrelation/1`, `PT-KBC-*`, `kb`, `test_kbc_*` | `patch_search`, `patch-search/1` (+`patch-pair-plan/1`, `patch-triage/1`, `patch-search-sidecar/1`), `PT-PATCH-*`, `patch`, `test_patch_*` | KBC names; KPS-only codes become `PT-KBC-SCOPE/STORAGE/LIMIT/STATE` |
| 2 | numbering | SPEC-31 | SPEC-32 | registry SPEC-34 base, SPEC-37 annex; fix the headings (A-1, A-3) |
| 3 | KB syntax | 4-10 digits, prefix optional in UI | 4-9 digits, bare digits accepted | canonical `KB`+4-10 ASCII digits (a superset), bare digits only at the CLI/GUI edge, no numeric cast, leading zeros kept, `kb-syntax/1` |
| 4 | search scope | default 24 months, max 60, implicit | always explicit, max 24, `scope_required` | always explicit and finite; UI pre-fills 12 months; max 24 months per plan; the 60-month index ceiling is reached by repeated plans |
| 5 | coverage | `complete=false`, "not observed" | five `SearchCoverage` states | KPS states + KBC per-document segments + RK1 two axes + constant `exhaustive_for_history=False` |
| 6 | relation | 6 relations | confirmed/proposed/conflicting/unknown | store KBC's 6; derive display labels; "confirmed" is never shown |
| 7 | sources | SUG, CVRF (deferred), CSAF | CVRF Type 2 first | CVRF month = KB-first (E0 import, E1 fetch); CSAF = CVE-first + applicability (built); SUG = context only; one lineage |
| 8 | storage | ProjectStore tables or extension + global cache | `patch_search.sqlite3` beside the project | neither: see 7.3. Pointer rows give backup, staleness and retention; a sidecar DB would be missed by `backup()` and adds a third mechanism |
| 9 | attach | one transaction | two-phase, `CONTEXT_PENDING`, idempotent repair | two-phase + workspace journal |
| 10 | pair state | AUTO_VERIFIED / USER_ASSERTED + reasons | one enum mixing three proofs | `bytes_state`, `lineage_state`, `fix_boundary` orthogonal + `reason_codes` + ordering grade A/B/X |
| 11 | state machine | NEW..ANALYZED | DRAFT..TRIAGE_AVAILABLE | one pure reducer (7.5) |
| 12 | UI | six-page dialog, "Investigation" menu | 8-step dialog + dock, File>New | one dock, six tabs, Project menu, no dialog |
| 13 | acquisition reuse | shared controller or prefilled dialog | dialog unchanged | new pure `acquisition/workflow.py` used by KB; dialog refactor optional, last |
| 14 | rules | SPEC-28/30 optional adapters | own `hypotheses.py`, `correlate.py` | reuse built `intelligence.*` through ports; PIL later through the same port |
| 15 | limits | 64 MiB doc, 250k nodes, 600 docs, 2 concurrent | 32/128 MiB, 25k nodes | `KbcLimits` (7.4), from the measured 7.1x memory |
| 16 | signatures | 5 states | 6 states | KBC's 5; E0-E2 emit `hash-matched-to-index`, `signature-unknown`, Windows `embedded-signature-valid` |
| 17 | fixtures | `fixtures/kbcorrelation/` | `fixtures/patch_search/MANIFEST.json` | KBC directory + KPS manifest (hash, UTC, origin, licence, test); synthetic only |
| 18 | packages | 31-D phases | P8 | E3, off the critical path |

Name map: EvidenceOrigin / SourceDocument / SourceSnapshot / SourceReference -> `SourceDoc` + `SourceRef`; UpdateVariant / ProductScope -> `ProductScope`; BinaryCandidate / BinaryRef / BinaryIdentity -> `BinaryRef`; PairAssessment / PairProposal / PairCandidate / PairDecision -> `PairProposal`; KBInvestigation / PatchSearchSession -> `InvestigationRevision`; SourceCoverage / LookupCoverage / SearchCoverage / SearchOutcome -> `Coverage`; Outcome / OperationResult / PatchIssue / KbError -> `OperationResult` + `KbcIssue`; DownloadPlan / PairAcquisitionPlan -> `PairPlan`; PatchHypothesis -> `intelligence.PatchHypothesis`; PatchLocalization / CorrelationAssessment -> `LeadRow` / `ContextReport`.

### 7.2 Records (pydantic 2.13.5 strict, frozen, extra=forbid; `contract: Literal['kbcorrelation/1']`; reuse `Sha256, Pointer, CveId, CweId, Timestamp` from `intelligence.contracts`)
- `SourceDoc`: doc_id=domain_id('kbc.source',1,{kind,sha256}), kind cvrf-month/csaf/sug-cve/winbindex-file/kev/local-note, sha256 (decompressed bytes), size, origin local-import/https-fetch, uri?, retrieved_at, release_id? (yyyy-Mmm), current_release_date?, dialect, parser_version, authenticity unverified-local-file/tls-allowlisted-host/tls-allowlisted-host-hash-match, lineage msrc/winbindex/nvd/cisa/analyst, object_path.
- `SourceRef`: doc_id, pointer, assertion advisory_fact/index_claim/binary_observation/rule_hypothesis/analyst_statement. `SearchScope`: kind selected_months/cached_corpus/provided_files/mixed, months<=24, doc_ids, corpus_digest?.
- `Coverage`: coverage_id, source_kind, scope, state (the 5 words), requested_ids, inspected_ids, failed[(id,reason)], unfetchable_ids, watermark_current_release_date?, retrieved_at, exhaustive_for_history=False. Invariant: `complete_in_scope` needs requested == inspected, no failed, at least one requested.
- `ProductScope`: scope_id, family windows-client/windows-server/other/unknown, release?, architecture amd64/arm64/x86/unknown, channel?, edition?, build?, display_name, source_product_ids[(doc_id,pid)], winbindex_key? ("11-24H2"), mapping verified/candidate/unknown/conflicted, alias_catalog_version. String-derived scopes are never `verified`.
- `KbCveEdge`: edge_id=domain_id('kbc.edge',1,{kb,cve,scope_id,relation,doc_id,pointer}), kb, cve, scope_id, relation (vendor-remediation, vendor-association, mention-only, package-contains, analyst-asserted, disputed), ref, release_id, fixed_build?, supersedes[kb], sub_type?, product_status? (raw value + pointer), conflict_ids, lineage='msrc'. CSAF-derived KB edges (an exact `KB`+digits token in a `vendor_fix` detail, or a `support.microsoft.com/help/<digits>` URL, with products from `product_ids` and expanded groups) are `vendor-association` until a live capture proves a structured field.
- `ComponentHint`: hint_id, basename (via `acquisition.contracts.validate_file_name`), scope_id, tier A-E, reasons, claim_refs, changed_in_kb yes/no/unknown. `BuildRow`: file_name, sha256 (dict key), version_key, kb, release_date, release_version, heading_class standard/preview/out-of-band/expired/none, shared_with, variant full/delta+/delta/raw, download, record_sha256, data_date.
- `BinaryRef`: sha256, size, basename, machine, file_version?, build_ubr?, origin index-row/local-file/download, availability local/direct/candidates/delta-only/unavailable, authenticity (5 states, row 16). `PairProposal`: pair_id=domain_id('kbc.pair',1,{older,newer,scope_id,window_id}), older, newer, bytes_state verified/pending/mismatch/incompatible, lineage_state index-adjacent/compatible-branch/user-asserted/unverified/incompatible, fix_boundary source-supported/unverified/contradicted, window[kb], window_complete bool?, reason_codes, grade A/B/X, tier.
- Pair rules. Grade A: no hard block, `lineage_state=index-adjacent` (the older row is the immediately preceding distinct-SHA row of the same version key), bytes verified or pending from an index row. Grade B: bytes verified and lineage asserted, branch-compatible or window confounded. Grade X: any hard block. `fix_boundary=source-supported` only if the newer row's build.UBR equals the edge's `fixed_build` and the older side is that immediate predecessor; `contradicted` if the older build is not before `fixed_build`. Reason codes: IDENTICAL_CONTENT, DELTA_ONLY, ARCH, CROSS_PRODUCT, ORDER_UNVERIFIED, DIGEST_MISMATCH, NO_OLDER, NO_NEWER, WINDOW_CONFOUNDED, SERVER_NOT_COVERED, NAME_MISMATCH, INDEX_GAP.
- `PairPlan`: plan_sha, pair_id, requests[(method,url,bytes?,why)], hosts, expected{sha,size}, destination policy; wraps acquisition `DownloadPlan`; absent for local files. `Attempt`: op, plan_sha?, stage, result ok/partial/cancelled/error, code?, created_at (the consent record and the recovery journal). `AnalystDecision`: op, prior, next, reason<=500, created_at, refs (append-only; product choice, pair approval, orientation override, name-mismatch confirmation).
- `InvestigationRevision`: investigation_id (UUID), revision, parent, lead{kind kb/cve/file/pair, value, raw<=200}, state, scope_ids, coverage_ids, selected_scope_id?, selected_pair_id?, plan_sha?, warnings. `ProjectLink`: project_id, project_revision, older_sha, newer_sha, investigation_id, revision, pair_id, state attached/context-pending/stale, stale_reasons. Attaching to an existing project (W3) records `lineage_state=unverified` and never reorients.
- `ContextReport`: per CVE a `CveCard` (source_kind cvrf/csaf, title?, stated CWE?, severity context?, kev, applicability?), embedded `intelligence` JSON (CweProfile, HypothesisSet, AnchorSet, ApplicabilityReport) where CSAF exists, coverage, unknowns, limitations, hooks. The reused classifier names any vendor-stated CWE `explicit-csaf-cwe`; KB shows it as "stated by vendor (CVRF)" from `source_kind`, without changing `intelligence/1`. `LeadRow`: lead_id, level component/function, group (cve / 'unattributed' / 'not-applicable'), subject, chips[(channel documentary/applicability/exploitation/hypothesis/binary-identity/code-change/anchor, state supports/neutral/contradicts/unknown/not-run, text, ref)], rank_basis, nav{match_id?, project_revision, run_id}, stale, hooks. `OperationResult[T]`: status ok/partial/unknown/unsupported/cancelled/error, value, issues[`KbcIssue`(code, message<=500, recoverable, source_id?)], warnings.
- Teach hooks (`hooks`, input for the E-5 guide): `kb.next.import_documents, choose_product, enter_filename, supply_pair, run_comparison, review_lead, widen_window` and `kb.meaning.coverage, relation, tier, grade, kev, hypothesis`; each maps to one copy key.

### 7.3 Companion store (`store.py`: `WorkspaceStore` and `ProjectAttachment`)
- Workspace root: `%LOCALAPPDATA%\PatchTrace\kb\`, else `$XDG_DATA_HOME/PatchTrace/kb/`, else `~/.local/share/PatchTrace/kb/` (local, never roaming); `--workspace DIR` overrides for tests. Files: `kbc.sqlite3` (`user_version=1`; a newer version opens read-only) and `objects/<sha[:2]>/<sha>.gz`.
- Tables: `meta, docs, coverage, segments`; dictionaries `kbs, cves, products`; `edges(kb,cve,product,doc,vi,ri,rel,fixed_build) WITHOUT ROWID PK(kb,cve,product,doc,vi,ri)` + index `(cve,kb)` (the pointer is rebuilt from `vi,ri` and the pinned dialect); `investigations, revisions(body_sha256), attempts, decisions` (append-only).
- Writes use `BEGIN IMMEDIATE`, `busy_timeout=5000`, current revision by compare-and-swap. The workspace tolerates concurrent connections; the project store stays single-owner-thread.
- Project side: enrichment rows `kb-investigation:<inv>:<rev>` (append-only) and `kb-context:<context_key>` (derived, Guard-stale), both new KINDS outside `DERIVED_KINDS`; sidecars `kb/sources/<sha>.json.gz` and `kb/investigations/<inv>-<rev>.json`. CSAF documents go through `AdvisoryStore.add` (standard `advisory-*` rows) and are not copied twice.
- Attach is two-phase: verify both files -> write the journal intent (plan_sha, project directory, ordered SHAs) -> `ProjectService.create` -> record project id and revision in the journal -> sidecars -> rows -> mark the attempt done. An interruption before create removes only operation-owned staging; after create it leaves `CONTEXT_PENDING`; `kb attach --repair` is idempotent and never deletes the project or a user file.

### 7.4 Errors, limits, keys, versioning
- Codes: `PT-KBC-INPUT, SCOPE, CONSENT, SOURCE, PRODUCT, LINEAGE, ACQUIRE, VERIFY, UNSUPPORTED, STALE, STATE, STORAGE, LIMIT, CANCEL, INTERNAL`; acquisition and enrichment codes are nested in `details`, never re-mapped.
- `KbcLimits` (provisional until live probe L1): CVRF document 32 MiB raw, depth 64, 5,000,000 JSON nodes, 500,000 edges per document; 24 documents per plan, 60 months in the index, fetch concurrency 1, request 60 s, plan 15 min, 3 attempts, Retry-After <=60 s; text field 64 KiB; hints 5,000 (paged); pairs 1,000 per file (truncation flagged); 20 files per investigation; 500 investigations; project sources 256 MiB; workspace objects 4 GiB (evict only unreferenced objects after a verified listing).
- Reused unchanged: Winbindex 64/256 MiB, 256 probes, 4 HEAD, download 512 MiB; CSAF 16 MiB; SUG/NVD 4 MiB.
- Keys: parse `domain_id('kbc.parse',1,{doc_sha256,dialect,parser_version,alias_catalog_version})`; context `{inv,revision,edge_set_digest,csaf_source_shas,rules_digest,lexicon_digest,kev_snapshot_sha,older,newer,scope_id,versions}`; leads `{context_key,run_id,raw_sha256,ranking_config_digest,unified_result_id,secondary_set_ids}`. Guards: `kb-investigation` uses `Guard(project_id,'kb',revision_sha,revision_id)`; `kb-context` is run-bound, so re-analysis marks it stale.
- Versioning is additive only; an unknown newer major is read-only and never downgraded; schemas are generated to `docs/schemas/kbcorrelation/` with regenerate-and-compare.

### 7.5 Workflow reducer (`workflow.py`, pure: `reduce(snapshot, event) -> snapshot | KbcIssue`)
- States: NEW, LEAD_PARSED, SEARCHED{METADATA_READY, METADATA_PARTIAL, NOT_OBSERVED, SCOPE_REQUIRED}, PRODUCT_SELECTED{NEEDS_PRODUCT}, COMPONENTS_READY{NEEDS_FILENAME}, PAIR_PROPOSED{NEEDS_OLDER, NEEDS_NEWER, LINEAGE_BLOCKED, NEEDS_PAIR_SELECTION}, PAIR_APPROVED, PLAN_READY (E1), ACQUIRING (E1), BYTES_VERIFIED, PROJECT_CREATED, CONTEXT_PENDING, CONTEXT_ATTACHED, COMPARISON_PENDING, ANALYZED, LEADS_READY.
- Rules: a transition needs its preconditions on the current immutable revision and appends a revision (compare-and-swap). Side effects run outside the reducer and return events carrying a generation id (a stale generation or a closed window is dropped). Never BYTES_VERIFIED before both final files are hashed and parsed; never PROJECT_CREATED from one verified side. Cancellation restores the previous committed snapshot and appends `Attempt(result=cancelled)`. A restart marks unfinished attempts interrupted and never fetches or runs an engine. A failure after PROJECT_CREATED becomes CONTEXT_PENDING (project kept).

### 7.6 Valuable-looking items rejected or demoted (charter failures)
- A free-text "search all of MSRC history" box: duplicates the Security Update Guide and cannot state coverage; only loaded documents are searched.
- KBC s12 and KPS 3.3 modal "what to look for" pop-ups: duplicate the Context pane and interrupt work; replaced by the non-modal pane and a banner.
- Any KEV-driven reranking of functions, a numeric "documentary strength", or "N of M channels" counts: false precision; channels are listed in words.
- KPS `PatchLocalization` as a separate view model: duplicates unified and PIL results; the lead row reads them through `EngineEvidence`.
- Catalog scraping, automatic multi-file batches beyond 5, DISM or PSFX hydration in the core path: unverifiable terms or fragile; E3 only.

## 8. CLI and GUI
### 8.1 CLI (one `cli_*.py` per verb module; `kbcorrelation/cli.py` assembles; hook of <=6 lines in `patchtrace/cli.py`)
```
kb index import FILE...  |  kb index status|verify            # offline; CVRF month or CSAF JSON
kb index plan --months YYYY-MM[,..] | --since YYYY-MM          # E0, pure: exact requests, hosts, caps, plan_sha; zero network
kb index sync --months .. --consent-hosts api.msrc.microsoft.com --consent-plan SHA     # E1
kb search KB|CVE [--months ..] [--scope-file F] [--offline] [--product ID] [--investigation ID]   # local index only
kb products|components|pairs INV [--product ID] [--file NAME]...
kb import-pair INV --older F --newer F --project DIR [--name N] [--confirm-same-component]    # E0
kb plan INV --pair ID ; kb acquire INV --pair ID --project DIR --consent-hosts winbindex.m417z.com,msdl.microsoft.com --consent-plan SHA   # E1
kb attach PROJECT --investigation INV [--repair] ; kb explain PROJECT --cve CVE ; kb leads PROJECT [--cve CVE] [--limit N] ; kb export PROJECT FILE.json|.md
```
- Every verb takes `--json` (one `enrichment-cli/1` document, `result.contract='kbcorrelation/1'`, diagnostics on stderr) and `--workspace DIR`. `search` result: `{investigation_id, lead, coverage, scopes, edges, cards, mention_only, not_applicable, warnings}`; `leads` result: `{groups[{group, kev, cwe, leads}], unattributed, not_applicable, coverage, run_id, project_revision, stale}`.
- `search` never fetches (KPS `--fetch-metadata` is replaced by `index plan` then `index sync`); `--months` and `--scope-file` only define the scope that coverage is computed against.
- Only `index sync` and `acquire` can touch the network, and only with `--consent-hosts` equal to the planned set (as `_consent_hosts`) and `--consent-plan` equal to the printed `plan_sha`; `--offline` with any consent flag is exit 2. `explain`, `leads`, `attach` and `export` never fetch or run engines. `export` writes JSON or escaped Markdown with pointers, hashes, rule ids and digests, lead groups, unknowns and limitations; no absolute paths, no code, no HTML.
- Exit: 0 ok; 2 invalid arguments, malformed local file, consent, contradiction, unsupported platform; 3 runtime failure OR `status: partial` (coverage incomplete for the requested scope); 4 complete in scope with zero edges, pairs or leads, or nothing to compute yet (`status: unavailable`, for example `leads` before any comparison); 5 cancelled. A KB not observed under partial coverage is exit 3, never 4.

### 8.2 GUI (single main window; no new top-level window)
**Placement and entry.**
- `KbDock(QDockWidget)` "KB / CVE investigation" (objectName `kb.dock`), Right area, hidden until toggled, closable, movable, floatable like the Evidence dock; minimum 560x360; geometry in QSettings `kb/geometry` (try/except).
- Menu `Project > Find KB / CVE...` is `dock.toggleViewAction()`, Ctrl+Shift+K (free: MainWindow uses Ctrl+N/O/S/E/I/R, F1, F5, Esc, Alt+Up/Down; Evidence uses Ctrl+Shift+E; planned: Unified Ctrl+Shift+U, Search Ctrl+Shift+F).
- Works with no project open; `project_changed()` switches to the attached investigation. It registers with the GUI-track panel registry when that lands; until then it copies the Evidence pattern exactly so migration is mechanical. Only existing modal helpers are used (`QFileDialog`, one consent `QMessageBox`).

**Layout** (Updates page shown; all pages are built eagerly, filled lazily):
```
+- KB / CVE investigation ------------------------------------------------------------------+
| Lead [KB5099001________] KB number   [Search] [Import file...] [Plan network search...]    |
| Checked 1 advisory document (2099-Feb to 2099-Feb); 0 unreadable. Nothing else was checked.|
| [1 Find] [2 Updates] [3 Files] [4 Builds] [5 Project] [6 Leads]                            |
| Product [Example OS 24H2 x64 v]  Relation [all v]  Filter [__________]                     |
| KB         CVE             Product          Arch   Relation                  Fixed build KEV|
| KB5099001  CVE-2099-20001  Example OS 24H2  amd64  Vendor remediation (CVRF)  -     listed |
| CVE card: CWE-125 stated by vendor | Hypothesis R-MEMORY-READ: guard before the read ...    |
| Mentioned only: CVE-2099-20003 (advisory text, not a remediation)                          |
| status: Found 1 security update for the lead.                              [Cancel]        |
+--------------------------------------------------------------------------------------------+
```
- Pages: Find = documents table with per-document coverage; Updates = edges (KB, CVE, product, arch, relation, vendor-stated fixed build, source, KEV) + product and relation filters + CVE card; Files = hints (name, tier, changed in KB, basis) + "add file name" (validated); Builds = older/newer tables (E1) or two file pickers (E0), Swap, pair strip (grade, window, reasons); Project = summary or plan, name, directory, Create (E1: Approve N requests); Leads = group filter + `LeadTableModel` + detail + Go to code, Copy provenance, Refresh.
- `Plan network search...` shows the exact request list, hosts, caps and `plan_sha` with a Copy button (E0, no network, so a file can be fetched on another machine and imported); "Approve and fetch" arrives with E1.
- Later steps stay disabled until their prerequisite holds; the reason is in the tooltip `Availability` and in adjacent text, never colour only.

**Model/view and threads.**
- `view_model.py` (Qt-free, banned-word swept, `secondary.evidence_view.sanitize_text` on every string) feeds `QAbstractTableModel`s with model-owned order (no proxy, no `ResizeToContents`, uniform row heights, `AccessibleTextRole` per cell with units spoken). Virtualization gate as C6: `data()` calls independent of row count at 10k and 100k leads.
- `KbController(QObject)`: generation counters, `TaskThread` (no Qt parent, module `_LIVE_THREADS`), `shutdown()` sets cancel events and joins (no `terminate()`). Workers get immutable requests; index import uses its own workspace write connection; project create, attach and row publish run only in GUI-thread slots; late or wrong-project results are dropped.

**States** (exact copy; `{}` is filled from data; all text is plain):
| id | trigger | text |
|---|---|---|
| KB0 | no lead | "Type a KB number (KB5012345) or a CVE ID (CVE-2024-12345). Searching uses only advisory files already on this computer." |
| KB1 | no documents | "No advisory documents are loaded, so nothing was searched. Import a saved CVRF or CSAF JSON file, or review a network plan." |
| KB2 | searching | "Searching the local advisory index..." (indeterminate bar, Cancel) |
| KB3 | found | coverage strip: "Checked {n} advisory documents ({first} to {last}); {f} unreadable. Nothing outside these documents was checked." |
| KB4 | not found, complete | "{lead} was not found in the {n} documents checked ({first} to {last}). That does not mean it has no security updates; these documents do not list it." |
| KB5 | not found, partial | "{lead} was not found, but {f} of {n} requested documents could not be read, so this result may be incomplete." |
| KB6 | several products | "This update applies to several products. Choose the product and architecture of the files you are analyzing." |
| KB7 | no filename | "The advisory does not name the changed file. Enter a file name such as clfs.sys, or choose two files you already have." |
| KB8 | CVE not applicable | "Microsoft lists this CVE for other products only. It is left out of the leads for {product}." |
| KB9 | pair blocked | the reason text below, adjacent to the disabled Create button |
| KB10 | review plan (E1) | "Review before anything is downloaded: {n} requests to {hosts}. Files are checked against the expected SHA-256 and size and are never run." |
| KB11 | acquiring (E1) | "Downloading {side}: {done} of {total}." Cancel: "Cancelling. The current request must finish; nothing is kept." |
| KB12 | context pending | "The comparison project was created, but the advisory context could not be attached. Retry attach; the project is unaffected." |
| KB13 | context ready | "Advisory context is attached. It records what the vendor states and which checks could not be made; it does not show that any changed function addresses a vulnerability." |
| KB14 | stale | "This context was prepared for a different file pair, analysis run or advisory revision. It is shown for reference; navigation is off." |
| KB15 | error | "{code}: {message} Nothing was changed." |
| KB16 | unsupported | "{feature} is not available in this build or on this system. Metadata and manual import still work." |
| KB17 | project open, no investigation | "This project has no advisory context. Search a KB or CVE to attach one; applicability to these two files stays unverified until you confirm it." |

Pair reasons shown for KB9 (reason code, then exact text):
| code | text |
|---|---|
| IDENTICAL_CONTENT | "These two files are byte-identical; this file did not change between them." |
| DELTA_ONLY | "Only a delta payload was found. A complete PE file is required; import one." |
| ARCH | "PatchTrace compares AMD64 PE files; this file is {arch}." |
| CROSS_PRODUCT | "The two builds belong to different products and are not compared automatically." |
| ORDER_UNVERIFIED | "The release order of these builds could not be established, so older and newer are your choice. Swap if needed." |
| DIGEST_MISMATCH | "The downloaded file does not match the expected SHA-256; no project was created." |
| NO_OLDER | "No earlier build of this file is listed for this product." |
| WINDOW_CONFOUNDED | "{k} other updates ship between these builds; differences may belong to any of them." |
| SERVER_NOT_COVERED | "The file index covers Windows 10/11 client updates only; Server-only builds are not listed." |
| NAME_MISMATCH | "The two files have different names. Confirm they are the same component to continue." |
Relation labels: "Vendor remediation (MSRC CVRF, product-specific)", "Vendor reference (CSAF text or URL)", "Mentioned in advisory text only", "Entered by you", "Revisions disagree".

**Accessibility** (docs [unverified], section 2).
- Accessible names: "KB / CVE investigation panel", "Lead", "Investigation steps", "Advisory documents", "Security updates for the lead", "Candidate files", "Older build candidates", "Newer build candidates", "Leads", "Advisory context details".
- The status label keeps an EMPTY accessible name so `setText` announces (C6 s1.8). Badges are text plus an ASCII glyph (`[=] index-adjacent`, `[~] asserted`, `[!] blocked`, `[?] unknown`), never colour alone. 2 px focus ring; contrast >=4.5:1 text and >=3:1 non-text by a pure test; no colour beyond `DARK_STYLE`; row heights from font metrics.
- Tab order: Lead, Search, Import, Plan, step bar, page controls in reading order, Cancel. Enter runs the page's primary action on a selected row; Ctrl+C copies a plain provenance block (<=16 KiB); Ctrl+PageDown/PageUp change step; Esc stays MainWindow "Cancel job" (ui.py:1529) and the dock Cancel is a button.
- NVDA/Narrator announcements, 125/150/200% DPI and a keyboard-only walk stay manual gates (C8).

**Tooltips.** Ids `kb.dock, action, lead, search, import, plan_network, steps, docs_table, edges_table, product_filter, relation_filter, cve_detail, hints_table, file_name, add_file, builds_older, builds_newer, older_file, newer_file, swap, pair_summary, project_name, project_root, create, approve, leads_table, group_filter, goto, copy, retry_attach, refresh, stale_banner, cancel`. Each has What/Why/Effect/Source (data origin, network yes or no)/Availability, a unique What, no `<` or `>`; per-row text uses `template('kb.row', ...)`. Entries live in KB-owned data modules merged by `ui_kb.py` at import.

**Qt pitfalls.** Running threads must never be garbage collected; build every page and control eagerly (tooltip audit); keep `QTabBar` and `QStackedWidget` indexes in sync and skip disabled tabs; plain text only (`PlainLabel`, registry tooltips); file dialogs and the consent box injectable for tests; QSettings reads in try/except; `QTableView`, never `QTableWidget`, above 1k rows; offscreen cannot prove contrast, DPI or screen-reader output.
**Offscreen tests and budgets.** `tests/test_ui_kb.py`: one test per state KB0-KB17, project switch and close while running (`test_worker_never_touches_widgets`, `test_close_while_running_cancels_and_waits`), `test_ui_kb_no_new_top_level_window`, tooltip and accessible-name audit, 20x repeat under `PYTHONFAULTHANDLER=1`. Budgets: lookup <=100 ms at 1M edges (0.4 ms measured in SQL), first table paint <=200 ms after `model_ready`, any GUI slot <=100 ms, import of a 32 MiB document <=20 s on a worker (0.8 s parse + about 9 s per 1M rows, measured).

## 9. Slice plan
Module map (a file has one owner per wave; cross-feature calls only through `ports.py`, bound in `wiring.py`, the only module that imports sibling packages):
| module | owner | responsibility |
|---|---|---|
| `kbcorrelation/{__init__ (empty), contracts, limits, ids, errors, ports}.py` | K0 | strict records, limits, KB/CVE/id rules, `PT-KBC-*`, port Protocols |
| `kbcorrelation/sources/{cvrf,csaf_bridge,scope,importer,net_plan}.py`, `products.py`, `alias_catalog.py` (pure data), `index.py`, `cli_index.py` | K1 | CVRF/CSAF -> edges, scope and coverage math, request preview and `plan_sha` (pure), versioned product alias catalog, local reverse index, import and plan verbs |
| `kbcorrelation/{store,workflow,recovery}.py` | K2 | workspace store, project attachment, reducer, journal and repair |
| `kbcorrelation/{components,pairs,plan,context,export,service,wiring,cli,cli_pairs}.py` | K3 | tiers, manual pairs, local plan, documentary context, facade, composition root, verb assembler |
| `kbcorrelation/{leads,cli_leads,view_model}.py` | K4a | CVE-grouped leads, Qt-free view models |
| `src/patchtrace/ui_kb.py`, `kbcorrelation/tooltips_kb.py` | K4b | dock, controller, models, tooltips |
| `kbcorrelation/{lineage,resolver}.py`; additive `acquisition/winbindex.py::parse_rows` | K5 | version keys, windows, changed-in-KB, pair candidates |
| `kbcorrelation/sources/cvrf_fetch.py`, `cli_online.py` | K6 | consented CVRF sync (sockets, retries, cancel) |
| `kbcorrelation/acquire.py`, `acquisition/workflow.py` (new), `src/patchtrace/ui_kb_online.py`, `tooltips_kb_online.py` | K7 | verified download and promote, online pages |
| `kbcorrelation/adapters/{engine,kev,search,anchors}.py`, `tooltips_kb_leads.py` | K8 | KEV, WB1, FAB, unified/secondary adapters |

| slice | scope | exclusive tests and fixtures | deps | tier and reason | size | acceptance gate | fallback |
|---|---|---|---|---|---|---|---|
| K0 | contracts, ids, limits, ports, schema generator | `tools/generate_kbc_schemas.py`, `docs/schemas/kbcorrelation/**`, `tests/test_kbc_{contracts,ids,schemas}.py` | - | sonnet: strict pydantic, no I/O | M | regenerate-and-compare; no Qt, urllib or sqlite3 import in domain modules; KB syntax matrix | - |
| K0f | fixtures and builders | `tests/kbc_helpers.py`, `tests/fixtures/kbcorrelation/{MANIFEST.json,README.md,cvrf-*,kev-synthetic.json,csaf-kb.json,identifiers.json}` | K0 names | haiku: mechanical, synthetic | S | manifest hashes verified; `two_cve_project()` reproduces the baseline shape | - |
| K1 | CVRF/CSAF edges, scope, index, import and plan verbs | `tests/test_kbc_{cvrf,csaf_bridge,scope,index,products,net_plan}.py` | K0, K0f | sonnet: parser with strict invariants | L | S01-S20 and NEG matrix merged from KBC/KPS; reorder-invariance property; 32 MiB cap; two-axis coverage; product status disputes | CSAF-only edges; CVRF "dialect unknown" error |
| K2 | store, reducer, recovery | `tests/test_kbc_{store,workflow,recovery}.py` | K0; A-5, A-6 first | opus: crash consistency, CAS, backup invariants | L | subprocess hard-kill at `index_after_doc, attach_before_row, after_project_create, after_sidecar_write, before_cas` leaves a valid project; newer store fails closed | workspace only; attach as JSON export |
| K3 | manual pair, components, context, service, CLI | `tests/test_kbc_{components,pairs,context,service,cli,e0_e2e}.py` | K1, K2 | sonnet | L | offline E0 script (10.1) with sockets denied; single JSON document and exit codes 0/2/3/4/5; banned-word sweep | CLI without GUI |
| K4a | leads, view models, `kb leads` | `tests/test_kbc_{leads,view_model}.py`, `tests/test_kbc_synergy.py` | K3 | sonnet | M | E0 synergy golden; contested stays contested; shared lineage counts once | leads as a text report |
| K4b | GUI E0 dock | `tests/test_ui_kb.py` | K3, K4a | sonnet | L | states KB0-KB17, tooltips, names, no new window, 20x repeat | CLI-only E0 |
| K5 | Winbindex rows, lineage, resolver | `tests/test_acquisition_winbindex_rows.py`, `tests/test_kbc_{lineage,resolver}.py`, `tests/fixtures/kbcorrelation/winbindex/**` | K1, K3 | sonnet, with the RK2 s2.3 decision table | L | no grade A across scope, arch or reverse order (property); md5-only and shared-KB rows kept; KB5077181 build-prefix case | manual pairs only |
| K6 | consented CVRF sync | `tests/test_kbc_cvrf_fetch.py` | K1, K3 | sonnet | M | consent equality and `plan_sha`; offline refusal; 429/5xx/Retry-After; 32 MiB cap; cancel; hostile redirect (fake opener) | file import only |
| K7 | acquisition workflow, online pages | `tests/test_acquisition_workflow.py`, `tests/test_ui_kb_online.py` | K4b, K5, K6 | sonnet | L | pair acquired through a fake transport; no half-project on cancel; `tests/test_ui_acquisition.py` unchanged | local import only |
| K8 | KEV, WB1, FAB, unified adapters | `tests/test_kbc_adapters.py`, `tests/test_kbc_synergy_full.py` | K4a; KEV, WB1, FAB, UE plans | sonnet | M | full synergy golden; KEV never alters order; each adapter optional by capability probe | chips read "not loaded" |
| K9 | QA, Windows, frozen, live probes | `tests/test_kbc_perf.py`, `tools/live_kbc_probe.py`, `.github/workflows/live-kbc.yml` | all | sonnet + haiku lint | M | frozen smoke imports; Windows CI green; probes recorded PASS/FAIL/BLOCKED | advisory workflow |
E0 = K0, K0f, K1, K2, K3, K4a, K4b (K1 and K2 in parallel, K4a and K4b in parallel). E1 = K5-K7. E2 = K8-K9. E3 (package inventory, curated component catalog) gets its own plan. K2 waits for A-5 and A-6 (a 3-line PR by the integration owner). Never two builders on one file; shared seams are in section 10.

## 10. Amendments, test and QA plan
| id | file, section | change |
|---|---|---|
| A-1 | `docs/specs/kb-cve-correlation-and-acquisition.md` title, s0 (line 36), s8, s9, s11, s15 | retitle SPEC-34; replace "intelligence/ does not exist" with "SPEC-28a/b built"; s8 layout and s9 storage point to 7.3; CLI examples to 8.1; retire the "E0/E1" evidence-layer names (localization belongs to PIL) |
| A-2 | `docs/specs/kb-cve/README.md`, `31-A..31-H` | status line "storage, limits, CLI superseded by KB-integration-plan"; 31-B B5 compact edges and B6 limits; 31-F F3 choice resolved |
| A-3 | `docs/specs/kb-patch-search-*.md`, `docs/plans/kb-patch-search-*.md` | banner "SPEC-37, annex of SPEC-34: read 32A s2 (CVRF join), 32B s5.1 (attach), 32D s2 (manifest)"; renumber SPEC-32 to SPEC-37; 32C CLI grammar replaced by 8.1 |
| A-4 | `docs/specs/REGISTRY.md` (absent at d972125) | rows SPEC-34 (base), SPEC-37 (annex) |
| A-5 | `enrichment/storage.py` `KINDS` | add `kb-investigation`, `kb-context` (not `DERIVED_KINDS`); test: rows survive retention |
| A-6 | `persistence.py:522` `backup()` | also copy `kb` and `intelligence`; verified round trip (repairs the CSAF gap too) |
| A-7 | `acquisition/winbindex.py` (K5 owns this edit) | additive `parse_rows()` (dict key as SHA, `(version, KB)` rows, `otherWindowsVersions`, heading class, BASE date); `parse()` unchanged |
| A-8 | `cli.py` | `COMMANDS`, `HANDLERS` and the `_command_name` set gain `kb` (<=6 lines) |
| A-9 | `ui.py` | import; `self.kb = KbController(self)` after line 1504; menu item in `_build_actions`; hooks beside 1984, 2985, 3113 (<=12 lines); the dialog refactor stays optional |
| A-10 | `intelligence/anchors.py`, `contracts.py` | public `text_anchors()`; `Anchor.source` gains `cvrf-title`, `cvrf-note`, `cvrf-tag` (additive, schema regenerated). Fallback: a KB-local copy plus a drift test |
| A-11 | `docs/specs/workbench/01-search-fts5-rapidfuzz.md` s4 | `SearchSourceRef.field` gains `advisory`; the extractor calls `AdvisoryTextSource` |
| A-12 | `docs/modules.md`, `tasks/todo.md`, `docs/qa.md`, `tools/frozen_smoke.py`, `pyproject.toml`, `tests/test_tooltips.py`, `.gitattributes` | KB rows; frozen smoke imports `kbcorrelation`; pytest marker `live_kbc` (no package data or PyInstaller datas are needed); KB dock names in the registry audit roots; LF for `tests/fixtures/kbcorrelation/**` and `docs/schemas/kbcorrelation/**` |

### 10.1 E0 acceptance script (`tests/test_kbc_e0_e2e.py`, offline, sockets denied)
1. `kb index import cvrf-2099-Feb.json --json` -> 0; 1 document, 4 edges, 1 mention-only, coverage `complete_in_scope`. A malformed file -> 2 and the index is unchanged.
2. `kb search KB5099001 --offline --json` -> 0: CVE-2099-20001 for client and ARM64, 20003 under `mention_only`. `kb search KB5099777 --offline` -> 4. A scope file naming a document that is not loaded -> 3 `partial`. `kb search KB12` -> 2.
3. `kb import-pair INV --older old/exampledrv.sys --newer new/exampledrv.sys --project P` -> 0: grade B, `lineage_state=user-asserted`, `fix_boundary=unverified`, project created and attached. The same file twice -> 4 `IDENTICAL_CONTENT` ("this file did not change"), no project; a renamed file -> 2 `NAME_MISMATCH` until `--confirm-same-component`.
4. `kb explain P --cve CVE-2099-20001 --json` -> 0: stated CWE-125, hypothesis R-MEMORY-READ, applicability `unknown` (no CSAF), KEV "not loaded", coverage and limitations present.
5. The existing `rank P` then `kb leads P --json` -> 0 and equals the golden. `kb leads` on a project with no run -> 4 `unavailable`.
6. Kill the process after project creation, then `kb attach P --investigation INV --repair` -> 0 and is idempotent. `kb export P out.md` -> 0, escaped, no local paths. A backup of P restores the `kb/` sidecars.

### 10.2 Test and QA plan
- **Fixtures:** synthetic only (CVE-2099-*, KB5099*, `example*` names). Winbindex excerpts derive from the committed `kbcve/windows` excerpt (GPL-3.0 metadata, test-only). PE files come from `patchtrace.sample.synthetic_pe` and `tests/pe_builder.py`. No Microsoft binaries and no MSRC bytes.
- **Goldens:** schemas, edges, coverage, pairs, plan, leads (sorted keys, LF).
- **Merged matrix:** the two specs reuse test ids (S01-S10, C01-C15/16); the merged suite prefixes them `KBC-` and `KPS-`, and each test docstring names its source id so no requirement is lost in the merge (KBC s14 S/P/C, KPS 32A S01-S20, 32B B01-B20, 32C C01-C16, 32D NEG-01..32, 32E E01-E10).
- **Properties (hypothesis):** CVRF array reorder invariance; an unrelated CVE changes nothing; no grade A across scope, arch or reverse order; `complete_in_scope` iff requested == inspected; edge ids stable across locale; plan_sha changes with any URL.
- **Hermetic network:** an autouse fixture denies sockets for every `test_kbc_*` except marked live tests.
- **Windows checklist:** CRLF via `.gitattributes`; short parametrize ids (`kb01`); `>=` on `time.monotonic`; YAML scalars containing `: `; wheels-only installs; close SQLite handles before deleting in tests; `os.replace` retry for antivirus holds (pattern in `unified/store.py`); path lengths under OneDrive-backed projects; a project lock held by the GUI makes CLI attach fail with a typed error.
- **Live and owner gates (BLOCKED here, never counted done):** L1 RK1 probe pack (about 25 requests) to pin the CVRF dialect, sizes, `Description.Value`, `FixedBuild`. L2 parse real Winbindex newest builds. L3 a symbol-server pair through the existing path. L4 CSAF provider metadata and the KB token location. L5 Windows frozen ZIP E0 flow with non-ASCII paths, NVDA/Narrator, 125/150/200% DPI, keyboard-only walk. L6 owner cases: a valid pair, and an honest partial one (KBC H6).

## 11. Open questions (defaults apply; none blocks a build)
1. Workspace location: default local (`%LOCALAPPDATA%`), not roaming.
2. KB digits 4-10: default the superset of both specs.
3. A new top-level "Investigation" menu: default no, Project menu.
4. CVRF fetch owner: default KB owns CVRF only; `intelligence fetch` keeps CSAF.
5. Real MSRC captures as fixtures: default no, hash-only provenance, until the terms are read.
6. Curated title->file catalog (tier D): default none shipped until reviewed, cited data exists.
7. Files per KB: default up to 5, one project each, sequential.
8. Refactor `AcquisitionDialog` onto `acquisition/workflow.py`: default after E1 merges, its tests untouched.
9. Anchor kind names until the FAB contract lands: default the table in section 4; KB adapts.
10. Authenticode and catalog verification: default embedded via `pe_overview` on Windows only, otherwise `signature-unknown`.
11. Auto-create a Series for confounded windows: default offer only.
12. Dock vs central view: default dock; revisit when the GUI-track panel registry lands.
13. CVRF 32 MiB cap: default 32 MiB until L1; above it a memory-capped child process (C3 pattern).
14. A KB section in the main report export: default later; `kb export` first.
15. How an offline user obtains a CVRF JSON file is unverified (whether the API serves JSON to a browser, L1): default `kb index plan` prints the exact URLs and the Accept header to use on another machine, and a CSAF document alone still supports CVE-first; add XML CVRF import only if L1 shows JSON is not served. This is the main risk to the usefulness of E0.
