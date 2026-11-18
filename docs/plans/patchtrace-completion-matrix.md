# PatchTrace production completion and acceptance matrix

## Baseline and meaning of completion

This is the 2026-11-18 autonomous-continuation baseline. Canonical `main` is
`9c411ca3d7b47f950be5f0c6f01b3c54184554c6`. The reviewed implementation candidate
is PR #307 at `1418617a80d6057de11f985488cfe6043a7787a2`, which includes PR #304
at `75ffee3840894adb52aff7f3df28043cc8e832ba`. Neither PR is represented here as
merged. Later fixes and qualification must be recorded as a dated append with
their own source SHA; do not relabel historical test receipts.

The percentages below measure **named acceptance milestones**, not estimated
coding effort, number of commits, number of passing tests, measured accuracy or
overall release readiness. Every feature has four equally counted milestones:

1. **D — delivery:** a specified implementation boundary exists for the feature;
   remaining user surfaces and partial scope are listed explicitly in the row.
2. **R — regression evidence:** a retained, scoped implementation/test review
   supports that slice. Historical evidence is explicitly retained as historical.
3. **J — representative journey:** the stated real analyst/source/native journey
   has completed with reproducible inputs and expected outcomes.
4. **G — final gates:** applicable independent review, Linux/Windows, repeated Qt,
   native, package and dependency gates pass on the actual final candidate.

Each row says which milestones are evidenced. A partial milestone counts zero.
For example, `D,R = 2/4 = 50%` means two named acceptance milestones have evidence;
it does **not** mean half the implementation is missing. Coverage is coarse and
cannot be aggregated into a meaningful project percentage. Offscreen fixtures
do not complete a native or manual journey. No final-head gate is inferred from
another SHA. The inventory worker runs Git/document checks only; product-test
results in the sources below were executed in prior sessions.

## Production feature matrix

| Feature | Current state | Completion | Remaining work | Source | Dependencies | Tests | Security | Owner | Acceptance |
|---|---|---|---|---|---|---|---|---|---|
| Project create/open, artifact import and orientation | Implemented; qualification blocked | D,R: 50% | Fresh GUI/CLI create-import-reopen-swap journey and final gates | #297/#304; `project_cli.py`, `persistence.py`, `service.py`; [core continuation](../qa/continuation-20261116.md) | Verified artifact bytes and project ownership | `test_project_cli.py`, persistence and service suites; real repeated journey remains | Preserve lock, revision and artifact identity; never execute targets | GUI/CLI + security | Reopen the same project with stable IDs; swap consistently without losing evidence; J/G pass |
| Primary Ghidriff comparison and cancellation | Implemented; original Windows incident unresolved | D,R: 50% | Reproduce original pair with effective budget/version receipt; profile candidate expansion; confirm cancellation/cache reuse | #297/#304; [timeout record](../qa/ghidriff-timeout-20261106.md) | External Ghidra/Java/Ghidriff; original pair | `test_compare_cli.py`, backend/jobs suites; original pair unavailable to this audit | Process ownership, bounded output, no target execution | Binary analysis + CI | Complete recorded pair or report bounded refusal; retain old results and cancellation evidence; J/G pass |
| Changed/unchanged function identities and one-to-many abstention | Implemented with conservative boundaries | D,R: 50% | Native compiler/optimization/rename/split/inlining controls and disagreement evaluation | #293/#297/#301/#304; SPEC-31 A-32 | Qualified primary/secondary outputs | `test_normalization_one_to_many.py`, unified/secondary suites; real RB-01 rerun remains | Never turn duplicate names or ambiguous side ownership into confirmed matches | Binary analysis | Identity/side ownership preserved, unchanged controls remain unchanged and ambiguous groups abstain; J/G pass |
| MSRC/NVD advisory ingestion and source provenance | Implemented; source coverage partial | D,R: 50% | Qualify current approved production transports, freshness and equivalent vendor-statement deduplication across complete journey | #291/#304; [lineage evidence](../qa/current302-integration-20261118.md) | Explicit preview/consent and immutable snapshots | `test_kbc_*.py`, intelligence transport suites; mocked transport is not live acceptance | No implicit OSV source; provider identity and raw hashes retained | CVE/KB | CVE lookup/import preserves source facts and uncertainty through reopen/export; J/G pass |
| KB/update, architecture, chronology and predecessor correlation | Partial | D,R: 50% | Resolve Server-source coverage; qualify full supersedence/update-DAG behavior and ambiguous chronology using representative cases | #291/#302/#304; [L1 replay](../qa/search-anchor-integration-20261118/l1-replay.md) | Source identity, product catalogue, build constraints | Existing KBC lineage/boundary tests; frozen six failures remain | Never select a unique binary from filename alone or manufacture chronology | CVE/KB | Correct scoped candidates and explicit unknowns, including Server/preview cases, without changing frozen expectations; J/G pass |
| Offline KB CSV inventory and explicit retained pages | Implemented; final gates blocked | D,R,J: 75% | Final-head qualification and manual native UI journey; retain source admission invariants | #303/#307; [capacity and real CSV](../qa/pw01-capacity-compat-20261118.md) | Immutable source bytes; v1/v2 contracts | 581 historical focused passes; nine historical shipped-CLI operations; current gate remains | v1 ceiling 50,000; v2 pages 5,000; full-source conflict witnesses and revision guards | CVE/KB + GUI/CLI | Genuine capture replays with unchanged hashes/IDs; retention is idempotent and does not select/revise; G passes |
| Production KB CSV/support retrieval | Implemented transport; qualification blocked | D,R: 50% | Complete exact-plan direct production retrieval and replay on a runner with working source DNS/TLS | #303/#307; [PW handoff](../qa/pw01-current-integration-20261118.md) | Approved hosts, one-operation consent and budgets | Fake transport and offline capture evidence exist; actual production retrieval remains | Saved proxy capture is not production network acceptance | CVE/KB + CI | Previewed request alone is issued; source hashes and limits retained; J/G pass |
| Bounded binary acquisition and safe publication | Partial/qualification blocked | D,R: 50% | Real approved acquisition; Windows native publication controls; source authenticity and extraction acceptance | #302/#304; [Windows publication](../qa/winpairs-windows-native-20261118.md) | Explicit target plan/permission, expected hashes and native Windows | Portable red/green controls retained; native acceptance remains | Archive traversal, symlink/junction replacement, TOCTOU, budgets | CVE/KB + security + CI | Source and byte identities verified, owned publication preserves concurrent evidence, cancellation cleans only owned files; J/G pass |
| Local MSU/CAB package fallback (PW-02) | Separate planned slice | None: 0% | Finalize separate contract, implement bounded local-only extraction, independent adversarial review and Windows journey | PW-01 spec explicitly defers PW-02; `docs/specs/kb-file-inventory-csv.md` | Windows extraction lane and approved local packages | No PW-02 completion evidence is claimed | Traversal, resource budgets, decompressor process isolation | CVE/KB + security | Explicitly selected local package yields verified scoped binaries without execution or implicit network; D/R/J/G pass |
| CVE-to-function candidate evidence and ranking | Partial | D,R: 50% | Complete representative end-to-end CVE/KB-to-binary-to-function journey; independent ranking/negative-control qualification | #291/#304/#307; [current handoff](../qa/pw01-current-integration-20261118.md) | Advisory lineage, verified pair, qualified engine | CVE/KB/pilot/normalization guards; independent real function oracle still needed | Heuristics and advisory name matches cannot establish a fix; retain counterevidence | CVE/KB + binary analysis | Facts, binary observations, heuristics and analyst judgments remain distinct throughout review/export; J/G pass |
| Symbol/address/evidence/CVE/KB search | Implemented with boundary corrections | D,R: 50% | Representative repeated GUI/CLI project search journey and final gates | #305/#306/#304; [search evidence](../qa/search-anchor-integration-20261118.md) | Existing project owner and typed binary anchors | 942 historical affected passes plus independent controls; not final-head acceptance | Advisory/note circularity rejected; query budgets, cursor and digest preserved | GUI/CLI + CVE/KB | Long valid anchors work; inadmissible evidence cannot self-confirm; repeated calls release locks; J/G pass |
| Saved searches and recent-query user flow | Backend stores implemented; UI/CLI flow partial | D: 25% | Wire existing stores into documented analyst controls; specify lifecycle/ownership and add journey regression review | `claude/instance-b-features` selective port into #301/#304; `search/saved.py` | Search contract and current project owner | Store tests exist; complete user-flow evidence absent | Avoid reopening held projects or mixing search history across projects | GUI/CLI | Save, recall, delete and reopen saved queries with bounded history, stable ownership and no duplicate service; R/J/G pass |
| Decompiled/assembly views and verified raw bytes | Implemented; native/manual qualification remains | D,R: 50% | Verify actual primary-engine text and retained sidecars on repeated native desktop journeys; reconcile #86 residue | Main/#297/#304; `alignment.py`, `unified/read_text.py`; retained #86 | Verified function identity and bounded sidecars | Alignment/unified/read-model suites; native manual evidence incomplete | Wrong-side/stale text must not attach to a function; inert display | GUI/CLI + binary analysis | Address/name/side remain coherent; missing text is explicit; views survive save/reopen; J/G pass |
| Bounded paired physical-offset alignment desktop controls | Core implemented; desktop wiring incomplete | D: 25% | Review and selectively adapt `ui_raw_alignment.py` from #168; preserve current UI ownership | #168 at `b304034e3c310528f7e0a3206eda48c94e0a6873`; core port in #301 | `raw_alignment_view.py`, `representations/alignment.py`, current task lifecycle | Pure alignment/view-model tests; current desktop integration tests missing | Workers use verified readers/scalars; stale queued results refused | GUI/CLI | Opt-in bounded alignment displays gaps without fabricating bytes; copy preserves original offsets; R/J/G pass |
| Manual match overrides, annotations and findings | Implemented; current full journey unverified | D,R: 50% | End-to-end review, override, stale-evidence invalidation, reopen and export journey | Main/#297/#304; `service.py`, evidence/findings contracts | Project transactions and immutable original evidence | Service/manual-match/report suites; fresh combined journey required | Manual interpretation must not overwrite original engine evidence | GUI/CLI + security | Every decision retains author/source context and stale state; original observations stay reproducible; J/G pass |
| Persistence, recovery, backups and interrupted work | Implemented; platform qualification blocked | D,R: 50% | Current corruption/recovery/backup-restore and Windows replacement-race acceptance | Main/#297/#304; [persistence security](../qa/persistence-security-20261105.md) | SQLite owner thread, verified sidecars and locks | Persistence, verified-backup and sidecar tests; native/full gate remains | Malicious DB, stale lock, ownership, backup verification, destructive pruning | Security + GUI/CLI | Restore verified project without dropping history; corrupt/stale inputs refuse safely and preserve prior data; J/G pass |
| Reproducible JSON/Markdown/HTML reports | Implemented; final journey incomplete | D,R: 50% | Reopen-export-replay journey with CVE/KB context, unknowns and manual judgments | Main/#291/#297/#304; `reports.py`, `report2/` | Stable source/run/findings identities | `test_report2_export.py`, report injection and backup suites | Escape hostile content; retain uncertainty and provenance | GUI/CLI + security | Self-contained exports identify inputs/runs and separate fact from interpretation; J/G pass |
| Strings export and extraction metadata | Partial; known publication review lead | D: 25% | Reproduce no-clobber race and repair; qualify extraction/truncation/redaction metadata including empty output | #289 scoped recovery; `strings/export.py`; current task tracker | Existing strings contracts and export callers | Export tests exist; race-specific proof/independent fix review still required at this baseline | Pre-check plus `os.replace` can overwrite a concurrently created destination; not yet reproduced by inventory worker | Security + GUI/CLI | `force=False` never clobbers a concurrent destination; metadata stays compatible and complete; R/J/G pass |
| Secondary BinDiff/BinExport/Rizin workflows | Implemented behind qualification boundaries | D,R: 50% | Current native Linux/Windows ownership, parser, cancellation and real-pair acceptance per adapter | Main/#293/#297/#307; secondary specs and identity guard record | Pinned external tools; verified inputs | Secondary/live-harness tests; parser tests do not prove native accuracy | Duplicate keys, malformed identities, output bounds, side ownership | Binary analysis + CI | Every adapter declares supported/blocked scope; malformed or ambiguous output cannot yield false HIT; J/G pass |
| Unified matching, semantic channels and calibration display | Implemented with conservative boundaries | D,R: 50% | Real cross-engine/compiler controls and independent calibration eligibility; keep ordinal display without valid gates | Main #287; #301/#304; SPEC-31 amendments | Qualified engine evidence, strict calibration artifacts | Unified symmetry/abstention suites and synthetic calibration tests | No unsupported statistical confidence, proof from name alone or forged calibration promotion | Binary analysis + research | Counterevidence/abstentions survive fusion; numeric confidence only after independent required validation; J/G pass |
| Multi-version series, PE/byte inspection and analyst panels | Implemented/alpha; manual qualification remains | D,R: 50% | Reopen and stale/missing pair journeys; native UI/accessibility acceptance for applicable panels | Main; module index and SPEC-09b/26 | Verified bytes, project series and Qt owner | nway, PE, representations and Qt suites; real/manual gaps remain | Bounded untrusted parsing, wrong-side evidence, safe text display | GUI/CLI + security | Partial/missing comparisons remain explicit, navigation never corrupts project history; J/G pass |
| Optional capa/FLOSS/diec, rules and callgraph context | Implemented with tool-specific limits | D,R: 50% | Current pinned-tool and real-source journeys; review outstanding raw-cache/layout branch residue | Main/#297; `intelligence/tools/`, rules/callgraph modules; `claude/instance-b-features` residue | Optional pinned tools and approved execution profiles | Tool parser/runner/live harness and rule/callgraph suites | Static defaults, explicit emulation opt-in, token redaction, bounded output | Binary analysis + GUI/CLI | Context retains provider/provenance and does not become vulnerability proof; J/G pass |
| Core CLI parity and documented analyst workflow | Implemented core verbs; complete journey pending | D,R: 50% | Complete create/import/compare/search/review/export/reopen journey; reconcile remaining UI-only convenience controls | #292/#297/#304/#307; core continuation and PW handoff | Existing backend/services; no parallel implementation | Project/compare/profile/doctor, KBC and search CLI tests | Owner-thread/store lifecycle; explicit network consent | GUI/CLI + documentation | Core work completes using documented commands with stable exit codes and recoverable cancellation; J/G pass |
| Linux package, Windows ZIP/installer and release guard | Implemented build/gate code; acceptance blocked | D,R: 50% | Fresh final-head package/native smoke, clean-machine/manual Windows acceptance and dependency/security gates | Main/#281/#297/#304; `qa-windows.yml`, build tools, release verifier | Native platform runners and external runtime documentation | Build/preflight/release-gate tests; real artifacts still require verification | Release must fail closed; `[no release]` retained; no tag/release authorization | CI/release + security | All mandatory required gates pass and artifacts match source/hash/license inventory; J/G pass without publishing |

## Research maturity remains separate

| Track | Preserved result | Remaining acceptance |
|---|---|---|
| L1 frozen source correlation | Historical `f69614fa` replay: 73 PASS, 6 FAIL, 0 BLOCKED, 8 excluded from 87 frozen cases; exit 1 | Resolve four Server coverage gaps and two preview cases in separate versioned experiments. Preserve original expectations and FAIL receipt. This debugging corpus is not independent predictive accuracy. |
| L2 native http-parser pilot | Original MISS / FAIL retained; isolated discovery correction has authored-control evidence | Independently review/pin any tool change, qualify native ownership/cancellation/Windows behavior and prospective source-oracle symbol identity before new scoring. |
| L3 CVE-2022-34718 | Metadata-only plan; `facts: unverified` | Concrete approved acquisition, exact binary/source identities and executable evidence; no acquisition or score is implied by this matrix. |

## Update rule

For each integrated milestone, append the exact source SHA, independent reviewer,
commands/results, newly completed named criteria and remaining blockers. Refresh
the branch/PR ledger separately. Preserve earlier failed, incomplete, skipped and
queued evidence. A changed head invalidates final-head acceptance; a documentation
append must not disguise that distinction. Beta readiness requires every mandatory
production journey and final gate, unresolved critical/high defects accounted for,
and explicit disposition of branch residue. This matrix makes no beta-ready claim.

## Later 2026-11-18 repair checkpoint

Source `9002a1f44c6aebcf2c49b29d631aacf20e7ce9e3` combines the reviewed #304
repair parent, golden-manifest/tooltip corrections, owned immutable KB objects and
research Ghidriff identity guard. **2,866 affected tests pass; four native/optional
checks are skipped and unverified.** Root independently reviewed the new storage
and parser boundaries. The [checkpoint](../qa/autonomous-consolidation-20261118/checkpoint/README.md)
records exact commands, source hashes, failures, reviews, fresh hosted receipts and
remaining gates. Earlier rows remain the baseline; the following entries update
only the named scope. No aggregate percentage or beta-ready claim is made.

| Feature/scope | Updated state and milestone coverage | Remaining acceptance |
|---|---|---|
| KB inventory/object durability | Reproduced object races and root/alias drift repaired and independently reviewed; existing inventory D/R/J remains 75% | Full actual-head/native Windows/manual/package/security G is unverified |
| Research Ghidriff name projection | Malformed/ambiguous reports block before scoring; decorated Markdown remains valid; separate parser-only evidence | Production/native ranking accuracy and frozen outcomes are unchanged |
| Non-forced strings publication | Reviewed repair published in #308 `92a411bf`; D/R 50% for this bounded export slice | Native/full G, representative J and document-level extraction/truncation/redaction metadata |
| Paired raw-offset desktop | Separate source `e4506666`, author 182 affected and independent 183 plus six controls; D/R 50% | Focused PR integration, native/manual J and final G |
| Saved/recent search | Separate source `e705974b`, 374 affected passes; independent review pending, D remains 25% | Review, publish, repeated real journey and final gates; saved rows are project-owned, recent text is explicitly per-user |
| CVE assessment freshness | Seven authored regressions confirm stale assessments can appear current after revision/advisory changes, and desktop KEV inputs differ | Assigned shared current-input/revision repair; preserve historical assessments and uncertainty |
| Release qualification | Exact-source native/security gate gaps confirmed; no qualification milestone added | Shared fail-closed checker and scan policy, then actual complete qualifying evidence; no publication authorized |

The 55-open-PR review/comment/check snapshot is preserved separately from the
initial 307-branch/297-PR mechanical inventory. Empty GitHub review collections
are not review approval. Four fresh #304 native fixture receipts are narrowly
credited at their recorded source tree; full/Qt/Windows/package/security remain
unverified. The local incomplete full-suite attempt is preserved, not counted.


## Reviewed advisory read-budget continuation — 2026-11-18

Source `06f5b210e5c6daffaae2b4d51fd8950c28be25c3` repairs reproduced unbounded retained-file reads. Author and independent affected gates each pass 140 tests; 11 independent filesystem controls and five backup tests also pass. Original seven failures are retained. This supports D/R for the advisory storage repair only and adds no J/G credit to the broader advisory/persistence rows. Native Windows, full/platform gates and cumulative store budgets remain open. [Evidence](../qa/advisory-read-bounds-20261118.md).


## Reviewed retained-CVE continuation — 2026-11-18

Combined source `ac789497597fba3cb87696990d171a7a27024fca` adds retained CVRF candidate context, shared current-evidence checks for CLI/desktop/publication/navigation/reports, and two independently reproduced SQLite repairs. Root verification is 1,924 passed with zero skips, including six unchanged defect probes and six combined history/report controls. The source preserves actual PR #313 as an ancestor. D/R evidence is complete for these bounded slices; the wider CVE-to-function and report rows remain D/R = 50% because representative real-source/native J and final G are open. No accuracy or overall completion percentage is inferred. [Evidence and remaining tasks](../qa/pilot-cvrf-reviewed-20261118/README.md).

## Paired raw-window independent integration checkpoint — 2026-11-18

The paired raw-offset desktop slice now has independent source review (183 affected plus six additional controls) and 183 source-pinned combined passes on published #307, source `21552835`. D/R coverage remains **50%**: the implementation and regressions are verified locally, while representative native/manual J and exact-head full/platform/security G remain open. The original author receipt and failure history are retained; this entry does not promote the historical #168 research content or claim beta readiness. [Review and evidence](../qa/raw-alignment-reviewed-20261118/README.md).

## Saved-search independent integration checkpoint — 2026-11-18

Saved/recent search advances to **D/R:50%** for the named slice: project-owned Save/Run/Delete and CLI operations, compatible mode/filter replay, and bounded per-user recent text are implemented and independently reviewed. The delayed Build execution-intent defect was reproduced and repaired at `c30c7911`; the combined published #307 base passed376 affected checks at `f021f2d0`. Real/native/manual J and exact-head full/platform/security G remain unverified. Original receipts and research boundaries remain unchanged. [Review and scope](../qa/saved-search-reviewed-20261118/README.md).

## Primary environment default repair checkpoint — 2026-11-18

The default primary-child environment slice has specification, reproduced failure, minimal repair and independent regression evidence at `1f9ad863` (370 independent affected/additional passes,3 native Windows skips). D/R scope is50%; real native/manual J and exact-head full/platform/security G remain open. Explicit legacy full inheritance remains a documented analyst compatibility choice; default minimization is not a network sandbox. The broader primary resource-bound/security work remains incomplete. [Evidence](../qa/primary-environment-20261118/README.md).

## Reviewed release-qualification continuation — 2026-11-18

Combined source `ef0398577c97b926259b533c5776e88146244b24` on published #307 carries the independent repair of `05176698`: canonical-byte checks, finite evidence and unique artifact ownership. Root affected verification is 458 passed / 3 existing expected failures, with 19 independent controls passing. This completes the guard slice's D/R evidence only; the package/release row remains D/R = 50%. No J/G credit is added. Missing scan evidence, blocked Windows BinDiff disconnected acceptance, native/package/full exact-head gates and the literal commit hold continue to prevent publication. [Checkpoint](../qa/release-qualification-reviewed-20261118/README.md).

## Reviewed PE manifest boundary — 2026-11-18

Source `e1c5006e51606caedd773bf079c20c145d290861` repairs an independently reproduced encoding-dependent DTD-policy bypass. Root exact-source gate passes 384 cases, including unchanged external probes; original failures remain retained. This supplies D/R for the narrow parser boundary and does not add native/platform J/G credit to PE inspection. Strict static scan findings and complete gates remain open. [Evidence](../qa/manifest-dtd-reviewed-20261118/README.md).

## Semantic branch review continuation — 2026-11-18

[Batch 1](autonomous-consolidation-20261118/semantic-disposition-batch1.md)
provides scoped source evidence for 20 of the 131 mechanically unresolved tips
at `ac789497597fba3cb87696990d171a7a27024fca`. Seventeen focal behaviors are
retained; three overlapping checkpoint tips remain partial. No product
completion percentage or acceptance milestone is added from branch counts or
passing test counts. The other 111 tips and broad checkpoint research residue
still need semantic review.

| Scope | Current observation | Remaining work |
|---|---|---|
| Incomplete-project retry | Three real SQL controls show foreign views, triggers or columns can be replaced; healthy empty-schema retry passes | Narrow refusal repair, bounds and preservation review |
| Callgraph completeness | Per-node omissions and duplicate focus inputs reproduce incorrect complete results | Selective query/export/UI cap-truth repair with negative and below-cap controls |
| Callgraph path work | Shared-budget and cancellation controls reproduce prepass/copy work outside the intended bound | Separate lazy CSR/shared-budget repair, deterministic witness and order verification |
| Packaged KB investigation journey | Historical synthetic F8 self-test exceeds current sample/panel-only self-test scope | Adapted source/frozen journey; native Windows and manual acceptance remain separate |

The passing current replacement gates and original red controls are retained in
the [QA receipt](../qa/semantic-disposition-batch1-20261118.md). They do not
authorize merges, branch deletion, a release, or a native compatibility claim.

## Combined follow-up acceptance — 2026-11-18

Current reviewed source `3be3af166897fc2376dc64850edc66485273dea1` combines published #308–#315, the actual #304/#307 ancestors and selectively reviewed repairs. Main remains `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`. The selected combined gate passes 1,770 with three existing expected failures; all 75 changed source/test/tool/workflow paths are accounted for. This adds scoped regression evidence, not final G acceptance. Earlier rows remain their dated baseline; the following table records the updated narrow boundaries.

| Feature | Current state | Completion | Remaining work | Source | Dependencies | Tests | Security | Owner | Acceptance |
|---|---|---|---|---|---|---|---|---|---|
| Incomplete-project retry | Narrow schema/replacement repair integrated | D,R: 50% | Native Windows and complete recovery journey; final gates | `8b3c6472`, this candidate | Project lock, SQLite connection ownership | Root 236 plus 5 controls; combined gate | Cooperative namespace assumptions remain explicit | Security/GUI | Foreign/replaced data preserved; interrupted retries reopen safely; J/G |
| Callgraph partial results and path work | Both narrow repairs integrated | D,R: 50% | Native/manual/full/platform acceptance | `2c69c4ad`, `f0b0eb02` | Existing CSR and Calls owner | Root 464 cap, 490 path, unchanged historical controls; overlapping counts | Work budgets, cancellation and omission truth retained | GUI/CLI/security | Correct partial/complete outputs and bounded work on representative journey; J/G |
| Saved/recent queries and raw-offset controls | Reviewed user surfaces integrated | D,R: 50% | Representative native/manual journeys and final gates | #309/#310 | Existing project/search/task ownership | Original focused gates and combined selection | Stale delivery and unintended delayed execution refused | GUI/CLI | Stable save/run/delete and original-byte navigation through reopen/export; J/G |
| Current CVRF/Leads/report context | Retained-context delivery integrated; full CVE journey partial | D,R: 50% | Approved acquisition, native candidate/negative-control journey | #313/#314 | Shared current inputs, typed rows, retained source IDs | Root 1,924 source checks plus new combined selection | BLOB/type and 16 MiB row budgets; stale evidence excluded | CVE/KB/security | Source facts and uncertainty survive complete investigation; J/G |
| Dependency/security provenance | Scanner/bootstrap delivered; static/platform qualification open | D,R: 50% | All79 static dispositions, native Windows and actual integrated scans | `b61e1593`, `0c004b68` | Exact installer/interpreter receipts and approved audit service | Root 160 bootstrap; local 17/32 complete zero-advisory inventories | Original failures retained; no package omission, ignore list or auto-fix | CI/security | Complete matching closures and substantive security acceptance on final source; J/G |
| Release qualification and packaging | Reviewed guards integrated; new-source qualification blocked | D,R: 50% | Final-source Linux/Windows/native/Qt/package/scanner evidence and reproducibility | #312, this candidate | Platform runners and native tool identities | #304 full/package results are separately scoped; new combined selected gate | Windows BinDiff blocked; compiler sweep partial; release hold retained | CI/coordinator | All applicable final gates pass, no absent/blocked evidence accepted; J/G |

The fresh #304 full suites, repeated Qt and package receipts do not provide G to this new tree. Compiler smoke 5/11 and the blocked Windows BinDiff artifact remain explicit. Research outcomes and the wider CVE/acquisition/manual feature gaps are unchanged. [Detailed checkpoint, sources and remaining work](../qa/verified-followup-integration-20261118/README.md).

## Staging and static boundary continuation — 2026-11-18

Source `2c0d51cb3cd237dfd6ef8740f36404cd15abe1bc` retains the independently accepted failed-mkdir ownership repair (`43ac4829`, root 140/author 219 overlapping passes). The narrow staging slice has D/R evidence; broader persistence J/G remain open. Forty-three original assertion/SQL sites have source-specific dispositions and 16 combined-source normal/-O child controls; the current complete strict scan still fails 81 diagnostics, including two later source additions. No whole-security milestone is earned. Failed/cancelled/timeout attempt persistence can omit a storage diagnostic in the desktop; the reproduced separate repair is assigned. [Current receipt and remaining scope](../qa/static-ownership-followup-20261118/README.md).

## Semantic branch review batch 2 — 2026-11-18

[Batch 2](autonomous-consolidation-20261118/semantic-disposition-batch2.md)
adds scoped evidence for 20 original tips at
`3be3af166897fc2376dc64850edc66485273dea1`: 18 focal behaviors retained,
two overlapping tips with one missing selected-source explanation. The original
mechanical set remains 131; 40 scopes have been selected across two batches,
leaving 91 unselected original tips plus documented broad-tip residue.

| Criterion | Current evidence | Remaining boundary |
|---|---|---|
| Selected enrichment/acquisition/rule/n-way behaviors | Source comparisons, replacement ancestry and current controls retained | No whole-branch closure; native/provider/empirical gates separate |
| Selected superseded advisory explanation | Original warning control is red; actual CLI JSON/text reproduces the missing explanation; source withholding is correct | Separate bounded warning/presentation repair and independent review |
| Historical controls | Original files and failures preserved with explicit contract/fixture diagnoses | Historical trees are not freshly qualified |
| Native platform acceptance | WinVerifyTrust and msdelta skipped on Linux | Windows execution and package/manual gates remain open |

This documentation does not add D/R/J/G percentage credit or change a feature
readiness estimate. Branch/test counts do not measure completed requirements.
The separately reviewed creation and two callgraph repairs now present in the
comparison tree retain their own acceptance receipts and original failure history.

## Semantic batch 3 scope update — 2026-11-18


This read-only update is pinned to actual PR #316 `55f3d074`, independently of later
continuation source. It adds no product milestone or percentage: the denominator
131 is original branch tips needing reconciliation, not feature acceptance criteria.
Twenty more selected scopes bring the cumulative selection to 60; 71 remain
unselected and broad-tip residue remains open.

| Assessed scope | Current evidence at the pinned source | Remaining work/acceptance |
|---|---|---|
| Eighteen focal runtime/desktop/representation behaviors | Actual source/caller replacements and 666-pass shared gate, four Windows skips | Unreviewed branch residue; native/manual/package and final combined gates |
| Backup destination ownership | Retained helper fails two POSIX empty-replacement controls; ordinary backup passes | Root-owned publication design/repair; preserve original database/foreign destination; separate Windows/native qualification |
| Code-highlighter bulk-load dispatch | Original historical guard is absent; one unchanged failure with two formatting/scroll positives | Narrow spec/test-first guard repair and independent source/normal/high-DPI checks; no native timing claim |

[Detailed exact-tip disposition](autonomous-consolidation-20261118/semantic-disposition-batch3.md)
and [raw QA receipt](../qa/semantic-disposition-batch3-20261118.md) preserve the
historical failures and current-source limits. No whole-branch closure follows.


## Reviewed continuation source — 2026-11-18

Source `5bbb925694b89ddc77e2aae1ea36c9f563c7760d` (tree `0ba373d19098c4c469dc3bfb9a0a0f75c573dd8c`) preserves actual PR #316 as its ancestor and
passes 2,764 selected checks with nine explicit skips. All 26 changed source/test/
tool/workflow files match reviewed owner bytes. This is scoped regression
evidence; final full/platform/native/package/security G remains open. Main is
unchanged. The [complete checkpoint](../qa/verified-continuation-20261118/README.md)
retains original failures, per-source results, capability limits and archive hashes.

| Feature/slice | Current state | Milestones | Concrete remaining acceptance |
|---|---|---|---|
| Failed-attempt diagnostics and named superseded-source explanations | Reviewed repairs integrated locally | D/R: 50% | Representative native/manual J; actual final G; unchanged evidence withholding/publication semantics |
| Backup/offline-runtime directory publication | Reviewed no-replacement helper and reparse admission integrated | D/R: 50% | Native Windows filesystem/junction checks, representative recovery J and final G |
| Highlighter dispatch | Narrow model/session/window guard integrated; current/historical positives retained | D/R: 50% | Native/manual scaling and complete investigation J; final G |
| Packaged KB self-test | Synthetic current-service journey, source snapshots and failure cleanup implemented | D/R: 50% | Extracted Windows/Linux packages and real-source/native/manual J; final G; no accuracy credit from authored fixtures |
| Windows BinDiff effective denial | Acceptance candidate plus canonical process identities integrated in tooling | D/R: 50% for portable validator/tooling slice | Windows SDK build, effective socket/token/descendant/lifecycle observations and actual adapter semantic equality; native J/G open |
| Broad suite and strict security | Original broad run incomplete; guarded path recheck and hermetic fixture repaired; strict 80 findings remain | No new G credit | Complete exact-source full/platform/scanner gates; all skips/blocked receipts unverified |
| PW-02 local MSU/CAB intake | Planned separate product slice | None: 0% | Bounded native extraction contract/implementation, independent review and Windows journey |

The seven named fixes add no aggregate product percentage. Batch 2/3 source
reviews select 60/131 original unresolved tips; 71 and broader residue remain at
this snapshot. R2 acceptance-witness/manual-attribution repair is still separate
active work and is absent from this source. Native/frozen L1/L2/L3 boundaries and
the no-release hold remain intact.

## Semantic batch 4 scope update — 2026-11-18

This read-only assessment is pinned to published PR316 55f3d074. Twenty further
selected scopes bring the original branch-tip denominator to 80 selected / 51
unselected out of 131; no feature percentage or completed-branch credit follows.

| Scope | Evidence at the frozen source | Remaining acceptance |
|---|---|---|
| Fifteen retained focal scopes and one stricter adapter replacement | Actual patch/caller/source proof; shared 42-file gate, 1,017 passed, zero skipped | Broader branch residue and final native/platform/package/manual gates |
| R2 witness and manual attribution | Original failures plus strict persisted detail and reopened CLI controls; four v3 failures/one positive | Separately owned mirror-safe cap/manual explanation repair and independent acceptance; preserve current Support semantics |
| Tier W acquisition developer workflow | Bounded exact-consent fetch library and explicit missing-CLI BLOCKED path | Saved plan and CLI orchestration, current contracts, real local-only corpus acceptance |
| R1 research orchestration | Immutable build receipts/session identity/truth guards retained | Four missing research runners; full matrix/holdout review and real native ground truth |
| R7 prototype | Three exact tool files and bounded pure controls | Production extractor/analyst bridge, verified control dependence and native accuracy remain unbuilt/unqualified |

The known directory publication, UI diagnostics, named-source, highlighter and F8
follow-ons remain separately attributed. [Detailed ledger](autonomous-consolidation-20261118/semantic-disposition-batch4.md)
and [QA packet](../qa/semantic-disposition-batch4-20261118.md) preserve all original
failures, explicit deselections, current contract mismatches and scope limits.


## Reviewed R2 continuation and hosted55 evidence — 2026-11-18

Source `ae0b1660e0cc71c51698d70a685ceeb646619184` passes 3,528 selected checks with
nine explicit skips, all 31 changed source/test/tool/workflow paths equal to reviewed
owners. [Complete source-specific checkpoint](../qa/continuation-r2-20261118/README.md).
R2 witness retention/manual attribution adds the defined D/R milestones (50% for
this bounded slice); representative native/manual J and final G remain open.
Support semantics and old evidence stay intact. Batch4 reaches 80/131 selected
original scopes, 51 remaining plus broader residue; no whole-branch percentage.

Hosted55 results establish limited authored native fixtures and one runtime audit
at that older tree. Strict81 diagnostics and missing static bootstrap text remain
failed/incomplete; the current source's separate strict scan remains 80 unchanged
sites. These results add no final candidate G credit. Saved advisory-scope repair,
remaining branch dispositions, PW-02 local package intake, full/platform/package
qualification and main integration remain unfinished. No beta/release readiness.

## Semantic disposition checkpoint 5 — 2026-11-18

Batch5 inspects 20 further exact source-bearing original tips against frozen actual PR316
55f3d0742f7d4cf32357a42b8b1cc76d85875e71. Current-source gate: 1,129 passed,
one Windows-only skip, one existing CODEX-14 xfail, four explicit compiler/native
deselections. Original historical failures are retained and individually classified.

Confirmed narrow omissions: saved advisory scope/digest (public reopened CLI and
actual missing-coverage mutation), unquoted COFF false-change acceptance in an optional developer API (fake
producer) and A/A failures omitted from merged shard provenance (persisted public
flow). COFF and saved-scope repairs have separate root-assigned ownership; no
repair credit is included here. Typed config, final-run/recipe/transfer research
workflows and part of the Windows CI proposal remain incomplete, with native and
platform gates explicit. Earlier continuation repairs are separately attributed.

100 of 131 original reconciliation tips now have selected scopes; 31 remain
unselected. These counts do not close whole branches or estimate feature completion.
See [batch5 ledger](autonomous-consolidation-20261118/semantic-disposition-batch5.md) and the exact JSON/archive.

## Semantic branch disposition batch6 — frozen actual 55f3 comparison

Twenty additional original tips have bounded focal dispositions: fourteen with
net production-source deltas and six fixture/test-only tips. Cumulative selection
is 120/131; eleven remain unselected. No new product defect was confirmed. This is
not whole-branch closure or a product completion percentage. The fresh 29-file gate
passed 173 cases with two explicit compiler deselections. Original Java 6 pass and
unified fixture 1 fail/6 pass/1 error then 7 pass/1 error are retained and explained;
current canonical controls pass without relaxing lineage or parser requirements.
Prior exact 55f3 receipts for inherited scopes are referenced, never counted twice.
Broad 79/85-path consolidation/research/native/platform residue remains open.
See [batch6](autonomous-consolidation-20261118/semantic-disposition-batch6.md).

## Semantic disposition batch7 — final original focal partition

The final 11 original tips have bounded workflow/test/documentation dispositions
against actual PR316 source 55f3. All 131 original reconciliation branch names now
have one focal record; zero remain unselected. Exact original tips and the known
alias are checked. This is not whole-branch closure or a product percentage.

The fresh gate passed 100 cases, with four known CODEX xfails and one explicit
real-launcher deselection. Original audit 19 pass/5 classified failures, deadline 2
pass, Phase2 reference 23 pass, and its initial missing-dependency collection error
are preserved. CODEX1/5/6/14 remain open; the old license-policy assertion is
superseded by explicit enforced current policy. The unretained reference package
needs contract reconciliation, and xdist/memory-isolation proposals remain
unqualified. Broad research/native/platform/hosted/manual residue remains open.
See [batch7](autonomous-consolidation-20261118/semantic-disposition-batch7.md).


## Verified continuation tail — 2026-11-18, source068513a7

Actual source `068513a72e8a1412ce3960d3024c462d68d51376` passes6,356 selected tests,18 explicit skips and three
known CODEX expected failures (215 files,385.72s). All552 imported project modules
and101 changed owner paths are pinned. Strict S remains80 unchanged findings;
full/platform/native/package/security final G remains open. Main stays `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`.
[Complete checkpoint](../qa/continuation-tail-20261118/README.md).

| Feature / bounded scope | Current state | Completion | Concrete remaining work | Source | Dependencies | Tests | Security | Owner | Acceptance |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Saved advisory-scope admission | Implemented and independently reviewed on candidate | D,R:50% | Representative real-source/native journey and final gates; preserve current documented recovery limits | a7f6c9c4, PR316 | Existing global index, coverage identity, caller-thread SQLite | Original failures, author2604/one native skip, root99, actual combined gate | Scope validation before approvals, inventory and all selected recovery writes | CVE/KB + root | Stable finite scope and admission-sensitive context after reopen; J/G |
| Local-package pure contracts and budgets | Bounded preparatory slice implemented; no native intake caller | D,R:50% for this slice | Serial worker grants, native stage/FDI, held reader and durable provenance composition |64583964, PR316| Existing acquisition errors; generated schemas | Original157/6 boundary failures and Kelvin red retained; corrected284 and independent281+19 per-source invocations; actual combined | ASCII-only selection, graph ownership, reserve-before-write, bounded names/counts/time | CI + security | Native and representative journey separate; no capability claim from records |
| Whole local MSU/CAB fallback (PW02) | Partial implementation; no working package-to-project route | None:0% of whole-feature milestones | Implement and qualify native decoder/worker/stage, existing KB/core path, durable linkage and frozen journey | Current contracts + separate joint design | Qualified Windows lane and explicit local inputs | Portable contracts only; native/frozen route absent | No target execution, retained locks, deadline and committed-project preservation required | CI + CVE/KB | Full specified package-to-project route before whole-feature D/R/J/G credit |
| A/A classification and optional COFF compatibility | Reviewed developer/research mechanics | D,R:50% for each bounded slice | Native compiler/rebuild/accuracy qualification and final applicable gates |9bd17bbe,ce093ec5| Existing shard/store/merge and optional source-layer check | Original public failures and actual combined regression | Preserve other statuses, full counterevidence and optional-caller boundary | Research + root | No frozen-outcome or product-accuracy credit from authored fixtures |
| Immutable workflow action references | Implemented reference-only repair | D,R:50% | Exact-source hosted behavior; dependency lock closure; other CI defects and final gates |3b3c3d63,f6cc9a18|23 canonical API objects; existing workflow policy|430/three known xfails at owner source; actual combined|178 mutable uses pinned; triggers/permissions/secrets/scripts unchanged|CI + root|Hosted and final qualification, not static checks alone |
| Windows source observation guards | Portable source repair independently reviewed | D,R:50% | Eight native Windows observations, actual scanner/BinDiff/package reruns |80df2735|CPython path/descriptor semantics; existing source verification|240/8 native skips, independent44 and252/8; actual combined|Final same-view ChangeTime and complete receipt checks retained|CI + root|Native Windows and final-source G; old hosted generic failure cause remains inferred |

All131 original reconciliation branch names now have a focal disposition; zero
remain unselected in that original partition. Whole-branch residue and research/
native/platform work remain. This count is not a feature percentage. The separate
cache/smoke/purity handoffs and next package work are absent from this frozen
candidate. Historical rows above remain attributed to their own dates/sources.


## CI follow-up — 2026-11-18, source f3b7a0e8

Source `f3b7a0e895c3b9928e08f93ac77d2afda5c56dd8` integrates independently reviewed archive-cache verification,
full Linux frozen-smoke wiring and lazy publication ctypes imports. Exact
30-file gate: **1,028 passed, two explicit skips, one CODEX5 expected failure**,
zero failures/errors,22.89s. All221 imported modules and ten changed owner files
match Git bytes. Normal Ruff passes; strict S remains80 unchanged findings and
fails. The preceding PR316 f3 checkpoint was published with a verified non-force
lease; main remains `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`. No merge/release/platform acceptance follows.
[Source-specific checkpoint](../qa/ci-followup-20261118/README.md).


| Feature / bounded scope | Current state | Completion | Remaining work | Source | Dependencies | Tests | Security | Owner | Acceptance |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Cached engine archive verification | Implemented and independently reviewed | D,R:50% for this slice | Hosted exact-source cold/cache-hit gates and full qualification |451e463d, PR316|Existing pins/download endpoints|Original failures,26 root checks,combined1,028|Verify before extraction; cooperative workspace boundary|CI + root|Native/hosted/final G remains open|
| Full Linux frozen smoke invocation | Implemented and independently reviewed | D,R:50% for this slice | Actual new frozen executable/package gate |2a7e3147, PR316|Existing complete smoke harness|Required policy,5 builder controls,source CLI and combined gate|Failure/timeout prevents archive creation|CI + root|Actual artifact smoke and final G|
| Pure IR import / native FFI boundary | Implemented and independently reviewed | D,R:50% for this slice | Native Windows and complete final gates |73bd7ead, PR316|Existing no-replace publication|Fresh subprocess imports,all existing ownership assertions,independent replay|No import-time FFI; move behavior unchanged|CI + root|Pure imports plus native/final G|

Whole PW02 remains partial with no package-to-project journey. New Windows
dependency encoding and BinDiff no-network failures are preserved on the prior
f3/preview tree and assigned for focused diagnosis; successful job badges do not
qualify those failed receipts. Worker grants, neutral core readers and signal
navigation are separate candidates under review, absent from this source.

### Phase 2 reference disposition supplement (frozen 068513a7)

All nine historical reference record families now have an explicit producer/consumer and incompatible-field disposition in [the follow-up](phase2-reference-contract-disposition-20261118.md). This adds no whole-branch closure or product-completion percentage. Current enrichment/1 and pilot/1 remain separate. The documented UI live-location validation omission has a real saved-row/reopen/navigation reproduction (3 failed / 4 positives) and is assigned as a separate repair; 697 passing neighboring checks do not close it. Native/provider/calibration and broader reference-only gaps remain stated in the receipt.

## P2-NAV-1 bounded navigation candidate — 2026-11-18

Pinned source `9592f8b362537c0545010d4499e35770a248297e` from `068513a7`;
[sealed QA](../qa/signal-navigation-validation-20261118.md). Current run/artifact/
function/side/address and line/excerpt validation, unsupported representation
refusal, unchanged valid decompiled navigation, repeated live-data checking,
and refusal without project/ranking/store mutation are covered by authored
persisted/reopened offscreen controls. The shared validator and scoring/storage
implementations remain byte-identical. The host seam and global tooltip gate pass.
This is a source-qualified candidate awaiting root independent final review,
not native Windows, packaged/frozen or manual analyst acceptance. Original
failures and fixture corrections stay visible; the overlapping test counts
do not define a completion percentage or discharge broader reference/research work.


## Worker, core and navigation milestone — 2026-11-18, source207eea9d

Exact source `207eea9d4e125ac1d371139d4db803ddbc2b4c8a` passes **1,103 tests, one native Windows skip**,
zero failures/errors/xfails,44.57s. The51-file gate preserves all28 unchanged
independent cases,23 reviewed owner paths and498 exact Git-pinned imports.
Normal Ruff and generated schemas pass; strict S remains80 unchanged findings.
Original terminal-counter, cleanup-primary-error and assembly-navigation reds,
fixture/preflight corrections and all preceding source-specific receipts remain.
[Complete checkpoint](../qa/worker-core-navigation-20261118/README.md).
Main remains `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`; PR316 is open, PR304/307 blocked by final gates.
No merge/closure/tag/release/deployment or branch deletion occurred.


| Feature / bounded scope | Current state | Completion | Remaining work | Source | Dependencies | Tests | Security | Owner | Acceptance |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Portable serial worker accounting | Implemented and independently reviewed | D,R:50% for this slice | Native handoff/worker composition and final applicable gates |7259f868,PR316|Existing package contracts and original parent budget|Author/corrected/original-red receipts plus exact combined gate|No terminal mutation, refunds or resumed failed worker|CI + root|Native and whole package journey remain separate|
| Neutral held-input core API | Implemented and independently reviewed | D,R:50% for this slice | Existing KB propagation, real native provider, durable package linkage, final gates |97408609,PR316|Core ingestion/store ownership; provider lease|Author318,independent52,exact combined with original14 cases|No path fallback; bounded reads; original error survives cleanup; before-COMMIT checkpoint|Core + root|Real caller/native/journey and final G|
| Live signal navigation validation | Implemented and independently reviewed | D,R:50% for bounded action | Native/manual/frozen analyst acceptance and broader Phase2 work |9592f8b3,PR316|Unchanged live validator and persisted evidence|Author175,unchanged7+2 probes,exact combined|Refuse stale/unsupported locations before mode/cursor changes|GUI + root|Current decompiled action preserved; no assembly support claim|
| Whole local package fallback PW02 | Partial; no package-to-project route | None:0% of whole-feature milestones | Native stage/FDI/process transfer, KB adapter, read ledger, durable provenance and frozen journey |Portable slice plus retained designs|Qualified Windows lane and existing KB/core service|Portable authored scopes only|Lease/lifetime/original budget/durable project ownership remain required|CI + KB + core|Whole-feature D/R/J/G requires complete specified journey|

The Phase2 reference disposition and installer/native/KB designs are now reviewed
records. They do not implement hash locks, reference interchange or native
support. Completion is based on the existing D/R/J/G milestones, not test counts.
Windows inventory encoding and native descendant diagnostics are active focused
workstreams. Final full/platform/native/package/security/reproducibility gates,
real CVE/KB journeys and frozen research limitations remain open.


## Internal KB held-input propagation candidate — 2026-11-18

Source `d9a939911f39f3641bd5eed97a2ce067d618856b` implements only the approved
internal capability in existing KB service/wiring/attachment. Its exact
15-file authored gate passes 300 cases with zero skips, and the unchanged
independent short-read probe passes all five cases. Earlier API and short-read
failures remain in [the sealed receipt](../qa/kb-held-input-propagation-20261118.md).
These overlapping counts are evidence at this source, not feature percentages.

| Boundary | Current evidence | Remaining gate |
| --- | --- | --- |
| Internal KB held capability | Same live pair/checkpoint, full hashes, finite PE prefix, ordinary injection, saved/global admission and typed stop/commit controls | Root final independent replay and integration |
| Held-origin package route | No CLI/GUI/package entry point added; serialized records unchanged | Durable expected identity/provenance and refusal of reader-less source-path recovery before exposure |
| Whole PW02 local package fallback | Still partial; no working native package-to-project journey | Native stage/FDI/worker lease transfer, durable reconciliation, postcommit read accounting, Windows/frozen journey and final applicable gates |

The existing injected post-create fault and postcommit project-copy reads remain
explicit limits. Portable descriptor and SQLite tests do not supply native or
manual acceptance. No whole-feature completion or release credit is added.


## KB, UTF-8 and native diagnostic milestone — 2026-11-18

Exact source `7b5f558fb1a51d45427648c39c15995ab3697e2c` passes803 tests with zero skips/failures/errors in9.76s.
All118 imported project/tool modules and14 reviewed owner paths match Git; the
same23-file gate retains the original802-pass/one-registry-failure result and its
one-row documentation correction. Normal Ruff passes; strict S still fails on80
unchanged sites. The KB short-read correction, isolated UTF-8 invocation and
bounded stderr diagnostic source are independently reviewed and integrated.
[Complete checkpoint](../qa/kb-native-followup-20261118/README.md).
Fresh316-branch/63-open-PR refresh preserves all131 focal tips and verifies all11
changed/new tips as ancestors of fb09. Main remains `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`; no main merge,
closure, force-push, deletion, tag, release or deployment occurs. Current fb09
Windows native/dependency failures and pending full/Qt jobs remain source-specific.


| Feature / bounded scope | Current state | Completion | Remaining work | Source | Dependencies | Tests | Security | Owner | Acceptance |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Internal KB held-reader propagation | Implemented and independently reviewed | D,R:50% for this slice | Durable held-origin intent/expected identity, postcommit checkpoints, native provider and final gates |d9a93991,PR316|Existing KB/core readers and caller-thread SQLite|Original32/1 and3/2 reds, author300, unchanged5 probe, combined803|No path fallback; full admission/hashes and finite prefix; retained committed outcome|KB + root|No exposed package route until durable recovery is qualified|
| Isolated dependency JSON UTF-8 | Implemented and independently reviewed | D,R:50% for this slice | Exact-source Windows pip/audit/packaging and lock closure |6dea194a,PR316|Existing isolated Python argv/environment and evidence validation|Original encoding failures, author/root167, combined803|Same bounds/pins/strict raw validation; no environment fallback|CI + root|Actual hosted Windows and final G|
| Native failure diagnostics | Implemented portable diagnostic support | D,R:50% for this diagnostic slice | Windows SDK build and actual error-path/complete native acceptance |9ca3c078/ace5db8b,PR316|Existing helper/Job/AppContainer evidence|Real portable formatter/refusal controls, preserved fixture errors, combined803|Fixed stderr vocabulary/numeric fields, finite lifetime budget; decisions unchanged|CI + root|Diagnostics cannot substitute for denial/cleanup/BinDiff receipts|
| Core durable admission hooks | Reviewed design; implementation assigned | None:0% for proposed hook implementation | Spec/tests-first optional ID and open/load recovery/checkpoint forwarding |3e4abd88|Existing model/store and approved core ownership|Ten current-behavior observations only|Committed/foreign/unknown retention and close-only stops required|Core + root|Meaningful reds, source review and actual-candidate replay|
| Whole PW02 local package fallback | Partial; no exposed package-to-project route | None:0% of whole-feature milestones | Native stage/FDI/worker handoff, durable intent/provenance/reconciliation, original budgets and frozen journey |Current portable slices and retained designs|Qualified Windows lane and existing KB/core services|Portable components only; whole journey absent|No lost-lease pathname resurrection or cross-project adoption|KB + core + CI|Complete specified D/R/J/G journey|

Frozen research outcomes, real CVE matching/calibration, full platform/Qt/native/
package/security/reproducibility acceptance remain unchanged and incomplete.
These completion fractions follow the existing D/R/J/G definitions, not test counts.


## Core admission and actual Windows evidence — 2026-11-18

Exact source `a8f698f6a1d075b673bc6ec94c991141113d2b30` passes **1,200 checks with zero failures, errors or
skips in 17.85 seconds**. The 45-file scope preserves six original external probes,
434 canonical project/tool imports and 21 reviewed owner paths. Core expected ID,
explicit non-recovering checkpointed reads, acquired-open and constructor cleanup
are independently reviewed and integrated. Normal Ruff passes; strict S still
fails on 80 unchanged sites. Original failure evidence and both core author packets
remain immutable. [Complete checkpoint](../qa/core-admission-integration-20261118/README.md).

At published source 771e, both actual Windows dependency profiles now pass exact
inventory/audit/UTF-8 verification (17 runtime, 34 packaging distributions). Native
diagnostics compile and identify restricted NUL-open error 5 before descendant
creation; complete no-network acceptance still fails. Unified Windows has a new
preserved repeated-analysis digest mismatch, with the second-run records absent;
six full QA/Qt jobs remain pending at the separate 22:37 snapshot. Durable package
design is reviewed with an actual-connection non-initializing capture prerequisite.
Main remains `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`; PR304/307/316 stay open and unmerged. No tag/release/deployment.


| Feature / bounded scope | Current state | Completion | Remaining work | Source | Dependencies | Tests | Security | Owner | Acceptance |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Core durable admission hooks | Implemented and independently integrated | D,R: 50% for this slice | Durable caller, native representative journey and final gates |441c47c2 /63ebc427; PR316 candidate|Existing core model/store and original reader checkpoint|Original open and constructor reds; author512/562; exact root1200|Strict early ID, complete verified reads, primary error and committed/foreign retention|Core + root|Per-call identity/ownership preserved through qualified durable/native journey and G|
| Isolated dependency JSON UTF-8 | Actual Windows inventory/audit verified | D,R,J: 75% for this slice|Final candidate gates, dependency lock closure and explicit unaudited categories|6dea194a; hosted771e|Existing isolated process and strict raw evidence contracts|Original CP1252 reds; root1200 union; actual Windows17/34-distribution audits|No environment fallback, skipped audit row or bound/pin relaxation|CI + root|Exact final-source profile/audit and G; no whole-package completion claim|
| Native failure diagnostics | Compiled and observed in actual Windows error path|D,R,J: 75% for diagnostics only|Trusted stdin transfer, effective-denial/descendant/adapter/lifecycle acceptance and final gates|9ca3c078; hosted771e|Existing C helpers, fixed bounded stderr protocol|Portable formatter controls; actual nine records/NUL error5; native overall failure retained|Timeout is not denial; source/handle/Job ownership remain required|CI + root|Complete native receipts at final source; diagnostics alone do not qualify isolation|
| Unified native repeatability | Implemented; current Windows determinism failure|D,R: 50%|Retain bounded first/second evidence, identify cause, repair only demonstrated defect, rerun native/final gates|771e run44409973392|Ghidra12.0.4/Java21.0.13/pyghidra3.0.2 and exact fixture hashes|CI pair passes; probe newer digest differs; Linux downstream skipped|No canonical-digest weakening or success from first-only metadata|Binary analysis + CI|Repeated exact inputs produce defensible stable identity under original assertions|
| Durable package intent/association/reconciliation|Reviewed design with confirmed capture prerequisite|None: 0% for implementation|Explicit non-initializing workspace mode; strict contracts, lazy storage/CAS/recovery/provenance and tests|efe68b18/988ce3f7 plus independent45-payload review|Accepted core hooks, original source budget and future native owner|Seven current-behavior positives; independent2-red/2-positive assumption counterexample|Legacy open writers remain possible; identity before sidecars; no stored-path revival|KB + core + root|Spec-first source, original/neighbor controls and representative durable journey|
| Whole PW02 local package fallback|Partial; no exposed package-to-project route|None: 0% of whole-feature milestones|Native stage/FDI/worker transfer, durable facade, Windows/frozen journey and all final gates|Portable slices and retained designs|Qualified Windows lane and existing services|Component evidence only; whole journey absent|Live lease/ownership, preserved provenance, finite original budgets and retained unknown outcome|KB + core + CI|Complete stated D/R/J/G journey before exposure|

These fractions count the existing named milestones for the stated bounded scope.
They do not add together or measure project coding progress. Frozen research,
real CVE matching/calibration, complete analyst, platform, packaging, security
and reproducibility acceptance remain incomplete.


## Exact held-reader import guard and full Linux result — 2026-11-18

The preceding published 771e Linux full run has 25,292 passes, 3 failures, 60 skips,
3 expected failures and 21 warnings. Its three failures are stale static import
guards for the already reviewed shared reader types in KB service/store/wiring.
The original failed hosted result, API ownership, exact log and artifact remain
immutable; newer candidate acceptance cannot reuse it as a pass.

Guard 52a562b6 follows spec/regressions 5cdf1732: thirteen original failures,
234 positives, then 247 passes with zero skips. Independent replay also passes
all 247 with 39 canonical imports and no child/network events. Seven exact
file/symbol exceptions preserve all previous import restrictions. All 45 original
functions, 67 new controls and the prior guard AST are independently checked for
preservation. Runtime/tools/workflows/configuration are unchanged. Full normal
Ruff passes; strict S still fails on 80 unchanged sites. No waiver or suppression.

[Complete correction and retained evidence](../qa/kbc-held-import-guard-20261118/README.md).
Five Windows/Qt jobs remain incomplete at the separate snapshot. Main merge,
native/package/security and final beta acceptance remain blocked. No release.
