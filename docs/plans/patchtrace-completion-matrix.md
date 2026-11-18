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

## Paired raw-window independent integration checkpoint — 2026-11-18

The paired raw-offset desktop slice now has independent source review (183 affected plus six additional controls) and 183 source-pinned combined passes on published #307, source `21552835`. D/R coverage remains **50%**: the implementation and regressions are verified locally, while representative native/manual J and exact-head full/platform/security G remain open. The original author receipt and failure history are retained; this entry does not promote the historical #168 research content or claim beta readiness. [Review and evidence](../qa/raw-alignment-reviewed-20261118/README.md).
