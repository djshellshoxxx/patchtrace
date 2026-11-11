# Current state, active work and remaining research gaps

Local date: **2026-11-03, America/Vancouver**; UTC date: **2026-11-04**. Final coordinator refresh: **02:27:24 UTC**, **59 open PRs**; initial 02:21:05 snapshot had 58. Main remains **`b77d84e5decf736b031f0a24094001274de41178`**. This is research/source reconciliation, not implementation, CI success or release acceptance. No targets, application workflows or native tests were executed in this pass.

## 1. Source-of-truth order

Read [AGENTS.md](https://github.com/djshellshoxxx/patchtrace/blob/b77d84e5decf736b031f0a24094001274de41178/AGENTS.md), [CLAUDE.md](https://github.com/djshellshoxxx/patchtrace/blob/b77d84e5decf736b031f0a24094001274de41178/CLAUDE.md), [the module index](../../modules.md), relevant specifications/contracts, current source and tests. Specifications govern contract changes; source establishes implemented behavior; retained tests/acceptance evidence establish verification. Research supplies evidence and proposals. Historical “not built” prose cannot erase modules now present. Code on a research branch is not proof of a merged/accepted feature.

Open-PR counts are triage facts, not completion scores. No successful checks, native run or publish permission is inferred from branch presence. Refresh main, affected heads/checks and ownership before implementation. Do not merge an old research branch wholesale because its documentation is useful.

`tasks/todo.md` contains invalid UTF-8 at this baseline; PR #173 owns tracker/spec repair. Do not round-trip it through forgiving decoding or replace it with a reconstructed list. Supply proposed work in a handoff until its owner reconciles the tracker.

The [repository license](https://github.com/djshellshoxxx/patchtrace/blob/b77d84e5decf736b031f0a24094001274de41178/LICENSE) is **MIT, copyright 2026 Circuit Drift Labs**. Older reuse-matrix language calling the application license undecided is stale. Upstream component licenses, vendor data/fixture rights, SDK terms and redistributed modified-tool obligations remain separate.

## 2. Active/unmerged work

These PRs are active/unmerged at the supplied snapshot; commits identify inspected trees, not accepted results.

| PR / pinned head | Scope and coordination boundary |
|---|---|
| [#173](https://github.com/djshellshoxxx/patchtrace/pull/173), `93587a0c19c654cd003938ad780520340248a87e` | Tracker encoding/text gate, spec/module reconciliation, ledger/triage. Do not duplicate tracker repair or allocate conflicting spec IDs. |
| [#174](https://github.com/djshellshoxxx/patchtrace/pull/174), `b1411fb57774233ef909fabf4afab34ab4b67dff` | Native/Rizin producer controls/patch, evidence/live-pair qualification, Java retry. Reuse its seams; wrapper/API controls are not production JSON acceptance. |
| [#175](https://github.com/djshellshoxxx/patchtrace/pull/175), `dabba4aea4ba0fa19e71ede05ce4fb8ab6741942` | Windows identity, icons/version resources, executable checks/notices. Avoid competing branding; accept the actual frozen artifact after integration. |
| [#176](https://github.com/djshellshoxxx/patchtrace/pull/176), `db0a0b05d48e4c8fb394ec4e221677b5efb37954` | Broad KB investigation/scope safeguards, retained corpus outputs/replay credits/preregistration, GUI adoption/sorting/audits. Inspect before changing investigation, persistence/replay/training, project switching or disclosure. |
| [#171](https://github.com/djshellshoxxx/patchtrace/pull/171), `f8050a1fef23b71fd3a02b216c5035bcac3f4889` | Eight-agent API workflow and `tools/parallel_cloud/{agent,guard}.py`. Infrastructure is separate from product/native acceptance; coordinate credentials/scope. |
| [#170](https://github.com/djshellshoxxx/patchtrace/pull/170), `6fe6c4b1be060eb6e9d5208a68f0d68e1082b59c` | Persistent API-funded autonomous workflow. Availability is neither authorization to execute it nor evidence of product completion. |
| [#177](https://github.com/djshellshoxxx/patchtrace/pull/177), `07db4ffe5f321b3522fab7ef721ee4fd00936ea9` | Late-observed WS-A CI parallel QA/pytest-xdist and pip-cache work, branch `claude/ws-a2-ci-speed-20261104`. Do not duplicate CI optimization. |

For #173–176 local refs are `origin/claude/ws-{i,bc,a,p}-20261104`; #170–171 use `origin/automation/{api-funded-persistent-codex,parallel-api-eight-agents}-20261103`. Inspect with `git show`/`git diff`; do not switch the shared checkout beneath another worker. The coordinator's machine-readable [repository snapshot](repository-snapshot.json) records refresh metadata.

## 3. Main implementation versus remaining acceptance

Paths below are in the [pinned source tree](https://github.com/djshellshoxxx/patchtrace/tree/b77d84e5decf736b031f0a24094001274de41178/src/patchtrace) and [tools tree](https://github.com/djshellshoxxx/patchtrace/tree/b77d84e5decf736b031f0a24094001274de41178/tools). Presence is not an aggregate test-pass assertion.

| Main implementation and exact seam | Separate evidence still needed |
|---|---|
| `jobs.py`, `backend.py`, `unified/extract/{runner,ghidra_script}.py`: supervision, private workspaces, extraction | Discovery is weaker than producer qualification; native completion/publication and Windows cleanup need runtime evidence. |
| `secondary/binexport_*.py`, `secondary/bindiff_*.py`, `secondary/rzdiff.py`: imports/probes/adapters | Parsed protobuf/SQLite and versions do not establish extension compatibility, orientation or native partitions. |
| `unified/{sources,pipeline,compute,store,read_model}.py`, facts/IR/ladder | Correspondence, material change, semantic equivalence and CVE attribution remain different claims; module presence is not statistical acceptance. |
| `intelligence/csaf/{validate,transport,discovery,identity}.py`, `intelligence/index.py`, `kbcorrelation/` | CSAF coverage is partial; signatures/trust roots and product→package→file relationships require independent acceptance. |
| `symbols/{pdbid,staging}.py`, `tools/calibration/tier_w/symbols_llvm.py` | GUID/age mismatch tests and LLVM symbol comparison exist. Independent LLVM identity extraction is narrower work; the adapter currently takes identity from its stdlib reader. |
| `persistence.py`, `verified_backup.py`, `reports.py` | Database integrity is not full sidecar closure; fixture tests do not establish NTFS failure recovery. |
| `gui/qt/{host,docks,layout,tasks,table}.py`, `ui.py` | Feature docks exist; core navigator/code/findings extraction is not complete thereby. Accessibility/DPI/monitor recovery needs platform acceptance. |
| `tools/build_windows.py`, `package_windows_installer.py`, `installer/PatchTrace.nsi`, release gates/workflows | Build/smoke tooling does not prove exact downloadable assets passed the essential workflow offline on clean Windows. |

## 4. Credit R1–R8 and reconcile their snapshots

Prior research PRs #128–#135 contain substantial analysis, experiments and some code proposals. They are not blank workstreams to repeat. Research labels do **not** follow PR-number order. Immutable entry points below prevent branch-tip drift; inspect each diff before reusing code.

| Prior research and pinned entry point | Preserve and reconcile |
|---|---|
| R1 / #128: [ground-truth-corpus, `10856edf`](https://github.com/djshellshoxxx/patchtrace/tree/10856edf05afae8166291f09fb3ead92f297360d/docs/research/ground-truth-corpus) | Pilot protocol, source admission, build receipts, label/evaluation integrity and failures. Pilot outcomes are not general corpus acceptance. |
| R2 / #131: [unified-matching-r2, `b3ceb8b3`](https://github.com/djshellshoxxx/patchtrace/tree/b3ceb8b30d7a83da5e22c231c3b8c28179246816/docs/research/unified-matching-r2) | Native findings, graph/performance experiments, fusion/replay provenance and producer uncertainty. PR #174 continues qualification. |
| R3 / #129: [semantic-analysis-r3, `2698b9a0`](https://github.com/djshellshoxxx/patchtrace/tree/2698b9a04d33b2d04f49c1ab737636539c6ef6f7/docs/research/semantic-analysis-r3) | Method comparison and proof limitations. Weak/lifted observations do not become equivalence guarantees. |
| R4 / #130: [vulnerability-correlation-r4, `ff570bdd`](https://github.com/djshellshoxxx/patchtrace/tree/ff570bdd784d02f745e4ad21d8aa7b4f1f776344/docs/research/vulnerability-correlation-r4) | Vendor sources, Windows servicing/package context and evidence graph. Later native-CVRF/revision repairs supersede old parser inventory claims. |
| R5 / #132: [calibration-r5, `4d9d9051`](https://github.com/djshellshoxxx/patchtrace/tree/4d9d9051aea87319847a0b321a14d37b95cb8abd/docs/research/calibration-r5) | Grouping, dependence, weighting, probability/display limits and engineering handoff. No replacement calibration policy is proposed here. |
| R6 / #133: [final-integration-r6, `3010f289`](https://github.com/djshellshoxxx/patchtrace/tree/3010f289dbb46a1db62218a35cca03420090e306/docs/research/final-integration-r6) | Essential workflow, release/recovery matrix and blockers. Recheck defects against merged repairs and active audits. |
| R7 / #134: [advanced-analysis-r7, `c9d1aab6`](https://github.com/djshellshoxxx/patchtrace/tree/c9d1aab6a78847ce1632fe833d15af2e3b9c6e9b/docs/research/advanced-analysis-r7) | Historical open research/prototypes and limitations. Preserve current implementation/non-execution boundaries; no new production adoption is inferred. |
| R8 / #135: [deep-uncertainty-r8, `12dd4f2b`](https://github.com/djshellshoxxx/patchtrace/tree/12dd4f2b41b468b0eb566bd502219daa821012df/docs/research/deep-uncertainty-r8) | Typed-literal/ICF counterexamples, ambiguity register and release risk. Preserve abstention rather than inventing one-to-one identity. |

These R1–R8 labels identify this research series, not older GUI guidance or UE-R1..UE-R13 implementation slices. The research trees have not all landed on main. An old note's experiment can remain useful even when its implementation inventory is superseded.

## 5. Corrections that prevent duplicate work

The proposed [dock workspace specification, PR #127](https://github.com/djshellshoxxx/patchtrace/pull/127), remains unfinished/unmerged. It builds on the existing host. Neither “no docks exist” nor “core dock extraction is complete” describes main. `docs/specs/gui-framework.md` retains old unbuilt language; PR #127's `DOCKABLE-WORKSPACE-SPEC.md` inventories existing feature docks and proposes remaining core extraction. Use its explicit completion boundary rather than counting a preset menu as the whole refactor.

Native MSRC JSON parsing and source-bound provenance have landed. Correct old R4 inventory claims without discarding its servicing/source analysis. Backup verification now has byte-stability/hash defenses and regression tests; an old size/mtime-only critique is not a fresh unfixed defect. Keep NTFS acceptance separate. Do not infer that resolving one old audit finding closed every release gate.

PR #176 already carries retained engine outputs, replay credits and preregistration selection. Qualify those paths rather than creating another output store. Existing grouped calibration, numerical checks, nuisance variants and symbol staging deserve explicit credit before naming missing experiments. Application MIT licensing is settled; dependency/source/SDK rights remain component-specific. “Read format,” “invoke external tool,” “copy source” and “redistribute modified binary” are distinct reuse decisions.

## 6. Additional gaps and handoff navigation

The sibling notes add bounded opportunities, not speculative rewrites:

- [02, engines/runtime](02-engine-runtime-reuse.md): producer receipts, GZF completion versus analyzed flag, BinExport mutation/timestamps and optional independent PE observations. Preserve PR #174 acceptance/quarantine ownership. Its source inspection is not a new native reproduction.
- [03, metadata/provenance](03-metadata-provenance-reuse.md): independent CSAF coverage oracle, acquisition/verification receipts and raw product/file identity separation. Authenticity stays unknown until actual signatures and accepted publisher keys are verified. A catalog entry or transport digest cannot substitute for publisher authority.
- [04, desktop/release](04-desktop-persistence-release-reuse.md): frozen external-child DLL search inheritance, settings/shutdown diagnostic visibility, backup closure and dock/accessibility recovery. These are recommendations/experiments, not reproduced failures from this pass.
- [05, corpus/reproducibility](05-corpus-calibration-reproducibility.md): explicit non-GitHub source-origin contracts, environment variation, qualified tooling and existing replay lifecycle. No new scoring architecture is needed.

Read the [package README](README.md) and [06 action plan/reuse register](06-claude-action-plan-and-reuse-register.md) for sequencing. Begin with ownership reconciliation and one failing/reproducible acceptance question. Select a small integration through an existing seam; update specifications before changing public contracts, preserve prior evidence on failure, and retain offline/local-first behavior. No new parser, renderer, framework or engine should become mandatory merely because it has a mature upstream project.

Completion evidence must name the integrated commit, tool/build identities, permitted input/fixture hashes, result and limitations. Keep implemented, automated-pass, native-pass, Windows/manual-pass and blocked statuses distinct. Missing/skipped native evidence never becomes passed, and research proposals receive no release credit. For release acceptance, use the actual downloadable portable/installer assets with their hashes and complete the essential local workflow on clean Windows; screenshots and mocked backend tests cannot supply native/runtime or accessibility proof.

Validation here was read-only reconciliation of pinned refs, selected source/tests, branch diffs and sibling research. It did not repair code, run CI/workflows, execute targets or establish production readiness. External facts and license/source qualification are developed in the linked sibling notes; this map does not broaden their adoption decisions.

For a concrete follow-up, place each observation against four artifacts: the governing specification, the implementation at the chosen SHA, the regression/native test seam and the retained result. `docs/qa.md` is evidence history, not a substitute for reading the named result; an audit disposition can be conditional or branch-local. `docs/specs/REGISTRY.md` and `docs/modules.md` are integration indexes and must agree with the implemented contract. Preserve the originating research snapshot when correcting an obsolete claim so later reviewers can distinguish a repaired defect from an inaccurate experiment. Public source availability alone proves neither compatibility with PatchTrace's pinned runtime nor suitability for the frozen distribution. The next owner should explicitly record whether a candidate is adopted, adapted, reference-only or deferred, and identify the exact acceptance question that justified that choice.
