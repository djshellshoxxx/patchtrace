# PR #349 Windows Intel and C4 follow-up — 837FE

## Current Tier R test repair and qualification

Tested source `829600f8d667b74329a79dd0b0d7964c2e092fd0`, tree `306c4d58fe6c0902c4c1b0fbbc3cddd64aed1c4b`, maps to remote code `175909a0b5ea0f1d2ef77012c672935698793dea` and directly follows published `a73cea498d93e353eb49ef08aff785bd0c0a768c`. Only `tests/test_tier_r_shard.py` changes after that publication. Runtime, workflows, tools and specifications retain their bytes. Resolve live [PR #349](https://github.com/djshellshoxxx/PatchTrace/pull/349) for the final records head and current checks.

The retained, cancelled predecessor Windows [QA job 136761991553](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44876416755/job/136761991553) exposed a stale `@v` assertion against pinned Actions. Its interrupted summary was **1 failed, 19,776 passed, 181 skipped and 2 xfailed**; this was not a completed full suite. The unchanged maintained test reproduced one failure on a73. The initial CODEX-1 review omitted this Tier R test; its coverage miss and the actual failed log remain preserved.

The repaired contract enforces all seven exact reviewed Action commits and their identity set. Independent AST and byte comparisons confirm preservation of every workflow byte, both archive digests, jobs, triggers, permissions, compiler requirements and all other test-module statements. The reviewer parsed all **984 Python test blobs** at a73 and inspected **55 workflow-related files**, finding no second concrete stale mutable-tag assertion. This bounded audit does not replace full CI.

On clean 829600f8, the 65-selector run completed **1,444 passed and 1 existing CODEX-5 xfailed**, with **1,445 distinct JUnit identities**, zero failures, errors or ordinary skips, and 91.481 seconds of command time. Whole-tree Ruff, pip check and isolated import binding passed. Independent review passed **67 cases**: 48 maintained cases plus 19 controls covering the original failure and refusal of incorrect commits, mutable tags, unknown or comment-only Actions, and changed existing requirements. Counts overlap and are not added.

Actual Intel [run 44880309380](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44880309380) on **a73** independently confirms the Windows identity repair: Linux **4 passed**; Windows **3 passed and 1 skipped**. Capa 9.4.0, FLOSS 3.1.1 and DIE 3.21 reproduce the authored synthetic-pair goldens. The Windows skip is the unavailable offline network namespace. Both logs prove checkout d6d08f6d and both downloaded artifact digests were verified. This is native evidence on the predecessor, not transferred qualification of the revised test head. Capa's exact historical missing module remains unproven.

Main remains `fdc2696c23bdbfe7668348f25e3b336ce33039f7` until applicable final full, Qt, native, package and both Ubuntu frozen checks complete and the expected-head guarded REST merge succeeds with **[no release] [no deploy]**. Broader CODEX-5, Tier R coverage gaps, native/manual/trust/accessibility, full provenance, historical semantic review and separate L1/L2/L3 release gates remain open.

Evidence: [qualification](evidence/cycle837fe-tier-r-20261121/qualification.json), [independent review](evidence/cycle837fe-tier-r-20261121/independent-review.md), [original cancelled failure](evidence/cycle837fe-tier-r-20261121/prior-cancelled-failure.json), [native a73 observations](evidence/cycle837fe-tier-r-20261121/a73-intel-summary.json), and [hash manifest](evidence/cycle837fe-tier-r-20261121/manifest.json). The earlier sections below preserve their source-specific observations; this section supersedes their current-source and next-action claims.

## Historical Intel and C4 source checkpoint

The actual Windows Intel failure on published `daee337c48c63dda8aeac149c407e900c79dcc86` is diagnosed and repaired in source. This continuation also consumes the completed, independently reviewed C4 Build environment and Pages work into the same PR #349 candidate. Main promotion remains pending the exact new publication's hosted gates.

| Checkpoint | Exact commit / tree |
| --- | --- |
| Published predecessor | `daee337c48c63dda8aeac149c407e900c79dcc86` / `6c2a8d018ccc00bf65ef074579604b40627f7658` |
| Reviewed Intel repair | `d628749401f61d3653b5e066ff38245b938c5dcd` / `5d4f2d3beff122b352d0d62a15ea0800c578c0b9` |
| Consumed C4 records | `39a95c549d48eb523e9efdfda394bb9f184e2b16` / `f53e92d6bc128c929295f6baf3c6241081ee6ed2` |
| Tested combined source | `6bf79feffe68a9fdc1293a69900320e12be662bc` / `dc659c7ef80e317b6c13c120e09f47c5d313f3ca` |
| Main before promotion | `fdc2696c23bdbfe7668348f25e3b336ce33039f7` |

The clean two-parent merge has no resolution edits: all C4 files and evidence plus exactly the four Intel repair paths. Independent review verified the complete 4,598-file map, modes and ordered parents. C4's tested implementation is `111803d54cfebc1b779f4832a069904b3ee91a7c`, mapped to `7ddb1130ca501b9cfda9949aa49e684f9f4b8f26`; its later records change no runtime, workflow, test, tool or specification bytes. Original source bundles and reviews remain retained. Resolve live [PR #349](https://github.com/djshellshoxxx/PatchTrace/pull/349) for the final documentation head, mapped code identity and current runs.

## Observed Windows failure and repair

[Actual predecessor Intel evidence](evidence/cycle837fe-native-c4-20261121/daee-intel-summary.json) records [run 44876415860](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44876415860): Linux **4 passed**; Windows **2 failed, 1 passed, 1 skipped**, despite advisory workflow success. The skipped Windows offline check is the same blocked check, not an additional result.

FLOSS version and help each exited 1. Complete stderr directly shows `vivisect.defconfig -> getpass.getuser -> ModuleNotFoundError: pwd`. The sanitized child environment omitted all four identity variables; real stdlib getpass with that builder and unavailable pwd reproduces the failure. Capa's actual `capa.exe 9.4.0` version and help now exit 0, confirming the banner repair. Its analysis reports only generic ModuleNotFoundError; a common getpass cause remains inference until new native evidence.

Intel `process.tool_env` now sets fixed synthetic `USERNAME=patchtrace` on Windows. Caller identities stay excluded and extras cannot override it. Shared BinDiff/Rizin and POSIX environments, private paths, SystemRoot, Java/DIE additions, admission and resource limits remain. The specification preceded implementation; no dependency/schema was added.

Author and peer each passed 130 overlapping maintained tests. Independent controls cover real getpass failure/pass/removal, 432 caller-name case variants, 894 refused extras and 24 actual adapter call paths through authored fake runners. These establish the mechanism, not native Windows compatibility. Original red controls and native failures remain archived.

## C4 work combined

Five Build environment headings expose registered help: Fact, OLDER, NEWER, Status and Basis. Existing labels, values, copy, sorting and filtering remain. The actual-host audit retains Strings, Search and Build environment mappings; removing either Search Why or Build environment Basis independently fails the exact ID. Native screen-reader acceptance remains open.

Pages installs its complete seven-wheel Linux x86-64/CPython 3.12 site test/build closure with exact versions and SHA-256. Build-only requirements remain portable. Its site-only pytest command isolates application conftest/plugin loading, repairing the reproduced missing-pydantic setup failure without changing app fixtures or site assertions. C4 retains a fresh offline locked installation, actual site build, and real pip refusals for bad hashes and omitted dependencies. Its site-only result is 247 passes/one existing optional GUI skip; the GUI case passes in the combined environment.

Action pins, triggers, permissions and deployment hold survive. Pages has no PR trigger; manual dispatch retains deployment behavior and was not invoked. Hosted index/build acceptance and broader CODEX-5 remain open. The [C4 report](cycle4-consolidation-20261121-95fe.md) preserves both feature-review axes and parent integration audit.

## Exact-source verification

| Source | Actual result |
| --- | --- |
| Combined `6bf79fef` | **1,396 passed/1 CODEX-5 xfailed**, zero failures/errors/ordinary skips; 1,397 distinct JUnit identities, 64 selectors |
| Same clean combined source | Whole-tree Ruff, pip check and isolated import binding passed |
| Independent combined review | **141 passed** plus controlled identity checks; complete-tree union verified; no blocker |
| Intel-only `d6287494` | 1,314 passed/1 CODEX-5 xfailed; separate earlier stage |
| C4 code `111803d5` | 580 passed/1 CODEX-5 xfailed; separate earlier stage |
| Historical correlation at `d6287494` | 134 passed; separate comparison scope |

Combined command duration 84.319 seconds; pytest 83.09 seconds. Counts overlap and are never added. The `LIVE ACCEPTANCE BLOCKED` banner belongs to a passing controlled unsupported-probe test. No local full aggregate or native success is inferred. Earlier AF_UNIX EPERM and independently unexplained SIGKILL remain unsuccessful historical observations; no assertion, skip or limit was weakened.

## Predecessor native evidence

[Sealed daee observations](evidence/cycle837fe-native-c4-20261121/daee-native-observations.md) retain complete logs and artifact hashes. Ghidriff has three positive fixture analyses, one expected plain-Ghidriff cached-PDB negative control and byte-identical raw-cache reuse. Rizin Linux/Windows actually passed. Linux BinDiff passed 7 checks; Windows passed 6 and blocked the Linux-only network-namespace check. Synthetic inputs do not establish real-driver accuracy.

Tier R's green workflow contains a **warning**: 5/11 attempted engine pairs completed; 6 tiny pairs report no functions in the older file; one corpus case is skipped because its images are identical. Windows advisory has 11 findings/exit 1 records, not native passes. The per-pair mapping and canonical report digest match original PR349 `11f51c10`: an existing coverage gap, not a newly demonstrated regression. Both Linux shards restored and rehashed the original rizin archive. Ghidra steps were skipped; its archive-cache gate remains open.

At the sealed 07:01:13 UTC snapshot, both full suites/most Qt jobs were running and packaging/frozen checks were pending. Later observations belong to the live PR and separate evidence. A changed implementation needs its own hosted/native qualification.

## Further consolidation and dependency boundaries

Four additional scopes were reviewed with live donor SHA verification: PR190 explicit filename choice is scoped DUPLICATE; PR122 architecture refusal, PR159 card-field provenance and original `feat/enrichment-cve` normalization are scoped SUPERSEDED by retained implementations. No port is needed. All whole branches remain PARTIALLY_REVIEWED; 181 unmatched/16 patch-equivalent census is unchanged. [Exact dispositions](evidence/cycle837fe-native-c4-20261121/historical-correlation-dispositions.json) preserve declarations, changed-test explanations and exclusions; no live-provider or L1/L2/L3 accuracy claim follows.

The [CODEX-5 assessment](evidence/cycle837fe-native-c4-20261121/codex5-bounded-assessment.md) at daee found 42 explicit pip install steps/lines across 38 job definitions and 20 workflows. It predates C4 Pages and is a static census, not run count. Existing verified backend wheelhouse infrastructure should be reused. It does not close host/bootstrap/app/dev/signing/other-engine closures. The whole-script flag heuristic cannot prove per-command authentication; strict CODEX-5 expected failure remains. No package hash or Windows resolution was invented.

## Ownership and promotion

Root 837FE owns existing PR349 integration and qualification. Component authors/reviewers are complete. Read the [ledger](task-ledger.json), [current handoff](../engineering-handoffs/cycle837fe-combined-pr349-20261121.md) and live coordination. C4 history is retained without rewriting its branch. Original source bundles preserve author identities; REST publication preserves complete trees and ordered mapped parents.

Require exact-current-source full Linux/Windows, Qt, applicable native jobs, Windows installer/package and both Ubuntu frozen CLI gates. Inspect actual Windows Intel records. Merge only with applicable green gates/no blocker, through REST with a fresh expected-head guard. The actual main merge commit must contain `[no release] [no deploy]`; confirm its resulting tree.

Main integration and release readiness are separate. Broader CODEX-5, transitive Action/npm/toolchain closure, hosted Pages, Ghidra archive cache, native/manual trust/accessibility, raw-input/index membership, historical semantics and separate L1/L2/L3 gates remain open. No release, deployment, tag, force update or branch deletion follows from this record.

## Final publication audit and C4 handoff

C4 completed and released its branch at `f928a0cef29eac2b603d390c40fb86448111b91b`, tree `a47f16d86f0fa1fb54234aefd335ae08a85821af`, matching local `5abccd25f558c9d9733470b0109bbec908980d83`. Its final three audit files are incorporated; application, test, tool, workflow, specification and site bytes remain identical to tested `6bf79fef`. The mapped code object is `9545c03961deb33f19db8a92dfe77f413e189209`, with the same complete code-checkpoint tree and correctly mapped ordered parents. The [publication map](evidence/cycle837fe-native-c4-20261121/code-publication-mapping.json) preserves all 21 original/mapped commits through the audited metadata correction; the final records commit is identified by the live PR body.

Independent [publication audit](evidence/cycle837fe-native-c4-20261121/publication-audit.md) passes on local `5435d9cd`, tree `754a90a94ed60cda2293c3c332e5778cda65c0a2`. N-PUB-H1 identified an aliased historical dictionary that had acquired current qualification fields during assembly; the correction restores only that archived object to its exact original `2a67980c` / 1,296-pass record. Current `6bf79fef` / 1,396 qualification remains separate. The original erroneous commit and audit evidence are retained. The auditor verified 45 original payloads, seven ZIPs, 225 inner hashes, 15 nested artifact ZIP CRCs, the two original source bundle packs, all 93 prior task IDs plus four new tasks, 12 insertion-only Markdown histories and 29 new links. Three final C4 audit files also passed. Later additions retain this audit and map; they do not change the tested implementation or establish hosted acceptance.
