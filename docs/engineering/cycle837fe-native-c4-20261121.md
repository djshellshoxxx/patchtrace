# PR #349 Windows Intel and C4 follow-up — 837FE

## Current source and purpose

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
