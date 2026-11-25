# Network recovery and tooling qualification — cycle 837FE

## Current state and actual PR357 promotion

PR [#357](https://github.com/djshellshoxxx/PatchTrace/pull/357) was merged through the expected-head REST API at **2026-11-21 15:32:22 UTC**. Actual main is `ea16019601486c831941f9bc1a7ba5862a170317`, with ordered parents `3a16290c0fcc4e0c21712fe10474a3ff33fad336` and `d60ac40daf767fe6a93ae152feb21235f6e75e0b`. Its complete tree `4a07cd88ded407bef30a8aeb81961e4041822dc2` equals qualified d60 and tested synthetic `254d26e58ef03a03e50c78b5f90c6ef7d9bf9e57`. Both actual title and body contain `[no release] [no deploy]`.

The separate next candidate's frozen local code is `@@SOURCE@@`, tree `@@TREE@@`. Equivalent immutable remote code ends at `@@REMOTE_CODE@@`; fetched complete trees, ordered parent mappings and messages are verified. Final records/publication and exact final-source hosted qualification are pending at this boundary. No earlier result transfers to a different source.

Automatic PR QA [44910528283](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44910528283) and native Windows [44910528348](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44910528348) succeeded on attempt1: **18 jobs, 16 executed successes and two intentional publication skips**. All16 executed checkouts identify synthetic254d.

| Gate | Actual d60 result |
|---|---|
| Linux full | 24,336 passed /53 skipped /4 xfailed /21 warnings |
| Windows full | 24,205 passed /185 skipped /3 xfailed /22 warnings |
| Full JUnit | 24,393 cases per platform; zero failures/errors |
| Separate boundary controls | Linux108/2; Windows107/3 passed/skipped |
| Qt repetitions | Ubuntu13,320 /10,860 /9,840 /8,460; Windows10,620; not unique-case totals |
| Actual PowerShell cases | All27 passed:17 artifact checks and10 archive checks; no skips/failures/errors |
| Windows producer and distinct consumer | Frozen64PASS/0FAIL; portable and NSIS install/launch/non-destructive uninstall passed; same-run envelope and both inner hashes verified before downloaded execution |
| Ubuntu22.04 and24.04 | Each64PASS/0FAIL; download/tar hashes, offscreen and XCB checks passed |
| Publication | Actual release-gate136865172968 and release136889308090 skipped |

Native Windows evidence is three authored known-patch positives, one expected-negative cached-PDB control and one application raw-cache contract. Original ZIP cache: **3 misses/2 hits**, all five hashes before fresh extraction, one save, two reservation declines and two primary-hit save skips. Earlier4202's1/4 pattern remains separate. The raw-cache artifact reports equal hashes and explicit reuse without containing raw output bytes. Three positive records have unverified JVM-version fields.

Independent native/QA/final delta reviews passed175/96/287 checks. Final evidence ZIP SHA256 is `0b70d118ec79e9a88230eb7dd404bc7ebf5080f78c6d2c15614dccdb493a6b08`; final delta ZIP is `884b388584e1f5b840f6bdeb9242442eeac302c1555749420b28464be5b1bcad`. Actual promotion proof independently checks the fresh guard, request/result, fetched Git object and complete prior PR-body suffix. Seven known xfail records remain: two broad C5 cases per platform, unconfigured live Ghidra on both, and missing Linux llvm-pdbutil.

## Separate main streams

Earlier main3a completed its own QA/Pages:14jobs,12executed successes,2publication skips. Linux24,295/53/4 and Windows24,164/185/3; both24,352-case JUnit reports had zero failures/errors. All5Qt, Windows64/portable/NSIS and bothUbuntu64/0 passed. The gate's `publish=true` is distinct from the actual release skip. Pages configuration skipped, site248passed/1skipped and build/upload passed, deployment skipped. Original queued snapshot004 and exact Pages ZIP remain;59release identities were unchanged. Independent review passed213checks.

New main ea160 remains a **separate pending stream**: QA44919714193 and native44919714141, both push events. At15:46:15, native was verified but full/Qt/downstreamQA remained in progress; no Pages run appeared in the head-filtered inventory. Native on this source recorded **five archive misses/zero hits**, one save/four reservation declines and all hashes before fresh extraction. Three positives, expected-negative and raw-cache contract passed with four artifact ZIPs verified. Native summary SHA256 `7e5dd4e9af1d224fded1d69eb9cb4934b8d18f170c3cebde2337bf61645ae771` is a live checkpoint, not final main qualification. Actual release was pending after gate `publish=true` for6merges.

## Recovered network work

| Source | Preserved contribution |
|---|---|
| PR354 a41c7a0d594d1fe26c16da395e6f6f9b33b07eca | Real HTTP reads honor remaining deadlines, including no-cancel and late-empty-read boundaries. |
| PR356 1d475d926314ae116442bfe2b7cd268ad95ea12c | Repairs late abandoned-opener cleanup accounting; all6PR354 and4PR356 commits retained. |
| PR352 e3928ab8c8e2deee7bb01b0f857205f68a1abda2 plus aa01a50844fed15823c6e03491ce3bc671a5ecfc | Preserves enrichment implementation and checks explicit cancellation/logical/wall deadlines after completion before publication. |
| PR353 d0a4bdf439775999340ea760d96a087e032ee6dd | Bounds actual CSAF reads/returned lengths before parsing/hash admission; strict writes, legacy layout, shard precedence and direct no-limit API remain. |
| PR355 e2127864cb481026db0157082d688b8a36595e3b | Three optional-import handlers catch ordinary exceptions; KeyboardInterrupt/SystemExit propagate. |
| 96baaee20f390a3f2a5629de3764d32323bb80e5 | Docstring-only clarification of admission threshold/concurrent overshoot; executable AST unchanged. |

All original histories/authors are retained in bundles and publication mappings. Only QA/TODO merges conflicted: exact PR352 prefix, complete d60 document and PR353 suffix remain. `findings.json` did not conflict; PR355 uses a separate finding. The initial suffix-only merge-guard failure is retained; the first completed merge was not reset or replayed.

Source96baa has31 unique commits/18 changed paths above d60. Root passed480 distinct cases across17modules with no failures/errors/skips, whole-tree Ruff and dependency checks. Independent review passed289 mechanical checks,44 completion/socket/attempt controls and9 separate optional-import controls;4,812 other tracked entries were unchanged. These selections overlap and are not added together.

Original PR352 completion failures remain attributable to that source. The unchanged cleanup control still failed on the completion-only child, then passed after PR356 integration and drained its counter to zero. A strict concurrent-cap assertion failed on both main902 and PR356; the clarified pre-existing admission threshold does not establish a strict concurrent cap. PR353 initially recorded142passes/16reviewer setup errors; rerunning only16 after creating the scratch parent gave16passes. This is158 distinct identities with passing outcomes, not one clean158-case invocation. All errors remain.

## Pilot tooling closure

Four original commits from 96baa through `f08632ab81e6ab24fcc34fc994dd2dda2556d267` protect the first installer in manual `pilot-eval.yml`. The seven-package Linux x86-64 CPython 3.12 lock selects pytest 9.2.0, Hypothesis 6.170.17, sortedcontainers 2.4.0, iniconfig 2.3.1, packaging 26.3, pluggy 1.7.0 and Pygments 2.21.0. The baseline is actual main3a QA; unavailable historical manual-pilot logs are not represented as that baseline.

Actual wheel bytes, metadata, tags and all five active dependency edges were verified. Fresh normal-resolver installs succeeded. Independent empty-environment controls refused a wrong root hash, omitted transitive entry, wrong transitive hash and present transitive entry without its hash, with all wheels available and negative environments left empty.

The test-only parent collected three intended failures and one pass. An intermediate unquoted YAML scalar caused four failures after 233 passes and one xfail; the corrective fourth commit quotes only that scalar. Invalid source and logs remain. Final author results were 19 pilot passes and a separate 236 passes/two unchanged strict C5 xfails. Independent review passed 298 checks and 259 source cases with those two xfails. The editable application install, manual trigger, readonly permissions, runner/Python version, timeout, Action pins and other commands are preserved.

The unchanged report writer emits empty arms and `not-evaluated`; no empirical pilot accuracy is established. The available GitHub connection has no manual workflow-dispatch operation, and earlier browser/CLI checks supplied no access. The proposed extra manual pilot run remains **unexecuted/access-blocked**. No trigger was changed, old-source run substituted or access restriction bypassed. Fresh install evidence and automatic full source tests remain separate.

## Sigstore tooling closure

Three original commits from f086 through `@@SOURCE@@` protect only the `backend-bundle.yml` / `vrfy` installer. Ubuntu/Python 3.12, the job condition, false `pin_verify` default, permissions, identity/artifact inputs, verifier commands, Action pins and every other workflow byte are preserved.

The complete 31-package closure preserves Sigstore 4.5.0 and exact versions/wheel filenames from successful historical run 38661029764, job 116182091312, source `bf7e936f358a1eb8ea36d86da8a0189793f17cfa`. The newer successful 4.4.0 run is excluded. All 31 actual wheel hashes, sizes, metadata and tags were verified; 41 active edges propagate `pydantic[email]`. Only the exact reviewed Pygments artifact is shared with the Pages/pilot locks.

A clean official-index normal-resolver install produced exactly 31 selected distributions and a clean dependency check. Three fresh author refusals cover a wrong root hash, omitted ordinary transitive entry and missing extra-transitive hash. Collected parent red: three assertion failures/one pass. Final author tests passed 265 cases with two unchanged strict C5 xfails; whole-tree Ruff and dependency checks passed.

@@SIGSTORE_INDEPENDENT@@

Author evidence-only wrong-directory probing, the nonexistent `run_index` census attribute and raw-SHA bundle-export failure remain. Corrections changed no candidate source and did not repeat passed tests. Independent-review fixture, literal and CLI-classification mistakes and evidence-script syntax errors remain with original outputs.

Actual census: **21 workflows, 203 run scalars, 38 installing jobs, 42 explicit installs: three protected/39 unprotected**. Earlier 42/1/41 and 42/2/40 snapshots remain. Both broad strict C5 gates are unchanged. Application/build/engine/other tooling and signature-verification acceptance remain open.

## Final combined code qualification

@@FINAL_LOCAL@@

One deduplicated set of 26 node selectors binds all four changed runtime modules, pilot contracts and audit tooling to the exact checkout and verifies all seven test-tool imports against qualified versions/locations. No existing environment was rebound. No local full-suite retry was attempted after the two preserved unexplained SIGKILLs. Full QA remains a hosted gate on the final record-bearing head. Component reviews stay scoped to their immutable sources; preservation checks establish that later tooling commits leave the network runtime unchanged.

## Additional historical accounting

Backend-exit donor `bc00a6912dde57482a301bf64ef6fbc3f324cb92`, base `736332cf63d3c7927f5c17f4aea5150f624bf957`, was reviewed across seven commits, six net paths, 13 historical paths and eight parent diffs. History-only paths were inherited changes. Current classification retains donor behavior and adds a cached-diagnostic branch; earlier hints, return codes, fallback, backend, specifications and tests remain.

Classification: **SUPERSEDED**, no source port. The diagnostic tail is bounded in Python characters, not UTF-8 bytes. Parent controls recorded eight intended failures; donor eight passes; unchanged old fixture on current source seven passes/one failure because stronger `-I` isolation removes working-directory imports. A maintained explicit import bridge passed ten controls, including credential boundaries. Fake-process diagnostics and exit7 JDK text were byte-identical. Independent review passed 1,158 mechanical checks without rerunning native engines. The original census bucket and donor branch remain.

## Evidence, ledger and next gates

The adjacent manifest records every payload's exact size and SHA-256. Nested author archives are retained once within reviewed parent archives; standalone summaries are exact copies. Prior PR353/PR355 evidence already in d60 remains referenced. All 116 prior task IDs/order, all 46 notes and prior continuation history remain. Explicitly updated tasks have complete before-images; earlier handoff/QA/TODO bytes remain exactly once behind the new prefix. The original 181-unmatched/16-patch-equivalent census is unchanged.

The existing hourly schedule is unchanged. Original-before, original update response and later live continuation evidence prove that the full 63,965-character prompt remains behind its exact 4,365-character prefix. The prepared 15:36 label, actual server update 15:34:47.917190 UTC and later unchanged live metadata timestamp are distinct observations. No cause is inferred for that metadata timestamp difference.

Final publication must preserve original donor ancestry or verified equivalent-object mappings, bind the record tree to actual main ea160 as an additional ordered parent, receive independent record review and pass applicable automatic hosted workflows. A later main merge requires fresh source/main/ownership/review/comment/status/check guards and the expected-head REST operation, with both publication holds in actual title and body. Original PR352–356 remain open until qualified combined promotion proves their retained contributions. Historical branches are not deleted.

Broader native-engine compatibility, corpus coverage, real pilot/L1–L3 accuracy, manual GUI/accessibility, trust/provenance, dependency closure, release qualification and deployment remain separate gates. Queued, skipped, interrupted, mocked and earlier-source outcomes are not current end-to-end acceptance.

Primary receipts: [manifest](evidence/cycle837fe-network-recovery-20261121/manifest.json), [PR357 final qualification](evidence/cycle837fe-network-recovery-20261121/pr357-final-qualification.json), [actual main proof](evidence/cycle837fe-network-recovery-20261121/pr357-main-promotion-proof.json), [network review](evidence/cycle837fe-network-recovery-20261121/network-combined-review.json), [pilot review](evidence/cycle837fe-network-recovery-20261121/pilot-tooling-independent-review.json), and the Sigstore/final-source receipts indexed by the manifest.
