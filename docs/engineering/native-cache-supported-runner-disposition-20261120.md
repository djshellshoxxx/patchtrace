# Generation 37 — independent evidence read of supported-runner native cache diagnostics

## Source-pinned receipt
The latest PR342 final-source Windows native workflow [44781837860](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44781837860) finished successfully on commit `5f34fb57267637b986814ddc81dba11550992fff`. Its `raw-cache-hit` job `136446262580` published [artifact 14660100681](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44781837860/artifacts/14660100681), named `native-static-acceptance-raw-cache-hit` (2,951 compressed bytes). This generation downloaded that existing artifact into the container and read its three JSON entries without invoking Java, analysis adapters or target binaries.

The exact ZIP SHA-256 is `8bbf458633ed708fda4eb44f92148bde34f41e6c62f0f51af73689d9cbb4edf1`. [Structured source-limited receipt](evidence/generation37/native-cache-supported-runner-44781837860.json) retains all three entry SHA-256 digests, archive identity, event-gap count and cache-key/hash equality.

## Observed, not inferred
- `first.json`: Java `-version` probe returned 0 and reported Temurin **25.0.5**; native first run completed with one match, raw SHA-256 `4e00001f4afe5fdf2dfacff3e8fc690066f270ac3130db4cb5f63a8042b14762`. It retained 64 bounded events, reporting 61 omitted.
- `second.json`: its Java probe also returned 0 and reported the same version; successful cached source has `cache_origin.key=3c2e377d...`, exactly the same raw SHA-256 as the first run, and one match. The three bounded events are `preflight`, `cache`, `completed`, including `raw output reused from cache`.
- `result.json`: `native-cache-diagnostics/1` status is `passed`. The source job log says `Raw cache hit verified`.
- This is stronger supported-runner acceptance evidence than a bare job-success label because the first/second Java probes and source-cache provenance can now be inspected independently. It still applies **only** to PR342's exact source/runner and cannot be transferred to later CSV candidate branches.

## Preserved contradictory evidence
The original initial-head native raw-cache job `136406567877` in [failed run 44770501981](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44770501981/job/136406567877), source `5cc3f2a540f2e49e8b86e20decf7d4f62ce89d0a`, failed `AssertionError: second run was not a cache hit; java=unverified`. No raw-cache diagnostic artifact was retained for that failed job. Both original and successful job logs showed Temurin 25.0.5 in `JAVA_HOME`; the environment setting does **not** prove that the failed run's application-level Java probe succeeded. Therefore the original failure's cause **remains unestablished**, and no cache/Java logic fix, retry or assertion weakening is justified from this differential alone.

## Review and qualification boundaries
The ZIP and JSON SHA-256 values and two-run content invariants were rechecked independently of the PR342 implementation cycle by Python 3.13.5 stdlib `zipfile`/`json`/`hashlib`. No source code was modified and this is not a separate external engineering reviewer signoff, repeatability determination or empirical accuracy evaluation. The original unexplained full local SIGKILL and ASM timing regression remain open. Required full QA/Qt/native/package and final-source gates must be assessed on their actual heads.

This evidence-only branch is stacked on the g36 candidate, not on the working PR342 ref. Do not cherry-pick shared ledger/status files wholesale or claim this branch's extra CSV source/test additions were part of PR342's successful Windows run.

## Next task
Use the existing first/second JSON schema to classify a *future failing* native run if one occurs; preserve its actual Java probe reasons and cache snapshot without changing assertions or rerunning a successful job speculatively. Obtain an external reviewer for the native diagnostics capture and the two-source comparison. The forced-export naming race, Winbindex raw provenance, native Qt/Windows trust/manual acceptance, and L1/L2/L3 remain separate blockers. No merge/release/deployment/source deletion or outbound message was performed.
