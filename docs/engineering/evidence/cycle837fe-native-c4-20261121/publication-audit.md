# Independent native/C4 publication-record audit

## Verdict

**Passed after correction of one record-integrity finding. No remaining blocking finding in the reviewed scope.**

Final reviewed commit: `5435d9cdb7daf272156916dd32034d103fa8988c`  
Complete tree: `754a90a94ed60cda2293c3c332e5778cda65c0a2`  
Tested implementation: `6bf79feffe68a9fdc1293a69900320e12be662bc`  
Tested implementation tree: `dc659c7ef80e317b6c13c120e09f47c5d313f3ca`

The audit initially bound documentation commit `717027dec2f3d4b1c6ee67c0c663f6505f7bf34a`, tree `dc8b45543f4ddd517aad239a5945f67dbf30ed59`. While the audit ran, the coordinator added three final C4 audit files in `7ace25243baffe92533e472ef7c0e8229b734e77`, then corrected the finding below. Those four changed paths were verified separately. The original 45-file evidence package and every runtime, test, tool, workflow, specification and site byte remain unchanged throughout these documentation steps.

## N-PUB-H1 — closed

The new `continuation_history` entry was labeled as the predecessor daee-stage checkpoint, but its nested `record.combined_followup_837fe` object contained the current source and 1,396-pass result. The assembler had retained a reference to a nested dictionary subsequently updated for the current stage. This changed historical attribution without changing application code or the original test receipts.

The coordinator repaired only that archived object in `5435d9cd`. Independent checks by this auditor and the separate links/history helper confirm that the repaired ledger equals the initial audited ledger with precisely that one object restored from the ledger at `6bf79fef`:

- Historical code remains `2a67980cfeb88ad72bf8ad523d2bafc8426e5b7c`, with **1,296 passing cases**.
- Current combined code remains `6bf79feffe68a9fdc1293a69900320e12be662bc`, with **1,396 passing cases**.
- Every other ledger value, all **97 tasks**, and the main-promotion/release holds remain unchanged.

The original incorrect commit and the helper's initial failed audit are retained. No history was amended or rewritten. See `final-delta-checks.json` and `links-history/repair-verification.json`.

## Package and source integrity

All checks read immutable Git-object bytes rather than relying on a moving checkout. The final recorded checkout is clean at `5435d9cd`.

| Verification | Result |
| --- | --- |
| Runtime/test/tool/workflow/spec/site differences from tested code | **None** |
| Original package manifest payloads | **45**, exact membership, sizes and SHA-256 values |
| Original payload bytes | **2,742,770** |
| Top-level ZIP archives | **Seven**, CRC and unique membership passed |
| Members across those ZIPs | **232**, including seven manifests |
| Enclosed payload hashes verified | **225** |
| Nested original artifact ZIPs | **15**, CRC passed |
| Added C4 final audit files | **Three**, outer manifest and exact source attribution passed |
| Added C4 audit ZIP | **Five members**, four enclosed hashes and CRC passed |

The added C4 package binds its audit to local `39a95c549d48eb523e9efdfda394bb9f184e2b16` and tree `f53e92d6bc128c929295f6baf3c6241081ee6ed2`. Its source-qualification field remains `111803d54cfebc1b779f4832a069904b3ee91a7c`. Its ZIP SHA-256 is `fc5b3fa4c7cfb92fce6abe44c4e8bc941356729470ed654bdca4de6b0a0c03db`.

## Test-count attribution

The combined JUnit was parsed independently, rather than accepting the summary counts:

- **1,396 passed**, **one expected failure**, **zero failures, errors or ordinary skips**.
- **1,397 unique test identities**; no duplicate identity.
- Exactly **64 unique selectors**, matching the retained command and test plan.
- The expected failure is exactly `tests.test_codex_pkg_workflows::test_pip_downloads_require_hashes`, message `CODEX-5`.

The combined test, whole-tree Ruff, dependency and isolated-source receipts all bind clean before/after states to `6bf79fef` and its exact tree. Their exit statuses are zero. The independently retained integration log records **141 passes** on that same code. Its fake-runner/stdlib controls remain distinguished from native execution.

Earlier results are separately attributed: Intel-only **1,314 passes plus one expected failure** at `d6287494`; C4 **580 passes plus one expected failure** at `111803d5`; historical correlation **134 passes with no expected failures** at `d6287494`. Their archived JUnit and source receipts agree. These overlapping counts are not added. The passing observer test's `LIVE ACCEPTANCE BLOCKED` banner is correctly described as controlled test output.

No repository test, full suite or native executable was run by this audit.

## Native evidence boundaries

The report and machine records retain actual daee Windows Intel **two failed / one passed / one skipped** results despite a successful advisory workflow. The skipped and blocked offline entries are the same check. The retained FLOSS JSON actually contains the getpass stack and missing-pwd error. Capa's JSON contains the successful `.exe` version banner but no matching stack, so the report correctly retains its shared-cause explanation as inference.

The Tier R aggregate remains a **warning**, with **five of eleven attempted engine pairs completed and six failed**, plus one separate skipped corpus case. The original-source comparison retains equal per-pair status/reason mapping and canonical report digest. Neither green workflow conclusions nor corpus-case statuses are promoted into full native acceptance. Windows BinDiff's network check, Ghidra archive cache, hosted Pages acceptance and remaining release gates stay open.

The 07:01:13 UTC daee QA snapshot remains explicitly incomplete. No predecessor result is transferred to the changed source, and no new main/release eligibility is claimed.

## Original source bundles

Both new bundles were independently parsed, indexed and pack-verified in temporary verifier repositories using existing prerequisite objects read-only. The packed commit list was checked, not just each bundle's advertised tip.

| Bundle | Exact packed commits |
| --- | --- |
| `intel-original-source.bundle` | Original `d6287494` only; prerequisite `daee337c` |
| `combined-original-source.bundle` | Original C4 records `39a95c54` and combined merge `6bf79fef`; prerequisites `111803d5` and `d6287494` |

Their original author identity, tree and ordered parent metadata match local Git. The combined merge parents remain Intel followed by C4. Earlier C4 bundles/evidence retain their existing blobs; this audit does not recreate or remap those histories.

## Links, history and coordination

A separately delegated read-only helper verified **29 newly inserted local Markdown destinations**, with no missing link, and **12 existing modified Markdown files** with insertions only. Every historical line remains in order. All **93 original task IDs and order** remain, followed by four new unique IDs. Of the original task objects, **88 are exact**; five allowed current-scope changes retain their original values or add current information. All three original C4 tasks remain exact.

The current tested source, local branch, handoff, PR349 target and explicit main/release holds are consistent. The historical four-scope dispositions do not reduce the whole-branch 181/16 census. N-PUB-H1 was the only identified historical-attribution defect and is closed.

## Publication limits and handoff

This is a documentation/evidence audit of the exact commits above. It does not assert a later GitHub ref, PR head, mapped final publication commit, hosted check outcome, main merge, native Windows acceptance or release readiness. The coordinator supplied the separate remote-mapping verification; this audit made no remote request or mutation and does not duplicate that verification.

The coordinator may incorporate this report, preserve its original source identities, verify the final local/remote tree and expected-head guard, then continue exact-published-source qualification. Full Linux/Windows, Qt, applicable native and packaging/frozen checks remain required. Main promotion still requires the applicable green gates and no blocker, and the actual merge commit must contain both `[no release] [no deploy]`.

All audit work is finalized under this evidence directory. No candidate source/file/ref, workflow, target binary, dependency policy or test assertion was changed. Ownership is released.
