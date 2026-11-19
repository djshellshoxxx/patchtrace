# Main promotion and local integration log — 2026-11-19

**No main merge or release has been performed by this continuation.** This log
distinguishes changes integrated into the local continuation branch from a future
accepted main promotion. Its starting main is
`fdc2696c23bdbfe7668348f25e3b336ce33039f7`, the existing foundation/saved-scope
admission repair merge. That baseline merge predates this continuation.

## Local continuation history

Branch: `codex/patchtrace-completion-20261119-81e4`.
Recorded local runtime/test checkpoint: `520b524beb0c837b6e50801bd97c88a2447e39fd`.

| Source or local event | Exact identity | Disposition |
| --- | --- | --- |
| N-way per-pair path failure repair | `24064cf67e3de15df9439141d0e407dfbdb9212b` | Present locally; base-red and 85-pass affected evidence retained. |
| Installer recovery source | `20b54521c858cc63f701ce8cada64e02464fe199` | Reviewed narrow recovery from historical `0bf1f8309e8425ba34199657009d3055215336f1`; broader workflow changes excluded. |
| Installer recovery on root branch | `ef9167d20bc6f6296148a6f5dad1c637184344f4` | Local port of the receipt behavior; 5 focused tests pass. |
| Complete branch-disposition records | `46f37373327eaf71d44a78ac23b3a459c63b7891` | Inventory and recovery records preserved; no branch deletion or automatic supersession. |
| Final parser repair in its source chain | `baf95fcd3d9c0ae843b2a7fbe037fd66c4ae063c` | Follows `2ca898b2` and `9527f53f`; includes the independent SQLite-classifier correction. |
| Parser integration merge | `7610aeaa77beb58fca9413c77443bc2ab8ba8e97` | Merged into the local continuation branch only; 432 passed, 1 skipped in the source slice. |
| PE cache source | `0bc41f6b684f5523a4f8382b7bfa73a75252db98` | Reviewed feature slice; 840 passed, 2 skipped, plus independent peer controls. |
| PE cache integration merge | `6bf57557d00ab58ddfe29c22c6c39699142d80d7` | Merged into the local continuation branch only. |
| Research facts-eligibility guard | `d87af0373948a4fc7207a5a9f527bcdf9d7cea0d` | 11 base failures, 33 focused passes and 140 final scoped/caller passes in 4.59s; original positive assertions retained. |
| Facts-guard integration port | `69fa6b8b588645a895b3edbdeff3aa4b74856be7` | Full-batch1 source: killed with exit 137 before summary/JUnit; no full pass. |
| BinExport2/rz-diff text sources | `efdd54caae926d2a157c0d74e8b7c1b34361751e`, `bdf6b520f2e90c2d4cb05b96a2f9653d25a8207b` | Reviewed narrow adapter repairs; 414 affected checks pass. |
| Adapter local ports | `d4bb5efb`, `af8772bf9f5abe54eee214f8b05f379389b2f076` | Source/spec/test changes integrated locally after the first full process ended. |
| Guarded remote checkpoint | `bdc929ebd3c6aaa2563c758936beb315a10eeea0` | Checkpoint branch advanced from expected main with force=false. Remote tree exactly equals local `af8772bf`: `424709da5b590e68262ea0a11b8f98bb52da8d4b`. No main merge. |
| CSAF redirect repair and static review | `0a4bb12e758e4c91df0cd8cf3001ae722a573897` | 33 transport checks pass after 4 red controls; all 65 supplemental scanner findings classified, not suppressed. |
| CVE numeric/time source | `93c9e395f7a410c6b007b348430e1799c9099427` | Reviewed exactness and error-boundary repair; final 124 checks pass after initial and independent red controls. |
| CVE integration port/source freeze | `a4d6dd9becb37b6245332643683a2ef1d2bf3812` | Historical source of the 855-file/54-group diagnostic; stopped after 9 groups at disk reserve with 2,602 passes, 8 skips and one separately corrected pin mismatch. No aggregate pass. |

All implementation commits above carry `[no release]`. Passing source-slice
results do not establish that either integration merge passed a complete suite.
See [test results](TEST_RESULTS.md) for executed outcomes and retained failures.

## Existing remote candidates and holds

The full census pins PR319 at
`a56ab13aaf9916fc12bea70ba1494075991b7f09` and broad PR318 at
`c4ace2088ce8dc9ce78a0bf3036b81096accbdb5`. At the coordinator's latest observed
snapshot, PR319 was queued; main's Linux/Windows QA and all Qt checks were green,
while Linux packaging was queued. These are earlier heads' states and
must not be credited to the new local aggregate.

Broad PR316/318 holds are unchanged. The inventory retains source branches and
unrecovered scope. No branch removal, forced update, blanket PR closure or
acceptance of a broad stack follows from these local ports.

The branch census is frozen at `2026-11-19T10:34:16.394Z`; it does not include
later remote changes. The coordinator subsequently observed these candidates:

| Later candidate | Observed source | Retained disposition |
| --- | --- | --- |
| PR320 | `188b4962e527c82b29e599f75cd952029b749348` | Draft broad integration of PR319/318 plus Tier W/callgraph scope; 928 files and 333 commits, with incomplete full-suite evidence. Preserve and review separately; do not adopt its scope through this record. |
| PR321 | `976dddfbbcdf9a320e48813d8cf2c3c6540aac81` | Documentation checkpoint atop PR319; retain as a separate source, not acceptance of the local aggregate. |

The coordinator also completed an all-state issues scan, identifying 10 open
non-PR issues and reading their comments. Raw issue receipts remain in the parent
workspace. Inventory/read completion is not issue resolution; this record closes
none of those issues. Main remains pinned at `fdc2696c` in that observation.

## Required promotion record

- [x] Integrate the reviewed facts-eligibility caller repair and record its exact head (`69fa6b8b`).
- [ ] Complete the full combined suite and final-source lint, dependency and schema checks.
- [x] Preserve focused logs/JUnit, discovery inputs and their identities in the verified 94-payload [archive](evidence/continuation-20261119-focused.zip). Active partition outcomes remain separate.
- [ ] Publish the reviewed aggregate and obtain all required hosted checks on its actual head/base.
- [ ] Resolve blocking findings without changing frozen facts or weakening assertions.
- [ ] Refresh main and PR head, then use the normal REST merge with the expected head SHA.
- [ ] Verify accepted main ancestry/tree and record the actual merge commit and checks here.
- [ ] Account for any superseded PR only after its exact scope is demonstrably replaced; retain branches.

There is deliberately no completed main-merge row until the remote result has
been observed and its source identity verified.

## Reviewed golden-fixture correction

The sole contextual-digest golden change reflects the new explicit rounding constant in the accepted CVE repair. Eight independent fresh-process checks establish determinism; the other three algorithm digests are unchanged. The complete9-case cache-identity test file passes after the fixture update. At golden-correction commit `70b82275`, production source was byte-identical to `a4d6dd9b`; the later history merge changes runtime source separately. The original diagnostic checkout and failed receipt remain untouched. Final hosted-head acceptance remains required.


## Phase 4 — candidate assembly

| Event | Identity | Evidence |
| --- | --- | --- |
| Reviewed digest golden | `70b82275` | Exact new ROUND constant reviewed; 9 passed in 1.85s, original pin failure retained. |
| History diagnostic source | `254190a0b36153d28f76782f8d5dae26e9d9a020` | Recovered historical slice plus independently reproduced post-write correction; 81 final passes. |
| Candidate history merge | `520b524beb0c837b6e50801bd97c88a2447e39fd` | Current frozen runtime/tests; all 856 files assigned to 54 groups. |

Original runtime `32abf9702538dc1b2027e8ae052949bbc2436c28`, tests/spec `1c2b770d2eef6266c56504b5d081e5d6d750151e`, lifecycle correction `4d7ae4af9aa6d60fee0f70025d774c3f5b468e0b`.

The original all-856-file diagnostic froze runtime/tests at `520b524b` and stopped after 34/54 groups at the 256 MiB temporary-storage reserve. Its JUnit counters total 15,971 tests, four failures, four teardown errors and 86 skips. The original stopped manifest and every completed receipt are preserved. Separate continuation session 78011 executes only groups 35–54 from the identical source/test/tool fingerprint, using the relocated checkout `/workspace/scratch/81e4938f4a3a/pt-candidate` (documentation head `3cde10ae`). No aggregate pass is available. Later integrated repairs require their own final-head qualification.

Remote checkpoint `bdc929ebd3c6aaa2563c758936beb315a10eeea0` still contains only the earlier `af8772bf` tree. Draft [PR #322](https://github.com/djshellshoxxx/patchtrace/pull/322) was created at `32cc4b04cf1f5b9e69d1d0e8691db7083c7a45a7`, tree `e00ee281fa43744e892bbcf806e4b07a90c15e13`, exactly matching local `3cde10ae`. Those hosted runs were queued at the latest observation. Main remains `fdc2696c`; no main merge or release is claimed.

[History evidence](evidence/history-diagnostic-20261119.zip): 9 verified payloads, 16,801 bytes; SHA-256 `60248a2e1bc603b6dba92451df639d22b7c58cc0d8153262a387242ae4dc5f67`.

## Phase 5 — published candidate and reviewed follow-ups

Initial draft PR #322 head `32cc4b04cf1f5b9e69d1d0e8691db7083c7a45a7` has tree `e00ee281fa43744e892bbcf806e4b07a90c15e13`, exactly equal to local `3cde10ae`. A later REST snapshot found main unchanged, ahead 2/behind 0, all five workflows queued and 21 substantive jobs without an assigned runner or completed step. The queue cause is not established; no workflow was cancelled or approval bypassed.

| Local follow-up | Identity | Evidence |
| --- | --- | --- |
| Reviewed downstream contextual stage pin | `18ccab51` | Independent old-map reconstruction; only one expected value changed; 12 related tests pass in 1.61 seconds. |
| Acquisition binding source and merge | `5131bd94` / `d7842532` | 255 affected passes; 55 integrated acquisition/lifecycle/identity passes. |
| Four-file harness repair | `f114eb96` | Both cleanup policies pass 85 tests with one existing optional-dependency skip. |
| Symbol scanner fixture lifetime | `bc485a6644bee406fbfd92f4bfa47fdfbb4dbcbd` | Original teardown failure retained; 30 affected checks pass in 2.42 seconds. |

The draft-readiness tool available in this session uses GraphQL and therefore is not used under the REST-only rule. If all actual final-head gates pass, an allowed route is a new non-draft PR on a new branch at that exact qualified commit, followed by its applicable checks and a normal expected-head REST merge. Preserve the original draft until replacement ancestry and scope are verified. No main promotion is recorded.
