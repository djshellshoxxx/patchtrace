# Reviewed follow-up integration checkpoint — 2026-11-18

The reviewed follow-up candidate combines the actual published heads of PRs
#308–#315 with the retained #304/#307 chain, then selectively ports the scanner,
project-retry and two callgraph repairs. **Canonical main remains `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`.**
No main merge, PR closure, remote branch deletion, release, tag or deployment
occurred. Qualification remains open; this is not a beta-ready declaration.

## Source and independent verification

- Branch: `codex/verified-followup-integration-20261118`.
- Tested integration source: **`3be3af166897fc2376dc64850edc66485273dea1`**.
- Tested tree: **`7ef690a25be236eb7c28e3ea92228dca348d2697`**.
- Base: actual published #314, `b41d6631e679ad2777d248fa087ea71582a5bf63`;
  it retains actual #313, #307 and #304 ancestors.
- Combined selected gate: **1,770 passed / three existing expected failures**.
  The exact command, absolute current-source `PYTHONPATH`, offscreen setting,
  log, JUnit and exit code are in `integration/combined-3be3af16*`.
- The earlier combined source `7023c3ad` passed 1,744 with the same three xfails;
  predecessor `ff4f8360` passed 1,025 with three xfails. These are different
  source-pinned selections, not additive unique coverage or a full-suite pass.
- Normal `python -m ruff check src tests tools` passes at `36e14051`, whose
  source/test/tool/workflow bytes equal the tested source. Path QA was the only
  later change. Archived QA copies are not normal lint scope.
- Independent source-preservation verification accounts for all **75** changed
  source/test/tool/workflow files relative to published #307. Every file matches
  a reviewed owner, except the explicitly reviewed combined `ui.py` hunks for
  raw navigation and environment defaults. Actual published parent ancestry is
  checked. No manual production-code conflict resolution was needed.

The three expected failures remain the existing CODEX action-pinning, pip-hash
and corpus-cache requirements. They have not been disabled or reclassified.
The new source still needs full Linux/Windows, repeated Qt, native, package,
dependency and security qualification. Prior source results do not satisfy it.

## Published PRs preserved

The latest REST observation at **08:43:56 PST on November 18** retains main at
the SHA above and lists 62 open PRs. That is a later PR observation, not a
replacement for the original complete 307-branch/297-PR inventory.

| PR | Exact published head | Scope / current disposition |
|---|---|---|
| [#304](https://github.com/djshellshoxxx/patchtrace/pull/304) | `d8c02caea407f6d323eecd636735849c1eb31a2d` | Reviewed CVE consolidation and native publication/chronology repairs; still open and blocked by acceptance semantics and later repairs. |
| [#307](https://github.com/djshellshoxxx/patchtrace/pull/307) | `58fc130631f602b6e907bb054d30c21d810551d4` | Retained KB sources/identity; includes actual #304 and original #307 history; still open, current full/platform checks incomplete. |
| [#308](https://github.com/djshellshoxxx/patchtrace/pull/308) | `92a411bf02fc8beb00b7a148e39db2bf68efa061` | Strings no-clobber publication. |
| [#309](https://github.com/djshellshoxxx/patchtrace/pull/309) | `3c9d3f074481b2f609330fa49ab9019eb6637849` | Bounded paired physical-offset desktop navigation. |
| [#310](https://github.com/djshellshoxxx/patchtrace/pull/310) | `26558cd0723aa5fa6d883f2935ad3c43cef94a86` | Saved/recent searches and delayed-Build intent repair. |
| [#311](https://github.com/djshellshoxxx/patchtrace/pull/311) | `09b032f205f4ffa1838bef56007ebdb7a2308420` | Primary-child environment minimization by default. |
| [#312](https://github.com/djshellshoxxx/patchtrace/pull/312) | `573829f33c84e9b2d53ba51ebd7f699e39f406fe` | Fail-closed source/run/native/security/release qualification. |
| [#313](https://github.com/djshellshoxxx/patchtrace/pull/313) | `a4061979547ef88855fbdb085228a42c3be21603` | Bounded retained advisory reads. |
| [#314](https://github.com/djshellshoxxx/patchtrace/pull/314) | `b41d6631e679ad2777d248fa087ea71582a5bf63` | Current retained-CVRF/Leads/report context plus SQLite type/row budgets. |
| [#315](https://github.com/djshellshoxxx/patchtrace/pull/315) | `23fbe4a54880319f62f40f3196794f85b6cdaec5` | Parser-level manifest DTD refusal. |

Actual #308, #309, #310, #311, #312 and #315 heads are merge parents of this
candidate, and #313 is retained through #314. The separate local/remote commit
mapping for #309–#315 is archived in `hosted/publication-mapping-complete.json`.
All integration messages retain the literal `[no release]` hold. No older PR is
closed as superseded before its valuable behavior is verified in canonical main.

## New reviewed slices

| Slice | Independent evidence and source | Implemented boundary / remaining limits |
|---|---|---|
| Scanner provenance | `b61e1593`; 128 root checks, original five identity contradictions retained | Complete inventories, interpreter/native-environment ownership, installation-report issuers, raw outputs and explicit refusals. Initial actual scans remain failed evidence. |
| Explicit bootstrap repair | `0c004b68`; 160 independent checks; author affected 631 / three existing xfails | Fresh ensurepip inventory and exact hashed pip-only 25.0.1→26.3 transition. Actual Linux runtime 17 / packaging 32 audits include pip and report zero advisories/skips/fixes. Static remains 79; Windows/current-integrated scans are unverified. |
| Incomplete-project schema and replacement refusal | `8b3c6472`; root 236 affected and five additional controls | Refuse foreign views/triggers/columns and companions; use verified retries in place; validate the actual connected database; rollback preserves retry bytes/inodes. Root's original replacement-data-loss failure is retained. Arbitrary noncooperating namespace races and native Windows are not claimed solved. |
| Callgraph cap truth | `2c69c4ad`; root 464 affected and six unchanged historical controls | Deduplicate roots before caps; carry omissions through query, JSON/DOT, CLI and Calls state. Synthetic CLI/Qt journey preserved exact omitted counts and unchanged database bytes. |
| Shared callgraph path budget | `f0b0eb02`; root 490 affected/oracle checks and 17 unchanged historical controls | One adjacency budget across discovery/reverse/enumeration; lazy CSR; cancellation; valid canonical witness retained after later exhaustion. Authored finite oracle and five real headless CLI invocations remain synthetic source evidence. |

The source/QA commits are selectively ported with original attribution. Their
sealed packets were independently checked for archive size, SHA-256, duplicate
names, CRC and every member hash. The two creation packets retain 34/32 members;
semantic batch1 has 74; cap 88; bootstrap 239; path 67. The scanner's prior 298-member
archive remains unchanged. Counts above describe separate overlapping gates,
not added test coverage or a product completion percentage.

The broader reviewed security changes retained through #308–#315 also include
exclusive strings publication, bounded advisory reads, SQLite storage-class
and 16 MiB metadata limits, parser-recognized DTD rejection, current-evidence
revalidation, minimized child environments, and release-source/artifact proof.
Their original reproducers and independent reviews remain in the linked QA
records. The manifest issue was internal-entity expansion through a text-screen
bypass; no external-entity exploit is asserted. Environment minimization is not
a network sandbox. Existing primary memory/output and wider TOCTOU questions
remain separate security work.

## Hosted #304 qualification: source and limits

The inspected jobs checked out GitHub merge preview
`f756d7f151857755c993ebeb95f7a27e1487b9d4`. Its tree
`ee85c94f12c8c52952ca0ced7b0f481e0ef2d674` equals actual #304's tree, with
main and #304 as parents. Raw logs, API observations, source proof and reviewed
artifact hashes are retained. This source identity does **not** transfer to
#307 or this newer integration candidate.

| Gate | Current-session observed result at #304 | Qualification scope |
|---|---|---|
| Full Linux QA | 22,874 passed; 50 skipped; 6 xfailed; 2,037.36 s | JUnit and raw log checked. Skips remain unverified. |
| Full Windows QA | 22,796 passed; 129 skipped; 5 xfailed; 3,509 s | JUnit and raw log checked. Platform/native/optional skips retained. |
| Publication prerequisite | Linux 108 pass / 2 native-Windows skips; Windows 107 pass / 3 Linux-specific skips | The native Windows replacement tests actually ran. |
| Repeated Qt | Windows 5 iterations: 10,150 passes. Linux 20 iterations across 4 shards: 12,200/10,580/8,980/8,840 passes | Repeated executions, not unique-test totals or manual accessibility acceptance. |
| Windows portable/installer | Hosted ZIP checksum/extraction/dependency/self-test and NSIS 3.13 installation, registration, frozen Qt and non-destructive uninstall pass | Large package was not independently downloaded/rebuilt by root. |
| Linux package | Build and Ubuntu 22.04 / 24.04 artifact/tarball checksums, offscreen and XCB/Xvfb self-tests pass | Large package was not independently downloaded/rebuilt by root. |
| Rizin fixtures | Real 0.9.1 on Linux and Windows, 30/322 fixture matches | Fixture compatibility only; not CVE/function accuracy. |
| Ghidriff | Clean and seeded-store variants return 0; raw cache hit verified; plain upstream cached-PDB case reproduces expected FileExistsError | Expected negative is not a successful comparison. Some runtime JVM identities remain unverified. |
| Unified extraction | Two fixture pairs pass repeated/GZF/retained-Ghidriff checks on Windows/Linux; Linux logs assert same content digests across OS | Extract script hash matches source. hm is intentionally coarser and refines; no full class-equality or calibrated-accuracy claim. |
| BinDiff | Linux native fixture passes; Windows job is green but its artifact is **blocked** on no_network | Windows effective network denial must be implemented and demonstrated. Provisioning trust evidence also remains limited. |
| Compiler sweep | Job green; artifact **warning**, only 5 of 11 Rizin pairs completed, 6 no-functions failures | Synthetic AA/mutation/noise/authored failures preserved; separate identical-source card skipped. No promotion of research metrics. |

At 08:43:56 PST all 31 #304 check records are completed: 28 success and 3 skipped
(release, release-gate and MSVC advisory). The native artifacts above explain
why this is not full acceptance. #307 still has full/Qt work in progress and
one queued native job; duplicated earlier native-run records are kept separate.

The two full-QA artifacts were independently downloaded, hashed and CRC-checked.
`hosted/qa-artifact-review.json` retains every skipped/xfail reason, including
missing optional tools/dependencies, opposite-platform checks and unavailable
native producer inputs. Native artifact status and actual runtime contents take
precedence over the green check badge. Package hashes in `hosted/native-review.json`
are corroborated by hosted logs/API metadata, not falsely labeled root rehashes.

## Branch audit and remaining product work

The frozen mechanical inventory covers 307 branches and 297 PRs. Semantic batch1
reviews 20 of 131 unresolved tips: 17 scoped behaviors are retained, while three
broad checkpoint tips retain unreviewed residue. The remaining 111 tips require
semantic inspection; batch2 is assigned on this candidate. Neither counts nor
empty GitHub review lists constitute approval or completion.

Representative live CVE→approved advisory→KB/product/build→verified binary pair
→native functions→analyst review remains incomplete. Retained CVRF context now
has correct freshness/uncertainty/report behavior, but it does not turn a changed
function into a proved vulnerability fix. Real approved acquisition, PW-02 local
MSU/CAB extraction, complete packaged KB/F8 journey, explicit partial-project
recovery UI, manual/native desktop journeys, extraction metadata and the
remaining security/native/resource qualification remain open.

Frozen research is unchanged: L1 remains 73 PASS / 6 FAIL / 0 BLOCKED / 8 excluded of 87;
L2 retains the original native http-parser MISS/FAIL; L3 CVE-2022-34718 remains
metadata-only with facts unverified. Current fixture or smoke receipts do not
replace these outcomes or establish predictive accuracy.

## Preserved coordination failures

The first local merge `194be690` accidentally committed conflict markers in two
documentation append files after a resolver assertion failed. Append-only
repair `04f2845b` retained both document sections; no production file was involved,
no branch tip or acceptance result used the unresolved tree, and no history was
rewritten. Later append conflicts were inspected and resolved with explicit
success checks. `integration/record-resolutions.jsonl` preserves each side and
stage hashes. This checkpoint records the error rather than concealing it.

The earlier selection preflight named two absent test files and stopped before
pytest; its explicitly post hoc note remains archived. Root's initial path
review hit a duplicate module-basename collection error; unchanged historical
controls then ran separately. The old cap expectation that omitted neighbours
were complete was corrected after its retained failing run, while exact visible
counts and below-cap positives remained. The initial scanner full attempt
ended with exit 137 after 14 progress dots without JUnit; cause is unestablished and no full
pass is claimed. Original scans and ineffective proxy controls are also retained.

## Continuing assignments and acceptance

- Integration coordinator: publish this reviewed candidate append-only, obtain
  actual-head full/platform/native/package/scanner evidence, and merge to main
  only when its applicable gates and independent review permit it.
- Integration worker: next bounded semantic batch from the111 unreviewed tips;
  explicit preservation/port/quarantine decisions, with no blanket closure.
- CI/native worker: Windows BinDiff effective-denial design and evidence,
  preserving the original blocked artifact and avoiding assumed child isolation.
- Security reviewer: source-specific disposition of all 79 strict diagnostics,
  with independent guards and reproducers before any repair. Raw findings and
  scanner policy remain intact; no suppression-based pass.
- Product/research follow-ons: approved source acquisition, complete CVE/KB
  analyst journeys, native compiler/identity limitations and frozen-failure
  investigations remain separate eligible workstreams.

The completion matrix retains named D/R evidence for these narrow deliveries;
no final G or whole-product percentage is inferred. No release is authorized.

## Retained packet

`evidence.zip`: **93 members**, **2,170,478 bytes**,
SHA-256 **`022b5a04fd2961524aa0a529790d726b0077387c6332a8240ec1b766471e74b4`**. `manifest.json` records exact sizes/hashes for
every member. All archive CRCs and member hashes were verified. Source/command
records and raw outcomes are complete in the packet; links to predecessor QA
remain in the repository. This documentation append will have its own commit;
only the tested source above is credited with the selected local gate.
