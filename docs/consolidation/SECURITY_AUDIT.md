# Continuation security and integrity review — 2026-11-19

This is a scoped review of the continuation from main `fdc2696c`, with reviewed
source integrated locally through `a4d6dd9b`. It records concrete findings,
repairs and limits. It is not a completed audit of all retained branches or a
native Windows qualification. No target binary was executed for these authored
parser/cache controls.

## Reproduced findings and repairs

| Boundary | Finding and correction | Evidence and status |
| --- | --- | --- |
| Winbindex raw JSON | `compressed=False` bypassed the decoded-byte budget. The shared strict JSON boundary rejects over-budget bytes before decoding or JSON allocation; exact-limit inputs remain eligible. | Part of the parser chain ending `baf95fcd`; initial new controls replayed on base produced 29 failed and 4 passed. Integrated locally through `7610aeaa`. |
| BinDiff key identity | Duplicate algorithm IDs overwrote names; REAL/TEXT SQLite values could alias integer identifiers. Require INTEGER keys and reject duplicate algorithm IDs while retaining eligible unknown integer IDs. | Covered by the same base-red and corrected parser selections. |
| BinDiff table identity | CREATE text can disguise virtual-table prefixes. Review also reproduced forged positive `sqlite_master.rootpage`, so that field cannot prove a table is ordinary. A bounded `PRAGMA main.table_list` inventory now rejects virtual/shadow tables and reconciles names before reads. | Independent review controls: 6 failed, 22 passed before correction; corrected parser/boundary selection: 107 passed. A missing classifier fails closed with a typed unsupported error. |
| Metadata cache ingress | Typed, bounded records must retain the exact envelope, artifact, owner, key and primitive types. Unknown/defaulted fields, corrupt hashes, hostile text, duplicate JSON keys and persisted chain/revocation claims are refused. | Authored cache regressions and real project-store round trips in `0bc41f6b`; malformed data becomes an optional-cache failure without hiding live inspection. |
| Cached digest and math claims | Review accepted invalid digest text and positive signature math with no supporting signer/certificate. Computed digests now require the algorithm's exact hexadecimal width; positive math requires supported signers and matching certificate identity fields. | Review red selection: 13 failed, 2 passed. Positive RSA controls and legitimate file-digest mismatch remain supported. Consistency checks do not re-prove cryptographic math. |
| Cache freshness | An equal-body shortcut reported success for stale/failed rows without renewing their unusable state. The shortcut now requires a current complete row. | Regression controls cover renewal after recomputation; the peer reviewer found the issue resolved. |
| Bounded row materialization | A row could grow between a size query and the body SELECT. The SELECT now repeats the byte predicate and refuses a row changed out of the allowed range. | A failing growth regression preceded correction. The guarantee bounds bodies returned to Python, not SQLite internal page reads or cast allocations. |
| Worker and store ownership | Metadata parsing previously used a second reader thread in the Files tab. The existing inspection worker now parses before handoff; cache reads/publication stay on the owner thread. | Offscreen tests exercise production lifecycle slots, observe thread ownership, prohibit the second reader, and prove subsequent cache reuse. |
| Cancellation and stale publication | Cancellation during the final metadata stage and stale project/oriented-artifact results must not publish cache entries. Fresh file hashing remains required even on a hit. | First/final-side cancellation, artifact replacement, stale owner and failed-storage controls preserve current results and prior rows. |
| N-way failure isolation | Path resolve/stat exceptions could discard the wider read instead of identifying the affected pair. Fixed public reasons now classify unreadable paths and retain healthy hops. | 11 failures on base; 85 affected tests pass at `24064cf6`. OS error details and absolute paths are not forwarded in the new fixed unreadable reason. |
| BinExport2 text admission | Four nested text fields accepted invalid UTF-8 or over-limit values, including the real capped acceptance worker. Reuse existing UTF-8/byte checks while retaining valid empty optional text. | Combined adapter base controls: 35 failed, 16 passed; final related selection: 414 passed in 87.86s. |
| rz-diff error typing | A raw surrogate in fallback output or diagnostics escaped as UnicodeEncodeError. Malformed successful output becomes typed INPUT; nonzero exits retain RUN with display-safe diagnostic text. | Included in the same 414-case selection and independent boundary review. Successful output bytes and hashes remain exact. |
| CSAF redirect typing | Malformed bracketed targets escaped urljoin as ValueError. The narrow wrapper maps only that failure to the established configuration error and retains response closure. | 4 red failures and 6 positive controls; 33 final transport tests pass in 1.08s at `0a4bb12e`. No extra dispatch or cache write on rejection. |

The parser's final broader selection passed **432 tests with 1 Windows skip**.
The cache's final affected selection passed **840 tests with 2 Windows skips**.
An independent peer reran **16 cache controls** and reported no remaining blocker
in the reviewed codec, bounded read, stale refresh, worker, ownership and
cancellation paths. These selections overlap and are not a total test count.
See [parser details](parser-integrity-20261119.md) and
[test receipts](TEST_RESULTS.md).

## Open security and integrity work

The [supplemental static audit](STATIC_AUDIT.md) classifies all 65 Ruff security
warnings, including 21 SQL sites. Baseline/current warning multisets match; that
does not establish absence of defects. No suppression was added. Dependency
vulnerability auditing remains separate work. The attempt-history observability
slice is now corrected in Phase 4 below; malformed-row retention remains open. The first complete-suite attempt ended 137/SIGKILL without
a final report, so focused repairs do not yet qualify the aggregate.

The CVE numeric/time slice is reviewed and integrated through `a4d6dd9b`. Besides
untyped extreme exponent and UTC conversion failures, independent probes showed
tiny or overprecise scores rounding into valid tenths and caller precision
altering 9.8 to 10.0. The final repair validates finite 0..10 values before exact
tenth quantization, uses a deterministic isolated Decimal context, and refuses
unrepresentable UTC instants while preserving original timestamp text. Initial
20 failures/10 controls and a further 10 exactness failures precede 124 final
passes in 6.70s. See [source, caller and issue evidence](RECOVERY_BATCH_3.md).

**Forced strings export remains open.** The retained PR319 audit records source
substitution and OSError cleanup races. Its cancellation correction addresses a
different boundary; neither the parser nor cache commits close these races.
Reproduce the current failure schedules, establish ownership of any file being
published or removed, and verify that cleanup cannot replace or remove a foreign
file. Retain the separate no-clobber and empty-export metadata work recorded in
[the prior consolidation review](../qa/branch-consolidation-20261118.md).

**Research eligibility is repaired locally; aggregate acceptance is pending.**
The shared scorer now admits only `facts: verified`, with other values BLOCKED
and excluded from scored/parity denominators. Eleven base failures precede 33
focused passes. A caller sweep found one authored adapter fixture missing its
facts metadata; its metadata was corrected while retaining the original positive
hit assertion. Final scoped/caller tests pass 140 cases in 4.59s at `d87af037`,
integrated through `69fa6b8b`. No real manifest facts changed. This integrity gate
does not establish correct labels, real producer compatibility, or an L1/L2/L3
accuracy result. See [the recovery receipt](RECOVERY_BATCH_2.md).

**Native trust and release gates remain open.** Portable metadata and mocked
trust checks cannot qualify WinVerifyTrust/catalog behavior. Offline cached
facts contain neither current chain trust nor a revocation result. Windows
packaging, clean-machine behavior, native tools and manual accessibility have
their own acceptance records and must retain their current blocked/pending state.

**Historical review is incomplete.** The census retains 139 branches for semantic
review. Clean merge simulations and patch-equivalent commits do not demonstrate
that every behavior is preserved or every security issue is resolved. Broad
PR316/318 holds remain in place; only documented compatible slices are recovered.


## Phase 4 — truthful attempt-storage outcomes

Recovered source `254190a0b36153d28f76782f8d5dae26e9d9a020`, integrated through `520b524b`, preserves bounded attempt-storage diagnostics without replacing original engine errors or prior trusted sets. Generic publication exceptions now say **"Attempt storage unconfirmed"** because a row may already have committed. Definite not-saved wording requires a returned ownership refusal; a result-kept claim requires confirmed publication. Lifecycle resets clear transient details. Malformed-row retention and the underlying post-write retention exception remain open.

Baseline: 12 failed/8 passed in 19.07s. Recovered slice: 79 passed in 42.63s. Real SQLite post-write controls: 2 failed in 3.59s. Final affected UI/host selection: 81 passed in 37.33s; whole-tree Ruff and whitespace checks pass. Independent source review found no blocker in the recovered diagnostics, scheduler/producer boundary or persistence ownership/refusal contract. Authored offscreen controls do not qualify native comparators or atomic storage.

[History evidence](evidence/history-diagnostic-20261119.zip): 9 verified payloads, 16,801 bytes; SHA-256 `60248a2e1bc603b6dba92451df639d22b7c58cc0d8153262a387242ae4dc5f67`.

The all-856-file, 54-group qualification is running on `520b524beb0c837b6e50801bd97c88a2447e39fd` in coordinator session 74806, with its own `/tmp/pt81-final-venv` environment and results under `/tmp/pt81-final-results`. Source/tests are frozen. No aggregate pass is available yet.


The final supplemental scan on `520b524b` reports 64 findings, no added normalized
warnings, and one removed S110 warning for swallowed `ui_evidence` publication
failure. Configured whole-tree Ruff passes. The 65-finding baseline remains
frozen; see [the final-scope amendment](STATIC_AUDIT.md). The raw final scan is
`/tmp/pt81-final-results/security-static-final.json`, pending coordinator archival.
This is not a clean-security or aggregate-test claim.
