# Independent lineage integration review — 2026-11-18

## Decision

Approve the production integration at **237d216f0784d429bfc5c61103100346576e0831**, tree **e5b934d1438d9298a1695645e48b9e46c02ee0af**, within this bounded source and synthetic-control review. No remaining source blocker was found. Four existing caller tests need their resolution doubles completed with `ambiguous=False, truncated=False`; the fixture-only correction is independently proven below. This is not Windows qualification or an accuracy result.

The merge **22aa4e8f58f69b7d8c90c15b263c732c8c6bdeac** preserves both exact parents:

- Previous #304: `6cc6b6b77564e12eaec2917877d94525a69c7102`.
- Incoming #302: `121ffb0bcdd6af4f24e5035389d4709dffddf263`.

The subsequent compatibility repair changes production by two lines in `predecessor`: resolve a value-equal target to the timeline's own row before using the identity-keyed chronology cache. Its specification and four cached/uncached regression cases accompany the repair.

## Reproduced blockers in the previous #304

All examples are independently authored metadata for an AMD64 Windows 11 scope. No target bytes, network retrieval, or target execution were used. The complete eight scenarios and results remain in `reproduce.py`, `304-results.json`, `302-results.json`, and `237d-results.json`.

| Scenario | Previous #304 result | Incoming #302 and integrated result |
| --- | --- | --- |
| Equal timestamp, different numeric build families (`26000.100` → `26100.200`) | Claims a change, grade A, source-supported fix boundary, and implicit selection | Chronology is unknown; grade X; boundary unverified; no implicit selection |
| Same-time observation with no stated build, hidden by display ordering | Ignores the unplaceable peer and claims a source-supported boundary | Retains the peer as a confounder; unknown change, unverified boundary, explicit choice required |
| Immediate predecessor observations contain both the target bytes and different bytes | Changing only the competing hash's sort position flips the change claim between `no` and `yes`; one ordering claims a supported boundary | Both orderings retain unknown change and unknown last-change provenance; boundary unverified; explicit choice required |
| Two target variants, one unavailable | The remaining viable pair is implicitly selected; the unavailable target may use a same-time sibling as its older side | Both seek a demonstrably older observation; full-source ambiguity survives filtering; explicit choice required |
| Two target variants, `limit=1` | Truncates output yet implicitly selects the surviving pair | Retains truncation and ambiguity; implicit selection is refused |
| 100 target identities, `limit=7` | Evaluates 100 pair proposals before retaining seven | Evaluates seven proposals; reports truncation and requires explicit choice |
| Unambiguous, strictly ordered ordinary pair | Grade A, source-supported boundary, implicit selection | Same full pair record, pair ID, and choice |

The predecessor-variant row above covers two separate scenarios, giving eight controls in total. Integrated results equal the incoming results in every recorded field except elapsed timing. That equality includes proposal IDs and reason codes, not just the compact summaries.

These findings justify retaining all three unique behavior commits together: `fbc164d401b103237fad2fbb633dc2d124afb2b7`, `154f030c7d170ebc757f8b1aa338c9f572f2133e`, and `7d80aee7b92eb9fe83c818cdfec7527f19efc252`.

## Incoming API regression, independently found and repaired

Before the new cache, `predecessor(line, target)` used value equality through `line.index(target)`. The incoming implementation keyed facts by object identity but looked up the caller's target directly. `dataclasses.replace(line[-1])` therefore raised `KeyError` despite being equal to the timeline row; a genuinely absent target also leaked `KeyError` instead of the previous `ValueError`.

The independent `test_predecessor_value_compat.py` passes both cases on previous #304, fails both on incoming #302, and passes both on the integrated repair. Root's four repository cases also cover a supplied cache and the default cache. The repair restores the original target contract before any cached lookup; it does not weaken chronology checks. Existing production resolver calls use their own timeline row objects, so the observed defect was at the pure helper compatibility seam.

## Caller fixture correction

The additional four failures are in the prefix-selection regression and the first three parametrized/ordinary selection-guard cases. Their `SimpleNamespace(pairs=...)` resolution doubles omit both evidence flags. Production callers obtain real `resolver.Resolution` objects, which supply the two default fields. `_pick_pair` is a private, currently unannotated static helper; the source does not literally annotate its argument as `Sequence[Resolution]`.

The unchanged selected cases fail four times on the frozen integrated source. Copies outside the repository with only `ambiguous=False, truncated=False` added to the resolution doubles pass all four cases, preserving every original assertion. `fixture-correction-proof/fixture-only.patch` records the precise change. Both invocations have logs, JUnit files, and receipts containing the exact command, environment, source head, timeout, exit status, and log hash. No repository test or production file was modified during this review.

Keep direct access to the real evidence flags in production. Defaulting missing evidence to false would hide an incomplete object instead of correcting these fixtures.

## Validation

The rows below are separate, overlapping test invocations; they must not be added as a count of unique tests.

| Invocation | Previous #304 | Incoming #302 | Integrated 237d216f |
| --- | --- | --- | --- |
| Exact copied new ambiguity/bounds tests against each source | 22 failed, 3 passed | 25 passed | 25 passed within the 27-case combined invocation |
| Two independent copied/absent-target controls | 2 passed | 2 failed (`KeyError`) | 2 passed within the 27-case combined invocation |
| Ten focused repository modules | Not rerun | 393 passed | 397 passed |
| Four original caller-fixture cases | Not needed | Not needed | 4 failed (`AttributeError`) |
| Same four cases, fixture-only copies | Not needed | Not needed | 4 passed |

The ten focused modules are lineage, lineage certainty, lineage ambiguity, resolver, resolver architecture, resolver bounds, index pairs, pairs, service, and contracts. Targeted Ruff passed on the reviewed lineage/resolver/service production files and ambiguity/bounds/index-pair tests. All three detached source worktrees remained clean and at their exact pins after execution.

## Compatibility and ranking implications

- `Resolution.ambiguous` is an additive final dataclass field with a default. The derived response gains an `ambiguous` key and displays the explanatory note even when pairs exist. Consumers should retain that evidence.
- Implicit pair choice deliberately becomes stricter. A viable pair cannot erase source ambiguity or incomplete enumeration. An explicit unique prefix still selects a candidate; the subsequent plan retains its grade-X refusal.
- The pair limit is now an enumeration budget. Availability and stable source position choose the bounded subset before the existing ranking sorts it. A truncated list does not promise the globally best pair; truncation and refusal of implicit choice make this limitation explicit.
- The one-million row-work cap bounds per-target enumeration work, not every initial input scan or sort. A truncated attempt with no evaluated predecessor reports `INDEX_GAP`, avoiding a false `NO_OLDER` claim.
- Pair identity construction is unchanged. The ordinary positive control preserves its exact pair record; ambiguous source windows can correctly change endpoints, flags, or eligibility.
- The chronology cache is request-local. The compatibility fix canonicalizes a target within the supplied timeline; a cache from a different timeline is outside that local-cache contract.

## Verified integration preservation and limits

The integrated resolver and service blobs exactly match incoming #302. The Windows publication implementation and `tests/test_research_qualification_l1_run.py` exactly match previous #304, preserving the native repair and TSP controls. Exact blob IDs, source SHA-256 values, commit parents, clean-worktree checks, JUnit totals, and result comparisons are in `review-metadata.json`.

Minimal verified integration is the history-preserving merge already present, followed by the two-line predecessor compatibility repair and the fixture-only correction. Do not replace the whole integrated tree with incoming #302: that would lose unrelated repairs reviewed by the other workers. This review does not substitute for the exact-head hosted Windows gate, a full-suite gate, or qualification against real acquired binaries. No new accuracy claim is made.

`COMMANDS.md` contains the exact focused commands and replay conventions. `manifest.json` hashes this review and every retained raw/control file; the sibling ZIP is a compact copy for the parent to persist with the Git-backed follow-up.
