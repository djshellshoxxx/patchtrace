# Generations 9–14: acquisition evidence, QA diagnosis and qualification

Repository: <https://github.com/djshellshoxxx/PatchTrace>.
This continues the [master directive](master-directive.md) and
[generations 2–8](generation-2-through-8-20261119.md). No project-wide completion,
main merge, release or deployment is claimed.

## Exact source and publication identities

| Checkpoint | Identity and meaning |
|---|---|
| Main at discovery | `fdc2696c23bdbfe7668348f25e3b336ce33039f7`; refresh before acting. |
| Prior candidate, draft PR322 | `f2458aae22ea6177be64cfc2fb439a79950f00ff`. |
| Published draft PR324 | `3862cb5de3256efec8f6392a3b6fb4d9e600c377`, branch `codex/maximum-completion-20261119-4c8d`, stacked on PR322. |
| PR324 exact tree | `59c37a3ba7f2c67607bbca60eeb7e683ef391e47`, equal to local publication `eb89c342fb9af9f7a647772aa559a408857b8dd0` and actual PR merge checkout `deab5a058da7814f6fbef9b108faa73695c3882e`. |
| Original unsplit qualification source | `bffcfa99d6a5044024256edbc0457ab20c92cbae`; process killed, not a passing gate. |
| Reviewed follow-up runtime/tests | `97ca0adfad5ea4e6cae0648a55529b9165a40b21`; 1,737 affected passes/one native skip. |
| Follow-up publication branch | `codex/patchtrace-followup-20261120-4c8d`, based on PR324's exact remote head. Resolve its current PR/head from the task ledger and GitHub before selecting work. |

The follow-up is a separate stacked candidate so the initial PR324 CI can finish
without cancellation by later source changes. The local integration branch stays
`codex/maximum-completion-20261119-4c8d`; REST publication creates a different
commit identity. Verify complete tree equality and do not force-push or reset the
local source graph to pretend these IDs are identical. Current publication and
worker state are in [`task-ledger.json`](../engineering/task-ledger.json).

## Engineering completed in this checkpoint

### Acquisition provenance

Implementation `fd886e194d8bd2ee346162017a8f0939310053f3`, integrated as
`f5cebcbf`; independent review `9404052a2ce928b00ad3ca68d6b6fed6d6762750`,
integrated as `97ca0adf`.

The initial controls reproduced two missing behaviors: a completed acquisition
did not persist its original source proposal, and documentary source-entry
changes still accepted old consent when binary hashes and URLs were unchanged.
The retained-ref scan found one acquisition-module blob and checked related
service/store/context/contract and inventory variants before implementation.
The later scan is 717 refs/78 relevant blobs; it does not rewrite the older
323-branch/312-PR/59-tag census or its 154 semantic-review dispositions.

The new bounded `AcquisitionEvidence` retains the full original proposal/window,
two normalized delivery rows and original entry hashes, exact consented request
plan, conservative inspected manual pair and verified download receipts. Consent
binds the frozen source claims. The existing attach journal carries the record;
its operation key binds the evidence ID and original base revision. Owner-checked
exclusive sidecar publication, immutable enrichment rows, idempotent recovery
without the mutable index, and existing backup preserve the record. Legacy local
imports and journals remain valid without invented provenance.

The manual pair remains grade B/tier E with user-asserted lineage and an
unverified fix boundary. Normalized source rows are not raw entries, a complete
index, authenticated vendor facts, or every input required to rerun the resolver.
UI display and advisory export are outside this slice.

Original two red controls, the intermediate architecture failure, and the final
1,547-pass/one-skip affected run remain preserved. The architecture repair binds
the existing publisher only at `wiring.py`, with a narrow explicit port and
finite import allowance. Four independent controls plus 27 author cases pass.
The first peer attempt incorrectly expected exit 2 for the established
`PT-KBC-VERIFY` exit 3; its original failures and test source remain archived.
No application change was made for that fixture correction.

Read the [implementation handoff](acquisition-provenance-20261120/README.md) and
[independent review](../engineering/acquisition-provenance-peer-review-20261120.md).
The earlier reviewer stopped by automated review is not credited as completed;
the coordinator performed the independent source review and authored controls.

### GUI test instrumentation

Implementation `a7a4b2d8202dfd5de8fd15276c5aa88948b9079f`, integrated as
`f7aa36c3`. The lazy-table helper wrapped a model class and counted pending work
on every instance. A real two-view control reproduced 183 reported calls versus
91 selected-model calls. The fix counts only the selected instance while still
delegating every call. Product code, timing thresholds, call ceilings and original
assertions are unchanged. All 186 affected cases and the coordinator's 41-case
table replay pass; those selections overlap.

The initial regression fixture's teardown segmentation fault, clean red replay
and final results are preserved in the [QA diagnosis](../engineering/qa-diagnosis-20261120.md).
This independently confirmed helper defect does not establish what caused the
original aggregate table failure, because its traceback never arrived.

### Linux forced-publication investigation

`79f5abf0` adds reviewed primitive evidence, not a runtime repair. Fourteen native
controls were replayed on tmpfs and overlayfs. The current named-source
substitution interval still allows foreign bytes to become visible before
receipt refusal. Descriptor links, empty-path rename attempts, exchange, locks,
leases and same-UID directory permissions did not provide the required repair
in these controls; blind rollback can displace a later publication. Original
filesystem-label fixture error and corrected replays are preserved.

The [primitive assessment](../engineering/linux-force-primitive-assessment-20261119.md)
does not claim universal impossibility. A separate broker is a future architecture
candidate requiring design and review, not an implemented mitigation.

## Qualification and evidence

| Source/scope | Observed result | Practical limit |
|---|---|---|
| Original unsplit `bffcfa99` | SIGKILL after 1,729.332 s; 19,877 progress markers, including two failures; no terminal traceback or JUnit | Incomplete; cause unestablished. |
| Previously unreported remainder on the same source | 14 processes; 3,849 passed/32 existing skips; all 3,881 distinct node IDs reconciled | 3,879 unreported nodes plus two overlaps; diagnostic coverage, not an unsplit pass. |
| Combined follow-up `97ca0adf` | 1,737 passed/one native Windows skip in 98.56 s; Ruff, schema drift and whitespace pass | Affected selection only; separate current-source hosted gates required. |
| PR324 native Windows Ghidriff | Both five-scenario workflows succeeded; clean fixture artifact digest verified; backend exit 0 in 93.953 s | Authored fixture compatibility on initial source, not general accuracy or follow-up acceptance. |
| PR324 Qt at 00:53–00:54 UTC | Linux shard 2/4: 10,680 repeated passes; shard 3/4: 8,640 repeated passes | Repeated executions, not distinct cases. Other Qt legs and both full QA legs were running. |

The original AF_UNIX check fails with constructor `EPERM`, including an unguarded
control. It fails before entering the project network guard. No permission,
policy, test or skip was weakened. Runtime diagnostics cannot establish the
SIGKILL cause: diagnostic APIs and cgroup memory-event counters are unavailable,
and ordinary kernel-log access is denied. No OOM or host-load attribution exists.

All 32 remainder skips require missing LLVM tools. The normal tool-path and
package-capability check found no usable installed toolchain. The cloud runtime
Packages guidance requires the managed package helper, which is absent; sudo is
also absent. No install, escalation or repeated known-skip test run occurred.
The original blocked cases and exact replay selection remain preserved.

The [aggregate qualification](../engineering/aggregate-qualification-20261119.md)
links raw receipts. Additional immutable evidence is under
`docs/engineering/evidence/`: `followup-combined-20261120`,
`aggregate-remainder-20261120`, `gui-counter-root-review-20261120`,
`pr324-ci-review-20261120`, and `pr324-native-patchtrace-clean`.
Do not sum overlapping selections or attribute earlier receipts to later source.

## Recovery and exact continuation

The original local source history is retained in the 20261119 bundle. After
fetching its PR322 prerequisite, recover it as described in the aggregate report.
The 20261120 follow-up bundle preserves four integration/author/review refs and
requires `8cfda72b`, `860fdf24` and `bffcfa99`, all available from the earlier bundle.
Verify both bundles before use. Their full hashes and source trees are in
`evidence/integration-checkpoint.json` and `evidence/followup-checkpoint-20261120.json`.

Refresh remote refs and reconcile the exact current candidate before making an
isolated worktree. Read `AGENTS.md`, `docs/modules.md` and the relevant spec. The
affected command is preserved verbatim in the follow-up ZIP receipt; the required
full gates remain:

```sh
QT_QPA_PLATFORM=offscreen python -m pytest -q --junitxml=qa-results.xml
python -m ruff check src tests tools
PYTHONPATH=src python tools/generate_kbc_schemas.py --check
```

Use an ordinarily supported execution environment for native fixture and local
socket acceptance. Preserve every failure and source identity. Do not repeat the
same interrupted unsplit run blindly, infer its cause from later memory readings,
or turn blocked tests into passes. Windows packaging runs on Windows.

## Current blockers and next useful scopes

1. Finish the original PR324 hosted Linux/Windows QA, remaining Qt and downstream
   package checks; read actual terminal artifacts. Separately qualify the new
   follow-up head. Refresh checks immediately before any eligible merge.
2. Provide an evidenced repair or disposition for the remaining Linux forced
   replacement exposure. Preserve feature behavior and reject unverified rollback
   or primitive guarantees.
3. Resolve native Qt advisories using a supported qualified artifact or a
   component-specific disposition. The last official refresh had no 6.12.1
   binding wheels; a version match alone is not application reachability proof.
4. Continue bounded raw Winbindex entry/index retention and resolver membership
   preservation, with independent review and without fabricated historical data.
5. Continue semantic review of the 154 retained heads and inventory later ref/PR
   deltas. No branch is superseded just because another commit looks similar.
6. Keep native Windows trust, packaging, clean-machine/accessibility/manual gates
   and separate L1/L2/L3 verified-label obligations open. No blended accuracy or
   `facts: unverified` scoring is permitted.

There are no unresolved integration conflicts at the reviewed source checkpoint.
Completed workers' historical ownership does not imply they remain active. Fetch
the ledger and live worker state before claiming a scope.

## Actual continuation

The hourly **Continue PatchTrace engineering** automation is enabled, with first
scheduled occurrence `2026-11-20T01:15:16Z` in the user's America/Vancouver schedule.
Environment selection is inherited; no future runtime availability or successful
execution is guaranteed. The prompt requires fresh refs and handoff, exact source
verification, isolated fresh workers, avoidance of active ownership, genuine
uniqueness proof, reviewed implementation, and retained failures. It permits only
normal expected-head merges when all applicable checks are green and no blocker
remains. It does not authorize automatic release publication or target execution.
