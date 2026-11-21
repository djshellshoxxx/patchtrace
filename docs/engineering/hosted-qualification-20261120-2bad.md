# Hosted qualification snapshot — 20 November 2026

Observed at **2026-11-20 23:36:29 UTC** using read-only GitHub connector calls.
The [machine receipt](hosted-qualification-20261120-2bad.json) preserves exact
heads, job identities, observed states, Windows QA steps and the independently
verified native cache archive. No workflow was dispatched or rerun.

## Source boundaries

| Candidate | Exact head | Observed status |
| --- | --- | --- |
| [PR #343](https://github.com/djshellshoxxx/PatchTrace/pull/343) | `1c60d91ab1d2038ba481d21d58611137f21b8454` | Draft, unmerged; QA workflow completed successfully |
| [PR #344](https://github.com/djshellshoxxx/PatchTrace/pull/344) | `67f7e08ea9bee61653f8ab5ad66048d3e7141810` | Draft, unmerged; qualification incomplete |
| Coordinator integration | `84798a04da9bc6a823b4b2d7802ea08a322c5367` | Later local source; not qualified by either predecessor's hosted results |

The actual PR344 native job checked out synthetic merge
`bb66f1de2a7de3dd4623ae472890411cdabdb1f7`. Fetching that exact merge ref and
comparing Git trees verified that it and the PR head both have complete tree
`0ba9b19fd69cc4c6ec59938e5d99d7628f0a53ca`. The artifact independently records
the PR head and branch. This avoids confusing workflow head metadata with the
actual checked-out source.

## PR343 completed acceptance

[QA run 44810716926](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44810716926)
reports success. Both full QA legs, all five repeated Qt jobs, Linux packaging
and both Linux smoke jobs succeeded. Release and release-gate jobs were skipped.

The Windows QA step receipt specifically confirms full pytest, whole-tree Ruff,
Windows build, frozen headless smoke, portable ZIP extraction, installer build,
and install/launch/uninstall checks succeeded. This is automated acceptance on
the recorded predecessor source. It is not clean-machine manual accessibility
or signing/trust approval, release authorization, or acceptance of PR344 and
the coordinator's subsequent changes.

## PR344 unfinished acceptance

| Workflow | Passed jobs | Running jobs | Queued jobs |
| --- | --- | --- | --- |
| [QA 44835855059](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44835855059) | None yet in this snapshot | Linux Qt shards 1/4 and 4/4; Windows Qt | Both full QA legs; Linux Qt shards 2/4 and 3/4 |
| [Native 44835855078](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44835855078) | Clean, seeded store, raw-cache-hit | None in this snapshot | Plain Ghidriff reproduction; seeded store without adjacent PDB |

The QA release-gate job is skipped. No downstream package or smoke completion
is inferred. The run-summary endpoint still said `queued` while its job endpoint
returned running/completed work; the receipt preserves these limits rather
than assigning an overall successful result. Refresh terminal jobs before any
merge decision.

## Native raw-cache receipt independently checked

[Raw-cache job 136631954930](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44835855078/job/136631954930)
succeeded and published
[artifact 14678947527](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44835855078/artifacts/14678947527).
Its downloaded ZIP SHA-256 matches the GitHub artifact digest:
`3209f24adcdf74cf1a82bca50e6490bfb39874e960c2ae7c7d19e26c9b3d9e88`.
The receipt retains the original 2,950 bytes as base64 plus each JSON entry's
SHA-256, so these observations remain inspectable after artifact expiry.

Both captured application-level Java probes returned zero and reported Temurin
25.0.5. Both analysis records completed with one match and identical raw SHA-256
`f244a0e2bb1862bd366309a24544d41df895f47bda56eaadcc2760f627f6bb82`.
The second records a cache-origin key and the existing cache-reuse event;
`result.json` says `passed`. The job log independently confirms cache-hit
verification. ZIP and JSON were read as data only; this review invoked no
analysis or target executable.

These observations **do not establish the cause** of the original
[5cc3f2a raw-cache failure](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44770501981/job/136406567877),
which reported `second run was not a cache hit; java=unverified` without a
retained application-probe artifact. The successful current probes cannot
reconstruct that failed probe. The original failure remains preserved and
unexplained. Do not introduce a speculative retry or weaken cache admission.

Likewise, PR343's successful Qt result does not explain PR342's earlier two
strict 10-second investigation-dialog create timeouts. That history remains
source-specific failed evidence. Historical interrupted local full suites,
manual Windows/trust/accessibility, complete raw provenance and separate
L1/L2/L3 qualification remain independent gates.

## Handoff

Use this as a timestamped receipt. Refresh exact-head jobs after publication of
the new integration candidate; its report cleanup, TaskRunner lifecycle and
Linux publication capability changes need their own supported-runner gates.
No main promotion, release, deployment, source deletion or outbound message
occurred in this review.
