# Product-start Windows candidate — 2026-11-06

This supplements the [completed qualification record](continuation-qualification-20261106.md)
with the later Windows result observed at 09:43–09:44 UTC. It preserves the
earlier snapshots and original local failures.

## Complete Windows qualification

Frozen #247 `37b771300053e8872febead1fc384fea9126ae90` passed its complete
Windows suite: **20,331 passed, 94 skipped, 5 xfailed and 19 warnings in
2,675.35 seconds**. The summary was emitted at 09:38:39 UTC in
[job 127790743999](https://github.com/djshellshoxxx/patchtrace/actions/runs/42187353481/job/127790743999).

The job also passed whole-tree Ruff, standalone build, frozen A1–A4 and
self-test, portable ZIP execution outside the checkout, NSIS/per-user
installer construction, install/launch/uninstall checks and artifact upload.
The portable and installer logs include checksum, Qt/runtime and frozen
execution checks. This is native Windows packaging evidence.

The checkout log identifies merge `bfecc248af653d8c93d7bf3bf46a2121122c6d23`,
with parents `f393bb68` and `37b77130`. Its tree is exactly the source tree
`cdbab24d14295b4450cd0d3c744d76734c98a561`, also tested by the completed
Ubuntu suite: **20,372 passed, 52 skipped, 6 xfailed and 19 warnings**.

## Downloadable candidate

[Download the Windows x64 candidate](https://github.com/djshellshoxxx/patchtrace/actions/runs/42187353481/artifacts/13492805458).
This is the first verified candidate in this continuation that contains
#247's explicit stored-product starting route, including source-bound local
pair creation and journal-bound pending repair.

| Field | Verified value |
|---|---|
| Artifact | `PatchTrace-windows-x64`, ID `13492805458` |
| Created | 2026-11-06 09:41:46 UTC |
| Size | 131,735,616 bytes |
| Source | `37b771300053e8872febead1fc384fea9126ae90` |
| Artifact SHA-256 | `020d6be11fbc4dd6bd3d3b6f88e66d822263e5d2e3855fea77393b8ad27b8d2a` |

The API and upload log agree on the artifact identity, size and digest.
The archive was not downloaded and independently rehashed in this review.
The [source-pinned Windows receipt](continuation-qualification-20261106/pr247-windows-product-start-qualification-20261106T0943Z.json)
retains the job, step, source/tree and artifact evidence.

## Remaining qualification

At the receipt's 09:43–09:44 UTC snapshot, both full application QA jobs and
all five Qt jobs passed. Linux package job `127822504185` was queued, with
both downstream Linux smoke legs not yet present. Parent promotion still
requires applicable current checks, normal review and scanner disposition.
Separate live-tool and manual release acceptance remains open.

The original local full run remains **1 failed, 20,284 passed** because this
environment denied AF_UNIX construction before the network guard. No local
application test was rerun for this later hosted-evidence addendum.

Pending product-start attachments require the new journal reader. The older
reader retains but ignores `selected_product` during repair; the observed
legacy repair lost product-source digests. Public schemas and SQL version
remain unchanged, while the persisted internal journal is extended.
