# PR316 hosted refresh: exact 14ef / preview 5ed

This bounded read-only snapshot is separate from all original 55f3 / 872947fd receipts. API reads observed PR316 open at `14efc52369146f4a638b7d688208736a05321bc0`, main at `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`, and preview `5ed108355f2626c9867782832c76b1c438c51281`. Source and preview have the same tree `b93fb18a7412fb31aab5516903bc300a9ad797e4`. All five retained job logs explicitly check out the preview; API run head ownership is the PR head. These are PR-event receipts, not canonical release-source receipts. The source commit retains the literal `[no release]` hold.

## Confirmed findings

| Job | Run | Observed result |
| --- | --- | --- |
| Windows BinDiff 135059889017 | 44377335166 | Fails before native helper compilation/launch in `checked_source`, with `tracked file changed at open`. Artifact 14462077720 contains only provision metadata. No new Windows sandbox/native acceptance credit. |
| Windows packaging dependencies 135059882415 | 44377335068 | Fails before dependency audit with the same source-guard reason. Artifact 14463320440 contains only the failed verdict. |
| Windows runtime dependencies 135059883163 | 44377335068 | Fails before dependency audit with the same source-guard reason. Artifact 14462856244 contains only the failed verdict. |
| Static scan 135059882502 | 44377335068 | Actual unsuppressed Ruff command exits 1, with 80 diagnostics: S608 35, S105 14, S110 12, S101 9, S310 6, S314 2, S603 1, S108 1. No timeout or output-limit event. This count is not a vulnerability count. Original artifact 14461004899 still lacks bootstrap-pip.txt, as expected before the separate retention repair is published. |
| Linux BinDiff 135059889495 | 44377335166 | Seven native subchecks pass on authored synthetic 20/21-function input. Ordinary and network-denied runs report identical complete imported semantic SHA-256 `77f36f7aac14a6e321c2c6aba9e0c7e3ca6cdba3f690fc18d188ca987b88e181`. The packet preserves both SQLite outputs and the native report; this review does not claim independent real-driver validation. |

The three Windows failure logs do not record the offending tracked pathname or individual stat values. A Windows stat/API cause cannot be inferred from this generic refusal alone. Root owns a separate source-guard investigation; this packet changes no source or gate.

The first status snapshot is 2026-11-18 19:23:45–46 UTC; subsequent bounded job/artifact reads carry individual UTC observations. Several main QA, Qt, unified and native scenarios remain queued or running in the retained snapshot. Successful summary rows outside the five inspected jobs receive no additional acceptance credit here. No completed-suite, package or release qualification is claimed.

## Retention and reproducibility

Five original artifacts total 48,375 bytes. Their exact API sizes, SHA-256 digests and ZIP CRCs were verified before retention. Original artifact bytes are not modified; no omitted file is manufactured. Raw API contents and raw decoded connector log deliveries are preserved in JSON envelopes; `.log` files are exact UTF-8 encodings of those delivered strings, including original line endings. Signed download URLs are not retained.

`review.py` reads those retained bytes and compares five local source snapshots from tree-equivalent commit `740869debb111f8edbef33899316e4c75e6fdf7a` against Git objects with replacements disabled. The snapshots are reference code, never executed. Run with the existing Python interpreter. This command performs local Git reads, JSON/ZIP parsing and hashing only; no scanner, compiler, native tool, workflow, or target is launched.

`manifest.json` hashes every sealed member. `evidence.zip` is a separate immutable archive of the files listed in that manifest; its own hash is returned in the handoff. No remote mutation, rerun, release, tag or deployment was performed.
