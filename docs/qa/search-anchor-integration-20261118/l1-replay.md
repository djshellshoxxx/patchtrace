# Final published #304: frozen real-source L1 replay

## Result

The one replay on published **f69614fa6b5bb9d25d4233b06a4c4ce179964a52**, tree **6585b91ab746f7615c614efea831a119f34ae8d2**, completed in **39.31 seconds** and retained the prior corrected result:

| Measure | Prior corrected run | Final published-head replay |
| --- | ---: | ---: |
| Frozen cases | 87 | 87 |
| Excluded `facts: unverified` cases | 8 | 8 |
| Asked cases | 79 | 79 |
| PASS | 73 | 73 |
| FAIL | 6 | 6 |
| BLOCKED | 0 | 0 |
| Advisory-edge checks | 79/79 | 79/79 |
| Applicable product checks | 76/76 | 76/76 |
| Expected-filename checks | 64/70 | 64/70 |

The command returned **exit 1 / receipt status FAIL**, preserving the six failures. There are **no case-outcome deltas**. The manifest, exclusions, recorded input observations, file rule, per-check totals, and per-stratum totals are identical to the prior corrected receipt. The inferential `bound` remains null.

This replay asks the real product importer, search service, and pair service about retained vendor/index metadata. Expected filenames are supplied from the frozen corpus. It is a regression and compatibility observation on a corpus already used during repairs; it does not establish independent file prediction, vulnerability attribution, function-ranking accuracy, L2/L3 qualification, or native Windows acceptance.

## Exact identities and preservation

- Published commit: `f69614fa6b5bb9d25d4233b06a4c4ce179964a52`.
- Published tree: `6585b91ab746f7615c614efea831a119f34ae8d2`.
- Local equivalent supplied by root: `70e356055c80ddd59163cf7406636d2162f4d5df`; its tree matches the published tree.
- Frozen canonical manifest SHA-256: `b27775b781db126675565eee5ee008d5854dbf99887726295e7c7c1982e4f487`.
- Frozen manifest raw-byte SHA-256: `b07bf06f7603d9e0c0631d73cf8c886222f98f736cc66eea6bba2d5b921089cc`.
- Baseline corrected receipt SHA-256: `8e858f3ee417a838943b570cbb56c40de48396dc59ed58555aed922e10ee044b`.
- New `file-receipt.json` SHA-256: `b84daff99d229d958ef2fea91deea70d5878be34b3e64c935f2dd2e4f4999e45`.

An ordinary local clone with detached HEAD was used so the unchanged receipt helper can read the exact published identity. The new receipt's `patchtrace_sha` is the published commit, not null. Independent before/after sidecars bind the run to its commit, tree, clean source state, imported package path, and raw inputs.

Preflight verified all 90 entries of the original snapshot hash index and all 37 MSRC plus 45 Winbindex files against their capture receipts. All 93 files now present in the snapshot, including the later corrected receipts, were independently fingerprinted before and after. None changed, and no file was added or removed. No new source retrieval, target acquisition, or target execution occurred. The previous lineage review artifacts remain sealed separately.

## Only case-record delta

Case `l1-2022-11-cve-2022-41073-kb5019959`, for `winspool.drv` under Windows 10 Version 21H1 x64, changes only `files[0].candidates` from **1 to 2**. Its change status stays `unknown`; all checks and its PASS outcome remain unchanged. The other 78 asked case records are identical. All eight excluded records are identical.

A separate post-replay, single-case inspection through the actual import/search/pairs/plan service retained both source variants:

| Field | Observed value |
| --- | --- |
| Older SHA-256, both proposals | `b6a38b711be0f58968f4986f40b6812d7918e4318c0096b75867c2e493f911e3` |
| Newer SHA-256, proposal 1 | `44c719c9eb454f2d8e7228f19e5f6ed6c42077347eb001b699cf229eeb813374` |
| Newer SHA-256, proposal 2 | `f3bcef47231bcfb6af54a6769f0221bd332254949611cb8d97d4e59ccbc06882` |
| Pair status | Both A/C, pending bytes, `WINDOW_CONFOUNDED`, unverified fix boundary |
| Resolution | `ambiguous=true`, `truncated=false`, `changed_in_kb=unknown` |
| Implicit plan | Refused with `PT-KBC-INPUT`, requiring explicit `--pair` |

The retained L1 rule asks whether at least one non-X candidate resolves and whether the index avoids a definite unchanged claim. It does not require unique automatic selection. The unchanged PASS therefore must not be described as proving a unique or confirmed fix pair. Full product output is retained in `winspool-diagnostic.json`; this diagnostic does not alter or replace the first replay receipt.

## Six unchanged failures

| CVE / KB | File | Retained reason |
| --- | --- | --- |
| CVE-2022-21910 / KB5009557 | `clusport.sys` | Server scope is outside the client file-index coverage. |
| CVE-2023-28231 / KB5025229 | `dhcpssvc.dll` | Server scope is outside the client file-index coverage. |
| CVE-2024-38077 / KB5040430 | `lserver.dll` | Server scope is outside the client file-index coverage. |
| CVE-2025-33071 / KB5060842 | `kpssvc.dll` | Server scope is outside the client file-index coverage. |
| CVE-2025-24056 / KB5053598 | `tapisrv.dll` | `changed_in_kb=no`; recorded last change is KB5052093. |
| CVE-2025-50174 / KB5066835 | `das.dll` | `changed_in_kb=no`; recorded last change is KB5065789. |

No expectation, product choice, exclusion, or source label was changed.

## Reproduction and evidence

Source checkout: `/workspace/scratch/e83fbf4505c3/l1-replay-final304-source-f69614fa`.

Raw metadata: `/workspace/scratch/e83fbf4505c3/l1-live-snapshot`.

Executed from the source checkout:

```bash
RQ_ALLOWED_DIRS=/workspace/scratch/e83fbf4505c3/l1-live-snapshot:/workspace/scratch/e83fbf4505c3/l1-replay-final304-20261118 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. QT_QPA_PLATFORM=offscreen /workspace/scratch/3a6632a6e5ff/venv/bin/python -m tools.research_qualification l1-run /workspace/scratch/e83fbf4505c3/l1-live-snapshot/frozen-manifest.json --months /workspace/scratch/e83fbf4505c3/l1-live-snapshot/months --frozen-sha b27775b781db126675565eee5ee008d5854dbf99887726295e7c7c1982e4f487 --evidence-class live --winbindex /workspace/scratch/e83fbf4505c3/l1-live-snapshot/winbindex --winbindex-date 2026-11-18 --out /workspace/scratch/e83fbf4505c3/l1-replay-final304-20261118/file-receipt.json
```

Use a fresh output path for any future replay; the runner refuses replacement. The `live` flag describes the retained real source documents. The unchanged index date is their capture date and does not assert current provider freshness.

`run-replay.py` is the executed 600-second bounded wrapper. `execution-receipt.json` preserves exact arguments, environment overrides, timing, exit code, source identity, and output hashes. `comparison.json` retains the full before/after record for the single delta and the complete counts. `inputs-before.json`, `source-before.json`, and `source-after.json` preserve input and source checks. Raw metadata remains in the existing snapshot rather than being duplicated into this compact evidence package.
