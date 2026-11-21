# Hosted qualification — continuation receipt, 20 November 2026

Read-only capture window: **2026-11-21 02:30–02:33:07 UTC**. This is a source-specific historical receipt, not a live status dashboard. The reviewer changed only this report, its JSON receipt and evidence archive. No workflow was retried/dispatched and no remote ref, PR, release, global ledger or production source was changed by this reviewer.

## Decision

- **PR345 attempt 1 remains failed:** its full Linux and Windows pytest steps passed, but Windows installer preparation hit a confirmed Chocolatey HTTP 503. Its downstream Linux package/smoke jobs were skipped.
- **PR346's applicable automated jobs are green:** both full QA legs, all five Qt jobs, all five native jobs, Windows build/frozen/portable/installer checks, Linux packaging and both Linux smoke jobs completed successfully. Preserve this sibling: its useful unique runtime changes were already selectively recovered into PR347. A wholesale merge of the sibling's broad status files would duplicate/reorder the authoritative record.
- **PR347 is not fully qualified in this snapshot:** Linux QA/four Linux Qt and all native jobs passed; Windows QA and Windows Qt were still running. Subsequent Linux package/smoke results were not yet established.
- The inventory successor at `a63a20b2` had **zero workflow runs** at the unfiltered head-SHA endpoint. The later coordinator source `91618abe` and subsequent repairs are outside this receipt.

The root coordinator owns independent post-integration source review and any qualified guarded merge. It has separately planned one failed-job-only retry for PR345 after preserving the failure; this receipt contains **attempt 1 only** and gives no result for that retry.

## Exact source binding

The checked-out PR merge commits were read from completed job logs. Git Data API commit objects independently prove complete tree equality with each published head.

| PR | Published head | Tested synthetic merge | Identical complete tree |
| --- | --- | --- | --- |
| [345](https://github.com/djshellshoxxx/PatchTrace/pull/345) | `39c38a02f126963fc03827fa49741255590227ad` | `0ad6c2ea6bfaa734c2fc8eb9fb99630ac4727950` | `c458f2bcdbafccb1704966d07c1809a323f7f540` |
| [346](https://github.com/djshellshoxxx/PatchTrace/pull/346) | `c07774ecf5a3f7337834f95a9a4c51c8ec5fad44` | `143d98c1e004d2fdb3464a676364aec3d9bfbd7a` | `8b3b62b05bb6e7bd9eb5de8cbda797aceca52ca0` |
| [347](https://github.com/djshellshoxxx/PatchTrace/pull/347) | `b461ac64eb9beb74449ce2b18b6795a2af34a02a` | `fd0d8d05a92fba18fcf75842d0582472ce1af3ff` | `34fd8e6926177ccccb7f9512100a7b40f8b2d636` |

All three PRs were open, draft, unmerged and mergeable in the metadata snapshot. Main was independently read by `git ls-remote` as `fdc2696c23bdbfe7668348f25e3b336ce33039f7`. Inventory head was `a63a20b2a272d53a09422222050080823fc3c664`.

A successful GitHub mergeability calculation is not qualification. No GitHub review submissions or inline review threads were returned for these three PRs; this does not erase earlier independent local review artifacts.

## Full pytest terminal summaries

| Source | Platform and job | Passed | Skipped | Xfailed | Pytest seconds |
| --- | --- | ---: | ---: | ---: | ---: |
| PR345 | [Linux 136648122190](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44840721370/job/136648122190) | 23,974 | 53 | 6 | 2,211.50 |
| PR345 | [Windows 136648122555](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44840721370/job/136648122555) | 23,847 | 181 | 5 | 3,719.74 |
| PR346 | [Linux 136649934519](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44841261805/job/136649934519) | 23,958 | 53 | 6 | 2,297.45 |
| PR346 | [Windows 136649934371](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44841261805/job/136649934371) | 23,845 | 167 | 5 | 3,489.39 |
| PR347 | [Linux 136657396037](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44843482603/job/136657396037) | 23,996 | 53 | 6 | 2,249.80 |

Do not add these counts across platforms or source trees. The separate pair-publication control selection overlaps the full suite and is not added. Hosted terminal summaries qualify the listed pytest steps; they do not convert the historical interrupted local processes into passes or establish their SIGKILL sender/cause.

## Workflow disposition

| PR and workflow | Result at capture |
| --- | --- |
| PR345 [QA 44840721370](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44840721370) | Failure: Windows NSIS dependency installation; Linux QA and all five Qt jobs successful; package/smoke downstream skipped |
| PR345 [PR-native 44840721268](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44840721268) | All five jobs successful |
| PR345 [push-native 44840716067](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44840716067) | Successful separate push run; not counted as additional distinct test coverage |
| PR346 [QA 44841261805](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44841261805) | Success, completed 02:32:21 UTC; all applicable QA/Qt/package/smoke jobs successful |
| PR346 [native 44841261831](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44841261831) | All five jobs successful |
| PR347 [QA 44843482603](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44843482603) | In progress: Windows QA and Windows Qt still running |
| PR347 [native 44843482467](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44843482467) | All five jobs successful |
| Inventory successor `a63a20b2` | Zero observed runs, including push events |

The commit-status endpoint reports Snyk success for all three PR heads. Check-run enumeration supplements it; the status endpoint alone does not describe all Actions checks. The full workflow query was unfiltered by event: counts 3, 2, 2 and 0 fit a single requested 100-item page. Check-run totals 21, 16 and 13 also fit the requested page. API observations occurred sequentially: PR346's earlier check-run list still had its last smoke job active; the later terminal jobs/workflow receipts establish success.

Release-gate and release were intentionally skipped for PR workflows. They are not missing successful release jobs.

## PR345 Windows failure: dependency feed, after tests

The only failed step in job `136648122555` was **Install pinned NSIS compiler**, running:

```text
choco install nsis --version=3.13 --yes --no-progress
```

At `2026-11-21T01:52:04.2942949Z`, Chocolatey reported HTTP **503 (Service Unavailable)** from its V2 package feed while resolving NSIS 3.13.0. The following steps were already successful in that job:

- Full pytest and whole-tree Ruff.
- Windows application build.
- Frozen EXE smoke/self-test.
- Extraction and execution of the portable ZIP outside the checkout.

Installer build and install/launch/uninstall steps were skipped. The dependency chain in `.github/workflows/qa-windows.yml` requires both QA legs and Qt before Linux packaging, so Linux package/smoke were skipped as well.

PR346 independently installed the same NSIS 3.13 pin successfully earlier, then completed the installer controls. This corroborates an observed feed-availability failure; it does not qualify PR345's skipped installer or prove permanent feed reliability. No PatchTrace source repair is supported solely by this failure. The original failed workflow remains part of the record even if a later retry succeeds.

## Merge and release boundary

AGENTS.md requires all applicable test jobs green and no blocking findings, with a fresh expected-head guard for REST merges. PR345 fails that condition in attempt 1. PR347 has active checks and still needs independent post-integration review. PR346 satisfies the observed automated-job portion, but the coordinator must preserve the selective consolidation topology and review/ledger disposition before any merge.

Manual Windows trust/catalog and native screen-reader acceptance, full raw provenance/membership requirements, and separate L1/L2/L3 evidence remain outside this automated receipt. They prevent project-complete/release-ready claims. This report does not classify every global release item as a defect in these narrow changes, nor does it authorize main promotion.

## Retained evidence and verification

- [Machine-readable receipt](hosted-qualification-cycle2-20261120-2bad.json)
- [Evidence archive](evidence/hosted-qualification-cycle2-20261120-2bad.zip)

Archive: **121,171 bytes**, SHA-256 `8cbf7198584c688bbc84abefb007b91697a66640f7ccc76dd1a044d112ddcb98`.

The archive contains five full decoded job logs, the captured API payloads and a manifest of byte lengths/SHA-256 values. Log text was re-encoded as UTF-8 without newline normalization; original HTTP transport bytes were not available from the connector. All seven archive members were read back and verified against their pre-archive bytes. No test, skip, timeout, retry or workflow policy was changed in this receipt.
