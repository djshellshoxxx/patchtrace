# Read-only native/corpus CI triage

## Scope and result

Exact PR #159 head: `56374f867594dd923383c91ea71970cb7d24d173`.
Original PR #152 head: `0130bf81e2fe3154f30af7b68a0e6ab197946040`.
Reviewed local portability candidate: `ca80cc0f310ad1a82174cd17ee1fa8443b016b73`.

The corpus and rz-diff failures remain explicit orientation-acceptance blockers under the existing pinned configuration. They are not repaired by the portability changes. No separate native/tool implementation failure was identified in the inspected jobs. Keep the quarantine, preserve failed/blocked evidence, and require independently reviewed orientation evidence and implementation before claiming Rizin or default Tier R acceptance.

## Exact #159 runs

The commit's workflow API returns exactly three runs:

| Run | Workflow | Result |
|---|---|---|
| [41509306365](https://github.com/djshellshoxxx/patchtrace/actions/runs/41509306365) | Native Windows Ghidriff, pull request | Success, five modes |
| [41509281649](https://github.com/djshellshoxxx/patchtrace/actions/runs/41509281649) | Native Windows Ghidriff, push | Success, five modes |
| [41509306110](https://github.com/djshellshoxxx/patchtrace/actions/runs/41509306110) | QA and Windows standalone | Failure; known QA/UI issues handled separately |

There are 23 check runs overall, including ten successful native-mode checks across the two events. These represent five modes repeated, not ten distinct acceptance dimensions. The plain-Ghidriff reproduction mode intentionally expects an upstream cached-PDB failure; the other modes test PatchTrace execution or raw-cache behavior on the workflow's repository-owned synthetic C fixtures. The clean-mode job log confirms actual hosted Ghidriff processing.

There is no corpus or live-rizin run for this exact #159 head. Those workflows have narrower path filters, so absence is not a green result and does not supersede their #152 failures. No new native acceptance is claimed for the local assembled candidate.

## Original #152 failures

| Evidence | Observed result |
|---|---|
| Corpus [run 41503829018](https://github.com/djshellshoxxx/patchtrace/actions/runs/41503829018), [shard 0 job 125478518407](https://github.com/djshellshoxxx/patchtrace/actions/runs/41503829018/job/125478518407) | `failed=[]`, `blocked=["evaluate:rz-diff"]`, six case records, exit 3. Orientation-unverified reason for pinned 0.9.1. |
| Same run, [shard 1 job 125478518634](https://github.com/djshellshoxxx/patchtrace/actions/runs/41503829018/job/125478518634) | Same blocked engine evaluation and empty failed list; six case records, exit 3. |
| Same run, [merge job 125479611289](https://github.com/djshellshoxxx/patchtrace/actions/runs/41503829018/job/125479611289) | Both shards read; `failing_cases=2`, exit 1. Source confirms blocked case rows are included in this aggregate count. Combined with the two shard summaries, these are the two blocked evaluation rows, not missing-shard evidence. |
| Live-rizin [run 41503829017](https://github.com/djshellshoxxx/patchtrace/actions/runs/41503829017), [Windows job 125478008453](https://github.com/djshellshoxxx/patchtrace/actions/runs/41503829017/job/125478008453) | `status="blocked"`, `blocked_reason="rz-diff-orientation-unverified"`, version/pin 0.9.1, exit 1. |
| Same run, [Linux job 125478008715](https://github.com/djshellshoxxx/patchtrace/actions/runs/41503829017/job/125478008715) | Same status, reason, and pin; exit 1. |

The live checker refuses at the unsupported capability probe before invoking matching. The corpus default engine is still rz-diff. These are deliberate refusals under the existing quarantine, not transient import, newline, or host-path failures.

## Unchanged source evidence

These blobs are identical across exact #152, the verified local representation of #159, and `ca80cc0`:

| Path | Git blob |
|---|---|
| `.github/workflows/corpus-tier-r.yml` | `baf6cd9b3fc93ac894dc2f12c28a60c820897cc6` |
| `.github/workflows/live-rizin.yml` | `90e0880cc66c1e8c950b2b5145ef8d251eb212a5` |
| `tools/live_rzdiff_check.py` | `45f4ef69cbe3e4b306d6f2321fe6b3af951b7266` |
| `tools/calibration/tier_r/shard.py` | `76cd1f9754fd4faf6a96fc726ca640f870701359` |
| `src/patchtrace/secondary/rzdiff.py` | `35ad5aa6ce1775d2c74679cd990b653fa21ce723` |

The concrete integration consequence is that a fresh run which triggers these workflows should not be expected to become successful merely from merging the reviewed portability, scope, backup, or schema fixes. Preserve the separate acceptance debt and its quarantine; do not label it fixed, loosen the version policy, or substitute Ghidriff's synthetic smoke for rz-diff/corpus acceptance.

Check/run metadata and decisive log excerpts, including original line numbers, are retained in `/tmp/patchtrace-ci-triage-evidence-20261102.json`. Only read operations were performed. No workflow was dispatched or rerun, no compared target was executed, and no remote state changed.
