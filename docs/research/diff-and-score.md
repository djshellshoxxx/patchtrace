# Diff and score workflow (L3, manual)

Workflow: `.github/workflows/diff-and-score.yml` (`workflow_dispatch` only). Orchestrator: `python -m tools.research_qualification.scorerun {plan,score}`. This produces **L3 evidence only** (real Windows binaries, function level). It says nothing about L1 or L2.

## Merge order (dependencies)

This branch contains merges of #265 (adapters) and #263 (parity) on top of #271 (winpairs). Merge #260, #265, #263, #271 first (in that order), then this PR. #260 supplies the default case manifest `docs/research/accuracy-cases/windows-candidates.json`, which does not exist on this branch.

## Flow

1. **plan**: downloads the `winpairs-manifest` artifact of a winpairs run (`pair_run_id`), runs `scorerun plan`, emits a matrix of found pairs. Only cases that are in the case manifest, layer L3, `facts: verified`, `status: found`, safe relative paths, and (when the case pins one) matching sha256 are diffed. Unverified or missing cases are never sent to the matrix; they are reported BLOCKED at scoring.
2. **diff** (one job per pair, `max-parallel: 3`, `fail-fast: false`): downloads `winpairs-binaries` (the whole artifact; it cannot be filtered per case), installs `ghidriff==<ghidriff_version>` (default 1.0.0, exists on PyPI), sets up Java (`actions/setup-java`, temurin), downloads Ghidra from an official `https://github.com/NationalSecurityAgency/ghidra/releases/download/...zip` URL and checks the sha256 you supply, then runs `ghidriff OLD NEW -o build/diff/<id> ...` under `timeout`. It writes `pt-run-status.json` (`rc`, `timed_out`) next to the report and uploads `ghidriff-report-<id>` even on failure.
3. **score** (`needs: [plan, diff]`, `if: always()`): downloads reports, runs `scorerun score`, appends a summary to `$GITHUB_STEP_SUMMARY`, uploads `diffscore-receipts` (a `rq-diffscore` receipt plus `scorerun-results.json`). The job exit code is the scorerun exit code, so a run with a FAIL or with nothing scored is red.

## Verdicts

| verdict | when |
|---|---|
| PASS | expected function in the top k of the adapter ranking, or a `no_change` case with no candidates |
| FAIL | expected function missing from the top k, or candidates listed for a `no_change` case |
| BLOCKED | never scored, never a miss: `unverified`, `layer_not_l3`, `missing_pair`, `sha_mismatch`, `missing_report`, `ambiguous_report`, `unparseable_report`, `timeout`, `tool_failed`, `bad_run_status` |

Holdout cases are aggregated separately from development cases (`development` and `holdout` blocks, own lower bound). The lower bound assumes the scored cases are independent (distinct projects), as in `scoring.py`. Exit codes of `scorerun score`: 0 scored with no FAIL, 1 at least one FAIL, 2 nothing scored or blocked/usage error (including a path outside the allowed roots; every file argument goes through `pathguard.confine`; results are never overwritten).

## Runtime: ghidriff can take hours

Large PE files (`ntoskrnl.exe`, `win32kfull.sys`) have been reported to run for hours or to time out; see PT-TIMEOUT-1..4 in `tasks/todo.md` and `docs/qa/ghidriff-timeout-20261106.md`. The slow-path hypothesis (PT-TIMEOUT-2) is **unverified**, and the separate per-function decompiler timeout (PT-TIMEOUT-3) is open. A longer timeout is not a performance fix. Here each pair gets `pair_timeout_minutes` (default 330) inside a 360-minute job limit (the GitHub-hosted maximum), so the report upload still runs. A timeout gives BLOCKED `timeout` for that case. Expect several pairs to be BLOCKED on a first run, and do not read BLOCKED as a result about the engine.

## Permissions and trust

`contents: read` plus `actions: read` (needed to download artifacts from another run; this is one permission beyond the brief). Only `actions/*` first-party actions are used. Nothing heavy is cached. Inputs go through `env`, never into shell text. Fetched binaries are never executed. Reports are treated as hostile data by the adapters. Microsoft binaries are not published by this workflow beyond 7-day workflow artifacts (winpairs) and 14-day report artifacts; the symbol-server terms question in `winpairs.md` still applies.

## Inputs to set before the first run

- `ghidra_url` and `ghidra_sha256`: **no default**. The zip file name and sha256 were not verified from here (the GitHub API and release asset pages were not reachable from this environment). A release page fetch reported Ghidra 12.1.4 with SHA-256 `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`, but the asset file name was not obtained and that reading is unconfirmed; copy both values from the official release page yourself. With either empty every pair is BLOCKED.
- `java_version` default 21 is an assumption about Ghidra 12.x, unverified.
- `ghidriff_version` 1.0.0: verified on PyPI (released 2025-07-04, requires pyghidra>=2.0.0). The flags used (`-o -p -n -s -g --log-path`) were checked in the 1.0.0 sdist argparse; the output file names the adapter expects (`*.ghidriff.json` or `*.md`) come from the adapter notes in `adapters.md`.

## UNVERIFIED

- The workflow has never run (it can only be dispatched once on the default branch). YAML parses with `yaml.safe_load`; `needs`/`if` references checked by eye.
- The Ghidra and ghidriff install steps are untested on a runner, including whether pyghidra finds the JDK and `GHIDRA_INSTALL_DIR`.
- Runtime per pair is unknown. Cross-run `download-artifact` with `run-id` and `github-token` is untested here. Whether `download-artifact` with a pattern that matches nothing succeeds is unverified (that step is `continue-on-error`).
- Disk and memory on `ubuntu-latest` for the largest binaries; `--max-ram-percent` is left at the ghidriff default.
- Receipt `tool.executable_sha256` is not recorded.

## Open gates

- Merge of #260, #265, #263, #271 (in that order), then this PR.
- Supply and check the Ghidra pin; pin or resolve the month-only candidate refs so pairs resolve.
- One real dispatch on one small pair before any multi-pair run.
