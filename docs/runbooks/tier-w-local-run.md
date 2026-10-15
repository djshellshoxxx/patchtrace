# Runbook: Tier W local run (owner machine only)

Tier W scores PatchTrace engines on real Windows binaries. Decision O1 (SPEC-33) keeps everything Microsoft-derived
local: binaries, PDBs, symbol maps, labels, review queues, engine outputs and reports never enter git, CI artifacts or
any upload. This runbook wraps the SPEC-33 s11 subcommands into one command.

## Prerequisites
- A short directory outside the repository, no dot-prefixed component, for example `D:\ptcal` (Windows) or `/srv/ptcal`.
  Ghidra rejects dotted project paths and Windows paths over about 180 characters.
- Python with the repository installed (`pip install -e .`) and, for the Ghidra run stage, a Python with `pyghidra`/`ghidriff`
  plus a Ghidra installation and Java (see the Windows backend notes in `docs/windows.md`).
- Network access to `winbindex.m417z.com` and `msdl.microsoft.com` for the catalogue, resolve and fetch stages only.
- The SPEC-33 s11 CLI (`python -m tools.calibration.tier_w`). If the checkout lacks it, `run_local` exits 3 (BLOCKED).

## One command
PowerShell:
```
$env:PATCHTRACE_CALIB_ROOT = 'D:\ptcal'
$env:PYTHONPATH = 'src'
python -m tools.calibration.tier_w.run_local --corpus-id tier-w-2026q4 `
  --consent-hosts winbindex.m417z.com,msdl.microsoft.com `
  --python C:\venvs\ghidra\Scripts\python.exe --ghidra-dir C:\tools\ghidra --timeout 3600
```
bash:
```
PATCHTRACE_CALIB_ROOT=/srv/ptcal PYTHONPATH=src python -m tools.calibration.tier_w.run_local --corpus-id tier-w-2026q4 \
  --consent-hosts winbindex.m417z.com,msdl.microsoft.com --python ~/venvs/ghidra/bin/python --ghidra-dir ~/ghidra
```
Stages run in order: `catalogue`, `resolve`, `pairs`, `fetch`, `symbols`, `labels`, `run`, `evaluate`, `status`, then
the repository guard (`python -m tools.calibration.corpus guard`). Options:
- `--dry-run` validates the environment and lists the stages without running anything.
- `--only run,evaluate` resumes from specific stages (runs resume per pair; completed runs are reused).
- Without `--consent-hosts` the network stages are skipped and say so; any host other than the two above is refused.
- To stop a long `symbols` or `run`, create `<root>/tier-w/CANCEL`.

## What it refuses
CI environments (`CI`, `GITHUB_ACTIONS`, ...), an unset `PATCHTRACE_CALIB_ROOT`, a root inside the git work tree, a dotted
or over-long root, an unknown stage or corpus id, and unknown consent hosts. Child processes get an allow-listed
environment (no tokens or API keys) plus the root.

## What it prints
Aggregate numbers only: per-stage status and exit code, counts, precision/recall and their intervals per condition.
It drops anything that could identify Microsoft data (file names, pair ids, hashes, paths, KB numbers, lineages, tags,
symbol or function names, free-text reasons). Full stage output is written to
`<root>/tier-w/run-local/<corpus-id>/<stage>.log` and a summary to `<root>/tier-w/reports/<corpus-id>.run-local.json`.
Both stay on this machine. Read the reports there; do not paste them into issues, PRs or chat.

## Exit codes
0 ok, 1 partial failure or guard findings, 2 configuration, consent or input error, 3 BLOCKED (tool, network or CLI
missing), 5 cancelled. Report a non-zero exit with the aggregate output only. A BLOCKED or failed stage is never
evidence of a passing result.

## After the run
1. Confirm the last line says nothing was uploaded and the `guard` stage is `ok`.
2. `git status` must show no new files. If it does, delete them and report the aggregate output only.
3. Record only aggregate numbers (for example, the precision/recall line) in `docs/qa.md`. Do not commit the report files.

## What only the owner's machine can verify
Winbindex and msdl access and rate behaviour, real Microsoft PE/PDB parsing, Ghidra time per family, the symbol-label
error rate, circularity of the export stratum, and the `pyghidra` driver on Windows (SPEC-33 s13).
