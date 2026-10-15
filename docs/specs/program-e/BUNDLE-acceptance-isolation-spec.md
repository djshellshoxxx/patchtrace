# BUNDLE acceptance: isolation, network denial, read-only tree and evidence

Status: approved for build (documents only). Date: 2026-10-15. Base commit: `54fd085`. Extends `docs/specs/program-e/BUNDLE-integration-plan.md` sections 5, 6, 10.2, 10.3 and `docs/specs/program-e/BUNDLE-release-checklist.md` section 3. Game plan: `docs/plans/backend-bundle-finish-gameplan.md` steps G3, G4, G5, G13. Code: `tools/bundle_acceptance.py`, workflow jobs `accept-windows-no-network-readonly` and `accept-linux-no-network-readonly (ubuntu-22.04|ubuntu-24.04)` in `.github/workflows/backend-bundle.yml`.

## 1. Purpose and non-goals

Purpose: prove, on the release artifact (not the build tree), that the bundle analyses a known pair with a scrubbed environment, with the install tree read-only and unchanged, with the network demonstrably denied and no external connection made. The proof must fail loudly when the denial itself is not proven.
Non-goals: proof of absence of all side channels, malware sandboxing, GUI testing (owner matrix M01 to M18), Windows SmartScreen behaviour.

## 2. Definitions

- **Release artifact**: the extracted `PatchTrace-<ver>-windows-x64-full.zip` or `...-linux-x86_64-full.tar.gz`; root = the folder holding the launcher and `backend/`.
- **Hostile path**: a directory name with a space and a non-ASCII character, `UNICODE_DIRNAME = 'Patch Trace é中'`, under `RUNNER_TEMP` (Windows) or `/tmp/pt-accept` (Linux). `path_is_hostile` requires both properties.
- **Positive control**: a TCP connect probe run by the bundle's own Python (`python -I -c`, target `1.1.1.1:443`, 5 s timeout inside, 30 s outer) that must **succeed before** the block and **fail after** it. `control_verdict`: `invalid-no-baseline` (never connected), `denial-ineffective` (connected after), `proven`.
- **Tree digest**: `tree_digest(backend)` = SHA-256 over sorted `relpath\0kind\n` rows, kind `D`, `L:<target>` or `F:<size>:<sha256>` for every entry.
- **Scrubbed environment** (`scrub_env`): only `PATH`, `TEMP`, `TMP`, `TMPDIR` plus `USERPROFILE`, `SystemRoot`, `LOCALAPPDATA` (Windows) or `HOME`, `LANG=C.UTF-8`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME` (Linux). `FORBIDDEN_ENV` (JAVA_HOME, GHIDRA_INSTALL_DIR, PYTHONHOME, PYTHONPATH, CLASSPATH, proxies, ...) and prefixes `PYTHON`, `JAVA`, `GHIDRA`, `PIP_` must be absent; PATH is `/nonexistent` (Linux) or `%SystemRoot%\System32;%SystemRoot%` (Windows) and must reveal no `java`, `javaw`, `python`, `python3`, `pythonw`.

## 3. Contract: step order and evidence

`run_acceptance` appends steps to `Evidence` (`patchtrace-bundle-acceptance/1`, JSON with `schema`, `os`, `root`, `ok`, `dry_run`, `wording`, `steps[]` of `{name, ok, detail, data}`); `ok` is true only if every step passed. Steps in order (VERIFIED in code): `layout` (manifest, python and launcher exist), `path-shape`, `env-scrub`, `path-has-no-java-python`, `digest-before`, `control-before`, `control-after` (aborts the run unless `proven`), `readonly-effective` (Linux), `backend-verify-full` (`<launcher> backend verify --full --json`), `backend-selftest` (`<launcher> backend selftest --older A --newer B --expect-function read_item --json`), `ghidriff-compare` (the bundle's python runs `-I -X utf8 -m ghidriff ... --no-symbols` and must produce a `*.ghidriff.json`), `no-external-connections` (sampled every 0.5 s, `ConnectionMonitor`), `digest-after-equal`.

**Wording rule** (`Evidence.wording`): the phrase "passed with OS network block (positive control proven)" is emitted only if `ok` and the `control-after` step passed; dry runs say "dry run with fake bundle: harness logic only, not release evidence". No document may say "air-gapped" or "verified offline" without a linked run whose JSON carries that wording.

**Additions defined by this spec** (additive): steps `exec-before-readonly`, `exec-after-readonly` (the bundle's `python -I -c "print(1)"` under the scrubbed environment must succeed before and after the lock), `readonly-effective` on Windows, `harness-exception` (traceback text); `main` writes `--evidence` in a `finally` so a crash still produces the file; every sub-process step records its command line (without secrets) and duration.

## 4. Algorithms

### 4.1 Linux denial

`linux_denial_argv(argv, env, uid, gid, sudo)` builds `sudo -n unshare --net -- sh -c 'ip link set lo up >/dev/null 2>&1 || true; exec "$@"' sh setpriv --reuid U --regid G --clear-groups env -i K=V... argv...`. The namespace is created by root, then the program runs as an unprivileged identity (workflow passes uid/gid 65534) so the tree is genuinely not writable (`readonly-effective`: a write probe as that identity must fail). Absolute paths of host tools are resolved before the environment is scrubbed (`_which`). Unprivileged `unshare -rn` is not used (AppArmor on 24.04 may refuse it: UNVERIFIED); the root-created namespace is expected to work on both images (UNVERIFIED until G3). Connection evidence: `/proc/<pid>/net/tcp{,6}` of the child, skipping samples taken while the child still shares the host network namespace (`linux_sampler`, race guard), ESTABLISHED non-loopback only (`parse_proc_net_tcp`).

### 4.2 Windows denial and read-only tree

Network: one outbound `New-NetFirewallRule -Direction Outbound -Action Block -Program <abs path>` per program that exists: `PatchTrace*.exe`, `backend\payload\python\python.exe`, `jdk\bin\java.exe`, `javaw.exe`, Ghidra `Decompiler\os\*\decompile.exe` (`windows_programs`); rule names `PatchTraceAccept-<sha256(program)[:10]>`; removed in `finally`. A blanket block is not used because it would cut the runner's log stream. Loopback exemption is UNVERIFIED; `no-external-connections` samples `Get-NetTCPConnection -State Established` for the child pid and filters `127.0.0.1`, `::1`.
Read-only tree (**defect found in run 38676664372, job 116261209710**): the current command `icacls <backend> /deny <USER>:(OI)(CI)(W,D,DC)` is followed by `PermissionError: [WinError 5] Access is denied` when the harness starts the bundled `python.exe` (VERIFIED log). `W` is `FILE_GENERIC_WRITE`, which includes `SYNCHRONIZE` and `READ_CONTROL`; HYPOTHESIS: denying `SYNCHRONIZE` on every inherited file makes `CreateProcess` fail to open the image. Corrected command:

```
icacls "<backend>" /deny "<account>:(OI)(CI)(WD,AD,WEA,WA,DE,DC)"
   WD write data/add file, AD append/add subdirectory, WEA write extended attributes, WA write attributes, DE delete, DC delete child
   (no SYNCHRONIZE, READ_CONTROL, RA, REA, RD, X)
cleanup: icacls "<backend>" /remove:d "<account>" /T
```
Alternative if the deny model keeps misbehaving: grant-only read-only, `icacls <backend> /inheritance:r /grant:r "<account>:(OI)(CI)(RX)" "*S-1-5-18:(OI)(CI)(F)"` then restore from `icacls /save` output; use only if the first form fails on a runner, because it removes inherited ACEs (more invasive).
Before relying on it, run both exec probes (3 above); if `exec-after-readonly` fails the harness must report that step, not crash.

### 4.3 Artifact reuse for iteration

New workflow input `reuse_run_id` (number, default empty): build jobs are skipped; the acceptance job uses `actions/download-artifact@v4` with `run-id: ${{ inputs.reuse_run_id }}`, `github-token`, and `permissions: actions: read`. The id is passed only through `env:` and matched against `^[0-9]{1,20}$`. Artifacts expire after 7 days (`retention-days: 7`): run 38676664372's `bundle-windows-assets` (id 11950241206, `expires_at 2026-10-22T05:18:33Z`) is available at the time of writing (VERIFIED `expired:false`).

## 5. Error behaviour and exit codes

`ba.main` returns 0 only when `ok`; 1 when any step failed; 2 on a bad `--control` target (`parse_target`). Step details are truncated to 400 characters; the evidence file is the source of truth.

## 6. Determinism

The positive control depends on the runner network and on `1.1.1.1:443` being reachable; `--control HOST:PORT` can name another target. Timeouts: step timeout 3600 s, workflow job 60 min. The tree digest ignores mtime. Ghidra output file names are sorted before reporting. Expected duration (VERIFIED for the Windows run before the crash): extraction and icacls about 15 s; the Ghidriff step is the long one (UNVERIFIED, minutes for the small fixture).

## 7. Security invariants

1. The program under test never receives host secrets: the child environment is constructed, not inherited.
2. The harness never executes the target binaries `old.dll/new.dll/old.so/new.so` (they are compiled in the job and only parsed by Ghidra).
3. The positive control is never weakened or skipped to make a run pass.
4. Firewall rules and ACL denies are removed in `finally`.
5. The release evidence is produced from the release artifact extracted to a hostile path, not from the build directory.
6. Workflow inputs reach shell only through `env:`.

## 8. Budgets

Acceptance job < 20 minutes expected, 60 minutes hard; evidence JSON < 100 KB; connection sampling interval 0.5 s.

## 9. Test plan

Existing (VERIFIED names, `tests/test_bundle_acceptance_unit.py`): scrub/violations, PATH hits, tree digest sensitivity, read-only round trip, `control_verdict`, probe against a loopback listener, `linux_denial_argv_shape`, `windows_firewall_commands_*`, `parse_proc_net_tcp*`, `ConnectionMonitor`, `evidence_wording_requires_proven_control`, `dry_run_with_fake_bundle_proves_denial_and_equal_digest`, `dry_run_fails_when_control_has_no_baseline`, `dry_run_detects_launcher_mutating_the_tree`.
To add: `test_windows_readonly_command_denies_only_write_and_delete_rights` (no `W,` generic token, no `SYNCHRONIZE`), `test_readonly_removal_runs_in_finally`, `test_run_acceptance_records_harness_exception_and_still_writes_evidence`, `test_exec_probe_runs_before_and_after_the_lock`, `test_reuse_run_id_is_numeric_and_env_only` (in `tests/test_backend_bundle_workflow.py`), `test_firewall_command_failure_is_a_step_not_a_crash`.

## 10. Open questions

1. Is the GitHub Windows runner's Defender Firewall enabled and does it block loopback? UNVERIFIED; the sampler filters loopback regardless.
2. Which control host is best (stable, allowed by the runner's egress policy)? Default `1.1.1.1:443`; change if `invalid-no-baseline` appears.
3. Should Linux acceptance also run under `docker run --network none` as a second proof? Default: no.

## 11. Acceptance

For each OS one run whose evidence JSON has `ok: true`, `wording` "passed with OS network block (positive control proven)", `digest-before == digest-after`, `ghidriff-compare` with a result file, `no-external-connections` with at least 3 polls and `seen=[]`; the run URL is in `docs/qa.md` BUNDLE-3/BUNDLE-4.
