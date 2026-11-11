# BUNDLE runtime policy: symbol servers off, per-analysis bounds, isolated child environment

Status: approved for build (documents only). Date: 2026-10-15. Base commit: `54fd085`. Extends `docs/specs/program-e/BUNDLE-integration-plan.md` sections 6 and 7.6 and `docs/research/ghidra-headless-large-pe.md` sections 1, 2, 6. Game plan: `docs/plans/backend-bundle-finish-gameplan.md` step G13. Code: `src/patchtrace/backend.py` (`BackendConfig`, `_bundle_errors`, `_apply_bundle_env`, `build_child_env`, argv at the Ghidriff launch), `src/patchtrace/backend_bundle.py` (`bundle_backend_kwargs`, `check_work_dir`), `src/patchtrace/runtime_discovery.py` (`bundle_config`, `require_bundle_ok`), `tools/build_backend_bundle.py` (`RUNTIME_POLICY`, `write_runtime_policy`).

## 1. Purpose and non-goals

Purpose: one authoritative, hashed description of how the bundled engine may run: no symbol-server traffic unless the analyst consents per operation, a bounded analysis time and memory, and a child process that sees only an allowlisted environment and writes only to per-run scratch outside the install tree.
Non-goals: offline PDB use through a local symbol store (separate slice; needs a store location and `PDB Universal.PDB File`), per-function decompile timeouts (Ghidra owns them), sandboxing beyond the environment (OS network denial is the acceptance proof, not a runtime feature).

## 2. Definitions

- **Runtime policy file**: `backend/payload/config/runtime-policy.json`, written at build time, listed in `manifest.files[]` (hash-covered). VERIFIED content: `{"analysis_timeout_s": 7200, "ghidriff_args": ["--no-symbols"], "schema": "patchtrace-runtime-policy/1", "symbol_servers": "disabled", "timeout_enforced_by": "process"}`.
- **Bundle mode**: `BackendConfig.bundle = True`: argv `[python, '-I', '-X', 'utf8', '-m', 'ghidriff', ...]`, restricted allowlist environment forced, `JAVA_HOME_OVERRIDE` set, `PYTHONDONTWRITEBYTECODE=1`, scratch redirection.
- **Scratch**: `tempfile.mkdtemp('patchtrace-ghidra-')` per run; `projects`, `gzfs`, `ghidra-settings` below it; removed in `finally` (`_remove_scratch`).

## 3. Contract

### 3.1 Consistency defects found (VERIFIED)

1. The policy file is written but read by nothing in `src/` or `tools/` (grep for `runtime-policy`/`runtime_policy`).
2. `RUNTIME_POLICY.analysis_timeout_s` is 7,200 s while `BackendConfig.timeout_seconds` defaults to 3,600 s; the unified engine's `l04_analyze_timeout_s` is 7,200 (`src/patchtrace/unified/limits.py`).
3. `PYGHIDRA` has no in-process analysis timeout (research row 6): the process timeout is the only bound.

### 3.2 Policy semantics (this spec)

`schema` `patchtrace-runtime-policy/1`; keys: `ghidriff_args` (list of strings, closed vocabulary `["--no-symbols"]`), `symbol_servers` (`disabled` only), `analysis_timeout_s` (int 60 to 86,400), `timeout_enforced_by` (`process`). Unknown keys are ignored; an unknown *value* for a known key makes the policy unreadable. Loader: `load_runtime_policy(ref)` in `backend_bundle.py`: reads `payload/config/runtime-policy.json` (<= 16 KiB, strict JSON without duplicate keys), only after a passing fast check; returns defaults (`--no-symbols`, 7,200) and a warning if the file is absent in a legacy bundle; raises `BundleError('PT-BUNDLE-MANIFEST', ...)` if present but invalid.

Mapping: `bundle_backend_kwargs` adds `timeout_seconds = policy.analysis_timeout_s` as the default; a user setting may lower it; raising it above the policy needs the explicit setting `allow_longer_analysis = true` (not implemented today; until then the policy value is a ceiling). `allow_symbol_downloads` is `False` unless the analyst enables it for an operation after the exact preview required by `docs/specs/network-egress-privacy.md`; bundle mode never enables it by default (owner decision 10 of 2026-10-15: not on by default, explicit consent per operation).

### 3.3 Child environment (VERIFIED `build_child_env`)

Allowlist from `_POSIX_ENV` / `_WINDOWS_ENV` plus `LC_*`; `GHIDRA_INSTALL_DIR`; for a private JDK: `JAVA_HOME`, `PATH = <jdk>/bin + <allowlisted PATH>`, `JAVA_HOME_OVERRIDE`; `PYTHONIOENCODING=utf-8`, `PYTHONNOUSERSITE=1`; bundle: `PYTHONDONTWRITEBYTECODE=1`, and `XDG_CACHE_HOME`, `TEMP`, `TMP`, `TMPDIR` set to the scratch parent; `XDG_CONFIG_HOME` = `ghidra-settings` (Ghidra 12.0.4 reads its settings directory from `application.settingsdir` then `XDG_CONFIG_HOME` on every OS: `docs/qa.md`). Network proxy variables are kept only when symbol downloads are enabled for Ghidra. `_bundle_errors`: bundle mode requires a Java home and refuses a cache/temp path inside `<ghidra_dir>/../..` (`PT-BUNDLE-WORKDIR`).

## 4. Algorithms

```
analysis(config):
  if config.bundle: require_bundle_ok(config)            # fast check in a worker thread; PT-BUNDLE-* line on failure
  errors = _config_errors(config); refuse on any
  argv = [python, (-I -X utf8 if bundle), -m ghidriff, older, newer, --output-path raw, --project-location scratch/projects,
          --gzfs-path scratch/gzfs]
  if not config.allow_symbol_downloads: argv += ['--no-symbols']
  run_process(argv, cwd=ghidra_dir, env=_environment(config, scratch/ghidra-settings), timeout=config.timeout_seconds)
  reasons: cancelled -> PT-CANCEL ; timeout -> "PT-BACKEND: analysis timed out; increase the configured timeout and retry"
  scratch removed in finally; a leftover is reported as a warning event
```
Heap policy (research L-03): default 50 percent of RAM capped at 16 GiB; floor 4 GiB: below it fail fast with `PT-BACKEND: at least 4 GiB of free memory are required for Ghidra analysis`. Add `-XX:+CrashOnOutOfMemoryError` through the supported VM-args route; heap dumps (if ever enabled) must go inside the scratch.

Belt and braces for symbols: besides `--no-symbols` (which also disables `PDB Universal`), set `PDB Universal.Search untrusted symbol servers = false` explicitly in program options when the extractor script is used (`ghidra_script.py`), because ghidriff enables untrusted remote symbol servers and loads well-known URLs by default (research section 6). Offline PDB use is out of scope.

## 5. Error codes

`PT-BACKEND:` (config/runtime), `PT-BUNDLE-WORKDIR` (scratch inside the install tree), `PT-BUNDLE-MISSING/-MANIFEST/-EXTRA/-SIZE/-LINK` from the fast check (`runtime_discovery.require_bundle_ok`), `PT-CANCEL`. Sample: `PT-BUNDLE-WORKDIR: work, cache and temp paths must be outside the bundle install tree`.

## 6. Determinism

Policy and env construction are pure functions of config and `os.environ` snapshot (`build_child_env` takes `base` explicitly). Scratch names are random but never part of results.

## 7. Security invariants

1. Bundle mode cannot start with a work/cache/temp path inside `backend/`.
2. The install tree is never written to (acceptance proves equal tree digest on a read-only tree).
3. Symbol-server traffic requires an explicit, previewed, per-operation consent; the default and the policy say disabled.
4. The environment is an allowlist; inherited `PYTHONPATH`, `PYTHONHOME`, `JAVA_*`, `CLASSPATH`, proxies are not passed in bundle mode (except proxies under explicit symbol consent).
5. Credentials are session-only and never passed to the engine.
6. Child processes are contained and terminated on cancel/timeout (`run_process`).

## 8. Budgets

Fast bundle check <= 3 s for 60,000 entries on SSD (CI budget 10 s); full verification streamed at 1 MiB chunks, cancellable; analysis timeout 7,200 s ceiling (policy), 3,600 s current default; memory floor 4 GiB.

## 9. Test plan

Existing: `tests/test_backend_bundle_env.py` (env, `-I`, `JAVA_HOME_OVERRIDE`, scratch outside backend), `tests/test_build_backend_bundle.py::test_runtime_policy_disables_symbol_servers_and_bounds_each_analysis`, `tests/test_backend_bundle.py`, `tests/test_runtime_discovery_bundle.py`, `tests/test_ui_bundle_setup.py::test_run_is_blocked_by_a_failing_fast_check`.
To add: `test_bundle_kwargs_apply_the_policy_timeout`, `test_policy_with_unknown_symbol_servers_value_is_refused`, `test_missing_policy_in_a_legacy_bundle_uses_defaults_with_warning`, `test_bundle_argv_always_has_no_symbols_without_consent`, `test_policy_timeout_is_a_ceiling_without_the_allow_setting`, `test_heap_floor_message`, acceptance evidence `test_acceptance_records_ghidriff_argv_with_no_symbols`.

## 10. Open questions

1. Should the policy file be signed or only hash-covered? Default: hash-covered (the whole inventory is attacker-equivalent if the tree is writable; the read-only acceptance proves the app does not write).
2. 3,600 or 7,200 s default? Default: bundle policy 7,200; non-bundle default stays 3,600 until a measurement on a kernel image exists.
3. Local symbol store for offline PDB: separate slice and spec.

## 11. Acceptance

The app reads the policy; the acceptance JSON shows `--no-symbols` in the recorded argv, `no-external-connections` with `seen=[]`; changing the policy file breaks `backend verify` (`PT-BUNDLE-HASH`); the heap floor message is covered.
