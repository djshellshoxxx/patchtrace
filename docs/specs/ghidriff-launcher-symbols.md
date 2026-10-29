# PatchTrace-owned Ghidriff launcher and symbol policy (SPEC-53)

Status: partial (SPEC-53), written 2026-10-14. Built 2026-10-21: GHR-1 (`symbols/modes.py`, `pdbid.py`, `staging.py`, `project.py`), GHR-2 (`ghidriff_launch/ptlaunch.py`, `validate.py`), GHR-3 (`backend.py` `symbol_mode`/`symbol_pdb_dirs`, launcher argv, handshake validation, cache key, run settings; `reports.py` safe keys; `RuntimeFingerprint.eligible()` rejects `local` without a 64-hex digest) and the CLI part of GHR-4 (`series create --run --symbols off|local|online --symbol-dir --consent-online-symbols`, exit 2 `PT-SYMBOL-NETWORK-REFUSED`/`PT-SYMBOL-MODE`). Runs in `off` mode keep their legacy settings byte for byte (the symbol keys are recorded for `local` and `online` only). Setup now has a three-radio mode group and a `QListWidget` folder list with directory chooser, remove action, accessible names, and a visible empty-list explanation. The existing keys `backend/symbol_mode` and `backend/symbol_dirs` remain stable; the legacy `allow_symbol_downloads` key migrates to `off|online` when no explicit mode is stored. Profiles now accept `symbol_policy=local`; this adds a distinct analysis-profile digest while preserving existing `disabled` and `online` digests, and named profiles can only narrow the Setup symbol mode. Remaining work: `backend diagnose` launcher revision lines, GHR-5 native air-gap matrix, GHR-6 PDB fetch. Evidence so far is hermetic only (fake `ghidriff` package); nothing here shows that real Ghidriff 4f5d895 or Ghidra 12.0.4 honours an empty server list. Closes the open item "Local-only symbol policy: needs PatchTrace-owned Ghidriff launcher (CLI cannot set empty symbol URLs)" (`tasks/todo.md`). Touches `src/patchtrace/backend.py` (`run_comparison`, `BackendConfig`, `_environment`), `enrichment/cache.py` (`RuntimeFingerprint`), `reports.py` (`SAFE_SETTING_KEYS`), `ui.py` Setup. Existing profile digests for `disabled` and `online` and the `allow_symbol_downloads` migration key are preserved; `local` is additive.

Source-access note: `learn.microsoft.com` and other Microsoft hosts were blocked from the sandbox on 2026-10-14; facts about Microsoft symbol services are `[unverified]`. Ghidriff source was read from the pinned commit through raw file fetches (retrieved 2026-10-14). A fetch tool summarized the files; function bodies not quoted in full below are paraphrased and must be re-read in the build slice.

## 1. Verdict and scope

Build: a small PatchTrace-authored launcher script that runs inside the external Ghidriff Python environment, forces the Ghidra symbol-server list to **empty** when the analyst has not consented to online lookups, and reports what it did. Introduce three explicit symbol modes: `off` (default, today's `--no-symbols`), `local` (symbols enabled, no servers, PDBs only from a PatchTrace-built per-run store), `online` (today's behaviour: Ghidra contacts servers, consent text required). Remote PDB fetching, when wanted, is a **separate PatchTrace step** with its own consent and URL preview (SPEC-08 transport), so Ghidra and Java never need network access in any default flow and an OS-level air gap can be asserted by tests.

Not built: copying or vendoring Ghidriff code (GPL-3.0; reference only); patching the user's Ghidriff install; managing Ghidra's global preferences; telemetry; automatic PDB download at analysis time; support for Ghidriff revisions other than the pinned one without an explicit "untested" label.

## 2. Sources and facts

| claim | source | retrieved | confidence |
|---|---|---|---|
| Pinned Ghidriff is commit `4f5d895fcbb1eacd65efd81145922c15bb7e741d` of clearbluejar/ghidriff; Ghidra 12.0.4 PUBLIC (zip digest pinned in CI); pyghidra `>=3.0.0,<4` | `docs/windows.md`, `.github/workflows/live-backend.yml`, `docs/research.md` (this repo) | 2026-10-14 | high |
| Ghidriff licence is GPL-3.0 (full GPLv3 text, 29 June 2007); whether "only" or "or later" is not stated in the LICENSE file | https://raw.githubusercontent.com/clearbluejar/ghidriff/4f5d895fcbb1eacd65efd81145922c15bb7e741d/LICENSE | 2026-10-14 | high (GPL-3.0), SPDX suffix [unverified] |
| CLI options: `-p/--project-location`, `-n/--project-name`, `-s/--symbols-path` (default `symbols`), `-g/--gzfs-path`, `--no-symbols` (`store_true`); there is **no CLI option for symbol server URLs** | https://raw.githubusercontent.com/clearbluejar/ghidriff/4f5d895fcbb1eacd65efd81145922c15bb7e741d/ghidriff/ghidra_diff_engine.py (`add_ghidra_args_to_parser`) | 2026-10-14 | high |
| `GhidraDiffEngine.setup_project(self, binary_paths, project_location, project_name, symbols_path, gzfs_path=None, symbol_urls: list = None) -> list`; `symbol_urls` is passed to `setup_symbol_server(self, symbols_path, level=0, server_urls=None)` | same file | 2026-10-14 | high |
| `setup_symbol_server`: when `server_urls is None` it loads well-known servers from `.pdburl` files in the Ghidra application; otherwise it requires a `list`; builds `SymbolServerService(localSymbolStore, sym_servers)` and saves it with `PdbPlugin.saveSymbolServerServiceConfig` (global Ghidra preference) | same file (paraphrased) | 2026-10-14 | medium (body summarized by the fetch tool) |
| Under `no_symbols` the engine skips `setup_symbol_server`, then calls `get_pdb(program, allow_remote=False)` and raises `FileExistsError` ("Symbols are disabled, but the symbol is already downloaded") if a PDB is found locally; `analyze_program` sets analyzer option "PDB Universal" to False | same file | 2026-10-14 | high |
| With symbols enabled, `get_pdb(prog, allow_remote=True)` uses `FindOption.ALLOW_UNTRUSTED` (or `ALLOW_REMOTE` on older Ghidra) and `PdbUniversalAnalyzer.setAllowRemoteOption(program, True)` is set | same file | 2026-10-14 | high |
| `ghidriff/__main__.py` has a `main()` that builds the parser, resolves paths, instantiates the engine and calls `setup_project`; call site of `setup_project` is in `__main__`, not in the engine file | https://raw.githubusercontent.com/clearbluejar/ghidriff/4f5d895fcbb1eacd65efd81145922c15bb7e741d/ghidriff/__main__.py | 2026-10-14 | medium (summarized) |
| Ghidra 12.0.4 reads user settings from `application.settingsdir`, then `XDG_CONFIG_HOME` on every OS; a persisted symbol store made plain Ghidriff fail under `--no-symbols`; per-run `XDG_CONFIG_HOME` fixes it | `docs/qa.md` line 40 (PR #9, native Windows CI matrix) | 2026-10-14 | high |
| Local symbol store layout level 1: `<store>/<name>/<GUID><age>/<name>`; reproduced by `tools/seed_symbol_cache.py` | `tools/seed_symbol_cache.py` (this repo) | 2026-10-14 | high |
| `RuntimeFingerprint` already carries `symbol_policy` and `symbol_input_digest`; the backend sets `'none'` for the digest today | `src/patchtrace/enrichment/cache.py`, `backend.py` `_open_raw_cache` | 2026-10-14 | high |
| Microsoft public symbol server serves PDBs at `https://msdl.microsoft.com/download/symbols/<name>/<GUID><age>/<name>` and may require a Microsoft-Symbol-Server user agent; files may be compressed (`.pd_`) | learn.microsoft.com symbols documentation | not retrievable | [unverified: MS host blocked] |
| Ghidriff `--jvm-args` and `--max-ram-percent` exist; leading-dash values use the equals form | `docs/research.md` (inspected README) | 2026-10-14 | medium |

## 3. Standalone baseline versus PatchTrace value

Standalone Ghidriff: `--no-symbols` or "symbols on, servers from `.pdburl` files", store in a global Ghidra preference, no record of what was contacted, and a local-store hazard (`FileExistsError`).

PatchTrace adds: (1) a third mode, **local symbols without any server**, which the upstream CLI cannot express; (2) per-run isolation of Ghidra settings and symbol store (no cross-run leakage, OneDrive-safe scratch); (3) the PDB identity (GUID/age from the already-parsed CodeView record, SPEC-26 D) decides which PDBs are staged, and their hashes enter the raw-cache key, so a run with different PDBs never reuses another run's result; (4) provenance: every run records mode, servers contacted (list, normally empty), staged PDB hashes and launcher version, and RPT2 exports them; (5) a verified air-gap test matrix so "offline by default" is evidenced rather than asserted.

Workflows: analyst has the vendor PDB for both builds (or fetched them earlier through SPEC-08 consent) and runs `local` mode: symbol names appear in function lists, nothing leaves the machine; analyst without PDBs stays in `off`; `online` remains available with an explicit consent dialog.

## 4. Cross-feature links

| Anchor | Direction | Counterpart | Use |
|---|---|---|---|
| build fact CodeView GUID/age/PDB name | consume | SPEC-26 D (`CodeViewInfo`) | Select and key the PDBs to stage |
| function names with symbol provenance (`symbol_source: pdb-local | none`) | emit | unified engine, BinDiff/BinExport (names come from the same staged PDBs), label corpus | Names derived from PDBs are labelled as such; label training must not treat PDB-named functions as unlabelled ground truth |
| run provenance `symbol_mode`, `symbol_servers`, `symbol_input_digest`, `launcher_version` | emit | RPT2, enrichment cache, diagnostics | Reproducibility and consent record |
| acquisition (PDB fetch step) | consume | SPEC-08 transport, consent dialog pattern | Only network path for PDBs in `local` flows |

## 5. Synergy test

Fixture: the committed compiled bounds-check DLL pair used by the native matrix (`tests/fixtures`, built with `/Zi /DEBUG /INCREMENTAL:NO`, self-made, not Microsoft) with its two PDBs. Scenario `local-mode-names`: `off` run yields address-only names for the changed function (`FUN_...`); `local` run with staged PDBs yields the source name and the same changed-function set; a decoy PDB with a different GUID is **not** staged (identity gate), and the raw-cache key differs between the two runs while a repeat `local` run is a cache hit. In the `local` run an outbound-block rule (firewall or network namespace) is active and the run still passes, and the launcher report lists `servers: []`. The combination (CodeView identity + staging + cache key + enforced no-network) is the claim; plain Ghidriff with `--no-symbols` cannot produce names, and plain Ghidriff with symbols enabled would contact `.pdburl` servers. Tests: `test_local_mode_stages_only_matching_guid`, `test_local_mode_cache_key_includes_symbol_digest`, live `air_gap_local_mode_names` (CI-only).

## 6. Traps and guards

| Trap | Guard |
|---|---|
| Launcher silently falls back to online | The launcher never catches its own patch failure: missing hook means exit code 78 and message `PT-SYMBOL-LAUNCHER-INCOMPATIBLE`; backend treats any unexpected launcher handshake as a failed run |
| Upstream change moves the hook (`GhidraDiffEngine.setup_symbol_server`) | Compatibility table keyed by Ghidriff revision; only the pinned revision is "tested"; any other gets an explicit "untested combination" status in `diagnose()`; `local` mode refuses unknown revisions, `off` still works (it needs no hook) |
| `--no-symbols` plus a local PDB raises `FileExistsError` | In `off` mode the launcher is not used; per-run `XDG_CONFIG_HOME` and a per-run empty store (existing). In `local` mode the PDBs are intentionally present |
| Copying GPL code into an MIT project | Launcher is original, calls two public methods by name, 40 lines; it is data shipped with PatchTrace and executed by the user's own interpreter; it is never combined into the PatchTrace binary. Owner/legal confirmation of this reading is an open question (section 11) |
| Java-side network (Ghidra PDB plugin) not covered by a Python guard | Empty server list is the primary control (no server to contact); OS firewall rules in the verification matrix are the evidence; a Python audit hook (`sys.addaudithook` on `socket.connect`) is defence in depth for the Python half only and is documented as such |
| Microsoft PDBs committed or exported | PDBs live in the PatchTrace cache outside the project; never copied into `exports/`; reports carry hashes and names only |
| Persisted global Ghidra symbol config reused | Always per-run `XDG_CONFIG_HOME`; launcher refuses to run if `XDG_CONFIG_HOME` is unset in `local` or `off` mode |
| Path trouble: dot-prefixed directory, Windows path over 240, OneDrive scratch | Existing `_validated_ghidra_output_path`, scratch via `tempfile.mkdtemp(prefix='patchtrace-ghidra-')`; the launcher and the staged store live under the same scratch root |
| Overstating "air-gapped" | Wording: "Ghidra was configured with no symbol servers"; "air-gapped" only appears next to a recorded OS-level test result |

## 7. Contracts

### 7.1 Modes and mapping

| `symbol_mode` | Ghidriff args | Launcher | Servers | Notes |
|---|---|---|---|---|
| `off` (default) | `--no-symbols` | not used | none | Identical to today; `allow_symbol_downloads=False` maps here; raw cache `symbol_policy='disabled'` |
| `local` | none (symbols on), `-s <scratch>/symbols` | used with server list `[]` | none | New; raw cache `symbol_policy='local'`, `symbol_input_digest=<sha256 of sorted (pdb_name, guid_age, pdb_sha256)>` |
| `online` | none | not used (today's path) or used with `--pt-allow-servers` | `.pdburl` well-known | `allow_symbol_downloads=True` maps here; consent text required in GUI and CLI |

`RuntimeFingerprint.symbol_policy` gains the additive value `local`. Today `RuntimeFingerprint.eligible()` (`enrichment/cache.py`, read 2026-10-14) rejects only `online` ("output is not a function of the key") and admits everything else; `local` stays eligible because its output is a function of the key once `symbol_input_digest` carries the staged PDB hashes, while `online` stays uncacheable. `_open_raw_cache` in `backend.py` currently derives `symbols = 'disabled'` unless `allow_symbol_downloads` is not False, so it must be changed to read `symbol_mode`; add a test that an empty digest with `local` is ineligible.

### 7.2 Launcher contract (`src/patchtrace/ghidriff_launch/ptlaunch.py`, data file, stdlib plus ghidriff only)

Invocation (argv list, `shell=False`, absolute paths): `<python> <scratch>/ptlaunch.py --pt-mode off|local|online --pt-report <path> -- <ghidriff arguments>`. Behaviour: parse own flags; import `ghidriff.ghidra_diff_engine`; in `local` mode wrap `GhidraDiffEngine.setup_symbol_server` so it always passes `server_urls=[]`; count wrapper invocations; delegate to the upstream entry point; on exit write the report JSON `{ "contract": "ptlaunch/1", "mode", "ghidriff_version", "server_urls_forced_empty": bool, "setup_calls": int, "pdbs_staged": [name], "python": version }`; print one line `PT-LAUNCHER/1 mode=<mode> servers=0` before delegating. Backend validates the line and the report; a mismatch (mode differs, `setup_calls == 0` in `local` mode, or report missing) turns a completed run into `failed` with `PT-SYMBOL-LAUNCHER-MISMATCH` and quarantines output. Exit codes: 0 pass-through of upstream, 78 incompatible hook, 64 bad launcher arguments.

### 7.3 Models and config (additive)

- `BackendConfig.symbol_mode: str = ''` (empty derives from `allow_symbol_downloads`), `symbol_pdb_dirs: tuple[str, ...] = ()` (absolute directories searched read-only for PDBs by CodeView name), validated in `_config_errors` (absolute, existing directories, count at most 16).
- `StagedSymbol(pdb_name, guid_age, sha256, size, side)`; staging copies (never moves) into `<scratch>/symbols/<name>/<GUID><age>/<name>`; a PDB whose identity does not match the side's CodeView record is skipped and listed under `skipped` with reason `guid_mismatch | age_mismatch | too_large | unreadable`.
- Run `settings` additive keys: `symbol_mode`, `symbol_servers` (list, empty unless `online`), `symbol_input_digest`, `launcher_version`, `staged_symbols` (names and hashes only). Add them to `reports.SAFE_SETTING_KEYS` with validators (mode in the closed set; digest 64 hex).
- Limits: PDB at most 512 MiB each, 64 staged per run, stage copy chunked at 1 MiB with cancellation; launcher report at most 64 KiB; handshake line at most 512 bytes.
- Error codes: `PT-SYMBOL-MODE` (invalid mode or unknown combination), `PT-SYMBOL-LAUNCHER-INCOMPATIBLE`, `PT-SYMBOL-LAUNCHER-MISMATCH`, `PT-SYMBOL-PDB-INVALID`, `PT-SYMBOL-NETWORK-REFUSED` (an `online` request without recorded consent).
- Cache key: raw key inputs unchanged plus `symbol_policy` and `symbol_input_digest` (fields already exist). Changing mode never reuses another mode's raw output.
- Versioning: `ptlaunch/1` contract string; launcher version equals the PatchTrace version; backend refuses a launcher file whose embedded contract differs.

### 7.4 Consent record (online)

`{ "mode": "online", "consented_at", "hosts_declared": ["msdl.microsoft.com"], "ghidra_version", "ghidriff_revision", "scope": "this analysis" }`. Never persisted as a default; the existing Setup checkbox remains a saved preference but the first run per project after enabling shows the dialog.

## 8. CLI and GUI

CLI: existing analysis command gains `--symbols off|local|online`, repeatable `--symbol-dir <path>`, and `--consent-online-symbols` (required with `online`; otherwise exit 2, `PT-SYMBOL-NETWORK-REFUSED`). Envelope `enrichment-cli/1` unchanged; exit codes 0/2/3/4/5; launcher mismatch is exit 3. `patchtrace doctor`-style diagnostics lines (in `backend.diagnose`): `Symbols: off (no lookups)`, `Symbols: local (no servers; N PDBs staged)`, `Symbols: online (Ghidra may contact Microsoft; consent recorded)`, and `Launcher: tested with ghidriff 4f5d895 / untested revision <x>`.

GUI (Setup dialog and the Profiles tab, no new window): replace the single checkbox by a `QButtonGroup` of three radio buttons "Off (recommended): no symbol lookups", "Local PDB folders only: no network", "Online: Ghidra may contact the Microsoft symbol server", plus a `QListWidget` of PDB folders with Add/Remove (Add uses a directory chooser; bounded list of 16). The Profiles tab `symbol_policy` combo adds `local` after `disabled`. Saved settings key `backend/symbol_mode` (new) with a migration read: if absent, map `backend/allow_symbol_downloads` (False to `off`, True to `online`) without rewriting the old key. Accessible names: `setup.symbols.off`, `setup.symbols.local`, `setup.symbols.online`, `setup.symbols.dirs`; tooltip ids with the same stems. Copy: online consent dialog text "Ghidra will contact the symbol servers configured in your Ghidra installation (normally Microsoft's public server) and may send the names and identifiers of the files being analysed. Nothing else from your project is sent. Continue?"; empty local list "No PDB folders chosen. Local mode will analyse without symbol names."; staged summary after a run "Symbols used: 2 of 2 PDBs matched (hashes recorded)." Blocked state: `local` selected while the launcher check fails: "Local symbol mode is unavailable for this Ghidriff revision (untested). Use Off or choose the tested revision." Tests offscreen with `QT_QPA_PLATFORM=offscreen`; radio logic is a pure view-model (`symbol_policy_vm.py`) tested without Qt; 20x repeat.

## 9. Slice plan

| Slice | Scope | Exclusive files | Depends | Tier | Size | Gate | Fallback |
|---|---|---|---|---|---|---|---|
| GHR-1 | Pure module: mode resolution, PDB identity match and staging plan, digest | `src/patchtrace/symbols/__init__.py`, `modes.py`, `staging.py`, `tests/test_symbols_staging.py` | none (uses `CodeViewInfo`) | sonnet | S | guid/age match, path traversal and symlink refusal in staging tests, digest stable | none |
| GHR-2 | Launcher script and handshake validator | `src/patchtrace/ghidriff_launch/ptlaunch.py`, `validate.py`, `tests/test_ptlaunch.py` with a fake `ghidriff` module on `sys.path` | GHR-1 | sonnet | S | tests: hook wrapped, report written, incompatible hook gives exit 78, never falls back | `off` only |
| GHR-3 | Backend integration | `backend.py` (sole owner during this slice), `reports.py` allowlist lines, `enrichment/cache.py` (`eligible()`: reject `local` with an empty digest) | GHR-1, GHR-2 | sonnet; opus only after two failed attempts on subprocess/Windows behaviour | M | existing backend tests unchanged and green; new tests with a fake launcher child; scratch cleanup | slice stops at `off` + report fields |
| GHR-4 | CLI flags, Setup radios, Profiles value, tooltips | `cli.py` symbol flags (owner of that hunk), `symbol_policy_vm.py`, `ui.py` Setup block (serialized via integration owner), tests | GHR-3 | sonnet | M | offscreen tests, settings migration test | CLI only |
| GHR-5 | Native verification matrix | `.github/workflows/live-backend.yml` variants, `tools/live_backend_check.py` additions | GHR-3 | sonnet | M | see section 10; lands alone in its own PR (workflow changes can block publishing, see WIN policy) | manual run record |
| GHR-6 (optional) | PatchTrace-owned PDB fetch with consent and URL preview | `src/patchtrace/symbols/fetch.py` on the acquisition transport | GHR-1, SPEC-08 | sonnet | M | fake-server tests; host allow-list; no live Microsoft test in CI | skip |

## 10. Amendments, test and QA plan

Amendments: `docs/specs/architecture.md` `run_comparison` paragraph: add symbol modes and launcher; `docs/windows.md` symbol sentence: three modes, `off` default; `docs/qa.md`: replace the "Verify Windows real fixture under default `--no-symbols` and optional online-symbol mode" todo with the matrix below; `tasks/todo.md` line 17: link to this spec; `docs/specs/windows-acceptance-and-milestone-builds.md` A11 and a new A13 (air-gap local mode); `docs/specs/secondary-engine.md`/`bindiff-execution.md`: note that BinExport/BinDiff runs read PDB names from the same staged store only if the unified engine adopts it (cross-reference, no change now); `docs/modules.md`: new packages `symbols/`, `ghidriff_launch/`. Registry is not touched (program-e excluded).

Test and QA plan: (1) hermetic unit tests above with a fake `ghidriff` package; (2) air-gap verification matrix, CI-only:

| Variant | OS | Setup | Pass |
|---|---|---|---|
| `off-airgap` | Linux (network namespace `unshare -rn`) and Windows (outbound firewall block rule for `python.exe` and `java.exe`) | `--symbols off` | run completes, same JSON as before |
| `local-airgap` | same | `--symbols local` with matching PDBs | run completes, symbol names present, launcher report `servers: []` |
| `local-decoy-pdb` | same | wrong-GUID PDB only | PDB skipped, names absent, run completes |
| `online-blocked` | same | `--symbols online --consent-online-symbols` with the block rule | run fails or analysis degrades with a clear message; documents the failure mode |
| `launcher-incompatible` | Linux | fake ghidriff lacking the hook | exit 3, `PT-SYMBOL-LAUNCHER-INCOMPATIBLE`, no output published |

Windows pitfalls: CRLF in the launcher (pin LF in `.gitattributes` because it is executed by Python from a copied path), 32767-character test-id limit, quoting of paths with spaces in subprocess argv (always list form), OneDrive scratch avoided. The clfs.sys pair of the owner and Ghidra 12.1.4 remain untested and stay listed as blocked external acceptance. Evidence wording rule: an air-gap row may say "passed with OS network block" only with the CI run link.

## 11. Open questions (defaults, none blocking)

1. Does running a PatchTrace-authored MIT script that imports GPL-3.0 Ghidriff in the user's environment raise licensing concerns for the shipped data file? Default: ship, keep it original and tiny, ask the owner for a legal read before the first release that includes it.
2. Upstream `__main__.main` import path stability across revisions. Default: tested only for the pin; fall back to `python -m ghidriff` re-exec if `main` is not importable, still through the wrapper.
3. Should `local` also use PDBs found next to the binary? Default no: only analyst-chosen folders, because adjacent files are untrusted input and Ghidra would use them silently.
4. Fetch step (GHR-6) now or later? Default later; analysts can place PDBs manually.
5. Treat `symbol_policy: online` profiles saved earlier as needing re-consent? Default yes, once per project.
