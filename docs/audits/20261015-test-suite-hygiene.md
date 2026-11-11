# Test suite hygiene audit (tests/ and tools/ non-bundle scripts)

Date: 2026-10-15. Audited base: `origin/main` at `21a005e` (fast-forwarded; already up to date at start).
Method: read-only static audit. No file under `src/`, no existing test and no tool was edited. Scan scripts live in the session scratchpad, not in the repository. pytest is not installed in this environment, so the suite was not collected or run. Parametrize ids and runtime behaviour are therefore inferred from source, not measured.

## Findings

| id | severity | finding | evidence (file:line) | suggested fix |
|---|---|---|---|---|
| TST-1 | Medium | Tests that run against a faked transport assert the probe's own label `mocked: False`, so the suite certifies mocked runs as non-mocked live evidence. The label is hard-coded in the probes. | `tests/test_live_kev_probe.py:143`, `:396` (`Net` fake installed at `:54-56`); `tests/test_live_nvd_probe.py:78` (fake via `_serve`, `:42-53`); `tools/live_kev_probe.py:278`, `tools/live_nvd_probe.py:195` hard-code `'mocked': False`. Files named `test_live_*` but documented as mocked: `test_live_harness.py`, `test_live_rzdiff_check.py`. | Derive `mocked` from the transport actually used (or pass it in), and assert `mocked is True` in fake-transport tests. Rename the mocked modules to `test_probe_*` so "live" means real acceptance. |
| TST-2 | Medium | `record_live_status` always writes `'mocked': False`. The fake-BinDiff run asserts `probe: passed` and is still recorded as non-mocked. A default unit-suite run also overwrites `build/live-status/*.json` inside the repo tree, clobbering any status left by a real live run. | `tests/conftest.py:17` (default dir `ROOT/build/live-status`), `:32` (hard-coded `mocked`); `tests/test_live_bindiff.py:230-242` writes on every plain run; `tests/tier_r_helpers.py:31`; `tests/test_live_harness.py:98-105` (fake exe, probe `passed`). | Make the status directory default to a temp location unless `PATCHTRACE_LIVE_STATUS_DIR` is set, or have CI only. Add a `mocked` parameter to the helper and set it from fakes. |
| TST-3 | Medium | Negative or liveness checks pass vacuously when the child or grandchild never starts: the "stopped growing" and "marker absent" checks compare 0 with 0. The stronger pattern is in `test_secondary_scheduler.py:140`, which asserts the grandchild started first. | `tests/test_bindiff_run.py:200-206` (size is 0 if `beat` never appears, then `0 == 0`); `tests/test_jobs.py:609-613` (`_stops_growing`, used at `:630`); `tests/test_rules_worker.py:262-263` and `:273-274`; `tests/test_binexport_isolation.py:204-205`. | Assert the beat or marker exists before the negative check, as `test_secondary_scheduler.py:140` does. |
| TST-4 | Medium | Fixed sleeps stand in for synchronisation. Under 23 shared workers these are timing-dependent and can fail or pass for the wrong reason. Within test bodies: 32 direct `time.sleep` calls (73 including child-process source strings). | `tests/test_jobs.py:610` (`sleep(1.0)` "child starts within this window"), `:612`, `:639`, `:654`; `tests/test_rules_worker.py:262`, `:273`; `tests/test_binexport_isolation.py:204`; `tests/test_bindiff_run.py:205`; `tests/test_secondary_scheduler.py:142`. | Replace with deadline polling on an event or marker (as `test_bindiff_run.py:200-203` and `test_cancel_latency.py:51-56` already do). |
| TST-5 | Medium | Timing upper bounds with no documented slack, or with an absolute budget the 15.6 ms Windows clock and shared CI cannot hold reliably. | `tests/test_unified_read_model.py:822` (`< 0.05` for 1050 `cell_text` calls); `tests/test_cli_registry.py:271` (`<= 0.125`, documented as 5x slack); `tests/test_cancel_latency.py:48`, `:82`, `:123` (`< 0.5`); `tests/test_nvd_pacing.py:106` (`< 0.5`); `tests/test_codetext_tokens.py:400` (`< 0.5`); `tests/test_pe_manifest.py:300` (`<= 0.5`). Good counter-example: `tests/test_codetext_tokens.py:556` (best of 5). | Use best-of-N as in `test_codetext_tokens.py:556`, or multiply the budget to at least 5x and document it. |
| TST-6 | Medium | Windows CRLF risk. The sha256 pins in `manifest.json` cover text fixtures under `tests/fixtures/intel_tools/**` (31 json and txt files on disk), but `.gitattributes` only pins `eol=lf` for `secondary/`, `pilot/`, `binexport/`. On a Windows checkout with autocrlf, the bytes change and the pin fails. Not verified on the Windows CI run. | `tests/test_intel_tools_parsers.py:53`; `tests/fixtures/intel_tools/manifest.json`; `.gitattributes` (no `intel_tools` line). | Add `tests/fixtures/intel_tools/** text eol=lf` to `.gitattributes`. This file is integrator-owned, so the line goes to the integrator. |
| TST-7 | Medium | 15 of 16 real `xfail(strict=True)` markers have no `raises=`. Any exception (ImportError, typo, AttributeError) then counts as the expected failure, and the feature being absent is not distinguished from breakage. `PIL_B2` does it right. | `tests/test_codex_pkg_packaging.py:44`, `:51`, `:62`, `:70`, `:85`, `:97`, `:104` (7 markers); `tests/test_codex_pkg_workflows.py:78`, `:90`, `:98`, `:106`, `:115`, `:124`, `:133`, `:141` (8 markers); good example `tests/pilot_synergy_support.py:52` (`raises=EngineMissing`). | Add `raises=<the expected error>` to each marker, as `PIL_B2` does. |
| TST-8 | Medium | Text IO without an explicit encoding or newline. On Windows the default codec is not UTF-8 and `write_text` emits CRLF. Most calls write ASCII and are benign, but hashed or non-ASCII content is at risk. | 154 `read_text`/`write_text` calls without `encoding=`; 231 `write_text` calls without `newline=` (for example `tests/test_audit_ai_reports.py:57`, `tests/test_bindiff_probe.py:109`, `tests/test_audit_runtime.py:37`). Good counter-example: `tests/test_unified_mutations.py:120` passes `encoding='utf-8', newline='\n'`. | Enable ruff `PLW1514` (unspecified-encoding) for `tests/` and `tools/`, and pass `encoding='utf-8', newline='\n'` where content is compared. |
| TST-9 | Low | `.hypothesis/` is not ignored. 59 modules use Hypothesis, so each run leaves an untracked directory at the repo root. Confirmed with `git check-ignore`, which matches only `build/`. | `.gitignore` (no `.hypothesis` entry); `pyproject.toml` (no hypothesis profile). Good counter-example: `tests/test_gui_core_lint.py:31` sets `database=None`. | Add `.hypothesis/` to `.gitignore`, or set `database=None` in a shared profile in `conftest.py`. |
| TST-10 | Low | Duplicated tests. Six structurally identical test-body groups, and 59 test-function names repeated across modules, often with the same body. | `tests/test_fabric_schemas.py:50`/`:103`/`:141` vs `tests/test_rules_contracts.py:72`/`:106`/`:126`; `tests/test_fabric_contracts.py:298` vs `tests/test_pilot_keys.py:438`; `tests/test_fabric_origins.py:72` vs `tests/test_pilot_keys.py:415`; `tests/test_codetext_palette.py:58` vs `tests/test_gui_core_theme_math.py:50`; `test_default_sleep_is_cancellable` at `tests/test_acquisition_transport.py:176` and `tests/test_enrichment_intelligence.py:291`. | Move shared contract checks to one support helper and delete the copies. |
| TST-11 | Low | Process-wide state leaks at import time. 67 `sys.path.insert` calls, 10 `sys.modules[...] =` assignments of which 8 are never restored, and 12 module-level `os.environ.setdefault('QT_QPA_PLATFORM', ...)` calls. | `tests/test_calibration_math.py:13` (path); `tests/test_acceptance_smoke.py:25`, `tests/test_release_gate.py:24`, `tests/test_backend_pin.py:20`, `tests/test_verify_backend_pins.py:24` (modules not restored); `tests/test_alpha_integration.py:7`. The `network_guard.py` globals (`:77`, `:87`, `:176`) are deliberate and lock-protected. | Move path setup to `conftest.py`, use `monkeypatch.setitem(sys.modules, ...)`, and set the Qt platform once in `conftest.py`. |
| TST-12 | Low | `assert all(...)` is vacuously true on an empty iterable. It is the only assertion in 17 test functions. | 260 `assert all(` lines overall; sole-assertion examples `tests/test_codex_pkg_packaging.py:67` (iterates a `literal_eval`'d list), `tests/test_calibration_math.py:94`, `tests/test_evalcore_stats.py:98`, `tests/test_jobs.py:175`. | Add a precondition (`assert names`, or `len(...) >= n`) before the `all`. |
| TST-13 | Low | Parametrize ids. 78 use dynamic `ids=` expressions and 23 rely on auto-ids from long string parameters (longest 147 characters at `tests/test_binexport_isolation.py:133`). Real nodeids are not measured here, because pytest is not installed. The 32767 limit applies to the whole nodeid, so this is a readability risk, not a confirmed Windows failure. | dynamic: `tests/test_fabric_ids.py:312`, `tests/test_codetext_marks.py:1179`, `tests/test_cli_registry.py:182`; auto-id: `tests/test_binexport_isolation.py:133`, `tests/test_bindiff_run.py:294` (93 chars), `tests/test_intel_lexicon.py:72` (84 chars). | Give long-string cases short explicit ids. Run `pytest --collect-only -q` on Windows once and record the longest nodeid. |
| TST-14 | Low | Tests with no explicit assertion, and tests whose only check is "does not raise" or "returns". Most of the 21 flagged by the scanner rely on an implicit check (`check=True`, `qtbot.waitSignal`, `waitUntil`, Hypothesis properties, or a helper that asserts). Two are real weak cases. | `tests/test_acquisition_transport.py:176` (no assertion and no timeout, so a regression hangs rather than fails); `tests/test_audit2_fixes.py:275` (only "does not raise"). | Add a timing or outcome assertion; bound the blocking call with a timeout. |
| TST-15 | Low | POSIX-only fixtures written without a skip. The shell scripts are created but only exercised as a stale-executable check, so the behaviour is probably platform-neutral. The symlink and FIFO tests are all guarded. | `tests/test_intel_tools_runner.py:215` (`#!/bin/sh` script, no `skipif`, stale check should refuse before execution); `tests/test_verify_backend_pins.py:48`, `:101` (hash only). Guarded and therefore OK: `tests/test_core.py:401`, `tests/test_binexport_pipeline.py:71`, `tests/test_enrichment_cache.py:350`, `:369`, `:387`. | Add a comment or `skipif(os.name == 'nt')` where the test relies on `sh` execution. |
| TST-16 | Low | Wall-clock dependence in tests. `datetime.now(UTC)` is used in three test modules. The date-sensitive checks could flip near midnight or on a date boundary. | `tests/test_acquisition_transport.py:296`, `tests/test_enrichment_retention.py:158`, `tests/test_intel_storage.py:124`. | Inject a fixed clock, as `test_kev_cli.py` does. |

Severity: Medium = flaky or vacuous on Windows or under load, or evidence mislabelled. Low = hygiene.

## Pattern counts (AST scanner over `tests/**/*.py` and non-bundle `tools/**/*.py`)

| pattern | raw hits | verdict |
|---|---|---|
| `time.sleep` (direct calls in test source) | 32 (73 by grep, incl. child-process strings) | real, see TST-4 |
| `qWait` | 0 | none |
| timing upper bound (`<`/`<=` on elapsed/perf/monotonic) | 60 | mostly real bounds; tight ones in TST-5 |
| timing `==` | 21 | false positives (matched "budget" or "duration" in non-timing code) |
| `pytest.skip` / `skip` / `xfail` without reason | 0 | none; xfail issue is TST-7 |
| `assert all(...)` | 260 | 17 sole-assertion functions, TST-12 |
| `assert True`, `or True`, empty-literal `for` loops | 0 | none |
| `len(...) >= 0` | 2 | false positives (guarded by `len > 0` elsewhere) |
| no-assertion test functions | 21 | 2 real (TST-14), rest implicit |
| `while True` | 8 | 4 in `tests/` (data-bounded, or encoder helpers that terminate on value); 4 in `tools/`, not individually reviewed; no finding |
| text IO without encoding | 154 | TST-8 |
| `write_text` without newline | 231 | TST-8 |
| POSIX-only APIs | 11 | all guarded or wrapped in try/skip |
| symlink/FIFO/chmod in tests | 11 | guarded (see TST-15) |
| network calls (direct) | 13 | all in `test_network_consent_guard.py` under the guard, or intended provisioning tools |
| `sys.path.insert` | 67 | TST-11 |
| `sys.modules[...] =` | 10 | TST-11 |
| `os.environ` mutation at import | 12 | TST-11 |
| `global` statements | 3 | `network_guard.py`, deliberate |
| `setattr` | 6 | 4 on fixture/dataclass records, 1 `modules[...]` (`test_unified_ghidra_script.py:938`), 1 `test_kev_transport.py:410` (clock fake); no finding |
| writes with target not obviously tmp | 960 | heuristic, dominated by `tmp_path`-derived names; refined check found no repo-tree write except the `build/` status files (TST-2) and `.hypothesis/` (TST-9) |
| `datetime.now` / `today` | 7 | TST-16 |
| unseeded random | 0 real | `test_gui_core_lint.py:219` uses Hypothesis `st.randoms`, seeded |
| uuid | 2 | identifiers only, no finding |
| parametrize dynamic ids | 78 | TST-13 (unmeasured) |
| parametrize auto ids > 40 chars | 23 | TST-13 |
| structural duplicate test bodies | 6 groups | TST-10 |
| duplicate test names across modules | 59 | TST-10 |
| identical test files | 0 | none |
| CRLF literals `\r\n` in tests | 66 lines | scanned, mostly intended |
| fixture digests on text files | 1 module (`test_intel_tools_parsers.py:53`) | TST-6 |

## Worst 10 examples

1. `tests/test_live_kev_probe.py:143` asserts `mocked is False` while the whole transport is monkeypatched (`:54-56`). (TST-1)
2. `tests/test_live_harness.py:105` asserts a fake BinDiff gives `probe: passed` in a status file labelled `mocked: False`. (TST-1, TST-2)
3. `tests/conftest.py:17` and `:32`: default status directory is `ROOT/build/live-status`, and `mocked` is hard-coded to `False`. (TST-2)
4. `tests/test_bindiff_run.py:200-206`: `size == 0` on both sides passes when the heartbeat never appears. (TST-3)
5. `tests/test_jobs.py:609-613` and `:630`: `_stops_growing` returns True when the child never ran. (TST-3)
6. `tests/test_rules_worker.py:262-263`: `sleep(3.5)` then `assert not marker.exists()`, with no proof that the grandchild started. (TST-3, TST-4)
7. `tests/test_intel_tools_parsers.py:53`: sha256 pins over text fixtures not covered by `.gitattributes` `eol=lf`. (TST-6)
8. `tests/test_unified_read_model.py:822`: `< 0.05` s on 1050 `cell_text` calls, with no slack. (TST-5)
9. `tests/test_codex_pkg_packaging.py:62-63` (and `tests/test_codex_pkg_workflows.py:78`): `xfail(strict=True)` with no `raises=`. (TST-7)
10. `tests/test_jobs.py:610`: `time.sleep(1.0)` assumes a surviving child starts and writes within one second. (TST-4)

## What I scanned

- All 418 files under `tests/` (including helpers such as `conftest.py`, `fake_*.py`, `*_support.py`, and `tests/fixtures/**/generate.py`), parsed with `ast`.
- 124 non-bundle `tools/**/*.py` files. Excluded: `build_*.py`, anything with `bundle` in its path, and `tools/pyinstaller_hooks/`.
- Patterns: sleeps and `qWait`; timing asserts; skip and xfail markers; `assert all`, `assert True`, `or True`, `len >= 0`; test functions with no assertion or helper check; `while True`; text IO without encoding or newline; POSIX-only APIs and shell literals; `sys.path`, `sys.modules`, `os.environ`, `global`, `setattr`, warnings and logging config; wall-clock and unseeded randomness; parametrize ids; structural and name duplicates; identical files; writes that reference `ROOT`, `__file__` or `REPO`; network calls and the presence of `network_guard`.
- Manual reads of the highest-risk hits (about 25 locations), the `record_live_status` helper and its callers, `.gitattributes`, `.gitignore`, and `git check-ignore` for `.hypothesis` and `build/`.
- Scanner caveat: the AST segment helper silently returns an empty string for some non-ASCII lines. Pattern counts that rely on source text may be a little low. Segment-based counts were rechecked after fixing the line-splitting bug.

## Not scanned

- Runtime behaviour: nothing was executed. No pytest collection, so the real nodeids, real skip and xfail counts, and duplicate-nodeid detection are unmeasured.
- Windows and Linux CI logs, and the `qa-windows.yml` results, which would confirm or refute TST-5, TST-6 and TST-8.
- The contents of `tests/fixtures/**` beyond the sha-pinned files, and the Ghidra, BinDiff and rizin fixtures.
- Hypothesis example coverage and runtime of property tests.
- `tests/test_backend_bundle*.py` and other bundle-only tests (excluded as bundle scope).
- `tools/` scripts for correctness; only hygiene patterns were checked (sleeps, network, writes, globals).
- `tests/test_tooltips.py` and other frozen shared files, read only for the hygiene patterns above.
