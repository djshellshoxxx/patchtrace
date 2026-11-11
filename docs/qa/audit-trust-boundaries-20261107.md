# Trust-boundary audit, 2026-11-07

Base: `origin/main` at `652677b0` (PR #256 merge). Branch `audit/trust-boundaries-20261107`.

**Read this first.** This is an AI-assisted code review (Claude, one pass, source reading plus small synthetic probes). It is not an independent security audit and makes no completeness claim. Absence of a finding below means "nothing found in this pass", not "safe". No target binary or untrusted sample was executed or loaded; every hostile input is a few synthetic bytes built inside a test.

Line numbers refer to `origin/main` before the fixes.

## Findings

Severity is my own estimate of impact on a single-user desktop tool: Medium = needs a hostile local/shared-project file and gives a hang or loss of a policy guarantee; Low = narrow precondition or limited effect.

| id | sev | file:line | scenario (input -> wrong behaviour) | test | status | suggested fix / what was done |
|----|-----|-----------|--------------------------------------|------|--------|-------------------------------|
| TB-01 **(security)** | Low | `acquisition/quarantine.py:66,76` | In the shared temp dir another local user creates a symlink `patchtrace-acquire-x -> <victim-owned dir or file>` whose target mtime is over 24 h old. The next `create_staging()` sweep follows it (`stat`, `isdir`), `rmtree` refuses the link and the error hook `chmod`s the target (dir 0700, file 0600). Permission change on a path outside the staging tree. | `test_sweep_staging_ignores_symlinked_staging_names` | fixed | `lstat`/skip links in the sweep, refuse links in `remove_staging`, never chmod through a link in the hook |
| TB-07 **(security, availability)** | Medium | `persistence.py:361` | Opening a shared project folder whose `project.sqlite3` has `user_version=1` and `current_snapshot` defined as a VIEW over an unbounded recursive CTE. `ProjectStore()` succeeds, `load()` never returns (reproduced: still running after 8 s). Hang of whatever thread opens the project. | `test_project_database_with_view_or_trigger_is_refused` | fixed | refuse any view or trigger in `sqlite_master` at open (PatchTrace writes two plain tables) |
| TB-06 **(security, policy: strict JSON)** | Low | `ghidriff_launch/validate.py:52,63` | Launcher report is written by the process that also parsed hostile binaries. A 20,000-deep `[` report raised `RecursionError` (not a `ValueError`) out of `validate_run`; `{"mode":"off","mode":"local"}` was accepted (last key wins); `"setup_calls": true` counted as a positive call count. | `test_launcher_report_is_strict_json[deep-nesting/duplicate-key/bool-as-count/nan]` | fixed | use `persistence.strict_json`, require `type(calls) is int` |
| TB-03 **(security, GUI spoofing)** | Low | `hostile_text.py:8` | `U+2028`/`U+2029` (categories Zl/Zp) are not in the shared hostile rule, so a PE file name such as `good FAKE ROW` is stored by `display_text` and Qt draws a second line in a one-line label. | `test_line_and_paragraph_separators_are_hostile` | fixed | add Zl and Zp to `_HOSTILE`; `docs/specs/pe-overview.md` updated first. Shared rule: also affects `intelligence.tools.process.sanitize` and `pe_overview` (existing tests pass) |
| TB-02 | Low | `acquisition/transport.py:437` | Winbindex response header `Last-Modified: Fri, 31 Dec 9999 23:59:59 -0100`: `astimezone(UTC)` overflows the year range, `OverflowError` escapes `fetch_metadata` after the whole body was downloaded instead of the header being ignored. | `test_last_modified_out_of_range_is_ignored_not_raised` | fixed | catch `OverflowError`; same guard added in `_retry_after` |
| TB-04 | Low | `artifact_inspection.py:98-103` | If anything after opening the readers raises (for example `compare_overviews` on an odd overview), the two `VerifiedArtifactReader` handles are never closed because the caller never receives them. | `test_inspection_closes_readers_when_comparison_raises` | fixed | wrap the side loop and comparison, close readers on any exception |
| TB-05 | Low | `offline_bundle.py:212` | Manifest listing `python/python.exe` and `python/python.exe/child.txt` passes `inspect_offline_bundle` (the user is shown a valid plan) and only fails halfway through `install_offline_bundle`. Clean failure and cleanup, but late. | `test_manifest_file_and_directory_path_conflict_is_rejected_at_inspection` | fixed | reject a path that is also a directory prefix of another path in `validate_manifest` |

### Open items (reported, not changed)

| id | sev | file:line | scenario | suggested fix |
|----|-----|-----------|----------|---------------|
| TB-08 | Low | `acquisition/transport.py:70` | `_check(blob=True)` admits any host ending `.blob.core.windows.net`, i.e. any Azure storage account, as the redirect target. A compromised or spoofed symbol server could redirect to an attacker-owned account; the attacker learns the client IP and can drip a slow body, but the SHA-256 and size check against the Winbindex record rejects the content. No test: this is by design and needs a data decision. | pin the known Microsoft symbol shard host pattern if one can be confirmed from live traffic |
| TB-09 | Low | `jobs.py:242,328` | `terminate()` runs `os.killpg(child.pid, SIGKILL)` again in `finally` after the child was reaped by `wait()`. If the pid was recycled to a new process-group leader in that window, an unrelated group is killed. Needs pid wraparound inside milliseconds. | skip the second kill once `poll()` has returned and the group is known empty, or use a pidfd |
| TB-10 | Low | `offline_bundle.py:289-291` | `zipfile.ZipFile` builds every central-directory entry before the `MAX_MEMBERS` check, so a hostile archive with millions of tiny entries costs memory first. Bounded by archive size, which the user selected. | read the EOCD entry count before opening |
| TB-11 | Low | `artifact_inspection.py:98` | Authenticode probe is given the project path, not the verified handle, so a swap between `VerifiedArtifactReader` verification and `WinVerifyTrust` is not excluded. Needs write access to the project folder. | verify on a handle or re-hash after the probe |
| TB-12 | Info | `ingestion.py:19` (`safe_path`) | Rejects drive letters, ADS, backslashes, `..`, symlinks, but not Windows device names (`CON`, `NUL`) or trailing dot/space components. Today the persisted paths are hash-derived (`artifacts/<sha>.bin`) so only `AnalysisRun.raw_path` (a free string) could carry one, and only after the project snapshot is attacker-edited. Not testable on Linux. | reuse `offline_bundle._safe_relative` rules inside `safe_path` |
| TB-13 | Info | `acquisition/delta.py:97` | `ApplyDeltaB` parses an attacker-influenced PA30/PA31 delta inside the PatchTrace process (Windows only, hash verified afterwards, not before). `update_compression` DLL is loaded from a user-chosen path by design. | run in a contained child process |
| TB-14 | Info | `backend_bundle.py:276` | The "full verified" marker is keyed by manifest hash only, so it does not prove the files are unchanged today. The CLI wording ("recorded for this manifest") is accurate. | none needed; keep wording |
| TB-15 | Info | `jobs.py:149` | Windows environment block is built with `'\0'.join(f'{k}={v}')`; a value containing NUL would inject a variable. Values come from `os.environ` and configured paths, which cannot hold NUL on Windows. | reject NUL in keys and values |

## Areas reviewed with no findings

- `artifact_bytes.py`: open-handle hashing, per-block digests, stat-key checks, FIFO via `O_NONBLOCK`, range and size arithmetic, read cap, close races.
- `ingestion.py`: `validate_pe`, `_validate_pe_prefix`, `inspect_artifact`, `verify_artifact`. I fuzzed 4,000 synthetic PE header variants (offsets, section counts, optional header sizes, directory counts, raw sizes at 32-bit extremes); only `ValueError` came out.
- `persistence.py` `strict_json`: deep arrays/objects (200,000 levels), 5,000-digit ints, `1e99999`, `NaN`, duplicate and NFC-equivalent keys, lone surrogates. All rejected as `ValueError`. Save/load atomicity, reloadability check, lock handling, history prune with verified backup, `backup()` publication.
- `offline_bundle.py` / `backend_bundle.py`: member-name rules (reserved names, trailing dots, ADS, `..`, backslash, case/NFC collisions), symlink and special members, declared-size and ratio checks, per-member hash with size cap, re-hash before install, no-replace publication, lock behaviour, junction handling.
- `netutil.py`: cancellation hand-off, abandoned-thread cap, bounded reads. It contains no URL handling, so the SSRF-class questions apply to `acquisition/transport.py` instead.
- `acquisition/transport.py` and `contracts.py`: HTTPS-only, exact-URL consent, userinfo/port/control-character rejection, one redirect hop re-checked, proxy env ignored, default TLS verification kept, size and time caps, signed blob URL not stored or echoed, file-name rules (device names, extension list, lowercase basename).
- `acquisition/quarantine.py` other than TB-01: header-only identification, CRC streaming, read-only staged files, project promotion path.
- `jobs.py`: `shell=False`, absolute argv[0], new session and process-group kill, Windows suspended start plus job object, log and output caps, timeout and cancel. Only TB-09 and TB-15.
- `ghidriff_launch/ptlaunch.py`: argument parsing, refusal when the hook is missing, report written atomically.
- `diagnostics.redact_log` was only skimmed (it has its own redaction tests).

## Areas NOT reviewed (or only partly)

- `tools/check_windows_package.py` does not exist on `origin/main`. Closest files, `tools/check_windows_exe.py`, `tools/package_windows_installer.py` and the `.ps1` scripts, were not read.
- `tools/build_backend_bundle.py` and `tools/verify_backend_pins.py` (tar/zip extraction, `urlopen`): only the extraction code was skimmed; `download()` follows redirects and only checks the final URL scheme afterwards.
- `backend.py` (argv/env construction, raw JSON publish at line 675 uses plain `json.loads`), `raw_cleanup.py`, `service.py`, `verified_backup.py`, `normalization.py`, `unified/`, `secondary/`, `rules/`, `strings/`: outside the assigned scope. Only `_ghidriff_argv` was read for leading-dash and env injection; the staged input names are absolute paths, so none was found.
- Plain `json.loads` call sites outside scope that may deserve the same treatment as TB-06: `raw_cleanup.py:156`, `backend.py:341,609,675`, `unified/extract/runner.py:252,277,468`, `unified/pipeline.py:558`, `unified/sources/secondary.py:95`, `unified/sources/diaphora.py:105`.
- Windows-only code paths (`_windows_process`, `file_fingerprint` on NT, msdelta, junction handling) were read but not executed; the Linux sandbox cannot run them.
- `acquisition/winbindex.py`, `kbcorrelation/`, `kev/`, `intelligence/`, `report2` advisories: assigned to another reviewer.
- No dynamic analysis, no live network, no fuzzing beyond the PE-header and JSON probes above.
- Code that exists only on `integrate/swarm-wave3-20261105` (PR #235) was not audited.
