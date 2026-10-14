# Audit C: acquisition/ and GUI layer (2026-10-14)

Read-only audit of `src/patchtrace/acquisition/*` (contracts, winbindex, transport, quarantine, delta) and the GUI
layer (`ui.py` AcquisitionDialog, `ui_evidence.py`, `ui_engine_setup.py`, `tooltips.py`). No `src/` file was modified.
Baseline: worktree at the branch head on 2026-10-14. Specs read: AGENTS.md, docs/modules.md, SPEC-08, SPEC-04.

Tooling note: the sandbox had no pytest/PySide6/libEGL, so a scratch venv (outside the repo) was used. With
`QT_QPA_PLATFORM=offscreen`, `tests/test_acquisition_*.py`, `test_ui_acquisition.py`, `test_tooltips.py`,
`test_ui_engine_setup.py` and `test_evidence_ui.py` pass (155 passed, 1 skipped; the first run showed 4
`test_ui_engine_setup` real-C3 failures only because `protobuf` was not installed in the scratch venv, which is a declared
dependency). Three consecutive runs of `test_ui_engine_setup + test_ui_acquisition + test_tooltips` were green (57 passed,
about 35 s each). Reproduction scripts lived in the scratchpad and are described inline; none touched the repo.

## Summary

| Severity | Count | IDs |
|---|---|---|
| High | 2 | C-01, C-02 |
| Medium | 5 | C-03, C-04, C-05, C-06, C-07 |
| Low | 12 | C-08 to C-19 |
| Informational / verified OK | 10 | section 4 |

Top three: C-01 (cancel, close and the total-download deadline are defeated by a slow server, trapping the dialog),
C-02 (the download consent box overflows the screen for "candidates" builds, so Yes is unreachable by mouse),
C-03 (AcquisitionDialog controls have no accessible names; the shared audit helper cannot catch it).

## 1. Findings: acquisition/

### C-01 High: cancellation, close and `DOWNLOAD_DEADLINE` do not work against a slow-drip response

- Where: `transport.py:181-204` (`_read`), specifically `response.read(min(_CHUNK, ...))` at line 193 with
  `_CHUNK = 1 MiB` (line 42); `urllib_open` timeout is per socket operation (line 99-101). Consequence in
  `ui.py:452-472` (`cancel`, `reject`, `closeEvent`).
- Scenario: `http.client` `read(1 MiB)` blocks until 1 MiB has arrived or EOF. A server (or a bad captive portal / throttled
  link) that sends one byte every 3 s never trips the 10 s socket timeout, so the loop never returns to the
  `_cancelled()` / `deadline` checks at lines 189-191. The 3600 s deadline and the Cancel button are both ineffective. In the
  GUI, `reject()`/`closeEvent` set `_close_requested`, call `cancel()` and `event.ignore()`, so the dialog cannot be closed
  and the status shows "Cancelling - waiting for the current request to stop" indefinitely; the user must kill the process.
  Even on an honest slow link (100 KB/s) Cancel latency is about 10 s per MiB-chunk. The same loop serves the Winbindex
  metadata fetch (`METADATA_DEADLINE`, line 224).
- Reproduction (ran): local `http.server` sending `Content-Length: 2000000` and 1 byte every 3 s, wrapped by
  `Transport.opener` that rewrites the msdl URL to the local server through the real `urllib_open`;
  `cancel.set()` at t=2 s. Result: `cancel set at 2.0s; returned: STILL BLOCKED after 25.0s`.
- Suggested fix: read in small chunks (for example 16-64 KiB) via `read1`, and/or bound each read with a monotonic
  deadline using a socket timeout shortened to the remaining time, and have `Cancel` close the underlying response from
  the GUI thread so the blocked read raises. Add a regression test with a real socket (the fake-opener tests cannot see this).

### C-06 Medium: non-`AcquisitionError` escapes `Transport._open`/redirect handling and can echo the signed URL

- Where: `transport.py:299-302` (`urljoin` then `_check(target, blob=True)` then `self._open('GET', target)`), `_open` at
  169-175 only maps `TimeoutError`/`OSError`; `urllib_open` (96-108) maps only `HTTPError`/`URLError`.
- Scenario: `_check` uses `urlsplit`, which strips tab/CR/LF but accepts a literal space. A redirect Location such as
  `https://x.blob.core.windows.net/a b` passes the allowlist and `http.client` then raises `InvalidURL` (a `ValueError`),
  which bypasses every `except AcquisitionError`. In the GUI the raw message becomes the status text and log; the message
  contains the request path including the query, that is, the SAS token the design promises never to keep (SPEC-08 §4.4,
  contracts.py:147). In the CLI `cmd_acquire` (`cli.py` `except AcquisitionError`) does not catch it.
- Reproduction (ran): `LEAKED non-AcquisitionError: http.client InvalidURL URL can't contain control characters. '/a b'
  (found at least ' ')`. Requires a misbehaving or in-path server, hence Medium rather than High.
- Suggested fix: validate the redirect target with a strict regex (no whitespace/control characters) and wrap
  `ValueError`/`http.client.HTTPException` in `urllib_open` as `ConnectionError('invalid URL')` without echoing the URL.

### C-11 Low: `promote` leaves a published project when the staged file no longer matches (TOCTOU)

- Where: `quarantine.py:287-293`. Staged files are `chmod 0400` (line 270) but sit in a user-writable directory, and
  nothing re-hashes the file between `acquire` and `ProjectService.create`.
- Scenario: another process of the same user replaces `older/<name>` after verification. `ProjectService.create` copies the
  replaced file; the post-copy check at line 292 detects the mismatch and raises `PT-ACQ-VERIFY`, but the project directory
  (with the foreign binary, `project.sqlite3`, lock file) remains. A CLI retry then fails with "project directory already
  contains a project" (`cli.py` fetch pre-check). This contradicts SPEC-04 "New ... failure leaves no published project".
- Reproduction (ran): tampered staged file, then `promote` printed
  `promote -> PT-ACQ-VERIFY project copy does not match the acquired file` and
  `project dir left behind: True ['.patchtrace.lock', 'artifacts', 'project.sqlite3']`.
- Suggested fix: re-hash the staged file immediately before `create`, and on mismatch remove the created root.

### C-12 Low: file-name validation admits Windows device names and an empty stem (unverified on Windows)

- Where: `contracts.py:22,39-45`. `[a-z0-9._-]{1,128}` plus extension allows `con.dll`, `nul.sys`, `aux.exe`, `com1.dll`,
  `lpt1.sys` and `.dll`. `quarantine.acquire` then does `Path(staging)/side/<name>` and `os.replace` (lines 266-269).
- Scenario (not run, needs Windows): on Win32 path normalisation `con.dll` still names the console device. A user typing
  `nul.sys` in the dialog (the GUI accepts it, `ui.py:491`) could make `os.replace`/`chmod`/`open` act on a device or fail
  with an untyped `OSError`. Winbindex has no such files, so the failure is a confusing error only; acceptable to fix cheaply.
- Suggested fix: reject the DOS device-name set (case-insensitive, stem before first dot) and an empty stem in
  `validate_file_name`; Windows CI test with `con.dll`.

### C-13 Low: `acquire()` raises untyped `FileExistsError` and `delta` has small robustness gaps

- `quarantine.py:266` `side_dir.mkdir(..., exist_ok=False)`: reusing a staging directory, or a retry after a partial failure
  in the same staging, raises `FileExistsError` (not `AcquisitionError`), so the CLI/GUI error mapping falls through.
- `delta.py:97` uses `ctypes.GetLastError()` on a `WinDLL` created without `use_last_error=True`; the value can be stale
  by the time Python reads it. `delta.apply_raw` has no input or output size cap and holds base, delta and result in memory;
  msdelta cannot be cancelled. The module is not called by CLI or GUI, so there is no current exposure.

### C-14 Low: consent object is built from the same list it checks, and the download GET is not named in the consent text

- Where: `ui.py:641,643`; `cli.py` lines around `AcquisitionConsent.for_urls(probes)` and `for_urls(d.url ...)`;
  `ui.py:621` ("the one probed URL that answers 302").
- Scenario: `Transport._consented` is meant to prove the user agreed to an exact URL, but each caller constructs the consent
  object itself from the URLs it is about to request, so the check is a tautology and does not bind to the text the user
  accepted. Separately, SPEC-08 §5 asks for the consent text to list URLs, yet the GET URL is only chosen after
  consent (it is one of the listed HEAD URLs, so the user-visible risk is small). Not a bypass today; a refactor hazard.
- Suggested fix: build `AcquisitionConsent` from the exact strings rendered in the consent box (pass the same list), and
  log the resolved GET URL before it is requested.

## 2. Findings: GUI layer

### C-02 High: download consent dialog is unusable when a build needs SizeOfImage probing

- Where: `ui.py:406-412` (`download_consent_text`), `ui.py:614-621` (up to 256 HEAD lines per candidate build, so up to 512
  lines plus GET lines), shown through `confirm()` (`ui.py:391-398`) as a `QMessageBox`.
- Scenario: for any `download == 'candidates'` build with more than a few dozen probes, the message box grows past the
  screen. The Yes/No buttons are off-screen; the default is No (good), so only keyboard users can accept (Alt+Y) and mouse
  users cannot proceed. The box has no scroll area, so the user also cannot read the full exact-URL list that consent is
  supposed to show.
- Reproduction (ran, offscreen 800x800 screen): 512 lines of consent text produced a QMessageBox 400 x 15552 px with the Yes
  button's bottom edge at global y = 15542; zero `QScrollArea` children. Existing tests replace `confirm()` entirely
  (`tests/test_ui_acquisition.py:68-74`), so this path has no coverage.
- Suggested fix: use a small custom `QDialog` with a read-only `QPlainTextEdit` for the URL list and fixed Yes/No buttons
  (set an accessible name), and add a test that the buttons lie inside the screen geometry with 512 URLs.

### C-03 Medium: AcquisitionDialog controls have no accessible names; the shared audit cannot detect it

- Where: `ui.py:318-320` (`name` line edit; its "File name" `PlainLabel` at line 322 is not a buddy), `326` (`table`),
  `347-355` (`root`: the form label's buddy is the wrapper `QWidget`, not the `QLineEdit`), `361` (`progress`), `368`
  (`log`). `apply_tooltip` (`tooltips.py:1072-1091`) sets `accessibleDescription` only.
- Scenario: a screen-reader user lands on an unlabeled edit/table/log. SPEC-04 requires accessible labels.
- Reproduction (ran, `QAccessible.queryAccessibleInterface(...).text(Name)`): `name=''`, `table=''`, `root=''`, `log=''`,
  `progress=''`; `project_name='Project name'` and the buttons are fine. A wider sweep of focusable widgets with an empty
  accessible name found 4 in AcquisitionDialog (`acquire.name`, `acquire.table`, `acquire.root`, `acquire.log`), 3 in
  NewProjectDialog (`new_project.older`, `.newer`, `.root`) and 9 in MainWindow (`job.log`, `findings.search`,
  `findings.list`, `findings.detail`, `findings.evidence`, `findings.conclusion`, `findings.notes`, `viewer.raw_page`,
  `viewer.raw_goto`). The evidence dock and engine-setup panel are clean (all named, buddies set).
- Root cause of the test gap: `tests/test_tooltips.py:105-121` `audit()` asserts `objectName` and `accessibleDescription`
  but never `accessibleName`. Only `test_engine_setup_ids_prefix_complete` (line 351-364) checks names, and only for that panel.
- Suggested fix: set names (or `QLabel.setBuddy` on the real edits), then add `assert widget.accessibleName() or buddy` to
  `audit()`.

### C-04 Medium: network-blocked states give a code and no remedy; cancel is reported as an error

- Where: `ui.py:437-439` (`_failed` prints `Error · <str(exc)>`, which includes the raw `PT-ACQ-*` code);
  `transport.py:96-99` (`ProxyHandler({})`: environment proxies deliberately ignored per SPEC-08 §4);
  `transport.py:175` (`'connection failed'`); `tests/test_ui_acquisition.py:205-217` asserts `'PT-ACQ-CANCEL' in status`.
- Scenario: an analyst behind a mandatory corporate proxy, or offline, sees only
  `Error · PT-ACQ-NETWORK: connection failed`. The dialog never says that proxies are ignored by design, that the symbol
  server must be reachable directly, or what to try next. A user-initiated cancel overwrites the "Cancelling" status with
  `Error · PT-ACQ-CANCEL: acquisition cancelled`, and a not-found is handled well but other typed codes are not translated.
- Suggested fix: map `PT-ACQ-NETWORK`, `PT-ACQ-LIMIT`, `PT-ACQ-VERIFY`, `PT-ACQ-CANCEL` to plain sentences with a next
  step (proxy note, retry, "cancelled, nothing was created"), keep the code in the log only.

### C-05 Medium: `AcquisitionDialog.download` can raise out of a slot on an unreadable destination

- Where: `ui.py:607-609`: `root.exists()` and `any(root.iterdir())` have no `OSError` handling (compare `NewProjectDialog`,
  `ui.py:280-283`, which does).
- Scenario: a destination under a directory the user cannot traverse (or a removed network share) makes `Path.exists()`
  raise `PermissionError` (the stdlib only ignores ENOENT/ENOTDIR/EBADF/ELOOP and `ValueError`). The exception escapes the
  Qt slot: the user clicks "Download and create project..." and nothing happens (traceback on stderr only).
- Reproduction (ran): as an unprivileged uid, `Path('<0700-dir>/sub/p').exists()` raised
  `PermissionError [Errno 13]`. The dialog code path was read, not driven, as the sandbox runs as root.
- Suggested fix: wrap the check in `try/except OSError` and show "Cannot read that directory".

### C-07 Medium: What's This text for dynamic tooltips is unescaped and auto-detected as rich text

- Where: `tooltips.py:1081-1084`: for template IDs `setWhatsThis(plain)` where `plain = template_description(...)` is the
  control-stripped but not HTML-escaped text. `toolTip` is escaped (`_rich`, line 1067); `whatsThis` and
  `accessibleDescription` are not, and Qt auto-detects rich text in What's This.
- Scenario: values from imported or untrusted data reach the templates: recent project path (`action.recent_project`),
  engine provenance/reason (`evidence.cell`, `evidence.row`, `evidence.badge`), series reason/state, overview `field`/
  `provenance`/`reason`, detector names. A path or reason containing `<b>..</b>` or `<img src=file:///...>` is rendered as
  markup in Shift+F1 What's This. SPEC-04 says "Imported strings rendered as plain text throughout". Impact is markup
  injection and local-image rendering, not code execution.
- Reproduction (ran): for all 10 `TEMPLATES` ids, `apply_tooltip(button, id, <every field>='<b>BOLD</b><img ...>')`
  gave `mightBeRichText(button.whatsThis()) == True` while the tooltip stayed escaped.
- Suggested fix: store whatsThis as `html.escape(plain)` wrapped in `<p style="white-space:pre-wrap">` (as `_rich` does), or
  prefix a non-markup character; add the template-injection case to `test_template_escapes_and_caps_untrusted_values`.

### C-08 Low: engine-setup probe/validation concurrency gaps

- `ui_engine_setup.py:636-641` `_executable_edited` bumps `probe_generation` and drops `probe_thread` but never sets the old
  thread's `cancel`; `594-603` `start_probe` does the same. The superseded probe keeps running the external BinDiff
  executable to completion (result dropped by generation), while the panel re-enables the Probe button, so several
  probes of an external binary can overlap.
- `ui_engine_setup.py:685-693` `cancel_validation` (and `695-702` `_inputs_edited`) clears `validation_cancel`, which is the
  guard for "one validation at a time" (line 645). A new validation can start while the cancelled checker tree is still
  being killed, so two C3 checkers can run at once (the first answer is discarded by generation, so no wrong result is
  shown; this is a resource and ordering issue).

### C-09 Low: probe failures are swallowed and the dialog parent owns a running QThread

- `ui_evidence.py:562-566`: `EngineProbeThread.run` converts any exception into `found = {}` and emits it; the user sees
  "Engine probe finished." with no engines and no error class (compare `EngineRunThread`, line 548, which reports the class).
  `self.probed = True` (line 1506) also prevents the automatic probe from retrying.
- `ui.py:420` `Worker(task, self)` parents a running `QThread` to the dialog, the pattern `ui_evidence.py:480-482` and
  `ui_engine_setup.py:159-161` document as process-aborting when the parent is destroyed first. `AcquisitionDialog` blocks
  close while a worker runs, but a quit while the modal dialog is open (session end, `QApplication.quit()`) or a test
  teardown can destroy it mid-run. The dialog is also never `deleteLater()`d after `exec()` (`ui.py:1933-1941`), so each use
  leaks one dialog and its widgets for the window lifetime. Not reproduced (needs a forced quit).

### C-10 Low: GUI-thread work and default-folder collisions

- `ui.py:680` runs `quarantine.promote` (copy and hash of up to two 1 GiB inputs, SQLite setup) on the GUI thread; the
  design comment gives the thread-affinity reason, but the window freezes with controls disabled and no progress.
- `ui.py:544-563` builds one `QTableWidgetItem` x 5 per candidate with a tooltip each. Measured offscreen:
  `complete_search` took 0.43 s for 3,000 builds and 3.67 s for 30,000 (parse itself: 2.3 s for 12 MiB, stalling a
  ticker thread by at most 0.26 s). Fine for realistic files; very large records freeze the GUI for seconds and the table
  has no filter or sort.
- `ui.py:590` Browse always proposes `<parent>/patchtrace-project`; a second download into the same parent trips
  "The project directory must be absent or empty." Derive the folder from the project name or file name.

### C-15 Low: file-name input and copy details

- `ui.py:491-494` + `contracts.py:41`: `CLFS.SYS` is rejected with
  `PT-ACQ-INPUT: file name must be a lowercase basename of [a-z0-9._-]`; the regex and code appear in user copy. Lowercase
  the input (it is a case-insensitive Windows name) and keep the message plain.
- `ui.py:651` logs `<sha> verified (unknown)` for a hash-matching but non-PE/non-AMD64 file; "verified" here means
  hash-equal only (SPEC-08 §3: not authenticity). Use "hash matches; format: unknown (cannot become a project input)" and
  stop before promote. The failure then surfaces only after both downloads (`quarantine.py:285-286`).
- `tooltips.py:451-453` says the log shows "exactly which requests were made", but the HEAD probes are not logged one by
  one (`ui.py:640` logs only a count) and the blob redirect host is not logged. `tooltips.py:462-464` `acquire.close`
  says a running job is "cancelled first", which can take unbounded time (C-01).

### C-16 Low: offscreen test stability and coverage notes

- Timing assertions: `tests/test_ui_engine_setup.py:327-328` (`slot < 0.25`, `max(gap) < 0.5`) and fixed
  `waitUntil(..., timeout=5000)` in `tests/test_ui_acquisition.py` may flake on a loaded Windows runner; they were green on
  three local runs.
- Coverage gaps: no test drives the real consent `QMessageBox` (C-02), a real socket (C-01), `Path.exists` failure (C-05),
  or accessible names (C-03). The existing cancel test asserts the error-styled copy (C-04).

### C-17 Low: Winbindex metadata bounds depend on a single third-party host

- `winbindex.py:402-403` caps 64 MiB compressed / 256 MiB decompressed; the largest per-file records on the live site
  (for example ntoskrnl.exe) were not measurable offline, so whether any real file exceeds 256 MiB is unverified
  (the limit would surface as `PT-ACQ-LIMIT` "exceeds 256 MiB"). SHA-256 equality proves identity with Winbindex only
  (documented, `contracts.py:3-4,16-17`); a compromised metadata host could steer the analyst to different genuine
  binaries, which no hash check can detect. This is a documented residual risk, not a defect.

### C-18 Low: `resolve` runs queued probes until the first failure in submission order is observed

- `transport.py:258-265`: `results = [f.result() for f in futures]` raises on the first failed future in list order, so
  while earlier probes finish, later ones (up to 256 HEADs, 4 at a time) keep running; cancellation only reaches queued
  futures after the exception propagates. Bounded (each `_with_retries` checks `cancel`) and low impact; use
  `as_completed` and cancel pending futures on the first error.

### C-19 Low: tooltip/ID coverage is enforced for built widgets only

- `tests/test_tooltips.py:196-227` proves every registry id is applied by a built widget, and `apply_tooltip` raises
  `KeyError` for an unknown id. A static scan of all string literals shaped like tooltip ids against
  `REGISTRY` (206 entries) plus `TEMPLATES` (10) found no unknown id in `src/`. Residual risk: an id used only in a branch
  that tests never build raises at runtime on the user's machine, not in CI. Dynamic ids built with f-strings are not
  covered by the scan.

## 3. Reproduction index (scratchpad, not in repo)

| Finding | What was run | Outcome |
|---|---|---|
| C-01 | loopback slow-drip server through real `urllib_open` and `Transport.download`, cancel at 2 s | still blocked after 25 s |
| C-06 | fake msdl 302 with `Location: https://x.blob.core.windows.net/a b` | raw `InvalidURL` escapes |
| C-11 | tamper staged file, then `quarantine.promote` | `PT-ACQ-VERIFY`, project directory left behind |
| C-02 | `QMessageBox` with 512 HEAD/GET lines, offscreen | 400 x 15552 px, Yes button off-screen |
| C-03 | `QAccessible` name query on 8 controls; widget sweep of main window and two dialogs | 4 / 3 / 9 unnamed |
| C-05 | `Path.exists()` under a 0700 dir as an unprivileged uid | `PermissionError` |
| C-07 | `apply_tooltip` on all 10 templates with markup values | `whatsThis` detected as rich text |
| C-10 | `AcquisitionDialog.complete_search` with 3,000 and 30,000 candidates; `parse` of 12 MiB | 0.43 s, 3.67 s; 2.3 s |
| C-19 | static scan of tooltip id literals | no unknown ids |
| baseline | pytest on acquisition and UI test modules, 3 repeats | all green |

## 4. Verified OK (no finding)

1. Host allow-list: `_check` (`transport.py:57-68`) enforces https, exact host set `{winbindex.m417z.com,
   msdl.microsoft.com}`, port 443 or none, no userinfo; the blob suffix is admitted only as the redirect target
   (`blob=True`), and a bare `blob.core.windows.net` is refused (`len(host) > len(BLOB_SUFFIX)`).
2. Redirects: `_NoRedirect` surfaces every 3xx; exactly one hop is followed for downloads; metadata redirects are refused;
   a second redirect is `PT-ACQ-NETWORK` (`transport.py:295-304`). Environment proxies are ignored (`ProxyHandler({})`).
3. Size caps: `Content-Length` pre-check and a streaming cap (`transport.py:181-204`); download cap is
   `min(512 MiB, planned.size)`; gzip bombs stop at 256 MiB via `decompressobj(max_length)`, trailing/truncated gzip rejected.
4. Hash and size verification happen on the staged temp file before `os.replace` into place; the temp file is unlinked on
   any failure (`transport.py:334-336`); the SAS blob URL is never stored (`Provenance.redirect_host` is host only).
5. Path traversal: file names are `fullmatch`-validated (no separators, no `.`/`..`), side directories are fixed
   (`older`/`newer`), staging is `mkdtemp` 0700. There is no zip/archive extraction anywhere in `acquisition/` (out of scope
   per SPEC-08 §1), so there is no zip-slip surface.
6. Strict JSON: duplicate keys, NaN/Infinity and non-UTF-8 are rejected; malformed entries are skipped and counted;
   candidate enumeration arithmetic matches SPEC-08 §4.3 and is capped at 256 probes.
7. Credentials: none are sent or stored by acquisition (fixed `User-Agent: PatchTrace` only). Untrusted Winbindex strings
   (version, KB) render through `PlainLabel`, `appendPlainText` and `plain_tip` in the dialog.
8. Offline cache: none exists and none is required by SPEC-08; metadata is not stored (consistent with the GPL-3 note),
   so offline use means "connection failed" (see C-04).
9. Consent: the search and download requests are each behind a `confirm()` that defaults to No; declined consent makes no
   network call (tested). `delta.py` loads `msdelta.dll` by absolute System32 path and calls `DeltaFree` in `finally`.
10. Threading in `ui_evidence.py` and `ui_engine_setup.py`: parentless `QThread`s held in a module registry, queued
    connections, generation counters, persistence only on the GUI thread, `shutdown()` cancels then joins. No data race found.
