# Whole-project audit TODO (2026-10-15, finder prefix WP-)

Partial audit (cut short by an API rate limit). Verified against the worktree at the time; WP-01 re-checked on claude/instance-d-gui 230d181.

| ID | Severity | Area | Status |
|---|---|---|---|
| WP-01 | High | cli / hostile text | fixed at 230d181 |
| WP-02 | Medium | ingestion / hostile text | open |
| WP-03 | Low | sanitiser consistency | open |
| WP-04 | Low | test that cannot fail | open |
| WP-05 | Low | tools/generate_schemas.py has no --check | open |
| WP-06 | Low | search --anchors-from capability stub | open |
| WP-07 | Low | service.py annotation | open |
| WP-08 | Low | gui tasks BaseException / start failure | open |
| WP-09 | Low | jobs killpg after reap | open |
| WP-10 | Low | rules show silent empty | open |
| WP-11 | Info | coverage note | - |

Details follow (same blocks as the scratch TODO file).

# Whole-project audit (finder: WP-). Base: worktree-agent-ad16c3f07b4a3e44b. Date 2026-10-15.

### WP-01 | High | cli / hostile text | fixed on claude/instance-d-gui (cli.py _emit now uses escape_text; verified at 230d181)
- where: src/patchtrace/cli.py:180-189 (`_emit`), fed by cli.py:318,326,477 (`rank`, `correlate`: `names = ' / '.join(f.name ...)`) and cli.py:722-724 (`series chains`: `n.name`, labels)
- what: text-mode output writes function names (taken verbatim from the target's Ghidriff JSON / symbols) and warnings straight to stdout/stderr. `models.FunctionRecord.name` has no control-character policy and `normalization.py:65` stores `record['fullname'] or record['name']` raw. A hostile binary with a symbol containing ESC/CSI/C1/bidi marks can rewrite the analyst's terminal or spoof ranking rows (`\n` forges extra rows).
- evidence: reproduced end-to-end: set a function name to `'read_item\x1b[2J\x1b[31mOWNED‮'` in a sample project and ran `python -m patchtrace rank <project>`; stdout was `'... complete    read_item\x1b[2J\x1b[31mOWNED‮\n'` (raw ESC and RLO written). Other CLIs I tried (graph leads, pilot leads, search, strings list, build-env show, unified status, flags) were clean, so the gap is limited to cli.py's own commands (rank, correlate, series chains/create text). Contrast `intelligence/reports.plain_text` and `kev/report.escape_md`, which escape. `ingestion.display_text` only backslash-escapes surrogates (see WP-02).
- fix hint: pass every untrusted token in text mode through one terminal-safe function (reuse `intelligence.reports.plain_text`) in `_emit` text paths for rank/correlate/series; keep JSON mode as is (json.dumps escapes).

### WP-02 | Medium | ingestion / hostile text | open
- where: src/patchtrace/ingestion.py:34-36 (`display_text`), used at ingestion.py:164 (artifact name) and service.py:41 (project name)
- what: the sanitiser is named like the others but only does `encode('utf-8','backslashreplace')`; ESC, NUL, C1, bidi, zero-width, CR and LS/PS survive into the persisted project and then to every sink that trusts `Artifact.name`/`ComparisonProject.name` (CLI text, reports, GUI tooltips that are not routed through `plain_tip`).
- evidence: ran `ProjectService.create` on a file named `old\x1b[2Jevil‮gpj.exe` with project name `proj\x1b[31mred` (PE validation stubbed): stored `name` == `'old\x1b[2Jevil‮gpj.exe'`, project name `'proj\x1b[31mred'`.
- fix hint: strip/replace `hostile_text.is_hostile` characters in `display_text` (artifact names are display-only; the real file is addressed by `relative_path`/sha256). Persisted-contract note: only affects newly created projects.

### WP-03 | Low | hostile text consistency | open
- where: src/patchtrace/hostile_text.py:1-3 ("the one rule") vs src/patchtrace/gui/text.py:15-17 (`_STRIP`), src/patchtrace/secondary/bindiff_probe.py:53-58 (`sanitize`), src/patchtrace/secondary/runs.py:109-112 (`sanitize_stderr`), src/patchtrace/callgraph/text.py:14, src/patchtrace/secondary/evidence_view.py:104, src/patchtrace/pe_overview/resources.py:95
- what: ~20 independent sanitisers disagree. Probe (`'a'+c+'b'` per char, scratchpad/probe_san.py): gui `sanitize_text` keeps ZWSP U+200B, BOM, SHY, TAG chars (Cf) although `hostile_text` defines Cf as hostile; `bindiff_probe.sanitize` and `runs.sanitize_stderr` keep C1 (U+009B CSI, U+0085), bidi overrides U+202E/U+2066, LS/PS; `callgraph.text.sanitize`, `evidence_view.sanitize_text`, `pe_overview.resources.sanitize_text` keep lone surrogates (cannot be encoded to UTF-8 on write).
- evidence: output of the probe script (run `python3 probe_san.py` from repo root).
- fix hint: implement each on top of `hostile_text.is_hostile`; add one parametrised test over all sanitiser entry points with the same battery.

### WP-04 | Low | tests that cannot fail | open
- where: tests/test_enrichment_intelligence.py:297-299 (`test_transport_imports_no_qt`)
- what: `assert 'PySide6' not in {m.split('.')[0] for m in sys.modules if m.startswith('patchtrace.enrichment.intel')}` builds a set whose only element is always `'patchtrace'`, so it can never fail.
- evidence: expression reads as above; every module name selected starts with `patchtrace.`.
- fix hint: run the check in a subprocess (like tests/test_kbc_service.py) or assert `'PySide6' not in sys.modules` after `importlib.reload` in a clean interpreter.

### WP-05 | Low | tooling | open
- where: tools/generate_schemas.py (module level, no argparse)
- what: it has no `--check`; any argument is ignored and the script rewrites docs/schemas in place. A CI step or contributor running `generate_schemas.py --check` believing it is read-only silently regenerates (and thus can never fail on drift).
- evidence: ran `PYTHONPATH=src python tools/generate_schemas.py --check` -> exit 0, files rewritten (no drift currently).
- fix hint: add `--check` that compares and exits non-zero, or reject unknown arguments.

### WP-06 | Low | search CLI / capability stub | open
- where: src/patchtrace/search/cli.py:176-180
- what: `--anchors-from` imports `patchtrace.search.anchors`, which does not exist (src/patchtrace/search has no anchors.py; comment says "slice S10 adds the module"), so the flag always fails with PT-SEARCH-CAPABILITY "not available in this build". The flag is advertised in the parser.
- evidence: `ls src/patchtrace/search` has no anchors.py.
- fix hint: hide the flag until S10 lands, or implement; list it as an open gate in docs.

### WP-07 | Low | tasks runner / type | open
- where: src/patchtrace/service.py:30 (annotation) vs :155 (value)
- what: `_prepared` is annotated as a 3-tuple but stores 4 elements (`staged` added); `discard_import`/`apply_import` index `[3]`. Type-checkers and readers are misled; no runtime bug.
- evidence: service.py:30 `tuple[PreparedImport, AnalysisRun, tuple[FunctionMatch, ...]]`, :155 appends `staged`.
- fix hint: correct the annotation.

### WP-08 | Low | gui tasks / resource | open
- where: src/patchtrace/gui/qt/tasks.py:_execute (`except Exception`), _start (`thread.start()`)
- what: a worker that raises a BaseException that is not an Exception (e.g. SystemExit from a library, KeyboardInterrupt) never posts an event, and a `thread.start()` failure (thread exhaustion) leaves the task in `_running`/`_threads`. `busy(channel)` then stays True forever (Run buttons remain disabled until restart).
- evidence: code read (`_work` posts only `_execute`'s return; no `finally`).
- fix hint: `_work` try/finally that posts a 'drop'/'error' event; in `_start` catch RuntimeError and discard.

### WP-09 | Low | jobs / process supervision | open
- where: src/patchtrace/jobs.py:run_process (`terminate()` after `child.poll()` has reaped the leader; also in `finally`)
- what: on POSIX `os.killpg(child.pid, SIGKILL)` is sent after the child was already reaped, to clean descendants. If the PID/pgid was recycled in the meantime, an unrelated process group could be killed; ProcessLookupError is the only guard.
- evidence: code read (poll() reaps, then unconditional killpg). UNVERIFIED in practice (needs PID reuse).
- fix hint: only killpg while the leader is unreaped (kill group first, then wait), or use a pidfd/job-style containment.

### WP-10 | Low | rules CLI | open
- where: src/patchtrace/rules/cli.py (`rules show`, text mode)
- what: with no candidates, `rules show <project>` prints nothing at all and exits 4; JSON mode gives an empty record. Analyst gets a silent empty result.
- evidence: ran `python -m patchtrace rules show <sample project>`: stdout empty, exit 4.
- fix hint: print a one-line "no rule candidates" message.

### WP-11 | Low | audit scope note (not a defect) | open
- Areas read without finding a defect: persistence.py (locks, backup, validate_project), service.py transactions, acquisition/transport.py and delta.py, providers.py (endpoint/redirect/credential handling), offline_bundle.py manifest validation, enrichment/ranking.py (deterministic, integer), tools/release_gate.py + qa-windows release job (prerelease only, target_commitish=sha), core schema drift (tests/test_unified_contracts.py regenerates all core/enrichment/secondary/profile/unified schemas; generate_schemas run showed no drift), all 40 CLI subcommands `--help` (no tracebacks), 13 CLI verbs against the sample project (no tracebacks). NOT covered: kev/, rules/, pilot/, fabric/, kbcorrelation/ internals, unified/ pipeline internals, gui/qt widgets beyond tasks.py, tools/calibration/. The audit was cut short by an API rate limit.
