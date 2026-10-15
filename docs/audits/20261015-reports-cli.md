# Audit: reports export and headless CLI (2026-10-15)

Auditor: Haiku 5.5, read-only review of `src/patchtrace/reports.py`, `cli.py`, `cli_commands/**`, `gui/cli.py`, `backend_cli.py`. Base: `origin/main` at `21a005e`. No src or test file was edited. Repro commands were run from the repository root with `sys.path.insert(0, 'src')`, because `PYTHONPATH` is not usable in this sandbox.

## Findings

Counts: High 0, Medium 7, Low 8.

| id | severity | location | finding | status |
|---|---|---|---|---|
| CLI-1 | Medium | `cli.py:330-333`, `cli.py:475-483` vs `cli.py:355-357`, `cli.py:702-704` | Partial results exit 0 for `rank` and `correlate` but 3 for `flags` and `series create`. | open; owner decision (SPEC-44 s8) |
| CLI-2 | Medium | `cli.py:443`, `cli.py:674`, `cli.py:680`, `cli.py:853-857` | A cancellation raised as `CliError(5)` writes envelope `status: "failed"`, not `"cancelled"`, which the spec requires. | open |
| CLI-3 | Medium | `cli.py:850`, `cli.py:842-858` | Argument-parse errors with `--json` print no envelope and no stdout. `args` is still `None` when the parse fails. | open |
| CLI-4 | Low | `backend_cli.py:89-92`, `backend_cli.py:176`, `backend_cli.py:205` | With no bundle present, `status` and `verify` exit 4, `diagnose` exits 2 with status `failed`, and `selftest` exits 2. | open; owner decision (SPEC-44 s8) |
| CLI-5 | Medium | `cli.py:486-500`, `enrichment/cache.py:590-591` | `cache status` on an unusable cache path returns status `complete` and exit 0, with `"error": "_Unsafe"` buried in `result`. | open |
| CLI-6 | Medium | `cli.py:853` vs `cli.py:869` | The `CliError` path prints and writes the message without `redact_log`. The generic path applies it. A secret quoted in an error reaches stderr and the JSON envelope. | open |
| CLI-7 | Medium | `cli.py:187`, `cli.py:318`, `cli.py:477` | Text output writes untrusted names (function names, evidence text) without escaping control characters or bidi controls. ESC sequences reach the terminal. | open |
| CLI-8 | Medium | `reports.py:204-206`, `reports.py:218-265` | Markdown and HTML export keep bidi controls (U+202E, U+2066 and similar) unchanged. SPEC-50 section 2 records this as a reproduced defect. | open (SPEC-50 build slice) |
| CLI-9 | Low | `reports.py:275` vs `reports.py:288` | `.encode('utf-8')` runs outside the `ExportError` translation. A lone surrogate escapes as `UnicodeEncodeError`. `strict_json` rejects surrogates on load, so this is reachable only from in-memory models. | open |
| CLI-10 | Low | `reports.py:265` | The "Evidence and provenance" block in Markdown is escaped as prose. JSON becomes `{"a"\: 1\}` and is no longer readable. | open |
| CLI-11 | Low | `gui/cli.py:55` | An empty panel set gives exit 4 with envelope status `ok`. Other verbs use `complete` and pair it with exit 4. | open |
| CLI-12 | Low | `backend_cli.py:17` vs `secondary/cli_run.py:39` | Timeout minimums differ: 10 s for `backend`, 60 s for `secondary`. Both help strings match their own code. | open; owner decision |
| CLI-13 | Low | `cli.py:459` | `--save-snapshot` uses `Path.write_text`. On Windows that writes CRLF, which differs from the LF rule for generated files. Code reading only; not run on Windows. | open |
| CLI-14 | Low | `tests/test_cli.py:75-77`, `tests/test_cli.py:139-146`, `tests/test_audit_ai_reports.py:42-47` | Test gaps. No test checks the envelope on a usage error, the `cancelled` status for exit 5, bidi neutralisation in exports, or a lone surrogate in export. | open |
| CLI-15 | Low | `cli.py:35-36` (`_Parser.error`) | Usage errors print one line with no usage block, so the help pointer is lost. | open |

## Details and repro

**CLI-1.** Repro (pipeline result monkeypatched to `partial`, no ranking entries): `rank --json` prints `status: partial` and returns 0. `flags --json` with the `wil` stage `partial` returns 3. `series create` returns 3 on partial (`cli.py:704`). Fix: one rule, documented in SPEC-44 section 8. The owner should choose between "partial is 3" and "partial is 0 with `status: partial`", then apply it to every verb.

**CLI-2.** Repro: `cache` handler raising `CliError(5, ...)`, run with `--json`. Output `{"status": "failed", "error": ...}`, exit 5. The `KeyboardInterrupt` path (`cli.py:858-863`) writes `status: "cancelled"`. Fix: in the `CliError` branch, use `'cancelled'` when `exc.code == CANCELLED`.

**CLI-3.** Repro: `python -c "import sys; sys.path.insert(0,'src'); from patchtrace.cli import main; sys.exit(main(['rank','--json']))"`, giving exit 2, empty stdout, and one stderr line. The `unavailable` verb path in `cli_commands/__init__.py` (`register_all`) raises from the same place. Fix: parse the subcommand's `--json` before the handler runs, or give `main` a best-effort JSON-mode flag scan.

**CLI-4.** Repro: `python -m ...` equivalent of `backend {status,verify,diagnose,selftest} --json --bundle-dir /nonexistent/bundle` gives exits 4, 4, 2 and 2. Fix: pick 4 for "no bundle" on all four actions, or record the decision in SPEC-44.

**CLI-5.** Repro: `cache status --cache-dir <a regular file> --json` returns exit 0 and `status: "complete"`. The `result` contains `"entries": 0`, `"enabled": true` and `"error": "_Unsafe"`. Fix: return `RUNTIME` when `result` has an `error` key, and carry a message, not a bare class name.

**CLI-6.** Repro: `rank <path> --profile 'apiKey=abcdef123456SECRET' --json` writes the secret to stderr and the envelope. `redact_log` on the same string gives `apiKey=[redacted]`. Fix: apply `redact_log` to `str(exc)` in the `CliError` branch.

**CLI-7.** Repro: a monkeypatched `rank` result with a function name `evil\x1b[2J‮name` writes the ESC sequence and U+202E unchanged. Fix: one `_safe_text` helper that replaces C0/C1 controls and bidi controls, used by every text table.

**CLI-8.** Repro: `export_project(project.model_copy(update={'name': 'Project‮gnp'}), 'md', path)`; U+202E is present in the output file. The same holds for `html`. Fix: follow SPEC-50 section 6 (escape matrix). Add a regression test first.

**CLI-9.** Repro: `export_project(project.model_copy(update={'name': 'bad\ud800name'}), 'json', dest)` raises `UnicodeEncodeError`, not `ExportError`. Persisted projects are protected by `persistence.strict_json` (`persistence.py:61-62`). Fix: move the `encode` into the `try`, or use `errors='strict'` and catch `UnicodeEncodeError` as `ExportError`.

**CLI-10.** Repro: `reports._markdown_escape('{"a": 1}')` gives `\{"a"\: 1\}`. Fix: emit the provenance block inside a fenced code block, with its own fence-length rule, or use a plain code span.

**CLI-11.** Repro: `gui.cli.run(Namespace(action='list', json=True), Event(), manifest=())` gives exit 4 and `"status": "ok"`. Fix: `complete` for exit 0 and 4 (or `no-results`, as the other verbs do).

**CLI-12.** Repro (code reading): `grep -n "TIMEOUT_RANGE = " src/patchtrace/backend_cli.py src/patchtrace/secondary/cli_run.py` gives `(10, 86400)` and `(60, 86_400)`. Fix: one shared constant in the envelope contract module, once SPEC-44 section 8 is decided.

**CLI-13.** Repro (code reading): `cli.py:459` uses `Path.write_text`. On Windows, text mode translates `\n` to `\r\n`. Fix: `write_bytes(payload.encode('utf-8'))`, or `newline='\n'`.

**CLI-14.** Repro: `grep -n "def test_invalid_arguments_exit_2" -A3 tests/test_cli.py` shows only exit codes are checked. `grep -rn "_markdown_escape\|export_project" tests/test_audit_ai_reports.py` shows no bidi or surrogate case. Fix: add red tests for CLI-2, CLI-3, CLI-8 and CLI-9 before the fixes.

**CLI-15.** Repro: `rank --json` (no project) prints `error: patchtrace rank: the following arguments are required: project` with no usage. Fix: print `parser.format_usage()` after the message.

## What I reviewed

- `src/patchtrace/reports.py` (all 296 lines): `_redact`, `_clean`, `_safe_settings`, `_ranking_section`, `_snapshot`, `_markdown_escape`, `_cell`, `_render` (json, html, md), `export_project`.
- `src/patchtrace/cli.py` (all 873 lines): parser, `_emit`, profile and config resolution, `cmd_rank`, `cmd_flags`, `cmd_correlate`, `cmd_cache`, `cmd_acquire`, `cmd_series`, `cmd_secondary`, `main`.
- `src/patchtrace/backend_cli.py` (all 279 lines).
- `src/patchtrace/gui/cli.py` (all 93 lines).
- `src/patchtrace/cli_commands/` (`__init__.py`, `fabric.py`, `kev.py`, `panels.py`, `pilot.py`, `rules.py`).
- Cross-checks: `enrichment/cache.py:status`, `persistence.strict_json`, `diagnostics.redact_log`, the existing tests `tests/test_cli.py`, `tests/test_audit_ai_reports.py`, `tests/test_interpretation.py`, and the specs `docs/specs/enrichment.md:139`, `docs/specs/report-export-contract-v2.md`.
- Ledger items already recorded in `docs/plans/ledger-A.md:29` (exit-code inconsistencies, no-bundle codes, timeout minimums) were confirmed by reading the code, not re-triaged.

Repro scripts were written to the scratchpad only, not into the repository.

## Not reviewed

- The feature CLIs behind the `cli_commands` adapters: `kev/cli.py`, `fabric/cli.py`, `pilot/cli.py`, `rules/cli.py`, `intelligence/cli.py`, `unified/cli.py`, `secondary/cli_*.py`, `kbcorrelation/cli_index.py`. Only their adapters were read.
- The frozen-build behaviour of `cli_commands` discovery. `pkgutil.iter_modules` may not see verbs inside a PyInstaller bundle. This is a suspicion, not a finding, and needs `tools/frozen_smoke.py` on Windows.
- Windows console behaviour: the `errors='replace'` reconfigure in `main` was read, not run on a Windows console.
- The HTML export in a browser and its CSP behaviour.
- `diagnostics.redact_log` coverage beyond the single case in CLI-6.
- Timeout and argument validation in `series create --timeout` (no range check in `cli.py`; `BackendConfig` checks positivity only at validation time).
- Full test-suite results. None were run; the repros above are the only executions.
