# Audit: intelligence, KEV, rules, fabric and pilot (2026-10-15)

Base: `main` at `21a005e` (fast-forwarded from origin before the audit). Read-only audit: no file under `src/` or `tests/`
was edited. Repros ran in a scratch venv (Python 3.13, pytest 9.1.1, hypothesis, networkx, yara-x, iced-x86) against this
worktree. Nothing was run on Windows; Windows conclusions are marked as suspicions. No network was used.

Counts (new findings): **0 High, 2 Medium, 2 Low**. Still open from earlier audits: **1 Medium, 3 Low** (see the
"Known" table). Suspicions (not counted, no runnable repro here): 5.

## Findings

| ID | Sev | Location | Summary |
|---|---|---|---|
| INT-1 | Medium | `src/patchtrace/kev/store.py:343-344` (`prune`) | `prune` keeps only snapshot files whose description (meta) is readable. When the in-use catalog's meta is missing or damaged, `prune --yes` deletes its raw snapshot although `current.json` still names it. For a `local-import` catalog those bytes are the only copy. |
| INT-2 | Medium | `src/patchtrace/rules/matrix.py:142` (`read_expectations`), `:131` | The analyst's expectations file is parsed with plain `json.loads`: a duplicated key silently keeps the last value, the size is unbounded, and the file is not checked as strict JSON. A changed verdict results with no message. |
| INT-3 | Low | `src/patchtrace/rules/matrix.py:131` (`_target`) | Expectation keys match file names case-sensitively. On a case-insensitive file system a differently cased key is ignored without a note: the analyst's `hit` becomes `unknown`, or `no-hit` for a clean build. |
| INT-4 | Low | `src/patchtrace/rules/engine.py:261-270` (`_cell`), `src/patchtrace/rules/contracts.py:582-585` | `hits` is capped at `max_matches_per_pattern` (64) and is 1 for a rule without patterns, yet both are shown as exact counts. There is no "at least" or "presence only" marker. |

### INT-1 details

- Evidence: `prune` computes `kept_hashes` from `metas` (listed descriptions) only (`kev/store.py:343-344`). The pointer's
  `raw_sha256` is never added, so a snapshot whose description is unreadable is treated as unreferenced and deleted by
  the snapshot glob at `kev/store.py:359`.
- Repro (ran, `scratchpad/int-audit/repro6.py`): install `kev-synthetic-2099.json` as `local-import`; delete
  `meta/<id>.json`. Output: `after meta removed: current loads? False snapshot exists True`, then
  `prune removed files 1 snapshot still exists False`, `pointer still names it: True`.
- Expected: the snapshot named by the pointer is kept (or the pointer is reported as dangling and nothing is deleted
  without a second confirmation).
- Fix: add `pointer.raw_sha256` to `kept_hashes`; a red test in `tests/test_kev_store.py` next to
  `test_prune_keeps_the_catalog_in_use_even_when_it_is_not_among_the_newest`, with the meta removed first. The existing
  tests do not cover a missing description.

### INT-2 details

- Evidence: `read_expectations` (`rules/matrix.py:139-147`) reads with `path.read_text` (no cap) and `json.loads`
  (no `object_pairs_hook`, no `parse_constant`). The AGENTS.md rule is strict JSON for imported files. The CLI takes the
  file through `--expect` (`rules/cli.py:371`).
- Repro (ran, `repro5.py`): `{"build-a.exe": "hit", "build-a.exe": "no-hit"}` returns `{'build-a.exe': 'no-hit'}`;
  `{"x.exe": "hit", "x.exe": "unknown"}` returns `{'x.exe': 'unknown'}`. A `NaN` value is rejected correctly.
- Expected: a duplicate key is `PT-RULE-INPUT` (`expect-shape`); the read is capped (for example 1 MiB) and uses the
  same strict loader as `rules/contracts.py:97`.
- Fix: reuse the strict pairs hook and a size cap in `read_expectations`; add the two duplicate-key cases as parametrized
  red tests with short ids (`dup-same-value`, `dup-other-value`) in `tests/test_rules_matrix.py`.

### INT-3 details

- Evidence: `expect.get(sha, expect.get(label, default))` (`rules/matrix.py:131`) compares `label` (the file name) exactly.
- Repro (ran, `repro8.py`): key `build-A.exe` gives `hit` for file `build-A.exe` and `unknown` for `build-a.exe`. A clean
  file `Clean.dll` with key `clean.dll: hit` gets the default `no-hit`.
- Impact: on NTFS the same file is found under either spelling, so the verdict depends on the case typed in the
  expectations file. The unscored case is silent.
- Fix: match names with `os.path.normcase` (or a casefold of the label) on the Windows branch, and report every
  expectation key that matched no target as a note on the run. Add a red test with `ids=['key-case-differs']`.

### INT-4 details

- Evidence: `_cell` sets `hits=len(matches) or 1` (`rules/engine.py:270`). `matches` is capped by the scanner
  (`max_matches_per_pattern`, `engine.py:214`). The contract docstring (`rules/contracts.py:582-585`) documents the cap, and
  `tests/test_rules_engine.py:279-280` asserts `capped.hits == 3` for ten matches. The number is still displayed as
  a count, and the matrix and report layers do not add a marker. The brief and the matrix contract say "a hit count is a
  raw number", so a capped 64 reads as the true count.
- Fix: add `hits_capped: bool` (additive field, schema regeneration) or report `hits` as a lower bound in the UI text
  ("64 or more"); keep the existing test and add an assertion on the flag.

## Suspicions (not counted; no runnable repro on this host)

- **S-1 (Windows, Medium if confirmed).** `rules/worker.py:90` calls `os.open(target.path, ...)` before any type check.
  `O_NONBLOCK` is not available on Windows, and the parent checks only `os.path.isabs` (`rules/runner.py:_check_request`).
  A target such as `\\.\CON` or another device name would make the open block until the run wall clock (up to 3600 s),
  because the per-file timeout does not cover the open. Needs a Windows run with a device path in a matrix request.
- **S-2 (Windows, Low).** `rules/export.py:163` opens `out` with `'x'` and records the basename. A reserved device name
  (`NUL.yar`, `CON.yar`) may not create a file on Windows while the export record still claims one. Needs a Windows run.
- **S-3 (Low).** `RuleSet.compile` (`rules/engine.py`) compiles each lint-passing rule again in one combined compiler. A
  rule that passes alone but fails combined would raise a raw `CompileError`, which the worker reports as exit 21 and the
  parent as `worker-crash`, failing the whole run instead of one cell. Not found by reading; yara-x was installed, but no
  such rule was constructed.
- **S-4 (Low).** `RuleSet.scan` calls `pe_map(data)` (`yara_x.Module('pe').invoke`) before `set_timeout` applies, so a
  pathological PE image is parsed outside the per-file timeout. The memory cap still applies.
- **S-5 (Low).** `intelligence/tools/capa.py:89` reads the whole Ghidra `application.properties` before truncating to 64 KiB.
  The file is in the user's own Ghidra install, so the impact is small.

## Known (earlier audits 20261014-C-*)

Status is on `main` at `21a005e`. "Reproduced" means the repro in the prior audit (or one of mine) was run; "by reading"
means the code was read and no run was done.

| ID | Prior sev | Status now | Evidence |
|---|---|---|---|
| C-01 | Medium | Fixed | Input now fails schema validation with `PT-INTEL-VALIDATE`, not `TypeError` (reproduced). |
| C-02 | Medium | Fixed | `x_extension: 5` loads with no crash (reproduced). |
| C-03 | Medium | **Still open on the explain path** (Medium) | `resolve` now uses every document (`csaf/applicability.py:298`, test `test_c03_*`). `explain.py:151` passes only the documents that list the CVE and no `superseded` map. Reproduced: all documents give `older.resolution = unknown`, the listing-only call gives `affected` with `superseded_sources = ()` (`repro7.py`). Fix: pass all unique advisories (or the store-wide map) from `explain`. |
| C-06 | Medium | Fixed | `_anchor` returns `None` for empty values (`intelligence/anchors.py:44-48`). |
| C-07 | Medium | Fixed | Trailing "requires no" no longer marks `heap-overflow` as negated (reproduced). |
| C-08 | Medium | Fixed | 2.5 million values are refused in 0.04 s, 247 MB peak (reproduced; pre-check in `csaf/validate.py:179`). |
| C-12 | Low | Fixed | `detail` is clipped to 500 characters (`csaf/applicability.py:132`). |
| C-13 | Low | Fixed | Lone surrogate gives `PT-INTEL-FORMAT` (reproduced). |
| C-14 | Low | Addressed | `tools/delta.py` has a per-link pass (`_unmatched`, TA-2 note). By reading. |
| C-15 | Low | Fixed | FLOSS records `base-differs` (`tools/floss.py:367-371`). By reading. |
| C-16 | Low | **Open** | `process.sanitize` keeps the part of a user name after a space: `'error opening John Smithx.dll'` (reproduced). `tool_text` is correct for DiE names. |
| C-17 | Low | Fixed | DiE labels go through `tool_text`, which escapes bidi and NUL (`tools/diec.py:245`). |
| C-18 | Low | Fixed | `1e999` gives `PT-TOOL-OUTPUT` (reproduced). |
| C-19 | Low | Open (by reading) | `_FUNCTION_ID` uses `$` with `.match`; `'rva:0x10\n'` matches (regex verified in Python). `tools/common.py:53`. |
| C-20 | Low | Open | `delta.compute(None, None, None, None)` raises `AttributeError: 'NoneType' ... 'engine'` (reproduced). |
| C-21 | Low | Not re-verified | `storage.py:137-149` (by reading the start of `_facts`). |
| C-22 | Low | Not re-verified | `csaf/transport.py:215-223` (`put`); reads only. |
| TA-1 | Medium | Fixed | `ValidationError` is turned into `ToolError` (`tools/capa.py:424,434`). By reading. |
| TA-2 | Medium | Addressed | Per-link classification in `tools/delta.py` (`_unmatched`). By reading. |
| TA-3 | Medium | Partly | Truncation note on added/removed (`tools/delta.py:190`). By reading. |
| TA-4 | Medium | Fixed | Exact bytes are kept (`capa.py:429` uses `stdout_bytes`; `process.py` keeps raw). By reading. |
| TA-5 | Medium | Fixed | Output stop at the limit (`max_output_bytes` in `process.py`). By reading. |
| TA-6 | Medium | Partly | `tools/intel_tools_pin.json` now exists; enforcement not re-verified. |
| TA-8 | Low-Med | Fixed for names | `tool_text` keeps `C/C++`, `UPX/LZMA` (reproduced). Error text still uses `sanitize` by design. |
| TA-9 | Low-Med | Fixed | Bidi and NUL escaped in DiE labels (reproduced: `MSVC‮evil\x00 1`). |
| TA-12 | Low | Fixed | See C-15. By reading. |
| TA-16 | Info | Fixed | See C-18. |
| (others) | | Not re-verified | TA-7, TA-10, TA-11, TA-13 to TA-15, C-04, C-05, C-09, C-10, C-11, C-23, C-24 (enrichment or cli, out of scope or not re-read). |

Missing tests found while reviewing (tied to the findings above):
- No test for a missing description with the pointer naming its snapshot (INT-1).
- No test that duplicate keys in the expectations file are refused, nor a size cap (INT-2).
- No test for expectation-key case (INT-3).
- No test that a capped hit count is flagged (INT-4).
- No test on the `explain` supersession path (C-03 residual).
- `kev/store.py` prune and `rules/matrix.py` read paths have no hostile-input test.

## Test and gate evidence (automated; this host, Linux, Python 3.13)

- `tests/test_intel_*`, `tests/test_kev_*`, `tests/test_fabric_*`: **2039 passed**.
- `tests/test_pilot_*`: **1308 passed**.
- `tests/test_rules_*` (run with yara-x 1.x wheel): **1110 passed, 1 failed, 1 skipped**. The failure is
  `test_rules_worker.py::test_parent_never_imports_yara_x`. Its control subprocess uses `Path(sys.executable).resolve()`,
  which in this scratch venv points at the base interpreter without yara-x, so this is an environment artifact of
  the venv, not a product defect (not confirmed on a standard install).
- Schema drift: `tools/generate_{kev,fabric,pilot,rules,intelligence,intel_tools}_schemas.py --check` exit 0; the core
  `tools/generate_schemas.py` (no check mode) rewrote `docs/schemas` and `git status` stayed clean, so the committed
  schemas match the models.
- Not run: ruff, the full suite, Windows, frozen smoke, live tools (`live-intel-tools.yml`), live KEV probe.

## What I reviewed

- Docs: `docs/plans/worker-brief.md` (section 2), `docs/plans/e4-audit-and-qa-plan.md`, `docs/audits/20261014-C-intelligence-enrichment.md`,
  `docs/audits/20261014-C-tool-adapters.md`, `CLAUDE.md` (via the prompt).
- `src/patchtrace/rules/`: `worker.py` (full), `runner.py` (full), `engine.py` (full), `limits.py` (full), `export.py`
  (write path and gates), `matrix.py` (expectations, verdicts, target construction), `gates.py` (wildcard gate),
  `contracts.py` (`WorkerTarget`, `WorkerLimits`, `CellResult`, `read_*` loaders), `synth.py` (escaping, quoting, comment lines).
- `src/patchtrace/kev/`: `parse.py` (full), `store.py` (full), `transport.py` (full), `contracts.py` (`clean_text`, `entry_digest`), `cli.py` (snapshot import).
- `src/patchtrace/fabric/origins.py` (full), `fabric/memory.py` (publish path, `_without`, `_union`, `_merge`), `fabric/convert.py` (tags).
- `src/patchtrace/pilot/fusion.py` (component and eligibility logic), `pilot/store.py` (`_write`, `_gunzip`, `read_manifest`), `pilot/sources/tools.py` (capa origin selection).
- `src/patchtrace/intelligence/`: `tools/process.py` (`tool_text`, `sanitize`, `regular_file`), `tools/diec.py` (labels, argv),
  `tools/capa.py` (argv, `ValidationError` handling, props read), `tools/floss.py` (argv), `tools/common.py` (strict JSON, `_FUNCTION_ID`),
  `tools/delta.py` (per-link pass, truncation note), `csaf/validate.py` (`parse_json` pre-check, schema errors), `csaf/applicability.py` (`resolve`, `supersession`), `csaf/transport.py` (`put`, `read_bytes`), `anchors.py`, `lexicon.py` (`_negation` path), `storage.py` (`_facts`), `explain.py` (call to `resolve`).
- Repros run: `scratchpad/int-audit/repro1.py` to `repro9.py` (scripts outside the repository).
- Test runs listed above.

## Not reviewed

- `src/patchtrace/enrichment/` and `cli.py` (the C-04, C-05, C-09, C-10, C-11, C-23, C-24 scope of the earlier audit).
- `intelligence/csaf/discovery.py`, `csaf/normalize.py`, `csaf/identity.py`, `hypotheses.py`, `reports.py`, `tools/store.py`, `tools/runner.py`, `tools/normalize.py`, `tools/cli.py` (only through the tests).
- `rules/candidates.py`, `rules/window.py`, `rules/features.py`, `rules/masks.py` and `adapters/` (only the gate calls and the tests).
- `kev/join.py`, `kb_adapter.py`, `service.py`, `view_model.py`, `report.py`, `teach.py`, `project_context.py`, `tooltip_entries.py`.
- `fabric/store.py`, `fabric/pins.py`, `fabric/ids.py`, `fabric/cli.py`, `fabric/contracts.py` (SQL is parameterised: checked by grep only).
- `pilot/sources/advisory.py`, `calls.py`, `code.py`, `kev.py`, `pe.py`, `unified.py`, `window.py`, `snapshot.py`, `identity.py`; `pilot/ranking.py`, `tiers.py`, `quality.py`, `why.py`, `read_model.py`, `report.py`, `review.py`, `keys.py`, `collect.py`, `service.py`, `cli.py`, `panel.py`.
- Windows behaviour of every path above (no Windows host). Frozen build, PyInstaller, and Job Object containment (covered by the process-supervision audit).
- Live network checks (CISA, MSRC, NVD) and the live tools workflow.
