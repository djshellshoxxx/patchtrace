# Slice card SEC-A - deep JSON must fail typed, never with RecursionError (TB-16, non-unified part)

Source finding: trust-boundary audit follow-up TB-16 (medium), verified on main 882d1ca0 by the security-backlog analyst.
Full evidence: `jq '.actionable_now[] | select(.id=="I1-T01")' docs/status/inventory/I1.json` and
`jq '.features[] | select(.id=="I1-F01") | .defects[] | select(.id=="TB-16")' docs/status/inventory/I1.json`.

## Goal
Every plain `json.loads` / `json.load` site that reads data from outside the process (child-process output, project files a
second user can edit, imported documents, bundle manifests) must turn a pathologically nested document into the module's
existing typed error or documented "unreadable" value. Today a 60,000-deep array or object raises RecursionError, which
escapes `except ValueError` handlers.

## Owned files (edit only these, plus new test files)
- src/patchtrace/reports.py
- src/patchtrace/search/service.py
- src/patchtrace/calibration/artifact.py
- src/patchtrace/diaphora/provenance.py
- src/patchtrace/raw_cleanup.py
- src/patchtrace/backend_bundle.py
- tests/test_json_recursion_boundaries.py (new)

## Not yours (other sessions' lanes) - list them under "Integrator asks" as still open
src/patchtrace/unified/extract/runner.py, src/patchtrace/unified/ir/reader.py, src/patchtrace/unified/pair_text.py,
src/patchtrace/backend.py, src/patchtrace/unified/sources/**.

## Method
1. For each owned file locate the JSON read sites named by the finding (and any other in the same file). For each, decide
   from the surrounding code what the module does today for malformed JSON (the typed error or the unreadable value). That
   is the behaviour deep JSON must get too. Follow the pattern already used on main, e.g. `except (ValueError,
   RecursionError)` in persistence.py, enrichment/cve.py, offline_bundle.py. Do not add a new shared helper unless three or
   more sites need byte-identical handling; do not change behaviour for well-formed input.
2. Red first: tests/test_json_recursion_boundaries.py, parametrized with short explicit ids over each PUBLIC entry point that
   reaches such a site, with both `"[" * 60000` and `'{"a":' * 60000`. Each case asserts the typed error / unreadable value
   and that no RecursionError escapes. Reach the site through the public function with real files in tmp_path (no mocks of
   json). Show the cases failing on the base before the fix.
3. Also grep the six files for other parser calls on untrusted text that can recurse (ast.literal_eval, pydantic
   model_validate_json on deep input) and treat them the same way if reachable; say what you found either way.

## Acceptance
- New tests red before, green after; no RecursionError from any covered entry point.
- Existing test files of the six modules stay green (find them with `grep -rl "<module name>" tests | head`).
- Ruff clean. No behaviour change for valid input. No file outside the owned list changes.
