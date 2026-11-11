# Slice card ST - machine-readable project status and its generated report (stdlib tool + drift test)

## Purpose
The owner asked for a continuously updated, evidence-based status: completion per feature, remaining effort, open defects
by severity, test status, accuracy, GUI/CLI parity, release readiness, blockers - with implementation completion kept
separate from validation completion and NO blended or invented numbers. Seventeen read-only analysts are writing one
inventory JSON per workstream; nine exist now, the rest arrive later. Build the tool that turns those files into the
status documents, deterministically, so every later update is one command.

## Inputs (already produced; copy them into the repository as part of this slice)
- docs/status/inventory/<KEY>.json for KEY in A B C D E F G H I1 I2 I3 J K L R T1 T2 (present now: B C D E F I1 K T1; the tool must
  work with any subset and list the missing keys as "not yet inventoried"). Shape: see docs/plans/production-completion-20261111/briefs/COMMON.md section
  "Output" (features[], actionable_now[], notes; T1/T2 also carry items[] and counts{}). Analysts sometimes add extra
  keys (pct_basis, checks, main_versus_branches): preserve unknown keys, never fail on them.
- docs/status/inventory/<KEY>.json (key "completion"): {KEY: {completion: {implementation_pct, validation_pct, basis}, external_blockers[],
  critical_defects[], summary, ...}} - each analyst's COUNTED completion with its basis sentence. Merge each entry into the
  corresponding repository copy under a top-level key "completion" (and "external_blockers", "summary") so one file per
  workstream is self-contained.
- docs/status/gui-cli-parity-matrix.md: the GUI/CLI parity matrix (copy to docs/status/gui-cli-parity-matrix.md unchanged except
  for a one-line generated-from header).

## Outputs
1. docs/status/inventory/<KEY>.json - the copies above (pretty-printed, sorted keys NOT required; keep the analysts'
   order; UTF-8, LF, trailing newline). Strip machine-local absolute paths: replace the scratchpad prefix
   "<scratch>/" by "scratch:/" everywhere in string values (they are evidence pointers that will not exist later).
2. tools/status/build_status.py (stdlib only, no third-party import, no network, no clock: a date comes only from the
   `--as-of YYYY-MM-DD` argument or from docs/status/meta.json):
   `python tools/status/build_status.py` regenerates everything below from docs/status/inventory/*.json,
   docs/status/meta.json and docs/status/slices.json; `--check` writes nothing and exits 1 listing the files that
   differ (exit 2 on bad arguments or malformed input, with the file and reason). Deterministic bytes.
3. docs/status/status.json (generated) - the machine-readable roll-up: baseline commit and date from meta.json; per
   workstream: title, counts of features by status, the analyst's counted completion (implementation_pct,
   validation_pct, basis) copied verbatim, sum of effort_hours over features that are not "implemented" (label it
   "analyst estimate, hours"), number of features per evidence_class, open defects by severity (features[].defects),
   blockers by type, number of actionable_now tasks; tracker counts (from T1/T2 "counts"); project totals that are pure
   sums (features by status, defects by severity, blockers by type, effort hours) - and NO project-wide completion
   percentage: the file must instead carry "completion_measures": a list of separately labelled measures (each
   workstream's counted completion; tracker measure; security-backlog measure from I1; GUI/CLI parity measure from F if
   its basis is present) each with its own basis string. Never average across measures.
4. docs/status/README.md (generated) - the status report a person reads first. Sections, in this order:
   "How to read this" (5 lines: evidence classes mocked / synthetic / fixture / live-native are never mixed;
   implementation and validation are different numbers; a missing workstream is not zero);
   "Completion by workstream" (table: workstream, features, implemented / partial / missing / blocked-external /
   deferred, implementation %, validation %, basis shortened to 160 characters with the full text in status.json);
   "Remaining effort" (hours per workstream, labelled analyst estimate, with the count of features it covers);
   "Open defects by severity" (counts table, then every critical and high defect with id, one-line summary, evidence
   pointer and owning workstream);
   "External blockers" (deduplicated list grouped by type: external-tool, windows-only, live-network, owner-decision,
   other-lane);
   "Tracker" (T1/T2 counts by state and by blocked_by when present);
   "Slices built by the completion session" (from docs/status/slices.json: id, title, state, branch or PR, verification
   evidence text) - the file is maintained by hand; create it with an empty list and document its shape in a comment-free
   docs/status/slices.schema.md paragraph inside README's "How to regenerate" section;
   "Not yet inventoried" (missing keys);
   "How to regenerate" (the two commands).
   Markdown only, no HTML, tables with pipes, text escaped so a "|" or newline inside a value cannot break a row; every
   value that came from an analyst is data, not markup: escape backticks imbalance and strip control characters.
5. docs/status/inventory.md (generated) - one table per workstream: feature id, name, status, implementation %,
   validation %, evidence class, first two "remaining" entries (shortened), blocker types, effort hours, confidence,
   active-lane overlap.
6. docs/status/defects.md (generated) - every open defect from every workstream sorted by severity then id: id,
   severity, workstream, summary, evidence, failure scenario, proposed fix, regression test (shortened to 300 characters
   per cell; full text stays in the JSON).
7. docs/status/meta.json (hand-maintained, create it): {"baseline_commit": "882d1ca0b4190bccddb6ce1f66b46c4db856703b",
   "baseline_date": "2026-11-09", "as_of": "2026-11-11", "session": "sleepy-fermi"}.
8. tests/test_status_docs.py: (a) regenerate-and-compare: run the generator into a temp directory from the committed
   inputs and compare every generated file byte for byte with the committed one (the repository's standard drift
   pattern - look at how tests/test_*schemas*.py do it); (b) input validation: every inventory file parses, has the
   required keys, every percentage is within 0..100, every status / severity / evidence_class value is from the allowed
   set or is reported in a "nonconforming" list that the test prints and bounds (analyst files are data: do not fail on
   an unexpected extra key, do fail on a missing required one); (c) status.json has no key named like an overall or
   blended completion percentage; (d) `--check` exits 1 after a generated file is altered in a TEMP COPY and 0 on the
   clean tree; (e) a hostile value (pipe, newline, backtick, U+202E) in a temp inventory cannot break a table row or
   survive as a control character.

## Rules
Read docs/plans/production-completion-20261111/briefs/IMPL-COMMON.md first (binding). Red first where it applies (write the tests with the generator absent or
stubbed and see them fail). tools/ has no __init__.py: follow how other tools/*.py scripts are invoked and tested
(`grep -rn "tools/generate_schemas\|import tools\." tests | head`). Line length 110, ruff clean. No dependency on
anything under src/patchtrace. Keep the tool under about 400 lines; prefer small pure functions; no cleverness.
The generated documents must make no claim the inputs do not support: where an input lacks a field, print "not stated".

## Owned files
tools/status/build_status.py (new), tests/test_status_docs.py (new), everything under docs/status/ (new directory).
NOT yours: every other file. .gitattributes is frozen: put the line "docs/status/** text eol=lf" under
"Integrator asks".
