# Slice card INT-1 - advisory interpretation: withdrawn claims, untested validation, CVSS consistency, redirect refusal

Evidence and designs: `jq '.actionable_now[] | select(.id=="C-T01" or .id=="C-T07" or .id=="C-T12" or .id=="C-T04")' docs/status/inventory/C.json`
and the matching defects `jq '.features[].defects[]? | select(.id=="C-D01" or .id=="C-D05" or .id=="C-D10")' docs/status/inventory/C.json` (read the
whole defect entries: each was reproduced offline on main with a script kept under <scratch>/inventory/tmp-C/).
Specs: docs/specs/csaf-cve-interpretation-engine.md, docs/specs/kb/vendor-feeds-and-source-matrix-spec.md (section 11
acceptance line about listing untested validation), docs/specs/network-egress-privacy.md.

Items, one commit each, red test first, spec sentence first where behaviour changes:

1. C-T01 (C-D01) - `patchtrace intelligence explain` and its exports report a WITHDRAWN vendor claim as the current
   resolution (affected / fixed): src/patchtrace/intelligence/explain.py does not pass the store-wide supersession map
   to applicability.resolve (open tracker item tasks/todo.md:212). Pass it; a withdrawn or superseded claim must be shown
   as withdrawn/superseded with its successor, never as the current answer. Golden fixtures under
   tests/fixtures/csaf/expected/ may legitimately change: show the exact diff in your report, do not regenerate blindly.
   Test tests/test_intel_explain.py.
2. C-T07 - a CSAF document with an inconsistent CVSS object is accepted and nothing printed says that mandatory tests
   6.1.8-6.1.13 were not run. Tell the user which CSAF validation tests were NOT run (limitations list in the explain
   report and the CLI output: src/patchtrace/intelligence/explain.py, intelligence/cli.py). New test
   tests/test_intel_limitations_list_untested_validation.py. Unknown is not a negative vote: the text must say "not
   checked", never "passed".
3. C-T12 - implement CSAF mandatory tests 6.1.9 (CVSS v3 base score matches the vector) and 6.1.10 (severity matches the
   score) in src/patchtrace/intelligence/csaf/validate.py as WARNINGS, not rejections (spec question Q2 is open: whether
   they reject is an owner decision - record that in the spec). Pure arithmetic, no network: implement the CVSS v3.0/3.1
   base-score formula from the FIRST specification exactly (roundup as specified; test against the published example
   vectors you know with certainty, e.g. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8, and a scope-changed vector = 10.0;
   mark any example you are not certain of as such and prefer property tests: score in [0, 10], monotone in each
   impact metric). After this item the limitations list of item 2 must no longer name 6.1.9 and 6.1.10.
4. C-T04 (C-D05) - src/patchtrace/intelligence/csaf/transport.py: a malformed redirect Location raises a raw ValueError
   from urljoin (the twin fix ACQ-1 in the acquisition transport skipped this one). Make it the typed refusal the
   transport uses for other bad redirects; look at how acquisition's transport fixed ACQ-1 and mirror it. Test
   tests/test_intel_transport.py with a local fake response (no network).

## Owned files
src/patchtrace/intelligence/explain.py, src/patchtrace/intelligence/cli.py, src/patchtrace/intelligence/csaf/validate.py,
src/patchtrace/intelligence/csaf/transport.py, docs/specs/csaf-cve-interpretation-engine.md,
tests/test_intel_explain.py, tests/test_intel_validate.py, tests/test_intel_transport.py,
tests/test_intel_limitations_list_untested_validation.py (new), golden files under tests/fixtures/csaf/expected/ that
item 1 legitimately changes, generated intelligence schemas if a model changes (tools/generate_intelligence_schemas.py).
NOT yours: src/patchtrace/intelligence/tools/** (another session), src/patchtrace/enrichment/** and kev/** (slice
INT-2), src/patchtrace/cli.py, tasks/todo.md (report the tracker rows instead).
