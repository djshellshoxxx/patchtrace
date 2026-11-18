# Slice card NA-1 - rz-diff: refuse results whose side ownership is ambiguous (B-D01, severity high), then adapter fidelity (B-D06/SEC-8, B-D09)

Evidence and designs (read all of it): `jq '.actionable_now[] | select(.id=="B-T01" or .id=="B-T05")' docs/status/inventory/B.json`,
`jq '.features[].defects[]? | select(.id=="B-D01" or .id=="B-D06" or .id=="B-D09")' docs/status/inventory/B.json`,
`jq '.features[] | select(.id=="B-F05" or .id=="B-F06")' docs/status/inventory/B.json` (B-F06.main_versus_branches explains what is on main and what
exists only on branches). Spec: docs/specs/secondary-engine.md (section 8 holds the research controls).
Handoffs: docs/handoff/rzdiff-native-red-control.md, docs/handoff/rzdiff-producer-implementation.md.

## Background (verified by the analyst on main 882d1ca0)
Stock Rizin 0.9.1 `rz-diff` takes a singleton branch in rz_analysis_match_functions when the first list has exactly one
function and returns the matched pairs and unmatched lists SWAPPED; the JSON then reports a newer-only function under
"original". src/patchtrace/secondary/rzdiff.py (about lines 119-120) maps original -> older and modified -> newer with no
guard, so main stores the swapped set as correct; reconcile then reports wrong-side agreement or disagreement. The JSON
for the 1:2 and 2:1 inputs is byte-identical, so the swap CANNOT be detected or undone from the output: a global parser
swap would corrupt every ordinary result and must never be implemented.

## Item 1 (B-T01) - refuse, never swap
Spec first: amend docs/specs/secondary-engine.md with the rule: a result whose shape is one the singleton defect can
produce is refused for producers without a qualified ownership fix - when the "modified" side holds at most one distinct
function across matched and one-sided rows (the analyst's exact condition; re-derive it from the retained evidence and
state the final condition precisely in the spec), parse_output raises SecondaryError PT-SECONDARY-ORIENTATION with kind
`rzdiff-singleton-ownership`; every other shape parses unchanged. Do NOT port the version-wide quarantine of the
unmerged PRs #163/#164 and do not touch unified/**.
Evidence shapes: four retained stdout shapes exist on the branch origin/qualify/native-cli-seeding-20261105 under
docs/qa/native-cli-20261105/ (read-only: `git -C <worktree> ls-tree -r --name-only origin/qualify/native-cli-seeding-20261105 docs/qa/native-cli-20261105 | head -80`
and `git -C <worktree> show origin/qualify/native-cli-seeding-20261105:<path>`). Build the fixture
tests/fixtures/secondary/rzdiff-singleton-shapes.json from them, recording for each shape its provenance (branch, path,
SHA-256 of the retained stdout) - these are real native outputs of stock rz-diff captured by another session; label them
as retained native evidence, not as something this slice ran. If the retained files cannot be found, stop and report;
do not invent rz-diff output.
Acceptance: shapes 1:1, 1:2 and 2:1 are refused with the code and kind above; 2:2 and the corrected
1-original/2-modified shape parse byte-identically to main; at scheduler level (tests/test_secondary_scheduler.py) the
run outcome is `failed` with error_code PT-SECONDARY-ORIENTATION and NOTHING is published or stored; the 66 existing
tests in tests/test_secondary_rzdiff.py stay green; tests/test_live_rzdiff_check.py stays green (the live fixture pair
has several functions on both sides). The user-facing message must say what happened and what the analyst can do
(use another engine for this pair; the result was not stored), without claiming the pair is wrong.
Report under open_risks: true N-versus-1 pairs are now refused (conservative); whether to add a version-wide quarantine
is an owner decision.

## Item 2 (B-T05) - adapter fidelity
Same files plus src/patchtrace/secondary/registry.py. Byte-exact stdout handling (a valid U+FFFD in a function name
parses; invalid bytes are refused, not silently replaced), output_sha256 equals the SHA-256 of the captured bytes, empty
stdout with the "No functions found" marker gives failure kind `no-functions`, provenance gains executable_sha256 and
untested_version for a version outside the tested 0.9.x range. Provenance is an append-only optional field (16 keys, 256
characters): existing stored rows must stay byte-identical when nothing new is recorded - pin that with a test. If a
contract model changes, regenerate the schemas (`grep -ln secondary tools/generate_*schemas.py tools/generate_schemas.py`).

## Owned files
src/patchtrace/secondary/rzdiff.py, src/patchtrace/secondary/contracts.py, src/patchtrace/secondary/registry.py,
docs/specs/secondary-engine.md, tests/test_secondary_rzdiff.py, tests/test_secondary_scheduler.py,
tests/test_secondary_runs.py, tests/fixtures/secondary/rzdiff-singleton-shapes.json (new, LF), generated schema files.
NOT yours: src/patchtrace/secondary/bindiff*.py and runs.py and bindiff_probe.py (slices NA-2 and SEC-B),
src/patchtrace/secondary/reconcile.py, tools/rzdiff/** and .github/workflows/** (other sessions), unified/**.
