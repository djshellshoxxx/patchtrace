# PR #164 rz-diff orientation: bounded investigation handoff

## Status: incomplete; quarantine unchanged; no merge

Refreshed through PR API: #163 head 6e82fd70f315b99c6798a42c9061a1424a02933e;
#164 head b58bb53debcb3323e5d8d634e09397cb7e02965f, stacked on #163.
This isolated documentation branch starts at that exact #164 head.
Neither original branch was updated. User-supplied failing workflow:
https://github.com/djshellshoxxx/patchtrace/actions/runs/41554639820
The supplied two-shard failure was not independently downloaded in this session.

## Located implementation and prior review

- src/patchtrace/secondary/rzdiff.py: probe and parse_output.
  Blob at #164: 35ad5aa6ce1775d2c74679cd990b653fa21ce723.
- src/patchtrace/secondary/contracts.py: rzdiff_orientation_unverified and warning.
- tools/live_rzdiff_check.py: blocked native gate.
- tests/test_rzdiff_orientation_20261101.py (blob 1b830225545c48db661dab69fe76147b61e95619),
  tests/test_secondary_rzdiff.py, tests/test_live_rzdiff_check.py.
- tests/fixtures/secondary/rzdiff-0.9.1-native-orientation.json.
- docs/qa/rzdiff-quarantine-independent-review-20261101.md,
  docs/qa/rzdiff-quarantine-verification-20261101.json,
  docs/qa/rzdiff-replay-final-e8319b9.json.

Read integration commit 953c0e9a8d0c01b475614928a0cd568c0577bb9c through full patches.
Its retained independent review approved defensive source e8319b9476898935dd2d3a3259e18982644991ed,
not an orientation correction. That review reports 179 passing bounded tests; this
is historical evidence, NOT tests executed here. Current branch inventory pages 1–2
and orientation PR search did not identify a reviewed unquarantine correction.
This is not exhaustive content comparison of every branch; default-branch commit
search cannot establish absence from unmerged refs.

## Root cause (from retained independent upstream-source review)

Rizin v0.9.1 librz/arch/similarity.c, blob
8544259e17a692bcb3c1d8858f104745cd0cba4c, lines 568–574:
when recovered list_a has length one, singleton callback receives list_b/list_a.
It constructs match_pair_new(fcn_a, fcn_b) after that swap.
librz/main/rz-diff.c, blob 3be455f898e91b906ed2d2307060f41c0833450e,
lines 2042–2047 and 2211–2219 serialize fcn_a as original and fcn_b as modified
without undoing the inversion. Normal callback retains argument order.
This explains conditional ownership, not a global reversal. Upstream bytes were
not freshly obtained in this session.

## Existing recorded witness and its limit

The retained replay identifies:
- one-recovered-vs-two: input0 6c8a798f89eea64c94eab84253068ba53e53aeb4bc7c3ec785147e90d3fcae7f,
  input1 a8d5944d442535f1998183524f0b98058cf0273cef9cd59357779309c9d607ac;
- two-recovered-vs-one: those same inputs reversed.
Both stdout SHA-256 values are
d5e968e689211215043851a3e06ae850a77ccaebfb32f16a7dbfb71ff908d8ab.
Identical JSON therefore cannot by itself determine side ownership.
The prior replay rejected all 27 records (20 INPUT, seven ORIENTATION).
Original recorded rz-diff executable SHA-256:
536987d5d0e5d2a35689f653502dc10f8be8751a46ef2ffd888e8d514ed9712e.
These are retained old/new *input-image* observations, not a fresh reproduction
or an old-tool/new-tool comparison performed here.

## Smallest correct change to investigate

Prefer repairing ownership at the producer's singleton pair-construction boundary:
restore caller A/B order for returned pairs, and audit unmatched lists as well.
Exact C hunk requires reading the complete callback/caller first; merely changing
argument order may violate the singleton callback's cardinality contract.
Do not globally swap parser fields or infer recovered cardinality from JSON rows.

If retaining stock 0.9.1 instead, a PatchTrace correction requires an authenticated,
same-version observation of the exact pre-serialization recovered lists and options,
bound to both input hashes and executable digest. Only that witness can select the
conditional inversion. No such proof was established here. Export/Ghidra counts,
an unrelated aflj query, address overlap, version suffix or a startup canary alone
is not sufficient. Keep unknown/ambiguous ownership refused, preserve raw bytes,
and ensure cache keys/persisted provenance cannot reuse unwitnessed results.

## Reproduction and regression acceptance to complete

With a complete checkout and approved pinned native tools, recover/regenerate the
recorded input images and verify their hashes. Never execute compared images.
Run the production invocation, retaining exact stdout, stderr, exit, executable/
library hashes, analysis settings and exact recovered inventories:

    rz-diff -C -j -t functions old.bin new.bin
    rz-diff -C -j -t functions new.bin old.bin

Matrix: recovered counts 1:1, 1:2, 2:1, 2:2, plus overlapping-address and one-sided/
unmatched controls. Distinct addresses and bytes must make ownership independently
checkable; same-byte A/A alone cannot do so. If patching producer, run identical
inputs with both original and corrected tool builds and retain both receipts.

Add executable regressions for ordinary orientation, reversed inputs, singleton
conditional inversion, and ambiguous identical JSON under opposite ownership.
Also require fail-closed missing/stale/wrong-tool/wrong-input witness tests, malformed
output/empty stdout controls, historical replay, pre-cache probe rejection, and
downstream no-vote/no-link/no-calibration behavior. No tests were added or executed
in this bounded session because source/runtime material was unavailable.

Offline selection once accessible (not run here):

    QT_QPA_PLATFORM=offscreen python -m pytest -q \
      tests/test_rzdiff_orientation_20261101.py tests/test_secondary_rzdiff.py \
      tests/test_live_rzdiff_check.py tests/test_secondary_reconcile.py \
      tests/test_secondary_evidence.py tests/test_calibration_runtime.py \
      tests/test_evidence_view.py
    python -m ruff check src tests tools

Native CI still required on the exact eventual implementation head: Linux/Windows
live rz-diff production-path checks; both Corpus Tier R shards and dependent
aggregation/training gates; relevant unified live-engine ownership tests; full
Linux/Windows QA and applicable Qt/package/smoke gates. Inspect actual evaluated
denominators and blocked/refused outcomes. Obtain independent source/provenance
review before any quarantine removal; prior quarantine review is not approval of
a new witness or corrected producer. No merge until exact-head requirements pass.

## Session execution evidence / blocker

- /mnt/data initially empty; no checkout was provisioned.
- git clone -q https://github.com/djshellshoxxx/patchtrace.git /mnt/data/patchtrace
  exited 128: Could not resolve host: github.com.
- get_file_contents returned only "successfully downloaded text file (SHA: ...)"
  strings for requested files, with no source body or local downloaded file.
  Directory listings, commit metadata and full patches remained readable.
- command -v rz-diff and command -v rizin produced no path.
- python -m pytest --version: pytest 9.0.2. No repository tests could run.
- No implementation, acceptance-threshold, workflow, pin or quarantine edits.
  No new passing-test or native-compatibility claim.

Next owner: obtain full source plus approved native runtime, inspect exact recovered
list semantics, implement one provenance-preserving strategy on an isolated branch,
then red/green regressions and native matrix above. Stop scope remains this single
orientation task; unrelated PR consolidation is not authorized by this handoff.
