# Tier R Windows path and schema repair — November 2, 2026

Source `4edf8f4c1f7272d408ffcbbd236b6e32b6fb4cdd`, tree
`02d62801e9c1c3fdde61c71e8b4222fe08d7719a`, based on central
`eccfb8d587f94e927f857fad248531a002ecc36c`.

The exact hosted Windows failure evidence was read from
`reconciliation/ci-monitor-20261102/windows-51a9b4af-failure-tracebacks.txt` and
the sibling JUnit receipt. That run used source
`51a9b4af02acb6078f8e06028aa4374eb381766f`, job `125172583133`, workflow run
`41413769950`. Its JUnit recorded 19,272 passing cases, eight failures and 90
skips. This slice owns four of those failures plus the subsequently assigned
credit-completion diagnostic-path expectation; other failures remain separately
owned. The original native failures are not replaced by local modeled results.

The two `TrainingManifest.json` drift failures are production newline behavior:
the new writer omitted the explicit LF argument already used by sibling schema
writers. The fix writes UTF-8/LF on every platform. A portable test supplies a
Windows CRLF text default and reproduces the original mismatch before the fix;
exact-byte schema comparison remains intact.

The explicit output-directory and uncredited-report path expectations are fixture
errors: production intentionally emits `Path.as_posix()` for JSON paths. Both
tests now assert the complete forward-slash representation rather than native
`str(Path)` separators. Fresh-directory refusal, original-byte preservation,
failed completion and uncredited diagnostic checks are unchanged.

The hosted failed-evaluator CLI case also reported `producer artifact is outside
its shard scratch` and emitted `verified_training=false`. The evaluator resolves
its store path, while the transfer reader previously compared only `abspath`
spellings. Nonlinked Windows short/long aliases can therefore name the same
scratch directory with different prefixes. The original native log does not print
both path spellings, so this cause remains a source-backed inference pending a
fresh Windows run. A portable alias model reproduced the exact refusal through
the actual export consumer using real labels, report and managed-output bytes.

`inside` now checks both original lexical paths before resolution, compares the
canonical paths for containment, binds each canonical leaf to its original
device/inode, and rechecks all original parent/leaf identities. Resolving cannot
hide an unchecked link or reparse component before `..`. Existing destinations,
outside-source files, changed identities, case ownership and report/output credit
checks remain fail-closed. The alias control completes actual export, bundle
verification and `train.load_outputs(..., allow_legacy=False)`. Additional controls
refuse a byte-identical report outside scratch, real scratch-link/.. traversal,
modeled Windows reparse/.. traversal, and scratch/report identity substitution
during canonicalization before any destination exists.

Primary API references: [pathlib resolve/absolute semantics](https://docs.python.org/3.12/library/pathlib.html#pathlib.Path.resolve),
[canonical Windows short-name handling](https://docs.python.org/3/library/os.path.html#os.path.realpath),
and the local Python 3.12 `ntpath.py` implementation (`_getfullpathname` for
abspath versus `_getfinalpathname` for realpath). These explain the distinction;
they do not constitute native acceptance of this patch.

Author command (shared Python, offscreen Qt, `PYTHONPATH=.:src:tests`):

```text
pytest -q tests/test_tier_r_training_artifacts.py
  tests/test_tier_r_output_persistence.py tests/test_tier_r_eval_cli.py
  tests/test_tier_r_shard.py tests/test_tier_r_credited_replay.py
  tests/test_tier_r_output_stat_compat.py tests/test_workflows.py
  tests/test_tier_r_credit_completion.py
```

**290 passed, 2 skipped, 3 expected legacy-output warnings in 9.43s**. Both skips
explicitly report missing `msvc-free` native tools as BLOCKED. Whole-repository
Ruff and `git diff --check` passed. No native engine, target binary, training fit
or final evaluation was run.

Independent review at exact source `4edf8f4` found no blocking issue. The reviewer
ran **290 bounded tests**, deliberately deselecting the two compiler-backed tests
under the no-native scope, plus **seven additional controls**. Those controls
covered aliases on both scratch and producer paths, ordinary `..`, report-link
and reparse-before-`..` refusal, an outside same-inode hardlink, changed original
ancestor identity, and an alias hiding a canonical Tier W path. The final tests
reproduced the original LF/alias failures against the baseline while existing
link/reparse controls continued to pass. Ruff and diff checks passed. The
coordinator owns `reviews-resume/windows-output-review-20261102.{md,json}`.
These overlapping selections are not added into a combined-suite total.

Fresh Windows execution remains a separate gate; no full-suite/native/release
acceptance is claimed. No remote mutation was performed by this worker.
