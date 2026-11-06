# Preregistration fence-prefix consolidation — November 2, 2026

Base: PR #154 at `f27d23a80ee49573ccca54cdf036427f57eebb2a`, tree
`8ef0a587631bd830ddb44f6a1fdaf1f698ab0f9b`.

## Scope and reasoning

The two `_FENCE.match` call sites consume only the marker prefix in capture 1.
Both receive an LF-free line produced by `str.splitlines()`, or concatenated
substrings of that same line. The trailing capture and end assertion contribute
no information to fence opening or closing decisions.

This change removes that unused suffix from the expression. For its actual
call-site domain, acceptance and the returned marker are unchanged. The pattern
now matches a fixed, bounded indentation followed by one contiguous marker run;
there is no overlapping trailing wildcard to backtrack into the marker run.
Fence closing, comment visibility, inline code, complete digest cells and the
original visible column-zero requirement retain their existing logic.

The previously preserved `prereg-fence-audit-20261102.tar.gz` on the combined
candidate established that the original expression's warned slow case was not
reachable at these call sites. This cleanup therefore does **not** claim a
demonstrated exploitable issue in PR #154. It removes an unnecessary expression
shape while preserving the existing supported record grammar.

## Verification

- The exact PR base was materialized from existing Git objects plus 24 missing
  blobs recovered through the GitHub connector. Every recovered blob was
  checked against its original Git object ID; checkout was clean before editing.
- Baseline protocol selection, preregistration tools and frozen-constant tests:
  **138 passed**, no failures, errors or skips (pytest 1.62 seconds).
- A separate bounded equivalence check compared the old and new marker result
  on **20,371 LF-free strings**. It included all strings of length zero through
  six over a five-character marker/space/tab/prose alphabet, and constructed
  indentation, marker-length and suffix cases. Every result agreed.
- The same three test modules after the change: **138 passed**, no failures,
  errors or skips (pytest 1.42 seconds).
- Whole-tree `python -m ruff check src tests tools`: passed.
- `git diff --check`: passed.

Commands for the focused acceptance selection:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests python -m pytest -q \
  tests/test_train_prereg_selection.py \
  tests/test_prereg_tools.py \
  tests/test_prereg_constants.py
python -m ruff check src tests tools
git diff --check
```

The final source file SHA-256 is
`13d050ab8d3b00786f2fcb70e19372dfd32d76bc69c6d2d34c7af1ee6ee747f3`.
No real corpus, locked final evaluation, owner approval, frozen protocol,
numeric threshold, workflow or scanner configuration was changed or consumed.

## Remaining qualification

The current PR #154 check `124877284805` still reports a failed SonarCloud
security quality condition and two annotations. The connector refused reads of
its annotations endpoint, so this check's detailed dataflow was not available
in this review. The preserved audit identifies the fence-expression annotation
and a separate generic `qa_path` traversal annotation. Arbitrary user-selected
local QA-file reads alone do not establish an unauthorized authority boundary;
no path restriction or scanner suppression was invented.

Fresh hosted checks and independent review of this source change remain
required. The old green full QA/package results qualify only the original PR
tree. This note does not mark the Sonar result cleared or the project complete.
