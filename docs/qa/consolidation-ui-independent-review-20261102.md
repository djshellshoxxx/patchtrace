# Independent paired raw-summary layout review — 2026-11-02

Reviewed commit: `b762828f5cbc644359e7fec0addd8f353e98aa11`.
Reviewed tree: `d9a7b7b3a2cb3be686cc8ebdc7fdae8145c5ccae`.
Parent: `419324610bfecaa843f4ed4a0130f57383f62a65`, the local exact-tree
snapshot of published PR #159 before this repair.

Verdict: **approve this bounded source repair; no blocking findings**.
This is an independent local review, not a GitHub review action or native
Windows acceptance. No repository files or remote state were modified.

## Source review

The six-line production change reserves the larger of the controls layout's
minimum height and total height for its current width. It preserves the existing
two-pass allocation bound, re-entry guard, parent layout activation, and width
constraints. The original containment assertions remain intact; the same test
now also exercises 24px and 28px summary fonts. The specification and author QA
note accurately limit the claim to container allocation.

## Independent local evidence

Existing summary/narrow/font controls:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests python3 -m pytest -q \
  tests/test_ui_raw_alignment.py -k 'summary or narrow or height or wrapping'
```

Result: **7 passed, 17 deselected in 3.95s**.

Four additional controls used the real Qt window, real EOF summary, and actual
layout transitions. The probe was outside the checkout:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests python3 -m pytest -q -s \
  -c pyproject.toml /tmp/test_patchtrace_ui_independent_controls.py
```

Result: **4 passed in 2.01s**. These do not add to or replace the author's
overlapping full paired-view result.

| Observation | Independent result |
|---|---|
| Repeated long/short summaries and widths 1440 → 960 → 1100 → 960 → 1440 | Valid containment throughout; the minimum returned to the same earlier values. |
| 28px font at 960px window width | Controls minimum fell from 299px for the real EOF summary to 134px for `Ready`. |
| 18px font at 960px window width | Controls minimum fell from 206px to 122px. |
| Hide the tall controls | Parent layout minimum fell from 545px to 240px. Changing the hidden label font did not reserve that space again. Reveal restored valid containment. |
| Width constraints | Requested window widths were honored; both offset fields retained their 150px maximum. |
| Resize/font/style event convergence | Maximum allocation call depth was 2, with the nested call stopped by the existing guard. Allocation calls stopped after layout processing; the guard was clear afterward. |

Whole-repository `python3 -m ruff check src tests tools` and `git diff --check`
passed. The checkout was clean and still at the exact reviewed commit/tree.

Scratch evidence: `/tmp/patchtrace-ui-independent-focused.log`,
`/tmp/patchtrace-ui-independent-controls.log`, and
`/tmp/test_patchtrace_ui_independent_controls.py`.

## Limits

Native Windows confirmation remains pending. Local Qt geometry observations do
not replace a fresh Windows run or relabel the prior hosted failure. This review
did not rerun the whole repository suite or claim interactive display-server,
packaged executable, accessibility, or release acceptance.
