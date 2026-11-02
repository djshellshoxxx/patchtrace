# Paired raw-summary container allocation — November 2, 2026

Base tree: `816864d631ec19ac8c0e8a273b18fda42ac01599`, local commit
`419324610bfecaa843f4ed4a0130f57383f62a65`, equal to published PR #159
`56374f867594dd923383c91ea71970cb7d24d173`.

## Reproduced problem

Hosted Windows QA job `125478350391` failed the existing 18-pixel-font
`test_summary_allocates_wrapped_lines_and_releases_short_text` assertion:
the summary rectangle `(0, 99, 333, 228)` extended below its controls rectangle
`(0, 0, 333, 258)` after narrowing the window. The label itself had adequate
height, but its enclosing controls had not reserved the full wrapped layout.

On this Linux Qt host the original 12/14/18 controls passed. Extending the same
existing test to 24 and 28 pixels reproduced the same containment defect at 28:
**1 failed, 4 passed**. Its real summary rectangle was `(0, 101, 429, 198)` inside
only `(0, 0, 429, 272)` controls. The test uses the actual EOF result, widgets,
resize, and immediate geometry assertions; no event-loop wait or assertion was
weakened.

## Repair

The existing bounded allocation loop now sets the controls' minimum height to
the larger of their layout minimum and total height-for-current-width. This
includes both the summary and wrapped input labels. Using the layout minimum
alone did not repair the reproduced case and was rejected before this commit.
The same calculation releases the previous container minimum on shorter text.
The current re-entry guard, two-pass bound, label sizing, and parent layout
activation remain intact. SPEC-26's paired-window layout paragraph records the
enclosing-container requirement.

## Verification

- Immediate allocation/narrow resize and all five font-size controls: **7 passed**.
- Full paired raw UI, raw view-model, and representation suites: **101 passed**
  in 13.45 seconds. Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests
  python3 -m pytest -q tests/test_ui_raw_alignment.py tests/test_raw_alignment_view.py
  tests/test_representations.py`.
- Whole-tree Ruff and whitespace checks passed.
- Native Windows confirmation remains pending; this local reproduction and
  repair do not relabel the previous failed Windows run as passed.
