# Multi-engine evidence UI: prior art and fit for SPEC-28 (C6)

Date: 2026-10-14. Scope: how diffing tools and the literature present several engines' results side by side without merging incomparable scores, and how a Qt (PySide6) table stays responsive at about 10,000 matches. Reads `docs/specs/multi-engine-evidence-panel.md` (SPEC-28) as the baseline.

Verification note: `doc.qt.io` and `ghidradocs.com` were not fetchable from this sandbox. Qt and Ghidra statements below come from search snippets and are marked "snippet". Licenses marked "repo page" were read from the GitHub page; others are from memory and flagged. Nothing here was re-verified against a running tool.

## 1. Findings table

| # | Source (link) | License | Concrete idea | Application to PatchTrace |
|---|---|---|---|---|
| 1 | Ghidra VT Matches table, [ghidradocs 12.1.2](https://ghidradocs.com/12.1.2_PUBLIC/help/VersionTracking/help/topics/VersionTrackingPlugin/providers/VT_Matches_Table.html) (snippet) | Ghidra: Apache-2.0 (memory, verify) | One table holds every match from every correlator. Scores are shown as aids, and the docs say not every correlator match is correct. Acceptance is a separate act from the match itself. | Keep one row per function pair. Ghidriff's match type stays its own column. Add "accepted in Ghidra" as a separate attribute, not as a verdict input. |
| 2 | Ghidra VT Related Matches table, [ghidradocs 9.2](https://ghidradocs.com/9.2_PUBLIC/help/VersionTracking/help/topics/VersionTrackingPlugin/providers/VT_Related_Associations_Table.html) (snippet) | Apache-2.0 (memory, verify) | Lists only the alternatives for the function under the cursor, not the whole table. | The spec's "Alternatives" block in the detail pane is the right shape. Keep it per selected row and load it lazily. |
| 3 | Ghidra VT Introduction, [ghidradocs 9.2](https://ghidradocs.com/9.2_PUBLIC/help/VersionTracking/help/topics/VersionTrackingPlugin/Version_Tracking_Intro.html) (snippet) | Apache-2.0 (memory, verify) | Accepting one match blocks conflicting related matches. Acceptance changes what other matches mean. | Do not let a user accept or override in the panel in v1. An override would turn the panel into a decision tool and blur the "evidence" framing. |
| 4 | ghidriff, [github.com/clearbluejar/ghidriff](https://github.com/clearbluejar/ghidriff) | GPL-3.0 (repo page) | Results are stored as JSON and rendered to markdown or side-by-side HTML. The JSON is a stable intermediate. | Ingest ghidriff's JSON as the Ghidriff source. Do not copy its code while PatchTrace's license is unresolved (section 5). |
| 5 | Diaphora, [github.com/joxeankoret/diaphora](https://github.com/joxeankoret/diaphora) | AGPL-3.0 (repo page) | Similarity ratio per match, with side-by-side pseudo-code diff. The README does not describe a match-list layout. | Borrow the idea of a per-match ratio shown next to a pseudo-code diff in the detail pane. Do not reuse its code (AGPL). |
| 6 | BinDiff manual, [zynamics.com/bindiff/manual](https://www.zynamics.com/bindiff/manual/index.html) (TOC only) | Proprietary (Google/Zynamics) | Matched Functions subview. Each match has similarity, a confidence value, and the name of the algorithm that produced it. | Import BinExport or BinDiff output as a read-only source. Show the algorithm name next to the number (see flag F1). |
| 7 | BinDiff secondary: [arXiv 2608.05350](https://arxiv.org/pdf/2608.05350) and [arXiv 1601.00763](https://arxiv.org/pdf/1601.00763) (secondary) | arXiv: per-paper | Confidence is a function of the matching algorithm, and its ranking is not fully documented. Thresholds such as 0.95 are used by analysts, not by the tool. | Supports flag F1: BinDiff's confidence is an ordering aid tied to the algorithm, not a calibrated probability. |
| 8 | rz-diff in Rizin, [github.com/rizinorg/rizin](https://github.com/rizinorg/rizin) | LGPL-3.0 / GPL-3.0 (repo page) | Compares two binaries as raw data or as analyzed executables. This is a different evidence class from function-level matching. | Keep rz-diff under its own engine column, labelled by its mode (raw or analyzed). Do not put its byte similarity in the same column as function similarity. |
| 9 | W3C, [Understanding SC 1.4.1 Use of Color](https://w3.org/WAI/WCAG21/Understanding/use-of-color) | W3C document license | Information carried by color needs a text or other visual cue (techniques G14, G182). The WCAG 2.2 page is the current one. | Verdict badges already carry text and a glyph (spec 0.7). Add a test that the badge's accessible name contains the verdict word. |
| 10 | Correll & Gleicher, [Error Bars Considered Harmful (IEEE TVCG 20(12), 2014)](https://graphics.cs.wisc.edu/Papers/2014/CG14/Error%20Bars%20Considered%20Harmful%20Exploring%20Alternate%20Encodings%20for%20Mean%20and%20Error.pdf) (abstract and captions read) | Paper, all rights reserved | Summary encodings (mean plus error bar) change how viewers decide. Alternatives such as gradient plots or violin plots show the spread without a single summary. | Show the set of engine verdicts as-is. A "consensus" glyph would be the summary encoding the paper warns against. |
| 11 | Chow 1970, "On optimum recognition error and reject tradeoff", [DBLP](https://dblp.org/pid/85/786) (bibliographic) | IEEE, bibliographic only | A reject (abstain) option is optimal only if the confidence scores are true posteriors. The reject rule is derived from that assumption. | Keep "unknown" as an explicit abstain state. Do not derive a reject threshold from the SPEC-27 triage index, which is uncalibrated (flag F2). |
| 12 | Qt 6 QSortFilterProxyModel, [doc.qt.io](https://doc.qt.io/qt-6/qsortfilterproxymodel.html) (snippet, not fetched) | Qt: LGPL-3.0 or commercial (memory, verify) | Warns against updating the source model through the proxy while dynamic sorting is on. Calling `invalidateFilter()` repeatedly may be slower than `reset()`, but `reset()` loses selection. | Matches the spec's `setDynamicSortFilter(False)` and precomputed-index filter. Restore the selected match by id after each reset (section 3). |
| 13 | PyQt list, data() call count after setSourceModel, [riverbank 2010](https://riverbankcomputing.com/pipermail/pyqt/2010-May/026659.html) (old, snippet) | Mailing list | A 555-row model made over 3 million `data()` calls on one reset, about 15 s. Possibly outdated. | Strongest reason to add a data()-call counter to the perf test. The spec's "<30 ms at 10k" claim is not measured yet (flag F4). |

Sources cited: 13 rows, of which 4 were fetched directly (ghidriff, Diaphora, rizin, BinDiff-adjacent arXiv via search only). The rest were search snippets or memory.

## 2. Ideas worth adopting

1. **Keep per-engine columns in native units, with no shared color scale.** This matches the spec's rule 1 and the Ghidra matches table, which lists scores without normalizing them across correlators. The table layout is already the right answer; no change is needed.
2. **"Alternatives" as a lazily loaded, per-row detail list** (Ghidra Related Matches). Do not put alternatives in the main table. Load them for the selected row only, which keeps 10k rows cheap.
3. **Treat "unknown" as an explicit abstain state** (Chow's reject option, spec's `Unknown`). Give it its own badge and keep it out of any sort order that implies a score. Sort unknown rows by name or address, not by a numeric key.
4. **Use the engine's raw match type or algorithm name as the cell text** (ghidriff match types, BinDiff algorithm name). This is more honest than a derived "quality" word. The spec currently labels a column "type / quality"; drop "quality" (flag F3).
5. **Raw JSON as the ingestion contract.** Ghidriff already writes JSON, and BinExport is a stable binary format. Both let the service read persisted results without re-running engines. This fits the spec's "read-only over stored reconciliation" rule.
6. **Separate evidence classes into separate columns.** rz-diff's raw-data mode and function-level matching measure different things. Labelling each engine column with its mode (raw or analyzed) prevents an analyst from treating them as comparable.

## 3. Pitfalls

1. **Selection is lost on model reset.** The spec does one `beginResetModel/endResetModel` per load, which is correct. The detail pane must store the selected `match_id` and reselect that row afterward, or the pane flickers to empty. Qt's `reset()` docs note that selection information is lost (snippet).
2. **Filtering with Python callbacks is slow at 10k.** `filterAcceptsRow` runs once per row in Python. The spec's precomputed `frozenset[int]` avoids that. Do not let the filter fall back to a per-row Python call in the proxy.
3. **Data-call storms.** The 2010 PyQt report shows that a reset can trigger millions of `data()` calls. Put a counter in the perf test (e.g. wrap the model's `data()` with a counting subclass) and fail the test on O(rows × columns) calls per paint.
4. **Tooltip-driven information is not keyboard-accessible.** The spec puts full evidence in the detail pane, which is correct. Ensure every tooltip fact is also reachable by keyboard focus in that pane.
5. **Glyph choice.** The spec uses ASCII-like markers such as `[=]`, `[!]`, `[1]`, `[?]`. Keep this set. Unicode symbols can render as boxes on some Windows fonts, which is a risk for the Windows alpha. Verify on Windows before adopting any new glyph.
6. **Confidence numbers invite probability reading.** A decimal confidence printed next to a similarity score reads as a probability even when the tool does not claim one. The spec's banned-string test covers `probab` and `likelihood`, but not this pattern (see F1).
7. **License contamination.** Reusing code from ghidriff (GPL-3.0), Diaphora (AGPL-3.0), or Rizin (LGPL/GPL) could impose copyleft terms. Use these only as format or idea references until PatchTrace's license is confirmed.
8. **Reject thresholds from uncalibrated scores.** Chow's rule assumes calibrated posteriors. Any abstain threshold built on the SPEC-27 index would be arbitrary.

## 4. Flags: what SPEC-28 should change

- **F1 (BinDiff confidence).** The wireframe shows `sim 0.97 conf 0.91` for BinDiff. BinDiff's confidence is tied to the matching algorithm and is not documented as a probability (section 1, rows 6 and 7). Change the cell to show the algorithm name and similarity only, or show the raw confidence label without a decimal. Add the algorithm name to the detail pane.
- **F2 (triage index denominator).** The detail line `Triage index 55 of 83` implies a percentage-like scale. Drop "of 83" and show the raw number only, with the existing "uncalibrated" wording. Consider not showing the index at all unless the user asks.
- **F3 (strength wording).** The column header "type / quality" uses a judgement word. Change it to "match type" and show the engine's raw type string.
- **F4 (unmeasured performance claim).** The spec says filter recompute is "measured < 30 ms at 10k". No such measurement appears in the repo as far as this review saw. Turn it into a test gate: 10k rows, filter and sort timings, and a `data()` call-count ceiling.
- **F5 (selection restore).** Add an explicit requirement that the detail pane's selected `match_id` survives every reset and every filter change.
- **F6 (Ghidra acceptance).** Add a separate "accepted in Ghidra" attribute to the Ghidriff row. Do not fold it into the verdict. Ghidra's own docs say acceptance is a decision, not evidence (row 3).
- **F7 (rz-diff column).** Label the rz-diff column with its mode (raw or analyzed). Byte similarity and function similarity must not share a column.
- **F8 (unknown sort order).** Specify that `Unknown` and `not-run` rows sort by name or address, never by a score key.

Confirmed as correct (no change needed): per-engine native units, no merged score, `contested` on any dissent, `missing != negative`, text plus glyph on every badge, plain-text rendering of tool output, `setDynamicSortFilter(False)` with an index set from `filter_rows`.

## 5. Open questions

1. **PatchTrace's license.** This determines whether any code from ghidriff, Diaphora or Rizin can be reused, or only their formats and ideas. Not found in the files reviewed; the owner needs to confirm.
2. **Stable match keys across runs.** Does the ghidriff JSON carry stable function identifiers (address pairs plus binary hashes) that can join to SPEC-26's stored records without re-running Ghidra? Needs a sample file.
3. **rz-diff output format.** Does rz-diff emit per-function similarity, or only whole-binary or byte-level results? The column design depends on it. Needs a local run.
4. **BinDiff confidence semantics.** The manual's Confidence/Similarity section was not retrieved. Read it before finalizing F1.
5. **Qt 6 specifics.** `doc.qt.io` was unreachable. The dynamic-sort and reset notes should be checked against the Qt 6 and PySide6 docs before the perf gate is written.
6. **Analyst workflow.** Does the analyst need to sort across engine columns at once, or is per-column sort enough? The spec assumes per-column.
7. **Windows glyph rendering.** Confirm the marker set renders in the Windows standalone build's default fonts.
