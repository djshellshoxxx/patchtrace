# Strings application header help — review and integration handoff

## Source, scope and ownership

- Frozen base: `91618abec4c4f13a27fd5821a25d1500f17601e4`.
- Worker branch: `codex/patchtrace-header-help-20261121-2bad`.
- Final runtime/test source: `e9eff30f19bf6545d4796ae9a4fa63eb4c154339`.
- Complete source tree: `5e92298111e55d87d5c9438e76682a4a403106f1`.
- Ownership: the Strings panel declaration, its eight column specifications,
  existing column-help copy, corresponding GUI/WB3 specifications, and actual
  application-header/registry coverage tests. No backend, scan, comparison,
  export, persistence, schema, or workflow behavior changes.

The inherited header-help framework was present but no Strings column assigned
`tip_id`, and the panel did not register its existing eight `strings.col.*` entries.
All eight displayed headers now serve their matching registered help: Change,
String, Type, Older, Newer, Function, Cues, and Source. Display and accessible
labels stay unchanged. Header rich text is escaped by the existing registry;
cell content and cell help retain their previous behavior. Unknown/unregistered
ids continue to fall back to the title through the existing framework.

The Change help now describes the recorded comparison state, including shared
and unknown results. Function help describes a missing/unknown link without the
obsolete claim that the current UI displays an empty cell. All other existing
column copy is reused. The other application tables remain separate work.

## Ordered implementation and test history

| Commit | Purpose |
|---|---|
| `14b8be5e5f6dc86d943ec2543899c87f59185a20` | Contract-first GUI and WB3 header-help requirements |
| `7b94837929153fdc1c19e2fa15cfcc06e3b1868d` | Seventeen new application regressions and actual model-header audit observation |
| `7b9618e2acf55919a14c10afef16c97a66363f4e` | Register and assign all eight existing Strings header ids; precise copy correction |
| `56ea320c14af28df63d6b3afae649c3951f13d26` | Correct Ruff's Qt import ordering finding |
| `67a58a931df286379c621dc92df4df80d705eb0e` | Retained intermediate audit attempt using an explicit model parent index |
| `6f8ea41e9e4620c84ff9cbcd4c83c98b457f3db5` | Audit actual `QTableView` header sections without probing private list-model methods |
| `e9eff30f19bf6545d4796ae9a4fa63eb4c154339` | Exercise real host activation before checking the prepared empty Strings headers |

The audit counts help returned by real horizontal header roles. It adds no
tooltip exemption and does not count an id merely because it was declared.
`build_all_for_test()` deliberately constructs hidden controllers without their
project hook; the audit therefore shows Strings through the existing host and
checks that all eight real header sections exist before collecting help.

## Executed evidence and boundaries

All pytest commands used `QT_QPA_PLATFORM=offscreen`, the real repository tests,
and the dedicated editable environment described below. The archive records
commands, source ids, elapsed times, full output, and JUnit results.

| Source | Selection | Actual result |
|---|---|---|
| `7b948379` | The 17 new header cases, before runtime changes | **17 failed**, 33 deselected |
| `7b9618e2` | Identical 17-case selection | **17 passed**, 33 deselected |
| `7b9618e2` | `test_ui_strings_panel.py`, `test_ui_strings_run.py`, `test_strings_view_model.py` | **91 passed** |
| `56ea320c` | Complete `test_tooltips.py` | **17 passed, 1 failed**: newly added audit omitted required list-model parent argument |
| `67a58a93` | Actual registry coverage audit | **1 failed**: some list-model bindings expose that method privately |
| `6f8ea41e` | Actual registry coverage audit | **1 failed**: hidden Strings controller had not received its first project hook |
| `e9eff30f` | Actual registry coverage audit after real host activation | **1 passed** |
| `e9eff30f` | Whole-tree Ruff, dependency consistency, isolated import identity, complete-range whitespace | **Passed** |

The early Ruff I001 failure is retained. It was corrected solely by ordering
`Qt` before `QTimer`. Intermediate audit failures were test-harness assumptions,
not failures of the runtime header mappings; their raw evidence remains intact.
The 17 new cases overlap the 91-case maintained selection. The final audit
overlaps the earlier tooltip file selection. Do not sum these receipts or call
them a final combined suite pass. The coordinator owns the final integrated
selection and its separate evidence. No full local suite was repeated here.

The dedicated environment was `/tmp/patchtrace-2bad-header-help-env`. It installs
this worktree editable and reuses the existing pinned dependency directory
without processing that directory's older editable-install hooks. `python -I`
confirmed `/tmp/patchtrace-2bad-header-help/src/patchtrace/__init__.py` before and
after qualification; the declaration's isolated no-Qt import test is included in
the 91-case maintained selection. No shared dependency environment was modified.

## Retained evidence and next owner

[Compressed raw evidence and manifest](evidence/cycle2-strings-header-help-20261121-2bad.zip)
retains the original failure output as well as successful receipts. The embedded
manifest contains per-payload SHA-256 hashes and sizes plus exact production-blob
comparisons: the regression baseline matches the frozen base, and final runtime
blobs match the first successful implementation. Archive payloads were read back
and verified after creation.

- Archive size: 30,595 bytes; 32 original payloads plus the manifest.
- Archive SHA-256: `a681a6cef7aefd93ba9b654023020aec987f7c4bf12496a86cd8d0b421de396c`.

The runtime/test source is frozen for a separate reviewer. Review all eight
semantic mappings, static registry registration without Qt imports, unchanged
display/accessibility and cell roles, and the actual-host audit. The coordinator
must obtain final integrated tests and hosted qualification before merging.
Native screen-reader output, other panels' column mapping, and broader release
acceptance remain open. This worker performed no remote mutation or main merge.
