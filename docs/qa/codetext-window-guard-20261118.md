# Code-highlighter dispatch guard — source and QA receipt

Source **`2bf86c883d4d9185f1fb845a7083f73c5541f342`**, tree `32aec313e3bc612694f38c8e489626b335cd78ff`, repairs the missing
historical window guard identified by semantic batch 3. Base:
`3faf436a3b11c69220641a167cf424e7f4060839`. Spec/tests-first commit: `367953e9ea6e7f0c837b01b01b6354c3b930c71f`. No remote mutation occurred.

## Change and reason

Qt invokes `highlightBlock` for many document blocks during bulk text installation.
The callback previously called `controller.spans` for every one and repeatedly
set the unchanged block state. The controller correctly rejected off-window
formatting, but the helper dispatch still scaled with the document.

The sole production change is `src/patchtrace/ui_codetext.py::CodeHighlighter.highlightBlock`
(seven added/two removed lines). It returns before dispatch if there is no current
model, the session has failed or the block lies outside that side’s window. It
leaves default block state at `-1` and uses the captured row for valid dispatch.
All checks/span/format work stay inside the existing exception boundary; failures
still retain text, emit one notice and detach on the next event-loop turn.
The controller’s own checks, visible-window margin, model-before-text ordering,
font/mark/selection behavior, UI seam and existing caps remain.

The WBQ contract now distinguishes Qt block callbacks from Python span dispatch.
It explicitly avoids a native timing claim or a requirement to globally clear
previously visited rows on every scroll. The module index maps the seven new
behavior cases, including all three colors/marks combinations, no-model mode,
failure-before-detach, explicit out-of-window rehighlight and unexpected window
access failure. No new module, tooltip, exemption or schema was added.

## Exact-source verification

| Phase | Source/state | Actual result | Pytest summary time |
|---|---|---|---|
| Seven new behavior cases before production change | `367953e9` | 6 failed, 1 passed; 0 setup errors | 0.82 s |
| Three unchanged historical nodes before change | `367953e9` | 1 failed, 2 passed; 0 setup errors | 0.55 s |
| Focused working-tree implementation check | `367953e9` plus retained source diff | 7 passed | 0.68 s |
| Nine affected current files, normal offscreen scale | `2bf86c88` | 804 passed, 1 skipped; 0 failures/errors | 47.74 s |
| Same nine files, 2x offscreen scale | `2bf86c88` | 804 passed, 1 skipped; 0 failures/errors | 48.73 s |
| Unchanged historical three-node replay | `2bf86c88` | 3 passed; 0 skips | 0.58 s |

The repeated scale runs and historical overlaps are not additive coverage or
completion credit. Exact command JSON, raw logs/XML and distinct JUnit durations
are retained. Absolute `PYTHONPATH` pins the active worktree; Python is
`/workspace/scratch/3a6632a6e5ff/venv/bin/python`. Both runs include the actual
global tooltip registry sweep, pane integrations, token/mark/palette tests and
existing scrolling/font/state controls. A separate Qt 6.12.0 observation confirms
`QT_SCALE_FACTOR=1/2` produced actual offscreen device-pixel ratios 1.0/2.0.

The sole skip is `test_simulation_equals_colorspacious_when_it_is_installed`:
“the validation oracle is optional and not a dependency.” It remains a skip,
not a new color-simulation/native acceptance claim. Whole normal Ruff over
`src tests tools` and `git diff --check` pass. No final full-repository/native
Windows/package/manual benchmark ran.

## Immutable historical evidence

Historical tip: `c7fb422c750f1d0e5591277b91492874afd79af7`. The complete
`tests/test_ui_codetext.py` is retained byte-for-byte (16,911 bytes), SHA-256
`238abb33cad9ff066f73564c97ee1215e514735c17aa62ea26a4e39d8f5721e3`.
Selected nodes are `test_bulk_load_skips_span_dispatch_outside_the_window`,
`test_windowed_highlighter_formats_only_the_window` and
`test_scroll_updates_window_within_budget`. The repaired replay reaches and
passes the historical call-count/state checks that the original failure did
not reach. The original batch 3 red at 55f3 and fresh precursor red at 3679 are
preserved under distinct source identities. No old assertion was weakened.

## Sealed packet and boundaries

[Full receipt archive](codetext-window-guard-20261118.zip): **54 members**,
**351,880 bytes**, SHA-256
**`b2877460946ab8456b8404aa4571f28b3c17e6343c21327adbd3335b7da1246e`**. Every member was reopened and matched to its
size/SHA-256 manifest after sealing. The packet includes exact baseline,
spec-first/current/historical source snapshots, the complete production diff,
all failures/positives, actual scale observations, commands and checker output.

Root independent review/selective integration is pending at this author checkpoint.
The report agent separately owns a reported pre-existing combined-registration
tooltip collision reached by the F8 journey; this guard neither repairs that
broader state nor claims its qualification. Later combined/full/platform gates
must use their own source. No native timing, Qt callback-count bound, release,
branch closure or product-completion percentage is inferred from these passes.
