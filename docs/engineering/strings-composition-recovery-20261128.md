# Strings composition completion

Date: 2026-11-27 (America/Vancouver).

## Source and gap

The isolated branch starts at published Pilot follow-up
`72de37b02cf51eb8be8cb4b6281897a827eabf48`. The retained comparison donor is
`6096e64d4e7b8f0ecc6af884f7d220e07790d85a`; it is reference material only.
Current CLI code supplied image import/export names, section regions and explicit
advisory anchors to the strings delta. The current dock supplied none of those
contexts and read only built-in sources. Existing pairing, extraction, admission,
redaction and held-source export code already exist and retain ownership.

## Incremental plan

1. Define one Qt-free CLI/dock composition and a bounded strict anchor reader;
   demonstrate metadata/anchor/cancellation gaps, then restore parity.
2. Consume the independently completed shared tool snapshot on the owner thread;
   add explicit dock source and anchor choices, preserving per-side refusal and
   original cache provenance. No automatic extraction or competing store reader.
3. Verify stale/cancelled/superseded results, real offscreen controls, existing
   schemas and export-publication regressions. Root owns independent review,
   combined-source tests, native acceptance, hosted gates and publication.

## Slice 1: shared comparison

The corrected pre-implementation regression lane failed **4** tests and passed
**1**: CLI/dock cue/region mismatch, absent anchor request input, a pre-cancelled
worker opening an artifact, and duplicate anchor JSON keys being accepted. An
earlier run also had 4 failures/1 pass, but its first assertion incorrectly
expected an unchanged import string in the delta. The authored fixture was fixed
with an equal-length import-name change; that earlier fixture error is not
implementation-failure evidence.

The shared composition now uses the existing cue, region, link, basis and anchor
rules for both callers. The table adapter moved without changing its contract;
the existing CLI import remains available. Explicit anchors are read with a
4 MiB byte bound and strict JSON, then validated as the existing `AnchorSet`.
Cancellation is checked before artifact inspection and at comparison stages.

The final slice lane passes **116** tests without skips in 5.42 seconds. It covers
the new composition, real authored-PE CLI/dock parity, export and cross-build API
context, resource and advisory cues, secret redaction, stage cancellation,
anchor-file boundaries, existing CLI/pairing/panel/basis/anchor tests and schema
drift. The earlier 110-test green run is a subset, not an additional count.
Focused Ruff and whitespace checks pass. Temporary XML receipts are
`strings-composition-core-red.xml`, `strings-composition-core-red-corrected.xml`
and `strings-composition-core-green-final.xml` beside the checkout.

No target or native extractor was executed, no live provider was fetched, and no
remote write was made. Stored-source UI and native/packaged acceptance remain
pending at this slice.

## Slice 2: captured sources and explicit dock controls

The common owner-thread snapshot foundation was taken from the independent Search
work: original commits `8c616b3eea686761af62e2ffe03d1f989d05719c` and
`f99996db0021e5e7e3639a822ca3841c41e29c11`, locally cherry-picked as `d97910f2`
and `196d3751`. Strings does not add another store reader or change the shared
helper, current admission, evidence contracts, extractor, consent, or raw storage.

The CLI and dock now use the same per-side source selection. Automatic selection
preserves an admitted opposite side when one side is absent or refused; explicit
FLOSS refuses missing evidence before artifact inspection. Global integrity or
capture-budget faults refuse the request. Built-in selection bypasses stored
tools entirely. Cache hits retain the evidence-producing run's executable, raw
digest and consent basis. Empty produced output remains a valid FLOSS source;
truncated stages and incompatible emulation settings keep existing basis rules.

The dock captures tools and a deep project copy on the owner thread and passes
only values to its worker. Source selection and explicit anchor choice do not
start work. They cancel superseded requests and mark accepted rows stale until
the next comparison. Repeat project notifications cannot clear that staleness.
The modal file chooser discards a returned path after a project-key change or
shutdown. Result publication and navigation also check the actual current port
key, including same-epoch revisions. Earlier rows survive failure or cancellation.

The source selector, anchor chooser and clear action have registered help and
accessible names. The existing eight column-help IDs remain intact. The body
StateView ID is `strings.body`, coordinated with the independent accessibility
slice to avoid colliding with the shell's state buttons. Both CLI and panel help
now explain the source choices and explicit anchors. No export code, format or
publication guard changed.

### Evidence and corrected test authoring

- Before the controls existed, the new UI/source lane failed all 18 cases.
- The first combined run passed 151 and failed 2: the existing `strings scan`
  command still called a removed private source helper. Its direct built-in path
  was restored, including the cancellation check. The repeat passed all 153.
- Two failing same-project-notification controls exposed input staleness being
  cleared. They were corrected in the controller. The first expanded baseline
  also used the wrong `ProjectKey` field in one test; the corrected three-case
  baseline was 2 failed/1 passed. That fixture error is not implementation evidence.
- Two further failing controls exposed a modal chooser returning into another
  project or a closed controller. The chooser now checks the captured key and
  shutdown state before accepting its result.
- Incompatible-emulation tests initially attempted to republish a changed
  configuration under an existing immutable run identity, then used a nonexistent
  top-level change type in an assertion. Both were test-authoring errors. The
  fixtures now publish distinct producing runs and assert the actual observation
  and harmonized-type contracts; both cases passed in the chooser baseline.
- The first complete focused selection passed 772 and failed one old exact
  tooltip-inventory assertion. The three additive help IDs were added to its
  expected list, retaining every existing entry and assertion and extending the
  visible-copy sweep to the new source labels.

The XML receipts beside the checkout retain all these outcomes, including the
ones whose filenames contain `green` but whose recorded result failed. They must
not be counted as passing evidence based on filenames. No counts above are
additive: the lanes overlap.

### Render inspection and remaining gates

An actual offscreen comparison of authored PE bytes rendered seven rows with
advisory anchors at 1100 by 650 pixels, using 9-point and 13.5-point fonts. Both
images were inspected; the source and anchor controls fit without clipping. The
existing accessibility audit reports only the pre-existing non-focusable table
header that `test_ui_strings_panel.py` already documents. No new exemption was
added. Temporary images and `render-receipt.json` are in `strings-evidence` beside
the checkout.

The complete focused command is:

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 QT_QPA_PLATFORM=offscreen \
  ../.venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_strings_*.py tests/test_ui_strings_*.py \
  tests/test_intel_tools_admission.py tests/test_intel_tools_snapshot.py \
  tests/test_tooltips.py tests/test_gui_core_isolation.py --tb=short \
  --junitxml=../strings-composition-final-corrected.xml
```

The corrected selection passed **776 tests, zero skips**, in 154.76 seconds.
Whole-tree `python -m ruff check src tests tools` and `git diff --check` passed.
During that run, unrelated short read and Ruff commands also slowed down; the
single existing test session was preserved and eventually finished successfully.
No product hang, cause of the slowdown, or corrective product change is claimed.

This selection includes existing schema, basis, source, pairing, cue, region,
ranking, anchor, CLI, UI, source-ownership and export-publication controls. Existing
tool-run tests use authored fake executables; they are not native FLOSS evidence.
Root owns independent exact-source review, combined-source and hosted gates,
Windows packaged rendering/assistive technology, and real FLOSS compatibility.
No target binary was executed or live provider fetched. The shared environment's
editable binding was not changed.

## Corrective slice: comparison and displayed table ownership

Independent review of `f8f169f6bcabce6403c73f34e3673d18c68b514f` exposed a
confirmed publication error. A new comparison replaced the controller's `Loaded`
and row lookup before the asynchronous filtered table arrived. With the same
string ID in two comparisons, an old visible row showing offset `0x640` could
navigate to the replacement's `0x950`. A failed view preparation left that
mismatch in place. The reviewer's two pending/failed-view controls failed; their
four production composition and capture controls passed. The original six
independent controls remain unchanged outside the checkout.

The specification now requires one displayed receipt. Successful comparison
loading creates only a candidate. The candidate's `Loaded`, project key, row
lookup, filter result and table publish together after view preparation. Details,
copied text, footer, incoming anchors and outgoing navigation continue to use the
earlier receipt until publication. Synchronous model-reset actions refuse
mismatched receipts. View requests have an independent generation, so late filter
results cannot overwrite a newer view. Cancellation remains available during
preparation and cancels both stages; source staleness clears only when the
replacement display publishes.

The first authored regression lane recorded 12 failures and 4 passes, including
test-authoring mistakes: a generic event was used instead of the existing
checkpoint-capable cancel token, and a copy assertion assumed raw text instead
of the established table format. Those mistakes were corrected before runtime
changes. The corrected baseline recorded 11 failures and 5 passes. Its strict
model-reset expectation was later relaxed to allow either refusal or an action
using the matching new receipt; the contract requires consistency, not a specific
callback implementation. The reviewer's original two wrong-offset regressions
remained unchanged throughout.

The final narrow lane passed **97 tests, zero skips**, with 9.694 seconds recorded
in JUnit. It covers ten new ownership controls, all six original independent
controls, and existing composition/panel tests. This is a corrective selection,
not a rerun of the earlier 776-test lane, and the counts overlap. Whole-tree Ruff
and whitespace checks pass. The command is:

```sh
PYTHONPATH=src:tests PYTHONDONTWRITEBYTECODE=1 QT_QPA_PLATFORM=offscreen \
  ../.venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_ui_strings_display_ownership.py \
  ../strings-independent-review.py tests/test_ui_strings_composition.py \
  tests/test_ui_strings_panel.py --tb=short \
  --junitxml=../strings-evidence/display-ownership-final.xml
```

The initial, corrected-red, first-green and final receipts are retained beside
the checkout in `strings-evidence` as `display-ownership-red.xml`,
`display-ownership-red-corrected.xml`, `display-ownership-green.xml` and
`display-ownership-final.xml`. Independent exact-source re-review remains pending
at this corrective slice. Combined-source, hosted and native/platform gates
remain root-owned; no target, native extractor or live provider was used.


## Independent corrective-source approval

The independent reviewer approved exact corrective runtime
`ea40cb5d73bed8035370539b0634a7cbbf73c567`, tree
`b5aafc01a51c9ce6fa0866b85eb5678007506f5f`. Two original failing
display-ownership controls plus their four passing controls are preserved,
along with five additional publication/cancellation controls: all 11 pass
on the corrected source. Ten maintained display controls and 118 adjacent
existing controls also pass. The initial added-review fixture errors and
the original failing outcomes remain recorded, not substituted with green logs.

The author passed 97 focused tests on the corrective source. The earlier
776-test composition lane applies to the preceding source, not a rerun of
that entire lane after the ownership correction. Required Ruff and whitespace
checks pass; seven protected common modules remain base-identical. Root also
reviewed the candidate/display pointer swap and action guards.

The raw XML, independent controls, render receipt and both offscreen images
are retained under `evidence/strings-composition-20261127/`, with byte hashes
and exact XML outcomes in `index.json`. These Linux offscreen checks establish
local composition and display ownership. Exact-head full/platform CI and native
Windows accessibility remain separate unverified gates.
