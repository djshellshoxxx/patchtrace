# Strings: one comparison for the CLI and dock

Date: 2026-11-27 (America/Vancouver). This amendment completes the composition
portion of WB3 using the current Strings, stored-tool admission and panel code.
It changes no persisted strings or tool-evidence contract and adds no extractor.

## 1. Shared comparison

`strings/compose.py` owns the Qt-free comparison used by the Strings CLI and
dock. Given the same sources, verified image metadata, project snapshot and
optional advisory anchors, both callers produce the same delta, cues, regions,
links, anchor hits and review order. Source labels remain explicit per side.

The composition supplies each build's import and export names, the other build's
imports, section regions and the supplied anchor terms to the existing cue and
delta rules. It reuses `pairing.project_links`, basis comparability, redaction,
ranking and anchor joining without adding scoring or function-link rules.
Advisory matches remain search hints and never become vulnerability findings.

Cancellation is checked before artifact inspection, before and after loading
each source and between pairing, delta and anchor stages. A cancelled operation
cannot publish a partially prepared comparison. The existing source, table,
delta and anchor bounds remain authoritative.

## 2. Explicit source and anchor choices

The dock exposes the same source choices as the CLI: `auto`, stored `floss`, and
`builtin`. Auto selects each side independently. An absent or refused selected
FLOSS result falls back to the built-in scan for that side; the other side keeps
its admitted source. Explicit FLOSS refuses when either side lacks admissible
stored evidence. Built-in selection does not read the tool store. These preserve
the existing CLI admission controls; a refused result never becomes a successful
empty FLOSS extraction and never selects an older produced run instead.

Only the shared `intelligence.tools.snapshot.capture_tool_sources` reads the
project store and stored sidecars, on the store owner thread. Its frozen value
provides per-side admitted evidence and the original evidence-producing run for
cache hits. The worker receives captured sources and a deep project copy, never
the service, SQLite connection or a deferred store reader. Global storage,
integrity or capture-budget failure refuses the request. Raw, executable, consent,
artifact and side provenance remain those of the admitted originating run.

The dock also accepts an explicitly chosen local advisory-anchor JSON file,
equivalent to CLI `--anchors`, and provides a clear action. No anchors are chosen
automatically from another project or advisory. Reading and parsing happen on
the comparison worker. Both callers use the same bounded reader: at most 4 MiB,
strict JSON followed by the existing `AnchorSet` schema. Invalid or unreadable
input is a typed `PT-STR-INPUT` failure and preserves earlier results. The chosen
path is request-local presentation state, is cleared on project switch, and is
never written into the strings delta or export.

Source or anchor-choice changes cancel superseded work and mark an existing
comparison stale until the next explicit comparison. Selecting a source or file
does not launch FLOSS, scan artifacts, fetch data or save a project. Existing
`intel-tools` execution, consent and storage remain the sole tool-run path.
Repeating the current project notification does not clear that input-change
staleness; cancelling the file chooser leaves the current request unchanged.
An open file chooser is bound to the current project key. A choice returned
after that key changes or the dock shuts down is discarded.

## 3. Publication and presentation

The current panel task generation, project identity, revision and shutdown guards
apply to every result. A same-epoch revision change also refuses publication.
Failure or cancellation keeps earlier accepted rows. A completed mixed-source
comparison retains the existing static/emulation comparability decisions and
names each source; incomplete stages remain indeterminate.

A completed comparison is a candidate until its filtered table is prepared.
The displayed `Loaded`, row lookup, project key, filter result and prepared table
publish together on the owner thread. Details, copied text, footer, incoming
anchors and outgoing navigation always use this displayed receipt. A pending,
failed, cancelled or superseded view preparation cannot replace any part of it.
Source/anchor staleness clears only when the replacement display publishes.
During the synchronous table reset, actions refuse a row unless the table still
matches the displayed receipt. View callbacks also belong to their own request
generation; a late filter result cannot overwrite a newer view.

The eight existing column-help entries, plain-text rendering, redaction, function
and hex navigation, keyboard behavior and table filtering remain in force. New
source and anchor controls have registered help and accessible names. No second
window is created except the explicit native file chooser.

CLI JSON/CSV formats and the current held-source export publication are unchanged.
In particular, Linux still requires a new export destination even with `--force`;
this composition feature does not implement Linux replacement.

## 4. Acceptance and limits

- A synthetic PE pair produces identical CLI/dock deltas, including import and
  cross-build API cues, export cues, section regions and advisory hits.
- Auto, explicit FLOSS and built-in choices cover both, one and neither stored
  side, stale/foreign records, swapped artifacts, cache-hit origins, incomplete
  extraction and incompatible bases. No target or native FLOSS is executed.
- Store and sidecar capture stay on the owner thread; comparison sees only
  captured values. Revisions, cancellation, source/anchor changes and shutdown
  cannot publish stale results.
- A replacement comparison with the same string ID but different offsets or
  links cannot change the backing data of an earlier visible row. Failed view
  preparation preserves its earlier details, copy, footer and navigation basis.
- Bounded malformed/duplicate/nonfinite anchor JSON fails without replacing
  accepted rows. Secret-shaped strings remain redacted and cannot gain anchor hits.
- Existing Strings schema, pairing, source, CLI, UI, and export-publication tests
  remain green. Native Windows rendering, assistive technology, packaged GUI and
  real FLOSS compatibility remain separate qualification gates.
