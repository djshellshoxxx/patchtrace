# Stored-source Search recovery — November 19, 2026

## Recovered consumer and shared admission

Historical source `33e7e33805e68b03665ab860fc19c83fd11fc5d8` introduced stored tool, advisory and CVE sources
into the CLI and dock. The current integration already had those source factories,
but its production SearchService constructors never supplied them. This port,
developed against `eb595b82e10ac7b8482650cd807dc180d26960fe`, restores that runtime consumer while preserving the
newer saved-query storage, recall and service-ownership behavior and the recovered
`search.body` accessibility identifiers.

The shared Qt-free `intelligence/tools/snapshot.py` owns bounded row capture and
tool evidence admission. `capture_tool_sources(service, engines=(...))` runs on
the store's owner thread. Its returned `ToolSources.latest(engine, side)` reads
only copied values, returns None for a missing produced run, and raises ToolError
for unreadable, foreign or uncaptured evidence. Search keeps advisory/CVE adapters
and bounded project copying in its own wiring module. The helper is available for
the separately integrated Strings consumer; this checkpoint makes no claim about
that later integration.

The port bounds metadata before bodies, verifies body hashes and project guards,
uses the current owned reader for content-addressed evidence sidecars, shares the
sidecar byte budget across groups, binds produced run/evidence configuration and
artifact identities, and refuses corruption of the newest produced result instead
of falling back to an older result. Raw-output paths must agree with the recorded
stdout digest; raw stdout is not replayed or re-read by this consistency check.
Legitimate cache-hit and empty-output records can retain absent raw metadata
without inventing a digest. Inline snapshots reuse data only while both SQLite
modification counters and the connection-owner identity stay unchanged. Sidecar-
dependent or failed snapshots are revalidated on every capture.

## Exact focused verification

Author result: **142 passed in 25.45 seconds**, using the seven test files below
with `QT_QPA_PLATFORM=offscreen`. The adjacent log and JUnit XML retain that gate.
The initial invocation without the offscreen Qt setting aborted while creating
QApplication; it was an environment setup failure and provided no complete gate.
After setting the environment, the recovered historical consumer selection and
its current saved-query regression suite passed, followed by the bounded row,
sidecar, provenance and shared-port controls in this final gate.

```sh
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_intel_tools_snapshot.py \
  tests/test_search_wiring.py \
  tests/test_search_wiring_boundaries.py \
  tests/test_search_cli.py \
  tests/test_ui_search_panel.py \
  tests/test_ui_search_saved.py \
  tests/test_search_saved_workflow.py
```

Scoped Ruff and `git diff --check` passed. The tests exercise real SQLite stores,
actual filesystem admission, owner-thread capture and offscreen GUI workers. Tool
fixtures use authored fake executables and synthetic PE pairs; no target image
runs and no network or live native-tool acceptance is claimed. Native Windows
accessibility, large-project responsiveness and full integration remain separate
gates. This is a scoped recovery, not semantic closure of the whole historical
feature branch.

## Exact source hashes

| Path | SHA-256 |
|---|---|
| `src/patchtrace/intelligence/tools/snapshot.py` | `ff734b4f4e45db0bc918416009d1ef6ce9e639917ae448bd6f2051612489b493` |
| `src/patchtrace/search/wiring.py` | `2fc4acafbc22f0db7885b6623d9e0c5acb15ac2123dda9772cb7dff9dd21a9c2` |
| `src/patchtrace/search/cli.py` | `27bf98d1293d3f7571e08c1e0d3ea38d9aaa3eee752469fd2865351d12ad3878` |
| `src/patchtrace/search/panel.py` | `7e3cca54b3ba0f351dd7cc0727c4c16029f8a4cb5d14b50e88f6cba9725d26ed` |
| `src/patchtrace/search/qt_panel.py` | `1059e0b6c84de6cf54746804652a831ed986cc8dc4b901f1f48fe2889441a301` |
| `tests/test_intel_tools_snapshot.py` | `25802c33e5c5764d3ebfec4f4df7da2f4f36f56082dbef95830b3c2bc3a1ef96` |
| `tests/test_search_wiring.py` | `ab48faf70a4d127f23c47b2124dd363b24547183173288ba1d8eb416db6e9c10` |
| `tests/test_search_wiring_boundaries.py` | `1ec6daeab03535bbf1a72f46e0675643b51f54dc50f5b27a01c3250c399ef05a` |
| `tests/test_search_cli.py` | `46b2b4f6c16e408db351a120cf40c56511967f1139e53388558f8f441042c813` |
| `tests/test_ui_search_panel.py` | `0201000187bf91ca0e2cdda89b6b47590ec10bb0e9724024b41021fa4925b5f3` |
| `tests/test_ui_search_saved.py` | `d01c2add72d575ccebe7f412c2352a405fa7da34ebc10aafd7276bf4f41c0ffd` |
| `tests/test_search_saved_workflow.py` | `d84a390753b5e35ddb479bd40bc69ec7afdc08ab2d635afa777a6fd3fb2decb9` |
| `docs/specs/program-e/WB1-integration-plan.md` | `fe48468f7c6d182e95ae3158cef226bc9481de7dec95036a2752d5ce851b9e6b` |
