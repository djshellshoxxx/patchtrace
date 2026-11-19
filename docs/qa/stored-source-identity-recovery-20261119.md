# Stored tool identity repair — November 19, 2026

## Independent failure evidence

Independent source review and real-store probes against immutable
`58b5421c8f4e40f56775cc9b7ab178ebc11a9543` demonstrated five admission failures:
a run row with a different raw-artifact guard, a different cache guard, a row id
unrelated to the typed run id, an edited executable manifest with unchanged
claimed configuration, and a normal run rebound to another run's sidecar.
All five expected refusals failed to occur. The original reviewer output is
preserved without modification as `stored-source-identity-red-20261119.log`:
**5 failed in 2.53 seconds**. Those failures were findings, not acceptance credit.

## Repair and boundaries

The shared owner-thread reader now verifies the full reserved guard, row id,
status and stale flag against the typed content, and rejects a future project
revision. It recomputes configuration and cache digests from the retained tool
manifest and options using the producer's current identity functions. Evidence
rows must have their recomputed content identity. A sidecar pointer admits only
its complete known header, and that header and its counts must match the
verified inner document with strict canonical types. The run's count and status
must match the admitted set.

A normal result must name that exact non-cache producing run. A cache hit may
retain an earlier evidence set only when its original non-cache producer remains
available and has compatible artifact, engine, side, manifest identity, options,
status and count. Both producer and hit undergo the row and digest checks.
The public `capture_tool_sources` / `ToolSources.latest` API is unchanged, and
legacy ToolStore writes and unrelated consumers are not modified.

Run validation is scoped to the requested engine and side. The first expanded
regression run exposed a recovery error: rejecting an older FLOSS run also hid
its valid newer group. The existing CLI presence test detected that error
(**175 passed, 1 failed**); the final repair preserves the valid side while
reporting the older side as unknown. No acceptance is inferred from that failed
intermediate run.

These are consistency checks on retained records, not an authenticity signature
for a deliberately rewritten store or proof that an external executable ran.
The canonical raw-output filename still binds the recorded stdout digest; raw
stdout is not replayed. Legitimate cache hits and empty results may omit raw
metadata. Actual runner cache reuse and retained empty-set controls verify that
this tightening does not invent raw output or require it for those cases.

## Exact focused gate

The final author gate passed **176 tests in 34.06 seconds**, with no skips, using
`QT_QPA_PLATFORM=offscreen` and these eight files:

```sh
python -m pytest -q \
  tests/test_intel_tools_snapshot_identity.py \
  tests/test_intel_tools_snapshot.py \
  tests/test_search_wiring.py \
  tests/test_search_wiring_boundaries.py \
  tests/test_search_cli.py \
  tests/test_ui_search_panel.py \
  tests/test_ui_search_saved.py \
  tests/test_search_saved_workflow.py
```

The adjacent log and JUnit XML retain the result. Scoped Ruff and
`git diff --check` passed. The 176-test gate includes the earlier Search
selection; it is not added to the earlier 142-test count. Tests use real SQLite
rows, actual content-addressed sidecars and authored tool boundaries on
synthetic inputs. No native Windows, external tool compatibility or full-suite
acceptance is claimed. Independent acceptance of this follow-up is recorded
separately by the integration coordinator.

## Frozen file hashes

| Path | SHA-256 |
|---|---|
| `src/patchtrace/intelligence/tools/snapshot.py` | `1405a5ba0ac03268a42c5c5271278b32722fdbd4ff2fd46f8422143ca709fa8c` |
| `tests/test_intel_tools_snapshot_identity.py` | `61db4e777da0f72882b071505d2d16fa061d535a3ed8076d1e0a7c1713f652f9` |
| `docs/specs/program-e/WB1-integration-plan.md` | `6753b21c6d57e8eea8a24d0993ddc857021f5ca90e240efacc31784ffb176ff7` |
| `docs/qa/stored-source-identity-red-20261119.log` | `a222ac8ea9566f6e90ab3fb2a90fb02bde7aff68c0a5cf4818c48ea901a231aa` |
