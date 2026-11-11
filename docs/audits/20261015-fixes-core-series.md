# Fixes for core and series audit findings, 2026-10-15

Source audits: `20261015-core-app.md`, `20261015-series-providers-calibration.md`. Each fix has a red test written first (confirmed failing), then the smallest change, one commit per finding. No persisted contract changed shape; SER-1 and SER-2 only add refusals with existing `PT-NWAY-*` codes.

| id | commit | test | status |
|---|---|---|---|
| CORE-1 | 7aadf27 | `tests/test_interpretation.py::test_core1_context_for_code_ending_in_blank_line_validates` | fixed (validator counts lines with `split('\n')`; stored evidence text unchanged) |
| CORE-2 | b9f6a84 | `tests/test_core.py::test_core2_normalizer_rejects_repeated_upstream_function` | fixed (`PT-SCHEMA` on a repeated side/name/address) |
| SER-1 | 35ba829 | `tests/test_nway_series_tolerance.py::test_ser1_*` (2 tests) | fixed (`save` refuses oversized output; an oversized existing file is replaced with `--replace-corrupt`, copy kept) |
| SER-2 | 3daf654 | `tests/test_nway_graph.py::test_ser2_*` (3 tests) | fixed (empty name with address becomes address-only node; over-long or nameless-addressless is `PT-NWAY-INPUT`) |
| SER-3 | ad87acd | `tests/test_nway_graph.py::test_ser3_*` | fixed (one-line condition change) |
| SER-4 | 09114c7 | `tests/test_nway_view_model.py::test_ser4_*` | fixed (direct-pair lock reason dropped, found by reason text because the direct pair has no snapshot) |
| SER-5 | b59c8b8 | `tests/test_calibration_scope.py::test_ser5_*` | fixed (`LedgerResult.live_entries`; `state()` shares the expiry rule) |

## Skipped by instruction

- CORE-3: owner decision pending.
- SER-6: another worker owns CLI output escaping.

## Deferred

- No Low finding qualified as a one-line fix inside the same function, so none was taken.
- `docs/specs/series-window.md` section 4.3 was not amended for SER-1 (the audit asks for it); the behaviour now matches the existing 256 MiB load cap, so only wording is outstanding.
