# Fixes: CLI, PE, QA-FUZZ and intelligence audit findings (2026-10-15)

Each fix has a red test first (a new test, or a strict xfail turned into a plain test). Focused suites run niced; ruff clean on touched paths.

| id | commit | test | status |
|---|---|---|---|
| CLI-2 | 6ee7bed | `tests/test_cli.py::test_cancel_clierror_writes_cancelled_envelope` | fixed |
| CLI-3 | 60260c8 | `tests/test_cli.py::test_json_usage_error_prints_envelope` | fixed |
| CLI-6 | d4ca4e0 | `tests/test_cli.py::test_clierror_message_is_redacted` | fixed |
| CLI-5 | 8ace5bb | `tests/test_cli.py::test_cache_status_unusable_path_is_a_runtime_error` | fixed |
| CLI-7, SER-6 | b191158 | `tests/test_cli.py::test_text_output_escapes_hostile_characters`, `tests/test_hostile_text.py::test_escape_text_*` | fixed (`_emit` text path, all verbs) |
| CLI-8 | 1fd1b92 | `tests/test_audit_ai_reports.py::test_export_neutralises_bidi_and_escape_controls` | fixed (json, md, html) |
| PE-1 | 54ed67d | `tests/test_artifact_bytes.py::test_change_between_hash_chunks_is_detected` | fixed |
| PE-2, PE-3 | 9957da8 | `tests/test_rules_masks.py::test_a_directory_larger_than_one_read_is_read_in_pieces`, `test_a_failed_table_read_is_a_table_error`, `test_unknown_relocation_types_warn_once` | fixed (one commit for both) |
| QA-FUZZ-2 | a382664 | `tests/stress/test_fuzz_archives.py` (xfail removed) | fixed |
| QA-FUZZ-3 | e186836 | `tests/stress/test_fuzz_text_fields.py` (xfail removed) | fixed |
| QA-FUZZ-1 | 7d78185 | `tests/stress/test_fuzz_json_importers.py` (xfail removed) | fixed (`persistence.strict_json`, `load_json_strict`) |
| QA-FUZZ-4 | b883f41 | `tests/stress/test_fuzz_feeds_and_ir.py` (xfail removed) | fixed |
| INT-1 | 835b51f | `tests/test_kev_store.py::test_prune_keeps_the_snapshot_the_pointer_names_when_its_description_is_gone` | fixed |
| INT-2 | 536d019 | `tests/test_rules_matrix.py::test_a_bad_expectations_file_is_refused` (dup-same-value, dup-other-value, too-large) | fixed |

## Skipped (owner decision)

CLI-1, CLI-4, CLI-12 (exit-code unification).

## Deferred

- Text output keeps newlines the renderer wrote, and so also a newline inside an untrusted name (rows could be forged). Per-field escaping would touch every verb renderer.
- PE-2 and PE-3 apply to `pe_overview/tables.py` only; the copies in `unified/ir/pe_tables.py` and `tools/calibration/tier_w/pe_tables.py` (audit S-5) are unchanged.
- PE-2 reads the whole directory into memory (up to the 64 MiB table cap) after chunking; streaming parse is larger than the slice.
