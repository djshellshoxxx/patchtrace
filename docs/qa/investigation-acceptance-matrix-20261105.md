# A3 deterministic investigation acceptance — 2026-11-05

Isolated branch `test/advisory-acceptance-20261105`, worktree
`/tmp/pt-independent-acceptance-20261105`, starting at published PR #218
`afc8a2967ba3dec6b1ac3351d20dd08c193ba9bc`. Test/fixture-only change after reading
the module index, SPEC-31-H and SPEC-32D acceptance requirements. Production,
specification contracts, shared trackers and active qualification files are
unchanged.

Existing coverage already exercises each requested negative category. This
slice adds integration checks at the persistence/reopen boundaries rather
than duplicate every parser/input test. Three authored strict-JSON fixtures
have their own manifest of exact bytes, hashes, license, authorship, dialect,
consumer and expected negative obligations. No upstream source was fetched,
and the synthetic documents are explicitly not Microsoft-derived evidence.

| Category | Completed acceptance evidence |
|---|---|
| Conflicting advisories | Existing `test_kbc_msrc_review_findings.py::test_conflicts_survive_raw_snapshot_reload_and_reach_kb_search_and_attached_context` rechecks conflict withholding through raw reload, search and project context. |
| Missing products | New `test_new_revision_without_product_evidence_removes_active_remediation_but_retains_history` imports a newer revision, verifies no active remediation borrows superseded product proof, preserves original selected-investigation history and exact old source bytes. Historical product labels may remain visible; this test does not forbid them. |
| Ambiguous KB relationships | New `test_ambiguous_type2_kb_text_stays_mention_only_after_workspace_reopen` checks both KB searches retain mention-only provenance and never promote the ambiguous sentence into a vendor remediation. |
| Stale metadata | New `test_stale_search_persists_new_coverage_without_refreshing_source_or_old_receipt` advances the injected clock, verifies stale warning/coverage persistence and unchanged source retrieval time, bytes and prior complete-coverage receipt. |
| Wrong architecture | Existing `test_kb_investigation_service.py::test_arm64_advisory_scope_cannot_preview_amd64_binaries` refuses the pair and preserves investigation revision. |
| Hash mismatch | Existing `test_kb_investigation_service.py::test_changed_local_bytes_refuse_preview_commit` changes bytes after preview and refuses creation. |
| Unsupported binaries | Existing `test_kbc_service.py::test_a_non_pe_file_is_an_input_error` verifies typed refusal of non-PE input. |
| Network failure | New `test_failed_fake_refresh_preserves_prior_source_investigation_and_search` uses the exact planned host/digest consent with a fake failing opener, checks partial receipt/no index change and preserves existing sources, investigation and later search. A socket-denial fixture prevents real network access. |

The fifth new test validates fixture integrity, strict parsing and declared
negative obligations through the real importer. All service/store paths are
real local implementations; the transport failure is explicitly synthetic.

## Completed validation

Initial new selection: **5 passed in 4.03 s**, with no production repair needed.

`env -u PYTEST_ADDOPTS PYTHONPATH="$PWD/src" QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_investigation_acceptance_matrix_20261105.py tests/test_kbc_fixtures.py tests/test_kbc_msrc_review_findings.py::test_conflicts_survive_raw_snapshot_reload_and_reach_kb_search_and_attached_context tests/test_kb_investigation_service.py::test_arm64_advisory_scope_cannot_preview_amd64_binaries tests/test_kb_investigation_service.py::test_changed_local_bytes_refuse_preview_commit tests/test_kbc_service.py::test_a_non_pe_file_is_an_input_error`

**135 passed in 7.19 s**; this includes existing fixture integrity tests and
selected prior controls. Counts overlap the earlier five and must not be added
as unique coverage. Whole-tree Ruff and `git diff --check` passed.

## Limits and remaining gates

No live MSRC/Winbindex response, native provider compatibility, actual binary
pair accuracy or Windows desktop acceptance is established. These are local
domain acceptance fixtures, with no analyzer invocation, target execution,
model training, API cost or cache-hit claim. No duplicate full suite or GUI
stress run was launched. Independent review, publication and exact-head
integration/full/Windows gates remain coordinator-owned. Existing PR #205
qualification and pinned-native ownership were untouched.
