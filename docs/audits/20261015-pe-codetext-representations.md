# Audit: PE overview, codetext, symbols and byte representations (2026-10-15)

Status: read-only audit, 2026-10-15. Base: `origin/main` at `21a005e` (fast-forwarded; worktree was clean). No file under `src/` or `tests/` was edited. Repro scripts are outside the repository in `/tmp/claude-0/-home-user-patchtrace/af0aa2a7-ecd2-5ddd-b998-aece6eb7ffa7/scratchpad/pe-audit/` (`repro1.py`, `repro2.py`, `fuzz1.py`, `fuzz2.py`).

Severity counts: High 0, Medium 3, Low 11 (14 findings). Six suspicions (S-1 to S-6) are noted below and are not counted, per the repro rule in `docs/plans/e4-audit-and-qa-plan.md` section 3.

## Findings

| id | severity | location | finding | evidence |
|---|---|---|---|---|
| PE-1 | Medium | `src/patchtrace/artifact_bytes.py:69, 87, 91-103` | The stat baseline is taken after hashing, so an in-place change during verification is accepted: the recorded SHA-256 is of the old bytes while `read()` serves new bytes, with no error. | `repro1.py toctou`: sha256 of served bytes `!=` recorded; no exception |
| PE-2 | Medium | `src/patchtrace/pe_overview/tables.py:100, 146, 176`; `src/patchtrace/artifact_bytes.py:144-145` | `read_rva` passes a whole directory to one `reader.read`. A `.reloc` over 16 MiB, or a `.pdata` over about 1.4 M entries, raises `ArtifactBytesError('read_too_large')`. The module contract is `PeTableError`, and `rules/window.py:308` catches only `ValueError`, so the error escapes the rule workflow. | `repro1.py read_too_large`: `escaped as ArtifactBytesError : read_too_large: single read capped at 16777216 bytes` |
| PE-3 | Medium | `src/patchtrace/pe_overview/tables.py:186-189` | Every entry with an unknown relocation type appends a new warning string. The list is neither deduplicated nor capped. Entries are capped at 16 M, which would allow about 16 M strings (extrapolated, not run). | `repro1.py reloc 100000`: `entries=100000, warnings list length=100000` in 0.09 s |
| PE-4 | Low | `src/patchtrace/pe_overview/resources.py:40-41, 95-97` | `sanitize_text` is a hand-written list and does not implement the shared rule in `hostile_text.is_hostile` (categories Cc, Cf, Cs). 158 non-surrogate Cf code points survive into resource names, version strings and manifest values, for example U+200B, U+00AD and U+0600 to U+0605. | `repro1.py sanitize`: `sanitize_text('a​b') -> 'a​b'`, `is_hostile: True` |
| PE-5 | Low | `src/patchtrace/codetext/intraline.py:62-66, 156-167` | The `_UNSAFE` class in the status-sentence snippet is hand-written and misses 29 Cf code points: U+0600 to U+0605, U+06DD, U+070F, U+0890, U+0891, U+08E2, U+110BD, U+110CD and U+13430 to U+1343F. These reach the one-line summary unescaped. | `repro1.py sanitize`: `codetext.intraline _UNSAFE misses 29` (by category, non-surrogate) |
| PE-6 | Low | `src/patchtrace/pe_overview/imports_exports.py:56-59, 91-94, 95-98` | The caps are checked before the entry is read. A valid table with exactly 512 DLL descriptors and a zero terminator is reported as cut short (`import_dlls_over_cap`), which makes `api_delta` and `PeTables.import_slots` return unavailable. The same pattern applies to the 4096-per-DLL and 20000-total caps (by reading; not run). | `repro1.py imports512`: 511 gives `truncated=False`; 512 gives `truncated=True`, `import_dlls_over_cap` |
| PE-7 | Low | `src/patchtrace/pe_overview/exports_table.py:94` | `name not in by_index.setdefault(index, [])` is a list scan, so binding k names to one ordinal costs O(k²). This is bounded by `max_export_names` (20,000) and is not polled for cancellation inside the scan. | `repro1.py exports_quadratic`: 5,000 names 0.14 s; 20,000 names 1.83 s |
| PE-8 | Low | `src/patchtrace/pe_overview/_common.py:55-65` | `cstring(offset, limit)` with a section-bounded `limit` and no NUL inside it reports `name_truncated` with the text "a name longer than 512 bytes", which is false. The truncation is at the section boundary. | `cstring` with `limit=300` on a 2000-byte file: warning "a name longer than 512 bytes was truncated" |
| PE-9 | Low | `src/patchtrace/codetext/tokens.py:280-296` | The full-document `tokenize()` builds one `Token` per punctuation character. No product code calls it (only `tokenize_line` is used, per row). If it is reached, 1 MiB of text gives about 1.04 M tokens and about 131 MiB RSS. | `repro1.py tokens`: `1048831 chars -> 1044736 tokens in 0.76 s; maxrss +131 MiB` |
| PE-10 | Low | `docs/specs/pe-overview.md` (warning codes; "Not done") | Spec drift. (a) "Not done" still lists version-info, manifest and resource enumeration, which now exist. (b) At least 12 emitted codes are not in the spec: `resource_depth_over_cap`, `resource_dir_unreadable`, `resource_name_truncated`, `resource_nodes_over_cap`, `version_block_malformed`, `version_over_cap`, `manifest_over_cap`, `export_table_over_cap`, `export_ordinal_out_of_range`, `export_name_table_loop`, `import_thunk_reserved_bits`, `metadata_time_budget`. (c) `section_unmapped` is listed but never emitted. (d) "hashlib-free" is contradicted by `manifest.py:27, 136`. | grep of emitted `warn(` codes against the spec: `comm` output lists the 12 codes above |
| PE-11 | Low | `src/patchtrace/representations/render.py:179-183`; `formatters.py:89-90` | Spec drift. The spec says the gutter is "widened consistently". Each segment of a page is formatted with its own gutter width, so one page can mix widths. | `format_hex` at `0x7ffffff0` gives an 8-digit gutter and at `0x100000000` a 9-digit gutter |
| PE-12 | Low | `src/patchtrace/pe_overview/tables.py:50-66, 119-126, 137-197` | `PeTables` has no cancellation after `open()`. The `.pdata` and `.reloc` loops never poll, and `executable_sections` joins whole sections in memory. The spec says reads are in at most 1 MiB pieces. Linear cost is about 3.8 µs per `.pdata` entry, so the 4 M cap is about 15 s without cancel (extrapolated). | `repro2.py`: 50,000 entries 0.21 s; 200,000 entries 0.76 s |
| PE-13 | Low | tests (see table below) | Missing regression tests for the defects above. | grep of `tests/`, listed below |

Missing-test evidence (grep of `tests/`):

* `test_artifact_bytes.py` has `test_mutation_after_verification_detected` (L71) and `test_cancel_during_verification` (L94). Neither covers a change between hash chunks (PE-1).
* `test_pe_overview.py` has cap tests for e_lfanew, sections and directories. None covers the 512 DLL, 4096 function or 20000 name boundaries (PE-6), or a bulk same-ordinal export table (PE-7).
* No test drives `PeTables` over a directory larger than 16 MiB (PE-2). No test covers a large unknown-type relocation count (PE-3).
* `test_pe_resources.py:452` covers controls and bidi characters only, not Cf characters such as U+200B or U+00AD (PE-4).
* `authenticode.py:75` is `# pragma: no cover`. Nothing runs `_win_verify` (S-1).

## Details and fix sketches

**PE-1.** Repro: a 2 MiB+10 file of `A`; the `cancel` callback writes `B` x 4096 at offset 0 on its second call, which runs after chunk 1 is hashed. `open_path` records `sha256` of the original bytes; `read(0, size)` returns `BBBB...`, and the hash of those bytes does not match. Fix: take `_stat_key` before the hash loop, pass it into `__init__`, and after hashing compare the current `fstat` with it, raising `artifact_changed` on any difference. Test: the same callback should now raise `ArtifactBytesError('artifact_changed')`.

**PE-2.** Fix: have `read_rva` read in pieces of at most `MAX_READ_BYTES` (or 1 MiB, to match the spec). Map `ArtifactBytesError` from table reads to `PeTableError`, which is what `rules/window.py` already catches through `ValueError`. Test: a 20 MiB `BaseReloc` returns a `PeTableError` or a correct result, never `ArtifactBytesError`.

**PE-3.** Fix: record each unknown kind once (a set), as `Ctx.warn` does. Test: 100,000 type-4 entries give one warning, and the entry count is unchanged.

**PE-4.** Fix: drop each code point for which `is_hostile` is true, so the drop rule is the shared one. Test: parametrize over the Cf set, with ids, and assert equality with `is_hostile`.

**PE-5.** Fix: call `is_hostile(char)` in `_snippet` (it is cheap per character) and delete `_UNSAFE`. Test: this file's snippet equals `is_hostile` over the BMP and SMP.

**PE-6.** Fix: read the descriptor, then apply the cap only to a non-zero descriptor (same for thunks and names). Test: 511, 512 and 513 descriptors; 512 must not be truncated, 513 must be.

**PE-7.** Fix: store `dict[int, dict[str, None]]` (ordered set) per index. Test: 20,000 names on one ordinal finish under a budget, with the same entries as now.

**PE-8.** Fix: when `limit` is below `cap + 1` and no NUL is found, return the unreadable or section-bounded case under its own code (for example `name_unmapped`) instead of `name_truncated`. Test: the 300-byte case.

**PE-9.** Fix: delete the unused whole-document path from the public API, or make it a generator with a test. No product caller is affected.

**PE-10.** Doc-only. Update the "Not done" section, the warning list and the hashlib sentence to match the code.

**PE-11.** Fix: compute the gutter width once per page and pass it to `format_hex` and `format_binary`, or reword the spec to say "per segment".

**PE-12.** Fix: thread the `cancel` hook through `PeTables`, poll every 1024 entries in the `.pdata` and `.reloc` loops, and read in chunks (see PE-2).

**PE-13.** Add the tests listed above with the fixes, one red test per finding first.

## Suspicions (not counted)

* **S-1. Authenticode constant and untested path.** `authenticode.py:96` sets `wtd_revoke_none = 0`. The Windows SDK constant `WTD_REVOKE_NONE` is `0x1`, and `pe-overview.md` names `WTD_REVOKE_NONE`. Network is still blocked by `WTD_CACHE_ONLY_URL_RETRIEVAL` (`0x1000`) and `WTD_REVOCATION_CHECK_NONE` in `dwProvFlags`. Any ctypes error is caught at `authenticode.py:69-70` and reported as `unavailable`, so the probe could fail silently on Windows. A Windows run is needed to confirm both points.
* **S-2. `OSError` bypasses the artifact error contract.** `artifact_bytes.py:87` (`_stat_key` inside `open_path`) and `:155` (inside `read`) can raise a bare `OSError`. `artifact_inspection.py` catches only `ArtifactBytesError`, so the "never raises for per-side failures" contract can break. Not reproduced.
* **S-3. Trust probe reopens by path.** `artifact_inspection.py:98` calls `verify_trust(safe_path(...))`. The docstring says it runs on hash-verified copies, but it reads the path rather than the verified handle. Low risk for immutable project copies.
* **S-4. Comment state past the cap.** `codetext/model.py` (`_comment_rows`) uses `open_comment_lines`, which stops at `MAX_DOCUMENT_CHARS` (`tokens.py:299-304`). Lines after 1 MiB in a pane are treated as outside block comments. Cosmetic. Not run.
* **S-5. Duplicated PE table readers.** `pe_overview/tables.py` says it is copied from `tools/calibration/tier_w/pe_tables.py`. `unified/ir/pe_tables.py:170-310` has its own `.pdata` and `.reloc` readers. Fixes for PE-2 and PE-3 must be applied to every copy. Outside this area; not reviewed in depth.
* **S-6. Windows path handling.** `artifact_bytes.open_path` has no `\\?\` long-path handling. Paths over 260 characters become `unreadable`. Depends on `ingestion.safe_path`, which was not reviewed.

Positive results (no defect found): tokenizer round-trip on 3,000 random strings (both languages), no failures; `resources`, `version_info`, `manifest` and `certificates` have bounded loops, cancel polls and a stage fault boundary; `intraline` band and bit-parallel LCS arithmetic re-derived by hand and consistent; `SectionMap` overlap rules match `pe-overview.md`.

## What I reviewed

Read in full: `pe_overview/_common.py`, `headers.py`, `sections.py`, `directories.py`, `certificates.py`, `debug_info.py`, `entropy.py`, `inspect.py`, `imports_exports.py`, `exports_table.py`, `resources.py`, `version_info.py`, `manifest.py`, `authenticode.py`, `tables.py`, `api_delta.py`, `compare.py`, `models.py` (`Limits`, `SectionMap`; `PeOverview` only at its accessors); `artifact_bytes.py`, `raw_view.py`, `artifact_inspection.py`; `representations/` (`paging.py`, `formatters.py`, `render.py`, `compare.py`, `scope.py`, `__init__.py`); `codetext/` (`tokens.py`, `names.py`, `intraline.py`, `operands.py`, `oracle.py`, `model.py`); `symbols/decoration.py`, `symbols/kinds.py`; `hostile_text.py`; `docs/specs/pe-overview.md`, `docs/specs/byte-representations.md`, `docs/plans/worker-brief.md` section 2, `docs/plans/e4-audit-and-qa-plan.md` sections 2 to 5.

Automated evidence (scratch, not in the repository):

* `repro1.py` and `repro2.py`: the repros quoted above, each run once. Output is in the table.
* `fuzz1.py pe`: 400 + 6,000 mutated PE files built with `tests/pe_builder.py`, through `inspect_pe`. Zero `internal_error_*` warnings.
* `fuzz2.py`: 795 + 3,975 mutated files with a resource directory, through `parse_resources`, `parse_version_info` and `parse_manifests`. Zero escaped exceptions.
* `fuzz1.py lossless`: 3,000 random strings in `c` and `asm`. Zero round-trip failures.
* Existing tests were not run. `pytest` is installed but `pydantic` is missing in this sandbox, so collection fails for the focused test files. This is not verified here; the integrator's gate covers it.

## Not reviewed

* `codetext/palette.py`, `codetext/marks.py`, `codetext/__init__.py`, `symbols/__init__.py`, `pe_overview/__init__.py`, `pe_overview/panel.py` (Qt adapter), and `models.py` outside `Limits`, `SectionMap` and `PeOverview` bodies.
* `ingestion.safe_path` and all Windows-only behaviour (`WinVerifyTrust`, long paths, reserved names, case-insensitive collisions). Nothing was executed on Windows.
* Qt widgets: `ui_codetext.py`, `codetext_view.py`, `pemeta_view.py`, `raw_cleanup.py`.
* `rules/window.py` and `unified/ir/pe_tables.py` beyond the excerpts needed for impact (S-5).
* Test bodies (grep only), `docs/qa.md`, `tasks/todo.md`, `docs/modules.md`.
* GitHub state beyond the fast-forward: open PRs and checks were not inspected, because this is a read-only audit.
