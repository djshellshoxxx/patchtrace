# SPEC-31 audit, slice irx (ProgramIR + extraction), 2026-11-04

Scope: `unified/ir/*` (not `ladder_port.py`), `unified/extract/*`, their tests. Baseline main 25b2ac8. Method: read code and
tests, probe hostile input, red test then minimal fix, one commit per defect group. Ghidra is not installed: fakes only.

Primary sources used: google/bindiff v8 `graph_util.h`, `flow_graph.cc`, `call_graph.cc`
(https://raw.githubusercontent.com/google/bindiff/v8/graph_util.h and siblings); MS PE format
(https://raw.githubusercontent.com/MicrosoftDocs/win32/docs/desktop-src/Debug/pe-format.md, mirror of
learn.microsoft.com/en-us/windows/win32/debug/pe-format) and x64 exception handling
(https://raw.githubusercontent.com/MicrosoftDocs/cpp-docs/main/docs/build/exception-handling-x64.md, mirror of
learn.microsoft.com/en-us/cpp/build/exception-handling-x64); learn.microsoft.com itself is blocked by the session proxy.

DELIBERATE identity change: `extract/ghidra_script.py` changed (irx-04, 08, 09), so `script_sha256` and every `ir_key`
change (old IRs are a cache miss). Ingest also changed what the SAME extractor output becomes (irx-03/04/10/13/14), so
`ir_key` now mixes `schema.INGEST_REVISION` (2) via `ingest.ingest_identity_digest` (runner mirrors it for
`predict_ir_key`; tests/test_unified_irx_key.py proves the key moves). `content_digest` of unchanged data is unaffected. The recorded fixtures keep their older script hash; no test compares it with the
current script. No `config_digest`, pass-table digest or persisted contract changed; no schema regeneration needed.

ID | severity | file:line | defect | status
---|---|---|---|---
irx-01 | High | ir/cfg.py `count_back_edges` | walked the idom chain per edge: O(blocks^2); 6.5 s at 20k blocks, minutes at the L-06 max | fixed: tests/test_unified_irx_cfg.py (hypothesis equality + 60k line < 5 s)
irx-02 | Medium | extract/runner.py `OutputGuard.__call__` | every `*.part` file was exempt from L-05, so a child could grow it unseen | fixed: test_a_part_file_other_than_the_progress_temp_counts_towards_the_cap (+ existing guard test amended: it encoded the hole)
irx-03 | Medium | ir/records.py, extract/ghidra_script.py patterns | `$` anchor matched before a trailing newline: "MOV\n", sha+"\n", "rva:1\n", raw hex+"\n" parsed as valid | fixed: test_a_trailing_newline_never_passes_a_shape_check, test_reference_text_with_a_trailing_newline_is_rejected
irx-04 | Medium | ir/records.py `_CONTROL`, extract/ghidra_script.py `_CONTROL`/`_CODE_CONTROL`, extract/runner.py `_STDERR_UNSAFE` | narrow copies of the control regex (no soft hyphen, zero-width, bidi marks, tag chars), U7-09; spec 12.3 says bidi/separators become `?` | fixed: test_scripts_control_ranges_equal_contracts, test_records_sanitiser_equals_contracts, test_stderr_scrub_hides_everything_the_shared_definition_hides
irx-05 | Medium | ir/ingest.py `ingest` | any failure after the DB was created (bad line, footer, L-07, cancel) left ir.sqlite3 in the caller's directory | fixed: test_a_failed_ingest_leaves_no_sidecar_behind, test_an_ingest_over_the_file_cap_leaves_no_sidecar_behind
irx-06 | Medium | ir/reader.py `_csr`, `open`, row readers; ir/schema.py `open_readonly` | corrupt rows raised raw IndexError (callee/fid out of range, negative index silently wrapped), TypeError, JSONDecodeError, sqlite3.DatabaseError; handle leaked when a PRAGMA failed | fixed: test_a_corrupt_row_is_a_typed_store_error (5), test_a_corrupt_block_row_is_a_typed_store_error (2), test_a_truncated_database_is_a_typed_store_error
irx-07 | Medium | ir/pe_tables.py `_in_section` | linear scan of all sections twice per RUNTIME_FUNCTION: ~10 s for 1M hostile entries x 96 sections | fixed: test_section_cover_is_the_union_even_for_overlapping_sections (hypothesis)
irx-08 | Medium | extract/ghidra_script.py `parse_pe_header` | read the file from 0 up to a hostile `e_lfanew` (up to 4 GiB) into memory | fixed: test_parse_pe_header_does_not_read_the_file_up_to_a_hostile_e_lfanew
irx-09 | Medium | extract/ghidra_script.py `import_key` | DLL part with a space, `!` or lengthening `lower()` (>128) built a key the ingest regex rejects: whole IR refused for one odd import | fixed: test_the_scripts_import_keys_always_pass_the_ingest_shape (5)
irx-10 | Medium | ir/records.py `parse_fn` import / `_IMPORT_KEY` | import stub dll/name and call/ref import keys were never sanitised: bidi/invisible text reached fn.import_key / call.import_key | fixed: test_import_stub_dll_and_name_are_sanitised_like_every_other_text, test_import_keys_with_bidi_or_invisible_characters_are_rejected
irx-11 | Medium | extract/runner.py `_spawn` | guard polls ~50 ms; a child that wrote past L-05/L-36 and exited inside one interval was accepted (oversized GZF reached retention) | fixed: test_output_written_past_a_cap_by_a_child_that_exits_at_once_is_still_refused
irx-12 | Low | ir/place.py `_replace`/`place_ir` | concurrent placement of the same key or a full disk gave a raw OSError (only PermissionError mapped) | fixed: test_a_concurrent_placement_of_the_same_key_is_idempotent_not_a_raw_oserror, test_a_failed_move_is_a_store_error
irx-13 | Low | ir/records.py `parse_fn` | `truncated: true` with raw bytes accepted (keys hashed a partial body, flag not set) | fixed: test_truncated_with_raw_bytes_is_rejected
irx-14 | Low | ir/records.py `_parse_objs`, `_parse_blocks` | `addr` object not bounded by the image (spec: null outside); block start+length not bounded by the image | fixed: test_an_addr_object_outside_the_image_is_rejected, test_block_extent_must_lie_inside_the_image
irx-15 | Low | extract/ghidra_script.py `_write_ir` | the script never enforces the L-05 line cap; a ~100k-instruction function can approach 64 MiB (raw hex alone 32 MiB) and the whole IR is then refused `line-too-long` | deferred: needs a script-side size check (truncate to `truncated`); changes behaviour on real binaries, needs live acceptance
irx-16 | Low | ir/records.py `parse_fn` | `calls[].site` and `strings[].site` are not required to be instruction RVAs of the function (referential integrity is only enforced for blocks and instructions) | deferred: spec 12.3 does not require it; no consumer depends on it today
irx-17 | Low | ir/ins.py `decode_text` | a function with exactly one instruction whose text is empty decodes to `[]` instead of `['']` | deferred: Ghidra never yields an empty instruction text; fix needs the instruction count at the call site
irx-18 | Low | extract/ghidra_script.py `extract_function` | body ranges outside the image make `len(raw) != total`; the function is flagged `oversize` instead of a distinct cause | deferred: label only; warning `range-outside-image` is recorded
irx-19 | Low | ir/ingest.py | `l08_ingest_rss_bytes` (L-08 target RSS) is not enforced or measured in ingest (the time budget is the caller's `Budget`) | deferred: spec calls it a target; the worker owns the RSS guard
irx-20 | info | ir/mdindex.py | verified against bindiff v8: edge formula and weights {2,3,5,7,11,13}, BFS levels (level 0 doubles as unvisited, roots seeded), top-down from in-degree 0 and bottom-up from out-degree 0, ascending sort + plain left-to-right accumulation, call-graph vertex MD sums the stored full-weight edge values with a self loop counted twice (`CallGraph::GetMdIndex(Vertex)`) | no defect; attribution header kept. Note: `CalculateMdIndexNode` with level weights 0 exists in graph_util.h but is not what `CallGraph::GetMdIndex(Vertex)` uses
irx-21 | info | ir/pe_tables.py | verified against the PE spec (Base Relocation Block: Page RVA, Block Size incl. header, WORD entries type<<12|offset) and the x64 doc (UNWIND_INFO tail `(CountOfCodes+1)&~1` UWORDs, chained RUNTIME_FUNCTION, flags exclusive of handlers): loops end (SizeOfBlock 0/<8/odd/oversized stop with `reloc-unreadable`; chain cycles, self chains and chains over MAX_CHAIN_HOPS clear the primaries); caps raise PT-UNIFIED-LIMIT | no defect; tests/test_unified_irx_pe.py pins it
irx-22 | info | ir/features.py, operands.py, retain.py, decomp.py | determinism checked (sorted multisets, sorted mnemonic vocabulary, no set/dict order in rows or digest); fuzz of 3000 single-field mutations of valid JSONL produced only UnifiedError, never a crash (scratch fuzz, not committed) | no defect

## ASKS (outside the owned files)
- None blocking. `extract/__init__.py` and `contracts.py` stay as is; the shared definition `contracts.strip_unsafe` is now
  used by `records.py` and `runner.py`, and the script's copy is pinned equal by test.
