# SPEC-RD-01 — radiff2-inspired multi-layer binary comparison
Status: Proposed, research and implementation contract (2026-10-14). No feature is claimed implemented.

## Research provenance and version caveats
Primary source: official radare2 current manual https://github.com/radareorg/radare2/blob/master/man/radiff2.1 (manpage dated July 10, 2025); official book https://book.rada.re/tools/radiff2/intro.html and https://book.rada.re/tools/radiff2/binary_diffing.html ; upstream source https://github.com/radareorg/radare2/blob/master/libr/main/radiff2.c . Historical examples differ markedly from current options: old `-c` meant count while modern `-n` means count; old `-i` meant imports, modern `-i type` compares multiple bin-information categories; old `-B` meant GDIFF, modern `-B addr` sets base. Runtime capability probing and tested version pinning are mandatory.

radiff2 uniquely *combines* convenient byte ranges, offset alignment, delta comparison, executable section metadata, opcode-only code diff, code graph matching, per-function CFG diff, JSON and Graphviz/r2 command output through one CLI. Individual methods are not fundamentally unique to radiff2 or unavailable elsewhere; do not advertise global uniqueness against BinDiff/Diaphora/Ghidra. The opportunity for PatchTrace is independent multi-layer evidence, fast triage, raw offset navigation and differential diagnostics, not wholesale replacement of Ghidriff.

## Verified documented modes (current manpage)
- Bare command: changed raw byte spans. `-x` two-column hex; `-D` disassembly display; `-u` unified format; `-r` radare commands; `-X` xpatch output. `-n` count.
- `-d`: delta diff to align insertions/deletions instead of only comparing same absolute offsets.
- `-s`: Myers-style insertion/deletion edit distance O(ND) as documented; `-ss`: Levenshtein with substitutions, quadratic. Guard large inputs: these are expensive and scores are not function-match probabilities.
- `-o offA:offB` with `-l lenA:lenB`: focus distinct ranges, used with strict file-offset bounds, detect base/image relocation separately. `-p` affects physical addressing in code diff modes.
- `-i type`: imports/exports/symbols/sections and related executable metadata depending on backend/build; discover types via versioned `-i help`.
- `-O`: opcode-byte comparison ignoring other instruction bytes. This can discount operand changes: valuable for code-shape comparison, but dangerously obscures changed constants, displacements and branch targets. Always present full-byte counterpart.
- `-C` with `-A` or `-AA`: analyze then match functions by code/graph, threshold `-t` default 70%; `-g sym` or `-g oldaddr,newaddr`: focused per-function graph differences.
- `-m a/s/d/g/j/J/k/t/i`: graph renderings ASCII, radare2 script, Graphviz DOT, GML, JSON, JSON+disassembly, sdb, tiny/interactive ASCII. Ingestion must use structured formats and validate the actual schema. DOT is optional export only.
- `-j`: JSON where supported; `-f` selects format where supported; saved `.prj` analysis can be compared with `-C` without new `-A`, provided projects have validated provenance.
- `-T` thread option is explicitly experimental/crashy in upstream manual: never enable by default.

## Analysis of technical operation
Raw byte diff compares byte sequences and detects changed offsets; naive offset-aligned differences cascade after insertion. Delta mode permits resynchronization to locate correspondences after shifted data; design our own aligned-span representation and assert reversible offsets. Myers O(ND) edit script computes minimum insertion/deletion edits between sequences; Levenshtein allows substitutions, with memory/time guards. Disassembly mode requires correct architecture, bitness and executable mapping. Opcode-only comparison separates instruction encoding opcode from operands but must retain operand deltas. Code comparison first discovers functions and builds control-flow/basic-block information using radare2 analysis; its graphdiff estimates function correspondence and supports focused CFG comparison. r2 heuristics and analysis versions influence results; do not assume one-to-one matching correctness, complete function discovery, or consistent JSON across versions. Saved analysis trades freshness for speed and must be keyed by binary hash and runtime/analysis-settings fingerprint.

## PatchTrace capability gap and cross-engine separation
README of PatchTrace documents Windows PE AMD64, Ghidriff native and imported JSON, function relationships, paired decompiled/assembly/metadata panes, SQLite storage, evidence reviews and offline workers. Verify actual code before wiring. Ghidriff remains primary; radiff2-derived raw data is independent at the raw-byte level but may share disassembler heuristics with Ghidra conceptually. Avoid double-counting correlated scores. Complement SPEC-QB-01 (QBinDiff-inspired programmable matching): reuse typed `MatchingEvidence` / provenance contracts if present, but keep raw byte spans and section metadata outside the function matching solver. Feature-detect optional modules, never cross-import their implementations.

## Standalone modules / stable contracts
- `comparison/ranges.py`: `FileRange(side,offset,length)`, `MappedRange(file_offset,rva,va,section)` with overflow-safe 64-bit arithmetic; valid no RVA when unmapped.
- `comparison/byte_diff.py`: `ByteEdit(kind,old_range,new_range,old_sha256,new_sha256)` plus bounded snippets, streaming hashes; deterministic SAME/INSERT/DELETE/REPLACE.
- `comparison/alignment.py`: bounded chunk/window fingerprint-based realignment with maximum shift/window/budget, fallback 'ambiguous' when repeated blocks. Optional Myers algorithm only for small capped inputs. Never claim byte-level similarity is semantic similarity.
- `comparison/pe_layout.py`: PE section/import/export/header normalized deltas, relocation/overlay/certificate/resource handling; physical file offset distinct from RVA/VA, address mapping verified against PE headers and overflow cases.
- `comparison/opcode_view.py`: instruction operands versus opcode bytes, architecture-specific support based on trusted decoded instructions; never guess instruction boundaries; surface changed immediates/displacements and opcode-stable operand changes as significant.
- `comparison/graph_delta.py`: canonical CFG node/edge change model, old/new node correspondence plus supporting evidence, distinguish unmatched from missing analysis.
- `comparison/engines/radiff2_adapter.py`: optional executable discovery/version/capabilities, command allowlist and explicit argument arrays, JSON adapters pinned per release, no arbitrary `-c`/`-e` input from users, supervised subprocess timeout/memory/cancel.
- `comparison/engines/radiff2_parser.py`: strict per-mode versioned JSON + bounded text parsing where structured format unavailable; no untrusted DOT/HTML injection.
- `comparison/evidence.py`: `ComparisonLayerResult` (layer, status, source, artifacts SHA, tool build, command flags, settings, time, diagnostics, confidence semantics, evidence references).
- `comparison/service.py`: `run_layers(old,new,requested_layers,budget,cancel) -> LayerReport`. Execution results are immutable and cannot edit Ghidriff matches.
- `desktop/widgets/byte_map.py` (future): synchronized changed-span browser and RVA/file-offset jump; progressive/virtualized rendering for large files.

## Priority features and exact acceptance
RD-F01 P1: bounded raw byte span comparator, offsets, counts and hex visualization. Stream input; test empty, identical, one-byte, sparse/dense, insertion/deletion, >4GiB offset via mocks, memory limits. No requirement to install radiff2.
RD-F02 P1: PE-aware layout and section/import/export changes; preserve signed/unsigned status without equating signature change to code change. Detect trailing overlays and relocated sections. Test synthesized PE x64 fixtures.
RD-F03 P1: old/new relative-offset alignment and paired navigation, including `-o A:B` semantics. Align only with explicit ambiguity marker. Test off-by-one, repeated byte blocks, file-vs-virtual address mapping.
RD-F04 P2: optional supervised external radiff2 diagnostic provider (raw/delta/metadata). Freeze a known radare2 build, verify output schema on Windows, never trust text color/locale; no auto-download. Display 'engine unavailable' without failing core analysis.
RD-F05 P2: opcode-only vs full-instruction-byte delta with immediate/offset warnings, Ghidra-derived instructions preferred; radiff2 `-O` as independent evidence, not ground truth. Test immediate-only security fix not suppressed.
RD-F06 P2: per-function CFG graph visualization and comparison from Ghidriff/Ghidra data where present; radiff2 `-g` optionally corroborates. Address identity anchored to artifact hashes, never names alone.
RD-F07 P3: edit-distance metrics using bounded Myers/Levenshtein and explicitly identified cost; coarse byte and section windows only, never entire multi-gigabyte files unconstrained.
RD-F08 P3: optional caching of validated radare2 project analyses, strict hash/version/flags identity, corruption rejection and stale invalidation.
RD-F09 P3: user export raw delta evidence in JSON and HTML/Markdown; optional DOT as inert downloadable text, never rendered as trusted HTML. Patching/radare commands remain export-only with warning and no auto-apply.
RD-F10 P4: cross-engine disagreements, CVE-aware weighting as explanatory evidence only, never convert byte/opcode similarity to vulnerability likelihood.

## UX
Add 'Byte & Layout' tab or collapsible inspector alongside existing decompiled/assembly/metadata choices without replacing them. Three synchronized coordinates: physical offsets, RVAs, VAs, with explicit unmapped states. A change-summary strip groups PE headers, sections, imports, raw bytes, operand-only differences, CFG changes. Filters: executable region/data/overlay, insert/delete/replace, changed immediates, function owner, noise category. Each finding navigates to exact old/new source ranges and corresponding function when known. Show which backend produced each observation, command/version, and whether raw vs interpreted. All controls get hover tooltips.

## Validation and non-goals
Do not clone radare2 internally or implement its full parser/graphdiff solver; reproduce selected capabilities with pure Python and optionally run upstream binary. No patch application or execution of analyzed sample. No invented graph data, assembly, or mapping. Cross-reference SPEC-QB-01 rather than build duplicate graph models. Bench: synthetic PE x64 with known changed branch immediate, adding a section, alignment shifts, changed imports, padding only, embedded PDB/relocation drift; real signed MSFT binaries only with authorized provenance. Compare Ghidriff-only and all-layers data without changing baseline. Performance measured peak memory/latency and changed-span recall. Mandatory failure-injection: missing executable, malformed JSON, timeouts, interrupted streams, bad PE signatures, cancellation, stale cache, multi-project races.
