# Raw byte representations (SPEC-26 requirement B, Hex / Binary / Base64)

> **SPEC-31 status amendment (2026-11-04, A-09, documentation only):** the file-level radiff2-inspired items are hosted as SPEC-26 extensions, not SPEC-31: RD-F01 (byte spans), RD-F02 (PE layout delta) and RD-F03 (offset alignment). This file is part of SPEC-26.

## Responsibility

Package `patchtrace.representations` turns verified, original on-disk bytes of a project-owned artifact into bounded, labelled pages in three views: Hex, Binary and Base64. It is pure Python (stdlib only, no Qt, no execution, no network). It owns scope selection, paging, text formatting, captions, copy text and byte-level comparison. It owns no widgets; a UI layer calls it from a worker thread.

The only source of bytes is `patchtrace.artifact_bytes.VerifiedArtifactReader`. Its initial full-file SHA-256 verification also records compact SHA-256 digests of 4 KiB blocks from the same bytes. Every nonempty read re-reads and checks each touched block and returns slices of those exact checked bytes; it checks file metadata before and after the read. Restoring size and timestamps cannot make changed requested bytes pass verification. Untouched blocks are checked when requested; an empty read performs metadata checks only. No verified block cache substitutes for current input bytes. Metadata, decompiled text and assembly are never encoded as bytes by this package, and no API here accepts text for encoding. Decompiled output is Ghidra C-like text, not original bytes; presenting it as Hex/Binary/Base64 would mislabel it, so it is out of scope by construction.

Code-line evidence navigation (next/previous hunk, evidence jump, line anchors) does not apply to raw views. Raw alignment is byte/range alignment only (equal-offset `byte_diff_mask`, or the opt-in bounded alignment below), never text `SequenceMatcher` hunks. The UI must disable code-line evidence navigation while a raw representation is shown.

## Interface

* `Representation` enum: `HEX='hex'`, `BINARY='binary'`, `BASE64='base64'`.
* `Segment(file_offset, length)` frozen dataclass.
* `ByteScope` frozen dataclass: `kind` (`whole_file`, `file_range`, `function_rva`), `segments`, `total_length`, `rva`, `label`, `available`, `unavailable_reason`, plus `file_size` (size the scope was built against, or None) and `clipped`.
  * `whole_file(size)`
  * `file_range(size, offset, length)`: integers only (bool and float rejected), non-negative, below 2**63; clipped to EOF with the clip recorded in `clipped` and the label; offset past EOF raises `ValueError`; offset equal to EOF gives a valid empty scope.
  * `function_rva(section_map, rva, length, *, max_length=1 MiB)`: depends only on the `SectionMapLike` protocol (`rva_to_file_ranges(rva, length) -> tuple[FileRange, ...] | None`, `FileRange` having int `file_offset`, `length`). A `None` result, a result whose lengths do not sum to the request, or malformed ranges yield `available=False` with reason `Function bytes unavailable: RVA range is unmapped, virtual-only or ambiguous`. Bytes are never guessed or extended. Non-contiguous segments keep their true file offsets. A length above `max_length` is unavailable (with its own reason), not clipped.
* `page_count(scope, page_size)`; `read_page(reader, scope, page_index, page_size=4096) -> PageBytes`.
  * `PageBytes`: `page_index`, `page_count`, `scope`, `chunks` (tuple of `(file_offset, bytes)`), `logical_start`, `byte_count`, `sha256` (of the concatenated page bytes).
  * `page_size` must be an int multiple of 16 within 16..65536, else `ValueError`.
  * Index out of range raises `IndexError`. An unavailable scope raises `ValueError` carrying the reason.
* Formatters: `format_hex(data, base_offset, width=16, ascii=True)`, `format_binary(data, base_offset, per_line=8)`, `format_base64(data, wrap=76)`, `base64_exact(data)`.
* `render_page(page, representation) -> RenderedPage(text, caption, copy_text, byte_count)`.
* `compare.byte_diff_mask(older, newer) -> tuple[int, ...]`.

### RD-F03: bounded insertion-aware raw offsets (`raw-offset-align/1`, 2026-11-01)

This is an opt-in backend API in `representations/alignment.py`; `byte_diff_mask` and all existing consumers
retain their equal-logical-offset behavior. It uses only stdlib and original byte sequences, with no external
engine, disassembler, function matching, cache or persisted schema. D-24/D-25/D-26 remain unchanged.
Native performance acceptance remains separate work. The core was ported 2026-11-18 from the unmerged `repair/rzdiff-native-red-control-20261103` chain (commits 953c0e9a, 51a9b4af) together with the Qt-free row model `raw_alignment_view.py` (paired windows, display-only gaps, exact original-window copy). The desktop continuation selectively recovers `ui_raw_alignment.py` from source `b304034e3c310528f7e0a3206eda48c94e0a6873`, following the contract below without adopting the branch's native research tools.

### RD-F03 desktop integration contract (2026-11-18 continuation)

The existing Hex and Binary viewer offers an opt-in paired physical-window mode.
Default fixed-offset rendering, Base64, evidence navigation restrictions and
project persistence remain unchanged. The existing raw navigation widgets are
constructed by the UI adapter; no new project service or persistence schema is
introduced, and the existing `ui.py` line/host seam ceilings remain unchanged.

- Older/newer offsets are explicit independent hexadecimal physical file offsets,
  not RVAs or inferred continuation. Each is bounded by its verified reader size,
  allowing exactly EOF. Window size is 16..4096 bytes per side, in multiples of 16.
- Only the existing verified readers and immutable scalar request values cross
  into the existing `TaskRunner`. Workers use `build_alignment_view`; no Qt,
  project service or SQLite object is passed to the worker.
- Results expose byte-equality, ambiguity, limits, EOF clipping and unresolved
  spans. Paired rows retain each original physical offset. Gaps have an explicit
  display-only label and never become bytes or semantic/function correspondence.
- Span selection navigates both current displays without changing offsets or
  inferring a next window. Copy buttons, Ctrl+C and the paired-view context menu
  copy the exact original window text with artifact/window hashes and project
  provenance, excluding alignment labels and display-only gaps.
- Editing either offset/window, changing match/project/revision/orientation or
  representation, replacing/clearing inspection, hiding the pane or closing the
  window cancels the active generation and clears copy eligibility. Late results
  and errors are ignored unless their complete context still matches.
- Turning off paired mode restores existing fixed-offset rendering. Public raw
  offset navigation exits paired mode before selecting the requested normal page.
  Closing the window/application cancels work through the existing task owner.
- All controls have registered tooltips and accessible names/descriptions. Status
  text remains readable at the supported minimum window size and larger fonts.

Acceptance covers repeated real offscreen Qt execution, worker cancellation,
stale-result refusal, exact copy provenance, independent offsets, EOF/ambiguity,
unchanged fixed-offset/Base64 behavior, tooltip coverage and the unchanged host
seam. Offscreen checks are not native manual or assistive-technology acceptance.

* `align_bytes(older: bytes, newer: bytes, *, older_offset=0, newer_offset=0, limits=AlignmentLimits(), cancel=None)`
  returns frozen `ByteAlignment(policy, status, reason, spans, work_used)`. Both inputs must be immutable `bytes`,
  at most `MAX_PAGE_SIZE` each. Offsets are independent physical file offsets, integer/non-bool, nonnegative, with
  each exclusive end at most `2**63-1`. They are never interpreted as RVA, VA or a function identity.
* `AlignmentSpan(kind, older_offset, older, newer_offset, newer)` holds exact original bytes on both sides.
  Kinds: `equal`, `replace`, `insert`, `delete`, `unresolved`. Empty bytes represent a zero-length range at the
  recorded cursor. Spans partition both inputs in order, without omitted or duplicated bytes; concatenating each
  side reproduces its input exactly. `equal` means byte equality only. A `replace` span is a raw region difference,
  not a minimal edit script or an instruction/semantic correspondence.
* `align_pages(older: PageBytes, newer: PageBytes, ...)` accepts exactly one contiguous chunk per page, validates
  scope/segment types, counts, bounds and non-overlap, page index/count/logical start, byte count and digest.
  The page's logical interval must map through its scope segments to exactly that chunk's physical range; an
  RVA substituted for the chunk's file offset is rejected even when the byte digest is unchanged. Metadata
  validation accepts at most 4096 scope segments and requires a possible legal paging size; it is bounded
  validation before alignment work. It delegates with the validated original file offset. Missing/multiple chunks are
  rejected rather than concatenated with invented offsets; callers may align individual verified segments.

Algorithm: consume bytes equal at the current independent cursors. On a mismatch, index every `anchor_size`
byte window whose start is within `max_shift` bytes of each cursor. Full anchor bytes are dictionary keys, so
hash collisions never establish equality. Resynchronization is allowed only when every shared anchor has one
occurrence on each side and all shared anchors imply the same relative displacement. The earliest such anchor
bounds an insert/delete/replace gap; subsequent equality is checked byte by byte. This is intentionally
conservative: multiple displacements, repeated shared anchors, or a pure inserted/deleted gap that can slide
left over an equal preceding byte return explicit `ambiguous` status. No nearest-match tie-break is used.
Uniqueness is local to the supplied bounded windows, not a claim about the whole artifact or its functions.

An exhausted side yields an exact insert/delete tail unless its boundary is repeat-ambiguous. Equal-length
terminal tails shorter than an anchor retain positional comparison (`replace`); no shifted match is inferred.
If no shared anchor is found for a larger mismatch, return `unaligned` with reason `no-anchor-in-window`, not a
claim that no insertion exists. `complete` means the bounded byte-span description completed; it is never a
semantic or unique historical edit claim.

`AlignmentLimits` defaults/hard maxima: anchor size 16 (allowed 8..64), lookahead/shift 4096 (allowed 0..4096),
work 2,000,000 (allowed 1..2,000,000), output spans 4096 (allowed 1..4096). Work charges one unit per directly
compared byte, `anchor_size` per indexed fingerprint and one per anchor lookup. The work cap is an operation
bound, not a wall-clock promise; dictionaries hold at most `max_shift+1` anchors per side. Input validation is
bounded before allocation. A cancellation callback is checked before work and at every charged operation.
Work/span exhaustion returns `limited` with reason `work-limit`/`span-limit`; cancellation returns `cancelled`.
Every incomplete outcome appends one `unresolved` span covering the entire remaining original input on each
side, reserving space within the span cap. Previously emitted spans remain, and no pending search is published
as an alignment. Callback exceptions propagate. Invalid inputs/limits/pages raise `ValueError`/`TypeError`.

Required controls: insert/delete and distinct old/new file bases; positional replacement and identical/empty
inputs; repeated blocks and shiftable repeated gaps; conflicting displacements; no anchor/beyond-window and

### Formats

Hex line: lower-case offset gutter (at least 8 digits, widened consistently when needed), two spaces, byte columns with an extra space after the 8th byte, then `|ascii|` where only 0x20..0x7e are shown and every other byte (nulls, high-bit) is `.`. A partial last line is padded so the ASCII column aligns. Binary line: offset gutter, two spaces, 8-bit groups (`01001101`) separated by a space. Base64: RFC 4648 standard alphabet with padding; wrapping is display only, `base64_exact` is the single-line form and encodes exactly the page bytes in logical order. For non-contiguous pages Hex/Binary emit one segment header line per chunk; Base64 shows no headers inside the encoded text (the caption lists the segments) so the text stays valid Base64.

Caption contains: scope label, representation, file offset range(s), byte count, page n/m, SHA-256 of the displayed bytes and the words "original on-disk bytes (not transformed)". Copy text is a one-line attribution header (`#` prefixed) followed by exactly the displayed text.

## Error contract

Reads use `clip=False`, so a file that changed, shrank or was swapped surfaces `ArtifactBytesError` (codes from `artifact_bytes`) unmodified; this package never catches or replaces it with guessed data. A reader whose size differs from the size recorded in the scope raises `ArtifactBytesError('size_mismatch')`. Argument errors are `ValueError`/`TypeError`; page index errors are `IndexError`.

## Bounds

* One page is at most 65536 input bytes (`MAX_PAGE_SIZE`); `render_page` rejects larger pages.
* Memory per page: input <= 64 KiB; rendered text roughly Hex 4.9x, Base64 1.4x, Binary 10x (under 700 KB), plus a copy-text duplicate. CPU is linear in page bytes.
* Returned bytes are bounded by the page size (reader cap is 16 MiB). Verification reads only the touched 4 KiB blocks, adding less than 8 KiB of I/O to a nonempty contiguous request; it never rehashes the full file per page. The digest index uses 32 bytes per block (8 MiB per GiB of input), plus bounded working buffers. Construction briefly holds both mutable and immutable digest indexes (up to twice that index memory); reads briefly hold an output buffer and its immutable return copy (up to twice the requested bytes), plus block buffers. Closing the reader releases its digest index.
* `byte_diff_mask` accepts inputs up to 65536 bytes each (`ValueError` otherwise).
* Function scopes are capped at 1 MiB by default (`max_length`).

## Not covered

PE parsing and the RVA map (separate worker), UI widgets, asynchronous scheduling and goto-RVA/goto-offset controls (the UI composes `file_range` and `function_rva`).
