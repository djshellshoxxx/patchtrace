# Raw byte representations (SPEC-26 requirement B, Hex / Binary / Base64)

## Responsibility

Package `patchtrace.representations` turns verified, original on-disk bytes of a project-owned artifact into bounded, labelled pages in three views: Hex, Binary and Base64. It is pure Python (stdlib only, no Qt, no execution, no network). It owns scope selection, paging, text formatting, captions, copy text and byte-level comparison. It owns no widgets; a UI layer calls it from a worker thread.

The only source of bytes is `patchtrace.artifact_bytes.VerifiedArtifactReader`. Metadata, decompiled text and assembly are never encoded as bytes by this package, and no API here accepts text for encoding. Decompiled output is Ghidra C-like text, not original bytes; presenting it as Hex/Binary/Base64 would mislabel it, so it is out of scope by construction.

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
Native performance acceptance remains separate work. The opt-in desktop adoption is described below.

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
short tails; exact reconstruction and monotone physical offsets; >4 GiB offsets and overflow; unchanged legacy
mask; noncontiguous/malformed page rejection; deterministic work/span bounds and cancellation before/during a
search. No binary is executed by these controls.

### Formats

#### RD-F03 paired physical windows (desktop)

Hex/Binary offer an unchecked-by-default paired alignment control. Older and newer physical file offsets are
entered independently as hexadecimal, and the requested window is an integer multiple of 16 within 16..4096
bytes. These values never infer function identity or an RVA. Each submission captures verified readers and
scalar inputs on the GUI thread, then reads and aligns on the existing TaskRunner. Reads use exact, EOF-clipped
file-range scopes with `clip=False`; nonempty pages go through `align_pages`. An offset at EOF yields an explicit
unavailable alignment and original bytes from the other side, not fabricated padding or a claimed insertion.
Offsets past EOF are rejected. Clipped windows and complete/ambiguous/unaligned/limited reasons remain visible.

Aligned rows retain each side's physical gutter; missing row bytes appear as a labelled display-only gap, never
zero bytes or an invented file offset. A span selector and previous/next controls navigate this single bounded
result, including unresolved spans. They never carry an inferred shift into another window. Copy formats the
exact original window bytes and their physical ranges/digest, without alignment labels or gaps. Base64 and the
default fixed-offset view retain their existing behavior. The controls never infer continuation offsets.
While paired mode is active, the Copy buttons, keyboard Copy shortcut and raw-pane context-menu Copy all use
this original-window copy route. Current paired captions replace earlier fixed-window tooltip provenance;
invalidating a result clears both its Copy availability and its provenance tooltip.

Mode, project, orientation, selection, inspection, input and panel visibility changes invalidate pending and
displayed results. Cancellation happens before releasing inspected readers; late results must match the captured
context and generation. Close and application quit cancel work through the shared TaskRunner. Summary layout is
allocated by its existing parent layout before result paint, including status/EOF line wrapping at narrow widths.
Its current wrapped height is a layout minimum even if the splitter does not propagate height-for-width.
Width/font/style changes recalculate it; shorter status text releases the previous minimum.


Hex line: lower-case offset gutter (at least 8 digits, widened consistently when needed), two spaces, byte columns with an extra space after the 8th byte, then `|ascii|` where only 0x20..0x7e are shown and every other byte (nulls, high-bit) is `.`. A partial last line is padded so the ASCII column aligns. Binary line: offset gutter, two spaces, 8-bit groups (`01001101`) separated by a space. Base64: RFC 4648 standard alphabet with padding; wrapping is display only, `base64_exact` is the single-line form and encodes exactly the page bytes in logical order. For non-contiguous pages Hex/Binary emit one segment header line per chunk; Base64 shows no headers inside the encoded text (the caption lists the segments) so the text stays valid Base64.

Caption contains: scope label, representation, file offset range(s), byte count, page n/m, SHA-256 of the displayed bytes and the words "original on-disk bytes (not transformed)". Copy text is a one-line attribution header (`#` prefixed) followed by exactly the displayed text.

## Error contract

Reads use `clip=False`, so a file that changed, shrank or was swapped surfaces `ArtifactBytesError` (codes from `artifact_bytes`) unmodified; this package never catches or replaces it with guessed data. A reader whose size differs from the size recorded in the scope raises `ArtifactBytesError('size_mismatch')`. Argument errors are `ValueError`/`TypeError`; page index errors are `IndexError`.

## Bounds

* One page is at most 65536 input bytes (`MAX_PAGE_SIZE`); `render_page` rejects larger pages.
* Memory per page: input <= 64 KiB; rendered text roughly Hex 4.9x, Base64 1.4x, Binary 10x (under 700 KB), plus a copy-text duplicate. CPU is linear in page bytes.
* A single read is bounded by the page size (reader cap is 16 MiB); seeking directly to the page means the last page of a multi-GiB file reads only that page.
* `byte_diff_mask` accepts inputs up to 65536 bytes each (`ValueError` otherwise).
* Function scopes are capped at 1 MiB by default (`max_length`).

## Not covered

PE parsing and the RVA map (separate worker), UI widgets, asynchronous scheduling and goto-RVA/goto-offset controls (the UI composes `file_range` and `function_rva`).
