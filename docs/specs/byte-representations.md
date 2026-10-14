# Raw byte representations (SPEC-26 requirement B, Hex / Binary / Base64)

## Responsibility

Package `patchtrace.representations` turns verified, original on-disk bytes of a project-owned artifact into bounded, labelled pages in three views: Hex, Binary and Base64. It is pure Python (stdlib only, no Qt, no execution, no network). It owns scope selection, paging, text formatting, captions, copy text and byte-level comparison. It owns no widgets; a UI layer calls it from a worker thread.

The only source of bytes is `patchtrace.artifact_bytes.VerifiedArtifactReader`. Metadata, decompiled text and assembly are never encoded as bytes by this package, and no API here accepts text for encoding. Decompiled output is Ghidra C-like text, not original bytes; presenting it as Hex/Binary/Base64 would mislabel it, so it is out of scope by construction.

Code-line evidence navigation (next/previous hunk, evidence jump, line anchors) does not apply to raw views. Raw alignment is byte/range alignment only (`byte_diff_mask`), never text `SequenceMatcher` hunks. The UI must disable code-line evidence navigation while a raw representation is shown.

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

### Formats

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
