# PE overview (SPEC-26 requirement D, backend stream)

## Responsibility

`patchtrace.pe_overview` produces a bounded, read-only, preliminary description of a PE file
(EXE/DLL/SYS), a section map for the raw byte viewer, a field-by-field old/new comparison and an
optional, Windows-only Authenticode trust probe. It never executes, loads or maps the target, never
touches the network, imports no Qt and uses only the stdlib (`struct`, `hashlib`-free: identity comes
from the reader). All bytes come from `patchtrace.artifact_bytes.VerifiedArtifactReader`; no other
file access exists in the package except `authenticode.verify_authenticode(path)`.

## Interface

- `inspect_pe(reader, *, cancel=None, limits=Limits()) -> PeOverview`
- `PeOverview.to_dict()` (JSON-serializable), `PeOverview.section_map() -> SectionMap`
- `SectionMap.from_overview(ov)`, `SectionMap.rva_to_file_ranges(rva, length) -> tuple[FileRange, ...] | None`
- `compare_overviews(older, newer) -> tuple[FieldComparison, ...]`
- `authenticode.verify_authenticode(path) -> TrustResult`, `authenticode.classify_hresult(hr) -> str`

All records are frozen slotted dataclasses. Unavailable values are `None`, never guessed.

## Error contract

`inspect_pe` never raises for malformed or hostile content. It returns a `PeOverview` with
`status` in `ok | partial | not_pe | cancelled` and `warnings` (`PeWarning(code, message)`, stable codes).
`not_pe`: no `MZ`, or a readable but wrong `PE\0\0` signature. `partial`: any header stage truncated,
cap exceeded, unreadable table or any other warning except purely informational ones. `cancelled`: the
`cancel` callable returned true between stages or between chunks; fields gathered so far are kept.
Only `ArtifactBytesError` from the reader (I/O or identity failures) propagates. An unexpected internal
exception in a stage is converted to the warning `internal_error_<stage>`.

Warning codes: `too_short`, `not_mz`, `lfanew_out_of_range`, `lfanew_over_cap`, `pe_signature_missing`,
`coff_truncated`, `optional_header_truncated`, `optional_magic_unknown`, `directories_over_cap`,
`section_count_over_cap`, `section_table_truncated`, `section_unmapped`, `import_rva_out_of_file`,
`import_descriptor_loop`, `import_name_pointer_loop`, `import_dlls_over_cap`, `import_functions_over_cap`,
`import_names_over_cap`, `export_rva_out_of_file`, `export_count_implausible`, `export_names_over_cap`,
`name_truncated`, `debug_unparseable`, `certificate_table_out_of_file`, `certificate_entry_invalid`,
`data_after_certificate_table` (informational), `checksum_skipped_large`, `internal_error_*`.

## Limits (`Limits`, all enforced)

max e_lfanew 64 KiB; max sections 96; max data directories 16; max import DLLs 512; max functions per
DLL 4096; max total import names 20000; max name length 512 bytes; max export names 20000; entropy cap
8 MiB per section/overlay (`sampled=True` when capped; the first 8 MiB is measured); checksum skipped
with a warning above 256 MiB. Reads are made in at most 1 MiB pieces. `cancel()` is polled between stages
and between chunks.

## Semantics

- Kind: `DLL` if IMAGE_FILE_DLL; else `SYS` if subsystem is NATIVE; else `EXE` if IMAGE_FILE_EXECUTABLE_IMAGE;
  otherwise `unknown`. A reason string states the rule. This is a heuristic, not a filename claim.
- COFF timestamp: raw integer plus ISO UTC string. It is attacker-controlled (and reproducible builds
  randomize it); it is never a file creation or signing date.
- Entrypoint: RVA and VA (`image_base + rva`) only. Register state is runtime state and is not reported.
- Checksum: stored vs. the standard PE checksum (16-bit ones-complement word sum with the checksum
  DWORD zeroed, folded, plus file length). Match is informational; most user-mode binaries store 0.
- Sections: names decoded latin-1, NULs stripped, control characters replaced by `?`. Entropy is Shannon
  entropy of raw bytes (bits/byte).
- Overlay: bytes after the last section raw end, excluding the certificate table (which is a file-offset
  directory, not an RVA, and not overlay).
- Certificate table: presence, offset, size, `WIN_CERTIFICATE` headers. `signature_status` is always
  `not_verified` in the overview; presence of a table is never validity.
- Debug: CodeView `RSDS` (GUID, age, bounded PDB path) when safely parseable.
- Packer hints: section-name and layout evidence with `confidence` `low` or `medium` and an evidence
  string. Entropy alone never produces a compression claim (only a low-confidence "high entropy
  executable section; may be packed or encrypted" note).

## SectionMap rules

Header region (`rva < size_of_headers`) maps 1:1 to file offset 0. In a section, an RVA in
`[VirtualAddress, VirtualAddress + extent)` (`extent = VirtualSize or SizeOfRawData`) maps to
`rva - VirtualAddress + PointerToRawData` while below `SizeOfRawData` and inside the file. Virtual-only
bytes, gaps, unmapped RVAs, overlapping coverage (including a section overlapping the header region),
negative values and results above 2**32 return `None`. A range crossing contiguous file-backed regions
returns one `FileRange` per region; a zero length returns `()`.

## Authenticode (`authenticode.py`)

Windows only, `WinVerifyTrust` via ctypes (`WTD_REVOKE_NONE`, `WTD_UI_NONE`, `WTD_CACHE_ONLY_URL_RETRIEVAL`
and `WTD_REVOCATION_CHECK_NONE`; `WTD_STATEACTION_VERIFY` then always `WTD_STATEACTION_CLOSE`). Status:
`trusted_no_revocation_check | unsigned | untrusted | invalid | unknown | unavailable`. It is never
described as fully valid: revocation was not checked. Embedded signatures only: catalog-signed files
report `unsigned` or `unknown`. Other platforms return `unavailable` without touching `windll`.

## Not done

No execution or loading, no network, no revocation or timestamp-authority checks, no catalog
signatures, no certificate chain parsing or signer names, no version-info or manifest parsing, no
resource enumeration (directory presence only), no .NET metadata, no ARM64EC/CHPE analysis, no trust in
timestamps, no unpacking.
