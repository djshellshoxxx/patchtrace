# 15. Files, PE overview and raw bytes

PatchTrace can show you facts about the two files **without any analysis backend**: what was recorded when the project was created, what a bounded read-only PE parse says now, and the raw bytes themselves. Nothing here executes, loads or installs the target. Specs: `docs/specs/pe-overview.md`, `docs/specs/pe-version-authenticode.md`, `docs/specs/byte-representations.md` (SPEC-26 parts A to D). Internals: [21](../internals/21-data-model-and-storage.md).

## The Files dock

Open **Project > File overview** (or View > Files). It is a bottom dock, **read-only**, and needs an open project. It has an explanation line, a status line, and two tables side by side:

**Recorded fields** (no file access, saved at project creation): File name, File size, Size change (newer minus older), SHA-256, Content hash comparison (Identical or Different), Format (`PE`), Architecture (`x86-64`). Source: `preflight.overview_rows`.

**PE comparison** (columns PE field, OLDER, NEWER, Status, Provenance). It first re-verifies each project-owned artifact copy against its recorded SHA-256 (`artifact_bytes.VerifiedArtifactReader`), then parses with bounded reads. Each row is `unchanged`, `changed` (bold) or `unavailable`, with a reason and provenance on hover. Rows (from `pe_overview/compare.py`):

| Group | Rows |
|---|---|
| Identity | file size, SHA-256, header magic, PE type (heuristic) |
| COFF header | Machine, COFF timestamp (labelled untrusted: forgeable or randomized, not a creation or signing date), Characteristics |
| Optional header | format, entrypoint RVA and VA, image base, section and file alignment, size of image and headers, Subsystem, DLL characteristics, stored and computed checksum |
| Sections | count, names, virtual/raw sizes, packer hints (heuristic, with confidence) |
| Imports/exports | imported DLLs (with "added" and "removed" reasons), imported function count, export count |
| File scan | overlay present and size |
| Data directories | certificate table present (**signature not verified**), TLS, relocation, exception, resource, debug |
| Debug | PDB path, PDB GUID and age (from the CodeView record) |

An `unavailable` row says which side lacked the value and each side's parse status (`ok`, a partial status, or `cancelled`). `inspect_pe` never raises for malformed content; it returns what it could read plus parser warnings (for example "reserved bits in a PE32+ thunk"). Limits keep it bounded: at most 96 sections, 512 import DLLs, 4,096 functions per DLL, 20,000 names in total, 512 characters per name, entropy sampled over at most 8 MiB, checksum computed for files up to 256 MiB, 64 certificate entries (`pe_overview/models.Limits`).

Inspection runs on its own worker thread, independent of the analysis job. A result is used only if it still matches the current project and orientation (an identity key is compared); otherwise it is discarded and the check restarts.

### Authenticode row

On **Windows only**, an extra row "Authenticode (embedded, offline)" reports the result of `WinVerifyTrust` with **no revocation check and no network**. Possible statuses and their wording:

| Status | Text shown |
|---|---|
| `trusted_no_revocation_check` | embedded signature chains to a trusted root (revocation NOT checked) |
| `unsigned` | no embedded signature (catalog signing not checked) |
| `untrusted` | signature present but not trusted |
| `invalid` | signature present but digest/format invalid |
| `unknown` | result unknown |
| `unavailable` | not checked on this platform |

PatchTrace never says "valid" or "fully trusted". Catalog-signed files (common for Windows system files) normally report `unsigned` or `unknown` because catalog signing is out of scope. A certificate table that is present is not a verified signature. Windows acceptance of this probe on signed, trusted and revoked samples is **open** (`tasks/todo.md`).

## Raw bytes in the code panes

In the main window's mode box, **Hex (raw bytes)**, **Binary (raw bytes)** and **Base64 (raw bytes)** show the **verified original file bytes** of each side instead of code. This is useful when a function has no decompiled text.

- **Scope**: *Whole file*, or *From function entry*. The entry address is translated to a file offset through the PE section map. The function's extent is **not claimed**: Ghidriff records carry an entry address but no verified contiguous body range, so the view pages forward from the entry offset and says so. An unmappable or ambiguous entry is reported unavailable; no range is guessed.
- **Paging**: page size 4096 bytes by default (16 to 65,536). Hex shows 16 bytes per line, Binary 8. A go-to-offset box jumps to an offset. A page past the end shows an explicit message instead of clamping.
- **Differences**: lines that differ at equal logical byte offsets are highlighted.
- **Copy** copies the displayed page with provenance. After an orientation swap, Copy never returns bytes from the previous orientation.
- Reads go through the verified reader: a file that changed since the project was created (hash or identity key mismatch) is refused rather than shown.

Raw views do not offer function boundaries, disassembly, or search; they are bytes. Planned and not built: verified function extents, asynchronous page reads, persisted per-hash results (`tasks/todo.md`, SPEC-26 B).

## Build facts: version resource, manifest, API delta (partly built)

Modules exist for the PE resource tree, `VS_VERSIONINFO`, the manifest, export entries and a static imported-API delta (`pe_overview/resources.py`, `version_info.py`, `manifest.py`, `exports_table.py`, `api_delta.py`), plus a pure view model (`pemeta_view.py`) and a Qt tab (`ui_pemeta.py`, "Build facts"). **They are not wired into `inspect_pe` or the Files dock yet** (slice WBQ S5 integrates them), so the dock does not show them today. The same applies to the Qt code colouring and token marks (`ui_codetext.py`, `codetext/`): built and tested offscreen on synthetic text, not yet attached to the main window's code panes. See [99](99-open-doc-questions.md).

## How the bytes are verified

Both the PE comparison and the raw views read through one audited seam, `VerifiedArtifactReader` (`artifact_bytes.py`):

- It hashes the project-owned copy through the **same open handle** it later reads from and compares with the recorded SHA-256 and size.
- It rejects a change detected after verification (identity key includes size, modification time and, on POSIX, change time), a path that is not a regular file (a FIFO or device cannot hang it), and any out-of-range request. A single read is capped at 16 MiB.
- Failures carry a stable code and are shown, never papered over with guessed bytes: `path_invalid`, `unreadable`, `hash_mismatch`, `size_mismatch`, `artifact_changed`, `range_invalid`, `read_too_large`, `closed`, `cancelled`. In the raw panes you will see, for example, "Verified artifact bytes unavailable (hash_mismatch)".
- Windows residual risk: an in-place edit that restores the modification time cannot be distinguished as well as on POSIX (the audit records it; the hash check still applies at open).

## Reading the comparison

- Start with rows marked `changed` (bold). The usual suspects in a servicing update are size of image, section sizes, imported DLLs and function count, entrypoint RVA, the checksum, and the PDB GUID and age. A changed PDB GUID with an unchanged name is the normal result of a rebuild.
- A changed stored checksum with an unchanged computed checksum (or the reverse) is worth a look: the stored value is a header field, the computed one is derived from the bytes.
- An identical hash means the two files are the same file; the sample reports `Identical` in the recorded table.
- "Imported DLLs" shows what was added and removed by name; this is a set difference of DLL names, not of imported functions.
- There is no CLI for this view yet (`pe-meta` is a planned verb); use the dock.

## What this chapter does not claim

- A PE field comparison is a structural check. A change in a header field does not say a patch is security relevant, and an identical header does not say the code is unchanged.
- "Packer hint" is a heuristic, not a detection verdict.
- Symbols and PDB names are text from the file; PatchTrace does not fetch a PDB for this view.
- Drivers are inspected statically only; they are never loaded or installed.

Next: [16 CLI reference](16-cli-reference.md).
