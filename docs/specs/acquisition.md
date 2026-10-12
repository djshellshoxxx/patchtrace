# SPEC-08: Binary acquisition (Phase 3a)

Status: developer-ready contract, 2026-10-12. Contract version `acquisition/1`. Verified tool facts: `../research/phase3/acquisition.md` (Winbindex @ aacec0c, live msdl probes 2026-10-12).

## 1. Outcome and boundaries

An analyst names a Windows file (e.g. `clfs.sys`) and picks two builds from a candidate list; PatchTrace downloads both from the Microsoft public symbol server with explicit consent, verifies them, quarantines and identifies them, and creates a normal two-artifact project from them. Nothing is executed, installed or re-hosted. Downloads are for the user only; PatchTrace never redistributes Microsoft binaries or bundles Microsoft DLLs. Winbindex is a metadata source (GPL-3 data, fetched at runtime, never bundled).

Out of scope for `acquisition/1`: extracting files from update packages/ISOs, Insider and ARM64 datasets (x64 only), automatic polling, and non-PE files.

## 2. Modules

| Module | Responsibility | Imports |
|---|---|---|
| `acquisition/contracts.py` | Strict records below | pydantic |
| `acquisition/winbindex.py` | Pure parsing of `<name>.json.gz` into `BuildCandidate`s; URL derivation | stdlib |
| `acquisition/transport.py` | Consented HTTPS GET/HEAD with allowlist, redirects, caps (same pattern as `enrichment/intelligence.py`) | stdlib urllib |
| `acquisition/quarantine.py` | Staging, hashing, PE/PA30 identification, promotion into project inputs | ingestion |
| `acquisition/delta.py` | Optional Windows-only PA30/PA31 reconstruction via the system `msdelta.dll` (ctypes) | ctypes (Windows) |

Pure modules import no network/Qt. The service creates projects through the existing `ProjectService.create`; acquisition only supplies verified local files.

## 3. Records

- `AcquisitionQuery`: `file_name` (lowercase basename, `^[a-z0-9._-]{1,128}$`, PE extension in {exe,dll,sys,efi,drv,ocx,cpl,scr}), `dataset: Literal['x64']`.
- `BuildCandidate`: `file_name`, `sha256`, `size` (int), `machine_type` (int; must be 34404 for x64 eligibility), `timestamp` (int, uint32), `virtual_size` (int|None), `last_section_va`/`last_section_raw` (int|None), `version` (str|None), `windows_versions` (sorted unique tuple), `kbs` (tuple of `{kb, release_date, release_version}`), `download: Literal['direct','candidates','unavailable']`, `source: 'winbindex@<data-date>'`.
- `DownloadPlan`: ordered candidates (exactly two for a project: older, newer, chosen explicitly by the analyst), exact URLs (`https://msdl.microsoft.com/download/symbols/<name>/<%08X timestamp><%x size>/<name>`), expected sha256 and size.
- `AcquiredArtifact`: local quarantine path, sha256, size, `format: Literal['pe','pa30','pa31','unknown']`, `machine`, provenance `{source_url, redirect_host, retrieved_at, winbindex_record_sha256}`.
- Identity: `acquisition_id = domain_id('acquisition', 1, {file_name, sha256})`. A matching SHA-256 proves identity with the Winbindex record, **not** vendor authenticity; Authenticode verification is out of scope for this version and is labelled as such.

## 4. Behavior

1. Metadata fetch: `https://winbindex.m417z.com/data/by_filename_compressed/<name>.json.gz` (lowercase, case-sensitive URL). Requires explicit consent naming the host and exact URL. Cap 64 MiB compressed / 256 MiB decompressed; strict JSON; required per-entry fields `fileInfo.sha256`, `size`, `machineType`, `timestamp` — entries missing any are skipped with a counted warning. All other fields optional.
2. Download classification: `direct` when `timestamp` and `virtualSize` exist; `candidates` when `timestamp`, `size` and both `lastSection*` exist; otherwise `unavailable` ("update-package only").
3. Candidate resolution (`candidates`): HEAD each SizeOfImage from `round_up(lastSectionVirtualAddress + (size − lastSectionPointerToRawData), 0x1000)` down to `lastSectionVirtualAddress + 0x1000` in 0x1000 steps; 302 = valid, 404 = invalid, anything else = error; accept only if exactly one is valid. At most 4 concurrent HEADs, 10 s each, overall cap 256 probes.
4. Download: GET, follow exactly one redirect, only to `*.blob.core.windows.net` over HTTPS; never cache the signed blob URL. 404 = "not on symbol server" (a normal outcome, not an error). Cap 512 MiB. Stream to private staging; compute SHA-256 while streaming; reject size or hash mismatch against the plan.
5. Identification: `MZ` + valid PE → `pe` (must be AMD64 via existing `ingestion.inspect_artifact`); 4-byte CRC32 + `PA30`/`PA31` at offset 4 (CRC verified: `zlib.crc32(data[4:]) == le32(data[:4])`) → `pa30`/`pa31`; raw `PA30` at offset 0 → `pa30`; else `unknown`. Only `pe` can become a project input.
6. Delta reconstruction (optional, Windows only): `ApplyDeltaB` from the system `msdelta.dll` for PA30; PA31 only with a user-selected `UpdateCompression.dll` path. Requires the exact base file; chain reverse (`r`) then forward (`f`); output must hash to the expected SHA-256. `DeltaFree` always called. On non-Windows the capability reports `unsupported` explicitly. No pure-Python applier is used (none is complete and licensed).
7. Promotion: verified `pe` files are passed to `ProjectService.create(older, newer, name, root)`; provenance is recorded in the project (`Artifact` name plus an acquisition annotation). Staging is deleted only for the current operation.

Network: HTTPS only; allowlist `winbindex.m417z.com`, `msdl.microsoft.com`, `*.blob.core.windows.net` (redirect target only); environment proxies ignored; no credentials; User-Agent `PatchTrace`; bounded retries (429/5xx, ≤ 3, Retry-After ≤ 60 s); cancellable. Nothing about the user's projects is sent.

## 5. Surfaces

- CLI: `PatchTrace acquire search NAME [--json]` (metadata only, needs `--consent-hosts winbindex.m417z.com`), `PatchTrace acquire fetch NAME --older SHA --newer SHA --project DIR --consent-hosts winbindex.m417z.com,msdl.microsoft.com [--json]`. Exit codes per SPEC-07 §11 (0/2/3/4/5; 4 = no downloadable candidates).
- GUI: New → "Download from Microsoft symbol server…" dialog: name, candidate table (version, KB, release date, download availability), explicit older/newer selection, consent text listing hosts and URLs, progress, cancel.

## 6. Acceptance

Pure: Winbindex fixture parsing (trimmed real afd.sys record + synthetic variants: missing virtualSize, missing required fields, non-x64), URL formatting `%08X%x`, candidate enumeration arithmetic, CRC/PA30 identification, wrong-hash rejection. Transport with fake opener: allowlist, single redirect to blob host only, 404 semantics, caps, cancellation, proxy ignored. Live probe (recorded separately, not CI-gating): one direct download of a small x64 system file with hash match. Windows-only CI: `msdelta.dll` presence and ApplyDeltaB on a synthetic delta created with `CreateDeltaB` in the test itself (no Microsoft payload committed).
