# PE version resource, manifest and Authenticode verification without execution (SPEC-51; SPEC-26 D2)

Status: draft (SPEC-51), written 2026-10-14; promoted from program-e/. Partly built: slices D2-1 and D2-2 exist on main (`pe_overview/resources.py`, `version_info.py`, `manifest.py`; tests `tests/test_pe_resources.py`, `test_pe_version_info.py`, `test_pe_manifest.py`). Not built: D2-3 to D2-6 (no `der.py`, `signature.py`, `catalog_win.py`, `rsa_verify.py`); the compare rows, tab and CLI of D2-5 are not verified here. Extends `docs/specs/pe-overview.md` (SPEC-26 D) additively. Owner package: `src/patchtrace/pe_overview/`. Canonical alias: SPEC-51 (part D2 of SPEC-26).

Source-access note (whole file): `learn.microsoft.com` and `download.microsoft.com` are blocked from this sandbox (egress proxy returned 403 on 2026-10-14). Every Microsoft-format fact below is therefore marked `[unverified: MS host blocked]`: it is written from the documented format as the author knows it and the build slice must re-check it against the cited page before coding. Upstream facts that could be fetched carry a retrieval date.

## 1. Verdict and scope

Build: (a) a bounded, read-only reader for the resource tree, `VS_VERSIONINFO` and the application manifest; (b) a cross-platform, stdlib-only Authenticode **structure and digest** verifier that reads `WIN_CERTIFICATE` blobs, parses the PKCS#7 `SignedData`, recomputes the PE Authenticode digest and reports signer identity, certificate validity window, timestamp claims and nested signatures; (c) a Windows-only extension of the existing `WinVerifyTrust` probe for catalog signatures and consented revocation modes; (d) old/new comparison rows, persistence by artifact SHA-256 and a "Version and signing" tab in File overview.

Deliberately not built: chain building or trust decisions on Linux (no trust store; reported `not_evaluated`); any network fetch of CRL/OCSP/timestamp/AIA URLs by PatchTrace itself; execution, loading or mapping of the target; .NET metadata; RSA/ECDSA signature math in v1 (optional slice D2-6); the words "valid", "verified publisher" or "safe" in UI or export for any combination of results.

## 2. Sources and facts

| claim | source | retrieved | confidence |
|---|---|---|---|
| Existing probe uses `WinVerifyTrust` with `WTD_REVOKE_NONE`, `WTD_UI_NONE`, cache-only URL retrieval; embedded signatures only; reopens the file by path | `src/patchtrace/pe_overview/authenticode.py` (this repo) | 2026-10-14 | high |
| Overview reports certificate-table presence only; `signature_status` is constant `not_verified` | `pe_overview/certificates.py`, `models.py` (this repo) | 2026-10-14 | high |
| `build_windows.py` passes no `--version-file`, so shipped `PatchTrace.exe` carries no PatchTrace version resource | `tools/build_windows.py` (this repo) | 2026-10-14 | high |
| Resource section is a directory tree (type, name, language); directory-entry offsets are relative to the resource section start; `IMAGE_RESOURCE_DATA_ENTRY.OffsetToData` is an RVA; high bit of an entry offset marks a subdirectory, high bit of a name field marks a UTF-16 name | https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section | not retrievable | [unverified: MS host blocked] |
| `RT_VERSION` = 16, `RT_MANIFEST` = 24, `RT_ICON` = 3, `RT_GROUP_ICON` = 14; manifest resource id 1 (EXE) or 2 (DLL) by convention | https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types ; https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests | not retrievable | [unverified: MS host blocked] |
| `VS_VERSIONINFO`: `wLength`, `wValueLength`, `wType`, UTF-16 `szKey` "VS_VERSION_INFO", DWORD padding, `VS_FIXEDFILEINFO` (signature `0xFEEF04BD`), `StringFileInfo` tables keyed by 8 hex digits (language id + code page), `VarFileInfo`/`Translation` | https://learn.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo (and `stringfileinfo`, `varfileinfo`, `vs-fixedfileinfo`) | not retrievable | [unverified: MS host blocked] |
| Security data directory "RVA" is a file offset; entries are 8-byte aligned `WIN_CERTIFICATE {dwLength, wRevision 0x0200, wCertificateType 0x0002 = PKCS_SIGNED_DATA}` | https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#certificate-table-section | not retrievable | [unverified: MS host blocked]; current parser already follows it with tests |
| Authenticode PE digest excludes the optional-header CheckSum field, the Security directory entry and the certificate table; hashes headers, then sections in ascending `PointerToRawData`, then trailing data before the certificate table | "Windows Authenticode Portable Executable Signature Format", https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx | not retrievable | [unverified: MS host blocked] |
| Container: PKCS#7 `SignedData` carrying `SpcIndirectDataContent` (OID 1.3.6.1.4.1.311.2.1.4), `SpcPeImageData` (1.3.6.1.4.1.311.2.1.15), `DigestInfo`; counter-signature attribute 1.2.840.113549.1.9.6; RFC 3161 timestamp attribute 1.3.6.1.4.1.311.3.3.1; nested signature attribute 1.3.6.1.4.1.311.2.4.1 | same Authenticode_PE.docx; RFC 2315 and RFC 5652 | not retrievable | [unverified: MS host blocked]; OIDs to be confirmed against a real fixture |
| `WinVerifyTrust` with `WTD_CHOICE_CATALOG` plus `CryptCATAdminCalcHashFromFileHandle` / `CryptCATAdminEnumCatalogFromHash` validate catalog-signed files | https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust | not retrievable | [unverified: MS host blocked] |
| `pefile` 2024.8.26 is MIT, pure-Python wheel, parses version info and resources | https://pypi.org/pypi/pefile/json | 2026-10-14 | high (version, licence) |
| `cryptography` 50.0.2 is `Apache-2.0 OR BSD-3-Clause`; cp312 wheel list not confirmed (page truncated) | https://pypi.org/pypi/cryptography/json | 2026-10-14 | high licence, low wheels |
| RFC 3161 `TSTInfo.genTime` is a claim bound to the TSA signature and chain | https://www.rfc-editor.org/rfc/rfc3161.txt | host blocked | [unverified: host blocked] |

Decision on dependencies: **no new runtime dependency.** `pefile` stays a test-only cross-check (dev extra, never imported at runtime, like `calibration-dev`): its resource parser follows attacker offsets without PatchTrace's per-read limits and bypasses `VerifiedArtifactReader`. `cryptography` would add a native wheel to the PyInstaller bundle for a v1 that deliberately makes no cryptographic trust claim. A small DER reader (`pe_overview/der.py`, about 150 lines, definite length only, depth and size capped) suffices for structure, digest and identity.

## 3. Standalone baseline versus PatchTrace value

Standalone: Explorer Details, `sigcheck` and `signtool verify` show one file's version strings and signature, on Windows, one file at a time; `signtool` shells out and may go online.

PatchTrace adds, only inside a pair:

1. **Orientation-aware deltas**: FileVersion/ProductVersion/OriginalFilename/CompanyName old vs new; manifest delta (`requestedExecutionLevel`, `uiAccess`, `supportedOS`, dependent assemblies, `longPathAware`); **signer delta** (subject or issuer changed, signature added or removed, digest algorithm downgraded). A newer build that lost its signature or requests more privilege is a triage lead no single-file viewer states.
2. **Digest against the exact verified copy**: recomputed from bytes read through `VerifiedArtifactReader` (hash-pinned), not a path that may change (the current `WinVerifyTrust` call reopens by path).
3. **Anchors out**: build facts (file version, product version, original filename; CodeView GUID already present) feed KB patch search and Winbindex matching; signer facts feed report provenance.
4. **Off Windows**: Linux analysts get structure, digest and identity instead of "not checked on this platform".
5. **Catalog honesty (Windows)**: most Windows system binaries are catalog-signed and today read `unsigned`; D2 says "no embedded signature; catalog signature present / absent".

Workflows: open a pair and read "FileVersion 10.0.22621.3880 -> 10.0.22621.4249; signer unchanged; digest matches embedded signature (both sides)"; spot a hotfix build whose newer side lost its signature (lead, never a verdict); copy FileVersion into KB patch search.

## 4. Cross-feature links

| Anchor / evidence | Direction | Other tracks | Use |
|---|---|---|---|
| build fact `file_version`, `product_version`, `original_filename`, `internal_name` | emit | KB patch search (KPS), acquisition, RPT2 provenance | Build identification only; never a vulnerability claim |
| build fact `manifest.requested_execution_level`, `ui_access`, `supported_os`, `dependent_assemblies`, `long_path_aware` | emit | DIE, capa notes, guided RE | "What changed in how this runs" lead |
| build fact `signer.subject_cn`, `issuer_cn`, `digest_alg`, `timestamp_claim` | emit | RPT2, FAB | Signer delta lead; timestamp is a claim |
| build fact CodeView GUID/age (existing) | consume | GHR symbol policy | Key for analyst-supplied PDBs |
| KB / CVE text | consume | KB-CVE correlator | Version string used as text search only, never a match score |

No score is produced. Signer or version changes enter ranking only as a labelled lead channel owned by FAB, never averaged with engine scores.

## 5. Synergy test

Fixture set `tests/fixtures/pe_meta/` built by `tests/pe_builder.py` plus new `tests/pe_meta_builder.py` (synthetic; no Microsoft bytes). Older: EXE, version 1.0.0.0, manifest `asInvoker`, one embedded signature by synthetic CA "PT Test Root". Newer: same layout, version 1.0.1.0, manifest `requireAdministrator`, signature **absent**, one code byte changed.

Expected: version channel `1.0.0.0 -> 1.0.1.0` changed; manifest channel `asInvoker -> requireAdministrator` changed and labelled "privilege request changed"; signature channel `present -> absent`; digest channel older `digest_match=true`, newer `not_applicable`. Combined lead: "newer build requests administrator rights and is not signed"; each channel alone is a neutral field diff. Second case: newer signed but one section byte altered after signing gives `digest_mismatch` and no trusted-looking label. Tests: `test_synergy_privilege_and_signature_delta`, `test_tampered_section_reports_digest_mismatch`.

## 6. Traps and guards

| Trap | Guard |
|---|---|
| "Signed" read as "safe" | Closed label set (7.4); no label contains "valid", "verified" or "trusted" except the existing Windows text suffixed "(no revocation check)" |
| Digest match mistaken for trust | Separate rows Structure, Digest, Chain, Revocation, Timestamp; each defaults to `not_evaluated` off Windows |
| Hostile strings (bidi override, control characters, huge values) | UTF-16 decode with `errors='replace'`; drop C0/C1 and bidi controls U+202A-U+202E, U+2066-U+2069; 1024 chars per value, 64 keys per table, `truncated` flag |
| Manifest XML bombs, XXE | Reject any manifest containing `<!DOCTYPE` or `<!ENTITY` before parsing; 256 KiB cap; `xml.etree.ElementTree` only after that check; no URL resolution; `schemaLocation` shown as inert text |
| Resource tree cycles and fan-out | Depth exactly 3, visited set of directory offsets, 512 entries per directory, 4096 nodes, data reads capped (version 64 KiB, manifest 256 KiB) |
| Timestamp shown as signing or file date | Show "claimed signing time (not verified)" from timestamp or counter-signature attributes only; never a file date; expired-at-signing not evaluated |
| CRL/OCSP/AIA URLs inside certificates are attacker data | Inert text only; revocation solely through OS APIs and consent (7.5) |
| WinVerifyTrust reopens by path (time-of-check gap) | Run on the hash-verified project copy (existing) and re-hash afterwards; discard the result if the digest changed |
| Hostile PKCS#7 (deep nesting, indefinite length, giant lengths) | DER reader: definite length only, depth 12, 20000 nodes, 256 KiB per signature, 64 certificates, 4 signers; failures become warning codes, never exceptions |
| Catalog-signed file shown as unsigned | Wording "No embedded signature (catalog signature: present / absent / not checked)" |
| False precision | No numbers or scores produced |

## 7. Contracts

All additive. New frozen slotted dataclasses in `pe_overview/models.py`; `PeOverview` gains optional fields defaulting to `None` or `()`. Persisted JSON carries `overview_version: 2` (class constant `OVERVIEW_VERSION`).

### 7.1 Models

- `ResourceSummary`: `present`, `types: tuple[ResourceTypeCount]` (`type_id`, `type_name`, `entries`), `total_nodes`, `truncated`.
- `VersionInfo`: `fixed: FixedFileInfo | None` (`file_version`, `product_version` as 4-tuples, `file_flags`, `file_os`, `file_type`), `translations: tuple[str, ...]` (e.g. `'040904B0'`), `strings: tuple[VersionTable, ...]` (`lang_codepage`, `values: tuple[tuple[str, str], ...]`, `truncated`), `rva`, `size`, `fixed_vs_string_mismatch`.
- `ManifestInfo`: `encoding`, `size`, `assembly_identity` (`name`, `version`, `processor_architecture`, `type`), `requested_execution_level`, `ui_access`, `supported_os` (GUIDs plus name from a fixed table), `dependent_assemblies`, `long_path_aware`, `dpi_awareness`, `active_code_page`, `status` in `ok | rejected_doctype | too_large | not_xml | absent`.
- `SignatureInfo` (one per `WIN_CERTIFICATE`; nested signatures flattened with `nested_depth`): `index`, `nested_depth`, `structure` (`ok | malformed | unsupported_type`), `digest_algorithm` (`sha1 | sha256 | sha384 | sha512 | md5 | unknown`), `digest_claimed_hex`, `digest_computed_hex`, `digest_match: bool | None`, `weak_digest`, `signers`, `certificates`, `timestamps`, `signature_math: 'not_evaluated'`, `chain` (`not_evaluated` or a WinVerifyTrust status), `revocation` (`not_checked | checked_cache | checked_online`).
- `SignerInfo`: `issuer_cn`, `issuer_dn`, `serial_hex`, `subject_cn`, `subject_dn`, `not_before`, `not_after` (ISO UTC from the certificate), `eku_code_signing`, `digest_alg`, `signature_alg_oid`, `signer_cert_found`.
- `TimestampClaim`: `kind` (`rfc3161 | ms_countersignature`), `claimed_time_utc`, `token_structure_ok`, fixed `note` "Claimed by the signature container; its signature and chain were not verified."
- `CatalogResult` (Windows): `state` (`present_trusted_no_revocation_check | present_untrusted | absent | not_checked | unavailable`), `catalog_name` (basename, cleaned), `hresult`.
- Existing `TrustResult` and `verify_authenticode(path)` keep their signatures. New: `verify_embedded(reader, overview, cancel) -> tuple[SignatureInfo, ...]`, `verify_catalog(path) -> CatalogResult`.

### 7.2 Warning codes (added to the pe-overview list)

`resource_dir_out_of_file`, `resource_depth_exceeded`, `resource_cycle`, `resource_nodes_over_cap`, `resource_data_out_of_file`, `version_unparseable`, `version_over_cap`, `version_strings_over_cap`, `manifest_over_cap`, `manifest_doctype_rejected`, `manifest_not_xml`, `signature_der_invalid`, `signature_der_over_cap`, `signature_unsupported_type`, `signature_digest_unsupported`, `signature_certs_over_cap`, `signature_nested_over_cap`, `signature_digest_mismatch`, `digest_skipped_large`.

### 7.3 Limits (added to `Limits`)

`max_resource_nodes=4096`, `max_resource_entries_per_dir=512`, `max_version_bytes=65536`, `max_manifest_bytes=262144`, `max_version_keys=64`, `max_value_chars=1024`, `max_der_bytes=262144`, `max_der_depth=12`, `max_der_nodes=20000`, `max_signers=4`, `max_signature_certs=64`, `max_nested_signatures=4`. Digest recomputation reads 1 MiB pieces via `ctx.read`, polls `cancel`, and is skipped with `digest_skipped_large` above 256 MiB (the existing checksum constant).

### 7.4 Closed label set (UI and export)

Row "Signature (embedded)": `Not signed`; `Signature present, structure unreadable`; `Signature present, digest does NOT match file`; `Signature present, digest matches file; trust not evaluated on this platform`; on Windows the existing `trusted_no_revocation_check` text. Row "Catalog": `Not checked`, `Catalog signature present (no revocation check)`, `No catalog signature found`. Test `test_label_set_is_closed` enumerates them.

### 7.5 Trust and network policy

Setting `inspection/trust_mode`, default `offline`: `offline` (structure, digest, local WinVerifyTrust with `WTD_REVOCATION_CHECK_NONE` and cache-only URL retrieval as today); `cache` (Windows; revocation from already-cached data only); `online` (Windows; the OS may contact CRL/OCSP/timestamp hosts named inside the file's certificates). `online` needs a per-operation consent dialog: "Windows will contact certificate revocation servers named inside this file, which tells those servers this file's certificate is being checked. PatchTrace does not make these requests itself." The consent record (time, mode, file SHA-256) is stored with the result. Never default, never remembered as "always".

### 7.6 Persistence and cache key

Enrichment sidecar kind `pe-metadata` (amendment to `enrichment/storage.py` `KINDS`; treated as derived). Key = `sha256(artifact_sha256 | OVERVIEW_VERSION | limits_digest | trust_mode | trust_fingerprint)` with fingerprint `win32:<build>` or `portable`; a portable result is never reused as a Windows result. Error codes: `PT-PE-INPUT` (reader failure), `PT-PE-LIMIT` (cap, partial), `PT-PE-TRUST-UNAVAILABLE`, `PT-PE-CONSENT-REQUIRED`. Existing statuses `ok | partial | not_pe | cancelled` are unchanged; D2 findings are warnings.

## 8. CLI and GUI

CLI: `patchtrace inspect <project> --side older|newer|both [--trust offline|cache|online --consent-online] --json`, envelope `enrichment-cli/1`, exit codes 0 ok, 2 invalid arguments, 3 runtime failure, 4 no PE input, 5 cancelled. `--trust online` without `--consent-online` exits 2 with `PT-PE-CONSENT-REQUIRED`. Output is stable-sorted and contains no absolute paths.

GUI (single main window): File overview gains a **"Version and signing"** tab. Widgets: `QTabWidget` page with a `QTableView` over a `QAbstractTableModel` of `FieldComparison` rows (changed first; model already supports `unavailable`), a read-only `QPlainTextEdit` for the manifest text, and a `QTreeView` of signature, signer and certificate nodes with lazy children. Under 200 rows, so default Qt view virtualization suffices. Keyboard: Tab order tab bar, table, manifest, tree; Ctrl+C copies selected rows as TSV. Accessible names `pe.version.table`, `pe.manifest.view`, `pe.signature.tree`; tooltip ids `pe.version.fileversion`, `pe.manifest.execlevel`, `pe.sig.digest`, `pe.sig.chain`, `pe.sig.timestamp` registered in `tooltips.py` in the existing WHAT/WHY/SOURCE form.

States and exact copy: empty "This file has no version resource."; no manifest "No embedded manifest was found. Sidecar .manifest files are not read."; loading "Reading version, manifest and signature (read-only)..."; blocked "Certificate chain trust is only evaluated on Windows. This platform reports the signature structure and whether the file digest matches the signature."; error "Could not read this section: <code>. Other sections are unaffected." File text renders as plain text: set `QLabel.setTextFormat(Qt.PlainText)` explicitly (auto-detect would render `<b>` from a vendor name), use `setPlainText`, never `QTextBrowser`. Parsing runs on the existing inspection worker; target under 150 ms for a 10 MB EXE excluding the cancellable digest pass. Offscreen tests build the model from fixtures, assert label strings, and run 20 times without abort.

## 9. Slice plan

| Slice | Scope | Exclusive files | Depends | Tier | Size | Gate | Fallback |
|---|---|---|---|---|---|---|---|
| D2-1 | Resource tree reader, `ResourceSummary` | `pe_overview/resources.py`, `tests/test_pe_resources.py`, `tests/pe_meta_builder.py` | none | sonnet (hostile-offset tests) | S | cycle, depth-4 and fan-out fixtures give warnings; `pefile` cross-check agrees on clean fixture | summary only |
| D2-2 | `VersionInfo`, `ManifestInfo` | `pe_overview/version_info.py`, `manifest.py`, tests | D2-1 | sonnet | S | Unicode and bidi cases, DOCTYPE rejection, UTF-8 BOM and UTF-16 manifests | version only |
| D2-3 | DER reader, embedded signature structure and digest | `pe_overview/der.py`, `signature.py`, tests with a DER-writing helper | none | sonnet; opus only if known-answer digests fail twice | M | digest equals an independent `hashlib` computation; tamper test; dual-signature fixture | structure without digest |
| D2-4 | Windows catalog and consented revocation | `pe_overview/catalog_win.py`, `authenticode.py` (owned here) | D2-3 | sonnet | M | native Windows CI on a system catalog-signed DLL read in place, never copied or committed; skipped elsewhere | catalog `not_checked` |
| D2-5 | Compare rows, persistence kind, CLI, GUI tab | `pe_overview/compare.py`, `ui_inspection.py`, tooltips, tests; one-line `enrichment/storage.py` KINDS edit by the integration owner | D2-2, D2-3 | sonnet | M | offscreen tests, label-set test, 20x repeat | table without tree |
| D2-6 (optional) | RSA PKCS#1 v1.5 check with `pow()`, no chain | `pe_overview/rsa_verify.py` | D2-3 | sonnet, opus review of wording | S | known-answer vectors; label stays "signature math ok, chain not evaluated" | skip |

## 10. Amendments, test and QA plan

Amendments: `docs/specs/pe-overview.md` "Not done": replace the version-info, manifest, resource and catalog bullets with "see SPEC-26 D2" and keep "no revocation check by default"; same file Semantics: add the closed label set. `docs/specs/gui-preflight-inspection.md` D: point signer/chain/timestamp to this file. `docs/specs/acquisition.md` line 29: Authenticode of downloaded binaries is reported (structure, digest) but is still not a vendor-authenticity claim. `docs/modules.md` pe overview row: add resources, version_info, manifest, der, signature. `tools/build_windows.py`: pass `--version-file` so `PatchTrace.exe` carries its own version resource (see `windows-release-signing-policy.md`, SPEC-52). Registry: promoted as SPEC-51 (alias SPEC-26 D2).

Tests: generated fixtures only (no Microsoft binaries); the synthetic CA key is a test constant. Goldens: JSON of `VersionInfo`, `ManifestInfo`, `SignatureInfo` for 6 fixtures. Properties (hypothesis, already a dev dependency): `inspect_pe` never raises on mutated resource and certificate bytes; `digest_match` is true only for unmodified files; byte flips inside the excluded regions (checksum, security directory entry, certificate table) keep the match, flips elsewhere break it. Windows pitfalls: mark `*.exe`/`*.der` fixtures and goldens binary or LF-pinned in `.gitattributes`, short explicit parametrize ids, `time.monotonic` compared with `>=`, hermetic tests. One-off manual cross-check against `signtool verify /pa /v` or `osslsigncode verify` on a self-made signed file is recorded in `docs/qa.md` as evidence only (osslsigncode is GPL: external reference, no code copied, licence [unverified]). Live gates only the owner or Windows CI can close: catalog result on a real system file, consented online revocation, screen-reader pass of the new tab, DPI 200% layout.

## 11. Open questions (defaults, none blocking)

1. Show issuer as well as subject in the signer delta? Default both, subject first.
2. Read sidecar `<name>.manifest` files? Default no (the reader sees one file).
3. Persist `online` results? Default yes with the consent record and a "network used" provenance flag.
4. Build D2-6 RSA math? Default defer until requested.
5. Allow `pefile` as a runtime fallback? Default no.
