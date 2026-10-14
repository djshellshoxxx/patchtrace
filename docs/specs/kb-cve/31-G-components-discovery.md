# SPEC-31-G: Component Identification, Filename Evidence and Discovery Without Guesswork

Status: developer-ready component pipeline. Parent [SPEC-31](../kb-cve-correlation-and-acquisition.md). Depends 31-A/B/C. Owner: component discovery worker. This component is essential because a CVE/KB association usually does not name every affected PE.

## G1. Deliverable

Produce evidence-tiered candidate Windows PE filenames for a given (KB, CVE, ProductScopeId) without claiming that any candidate actually contains the CVE fix. If no credible file emerges, emit NEEDS_FILENAME with supported manual options; never manufacture a .dll or .sys from CVE title, API or CWE. The entire module is pure apart from injected sources of package index and user selection.

## G2. Input sources and trust

Tier A: explicit filenames/module names in structured official MSRC/CSAF remediation/component/reference fields, with source pointer and scope. Some records contain general product/component names only; those are not a filename until an explicit extension/path exists. A title like "Windows TCP/IP" is a component description, not tcpip.sys unless a separate record explicitly says so.

Tier B: validated specific package inventory showing member file path, package identity, product release, arch and KB association. Demonstrates package membership, never CVE-fix causation. A package may include many ordinary updated binaries.

Tier C: Winbindex candidate Windows-version/KB metadata or local file inventory, mapped to selected product and build. A KB listed beside a file version may mean present in cumulative update, not necessarily changed in that release; compare SHA across adjacent builds.

Tier D: behavior/location hints from imports, strings, PDB symbols, filename aliases, known component catalog entries; advisory language/CWE text is contextual only. Requires a verified mapping catalog and versioned source if mapping title->file, else stays a search suggestion without file eligibility.

Tier E: user-entered filename or local PE; explicit user asserted origin, validate syntax/content and never pretend it is vendor documented.

A tier orders *how much file association is documented*. It is NOT a patch attribution score and cannot overcome a wrong product or invalid pair.

## G3. Typed contracts

SourceComponentClaim {claim_id, product_scope_id?, kb?, cve?, original_component_text, explicit_basename?, source_document_id, source_pointer, source_kind, mapping_kind, claimed_release?, revision?}.
FileCandidateHint {id, canonical_basename, original_spelling, product_scope_id, linked_cve_ids[], linked_kb_ids[], evidence_tier A..E, reasons[], source_claim_ids[], first_seen_build?, last_seen_build?, availability, validated_extension}.
ComponentSearchResult {requested_kb/cve/product, candidates[], descriptive_only_claims[], rejected[], status, coverage_ids[], blockers[]}.
Reject basenames containing directory separator, drive/UNC/ADS, path traversal, trailing dot/space, reserved Windows device name, NUL/control characters; normalize to lowercase ASCII where compatible with existing acquisition.validate_file_name. Use existing allowed PE extensions for automatic symbol-server search: exe, dll, sys, efi, drv, ocx, cpl, scr. Non-PE types remain descriptive leads; no Ghidriff input.

## G4. Pipeline design

1. Accept verified or selected ProductScope and documentary remediation edges; if product not-applicable, do not emit CVE-specific candidates.
2. Parse only explicit official module/filename fields with recorded pointer. Split structured arrays, not arbitrary prose tokens. Filenames with an extension require basename validation. Normalize product aliases from 31-C first.
3. If user supplies a local MSU/CAB inventory, index file names by exact package lineage and product scope, then intersect with official remediation context. Show all candidates with tier B and count; cap results and require filtering because cumulative packages can have thousands of files.
4. If Winbindex metadata is already fetched for an explicit filename, add tier C link. Do not perform unbounded Winbindex lookups over all possible filenames or guess symbol-server paths.
5. Apply analyst provided filename as tier E, validate file and target architecture. The UI can suggest searching official KB page/browser for file information, but no implicit scraped candidate upgrades.
6. Deduplicate same (basename,product scope) for presentation while preserving every distinct source claim, contradictory build association and tier on evidence list.
7. Determine whether before/after SHA differs only after candidate hashes and product builds are known. A file carried in a KB with identical SHA across selected builds yields no-change-for-file and is never forcibly correlated to a CVE.

## G5. Selection with many candidates

Defaults: initially show all Tier A, then B/C, with total counts for truncated groups; no automatic top filename when multiple plausible. Interactive filter: exact filename; component text; source tier; package role; changed/unchanged/unknown (only after SHA query); product/build. Provide bulk selection for multiple files as *multiple independent pair projects*, not one file pair containing unrelated basenames. Cap batch analysis to a user-confirmed bounded number. Each file's selected pair has its own verification/reports; an investigation may reference multiple projects.

If no filename: Search page must say "The advisory does not identify a verified PE filename. Enter a filename or inspect an update package." Show official reference link and source status. Do not label this a provider error.

## G6. Demonstrations

Synthetic sample A: CVE affects 'ExampleOS Networking Stack', no official filename; Winbindex not yet searched => descriptive-only claim, NEEDS_FILENAME.
Sample B: analyst enters 'exampledrv.sys'; Winbindex returns hashes for two selected builds. Show 'analyst suggested filename; hashes tied to selected build metadata', not Tier A.
Sample C: official structured source explicitly names exampledrv.sys but package contains unrelated examplecore.dll; A and B separate candidates. File-to-CVE evidence is still only a localization hint.
Sample D: official product A CVE linked to update, package inventory from product B same KB number; reject B candidate for selected A product.
Sample E: SHA old=new despite packaging; show "no observed binary change"; no conclusion about CVE scope.
Sample F: local file named exampledrv.sys is ARM64 despite selected x64; reject for current PatchTrace analyzer even if description suggests correct component.

## G7. Tests and performance

Test dozens of malicious filenames, Unicode homoglyphs, path traversal, duplicate basenames under different package identities, product mismatch, case-insensitive collisions, empty official component, multiple CVEs to one DLL, one CVE to many DLLs, partial Winbindex availability, cache replay determinism. For giant package inventory, index by lower basename+scope, cap 5,000 visible hints per query with explicit truncated status and page cursor; no silent truncation. No network or Qt imports in component_hints.py; all source claims cite exact immutable source bytes.

Interface: discover_components(request:ComponentRequest, claims:tuple[SourceComponentClaim,...], inventory:PackageInventory|None, metadata_index:FilenameIndex|None)->ComponentSearchResult. Service layer performs all fetching and passes validated input.
