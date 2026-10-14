# SPEC-31-D: Verified Acquisition, Delta Recovery and Offline Package Safety

Status: developer-ready with optional advanced package support. Parent [SPEC-31](../kb-cve-correlation-and-acquisition.md). Depends on 31-A/C and existing SPEC-08. Owner: acquisition worker. First release uses existing Winbindex+symbol server and local PE import.

## D1. Sequence and exact ownership

Do not replace acquisition.winbindex.parse, metadata_url, BuildCandidate, acquisition.transport, acquisition.quarantine or acquisition.delta. The new bridge converts a chosen immutable PairProposal to the existing SPEC-08 DownloadPlan, coordinates separate old/new fetches and checks final hashes. It must use ProjectService.create only after both files are ready and SHA verified. No source provider creates a project; no Qt worker writes the project database.

Stages with side-level status: identified -> planned -> consented -> downloading -> staging -> format-detected -> delta-requires-base or final-pe-verified -> hash/PE/signature-assessed -> eligible-for-promotion. Any failure leaves old and new completely segregated and previously valid project untouched. A failed second side must not promote the first side into a project. DownloadPlan itself is immutable and pinned by plan_sha; consent covers exact URLs and operation kinds, not merely a checkbox/host.

## D2. Reuse of existing transport constraints

SPEC-08 constraints remain authoritative for symbol-server use: Winbindex metadata compressed ≤64 MiB and inflated ≤256 MiB, downloader payload ≤512 MiB, validated Microsoft symbol-server host and bounded redirect to Microsoft Azure blob endpoint, at most 256 candidate HEADs / four concurrent probes, bounded retries/timeouts, exact hash check against selected metadata record, no external upload. Explicit request-specific network authorization; --offline ignores all prior grants. Actual redirected signed URLs are never persisted. Enforce no proxy inheritance per existing transport until an explicit profile setting is reviewed.

Metadata fetch + binary fetch are two separate grants. An acquired sample's SHA matching Winbindex proves index consistency, not Microsoft vendor signature. Preserve source entry hash, expected vs observed bytes/hash, original and final response host, source record time and parser version.

## D3. Verification precedence and authenticity states

Mandatory: stream to private non-executable staging, bounded size, SHA-256, final PE parse, supported architecture, filename identity, selected product/build association, chronology check, stable final bytes (no TOCTOU between verification and project copy). Promote only after re-opening/hash verification via existing ingestion path. Use private scratch names chosen by program; reject symlink traversal and path escape.

Distinct authenticity states:
- hash-matched-to-index: exact digest matches Winbindex source entry; no publisher authentication inferred.
- embedded-signature-valid: Windows Authenticode verification succeeded and identifies signer under recorded trust policy.
- catalog-signature-valid: matching catalog member hash and trusted catalog signature verified; important because many Windows binaries are catalog signed without embedded signatures.
- signature-unknown: no reliable verification, non-Windows host, unavailable catalog, untrusted/offline root state.
- signature-invalid: cryptographic failure or identity mismatch.
A signed package does not imply every extracted artifact is a valid target build without matched manifest identity. Verification result must capture policy, verifier version, time/chain status and SHA. For first alpha, report signature-unknown and keep strict policy configurable; never label Winbindex checksum as signed.

Microsoft docs distinguish catalog and embedded signing; future verifier can reuse pe_overview/authenticode.py if Windows-tested, or use separate WinVerifyTrust/CryptCAT APIs. Do not assume that inspecting a PE certificate table verifies catalog-member signing.

## D4. Direct/delta formats

Direct PE: existing quarantine identifies MZ/PE AMD64, verifies final expected hash and passes artifact path.

PA30/PA31 (and any recognized variant): return NEEDS_BASE rather than treating delta bytes as a PE. Resolve exact base artifact SHA and package/branch lineage, not simply a same-named older file. Maintain ReconstructionPlan (algorithm, delta_sha, expected_output_sha, base_sha, base_source, platform capability, required DLL/tools, resource estimates). Apply only with user-approved known exact base. SPEC-08 currently defines Windows msdelta.dll ApplyDeltaB for PA30 and optional explicit UpdateCompression.dll for PA31. Treat unsupported extensions as UNSUPPORTED_FORMAT. A delta chain (A -> B -> C) requires every verified intermediate output SHA; a wrong base aborts before promoting any output. All temporary outputs remain quarantined and rehashed.

No arbitrary Windows executables from package content are launched and no WUSA/online DISM operations. No Python 'best-effort' decompressor may label a partial reconstruction successful.

## D5. Package fallback as an optional separate capability

Initially provide official Microsoft Catalog browser handoff and manual local MSU/CAB intake, not an unverified programmatic Catalog JSON API. Never scrape temporary Catalog download URLs and persist them as a stable provider contract. Do not automatically install packages.

Inventory contract:
PackageSource (name, original_path_redacted, local_sha256, source_uri?, source_claims, signature_state)
PackagePart (kind msu|cab|cat|mum|manifest|delta|fullfile|unknown, inner_path, compressed_size, decompressed_size?, observed_sha, parent_sha, required_checkpoint_ids, package_identity?)
PackageInventory (package_id, parts, selected_product_scope_id?, applicability, manifest_evidence, component_claims, warnings, complete boolean)
All member paths are logical archive paths; physical extraction stays under private root.

For Windows servicing, catalog-provided MSUs on 24H2 and Server 2025+ may depend on previous checkpoint updates. Graph prerequisites come from independently sourced metadata; do not infer dependencies solely from naming or KB order. DISM image servicing, if offered in a later separate milestone, MUST operate only on an explicitly supplied disposable offline image, never /Online or the analyst workstation. Different servicing baselines, optional features and languages may yield different outputs.

## D6. Extraction threat model and budgets

Default optional package limits (tune with real fixtures): input ≤4 GiB, total expanded ≤8 GiB, per-entry ≤1 GiB, max entries 50k, recursive archive depth ≤4, min free space ≥2× estimated scratch, total 30 minutes, max 2 workers. Reject absolute/drive/UNC paths, path traversal, alternate data streams, NTFS reparse points, filename casefold collisions, decompression bombs, size lies, symlink/hardlink target escapes, duplicate manifest identities and hostile locale/unicode path tricks. Output creation must use exclusive handles in a newly created private directory under a controlled base. Never trust archive manifest file paths as host paths. Version and sanitize helper tool stdout/stderr, bound it, shell=False, absolute paths and process-tree kill-on-cancel. Prefer header/manifest inventory without full extraction. Enforce actual expanded bytes incrementally, not a declaration alone.

## D7. Crash and cancellation

A plan can be retried only when same plan_sha and expected bytes; staging artifact SHA must be verified again after restart. Partial files carry separate .partial marker and cannot be selected by pair resolver. Cancellation closes handles, terminates controlled jobs, retains completed verified source caches but never updates active project on incomplete state. Interrupted attempt journal records plan_id, side, last completed stage, file/hash, failure reason and cleanup outcome; stale workdirs are removed only if owned by the job and no live lock. No implicit resume that accesses network.

## D8. Fault injection and acceptance

Acceptance matrix:
- old downloaded, new 404 -> no project, metadata retained.
- first 302 to unexpected host -> rejected, no data written outside quarantine.
- wrong SHA same size -> verification failure, never reused.
- PA30 with missing base -> explicit needs-base, metadata available.
- PA30 correct base -> verified final PE SHA (native Windows fixture required); PA31 missing UpdateCompression.dll -> typed unsupported.
- changed source bytes during copy -> fail rehash.
- user-provided local signed file but product unknown -> can inspect manually, no verified product label.
- malicious CAB entry ..\\ or C:\\ / ADS / duplicate case -> blocked.
- compressed package crosses expanded cap -> bounded abort, no partial project.
- valid package with two checkpoint dependencies -> ordered plan or unknown if graph lacks evidence.
- cancellation between staging and ProjectService.create -> atomic project absence and no orphan records.
- frozen Windows build passes direct PE pair import and one delta fixture independently; Linux reports Windows-only functionality as unsupported, not success.

Exit/transport codes wrap existing PT-ACQ-* with PT-KBC-* wrapper but do not alter existing CLI behavior. Docs: https://learn.microsoft.com/windows/deployment/update/catalog-checkpoint-cumulative-updates , https://learn.microsoft.com/windows/win32/secbp/understanding-pe-signatures , https://learn.microsoft.com/windows-hardware/drivers/install/catalog-files .
