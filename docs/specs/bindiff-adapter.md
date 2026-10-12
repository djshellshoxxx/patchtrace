# SPEC-10: BinExport / BinDiff adapter (Phase 3c)

Status: developer-ready contract, 2026-10-12. Contract version `bindiff-adapter/1`. Verified facts: `../research/phase3/binexport-bindiff.md` (binexport @ 2bff7af, bindiff @ 13c437a; Apache-2.0).

## 1. Outcome and boundaries

Analysts who have Google BinExport/BinDiff installed can import a genuine BinDiff result for the project's exact artifact pair as a **second, independent match set** alongside Ghidriff, or export function records for use elsewhere. PatchTrace never bundles or builds these tools, and never labels its own JSON/CSV as `.BinExport`/`.BinDiff`.

Tool facts that constrain the design: the latest BinExport release (v12-20240417) targets Ghidra 11.0.3; Ghidra 12 support exists only on unreleased main (source build required). BinDiff v8 (2023-09) ships msi/dmg/deb. `.BinExport` has no magic number (bare proto2 `BinExport2`). BinDiff exits 0 on success, 1 on any error; output is `<a>_vs_<b>.BinDiff` (SQLite), named from input basenames.

## 2. Inputs and validation

- `.BinExport` validator (pure; protobuf bindings generated from pinned `binexport2.proto`, Apache-2.0 notice added): parse succeeds; `meta_information.executable_id`, `executable_name`, `architecture_name` non-empty; `call_graph.vertex` non-empty and address-sorted; every `*_index` within bounds; each flow graph's entry block in its block list; size ≤ 512 MiB. `executable_id` must equal the project artifact's SHA-256 (the Ghidra exporter writes it) — otherwise reject as wrong pair.
- `.BinDiff` validator: first 16 bytes `SQLite format 3\0`; opened read-only (`file:…?mode=ro` URI, immutable); required tables/columns per research §schema via `PRAGMA table_info`; exactly one `metadata` row with `version LIKE 'BinDiff %'`; `file` ids {1,2} with `metadata.file1=1, file2=2`; `file.hash` of 1 and 2 equal the project's older/newer SHA-256 in that order (reversed → reject as orientation mismatch); every `function.algorithm` present in `functionalgorithm`; `0 ≤ similarity, confidence ≤ 1`; addresses masked `& 0xFFFF_FFFF_FFFF_FFFF`; image-base subtraction recorded if detectable from BinExport metadata, else `unknown`.

## 3. Records and storage

`SecondaryMatch` (strict): `engine: 'bindiff'`, `engine_version` (from metadata), `older_address`, `newer_address`, `older_name`, `newer_name`, `similarity_milli` and `confidence_milli` (integers 0..1000, from upstream doubles via `round(x*1000)`; upstream values preserved as text), `flags` (bitmask names G/I/O/J/E/L/C), `algorithm` (joined by name, never by id). Stored as an enrichment entry kind `secondary-matches` keyed by `domain_id('secondary', 1, {engine, file_sha256, older, newer})`. Unmatched functions are derived from the BinExport call graph, not from BinDiff.

## 4. Running the tools (optional convenience)

`bindiff --nologo --output_dir=<private tmp> --output_format=bin <older>.BinExport <newer>.BinExport` via the existing supervised process runner (timeout, cancel, bounded logs). Inputs are copied to unique basenames first. Success = exit 0 **and** the expected output file exists and validates. BinExport generation inside Ghidra is the user's responsibility in this version (headless invocation is unverified); PatchTrace documents it but does not automate it.

## 5. Reconciliation with Ghidriff

The match view shows, per Ghidriff match, whether BinDiff agrees (same endpoints), disagrees (different partner) or is absent. Disagreements stay explicit. Agreement is reported as agreement, not as independent proof or a calibrated probability. Secondary matches never change Ghidriff records, manual corrections or attention scores.

## 6. Acceptance

Validator unit tests with generated small BinExport messages and handcrafted SQLite files (valid; wrong magic; missing table; reversed hashes; algorithm id without name; out-of-range indexes; negative BIGINT addresses). Lookalike rejection: a PatchTrace JSON renamed `.BinDiff` is rejected. Live (recorded, optional): BinDiff v8 on Windows with BinExport files produced by the user's Ghidra; not CI-gating because the Ghidra 12 exporter is unreleased.
