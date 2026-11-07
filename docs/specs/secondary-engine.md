# SPEC-11: Secondary engine — Rizin rz-diff (Phase 3d)

Status: developer-ready contract, 2026-10-12. Contract version `secondary-engine/1`. Verified facts: `../research/phase3/rizin.md` (rizin v0.9.1 @ c3a90e9, LGPL-3.0-only; run locally on two afd.sys builds).

## 1. Outcome and boundaries

Optionally run rz-diff on the project's artifact pair to obtain a second, independent function-match set. Ghidriff remains the default and primary engine; both evidence sets are kept; disagreements stay explicit. rz-diff is an external, user-installed tool (official Windows/Linux builds exist); PatchTrace does not bundle it.

## 2. Capability probe

`rz-diff -v` (version line) must report ≥ 0.9.0; otherwise `unsupported` with the observed version. Detection never installs anything. Capability record: `{engine: 'rz-diff', version, path, supports_json: true}`.

## 3. Invocation and parsing

`rz-diff -C -j -t functions <older> <newer>` with argv list (no shell), cwd = private temp, stdout bounded at 64 MiB, stderr tail 2 MiB, wall-clock timeout default 1,800 s (configurable 60–86,400), process-tree kill on cancel/timeout (existing `jobs.run_process`). Exit 0 = ran; non-zero = error with stderr tail. Stdout must parse as a strict JSON array of objects `{similarity: number 0..1, type: 'COMPLETE'|'PARTIAL'|'UNLIKE', original: {addr:int, name:str, size:int}|null, modified: {…}|null}`; empty/invalid output is an error even with exit 0. Addresses are unsigned VAs.

## 4. Records

`SecondaryMatch` from SPEC-10 with `engine: 'rz-diff'`, `similarity_milli` = `round(similarity*1000)` (upstream text preserved), `algorithm: 'levenshtein-bytes'`, `confidence_milli: null`, `flags: ()`. Functions are mapped to PatchTrace/Ghidra functions **by address only** (rz-diff names are `fcn.*` without PDB). Unmatched sides (`original` or `modified` null) become one-sided records.

## 5. Interpretation limits (shown in UI/exports)

> SPEC-31 amendment A-17 (2026-10-14): in the SPEC-31 unified engine every rz-diff row is tier-W evidence (never accepting), flagged `non-exclusive` when its newer endpoint is shared by two or more rows (rizin 0.9.1 keeps the last candidate and never consumes B), and its similarity never selects, ranks or decides: it is carried as upstream text only.

Similarity is raw-byte Levenshtein: not semantic, sensitive to relocations and address shifts; no per-match confidence; no symbol names. Agreement with Ghidriff is not independent proof or a probability. Resource guidance: ~90 s and ~235 MB for two small drivers on 4 cores; large binaries can take hours — the default timeout bounds this.

## 6. Acceptance

Parser tests from a trimmed real rz-diff JSON output and synthetic malformed variants (non-array, wrong types, missing keys, similarity > 1, exit 0 with empty stdout); probe version parsing; timeout/cancel via fake child; address mapping and one-sided records; reconciliation display shared with SPEC-10. Live (recorded, optional): Linux CI job installing the pinned rizin release and diffing the compiled fixture DLLs.


## 7. Parser-boundary hardening (2026-10-29)

The public output parser enforces the same 64 MiB UTF-8 byte ceiling as the process
adapter, before JSON decoding. It uses the project's strict JSON loader: duplicate
keys, non-finite values, unpaired surrogate escapes and excessive nesting are
`PT-SECONDARY-INPUT`, never a Python exception or an unpersistable accepted result.
The recorded output digest remains the SHA-256 of the original UTF-8 stdout bytes;
valid Unicode names and escaped surrogate pairs retain their exact text.

Version components use one to nine ASCII decimal digits each. Malformed or oversized
versions make the capability probe unsupported, without integer-conversion errors.
This bounds parsing only; versions accepted by the existing ≥ 0.9.0 policy keep
that policy and the unified adapter's untested-version limitation.

## 8. Isolated producer research controls (2026-11-05)

`tools/rzdiff` may apply the bounded singleton ownership correction only to the exact pinned v0.9.1 source bytes: both SHA-256 `a0b196dbc39e4fb3df4f850e156482ba9668838ccf5bb99a25563fd7a8c7ee5a` and Git blob `8544259e17a692bcb3c1d8858f104745cd0cba4c` must match. SHA-256 authorizes source content; SHA-1 is used only as the non-security Git object identifier. The explicit CLI checkout root may be outside the working directory, but the resolved fixed `librz/arch/similarity.c` path must remain inside that resolved root before mutation. Compiled wrapper doubles and native public API oracle output are separate evidence categories; neither alone permits CLI JSON acceptance or removal of producer quarantine. Native stock-red qualification requires the complete 32-row ownership matrix with expected singleton-only failures, and corrected qualification requires the same matrix with no failures. Missing rows, NULL results, malformed output, crashes, and wrong process exit fail qualification.

The native evidence runner reserves an exclusive marker in its output directory before reading or executing the oracle. It refuses pre-existing native receipt/log files and any reused run directory, preserving all earlier raw evidence on retries and failures. Other build diagnostics may already occupy the directory. The marker remains after failure; use a fresh output directory for each attempt. No automation is enabled by this research-tool integration.

Research CLI path scope: the evidence runner accepts explicit executable and output paths from its local operator, including paths outside the working directory. Those are trusted user choices, not remotely supplied evidence paths. Output child names are fixed and created exclusively; pre-existing receipt/log symlinks are refused. These tools do not claim protection against a hostile process replacing filesystem components during operations.


The research native oracle keeps its default exact 32-row equal-NOP matrix unchanged. Optional `--io-context` exercises actual public-API functions with distinct owned analysis/IO contexts and authored per-side four-byte buffers, in 1:2/2:1 orientations with overlapping and disjoint addresses. Each IO address space contains two readable slots independently of function inventory cardinality; read counters reset after constructor setup, immediately before matching. It requires complete input ownership/coverage, matcher reads through both IO contexts, and the independently known per-pair similarity values (3/4 or 1/2). `--io-context --wrong-bytes` intentionally returns identical bytes and must fail all four rows; `--io-context --wrong-io` intentionally binds both analyses to one IO context and must fail both overlapping-address rows. These are negative oracle controls, never successful producer evidence. The mode's raw rows/return code are retained separately from the default matrix; only an executable linked against the verified pinned native libraries counts as native execution. Header compilation and helper doubles remain separate evidence. No runtime acceptance/quarantine change follows from these research checks alone.
