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

Similarity is raw-byte Levenshtein: not semantic, sensitive to relocations and address shifts; no per-match confidence; no symbol names. Agreement with Ghidriff is not independent proof or a probability. Resource guidance: ~90 s and ~235 MB for two small drivers on 4 cores; large binaries can take hours — the default timeout bounds this.

## 6. Acceptance

Parser tests from a trimmed real rz-diff JSON output and synthetic malformed variants (non-array, wrong types, missing keys, similarity > 1, exit 0 with empty stdout); probe version parsing; timeout/cancel via fake child; address mapping and one-sided records; reconciliation display shared with SPEC-10. Live (recorded, optional): Linux CI job installing the pinned rizin release and diffing the compiled fixture DLLs.
