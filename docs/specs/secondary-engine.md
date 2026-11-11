# SPEC-11: Secondary engine — Rizin rz-diff (Phase 3d)

Status: developer-ready contract, 2026-10-12. Contract version `secondary-engine/1`. Amended 2026-11-11: section 9 (singleton ownership refusal, finding B-D01) and section 10 (adapter fidelity, findings B-D06/SEC-8 and B-D09). Verified facts: `../research/phase3/rizin.md` (rizin v0.9.1 @ c3a90e9, LGPL-3.0-only; run locally on two afd.sys builds).

## 1. Outcome and boundaries

Optionally run rz-diff on the project's artifact pair to obtain a second, independent function-match set. Ghidriff remains the default and primary engine; both evidence sets are kept; disagreements stay explicit. rz-diff is an external, user-installed tool (official Windows/Linux builds exist); PatchTrace does not bundle it.

## 2. Capability probe

`rz-diff -v` (version line) must report ≥ 0.9.0; otherwise `unsupported` with the observed version. Detection never installs anything. Capability record: `{engine: 'rz-diff', version, path, supports_json: true}`.

## 3. Invocation and parsing

`rz-diff -C -j -t functions <older> <newer>` with argv list (no shell), cwd = private temp, stdout bounded at 64 MiB, stderr tail 2 MiB, wall-clock timeout default 1,800 s (configurable 60–86,400), process-tree kill on cancel/timeout (existing `jobs.run_process`). Exit 0 = ran; non-zero = error with stderr tail. Stdout must parse as a strict JSON array of objects `{similarity: number 0..1, type: 'COMPLETE'|'PARTIAL'|'UNLIKE', original: {addr:int, name:str, size:int}|null, modified: {…}|null}`; empty/invalid output is an error even with exit 0. A run stopped by timeout, cancel or the output limit is an error whatever its exit code, and its stdout is never parsed or committed (verified: the adapter's parse refuses a stopped run; the scheduler records timeout and cancelled as their own statuses). Addresses are unsigned VAs.

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

## 9. Singleton ownership refusal (2026-11-11, finding B-D01)

**Defect.** In Rizin 0.9.1 `rz_analysis_match_functions` takes a separate branch when its first list (the older file's functions) holds exactly one function. It runs the common helper with the two lists exchanged and returns the matched pairs and both unmatched lists without exchanging them back (`tools/rzdiff/singleton-ownership.patch` is the research correction, section 8). `rz-diff` serialises that result as it stands, so the newer file's functions appear under `original` and the one older function under `modified`. Retained native output shows it: for an input with one older and two newer functions the newer-only helper is reported under `original` (`seeded-stock-elf-pair-1-2.stdout.log` and its relocatable twin on branch `qualify/native-cli-seeding-20261105`, directory `docs/qa/native-cli-20261105`).

**Why it cannot be repaired here.** The output names no file. The swapped one-older/two-newer result and the correct two-older/one-newer result have the same structure; in the retained pair they differ only in the size and similarity of the second row, which are properties of the authored inputs, not of the side. The swap can therefore be neither detected nor undone from the output. A swap in the parser is forbidden: it would corrupt every result of the ordinary branch.

**Rule: refuse, never swap.** Let M be the set of distinct `modified.addr` values over all rows whose `modified` is not null (matched rows and newer-only rows alike). A result with at least one row and at most one element in M is refused: `parse_output` raises `PT-SECONDARY-ORIENTATION` with kind `rzdiff-singleton-ownership`. Every other result parses exactly as before. Malformed output is still reported as `PT-SECONDARY-INPUT` first.

- Exactly one element: the singleton branch can only put its one older function on the `modified` side, so every swapped result has this shape, and a result with two or more distinct `modified` functions cannot come from that branch.
- No element, but rows: no two-sided run produces this (a file without functions yields no JSON, section 10), so its sides are not trusted either.
- The empty array has no rows and assigns no function to a side; it still parses as an empty set.

**Scope.** The rule applies to every rz-diff version, because no producer with a qualified ownership correction exists (section 8). It is not the version-wide quarantine of the unmerged PRs #163/#164; whether to add that remains an owner decision.

**Cost.** The rule is conservative. A pair whose newer file really has one function, a one-to-one pair, and an ordinary result in which every row points at the same newer function are refused although they may be correct.

**What the analyst sees.** The run is `failed` with `error_code` `PT-SECONDARY-ORIENTATION` and `provenance.failure_kind` `rzdiff-singleton-ownership`. No match set is produced, so nothing is published, cached or reconciled, and an earlier current set stays current. `secondary run` exits 2 when no other selected engine produced a set (SPEC-28 section 7 maps this error code to 2) and 3 with `status: partial` when one did. The message is: "rz-diff result not stored: it lists at most one newer-side function, and for that shape rz-diff can swap older and newer sides without a trace. The pair itself may be fine; use another engine for it." It states what happened and what to do; it does not say the pair is wrong.

**Evidence.** `tests/fixtures/secondary/rzdiff-singleton-shapes.json` holds ten retained stdout documents (one-to-one, one-to-two, two-to-one, two-to-two from the stock matcher library and one-to-two from the research-corrected library, each for two ELF input kinds) with branch, commit, path and SHA-256. They are native output captured by another session from an experimental analysis-seeding build on authored ELF inputs; they show output shapes and are not acceptance evidence for PE or Windows inputs.

## 10. Adapter fidelity (2026-11-11, findings B-D06/SEC-8 and B-D09)

**Byte-exact stdout.** The registry adapter and `run_rzdiff` hand the parser the stdout bytes that `jobs.run_process` captured (`ProcessResult.log_bytes`), not their lossy text. The parser decodes them as strict UTF-8. An invalid sequence is `PT-SECONDARY-INPUT` naming the byte offset; nothing is replaced. A U+FFFD that is really in the output (bytes EF BF BD) is ordinary text and parses. `SecondaryMatchSet.file_sha256` and `EngineRun.output_sha256` are the SHA-256 of exactly those bytes. A runner that kept no bytes supplies lossy text only; a U+FFFD in such text may stand for a replaced byte and is refused as before.

**No functions.** Exit 0 with empty stdout and a stderr that contains `No functions found in file0` is `PT-SECONDARY-INPUT` with kind `no-functions` and the message "rz-diff reported no functions in the older file, so it compared nothing. rz-diff may not support this file; use another engine for this pair." `file1` names the newer file. `file0` is the retained native form (all 16 baseline runs in `docs/qa/native-cli-20261105`); `file1` is inferred from the same message and was not observed. The message reports what rz-diff said: in the retained runs the files did contain functions. Empty stdout without the marker stays "rz-diff produced no output".

**Provenance.** `EngineRun.provenance` (append-only and optional, at most 16 keys of at most 256 characters, SPEC-29 section 5) gains two rz-diff keys, recorded only for an attempt that launches rz-diff:

- `executable_sha256`: SHA-256 of the file the adapter launches (`argv[0]`, the probed executable path), read immediately before the launch. It is left out when the file cannot be read or is larger than 512 MiB.
- `untested_version`: `true` when the probed version is outside the tested 0.9.x series.

`failure_kind` carries the kind of a refusal (`rzdiff-singleton-ownership`, `no-functions`) and, as for BinDiff, `timeout` or `cancelled`. A row of an attempt that records none of these (an unsupported engine, a cache hit, a successful run of a tested version whose executable could not be read) has no `provenance` member, and rows written before this amendment read and serialise byte-identically.

Limits of `executable_sha256`: it identifies the launched file only, not the libraries it loads. A dynamically linked stock build and a corrected build can share the same executable bytes (the retained builds differ only in `librz_arch`), so this hash alone cannot qualify a producer. The file is hashed before the launch, not attested at execution. The cache key does not include it.
