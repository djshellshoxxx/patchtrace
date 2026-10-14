# BinExport2 producer and Ghidra host boundary (SPEC-49)

Status: draft ADR, 2026-10-14. Owner: [proposal] SPEC-10b owner with the SPEC-31 S1 owner; decision pending owner sign-off. Documents: `src/patchtrace/secondary/binexport_producer.py`, `src/patchtrace/secondary/binexport_run.py`, `src/patchtrace/unified/extract/` (no code is changed by this record). Parent specs: `docs/specs/binexport2-support.md` (SPEC-10b, s8 and s14), `docs/specs/unified-engine/03-extraction.md` (SPEC-31 S1).

## 1. Scope and non-goals

Scope: which component may write a file that PatchTrace treats as a BinExport2 input for a pair, how that differs from the component that writes unified IR, and the boundary a Ghidra-hosted exporter must respect. This answers audit item `docs/audits/spec-gaps-20261014.md` section 5 row 12, parts (1) and (2), and the host boundary that SPEC-14/15 need.

Non-goals: the Phase E implementation of `GhidraHeadlessProducer` (its own spec and PRs, per SPEC-10b s8); any change to `accept_binexport`, the C3 worker or the BinExport2 wire contract; the C3 worker mode `ir-export` (A-18, `unified-engine/10-amendments.md:27`); BinDiff execution (`bindiff-execution.md`).

## 2. Context (verified in code and specs)

| # | Fact | Evidence |
|---|---|---|
| C1 | The only v1 producer is `UserSuppliedProducer`, which returns the file the user selected. Producer output is untrusted and goes through `accept_binexport` with no fast path. | `secondary/binexport_producer.py:3,18-27`; `secondary/binexport_run.py:96-99` |
| C2 | No test imports `BinExportProducer` or `UserSuppliedProducer`. The producer seam is untested. | grep over `src/ tests/ tools/` (only the module itself) |
| C3 | The S1 extractor is the IR producer. It launches the user's Python with the packaged `ghidra_script.py` in private directories, does not cap JVM memory (`-Xmx` bounds it) and never executes the target. | `unified/extract/runner.py:1-10`; `docs/specs/unified-engine/03-extraction.md` s3-s4 |
| C4 | S1 modes are `gzf`, `analyze` and `decompile`. Its output is `ir-extract/1` JSONL, plus an optional GZF. The script contains no BinExport writer (no `BinExport` string in `ghidra_script.py`). | `03-extraction.md` s1, s4; grep of `unified/extract/ghidra_script.py` |
| C5 | The worker has no `ir-export` mode. A-18 plans one as a C3 amendment, because `accept_binexport` returns only a summary to the parent. | `secondary/binexport_worker.py`; `unified-engine/10-amendments.md:27`; `11-review-log.md` R-22 |
| C6 | `ProducerMode` already names `binexport` (`unified/contracts.py:172,618`). That mode means IR read from an accepted BinExport, not a BinExport written by PatchTrace. | `unified/contracts.py:618`; `06-adapters.md:83` |
| C7 | The upstream Ghidra exporter writes no operand masks, emits jumps to function entries as `call_target`, and has no LIBRARY type. Hashes and call semantics therefore differ from the S1 IR. | `03-extraction.md` s1 (`binexport` row); `06-adapters.md:83`; `docs/research/unified-engine/02-bindiff.md:33` |
| C8 | S1 was measured on Ghidra 12.0.4, pyghidra 3.0.2, JPype 1.5.2 and Java 21. The upstream Ghidra extension zip is released for Ghidra 11.0.3. The two versions cannot be assumed to share an install. | `03-extraction.md` header and s4; `binexport2-support.md` s8 (1). External: https://github.com/google/binexport (not re-fetched in this run: [unverified]) |
| C9 | The documented exporter run is a pre-script on an imported program with `-noanalysis`. Whether a failed export still exits 0 is not verified. | `binexport2-support.md` s8 (2) (checked 2026-10-14; [unverified] for this run) |
| C10 | `executable_id` for a Ghidra export is the SHA-256 stored at import time. A pre-existing Ghidra project may give a different id. | `binexport2-support.md` s6.6 and s8 (7) |
| C11 | `binexport2-support.md` s8 says the Phase E producer is "to be specified before coding". Nothing in the repository decides between a Ghidra-hosted exporter and a PatchTrace-written "lite" writer. | `binexport2-support.md:419,549`; `docs/audits/spec-gaps-20261014.md` s3 and s5 row 12 |

## 3. Options

| Option | What it is | For | Against |
|---|---|---|---|
| O1 User-supplied only (status quo, v1) | The user exports a `.BinExport` from their own Ghidra or IDA and selects it. | No new process, no version pin, no new trust surface; already implemented by C3. | No automated pair path; the user must match the Subtract Imagebase choice by hand. |
| O2 Ghidra-hosted exporter | A new `GhidraHeadlessProducer` runs `analyzeHeadless` with a reviewed script that writes a `.BinExport` for one artifact, through a runner that follows `unified/extract/runner.py`. The output goes through `accept_binexport` unchanged. | Produces the file the exporter's consumers (BinDiff) expect. Reuses the S1 runner pattern: private dirs, `run_process`, output guard. | Second JVM and extension pin; version split with S1 (C8); exporter may not fail loudly (C9); needs an external install and a version probe. |
| O3 "BinExport-lite" writer | PatchTrace serialises its own IR into BinExport2 bytes. | No JVM; one run; keeps operand masks. | A PatchTrace-written file in an exporter format makes PatchTrace an exporter that BinDiff trusts, which conflicts with SPEC-10b s8 ("PatchTrace never labels its own file `.BinExport`"). No spec, owner or caller exists. The file would carry IR semantics that differ from C7. Doubles the proto maintenance. |
| O4 IR only | Unified engine diffs IR (S1, or A-18 from an accepted file). BinDiff is fed only by user files. | Simplest; S1 already covers the unified path. | Leaves BinDiff without an automated input; not a replacement for O2 when BinDiff is the goal. |

## 4. Decision [proposal]

D1. S1 (`unified/extract/`) is the only automated IR producer. It MUST NOT write a file named or typed as `.BinExport` or BinExport2.

D2. O3 is rejected. No "lite" writer is specified, implemented or named in any spec or plan.

D3. Alpha and v1: pairs for BinDiff come from user-supplied files only (O1). Automated production stays off until every gate in D5 is met.

D4. Phase E: O2 is the only automated `.BinExport` producer. It implements `BinExportProducer` (`binexport_producer.py:12-15`) and produces exactly one file per artifact, which is then accepted by `accept_binexport` with the same caps and failure taxonomy as a user file (SPEC-10b s7). It has no fast path.

D5. Gates before O2 may run in any build (all required):
- G1 Version probe: the Ghidra install and the exporter extension are read from the installed `Ghidra/Extensions` listing and `application.properties`. A mismatch refuses the run with a reason slug. Nothing is guessed.
- G2 Import: the producer imports the artifact path itself into a private 0700 project. It never reads a pre-existing analyst project (C10).
- G3 Script: the script is a PatchTrace-owned, reviewed file pinned by SHA-256. The upstream `BinExport.java` may be used only after the same review and pin. `-scriptPath` and the project directory are never user-controlled.
- G4 Success: exit code 0 AND `accept_binexport` returns a summary. Exit code alone is never success (C9).
- G5 Options: the Subtract Imagebase choice is identical for both sides of a pair and is recorded in provenance. The UI and CLI say so.
- G6 Bounds: `run_process` with a hard timeout, the Job Object (Windows) or equivalent kill, and the stdout/stderr limits of `extract/runner.py`. A hostile PE is parsed by Ghidra's loaders, so the Java process is treated as untrusted-input parsing.
- G7 Licence: Ghidra, Java and the extension stay external. PatchTrace references an installed copy only (`AGENTS.md`; SPEC-10b s8 (5)).

D6. The S1 IR path does not depend on O2. A Ghidra install may be shared by S1 and O2 only if the exporter supports that version (G1). Otherwise two installs are used. This choice belongs to the Phase E spec, not here.

D7. A BinExport written by O2 is labelled with its producer (`ghidra-binexport` plus the extension and Ghidra versions) in provenance. It is never displayed as a PatchTrace file.

## 5. Contracts and error codes

- Producer seam: `BinExportProducer.produce(artifact, out_dir, *, cancel) -> Path` (`binexport_producer.py:15`) is kept. The return value is untrusted.
- Failures use the existing `SecondaryError` codes and reasons (SPEC-10b s7). New producer reasons [proposal]: `PT-BINEXP-PRODUCER-UNSUPPORTED` (reasons `no-backend`, `ghidra-version`, `extension-missing`), `PT-BINEXP-PRODUCER-FAILED` (reasons `exit-nonzero`, `timeout`, `no-output`, `output-limit`), `PT-BINEXP-PRODUCER-PAIR` (reason `artifact-hash` or `program-hash` mismatch, as in `03-extraction.md` s9). Messages are fixed English templates; they never echo file or log text.
- No persisted contract changes. `SecondaryError.reason` stays additive (SPEC-10b status line).

## 6. Consequences

Positive:
- The BinExport path cannot be confused with IR. Provenance stays exact.
- No second parser, no lite proto writer, no new trust in PatchTrace-written exporter output.
- The S1 runner pattern is reused, so O2 adds a producer and a script, not a new process model.

Negative and costs:
- Alpha has no automated pair path for BinDiff (same as today).
- O2 needs a Ghidra version decision that S1 and the upstream extension may not share (C8).
- A Phase E spec, script review and live goldens are required before any code (SPEC-10b s12, s14 item 4).

## 7. Test and acceptance plan

Covered by existing tests (names only; per-rule mapping to be confirmed by the owner, not re-read in this run):
- `tests/test_secondary_binexport.py`, `tests/test_binexport_pipeline.py`, `tests/test_binexport_isolation.py`, `tests/test_binexport_check.py`, `tests/test_binexport_prescan.py`, `tests/test_binexport_property.py`: validation and isolation behind `accept_binexport` (C1, G4 for user files).
- `tests/test_unified_extract_runner.py`, `tests/test_unified_ghidra_script.py`, `tests/test_unified_retain_gzf.py`, `tests/test_unified_packaging.py`: S1 runner, script and packaging (C3, C4).

Gaps (proposed tests, red first, none yet written):
- T-49-1: `UserSuppliedProducer.produce` returns the supplied path and never copies or renames it. Covers C2.
- T-49-2: static guard: no module under `unified/extract/` contains a BinExport writer or the strings `BinExport2` or `.BinExport` as an output. Enforces D1.
- T-49-3: `accept_binexport` rejects a file whose `executable_id` does not match the artifact SHA-256 (already in SPEC-10b s6.6; confirm the test exists).
- T-49-4 (Phase E only): version-probe refusal, exit-zero-without-file failure, and a hostile-output fixture through the producer path. Not in scope for this record.

Owner-only or external gates, listed separately and not counted as done:
- Live Ghidra plus BinExport goldens and a licensed IDA sample (SPEC-10b s14 item 4).
- Windows frozen run of any producer (SPEC-10b s9 (3)).
- Owner decisions in SPEC-10b s14 items 1-3.

## 8. Open questions (recommended default each)

Q1. Which Ghidra version does the exporter target? Default: the S1 version, if an extension exists for it (G1 decides); otherwise two installs with separate probes. Owner decision.
Q2. Upstream `BinExport.java` or a PatchTrace script? Default: PatchTrace script, pinned by SHA-256 (G3).
Q3. Does a failed export exit 0? Default: unverified; treat any missing or rejected output as failure (G4).
Q4. Does the producer run for `analyze` only, or also for GZF-backed runs? Default: import-based only (G2); GZF reuse is not assumed.
Q5. Is O2 in the alpha? Default: no. Alpha stays O1.
Q6. Does the UI need a separate "make BinExport" action? Default: no. It is a producer option in the existing older/newer picker, after Phase E.

## 9. Integrator asks

- `docs/specs/REGISTRY.md`: add the SPEC-49 row (ADR, draft, owner files in section 1). SPEC-49 is reserved for this record in ledger A (`docs/plans/ledger-A.md` on `origin/claude/clever-clarke-s4nhi6`). SPEC-41 to SPEC-45 are used on that branch; this record does not take them.
- `docs/specs/binexport2-support.md` s8: add a one-line pointer to this record (the file is owned by the C3 owner; not edited here).
- `docs/audits/spec-gaps-20261014.md` s5 row 12 and s3 row 74: mark as answered by SPEC-49 (not edited here).
- `docs/specs/unified-engine/03-extraction.md` s1: optional note that the `binexport` row is import only (not edited here).

## 10. External facts

| Fact | Primary source | Retrieved |
|---|---|---|
| BinExport2 proto pin `2bff7af` and Apache-2.0 licence | https://github.com/google/binexport | 2026-10-14 in SPEC-10b s1; [unverified] for this run |
| Ghidra extension zip released for 11.0.3 | https://github.com/google/binexport/releases | 2026-10-14 in SPEC-10b s8 (1); [unverified] for this run |
| Pre-script invocation with `-noanalysis` | https://github.com/google/binexport (README) | 2026-10-14 in SPEC-10b s8 (2); [unverified] for this run |
| Ghidra headless `analyzeHeadless` options | Ghidra release docs | [unverified]: URL not checked in this run |
