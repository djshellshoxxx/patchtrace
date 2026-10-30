# 03 — Ghidriff, BinExport2, BinDiff and rz-diff native compatibility

**Reference:** SPEC-10b BinExport2, SPEC-28 secondary orchestration, SPEC-29 BinDiff execution, SPEC-31 adapter/extraction, main `src/patchtrace/{backend,secondary,unified/sources}.py` and active #131. **Evidence boundary:** the main branch has native smoke CI; **broad genuine multi-engine feature acceptance remains open**.

## 1. Adapters and roles: do not conflate them

| Backend | Role | Current implementation | Current verified evidence | Missing acceptance |
|---|---|---|---|---|
| **Ghidriff** | Primary source and optional retained Ghidra program GZF | `backend.py`, `backend_cli.py`, `ghidriff_launch/*`, `unified/sources/ghidriff.py` | [main-native Windows run 41060959854](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959854) five green native jobs; unified extraction [41060959558](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959558) | Correct function-modified coverage on accepted R1 patch pair, identical status handling, native extracted facts and real GZF-to-IR handoff |
| **BinExport2** | Ghidra/IDA-exported per-image protobuf with identity; producer/input for BinDiff, not itself a comparison engine | `secondary/binexport_{proto,prescan,worker,run,pipeline,producer,identity,snapshot}.py` | Extensive strict/frozen tests and nightly non-gating fuzz; existence and import are not full host exporter acceptance | Genuine exporter on real PE x64, full input binding, Ghidra extension version, schema/coordinate proof, frozen worker and cancellation |
| **BinDiff 8** | Optional separate comparison over two accepted BinExports | `secondary/{bindiff_probe,bindiff_run,bindiff_inputs,bindiff}.py`, `registry.py::BinDiffAdapter` | Linux research executed BinDiff 8 against real but small synthetic BinExport, import accepted 20 matches; main CI may have optional probe | Pinned and independently trusted native executable, Windows MSI path/probe, actual Ghidra-generated BinExports, native .BinDiff SQLite parse, parity and error correlation |
| **rz-diff** | Optional native Rizin comparison; weak W/E-BODY proposal source | `secondary/{rzdiff,registry,scheduler,store}.py`, `unified/sources/rzdiff.py` | [41060959715](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959715) succeeded Linux and Windows smoke | Version and JSON dialect coverage, orientation check, alternate candidates, true positives/false positives under R1 labels |
| **ghidriff-baseline** | Read-through record of the existing primary run for common scheduler provenance | `secondary/registry.py` and `secondary/cli_run.py` | Unit/source verification; must not spawn another independent Ghidriff comparison | Native run ID/hash integrity and no duplicate evidentiary vote |
| **Diaphora** | Existing optional subsystem and registry metadata | `diaphora/` and unified registry source entry | Some code; not complete unified adapter according to R2 audit | Defer from R6 essential release; do not mistake registry row for live integration |

**Primary constraint:** never silently swap unavailable BinDiff, Ghidriff, BinExport2 or rz-diff with a fake executable and call it compatible. Real engine acceptance requires a nonmock executable version, process and output SHA, correct raw artifact orientation, normalized result, provenance, failure state, independent expected answer and exact input hashes.

## 2. Supported pinned toolchain (verify actual release environments)

`tools/backend_pin.json` identifies Ghidra **12.0.4**, JDK **Temurin 21.0.12.1+1**, pyghidra **3.0.2**, Python embed **3.12.10** and Ghidriff git revision `4f5d895fcbb1eacd65efd81145922c15bb7e741d` for the offline runtime design. The pin file is a **provisioning recipe**; do not equate it with an installed, published and successfully exercised backend bundle. It contains trust and source-digest states that must be checked by `tools/check_backend_pin.py`, and the bundling tests must demonstrate actual offline installation. Report host Java/Ghidra/Ghidriff versions returned by the executables rather than assumed from a manifest.

`tools/bindiff_pin.json` specifies **BinDiff 8**, Linux `bindiff_8_amd64.deb` and Windows `bindiff8.msi`, with known digests and `verified:false` because the published signature/independent source verification was not completed. A successful TOFU download twice through one egress path is not a trusted independent signature. Verify the actual signature with approved key material or an independent trusted source, licence, executable SHA, version string and Windows extraction layout before calling it a release-accepted pin. User-provided/installed BinDiff is optional; treat not-configured as `unsupported` rather than failing the rest of the app.

## 3. Universal compatibility contract per backend

For each executable and each ordered PE pair, record in `EngineRun`/the unified result:
- Executable canonical absolute path or non-sensitive path digest, executable SHA-256, source/vendor and version; probe result (supported/unsupported/failed) with exact error code.
- Older/newer PE SHA-256, arch PE32+ AMD64, size, PE image base, exporter/producer and trusted BinExport identity, verified orientation, exact project/analysis run ID.
- Full structured argv **without shell interpolation**, path-independent command digest, working directory, approved environment allowlist, network-off status, normalized deadline and OS-specific process-tree containment.
- Start/end UTC, elapsed wall time, timeout/cancel/exit classification, bounded stderr/stdout plus hashes, no leaked secrets/absolute private source paths in exports.
- Native output file hash/size/parser version/schema, expected endian/address basis, exact match count, alternatives, per-source evidence IDs, limitations and current-set selection.
- Imported data policy: strict size/row/range/depth/duplicate-key bounds, immutable private copy in quarantine, no actor-controlled SQL or ZIP extraction paths, no permission to run target code.
- Repeat behavior: same tool/version and inputs may result in a legitimate cache hit; version/input/order/policy/config changes invalidate the old cache; existing valid result survives failure.

**Acceptance status categories:** `passed-native`, `passed-mock`, `unsupported`, `failed`, `cancelled`, `timeout`, `blocked-tool`, `blocked-network`, `not-run`. Do not collapse them into a Boolean success indicator. Backend unit tests using fake files can only prove validation/orchestration.

## 4. Ghidriff primary acceptance and identical analysis

- Native Ghidriff must be run by its existing project analysis route—not invoked as a second “secondary engine” Ghidriff.
- The current live-pairs harness `tools/unified/live_pairs.py::analyse_pair` accepts only `run.status=='completed'`, while Ghidriff returns `identical` for byte-identical pairs. This explains missing live outcomes on A/A cases; it does **not** explain other backend errors. Fix must distinguish a legitimate unchanged result from a never-run engine or a failed extractor. Record “identical” as a verified unchanged-pair state only when whole SHA identity, project pair, committed run and expected source artifacts permit it; do not fabricate absent function correspondences.
- Verify persisted raw Ghidriff JSON and the extracted GZF are from the same ordered SHA pair and engine version. GZF extraction should reject unanalyzed program states and fallback own Ghidra analysis with explicit provenance; compare independent extraction output identity where specified.
- Exercise exact source-level known patch, rename, deleted/added, A/A, rebuilt A/A, displacement change, identical body with different target, compiler nuisance and cancellation, on Windows 11 x64 and Linux with the same SHA bytes.
- Run Ghidriff native with actual Ghidra/JDK/Python pin and source-run hash. Confirm changed functions, row orientation and original raw result remain accessible after unified analysis; test a false “function missing” diagnosis by checking disassembler function inventory and Ghidriff raw match data separately.

**Critical defect:** R2 native probe observed an integer constant edit that produced a changed IR scalar but the primary Ghidriff modified row omitted that function. A unified fallback/IR candidate may bring it to review; do not assume Ghidriff alone finds every code change. Add a minimal fixture and acceptance check that verified changed function is visible in the combined UI even if absent from one backend's modified list, without manufacturing match certainty.

## 5. BinExport2: real producer to verified immutable input

The intended workflow is `verified PE -> Ghidra BinExport2 producer -> private snapshot -> strict protobuf parser/validator -> executable_id SHA binding -> older/newer pairing -> BinDiff`.

Source locations:
- `secondary/binexport_prescan.py`: wire length, record/depth cap and memory-amplification pre-scan.
- `binexport_proto.py`/`binexport_descriptor.py`: pinned protobuf schema with `upb` parser; pure Python protobuf fallback can amplify memory.
- `binexport_worker.py`/`binexport_run.py`: isolated child, deadline and snapshot/identity, frozen worker command.
- `binexport_identity.py`, `binexport_pipeline.py` and `binexport_producer.py`: artifact binding, expected base/layout and real Ghidra export producer.
- `binexport_snapshot.py` and `binexport_check.py`: immutable snapshot and strict structural guards.

Potentially dangerous cases: an exported file whose metadata hash is absent (e.g. IDA may legitimately omit SHA), MD5-only older exporter, unrelated SHA, mismatched arch, a valid protobuf with out-of-range indices, duplicate addresses, cycles, invalid flow edges, huge unknown groups, malicious path names, outer file symlinks, mutation between validation and process start, `protobuf` silently falling back to slow Python, truncated body or a valid-but-unbound BinExport.

**Required accepted default:** an input with a SHA-256 binding must equal that side's verified full PE SHA. Unbound exports must remain explicitly unsupported unless a documented analyst waiver is part of accepted scope and exact consumer provenance. A matching filename or file-size is not a binding. Validate old/new side orientation twice: when snapshot accepted and when BinDiff builds argv. Protect the current project from a failed export.

**Producer acceptance sequence:**
1. Confirm current Ghidra extension/compiler compatibility from actual installed version, external `BinExport2` package/licence, and an approved local PE source, with no network unless the operator consents.
2. Inspect target PE headers and hash, import to headless Ghidra under private temp root; never run the PE.
3. Use the real producer to emit one .BinExport per side, record producer and source image SHA, file size, output file SHA and format metadata. Do not use hand-encoded protobuf to satisfy this step.
4. Run `accept_binexport` under the actual subprocess/memory caps and store accepted snapshot. Run negative tests with wrong hash, reversed side, 1-byte truncation, huge counts, invalid RVA, malformed edge, path traversal and cancellation.
5. Rerun using Windows frozen helper/worker, verify subprocess gets no API secrets and temp files removed. Test replay from immutable snapshot without launching Ghidra again.

## 6. BinDiff 8: native CLI and result schema

The existing native research [`docs/research/phase-c/bindiff-automation.md`](../../phase-c/bindiff-automation.md) directly measured BinDiff 8 Linux portable behavior:
- `bindiff --version` exit 0, text begins `BinDiff 8`. `--help` can exit **1 even on successful help**; the probe must parse the expected output rather than treating exit 1 as unconditional failure.
- CLI executable path must resolve to the headless `bindiff` binary; `bindiff_ui` symlink or `--ui` triggers GUI. Never pass untrusted `--flagfile`/`--fromenv`, directory inputs or user config from HOME.
- The headless CLI reads user configuration unless forced to an explicit empty private config `{}`; a user algorithm config changed reported similarity materially in prior research. Existing `bindiff_run.py` must enforce a private config and output directory.
- `--primary` MUST receive **older** approved BinExport and `--secondary` the **newer**. The metadata `file.id 1`/`2` and hash must agree. Check `--nologo`/`--output_dir`/`--output_format` against exact probed version, use fresh out-dir and a single validated `older_vs_newer.BinDiff` file.
- Exit 0 alone is not proof of output; a partially written SQLite file after SIGKILL can have valid header but empty match tables and a hot journal. **Never import after timeout/cancel/nonclean stop.** Use deep SQLite schema and count validation, read-only/immutable only after clean output close and hash.
- Native output similarity and confidence are BinDiff-native diagnostic scores, **not** independent statistical correctness probability.
- A confirmed research run imported a genuine native .BinDiff with 20 matched functions from small synthetic BinExports; this establishes CLI/parser integration on that fixture, not accuracy on real patched DLLs.

**Windows acceptance:** use pinned BinDiff 8 MSI/approved locally installed CLI, verify actual `bindiff.exe` path/version, export a real x64 PE pair, run real CLI in clean HOME/private temp, prove newer/older hash pair, parse functionalgorithm/basicblockalgorithm, function/address tables, alternates and provenance; cancel mid-write, reject residual journal, unsupported version and untrusted config. Record whether the executable can run with the Python frozen app and whether Java is needed (headless BinDiff 8 CLI on Linux did not need Java; verify Windows separately). The optional tool may be **blocked**, but the product cannot claim “BinDiff native integrated and accepted” until it passes.

## 7. rz-diff: native JSON, orientation and weak evidence

`secondary/rzdiff.py::{probe,parse_output,run_rzdiff}` and `secondary/registry.py::RzDiffAdapter` implement probe/spawn/normalize. Main's live Rizin workflow succeeded on Windows and Linux, but R2's 0.9.1 probe also reported parser incompatibility for some genuine outputs and two orientation anomalies in standalone fixtures. Investigate *exact raw stdout* before changing parser or blindly reversing every result. Version/JSON syntax must be versioned; unknown-major/minor should report compatibility limited, not reinterpret a different shape as matched functions.

A proposed rz-diff pair is W/E-BODY unless stronger independent evidence supports it. Duplicates and non-exclusive matches can form contests; do not let a last-wins dictionary silently replace the user's Ghidriff primary pair. If candidate alternatives are not imported, report the skipped alternative count as a limitation. To test symmetry run both orientations and compare normalized old/new pairs, not just return code. Record actual Rizin `rz-diff --version`, raw bounded JSON SHA and generated normalized set digest.

**Test cases:** legitimate matched x64 pair; same RVA but different image base; multiple candidate targets for one old endpoint; reversed pair; malformed JSON with duplicate keys and huge arrays; unsupported version; timeout/forced process death; UTF-8/output logging; no network; Qt and CLI both display unavailable tool states without lying.

## 8. Scheduler, security and failure isolation

`secondary/registry.py::EngineAdapter` defines `probe/argv/run/parse` with injected `jobs.run_process`. `secondary/scheduler.py::run_engines` owns bounded parallelism and cancellation; `secondary/store.py` and `cli_run.py` own immutable `EngineRun`/`SecondaryMatchSet`, one current set per engine and historical attempts. All adapters should:
1. Probe without touching inputs and report `unsupported` when unconfigured.
2. Validate pair SHA/arch/identity/side before spawning or cache use.
3. Use absolute argv elements (no shell), a private cwd, explicit allowed env, bounded stdio and timeout, Job Object on Windows or killpg on POSIX.
4. Attribute error to that engine only and preserve completed primary/other engine results.
5. Read the normalized results through strict bounds, preserve conflicting alternatives and source version, and avoid forced numerical fusion.
6. Delete temporary outputs from failed children without deleting already published historical rows.
7. Emit meaningful GUI states, including “not installed”, “unsupported version”, “output rejected”, “cancelled” and “cached”.

**Concurrency tests:** two engines in parallel with one failing; scheduler cancellation fans out to all descendants; one times out; third is unsupported; the current project's primary run remains unchanged; engine cache invalidates on executable digest and pair inversion; a repeated run selects the most recent valid set without duplicating the original history. Use real Job Objects to confirm kill-on-close on Windows, not only a fake runner in unit tests.

## 9. Executable compatibility matrix and evidence worksheet

| Test ID | Platform and real input | Expected | Required proof |
|---|---|---|---|
| N-GH-01 | Windows 11 x64, verified A/A DLL | Real Ghidriff completed or legitimate identical state; project and IR accessible | Program/PE and raw/GZF SHA, run status, output count and persisted receipt |
| N-GH-02 | Linked real patch old/new | Correct changed function appears for analyst, even if Ghidriff omitted a modified row | Independent truth label and canonical RVA mapping |
| N-BE-01 | Ghidra 12.0.4 with real BinExport producer | Correct, bounded, SHA-bound old/new exports | Extension version, protobuf size/hash and exact PE identity |
| N-BE-02 | malformed/adversarial BinExport | Reject typed with bounded time/RSS; no published state | Rejection reason, worker exit, memory/cancel receipt |
| N-BD-01 | Windows BinDiff 8 with real exports | One valid native .BinDiff imported with correct older/newer orientation | CLI binary SHA/signature status, output deep check, function count |
| N-BD-02 | mid-write kill and hostile output | No partial SQLite or journal imported, no stale cache | Process tree and store integrity |
| N-RZ-01 | Linux and Windows rz-diff pinned | Genuine JSON parser roundtrip on same ordered SHA pair | Raw JSON/hash/version, normalized candidates and alternatives |
| N-RZ-02 | reversed pair/duplicates | Deterministic orientation or explicit error; conflict preserved | Two raw outputs and normalized comparison |
| N-ME-01 | all available genuine engines | Every source visible, independent evidence-class fusion, conflict not hidden | Atom source refs, raw version, dependency components |
| N-PF-01 | clean Windows frozen desktop | Same real local workflow without developer Python installed | ZIP/Setup SHA and installed external backend configuration |
| N-FAIL-01 | every backend failed or absent | Existing saved project still opens, core GUI informative | Database and snapshot digests before/after |

All results need status `PASS / FAIL / BLOCKED / NOT RUN` with exact SHA and CI URL. A green adapter mock is not N-GH/N-BD/N-RZ native acceptance.

## 10. CLI smoke and test sequence

```bash
python -m patchtrace secondary --help
python -m patchtrace secondary run --help
python -m patchtrace secondary import-bindiff --help
python -m patchtrace unified --help
python -m ruff check src tests tools
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

Execute the actual native flags **only after inspecting current help and preparing approved/verified PE and BinExport inputs**. Note exact source SHA and engine versions in `docs/qa.md` under the coordinator once accepted. Do not fabricate a licensed BinDiff binary, substitute a mock engine or report a skipped CI job as passed.
