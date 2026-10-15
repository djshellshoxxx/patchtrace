# SPEC-31 / 03 Extraction: ProgramIR from Ghidra (GZF reuse first), ingest, PE tables

Status: S1 implemented the extractor script, runner, ingest, features, MD index, PE tables, IR reader and placement, the `retain_gzf` backend seam, the packaging lines and the live workflow (2026-10-14, `src/patchtrace/unified/{extract,ir}/`); the formats this chapter left open and its deviations are frozen in s12. S3b then built the `decompile` mode of the script, the runner entry `decompile_side` and the strict reader of `decomp.jsonl` (2026-10-14, s12.9); the worker stage that drives them (`refacts`) is the integration owner's.

Purpose: produce one validated, deterministic `program-ir/1` per artifact ([02 s3](02-data-model.md#3-programir-program-ir1-canonical-written-by-patchtrace-read-only-after-publish)) without bundling Java/Ghidra/pyghidra and without executing the target. Owner slice S1 (S3b decompile mode: S3). Numbers: L-xx in 02 s6. Facts marked [own] were measured by the review on Ghidra 12.0.4 / pyghidra 3.0.2 / JPype 1.5.2 / Java 21 with clang-built x64 PE DLLs ([11-review-log](11-review-log.md) s2).

## 1. Producers and modes

| Producer | Mode | When | Cost | Notes |
|---|---|---|---|---|
| Ghidra via external Python + pyghidra | `gzf` | Ghidriff ran fresh with `retain_gzf` (D-05) | GZF import < 0.1 s on small inputs [own]; no auto-analysis | analysis identical to the primary run (F1 by construction); refused unless `GhidraProgramUtilities.isAnalyzed(program)` (Ghidriff saves the GZF in a `finally`, even after a failed analysis [src ghidriff 4f5d895 l.993-997]) |
| same | `analyze` | no GZF (raw-cache hit, imported Ghidriff JSON, flag off, GZF refused) | full Ghidra auto-analysis per side (ntoskrnl ~1349 s per side, R03 s3) | plain Ghidra defaults (as Ghidriff without `--program-options`, T-06); both sides MUST share mode, `analysis_options_digest` and symbol policy; the analysed program is also packed to a GZF in `out_dir` for S3b |
| same | `decompile` (S3b) | after facts, for <= L-41 review pairs | JVM start ~3.5 s + GZF imports + ~0.013 s median per function [own] | reads the two GZFs of this run; emits `decomp.jsonl` only (05 s2.8) |
| BinExport2 import | `binexport` | user-supplied `.BinExport` accepted by C3 (`accept_binexport`) | parse only | needs a new C3 worker mode (A-18); jump refs exported as `call_target`, no LIBRARY type, `FUN_` names omitted, no operand masks (R02 s2) -> `h1..h3` NULL, tiers limited (06 s7) |
| rizin `aflj/afbj/pdfj` | `rizin` | backup B-02 only, no Ghidra | 0.64 s per 148 functions (R03 s4) | discovery is reachability-bound (77/138 found) -> flag every IR `coverage-partial`; never mixed with a Ghidra IR on the other side |

Symbol policy (F1, R-13): `gzf` mode inherits the primary run's symbols (PDB applied by Ghidriff when the user allowed downloads, backend.py:541-542). `analyze` mode never downloads (no network, private settings dir) and records `symbols: none`; if the primary run used symbols, the result carries limitation `ir-symbols-differ` (function starts and names may differ from Ghidriff's rows; fusion treats unmatched IR rows as one-sided, never as contests).

## 2. Request (`ir-extract-request/1`, written by the runner, read by the script)
```python
class ExtractRequest(_Strict):
    contract: Literal['ir-extract-request/1'] = 'ir-extract-request/1'
    side: Literal['older', 'newer']; artifact_path: str; artifact_sha256: Sha256
    mode: Literal['gzf', 'analyze', 'decompile']; gzf_path: str | None; gzf_sha256: Sha256 | None
    out_dir: str; work_dir: str             # both private, absolute, existing, no dot-prefixed component, < 240 chars on Windows
    max_heap_mb: int = Field(ge=512)        # L-03
    analysis_options: dict[str, str]        # analyze mode only; digest recorded; identical for both sides
    limits: dict[str, int]                  # L-01, L-02, L-05, L-06 (the script stops at the caps and marks `partial`)
    decompile_rvas: tuple[Rva, ...] = ()    # decompile mode only, <= L-41 per side, sorted
```

## 3. Runner (`extract/runner.py`, PatchTrace side; pure except for the injected `runner=run_process`)
```python
def extract_side(req: UnifiedRequest, side: Side, budget: Budget, emit, *, runner=run_process) -> ExtractOutput:
    cfg = req.backend                                              # BackendConfig of the project (python, ghidra, java)
    if not cfg.python_executable or not cfg.ghidra_dir:
        raise UnifiedError('PT-UNIFIED-UNSUPPORTED', 'Ghidra extraction needs the configured Python and Ghidra', reason='no-backend')
    work = private_dir('patchtrace-ir-')                           # tempfile.mkdtemp; validated like backend._validated_ghidra_output_path
    script = work / 'pt_ir_extract.py'
    copy_verified(SCRIPT_RESOURCE, script)                         # empty private dir: nothing else importable (01 s9.5)
    (work / 'ghidra').mkdir(); (work / 'out').mkdir()              # GhidraProject.createProject needs an existing dir [own]
    request = ExtractRequest(..., mode='gzf' if gzf_for(side) else 'analyze', out_dir=str(work / 'out'),
                             work_dir=str(work / 'ghidra'), max_heap_mb=heap_mb(L03), ...)
    write_json(work / 'request.json', request)
    env = backend._environment(cfg, settings_dir=work / 'ghidra-settings')   # private XDG_CONFIG_HOME, no symbol server state
    argv = [abs(cfg.python_executable), '-B', '-X', 'utf8', str(script), '--request', str(work / 'request.json')]
    res = runner(argv, cwd=work, env=env, cancel=budget.cancel, timeout_seconds=timeout_for(request.mode),   # L-04
                 check_output=progress_and_size_guard(work / 'out', emit, cap=L05), separate_streams=True,
                 log_limit=64 * 1024, stderr_limit=256 * 1024)  # NO memory_limit_bytes: RLIMIT_AS breaks JVM reservations; -Xmx bounds it
    classify(res)                                                  # cancelled / timeout / output-limit / exit != 0 -> 01 s6 codes
    out = work / 'out' / 'ir.jsonl'
    require(out.is_file() and not out.is_symlink(), 'PT-UNIFIED-EXTRACT', reason='no-output')
    return ExtractOutput(jsonl=out, gzf=work / 'out' / 'program.gzf', stderr_tail=sanitize(res.stderr_tail), provenance=probe_versions(res))
```
- `progress_and_size_guard` returns `'output-limit'` when `out/` exceeds L-05 or contains a symlink/directory, and forwards `progress.json` (`{phase, done, total}`, <= L-37) as `StageEvent`s; it never raises (a bad progress file is ignored).
- The script resource is located with `importlib.resources.files('patchtrace.unified.extract') / 'ghidra_script.py'`; it is collected as a DATA file (PyInstaller stores `.py` modules as bytecode in the PYZ, where the external interpreter cannot read them) by a hook `tools/pyinstaller_hooks/hook-patchtrace.unified.extract.py` = `datas = collect_data_files('patchtrace.unified.extract', include_py_files=True)` (`.py` files are excluded unless `include_py_files=True`); both build scripts already pass `--additional-hooks-dir tools/pyinstaller_hooks` (build_windows.py:41, build_linux.py:56). Frozen smoke asserts it exists (plan, packaging).
- No `-I` flag: user-site installs of ghidriff/pyghidra must keep working exactly as for the primary run (backend.py runs `python -m ghidriff` without `-I`); `PYTHONPATH`/`PYTHONHOME` are already removed by `_environment`.
- Version probe: the script prints one JSON line `{"probe": {...}}` to stdout first; versions `unknown` are allowed but make the IR cache-ineligible (02 s5). The Ghidra version is also read without a JVM from `Ghidra/application.properties` (`backend._ghidra_version`), so `ir_key` is computable before extraction (02 s5).

## 4. Script behaviour (`extract/ghidra_script.py`; runs in the external interpreter; normative)
Rules: imports only stdlib, `pyghidra`, `jpype` and Ghidra Java classes; never imports `patchtrace` or `ghidriff`; computes no hashes beyond SHA-256 of the input file and string values; writes only below `out_dir`/`work_dir`; no network; deterministic iteration (`getFunctions(True)` = ascending entry). API calls below were exercised on Ghidra 12.0.4 / pyghidra 3.0.2 [own] unless marked.
```text
main(request):
  probe -> print {"probe": {ghidra, pyghidra, java, python, script_sha256}}
  verify sha256(artifact_path) == request.artifact_sha256 else exit 3 'artifact-hash'
  launcher = pyghidra.launcher.HeadlessPyGhidraLauncher(install_dir=GHIDRA_INSTALL_DIR)
  launcher.add_vmargs('-Xmx%dm' % max_heap_mb); launcher.start()     # pyghidra.start() takes no VM arguments [src pyghidra 3.0.2]
  gp = ghidra.base.project.GhidraProject.createProject(work_dir, 'pt', True)   # temporary project; never the analyst's projects
  program = gp.importProgram(java.io.File(gzf_path | artifact_path))  # GzfLoader is picked for a .gzf [own]
  mode gzf:     require GhidraProgramUtilities.isAnalyzed(program) else exit 3 'gzf-not-analyzed'
  mode analyze: pyghidra.analyze(program)    # acquires the script bundle host and marks the program analysed;
                                             # GhidraProject.analyze() lacks the bundle host and an analyser raises NPE [own]
                gp.saveAsPackedFile(program, File(out_dir/'program.gzf'), True)       # kept for S3b (03 s8)
  verify str(program.getExecutableSHA256()) == artifact_sha256 else exit 3 'program-hash'   # equal on original and GZF [own]
  verify str(program.getLanguageID()) startswith 'x86:LE:64' else exit 4 'unsupported-language'
  emit header (image_base, size_of_image, language, compiler spec id, producer, analyzed, symbols)
  for f in program.getFunctionManager().getFunctions(True):          # externals listed with kind 'external'
      if cancel or caps reached: footer status 'partial'; break
      for ins in program.getListing().getInstructions(f.getBody(), True):
          proto = ins.getPrototype()                                    # memoise masks per prototype identity (they are per prototype)
          imask = proto.getInstructionMask()                            # may be None -> record null, function flag `mask-missing` [src]
          per operand i: optype = ins.getOperandType(i) (OperandType flags), omask = proto.getOperandValueMask(i),
                         objs = ins.getOpObjects(i) (Register | Scalar | Address), refs = ins.getOperandReferences(i)
                         (type, to-address: memory -> RVA, stack -> 'stack:<offset>', external -> import key)
      rec = {rva, ranges (body address ranges), name, name_src (symbol.getSource()), aliases (other symbols at the entry),
             lib (FID tag, [unv] API: see below), kind, thunk_target (getThunkedFunction(False)), import, raw (<= L-06),
             blocks (BasicBlockModel(program).getCodeBlocksContaining(body, monitor); successors via getDestinations,
             incl. COMPUTED_JUMP switch targets [own]), insns, calls, strings, text (str(ins))}
      write one JSON line; every 500 functions write progress.json (.part then replace)
  emit footer {functions, instructions, status, warnings}; gp.close(); exit 0
main(decompile): same launch; import both GZFs; DecompInterface().openProgram(p); decompileFunction(f, 60, monitor) per rva;
  write decomp.jsonl lines {side, rva, status: ok|timeout|failed, code} (code <= L-29); never decompiles outside decompile_rvas
```
Exit codes: 0 ok, 2 bad request, 3 input mismatch, 4 unsupported, 5 cancelled by signal, other = crash. Measured cost of the per-instruction dump through JPype [own]: 18-25 us/instruction for address, length, mnemonic and operand types; 68-70 us with masks, op objects, references, flow and text (about 3.5 min per side at 3 M instructions on a 2.1 GHz vCPU), so per-prototype memoisation of masks is required and L-04 holds. Still [unv] (first live S1 run, `--self-check` lists missing classes): the FID "library" signal (FID applies names with source ANALYSIS; the exact marker to read is unverified, so `lib` stays `false` until verified, F16 degrades to no tag), and behaviour on MSVC-built PEs (the review used clang/nasm PEs).

## 5. Ingest (`ir/ingest.py`, runs in the worker child; pure + file output)
```python
def ingest(jsonl: Path, expect: ExpectedSide, limits: UnifiedLimits, budget: Budget) -> IrBuildResult:
    tables = Tables()                                       # in-memory rows, then one SQLite write transaction
    with open_bounded(jsonl, max_bytes=limits.l05_total) as lines:
        header = parse_header(next(lines))                  # pydantic strict; hashes == expect.artifact_sha256 (PAIR / ORIENTATION)
        pe = expect.pe_tables                               # from ir/pe_tables.py: pdata entries, unwind info, reloc set, image_base
        require(header.image_base == pe.image_base, 'PT-UNIFIED-IR', reason='image-base-mismatch')
        prev = -1
        for line in lines:                                  # streaming; each line <= L-05 per-line cap
            budget.tick()
            rec = validate_fn(line, limits)                 # hand-written: types, ranges in image, order, caps, utf-8
            if rec is FOOTER: footer = rec; break
            require(rec.rva > prev, reason='fn-order'); prev = rec.rva
            ops = classify_operands(rec, pe)                # vkind per operand + located address fields (s6)
            tables.add_fn(rec, keys=features.compute(rec, ops), extent=pdata_check(rec, pe), eh=pe.eh_sig(rec.rva))
        require(footer and footer.counts == tables.counts, reason='footer-mismatch')
    tables.resolve_calls()                                  # target rva -> fid or import key; unresolved -> NULL
    tables.md_index()                                       # ir/mdindex.py (04 s2)
    digest = tables.content_digest()                        # canonical JSON in primary-key order
    write_sqlite(tables, tmp_file); manifest = build_manifest(...); return IrBuildResult(tmp_dir, manifest)
```
Determinism: rows sorted by `rva`; `fid` = rank; mnemonic ids assigned by sorted mnemonic text (not first appearance) so ids are stable across sides; JSON parsed with duplicate-key and constant rejection (`persistence.strict_json` rules). Measured on a synthetic 60,000-function / 2.84 M-instruction / 355 MB side [own]: 28.9 s wall and 304 MiB peak RSS for strict parse, masking, blake2b keys, zlib blobs and the SQLite write (no MD index, text blobs or content digest yet), far inside L-08.

## 6. Operand classes, address fields and normalisation (`norm/1`, R-07)
`vkind` per operand, from positive evidence only (probe facts [own] in brackets):
| vkind | Rule (first match) | Masked in |
|---|---|---|
| `address` | the operand has a reference to a memory address of the image (`getOperandReferences`), or OperandType ADDRESS with a value in [image_base, image_base+size_of_image), or a base relocation covers its value bytes. Covers RIP-relative data and code [`ADDR | DATA`, mask = disp32 only], LEA scalars (value = absolute VA), relative branches, and RVA-form displacements such as MSVC jump tables `[rdx + rax*4 + RVA]` [`ADDR | DYN`, DATA ref, no scalar] | L1, L2 |
| `stack` | a stack reference (`Stack[...]`) or base register RSP/RBP with a frame displacement | L2 |
| `memory` | other memory operand (base/index + displacement), no image reference | L2 (displacement) |
| `scalar` | OperandType SCALAR without a memory reference | L2 |
| `register` | registers only | never |
Address fields are cleared, never whole operand masks: an operand value mask also covers SIB/ModRM register bits (`[rdx + rax*4 + disp]` mask = SIB + disp32 [own]), so masking it would hide an index-register change. The ingest clears only the displacement or immediate bytes: the trailing `n` bytes of the operand's mask range whose little-endian value equals the displacement (`getOpObjects` scalar, or target - next_ip for RIP-relative, or target - image_base for RVA form); if they cannot be located unambiguously the operand is not masked and the function gets flag `mask-unlocated` (no COS-ADDR possible).
```python
def address_fields(rec, ops, pe):
    for ins in rec.insns:
        raw = ins.raw_bytes; l1 = bytearray(raw); l2 = bytearray(raw)
        for op in ops[ins]:
            if op.vkind == 'address': clear(l1, op.field); clear(l2, op.field)      # located field only
            elif op.vkind in ('stack', 'memory', 'scalar') and op.field: clear(l2, op.field)
        l3 = and_bytes(raw, ins.imask) if ins.imask else None                     # SLEIGH instruction mask; None -> h3 NULL
        yield (l1, l2, l3, ins.mnem in NOP_FAMILY)       # closed table v1: NOP, multi-byte NOP forms; int3 after the last ret
```
Rules: over-masking would hide immediate edits (R05 F2 risk), so masking follows positive evidence only, and every masked address field is re-validated by target consistency before any proof (05 s2.7). Register fields stay in L1/L2 (register renaming is detected by C2, not hidden). `mov edi, edi` (zero-extends RDI on x64, not a NOP), `xor r,r` vs `mov r,0` and other idioms are NOT normalised in v1 (measure first, R04 s5).

## 7. PE tables (`ir/pe_tables.py`, stdlib, bounded, via `VerifiedArtifactReader`)
- Exception directory (index 3): RUNTIME_FUNCTION = 3 x uint32 (BeginAddress, EndAddress, UnwindInfoAddress), sorted, <= `size/12` entries, each inside a section; UNWIND_INFO flag `UNW_FLAG_CHAININFO` links chained entries to their primary function (chunks). Function extent is `pdata-confirmed` when Ghidra's entry equals a primary BeginAddress and the union of its ranges equals the chained entries' union; leaf functions have no entry (stay `extent_src=0`).
- EH signature (EH-EQ, 05 s2.5): per primary entry, normalised UNWIND_INFO (version, flags, prolog size, frame register/offset, unwind code bytes), handler RVA (as a target to map), handler-data length, and for `__C_specific_handler` the scope records with begin/end/target made function-relative; stored as `eh` JSON (<= 4 KiB) per function, `NULL` = no unwind data.
- Base relocations (index 5): blocks of (page RVA, size, uint16 entries); only type 10 (DIR64) and 0 (padding) accepted, others recorded as warnings; result = sorted RVA list for relocation coverage.
- Caps: 1,000,000 RUNTIME_FUNCTIONs, 4,000,000 relocations; violations -> `LIMIT` with reason; malformed tables -> IR still built, `extent_src=0`, `eh` unavailable, warning `pdata-unreadable` (never fatal).
- Dynamic value relocations, RTTI and XFG hashes (R04 s6) are NOT parsed in v1 (backup B-11).

## 8. Backend seam for GZF retention (S1, `backend.py`, additive)
```python
@dataclass(frozen=True)
class BackendConfig: ...; retain_gzf: bool = False               # new, default False; not part of the raw-cache fingerprint (argv unchanged)
# in run_comparison, after `result = run_process(...)` returned and BEFORE `finally: _remove_scratch(scratch_root)` (backend.py:543-549):
if config.retain_gzf and result.returncode == 0 and result.reason is None and not cancel.is_set():
    files = sorted(engine_gzfs.glob('*.gzf'))                    # Ghidriff names them <artifact file name>-<sha1[:6]>.gzf [src l.1406-1411]
    if len(files) == 2 and all(f.is_file() and not f.is_symlink() for f in files) and total_size(files) <= L36:
        target = quarantine / 'unified' / 'gzf'; target.mkdir(parents=True)       # renamed with the quarantine dir by publish()
        for f in files: move_and_hash(f, target)                  # sha256 recorded in run settings['gzf']; failures -> warning, never fail the run
```
Mapping a GZF to a side: by the Ghidra-recorded executable SHA-256 inside the program (checked by the script), never by file name. Lifetime: retained GZFs (and `analyze`-mode `program.gzf`) are transient: deleted after the result is published and S3b finished, or at the start of the next unified run, whichever comes first (U-02). A project backup taken while they exist includes them (`ProjectStore.backup` copies all of `runs/`, persistence.py:425-432), so `unified status` reports their size. Raw-cache hits produce no GZF -> `analyze` mode.

## 9. Failure modes (reason slugs; code in 01 s6)

| Reason | Code | Cause | Effect |
|---|---|---|---|
| `no-backend`, `pyghidra-missing`, `ghidra-version` | UNSUPPORTED | no configured Python/Ghidra; script `--self-check` failed | S0 mode (B-00), row flag `ir-missing` |
| `artifact-hash`, `program-hash` | PAIR | wrong file or GZF for this side | refuse; nothing stored |
| `gzf-not-analyzed` | EXTRACT | GZF saved by Ghidriff's `finally` after a failed analysis | that side falls back to `analyze`; F1 then forces `analyze` on both sides |
| `unsupported-language` | UNSUPPORTED | not x86-64 PE | S0 mode |
| `no-output`, `no-footer`, `footer-mismatch`, `fn-order`, `bad-record:<field>` | IR | crash, truncation, malformed line | refuse IR; previous IR (if any) unaffected |
| `output-limit`, `functions-cap`, `instructions-cap`, `ir-too-large` | LIMIT | L-01/L-02/L-05/L-07 | IR refused, or `partial` with flags when only per-function caps hit |
| `timeout`, `cancelled` | TIMEOUT / CANCEL | L-04 or user | tree killed, private dir removed |
| `image-base-mismatch`, `pdata-unreadable`, `mask-missing`, `mask-unlocated` | IR / warning | loader rebased, hostile tables, SLEIGH parse without masks, unlocatable displacement | refuse / continue without pdata / function keys `h3` NULL / no COS-ADDR for that function |

## 10. Tests (red/green, named; fakes = `tests/fake_exe.py` interpreters running a fake script)
- `test_runner_builds_argv_without_shell_and_absolute_python`; `test_runner_copies_script_into_empty_private_dir`; `test_runner_env_has_private_settings_dir_and_no_pythonpath`; `test_runner_never_sets_memory_limit_for_jvm`.
- `test_progress_file_drives_stage_events_and_bad_file_is_ignored`; `test_output_guard_kills_on_size_cap_and_symlink`.
- `test_cancel_and_timeout_kill_tree_and_remove_private_dir` (heartbeat grandchild, as SPEC-28 s10).
- `test_ingest_rejects`: unknown key, NaN, duplicate key, out-of-order rva, missing footer, footer count mismatch, ranges outside image, wrong artifact hash, reversed side, oversize line (one case each, parametrised with short ids: Windows console stall rule, docs/qa.md).
- `test_ingest_is_deterministic_under_record_permutation_of_equal_keys` and `test_content_digest_independent_of_sqlite_file_bytes`.
- `test_l1_masks_only_positive_address_evidence`; `test_l1_masks_displacement_not_sib_register_bits`; `test_rva_form_jump_table_displacement_is_address`; `test_stack_operand_is_frame_class`; `test_l2_masks_immediates_keeps_registers`; `test_l3_equals_sleigh_mask`; `test_nop_family_skipped`.
- `test_pdata_chained_entries_merge_chunks`; `test_eh_signature_function_relative`; `test_reloc_dir64_only_others_warn`; hostile tables from `tests/pe_builder.py` (overlap, out-of-section, huge counts).
- `test_retain_gzf_moves_two_files_and_records_hashes`; `test_retain_gzf_skipped_on_failed_or_cancelled_run`; `test_retain_gzf_off_is_byte_identical_to_today` (golden run settings); `test_raw_cache_hit_has_no_gzf_and_falls_back_to_analyze`; `test_gzf_not_analyzed_falls_back`.
- `test_ghidra_script_imports_no_patchtrace` (AST); `test_script_self_check_lists_missing_classes` (fake pyghidra module).
- Live (not mocked, recorded separately in docs/qa.md): `live-unified-extract` workflow on the CI fixture DLL pair (`tests/fixtures/old.c`/`new.c`) with Ghidra 12.0.4 on Windows and Linux; asserts header hashes, counts > 0, `gzf` and `analyze` modes produce identical records for the same analysis, determinism of `content_digest` across two runs and across OSes.

## 11. Security and Windows notes
Target never executed (Ghidra static load only); no symbol server (private settings dir, `--no-symbols` policy recorded); script and request files live in a fresh private dir; output treated as hostile (caps, strict parse, plain-text display of names and instruction text). Windows: Ghidra paths < 240 characters and no dot-prefixed components (Ghidra rejects them, backend precedent); sidecar directories use 16-hex short ids (02 s3) so `runs/<run_id>/unified/...` stays short; the request travels as a file, so the 32,767-character command-line and environment-block limits are not approached; antivirus may lock `ir.sqlite3` during `os.replace` -> bounded retry (5 x 200 ms) then `STORE` with the path redacted; the JVM child is inside the Job Object (killed with the tree); two extractions never run concurrently by default (JVM memory; the spawn-handle race is fixed, jobs.py:14-17).


## 12. S1 freeze notes, formats left open above, and deviations (2026-10-14)
Facts marked [own] were measured on Ghidra 12.0.4 / pyghidra 3.0.2 / JPype 1.5.2 / Java 21 (Linux) with clang+lld-link and MinGW PEs; Windows behaviour of every [own] fact is verified only by `live-unified.yml`.

### 12.1 Newly recorded Ghidra facts [own]
1. `Instruction.getPrototype().getInstructionMask()` and `.getOperandValueMask(i)` return `ghidra.program.model.lang.Mask` objects (bytes through `.getBytes()`), not `byte[]`. `OperandType` values: READ 1, WRITE 2, INDIRECT 4, IMMEDIATE 8, RELATIVE 0x10, IMPLICIT 0x20, CODE 0x40, DATA 0x80, PORT 0x100, REGISTER 0x200, LIST 0x400, FLAG 0x800, TEXT 0x1000, ADDRESS 0x2000, SCALAR 0x4000, BIT 0x8000, BYTE 0x10000, WORD 0x20000, QUADWORD 0x40000, SIGNED 0x80000, FLOAT 0x100000, COP 0x200000, DYNAMIC 0x400000. The ingest hard-codes ADDRESS, SCALAR, REGISTER, DYNAMIC and INDIRECT; the script compares the complete table with the live class at start and exits 4 (`operand-flags`) on any difference.
2. `SourceType` has five values in 12.0.4 (`DEFAULT`, `ANALYSIS`, `AI`, `IMPORTED`, `USER_DEFINED`): `fn.name_src` codes 0..4 in that order; `AI` is accepted and, like `DEFAULT` and `ANALYSIS`, is never a name anchor.
3. Operand mask anatomy (x86-64): an immediate, a relative branch target or a RIP-relative displacement is a pure run of `ff` bytes (ModRM mod/rm are fixed by the instruction mask). A DYNAMIC operand (`[base + index*scale + disp]`) starts with ONE leading byte that is ModRM.rm (mask `07`) or SIB (`ff`, or a partial mask such as `07`/`f8` when index or base are fixed by the constructor); the displacement, if any, follows as `ff` bytes. `getOpObjects` of a DYNAMIC operand lists registers and BOTH the scale and the displacement as scalars (`[RBP + RDX*1 + -0x80]` -> RBP, RDX, 1, -128), so scalars alone cannot say which is the displacement.
4. A stack reference can sit on a REGISTER operand (`LEA RBP,[RSP + 0x80]` carries `Stack[-88]` on operand 0); RVA-form jump-table operands (`[RDX + RCX*4]`) carry a DATA reference to the table but no displacement bytes at all.
5. An import call (`CALL qword ptr [IAT slot]`, `JMP qword ptr [IAT slot]`) has: operand reference READ or INDIRECTION to the slot (data, `pointer`), a reference FROM THE SLOT to the external location (`ExternalLocation.getLibraryName()` upper case, `getLabel()`), and a flow reference at operand index -1 into the EXTERNAL space. `BasicBlockModel` destinations of such blocks include the EXTERNAL address and the INDIRECTION slot (as huge negative values once the image base is subtracted): the script keeps only successors that are block starts of the same function.
6. MinGW import stubs are THUNK functions whose thunked function is external (`getThunkedFunction(True).isExternal()`); there is no function object for an import without a stub. Functions may own up to 10+ ranges (cold chunks); `getExternalFunctions()` returns only imports reached by a call.

### 12.2 Interfaces and deviations from s2-s9
1. `extract_side(req: UnifiedRequest, ...)` cannot be written (`UnifiedRequest` is S0b's and does not exist yet): the runner takes `ExtractJob` (side, artifact path and SHA-256, `BackendConfig`, mode, optional GZF path and SHA-256, analysis options, limits, optional heap/timeout) and returns `ExtractOutput` (private directory, `ir.jsonl`, optional `program.gzf`, probe, sanitised stderr tail, `cleanup()`). It emits `ExtractProgress(stage, done, total)`; S0b adapts it to its `StageEvent`. Total RAM comes from the caller (`ExtractJob.total_ram_bytes`; the package may not import `ctypes`, 01 s3): unknown RAM gives `-Xmx4096m`, not the 512 MiB floor of `jvm_heap_mib`.
2. Reason slugs are `[a-z0-9-]{1,48}` (`UnifiedError`): `bad-record:<field>` (s9) is spelled `bad-record-<field>`.
3. `fn.kind` `external` stays in the contract but the Ghidra producer never emits it: an external function has no RVA (`rva` is the unique key). Imports are identified by the import key carried by (a) thunk functions (`import`), (b) `calls`, (c) operand references (`ext:`). The ladder's P01 matches thunk functions that carry `import_key`.
4. `ir_key` is computed by the ingest from the validated header (actual probed versions) via `ir.ingest.ir_key_inputs`; the runner can predict it before extraction from the run settings (`extract.runner.predict_ir_key`), and a different actual key only costs a cache miss.
5. A-04b (global `DerivedCache` stage `program-ir`) is NOT built: `enrichment/cache.py` belongs to the hardening track this wave and U-08 makes the global copy optional. The project-local IR (`runs/<run_id>/unified/ir/<ir_key[:16]>/`) is complete without it.
6. `place_ir`/`find_ir` (deferred by S0a, 02 s9 item 9) live in `ir/place.py`, not in `store.py`.
7. `lib` stays `false` and `RowFlag` `library` is never set. The marker is now known (research note `../../research/ue-open-questions.md` Q1): FID sets a plate comment `Library Function - Single Match.`, a bookmark of type Analysis and category `Function ID Analyzer` (`Function ID Conflict` for ambiguous matches), no tag and no flag; reading the bookmark category is the follow-up, pending a live probe with an FID database; the script's `--self-check` lists missing classes.
8. `ExtractRequest`, `IrExtractHeader` and `IrExtractFooter` are used unchanged; everything else in this section is S1-internal and versioned by `ingest_version` `ir-ingest/1` / `norm_version` `norm/1`.

### 12.3 `ir-extract/1` `fn` line (all keys required, unknown keys rejected)
`{"type":"fn","rva","ranges":[[rva,len]..<=64 sorted, disjoint, inside the image; the entry lies in one of them],"name"<=512,"name_src":DEFAULT|ANALYSIS|AI|IMPORTED|USER_DEFINED,"aliases"<=16 names,"kind":normal|thunk,"thunk_target":rva|null,"import":{"dll","name"|null,"ordinal"|null}|null,"lib":false,"raw":hex|null,"truncated":bool,"blocks":[[rva,len,n_insn,[succ_rva..],[kind..]]..],"insns":[[off,len,mnem,imask|null,[[optype,omask|null,objs,refs]..<=6],flow]..],"calls":[[site_rva,target_rva|null,import_key|null,"call"|"jump"]..],"strings":[[site_rva,sha256,len,prefix<=64]..],"text":[str<=256 per instruction]}`.
- `off` is the byte offset of the instruction inside `raw` (the concatenation of the ranges in ascending address order); an instruction never straddles two ranges. `mnem` matches `[A-Za-z0-9_.]{1,32}`; `imask`/`omask` are lower-case hex of exactly `len` bytes or `null`; `flow` is a Ghidra `FlowType` name (`[A-Z_]{3,48}`).
- `objs` entries: `["reg",name<=16]`, `["scalar",signed int64]`, `["addr",rva|null]` (null outside the image). `refs` entries: `[reftype<=40, target]` with target `rva:<n>` (inside the image), `stack:<n>` or `ext:<import key>`. Import key = `<dll lower case>!<name>` or `<dll lower case>!#<ordinal>`.
- A reference to a pointer slot that holds an external reference is emitted as `ext:<key>` (the slot RVA stays in `objs`); flow references at operand -1 are not operand references and only feed `calls`.
- `raw` null means oversize (`raw` > L-06 bytes: `insns`, `text`, `strings` are empty); `truncated` true means the instruction list was cut at L-06 (keys NULL, flag `truncated`).
- Successors in `blocks` are block starts of the same function; kind is one of `fall|jump|cond|switch|call-return`. `n_insn` must equal the number of instructions whose RVA lies in the block.
- Names are sanitised on ingest (control, bidi and separator characters become `?`; the count is a warning).

### 12.4 Operand typing and located fields (`norm/1`, refines s6)
vkind from positive evidence, first match: `address` (an `rva:` reference, or the ADDRESS flag with an `addr` object inside the image, or a DIR64 base relocation inside the operand's field), `stack` (a `stack:` reference, or a DYNAMIC operand whose first register is RSP/RBP/ESP/EBP), `memory` (other DYNAMIC operand), `scalar` (SCALAR flag), `register` (everything else, including unknown flag mixes: never masked). An address operand whose reference is `ext:` has value = the import key.
Field location, per operand with a mask (`field` = (offset, length) inside the instruction, length 1/2/4/8):
1. non-DYNAMIC: the field is the whole non-zero mask run and every byte of it must be `ff`; DYNAMIC: skip the single leading non-zero mask byte (ModRM.rm or SIB, partial or whole); the remaining non-zero bytes, if any, must be contiguous `ff` bytes and form the field; none left = `absent` (the address comes from a register: nothing to mask, no flag).
2. The field is accepted only if its little-endian value equals an expected encoding (unsigned, modulo 2^(8n)): a scalar object, `target - (insn_rva + len)` (relative), `target - 0` (RVA form) or `image_base + target` (absolute) for the `addr` objects / `rva:` references. The instruction mask must not overlap the operand mask. Anything else is `unlocated`: the operand is NOT masked.
3. `mask-unlocated` is set only when an `address` operand is unlocated (the flag exists to stop COS-ADDR; a stack/memory/scalar operand that is not located merely stays unmasked in L2 and is counted in the manifest warnings). `mask-missing` is set when an instruction mask or an operand mask is `null` (h3 NULL).
4. Located fields are cleared, never whole operand masks: L1 clears `address` fields; L2 additionally clears `scalar`, `stack` and `memory` fields.

### 12.5 Keys and tables (refines s5 and 02 s3)
- Every hash is `blake2b(digest_size=8)` as signed int64 (INT64_MIN remapped to INT64_MIN+1, so NULL is unambiguous in arrays). A function's `h0` hashes the raw bytes; `h1..h3` hash, for each non-NOP instruction, one length byte followed by its masked bytes (L3 = bytes AND instruction mask); `hm` hashes the mnemonics in order, `hms` the sorted multiset, joined by `\n`. NOP family (closed v1 table): mnemonic `NOP` in any encoding, and `INT3` instructions after the last `RET` of the function. Ghidra's ExactInstructions / ExactMnemonics hashers walk every code unit of the body, so `h3` and `hm` are coarser than their classes wherever a function contains a skipped instruction (and `hm` leaves out Ghidra's operand counts); live acceptance L5 states that relation and checks it (A-27).
- `bb.h1` is the L1 hash of the block body WITHOUT its final direct `JMP`/`Jcc` (COS-LAYOUT body key, P17 block votes); `bb.hms` the sorted mnemonic multiset of the non-NOP instructions; `bb.succ` is JSON `[[succ_ord,kind_code]..]` (codes: fall 0, jump 1, cond 2, switch 3, call-return 4).
- `fn.kind` 0 normal / 1 thunk / 2 external; `fn.name_src` 0 DEFAULT, 1 ANALYSIS, 2 IMPORTED, 3 USER_DEFINED, 4 AI; `fn.flags` bits: tiny 1, thunk 2, import 4, oversize 8, truncated 16, pdata-confirmed 32, library 64, mask-missing 128, mask-unlocated 256 (tiny = at most L-10 non-NOP instructions); `fn.aliases` is a JSON array of names; `fn.import_key` NULL unless the function is an import stub; `fn.size` = sum of range lengths; `n_edge` counts duplicate edges; `loops` = back edges whose target dominates the source (Cooper-Harvey-Kennedy dominators); `call.kind` 0 call / 1 jump; `call.callee` = fid of the function whose entry is the target, else NULL; `ref.kind` 0 code / 1 data / 2 import / 3 stack (code = target inside an executable section); `cst.ctx` 0 other, 1 compare (CMP, TEST), 2 mask (AND, OR, XOR, NOT, BT*), 3 shift/rotate, 4 arithmetic (ADD, SUB, ADC, SBB, INC, DEC, NEG, MUL, IMUL, DIV, IDIV), 5 move (MOV*, LEA, PUSH, XCHG). `cst` holds every `scalar` operand value; `str` the extractor's string references; `ref` the references of `address`, `stack` operands (ord = instruction ordinal in the `ins` blob, opi = operand index).
- `mnem` is the sorted vocabulary (`id` = rank of the text). `ins.blob` = zlib of the canonical JSON `ins/1`: an array with one record per instruction (NOP included) `[rva, raw_hex, mnem, flags, flow, [op..]]`, `flags` bits call 1, conditional branch 2, unconditional jump 4, return/terminator 8, computed transfer 16, NOP family 32, and `op = [vkind_code, optype, value, field_off|null, field_len|null, regs]` with vkind codes register 0, scalar 1, memory 2, stack 3, address 4; `value` = register name | signed int | displacement | target RVA | import key | null; `regs` = register names of memory/stack operands. `ins.txt` = zlib of the instruction texts joined by `\n` (UTF-8). Blobs are read through the bounded `ir.reader` decoders only (zlib bomb cap = L-05 string and function caps).
- `content_digest`: for each table in the order mnem, fn, bb, call, str, cst, ref, ins the rows in key order as canonical JSON lines (blob columns replaced by the SHA-256 of the DECOMPRESSED payload), per-table SHA-256, then SHA-256 of the canonical JSON of the table digests; `meta` is excluded. `file_sha256` in the manifest is the SHA-256 of the SQLite file bytes (an integrity check, not an identity).
- `analysis_options_digest` = SHA-256 of canonical JSON (sorted keys, `(',', ':')`) of `{"mode": <mode>, "options": <analysis_options>}`; the script and the runner share one definition and a test pins a value. `symbols`: `primary` in `gzf` mode, `none` in `analyze` mode. Ghidriff without `--program-options` runs plain defaults and, with `--no-symbols` (PatchTrace's default), sets the boolean program analysis option `PDB Universal` to false right before `analyzeAll` [src l.974-981]; the runner therefore sends `analysis_options = {"PDB Universal": "false"}` in `analyze` mode so that both modes analyse identically (T-06); the script sets each option by its declared type like Ghidriff's `set_analysis_option`.

### 12.6 PE tables and EH signature (refines s7)
`ir/pe_tables.read_pe_tables(reader)` returns a frozen `PeTables` (image base, size of image, sections with execute flag, sorted RUNTIME_FUNCTIONs with chained entries merged into their primary function, DIR64 relocation RVAs as an `array`, per-primary `eh` JSON, warnings). Malformed tables never fail the IR: the affected part is absent and a warning (`pdata-unreadable`, `reloc-type-<n>`, `reloc-unreadable`) is kept. `fn.extent_src`: 1 when Ghidra's entry is a primary Begin and the union of its ranges equals the union of the primary and chained entries, 2 when the entry is a primary Begin but the unions differ, else 0.
`eh` JSON (<= 4 KiB, else `{"v":1,"trunc":true}` which S3 must read as `unavailable`): `{"v":1,"ver":n,"fl":n,"prolog":n,"frame":[reg,off],"codes":hex,"handler":rva|null,"hlen":n,"scopes":[[begin_rel,end_rel,filter,target_rel]..]|null}`; scope records are present only when the handler data has the C scope-table shape (`count`, then 16-byte records, total `4 + 16*count`, <= 64 records); begin, end and target are relative to the primary Begin, the filter stays raw (0, 1 or an RVA to map). Functions without a primary entry have `eh` NULL.

### 12.7 Runner, script and seam
- The script copy is verified: the runner reads the packaged resource, writes it into the empty private directory and passes its SHA-256 (the script reports it as `script_sha256`; a different value in the header is an `IR` error `script-mismatch`). `python -B -X utf8 <script> --request <file>`; `--self-check` needs no request.
- Script exit codes as s4; the last stdout line on failure is `{"error": {"reason": slug}}`, the first stdout line is `{"probe": {...}}`. Reason to code: `artifact-hash`, `program-hash` PAIR; `gzf-not-analyzed` EXTRACT; `unsupported-language`, `ghidra-version`, `pyghidra-missing`, `operand-flags`, `unsupported-mode` UNSUPPORTED; exit 5 CANCEL; anything else EXTRACT `crash`.
- `retain_gzf`: `BackendConfig.retain_gzf: bool = False`; the seam is `unified.extract.retain.retain_gzfs(engine_gzfs, target, sources, limit)` (stdlib only, called lazily from `run_comparison` before the scratch directory is removed). Ghidriff names a GZF `<artifact file name>-<sha1[:6] of the artifact>.gzf` [src 4f5d895 l.1411, 997], so the two files are assigned to sides by that exact name; exactly two regular, non-symlink files within L-36 are moved into `quarantine/unified/gzf/` (renamed with the quarantine directory by `publish()`) and `settings['gzf'] = {"older": {"name","sha256","bytes"}, "newer": {...}}` records them. Any deviation (count, names, size, I/O error) retains nothing, adds a warning event and never fails the run (the extractor then uses `analyze` mode, B-01). With the flag off nothing changes (golden settings test). The script still verifies the program SHA-256, so a wrong assignment can only cost an `analyze` fallback.
- Packaging: hook `tools/pyinstaller_hooks/hook-patchtrace.unified.extract.py` adds `ghidra_script.py` as a data file (path taken from the hook's own repository location, see 12.8 item 6); both build scripts require `bindiff-v8-aecc14d/{LICENSE,PROVENANCE.txt}` (BinDiff tag `v8` = commit `aecc14dcc2e0f06a0f8957dc465a9073215b5920`, resolved with `git ls-remote`) and fail unless the packaged script is byte-identical to the source tree's; `tools/frozen_smoke.py` check U1 verifies the same two facts in the onedir and check U2 (`unified --help`, `unified _worker --self-check`) switches on when `src/patchtrace/unified/cli.py` exists (otherwise it prints SKIP).
- Live evidence: `.github/workflows/live-unified.yml` runs `tools/live_unified_check.py` (checks L0-L6, see its docstring) on Windows and Linux; the Linux job analyses the Windows-built DLL bytes so `content_digest` equality across operating systems is a real comparison. The tool prints PASS/FAIL lines and writes `live-unified-<tag>-<os>.json`; it does not use conftest's `record_live_status` (a failed job is the gate).

### 12.8 Refinements made while building S1 (final state)
1. Runner layout: `<private>/script/pt_ir_extract.py` is alone in its directory because the interpreter puts the script's directory first on `sys.path` (so a sibling directory named `ghidra`, the Ghidra project, can never shadow Ghidra's Java package of that name); `request.json`, `out/`, `ghidra/` (the Ghidra project; removed right after a successful run, it can be large) and `ghidra-settings/` are siblings. The interpreter path is made absolute but never resolved (a venv interpreter selects its site-packages by its own location). Argv `python -B -X utf8 <script> --request <file>`; environment from `backend._environment`; no `memory_limit_bytes` for the JVM.
2. Output guard (`run_process(check_output=...)`, polled about every 50 ms): text files in `out/` are capped by L-05, `program.gzf` by L-36, a symlink or a directory in `out/` kills the child (`output-limit`); `progress.json` is read only when a listener exists, only up to L-37 bytes and only with a slug phase and non-negative integers; a raising progress listener never interrupts containment. Failures carry the sanitised stderr tail as the attribute `diagnostics` (plain text for a log; it is never part of the message).
3. Ingest and IR: ORIENTATION (`reversed-side`) uses `ExpectedSide.other_sha256` (the other artifact's hash); structural failures use the plain slugs `no-output`, `no-footer`, `truncated`, `trailing-data`, field failures `bad-record-<field>`; block successors are sorted by (target ordinal, edge kind); PE export placeholders named `Ordinal_<n>` are not aliases.
4. Located fields (12.4 item 1): a DYNAMIC operand whose mask is a run of 4 or 8 whole bytes is a bare displacement (`[GS:0x30]`, `[disp32]` with the SIB fixed by the instruction mask); a partial-only operand mask is `absent` (its value comes from registers).
5. Extents (12.6): `extent_src` 1 requires every Ghidra range to start at the begin of a primary or chained component and to lie inside it, with at most 15 bytes of alignment padding between the end of a component and the end of the range (MinGW `.pdata` ends before the padding). In the MinGW fixture (61 functions, 38 with a primary `.pdata` entry) Ghidra's range list equals the `.pdata` component list for 17 primaries; the other 21 differ only by alignment padding or a one-byte tail, and the padding rule confirms all 38 (`pdata_confirmed` 38).
6. Packaging: the hook adds the script from its own repository path instead of `collect_data_files`, which imports the package in an isolated child process and silently collects nothing when a stale editable install elsewhere shadows the source tree (observed in the build container); an absent script aborts the build. `backend.py` imports `patchtrace.unified.extract.retain` lazily inside `run_comparison`; PyInstaller's analysis follows that import, so the hook fires without a hidden import (verified with a frozen probe on Linux).
7. Live tool: `tools/live_unified_check.py` re-records the committed fixtures (`--record DIR NAME_OLD NAME_NEW`) together with `tests/fixtures/unified/PROVENANCE.json`, so no scratch scripts are needed to refresh them.

### 12.9 S3b: the `decompile` mode as built (2026-10-14)
- Request: `ir-extract-request/1` is unchanged (the S0a `ExtractRequest` already carried the mode). One child per side: `mode = decompile`, `gzf_path` / `gzf_sha256` of the GZF retained by the run that produced the IR (`out/program.gzf` of an `analyze` run, or the GZF Ghidriff left with `retain_gzf`), 1..L-41 `decompile_rvas` (sorted, unique), empty `analysis_options`, `limits` = `l29_pseudo_chars`, `l29_pseudo_lines`, `l41_decompile_fn_s`, `l41_decompile_run_s`. Deviation from 05 s2.8's "ONE extractor session": the frozen request names one side, so a run is two sequential children and pays the JVM start, the GZF import and the decompiler start twice (22.7 s for two pairs on both sides, measured live).
- Script: the hash and language checks of `gzf` mode (artifact, GZF, program SHA-256, `x86:LE:64`, `isAnalyzed`), then `DecompInterface()`, `openProgram(program)` and, for each requested RVA, `getFunctionAt(imageBase + rva)`, `decompileFunction(function, seconds, TaskMonitor.DUMMY)`, `getDecompiledFunction().getC()` (what `FlatDecompilerAPI.decompile` does, no options set), never a function outside the request. `seconds` = the smaller of L-41 per function and what is left of the L-41 run budget; once the budget is spent the remaining RVAs are `timeout` and are not attempted. Status `ok` (with the text), `timeout` (the decompiler's or the budget's), `failed` (no function at the RVA, an external function, a decompiler error or exception, no text or an empty one, a text over L-29). The text is cleaned (CRLF to LF, TAB and LF kept, other controls, bidi controls and lone surrogates become `?`). `out/decomp.jsonl` holds one line `{"side","rva","status","code"}` per RVA in ascending order (`code` is null unless `ok`) and nothing else is written; `progress.json` uses the phase `decompile`. New slug `decompiler-unavailable` (exit 4, `PT-UNIFIED-UNSUPPORTED`): the class is missing or `openProgram` is false; `--self-check` lists a missing decompiler class too, the analysis modes never ask for it.
- Runner: `decompile_side(DecompileJob, budget, emit, runner=)` shares the private layout, the script copy, the environment, the supervision and the classification with `extract_side` (`_spawn`); the process timeout is `l41_decompile_run_s + 120` (JVM start and teardown); `extract/decomp.read_decomp` validates the file before anything uses it (closed keys and statuses, the requested RVAs exactly once each, `code` exactly for `ok`, L-29 on the text and the line, no floats, NaN or duplicate keys, controls replaced): a violation is `PT-UNIFIED-EXTRACT` with the reason `bad-decomp-<field>` or `no-decomp`.
- Facts side (05 s2.8, s7): `FactsContext.build(..., decompiled={"older": {rva: text}, "newer": {rva: text}})` supplies C6 for a pair that has no Ghidriff code on both sides (the text of BOTH sides or neither, never one of each; a text over L-29 is `pseudo-cap`); `facts/refacts.select_for_decompile` picks the rows. The `refacts` worker mode (select, `decompile_side` per side, build the context again with `decompiled=`, judge those rows only, publish) is not part of this slice.
