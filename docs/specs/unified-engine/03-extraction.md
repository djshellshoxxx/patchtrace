# SPEC-31 / 03 Extraction: ProgramIR from Ghidra (GZF reuse first), ingest, PE tables

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
