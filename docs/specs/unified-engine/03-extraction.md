# SPEC-31 / 03 Extraction: ProgramIR from Ghidra (GZF reuse first), ingest, PE tables

Purpose: produce one validated, deterministic `program-ir/1` per artifact ([02 s3](02-data-model.md#3-programir-program-ir1-canonical-written-by-patchtrace-read-only-after-publish)) without bundling Java/Ghidra/pyghidra and without executing the target. Owner slice S1. Numbers: L-xx in 02 s6.

## 1. Producers and modes

| Producer | Mode | When | Cost | Notes |
|---|---|---|---|---|
| Ghidra via external Python + pyghidra | `gzf` | Ghidriff ran fresh with `retain_gzf` (D-05) | open GZF, no auto-analysis [unv] | analysis identical to the primary run: F1 symmetry by construction |
| same | `analyze` | no GZF (raw-cache hit, imported Ghidriff JSON, flag off) | full Ghidra auto-analysis per side (ntoskrnl ~1349 s per side, R03 s3) | analyser options recorded; both sides MUST use the same `analysis_options_digest` |
| BinExport2 import | `binexport` | after C3 (`accept_binexport`, binexport2-support.md s4) merges | parse only | Ghidra exporter: jump refs exported as `call_target`, no LIBRARY type, `FUN_` names omitted, raw bytes only, no operand masks (R02 s2) -> `h1..h3` NULL, tiers limited (06 s3) |
| rizin `aflj/afbj/pdfj` | `rizin` | backup B-02 only, no Ghidra | 0.64 s per 148 functions (R03 s4) | discovery is reachability-bound (77/138 found) -> flag every IR `coverage-partial`; never mixed with a Ghidra IR on the other side |

## 2. Request (`ir-extract-request/1`, written by the runner, read by the script)
```python
class ExtractRequest(_Strict):
    contract: Literal['ir-extract-request/1'] = 'ir-extract-request/1'
    side: Literal['older', 'newer']; artifact_path: str; artifact_sha256: Sha256
    mode: Literal['gzf', 'analyze']; gzf_path: str | None; gzf_sha256: Sha256 | None
    out_dir: str; work_dir: str             # both private, absolute, no dot-prefixed component, < 240 chars on Windows
    max_heap_mb: int = Field(ge=512)        # L-03
    analysis_options: dict[str, str]        # analyze mode only; digest recorded; identical for both sides
    limits: dict[str, int]                  # L-01, L-02, L-05, L-06 (the script stops at the caps and marks `partial`)
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
    request = ExtractRequest(..., mode='gzf' if gzf_for(side) else 'analyze', out_dir=str(work / 'out'),
                             work_dir=str(work / 'ghidra'), max_heap_mb=heap_mb(L03), ...)
    write_json(work / 'request.json', request)
    env = backend._environment(cfg, settings_dir=work / 'ghidra-settings')   # private XDG_CONFIG_HOME, no symbol server state
    argv = [abs(cfg.python_executable), '-B', '-X', 'utf8', str(script), '--request', str(work / 'request.json')]
    res = runner(argv, cwd=work, env=env, cancel=budget.cancel, timeout_seconds=timeout_for(request.mode),   # L-04
                 check_output=progress_and_size_guard(work / 'out', emit, cap=L05), separate_streams=True,
                 log_limit=64 * 1024, stderr_limit=256 * 1024)
    classify(res)                                                  # cancelled / timeout / output-limit / exit != 0 -> 01 s6 codes
    out = work / 'out' / 'ir.jsonl'
    require(out.is_file() and not out.is_symlink(), 'PT-UNIFIED-EXTRACT', reason='no-output')
    return ExtractOutput(jsonl=out, stderr_tail=sanitize(res.stderr_tail), provenance=probe_versions(res))
```
- `progress_and_size_guard` returns `'output-limit'` when `out/` exceeds L-05 or contains a symlink/directory, and forwards `progress.json` (`{phase, done, total}`, <= L-37) as `StageEvent`s; it never raises (a bad progress file is ignored).
- The script resource is located with `importlib.resources.files('patchtrace.unified.extract') / 'ghidra_script.py'`; both build scripts collect it as a DATA file (PyInstaller stores `.py` modules as bytecode in the PYZ, where the external interpreter cannot read them). Frozen smoke asserts it exists (plan, packaging).
- No `-I` flag: user-site installs of ghidriff/pyghidra must keep working exactly as for the primary run (backend.py runs `python -m ghidriff` without `-I`); `PYTHONPATH`/`PYTHONHOME` are already removed by `_environment`.
- Version probe: the script prints one JSON line `{"probe": {...}}` to stdout first; versions `unknown` are allowed but make the IR cache-ineligible (02 s5).

## 4. Script behaviour (`extract/ghidra_script.py`; runs in the external interpreter; normative)
Rules: imports only stdlib, `pyghidra` and Ghidra Java classes; never imports `patchtrace` or `ghidriff`; computes no hashes beyond SHA-256 of the input file and string values; writes only below `out_dir`/`work_dir`; no network; deterministic iteration (`getFunctions(True)` = ascending entry).
```text
main(request):
  probe -> print {"probe": {ghidra, pyghidra, java, python, script_sha256}}
  verify sha256(artifact_path) == request.artifact_sha256 else exit 3 'artifact-hash'
  start pyghidra with ['-Xmx%dm' % max_heap_mb]                       # [unv] exact launcher API on pyghidra 3.x
  project = temporary GhidraProject in work_dir                        # never the analyst's projects
  program = import GZF (mode gzf) | import binary + analyse with analysis_options (mode analyze)   # [unv] GZF import path
  verify program.getExecutableSHA256() == artifact_sha256 else exit 3 'program-hash'
  verify language startswith 'x86:LE:64' else exit 4 'unsupported-language'
  emit header (image_base, size_of_image, language, compiler, producer)
  for f in functionManager.getFunctions(True):                        # externals listed with kind 'external'
      if monitor/cancel or caps reached: footer status 'partial'; break
      rec = {rva: f.entry - image_base, ranges: body ranges, name, name_src: symbol.getSource(), aliases: symbols at entry, lib: FID match,
             kind, thunk_target, import, raw (<= L-06), blocks (BasicBlockModel), insns (getPrototype().getInstructionMask(),
             per-operand value masks, OperandType flags, scalars, references), calls, strings (defined string data
             referenced from the body: SHA-256 of UTF-8 value, length, 64-char prefix), text (str(instruction))}
      optional parity fields: Ghidra ExactBytes / ExactInstructions hasher values for f (oracle for 08 s4)
      write one JSON line; every 500 functions write progress.json (.part then replace)
  emit footer {functions, instructions, status, warnings}; close project; exit 0
```
Exit codes: 0 ok, 2 bad request, 3 input mismatch, 4 unsupported, 5 cancelled by signal, other = crash. API names marked [unv] must be confirmed on Ghidra 12.0.4 / pyghidra 3.0.2 by the first live run (reviewer item W6); the script carries a `--self-check` mode that imports the classes it needs and prints which are missing.

## 5. Ingest (`ir/ingest.py`, runs in the worker child; pure + file output)
```python
def ingest(jsonl: Path, expect: ExpectedSide, limits: UnifiedLimits, budget: Budget) -> IrBuildResult:
    tables = Tables()                                       # in-memory rows, then one SQLite write transaction
    with open_bounded(jsonl, max_bytes=limits.l05_total) as lines:
        header = parse_header(next(lines))                  # pydantic strict; hashes == expect.artifact_sha256 (PAIR / ORIENTATION)
        pe = expect.pe_tables                               # from ir/pe_tables.py: pdata entries, reloc set, image_base
        require(header.image_base == pe.image_base, 'PT-UNIFIED-IR', reason='image-base-mismatch')
        prev = -1
        for line in lines:                                  # streaming; each line <= L-05 per-line cap
            budget.tick()
            rec = validate_fn(line, limits)                 # hand-written: types, ranges in image, order, caps, utf-8
            if rec is FOOTER: footer = rec; break
            require(rec.rva > prev, reason='fn-order'); prev = rec.rva
            masks = operand_masks(rec, pe)                  # L1/L2/L3 per instruction (s6)
            tables.add_fn(rec, keys=features.compute(rec, masks), extent=pdata_check(rec, pe))
        require(footer and footer.counts == tables.counts, reason='footer-mismatch')
    tables.resolve_calls()                                  # target rva -> fid or import key; unresolved -> NULL
    tables.md_index()                                       # ir/mdindex.py (04 s2)
    digest = tables.content_digest()                        # canonical JSON in primary-key order
    write_sqlite(tables, tmp_file); manifest = build_manifest(...); return IrBuildResult(tmp_dir, manifest)
```
Determinism: rows sorted by `rva`; `fid` = rank; mnemonic ids assigned by sorted mnemonic text (not first appearance) so ids are stable across sides; JSON parsed with duplicate-key and constant rejection (`persistence.strict_json` rules).

## 6. Operand masks and normalisation (`norm/1`)
```python
def operand_masks(rec, pe):
    for ins in rec.insns:
        raw, imask = ins.raw_bytes, ins.imask_bytes
        l1 = raw; l2 = raw
        for op in ins.ops:
            addr = op.vkind == 'address' or op.is_relative or (op.vkind == 'scalar' and pe.in_image(op.value)) \
                   or pe.reloc_covers(ins.rva, ins.len)          # base relocation inside this instruction
            if addr: l1 = clear(l1, op.mask)                     # address-bearing bits only
            if addr or op.vkind == 'scalar' or op.is_displacement: l2 = clear(l2, op.mask)
        l3 = and_bytes(raw, imask)                               # SLEIGH instruction mask (all operand fields)
        skip = ins.mnem in NOP_FAMILY                            # closed table v1: NOP, multi-byte NOP forms; int3 after the last ret
        yield (l1, l2, l3, skip)
```
Rules: an operand counts as address-bearing only on positive evidence (Ghidra address type, relative flag, image-range value, relocation); over-masking would hide immediate edits (R05 F2 risk). Register fields stay in L1/L2 (register renaming is detected by C2, not hidden). `mov edi, edi`, `xor r,r` vs `mov r,0` and other idioms are NOT normalised in v1 (measure first, R04 s5).

## 7. PE tables (`ir/pe_tables.py`, stdlib, bounded, via `VerifiedArtifactReader`)
- Exception directory (index 3): RUNTIME_FUNCTION = 3 x uint32 (BeginAddress, EndAddress, UnwindInfoAddress), sorted, <= `size/12` entries, each inside a section; UNWIND_INFO flag `UNW_FLAG_CHAININFO` links chained entries to their primary function (chunks). Function extent is `pdata-confirmed` when Ghidra's entry equals a primary BeginAddress and the union of its ranges equals the chained entries' union; leaf functions have no entry (stay `extent_src=0`).
- Base relocations (index 5): blocks of (page RVA, size, uint16 entries); only type 10 (DIR64) and 0 (padding) accepted, others recorded as warnings; result = sorted RVA list for `reloc_covers`.
- Caps: 1,000,000 RUNTIME_FUNCTIONs, 4,000,000 relocations; violations -> `LIMIT` with reason; malformed tables -> IR still built, `extent_src=0`, warning `pdata-unreadable` (never fatal).
- Dynamic value relocations, RTTI and XFG hashes (R04 s6) are NOT parsed in v1 (backup B-11).

## 8. Backend seam for GZF retention (S1, `backend.py`, additive)
```python
@dataclass(frozen=True)
class BackendConfig: ...; retain_gzf: bool = False               # new, default False; not part of the raw-cache fingerprint (argv unchanged)
# in run_comparison, inside `finally`, BEFORE _remove_scratch(scratch_root) (backend.py:549):
if config.retain_gzf and result_ok:
    files = sorted(engine_gzfs.glob('*.gzf'))
    if len(files) == 2 and all(regular(f) and not f.is_symlink() for f in files) and total_size(files) <= L36:
        target = quarantine / 'unified' / 'gzf'; target.mkdir(parents=True)
        for f in files: move_and_hash(f, target)                  # names kept; sha256 recorded in run settings['gzf']
```
Mapping a GZF to a side: by the Ghidra-recorded executable SHA-256 inside the program (checked by the script), never by file name. GZFs are deleted after both IRs are published (provenance keeps their SHA-256). Raw-cache hits produce no GZF -> `analyze` mode.

## 9. Failure modes (reason slugs; code in 01 s6)

| Reason | Code | Cause | Effect |
|---|---|---|---|
| `no-backend`, `pyghidra-missing`, `ghidra-version` | UNSUPPORTED | no configured Python/Ghidra; script `--self-check` failed | S0 mode (B-00), row flag `ir-missing` |
| `artifact-hash`, `program-hash` | PAIR | wrong file or GZF for this side | refuse; nothing stored |
| `unsupported-language` | UNSUPPORTED | not x86-64 PE | S0 mode |
| `no-output`, `no-footer`, `footer-mismatch`, `fn-order`, `bad-record:<field>` | IR | crash, truncation, malformed line | refuse IR; previous IR (if any) unaffected |
| `output-limit`, `functions-cap`, `instructions-cap`, `ir-too-large` | LIMIT | L-01/L-02/L-05/L-07 | IR refused, or `partial` with flags when only per-function caps hit |
| `timeout`, `cancelled` | TIMEOUT / CANCEL | L-04 or user | tree killed, private dir removed |
| `image-base-mismatch`, `pdata-unreadable` | IR / warning | loader rebased, hostile tables | refuse / continue without pdata |

## 10. Tests (red/green, named; fakes = `tests/fake_exe.py` interpreters running a fake script)
- `test_runner_builds_argv_without_shell_and_absolute_python`; `test_runner_copies_script_into_empty_private_dir`; `test_runner_env_has_private_settings_dir_and_no_pythonpath`.
- `test_progress_file_drives_stage_events_and_bad_file_is_ignored`; `test_output_guard_kills_on_size_cap_and_symlink`.
- `test_cancel_and_timeout_kill_tree_and_remove_private_dir` (heartbeat grandchild, as SPEC-28 s10).
- `test_ingest_rejects`: unknown key, NaN, duplicate key, out-of-order rva, missing footer, footer count mismatch, ranges outside image, wrong artifact hash, reversed side, oversize line (one case each, parametrised with short ids: Windows console stall rule, docs/qa.md).
- `test_ingest_is_deterministic_under_record_permutation_of_equal_keys` and `test_content_digest_independent_of_sqlite_file_bytes`.
- `test_l1_masks_only_positive_address_evidence`; `test_l2_masks_immediates_keeps_registers`; `test_l3_equals_sleigh_mask`; `test_nop_family_skipped`.
- `test_pdata_chained_entries_merge_chunks`; `test_reloc_dir64_only_others_warn`; hostile tables from `tests/pe_builder.py` (overlap, out-of-section, huge counts).
- `test_retain_gzf_moves_two_files_and_records_hashes`; `test_retain_gzf_off_is_byte_identical_to_today` (golden run settings); `test_raw_cache_hit_has_no_gzf_and_falls_back_to_analyze`.
- `test_ghidra_script_imports_no_patchtrace` (AST); `test_script_self_check_lists_missing_classes` (fake pyghidra module).
- Live (not mocked, recorded separately in docs/qa.md): `live-unified-extract` workflow on the CI fixture DLL pair (`tests/fixtures/old.c`/`new.c`) with Ghidra 12.0.4 on Windows and Linux; asserts header hashes, counts > 0, determinism of `content_digest` across two runs and across OSes.

## 11. Security and Windows notes
Target never executed (Ghidra static load only); no symbol server (private settings dir, `--no-symbols` policy recorded); script and request files live in a fresh private dir; output treated as hostile (caps, strict parse, plain-text display of names and instruction text). Windows: paths < 240 characters and no dot-prefixed components (Ghidra rejects them, backend precedent); antivirus may lock `ir.sqlite3` during `os.replace` -> bounded retry (5 x 200 ms) then `STORE` with the path redacted; the JVM child is inside the Job Object (killed with the tree); two extractions never run concurrently by default (JVM memory, and the spawn-handle race fixed by P1).
