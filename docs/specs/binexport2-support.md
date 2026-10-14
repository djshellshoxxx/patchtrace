# SPEC-10b: BinExport2 support (Phase C, step C3)

Status: implementation-ready draft, 2026-10-14. Extends SPEC-10 (`bindiff-adapter.md` §2) and plan item C3 in `../plans/phase-c-multi-engine-plan.md`. Owner of files: `secondary/binexport*.py`, `pyproject.toml` dependency line, `tools/build_*.py` notice lists, `third_party/notices/binexport-*`, one CI workflow step. Contract-visible changes: `SecondaryError.reason` (additive), SPEC-10 §2 size cap 512 -> 256 MiB default (see §5).

Goal: take a user-supplied `.BinExport` for one project artifact, prove it is a genuine, well-formed, bounded BinExport2 message that belongs to that artifact and orientation, and hand BinDiff (C4) a private immutable snapshot. Never execute targets, never upload, never trust field values from the file.

## 1. Verified facts (checked 2026-10-14; labels: [src] read upstream/installed source, [run] measured here, [inf] inference)

| Fact | Evidence |
|---|---|
| `binexport2.proto` at google/binexport main is byte-identical to the SPEC-10 pin `2bff7af27af206354b2a90a9de566dc6bbae3e1b`; sha256 `e8e4943de00b37038b614bbd0515cb188caf3e4a2e20c6566544e791f93647d8`, 16058 bytes, proto2, **no `package`**, top-level message `BinExport2`, `extensions 100000000 to max`, `md_index = 93992622` | [src] raw.githubusercontent, `sha256sum` both URLs |
| Repo license Apache-2.0; the .proto carries its own Apache header ("Copyright 2011-2025 Google LLC"); there is **no NOTICE file** (HTTP 404) | [src] |
| Exporter id fields: Ghidra = `program.getExecutableSHA256()`; IDA = `GetInputFileSha256().value_or(GetInputFileMd5().value_or(""))` (so IDA may write MD5 (32 hex) or `""`); Ghidra `executable_name = basename(getExecutablePath())`, `architecture_name = "<processor>-<addrsize>"` from language id (e.g. `x86-64`, `x86-32`, `AARCH64-64`); `timestamp = now` | [src] `BinExport2Builder.java` L151-166, `ida/main_plugin.cc` L133 |
| Ghidra addresses are `offset - addressOffset` (addressOffset = image base only when "Subtract Imagebase" chosen); not recorded in the file | [src] `getMappedAddress` |
| README main: IDA 9.4+ only (8.x dropped); Ghidra extension zip from Releases; latest tagged release is still `v12-20240417-ghidra_11.0.3` per research doc (GitHub API not reachable from this session, re-check) | [src]/[inf] |
| `protobuf` on PyPI latest 7.36.2 (2026-09-17), license "3-Clause BSD", `Requires-Python >=3.10`, **no dependencies**. Wheels: `cp310-abi3` win_amd64 456,514 B, manylinux2014_x86_64 343,223 B, `py3-none-any` 179,806 B (pure Python), sdist 512,737 B. Installed footprint 1.8 MB (win), contains `google/_upb/_message.pyd` 745 KB | [run] `pypi.org/pypi/protobuf/json`, wheel unzip |
| Generated code embeds `ValidateProtobufRuntimeVersion(PUBLIC, major, minor, patch)`; in 7.36.2 the check rejects only gencode **newer** than the runtime (and domain mismatch); documented cross-version guarantee is one major back | [run] read `runtime_version.py`; [src] protobuf.dev guarantee page (cited by the code) |
| Python runtime selection: `api_implementation.Type()` is `upb` (C ext) or `python` (pure fallback, also forced by env `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python`) | [run] |
| **Cost of pure-Python vs upb on a 13.97 MB synthetic file (2 M tiny records), fresh process**: upb parse 0.13 s, +152 MB RSS (11x); pure Python parse 16.5 s, +1194 MB RSS (85x). Pure Python is a DoS vector | [run] |
| Python walk of top-level tags only (no object creation): 2 M records in 0.57 s (~3.5 M rec/s) | [run] |
| upb rejects nested unknown groups: depth 50 OK, depth 200 `DecodeError` (recursion limit ~100) | [run] |
| A **private** `DescriptorPool` + `message_factory.GetMessageClass` built from a 4,144-byte `FileDescriptorSet` (`protoc --descriptor_set_out`) works under upb with identical speed/RSS; no gencode file needed | [run] |
| PyInstaller 6.22.3 froze a program importing `google.protobuf` with **no custom hook**: collected `google/_upb/_message.abi3.so` (396 KB on Linux); frozen run printed `upb`. `pyinstaller-hooks-contrib 2026.8` has no `google.protobuf` hook (only cloud/api_core ones) | [run] Linux only; Windows frozen run is an acceptance item (§9) |
| Existing code: `check_message` runs structural checks over duck-typed objects (tests use `SimpleNamespace`); `validate_binexport` returns `unsupported` without bindings; `MAX_SIZE` 512 MiB; `jobs.run_process` Windows Job Object sets only `KILL_ON_JOB_CLOSE` (no memory limit) | [src] repo |

Gaps in current `check_message` that this spec closes: vertex sort allows duplicates; effective defaults (`mnemonic_index` default 0 with an empty mnemonic table, `Reference.instruction_operand_index/operand_expression_index` default 0) unchecked; reference operand/expression sub-indexes unchecked; `address_comment` unchecked; expression parent cycles/depth unchecked; range-overlap and block/flow-graph amplification unchecked; flow-graph edge endpoints not required to belong to the graph; no wire-level pre-scan; whole file read twice into memory in-process; no memory/time bound; no TOCTOU-safe snapshot.

## 2. Decision record DR-C3-1: protobuf runtime + checked-in descriptor set (firm)

Options:

| | A. Vendor pure-Python protobuf runtime | B. Dependency `protobuf` + checked-in **gencode** `_binexport2_pb2.py` | **C. Dependency `protobuf` (pinned) + checked-in descriptor set, classes built at runtime from a private pool (recommended)** | D. Hand-written wire decoder, no protobuf |
|---|---|---|---|---|
| Added size to frozen app | ~1 MB source, but forced pure Python | ~+1 MB (`_message` 0.4-0.75 MB + py modules) | same as B, minus ~10 KB gencode | ~0 |
| Parse cost 14 MB file | 16 s / 1.2 GB (measured) - **rejected, DoS** | 0.13 s / 152 MB | same as B (measured) | est. 10-30x slower than upb, unmeasured |
| Licenses | BSD-3 (runtime) + Apache-2.0 (proto) | same | same (descriptor is an Apache-2.0 derivative of the .proto) | Apache-2.0 only |
| Gencode/runtime coupling | none | **header pins protoc version; runtime must be >= gencode; regeneration on each bump** | **none** (descriptor format is stable across protoc versions) | none |
| PyInstaller | needs vendored path hacks | works without hook (measured); gencode is a normal module | same; descriptor embedded as a Python bytes literal (no data-file collection) | trivial |
| Hostile-input surface | Python (safe, slow) | upb C parser (heavily fuzzed upstream) | same | **our own decoder = new unfuzzed attack surface** |
| Supply chain | copy rots | one new PyPI dep, zero transitive deps, abi3 wheel | same | none |

Decision: **C**. Add `protobuf==7.36.2` (exact pin, like PySide6/pydantic) to `[project].dependencies`; install with `--only-binary=:all:` in CI and the build scripts so an sdist can never compile on a runner; record the wheel SHA-256 for win_amd64 and manylinux x86_64 in `docs/qa.md` and `third_party/notices/protobuf-7.36.2/MANIFEST.txt`. Re-pin only by a dedicated PR that re-runs the §9 gates. If PR-1 shows the private-pool path fails frozen on Windows, fall back to B (generate with a protoc whose version header is <= the pinned runtime and the same major; the §9 gencode check applies) - do not fall back to A or D.
Rejected alternative detail: D remains the contingency only if the `protobuf` wheel becomes unobtainable offline; a streaming validator is feasible because §6.2 already walks the wire format.

Consequences and rules:
1. `binexport_proto.py` must assert `api_implementation.Type() == 'upb'` after import; otherwise `unsupported(reason=protobuf_not_upb)`. **This assertion is the only real guard**: if `google._upb` fails to import, protobuf only warns and falls back to pure Python even when `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=upb` is set. The worker environment still sets that variable (an explicit `python` value from the user's environment must not leak in) and drops `TEMPORARILY_DISABLE_PROTOBUF_VERSION_CHECK`, but neither is relied on.
2. The private pool avoids a name clash with any other library registering a top-level `BinExport2` in the default pool (the proto has no package).
3. The descriptor set is generated once from the pinned .proto by `tools/gen_binexport_descriptor.py` (uses `grpcio-tools` or a local `protoc`, **not** a runtime/dev dependency) and written to `src/patchtrace/secondary/binexport_descriptor.py` as `DESCRIPTOR_SET_B64`, `PROTO_SHA256 = 'e8e4943d...'`, `PROTO_COMMIT = '2bff7af...'`. A unit test decodes it and asserts a **golden field table** `{(path, number): (name, label, type)}` for all 17 listed tables plus 93992622, so a silent descriptor change fails CI.
4. Third-party notices (Apache-2.0 §4): `third_party/notices/binexport-2bff7af/{LICENSE,binexport2.proto,PROVENANCE.txt}` (LICENSE text copied from the repo, proto copied unmodified with its header, provenance = URL + commit + sha256 + tool versions used). `third_party/notices/protobuf-7.36.2/LICENSE` (BSD-3 text from the wheel `dist-info/LICENSE`). `build_windows.py`/`build_linux.py` add `'protobuf'` to their distribution lists (already copy `LICENSE*` from `dist.files`) and their `required` notice list gets both new directories; the build refuses to publish if missing.

## 3. Module layout (all under `src/patchtrace/secondary/`; every module pure, no Qt, no network)

| Module | Responsibility | Depends on |
|---|---|---|
| `binexport_limits.py` | `BinExportLimits` frozen dataclass with defaults (§5), `Budget` (deadline + cancel + tick counter), `LimitExceeded` helper | stdlib |
| `binexport_descriptor.py` | generated constants only (§2.3); no logic | none |
| `binexport_proto.py` | `load_binexport2_class() -> type | None`, runtime assertions (upb, version >= pin), memoised; `ProtoUnavailable(reason)` | `binexport_descriptor`, `google.protobuf` (lazy import) |
| `binexport_prescan.py` | wire-level top-level scan **without protobuf**: field counts, byte totals, wire types, record-size and unknown-field caps; returns `WireStats` | `binexport_limits` |
| `binexport_check.py` | structural validator over a parsed message (duck-typed, Protocol-based so unit tests keep `SimpleNamespace`): `check_message(msg, limits, budget) -> CheckReport` | `binexport_limits` |
| `binexport_identity.py` | `executable_id` classification, pair/orientation, address-basis detection, arch hint | `contracts.check_pair` |
| `binexport_snapshot.py` | open-once, regular-file, bounded copy into private dir while hashing; `Snapshot` | stdlib |
| `binexport_pipeline.py` | `inspect_binexport(...)` = snapshot -> prescan -> parse -> check -> identity (the only function the worker and in-process tests call) | all above |
| `binexport_models.py` (added in the build) | strict pydantic `BinExportSummary`, `WorkerRequest`, `WorkerResult` crossing the worker boundary | `contracts` |
| `binexport_worker.py` | subprocess `main(argv)`; reads `WorkerRequest` JSON, writes `WorkerResult` JSON to a private file; maps exceptions to exit codes | `binexport_pipeline` |
| `binexport_run.py` | parent side: build argv/env, memory cap, `jobs.run_process`, parse result file strictly, map to `SecondaryError`; `accept_binexport(...)` public entry | `jobs`, `contracts` |
| `binexport_producer.py` | `BinExportProducer` Protocol + `UserSuppliedProducer` (v1 only implementation) | `binexport_run` |
| `binexport.py` (existing) | **thin compatibility facade**: re-exports `BinExportResult`, `check_message`, `check_executable`, `check_pair_exports`, `unmatched_addresses`, `validate_binexport`; `MAX_SIZE` retained as alias of `BinExportLimits().max_file_bytes` | the above |
| (later, Phase E) `binexport_ghidra.py` | `GhidraHeadlessProducer`; not part of C3 PRs | `binexport_producer` |

CLI/GUI wiring (not in C3): hidden subcommand `patchtrace secondary _binexport-worker --request <file> --result <file>` (frozen exe dispatches through the existing `__main__` CLI path; `python -m` is unusable frozen). User-facing: `patchtrace secondary binexport-check --artifact-sha256 H --role older|newer FILE`.

## 4. Typed interfaces

```python
# binexport_limits.py
@dataclass(frozen=True, slots=True)
class BinExportLimits:             # defaults in §5
    max_file_bytes: int; max_record_bytes: int; max_unknown_bytes: int
    max_counts: Mapping[str, int]  # per table name
    max_string_bytes: int; max_string_total: int
    max_expr_depth: int; max_operands_per_instr: int; max_exprs_per_operand: int
    max_ranges_per_block: int; coverage_factor: int   # sum(range len) <= factor*instr + slack
    wall_seconds: float; memory_bytes: int

class Budget:                      # cancellation + deadline; cheap
    def __init__(self, deadline: float | None, cancel: threading.Event | None): ...
    def tick(self, n: int = 1) -> None   # every 8192 units: raises Cancelled / DeadlineExceeded

# binexport_prescan.py
@dataclass(frozen=True, slots=True)
class WireStats:
    counts: Mapping[int, int]      # field number -> top-level record count
    bytes_by_field: Mapping[int, int]
    unknown_bytes: int; total_bytes: int

# binexport_check.py
class Sized(Protocol): ...         # len(), __getitem__, __iter__
@dataclass(frozen=True, slots=True)
class CheckReport:
    vertex_addresses: tuple[int, ...]       # sorted, strictly increasing, <= cap
    counts: Mapping[str, int]
    warnings: tuple[str, ...]               # tier-2 findings, never reject (§6.5)

# binexport_identity.py
IdBinding = Literal['sha256', 'md5', 'empty', 'other']
AddressBasis = Literal['va', 'rva', 'unknown']

# public result (strict pydantic, crosses the worker boundary as JSON, schema-version tagged)
class BinExportSummary(_Strict):
    contract: Literal['binexport-summary/1'] = 'binexport-summary/1'
    file_sha256: Sha256            # of the private snapshot (provenance, used by C4 cache key)
    file_size: int
    executable_id: str; executable_name: str; architecture_name: str
    timestamp: int | None
    id_binding: IdBinding; role: Literal['older', 'newer']
    address_basis: AddressBasis
    counts: dict[str, int]
    function_addresses: tuple[Address, ...]   # ALL call-graph vertices, strictly increasing
    vertex_types: tuple[int, ...]             # parallel to function_addresses (enum 0..4: NORMAL, LIBRARY, IMPORTED, THUNK, INVALID)
    warnings: tuple[str, ...]
    protobuf_version: str; descriptor_proto_sha256: str
# names/strings are deliberately NOT in the summary (untrusted display text; add only with an escaping spec)

@dataclass(frozen=True, slots=True)
class AcceptedBinExport:
    snapshot_path: Path            # read-only copy in the case's private dir; C4 must use THIS path
    summary: BinExportSummary

class BinExportProducer(Protocol):
    name: str
    def produce(self, artifact: Path, out_dir: Path, *, cancel: threading.Event) -> Path: ...   # returns an UNTRUSTED file

def accept_binexport(path: Path, *, artifact_sha256: str, role: Literal['older','newer'],
                     private_dir: Path, limits: BinExportLimits = BinExportLimits(),
                     cancel: threading.Event, pe_layout: PeLayout | None = None,
                     accept_unbound: bool = False) -> AcceptedBinExport: ...   # raises SecondaryError
def accept_pair(older: AcceptedBinExport, newer: AcceptedBinExport, older_sha256: str, newer_sha256: str) -> None  # check_pair + identical/ same-file guards
```

`contracts.py`: `SecondaryError.__init__(self, code, message, *, reason: str | None = None)`; `reason` is a slug from §7. No new `ErrorCode` values. `PeLayout` = `(image_base: int, size_of_image: int)` taken from the existing PE overview.

## 5. Resource caps (defaults; all overridable only through `BinExportLimits`, never by file content)

| Cap | Default | Rationale |
|---|---|---|
| `max_file_bytes` | **256 MiB** (SPEC-10 said 512; measured 11x RSS amplification makes 512 MiB a ~6 GB parse) | change requires live evidence (§12 U1) |
| `max_record_bytes` (one top-level record) | 32 MiB | blocks one giant `string_table`/`comment` entry |
| `max_unknown_bytes` (sum of unknown top-level fields) | 64 KiB | forward-compat tolerance without a hiding place |
| counts: `expression` 40 M, `operand` 30 M, `mnemonic` 65 536, `instruction` 40 M, `basic_block` 10 M, `flow_graph` 1 M, `vertex` 2 M, `call_edge` 20 M, `flow_edge` (sum) 40 M, `string_table` 4 M, `comment` 4 M, `string_reference`/`expression_substitution`/`address_comment` 4 M each, `data_reference` 20 M, `section` 4096, `library` 4096, `module` 4096, `md_index` <= vertices | | each also bounded implicitly by `max_file_bytes` (>= 2 bytes/record) |
| `max_string_bytes` per string / `max_string_total` | 64 KiB / 128 MiB | names + comments |
| `max_expr_depth` | 64 | x86 operand trees are < 16 deep |
| `max_operands_per_instr` / `max_exprs_per_operand` | 16 / 64 | x86 <= 4; EVEX 4 |
| `max_ranges_per_block` | 4096 | |
| `coverage_factor` | 4 (+ slack 1 024) | `sum(range len) <= 4*instructions+1024`; `sum(len(flow_graph.basic_block_index)) <= 4*basic_blocks + vertices` |
| `wall_seconds` | 600 (worker) | prescan ~3.5 M rec/s; checker est. 3-6 M items/s per pass x ~12 passes (§12 U2) |
| `memory_bytes` | `clamp(14 * file_size + 256 MiB, 512 MiB, 6 GiB)` | measured 11x + slack; above 6 GiB -> `PT-SECONDARY-LIMIT` before spawn |
| `max_summary_bytes` (worker result file) | 64 MiB | 2 M vertices x ~(20+3) B JSON |

All numbers other than the three measured ones are initial guesses to be tuned against real fixtures (§12).

## 6. Pseudocode (normative; Python-like, all loops iterative, every loop calls `budget.tick`)

### 6.1 Parent entry `accept_binexport` (binexport_run.py)

```
def accept_binexport(path, *, artifact_sha256, role, private_dir, limits, cancel, pe_layout, accept_unbound):
    require re.fullmatch('[0-9a-f]{64}', artifact_sha256)
    if cancel.is_set(): raise Err(CANCEL, 'cancelled', reason='cancelled')
    if limits.memory_bytes_required(file_size_hint) > HARD_MEMORY_MAX: raise Err(LIMIT, reason='memory_cap')
    mod = load_binexport2_class()                 # parent probes only to give a quick UNSUPPORTED;
    if mod is None: raise Err(UNSUPPORTED, reason=ProtoUnavailable.reason)   # worker re-checks (its own interpreter)
    work = private_dir / f'binexport-{uuid4().hex}'; work.mkdir(mode=0o700)
    req = WorkerRequest(src=str(path), snapshot=str(work/'in.BinExport'), result=str(work/'out.json'),
                        artifact_sha256, role, limits=asdict(limits), pe_layout, accept_unbound)
    write_json(work/'req.json', req)
    argv = worker_argv() + ['secondary', '_binexport-worker', '--request', work/'req.json']   # frozen-aware
    env = minimal_env(); env['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'upb'; env['PYTHONUTF8'] = '1'
    res = run_process(argv, cwd=work, env=env, cancel=cancel, timeout_seconds=limits.wall_seconds + 30,
                      memory_limit_bytes=limits.memory_bytes,            # NEW kw in jobs.py (§11 PR-6)
                      log_limit=64 KiB, stderr_limit=64 KiB, separate_streams=True)
    if cancel.is_set() or res.returncode == -1 and res.log_tail == 'cancelled': cleanup(work); raise Err(CANCEL)
    if res.timed_out: cleanup(work); raise Err(RUN, reason='worker_timeout')
    out = work/'out.json'
    if not out.is_file() or out.stat().st_size > limits.max_summary_bytes:
        cleanup(work); raise Err(RUN, reason='worker_crash' if res.returncode not in OOM_CODES else 'worker_oom',
                                 message=tail(res.stderr_tail))
    doc = strict_json_load(out)                  # project-wide strict JSON (no NaN/dup keys)
    kind = doc['kind']                           # 'ok' | 'error'
    if kind == 'error': cleanup(work, keep_nothing); raise Err(doc['code'], doc['message'], reason=doc['reason'])
    summary = BinExportSummary.model_validate(doc['summary'])      # strict pydantic; extra=forbid
    assert summary.file_sha256 == sha256_file(work/'in.BinExport')  # parent re-hash: worker is not trusted blindly
    assert summary.role == role
    os.chmod(snapshot, 0o400) ; return AcceptedBinExport(snapshot, summary)
```

### 6.2 Worker pipeline `inspect_binexport` (binexport_pipeline.py; runs in the child)

```
def inspect_binexport(req, budget):
    snap = take_snapshot(req.src, req.snapshot, limits)            # §6.3
    data = snap.path.read_bytes()                                  # <= max_file_bytes by construction
    sniff_lookalike(data[:16])                                     # reason lookalike_* (advisory text only)
    stats = prescan(memoryview(data), limits, budget)              # §6.4  (BEFORE any protobuf object exists)
    cls = load_binexport2_class() or raise Err(UNSUPPORTED, reason=...)
    msg = cls()
    try: consumed = msg.ParseFromString(data)                      # C call: NOT interruptible; bounded by caps+process kill
    except Exception: raise Err(INPUT, 'not a parseable BinExport2 message', reason='parse_failed')
    if consumed != len(data): raise Err(INPUT, reason='trailing_bytes')
    del data                                                       # free 1x before the long Python passes
    report = check_message(msg, limits, budget)                    # §6.5
    ident = classify_identity(msg.meta_information, req.artifact_sha256, req.accept_unbound)   # §6.6
    basis = detect_address_basis(report.vertex_addresses, req.pe_layout)
    return BinExportSummary(...)
```

### 6.3 Snapshot (TOCTOU-safe, bounded)

```
def take_snapshot(src, dst, limits):
    flags = O_RDONLY | O_BINARY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(src, flags)                                      # OSError -> INPUT reason=unreadable (no errno text beyond strerror)
    with os.fdopen(fd, 'rb', buffering=0) as f:
        st = os.fstat(f.fileno())                                 # fstat the OPEN handle, not the path
        if not stat.S_ISREG(st.st_mode): raise Err(INPUT, reason='not_regular_file')
        if st.st_size == 0: raise Err(INPUT, reason='empty_file')
        if st.st_size > limits.max_file_bytes: raise Err(LIMIT, reason='too_large')
        h = sha256(); total = 0
        with open(dst, 'xb') as out:                              # 'x': never overwrite; dst is in a fresh 0700 dir
            while chunk := f.read(4 MiB):
                total += len(chunk)
                if total > limits.max_file_bytes: raise Err(LIMIT, reason='too_large')   # file grew while reading
                h.update(chunk); out.write(chunk); budget.tick(1)
        if total != st.st_size: raise Err(INPUT, reason='file_changed_during_read')
    return Snapshot(dst, h.hexdigest(), total)
```
The snapshot hash is the provenance identity; C4 runs BinDiff on the snapshot only, so what was validated is what is diffed.

### 6.4 Wire pre-scan (pure Python, no protobuf; first line of defence)

```
KNOWN = {1:'meta_information', 2:'expression', 3:'operand', 4:'mnemonic', 5:'instruction', 6:'basic_block',
         7:'flow_graph', 8:'call_graph', 9:'string_table', 10:'address_comment', 11:'string_reference',
         12:'expression_substitution', 13:'section', 14:'library', 15:'data_reference', 16:'module',
         17:'comment', 93992622:'md_index'}                  # all are wire type 2 (length-delimited) in proto2 here
SINGLETON = {1, 8}                                           # >1 record would be merged by protobuf: reject (ambiguity)
def prescan(buf, limits, budget):
    pos, n = 0, len(buf); counts = defaultdict(int); size = defaultdict(int); unknown = 0
    while pos < n:
        start = pos
        tag, pos = read_varint(buf, pos, n)                  # raises wire_malformed if >10 bytes or past n
        field, wt = tag >> 3, tag & 7
        if field == 0: raise wire_malformed
        if wt == 2:
            length, pos = read_varint(buf, pos, n)
            if length > limits.max_record_bytes: raise Err(LIMIT, reason='record_too_large')
            if pos + length > n: raise wire_truncated
            pos += length
        elif wt == 0: _, pos = read_varint(buf, pos, n)
        elif wt == 1: pos += 8 ; check pos <= n
        elif wt == 5: pos += 4 ; check pos <= n
        else: raise Err(INPUT, reason='group_wire_type')     # wt 3/4 (groups) or 6/7: never legitimate at top level
        if field in KNOWN:
            if wt != 2: raise Err(INPUT, reason='wire_type_mismatch')   # proto2 would silently demote to unknown field
            counts[field] += 1; size[field] += pos - start
            name = KNOWN[field]
            if counts[field] > cap_for(name): raise Err(LIMIT, reason=f'count_cap:{name}')
            if field in SINGLETON and counts[field] > 1: raise Err(INPUT, reason='duplicate_singleton')
        else:                                                # unknown number (incl. extension range >= 100000000)
            unknown += pos - start
            if unknown > limits.max_unknown_bytes: raise Err(INPUT, reason='unknown_fields_excess')
        budget.tick(1)                                       # cancel/deadline every 8192 records
    if counts[1] == 0: raise Err(INPUT, reason='meta_missing')
    if counts[8] == 0: raise Err(INPUT, reason='callgraph_missing')
    return WireStats(counts, size, unknown, n)
```
The pre-scan is the reason `ParseFromString` is never called on a message that would allocate > caps: counts are bounded before objects exist. It cannot see nested counts (e.g. vertices inside the single `call_graph` record, ranges inside blocks); those are bounded by `max_record_bytes` (32 MiB for call_graph) times the checker's per-table caps, checked on the parsed message before any O(n^2)-capable pass.

### 6.5 Structural checker (`check_message`; all passes iterative; `idx(values, n, label)` = `values` empty or `min(values) >= 0 and max(values) < n`, using builtins `min`/`max` on repeated scalars so they run at C speed; on failure raise `Err(INPUT, reason=f'index_oob:{label}')` naming only the label and first bad value)

```
def check_message(msg, L, B):
    n = {t: len(getattr(msg, t)) for t in TABLES}               # expression, operand, mnemonic, instruction, basic_block,
                                                                #  flow_graph, string_table, comment, library, module, section, ...
    enforce_counts(n, L)                                        # nested-table caps not seen by the pre-scan
    # --- meta ---
    meta = msg.meta_information (must HasField); 
    for f in (executable_id, executable_name, architecture_name): non-empty, <= 4096 bytes, no NUL  -> meta_field_empty / meta_field_invalid
    ts = meta.timestamp if has else None; warn if ts is None or ts<=0 or ts > now+2d  ('timestamp_implausible')
    # --- call graph ---
    cg = msg.call_graph (HasField); V = cg.vertex; nv = len(V); if nv == 0: callgraph_empty
    prev = -1; addrs = []
    for i, v in enumerate(V):                                   # strictly increasing: duplicates AND disorder rejected
        a = v.address; if a <= prev (and i>0): raise vertex_unsorted_or_duplicate
        if v.type not in (0,1,2,3,4): raise vertex_type_invalid   # upb keeps unknown enum ints for proto2? treat as invalid
        li = v.library_index if v.HasField('library_index') else None; idx([li], n.library) ; same for module_index
        name lengths <= L.max_string_bytes, no NUL; prev = a; addrs.append(a); B.tick()
    ne = len(cg.edge); require ne <= L.max_counts['call_edge']
    for e in cg.edge:                                           # both endpoints REQUIRED present (absent = default 0 would alias vertex 0)
        require e.HasField('source_vertex_index') and e.HasField('target_vertex_index') else call_edge_incomplete
        idx([s, t], nv, 'call_graph.edge'); B.tick()            # self-loops/recursion allowed; call-graph cycles are legitimate
    # --- string table ---
    total = 0
    for s in msg.string_table:
        b = len(s) ; if b > L.max_string_bytes: string_too_long    # len(str) is code points; use s.encode('utf-8','strict') only when len(s)*4 > cap
        total += b; if total > L.max_string_total: string_total_bytes
        if isinstance(s, bytes): raise utf8_invalid   # MEASURED (U4): upb returns bytes for invalid UTF-8 in proto2 strings
        try: s.encode('utf-8') except UnicodeEncodeError: raise utf8_invalid   # lone surrogates (duck types); control chars are NOT rejected
        B.tick()                                                # (display layers must escape; see §8 T6)
    # --- expressions: parent indexes, cycles, depth ---
    E = msg.expression; ne_ = len(E)
    parent = array('i', [-1]) * ne_ ; for i,e in enumerate(E): if e.HasField('parent_index'): p = e.parent_index; idx([p], ne_, 'expression.parent'); require p != i (self_parent); parent[i] = p
    depth = array('i', [0]) * ne_                               # 0 = unknown, else depth+1
    for i in range(ne_):                                        # iterative path walk with memo; O(n) total
        if depth[i]: continue
        path = []; j = i
        while j != -1 and depth[j] == 0:
            if state[j] == IN_PROGRESS: raise expression_cycle   # state array marks nodes on current path
            state[j] = IN_PROGRESS; path.append(j); j = parent[j]
            if len(path) > L.max_expr_depth: raise expression_depth
        base = 0 if j == -1 else depth[j]
        for k in reversed(path): base += 1; depth[k] = base; state[k] = DONE
            ; if base > L.max_expr_depth: raise expression_depth
        B.tick(len(path) or 1)
    # --- operands ---
    for o in msg.operand:
        ex = o.expression_index; require len(ex) <= L.max_exprs_per_operand (operand_arity); idx(ex, ne_, 'operand.expression')
        (tier-2 warn, NOT reject: not exactly one root with parent unset and others descending from it -> 'operand_tree_shape'; Ghidra's exporter has no operand trees)
    # --- mnemonics / instructions ---
    require n.mnemonic >= 1 if n.instruction > 0 (default mnemonic_index 0 is effective)       # mnemonic_default_oob
    for ins in msg.instruction:
        m = ins.mnemonic_index if ins.HasField('mnemonic_index') else 0; idx([m], n.mnemonic, 'instruction.mnemonic')
        require len(ins.operand_index) <= L.max_operands_per_instr; idx(ins.operand_index, n.operand, 'instruction.operand')
        idx(ins.comment_index, n.comment, 'instruction.comment'); require len(ins.call_target) <= 1024 ; B.tick()
    # --- basic blocks: ranges + amplification ---
    cover = 0
    for b in msg.basic_block:
        rs = b.instruction_index; require 0 < len(rs) <= L.max_ranges_per_block ... (empty block allowed? NO: reject block_empty)
        for r in rs:
            begin = r.begin_index if r.HasField('begin_index') else 0
            end = r.end_index if r.HasField('end_index') else begin + 1
            if not (0 <= begin < end <= n.instruction): raise range_invalid
            cover += end - begin
        if cover > L.coverage_factor * n.instruction + 1024: raise coverage_amplification   # checked per block, not at the end
        B.tick()
    # --- flow graphs: membership, entry, edges, amplification ---
    members_total = 0
    for g in msg.flow_graph:
        bl = g.basic_block_index; members_total += len(bl)
        if members_total > L.coverage_factor * n.basic_block + nv: raise coverage_amplification
        idx(bl, n.basic_block, 'flow_graph.basic_block'); S = set(bl)           # |S| == len(bl) else warn 'flow_graph_duplicate_blocks'
        require g.HasField('entry_basic_block_index') and g.entry_basic_block_index in S  -> entry_not_in_graph
        flow_edges += len(g.edge); require <= L.max_counts['flow_edge']
        for e in g.edge:
            require both endpoints present; require s in S and t in S -> edge_endpoint_not_in_graph   # stronger than bounds-only
            B.tick()
    # --- references (string_reference, expression_substitution, address_comment, comment, data_reference) ---
    for ref in chain(msg.string_reference, msg.expression_substitution, msg.address_comment):
        i = ref.instruction_index (HasField required) ; idx([i], n.instruction, ...)
        op = ref.instruction_operand_index (default 0)  ; idx([op], len(msg.instruction[i].operand_index), 'reference.operand')       # per-instruction local index
        ex = ref.operand_expression_index (default 0)   ; operand = msg.operand[msg.instruction[i].operand_index[op]];
        idx([ex], len(operand.expression_index), 'reference.expression')
        idx([ref.string_table_index] if has else [], n.string_table, ...)  ; require has for string_reference/expression_substitution
    same for msg.comment (instruction_index optional; if HasField then the local-index rules apply; string_table_index required)
    # BUILD DEVIATION (§15): for comment/address_comment an ABSENT operand/expression index on an instruction (operand)
    # with nothing to point at is a plain instruction comment (the proto documents these indexes as operand-level markup)
    for d in msg.data_reference: idx instruction_index; (d.address any uint64)
    # --- sections / libraries / md_index ---
    for s in sections: require address + size < 2**64 (no wrap) else section_wraps ; flags free
    require len(msg.md_index) <= nv ; (md_index.address should be a vertex address: warn only; md_index is a finite double: reject NaN/inf -> md_index_invalid)
    return CheckReport(tuple(addrs), n, tuple(warnings))
```
Rules that apply to every pass: no recursion; no `list(...)` copy of a whole table (iterate the protobuf container); `HasField` for every optional index whose absence is semantically distinct from 0 (vertex/edge/flow-graph indexes use "required-present"; instruction/reference defaults are applied explicitly as above); warnings never alter validity; the first violation raises (no error accumulation, bounded error text <= 200 chars, contains labels and numbers only, never file strings).

### 6.6 Identity, orientation, address basis (binexport_identity.py)

```
def classify_identity(meta, artifact_sha256, accept_unbound):
    x = meta.executable_id.strip()
    if re.fullmatch('[0-9A-Fa-f]{64}', x):
        if x.lower() != artifact_sha256: raise Err(PAIR, reason='executable_id_mismatch')     # "claimed" != "actual"
        return 'sha256'
    kind = 'md5' if re.fullmatch('[0-9A-Fa-f]{32}', x) else 'empty' if not x else 'other'     # IDA fallback / unknown
    if not accept_unbound: raise Err(INPUT, reason=f'executable_id_{kind}', message='re-export with SHA-256 ids or confirm explicitly')
    return kind                                   # user-asserted binding is recorded in summary.id_binding and shown as such
def accept_pair(older, newer, older_sha, newer_sha):
    if older_sha == newer_sha: raise Err(PAIR, reason='identical_pair')
    if older.file_sha256 == newer.file_sha256: raise Err(PAIR, reason='same_file_twice')
    if both id_binding == 'sha256': contracts.check_pair(older.id, newer.id, older_sha, newer_sha)   # existing: swapped -> ORIENTATION
    # unbound members cannot be orientation-checked: caller must pass role explicitly and the UI must say 'asserted'
def detect_address_basis(addrs, layout):
    if layout is None: return 'unknown'
    lo, hi = addrs[0], addrs[-1]                  # sorted
    if layout.image_base <= lo and hi < layout.image_base + layout.size_of_image: return 'va'
    if hi < layout.size_of_image: return 'rva'    # 'Subtract Imagebase' was used
    return 'unknown'
# later (C4): BinDiff file.hash(1/2) must equal summary.executable_id of the primary/secondary snapshot, else ORIENTATION/PAIR.
# Mixed bases across the two files (one 'va', one 'rva') -> reject at accept_pair: reason='address_basis_mixed' (matches would be garbage).
```
Architecture check is advisory: `architecture_name` is compared (case-insensitive prefix `x86-64`/`x86-32`/`AARCH64-64`/`ARM-32`) with the PE `Machine`; mismatch -> warning `architecture_mismatch` (live naming per exporter unverified, §12 U6).

## 7. Failure taxonomy (`SecondaryError.code` + `reason`; messages are fixed English templates with labels/numbers only)

| code | reason slugs | meaning / UI action |
|---|---|---|
| `PT-SECONDARY-UNSUPPORTED` | `protobuf_missing`, `protobuf_not_upb`, `protobuf_too_old`, `descriptor_mismatch`, `worker_unavailable` | feature unavailable on this build; never "valid" |
| `PT-SECONDARY-INPUT` | `unreadable`, `not_regular_file`, `empty_file`, `file_changed_during_read`, `lookalike_sqlite/json/zip/pe/elf/pdf`, `wire_malformed`, `wire_truncated`, `group_wire_type`, `wire_type_mismatch`, `duplicate_singleton`, `unknown_fields_excess`, `parse_failed`, `trailing_bytes`, `meta_missing`, `meta_field_empty`, `meta_field_invalid`, `callgraph_missing`, `callgraph_empty`, `vertex_unsorted_or_duplicate`, `vertex_type_invalid`, `call_edge_incomplete`, `index_oob:<label>`, `range_invalid`, `block_empty`, `expression_cycle`, `expression_depth`, `self_parent`, `operand_arity`, `entry_not_in_graph`, `edge_endpoint_not_in_graph`, `coverage_amplification`, `string_too_long`, `string_total_bytes`, `utf8_invalid`, `section_wraps`, `md_index_invalid`, `executable_id_md5/empty/other` | file is not an acceptable BinExport2; keep file, show reason |
| `PT-SECONDARY-PAIR` | `executable_id_mismatch`, `identical_pair`, `same_file_twice`, `address_basis_mixed` | genuine file, wrong artifact(s) |
| `PT-SECONDARY-ORIENTATION` | `orientation_swapped` | files given as (newer, older) |
| `PT-SECONDARY-LIMIT` | `too_large`, `record_too_large`, `count_cap:<table>`, `memory_cap` | resource caps; message names the cap, not file content |
| `PT-SECONDARY-RUN` | `worker_timeout`, `worker_oom`, `worker_crash`, `worker_bad_result` | isolation boundary tripped; stderr tail (<= 64 KiB, sanitised) in diagnostics only |
| `PT-SECONDARY-CANCEL` | `cancelled` | user cancel; worker tree killed, private dir removed, no partial state |

Worker exit codes: 0 result written; 20 `error` document written; 21 internal error (traceback to stderr tail only); 22 `MemoryError`; 2 unusable request. Out-of-memory classification (measured on Linux, §15): under a cap upb raises `DecodeError("... Arena alloc failed")`, **not** `MemoryError`, and the failed arena growth can leave the peak well below the cap; pydantic-core (Rust) aborts with SIGABRT and `memory allocation of N bytes failed`. So `worker_oom` = exit 22, or a parse failure whose text is an allocation failure or whose peak is >= 0.9 x cap (the worker reports it as RUN/worker_oom, never as INPUT/parse_failed), or a runtime allocation-failure text in the stderr tail, or (Windows) the Job Object `PeakProcessMemoryUsed` >= 0.9 x cap; anything else is `worker_crash`. Every failure removes the snapshot unless the caller asks to keep rejected inputs for triage (default: remove; the user's original is never modified or deleted).

## 8. Accepting produced files

Phase 1 (this spec, C3/C4): **user-supplied only**. Flow: user selects `older.BinExport` and `newer.BinExport` (extension is a hint, case-insensitive, never decisive) -> `accept_binexport` twice with explicit roles -> `accept_pair` -> snapshots handed to C4. UI/CLI copy tells the user how to produce them (Ghidra File > Export > "Binary BinExport (v2) for BinDiff" with extension matching their Ghidra; IDA 9.4+ `Edit > Plugins > BinExport 12`; Binary Ninja is also an upstream-supported exporter, untested here) and that "Subtract Imagebase" must be chosen identically for both files. PatchTrace never labels its own JSON/CSV `.BinExport`.

Phase 2 (Phase E, **separate spec/PRs**): `GhidraHeadlessProducer` implementing `BinExportProducer`. Whatever it writes is exactly as untrusted as a user file and goes through `accept_binexport` unchanged (no fast path). Its own risks, to be specified before coding: (1) extension zip must match the user's exact Ghidra version (released zip targets 11.0.3; later versions require a source build) - probe by installed `Ghidra/Extensions` listing, refuse otherwise; (2) upstream README (re-checked 2026-10-14) runs the exporter as a **pre**-script on an already imported program: `analyzeHeadless <proj> <name> -process <file> -propertiesPath <dir> -preScript BinExport.java -noanalysis` (configured by `BinExport.properties`) or `-preScript BinExport.java <out.BinExport> "<choices>" -noanalysis`, after a separate `-import <file>`; the earlier `-postScript` text here was wrong. Whether the script fails without throwing is unverified - success = exit 0 **and** file accepted; (3) `-scriptPath` and the project dir are code/data injection points: only point at the verified extension dir and a private 0700 project dir; never at a user-controlled path; prefer shipping our own reviewed 30-line GhidraScript over the upstream one; (4) analysis time/memory of Java on hostile PEs: supervised by `run_process`, hard timeout, Job Object memory limit; Ghidra does not execute the target but its loaders/analysers parse hostile input; (5) licensing/redistribution: we reference an external install only (AGENTS.md: Ghidra/Java stay external); (6) the producer must pass `Subtract Imagebase` consistently for both artifacts and record the choice; (7) `executable_id` is the hash Ghidra stored **at import**: producing from a pre-existing Ghidra project may yield a different id - the producer imports from the artifact path itself.

## 9. Packaging steps and CI checks

1. `pyproject.toml`: `dependencies = [..., "protobuf==7.36.2"]`; add `[tool.setuptools.package-data]` only if descriptor ever moves out of Python source (it does not). Dev extra unchanged.
2. `tools/build_windows.py` and `tools/build_linux.py`: add `'protobuf'` to the distribution-notice loops (the Windows list is inline, the Linux one is `DISTRIBUTIONS`); extend `required` with `protobuf-7.36.2/LICENSE` and `binexport-2bff7af/{LICENSE,binexport2.proto,PROVENANCE.txt}`; `dependency-versions.json` then records `protobuf`. Add `--hidden-import google._upb._message` **only if** the frozen test below fails without it (measured: not needed on Linux).
3. Frozen smoke (extend the existing `--self-test`, which already runs after the build on both OSes): build an in-memory minimal valid BinExport2 with the loader class, serialize, run `inspect_binexport` on a temp file with a known SHA, assert summary fields and `api_implementation.Type() == 'upb'`; also run the worker route once (`PatchTrace secondary _binexport-worker` as a child) because that is how production runs and it exercises `run_process` + Job Object in the frozen layout. Failure = build fails.
4. Inventory guard: add `google/_upb/_message.*` to an **expected** list in the build scripts' inventory check; fail if absent (a silent pure-Python fallback is the 85x memory case).
5. CI (`qa-windows.yml`, both matrix OSes): `pip install --only-binary=:all: -e '.[dev]'`; `pip check`; a small step asserts the installed `protobuf` version equals the pin and that `api_implementation.Type()` is `upb`; new pytest marks run in the existing job; no new network at test time.
6. Gencode guard (only if fallback B is ever used): test parses the `# Protobuf Python Version:` header, asserts same major as the pin and header <= pin.
7. License review gate in PR-1: confirm BSD-3 + Apache-2.0 texts present, no other new licenses (`pip show -f protobuf` file list reviewed), update README dependency notice list.
8. `docs/qa.md` entry per bump: wheel SHA-256s, frozen-size delta (measure: Linux dev measurement was +0.4 MB for `_message` alone; record real Windows number), `upb` assertion result.

## 10. Golden files, fuzzing and property tests

### 10.1 Fixture strategy (legitimate sources only)
1. **Synthetic (default, committed)**: `tests/binexport_builder.py` builds messages via the runtime class (valid minimal, plus one mutator per taxonomy reason). Sizes < 20 KB. These carry the bulk of CI.
2. **Real-plugin goldens (committed, tiny)**: produce by running the **real** BinExport plugin (Ghidra release matching the zip) on the repo's own `tests/fixtures/new.c`/`old.c` compiled to small PEs (project-owned code, so redistribution is unencumbered) - or on tiny binaries we compile ourselves. Never commit exports of Microsoft or third-party binaries (redistribution rights unknown; the project's winbindex corpus stays external). Limits: each golden <= 256 KiB, total <= 2 MiB; larger ones live outside git and are CI-optional (`PATCHTRACE_BINEXPORT_CORPUS` env path).
3. **Provenance record** per fixture in `tests/fixtures/binexport/PROVENANCE.json` (strict JSON): `{file, file_sha256, source_sha256 (input PE), source_origin ("compiled from tests/fixtures/new.c with <compiler+flags>"), tool: "Ghidra x.y.z + BinExport v12-20240417 / IDA 9.4 + BinExport 12", options: ["Subtract Imagebase"?...], produced_on (date, OS), produced_by (person/CI run), license: "test fixture derived from project-owned source; BinExport output Apache-2.0-tool-generated, no third-party content", architecture_name, observed executable_id}`. A test asserts every `.BinExport` file in the folder has a record and the hashes match, and that `executable_id` equals the record's `source_sha256`.
4. IDA fixtures only if a maintainer holds a license; record it; absence is fine.
5. Regeneration steps documented in `tests/fixtures/binexport/README.md`; regeneration is manual and out of CI (Ghidra/Java external). Goldens double as the live-compat evidence for U3-U6; synthetic tests must never be reported as live compatibility (AGENTS.md).

### 10.2 Fuzz / property plan (`hypothesis` already a dev dependency; no new deps)
- **Unit/property (in CI, fast)**: (a) *round trip*: random valid messages from a hypothesis strategy (bounded sizes) always `valid`; (b) *single-mutation oracle*: take a valid message, apply exactly one mutation from a table (index +1, index -1, duplicate vertex, swap vertices, set parent to self/descendant, drop entry, edge to non-member, range end > count, huge range overlap, remove meta field, add 1 MiB unknown field, flip wire type of field N) and assert the **specific** reason slug; (c) *never-crash*: arbitrary `bytes` (and bytes derived by random byte flips/truncations/splices of a valid file) into `inspect_binexport` either returns a summary or raises `SecondaryError` - never another exception, never exceeds a 5 s / count-bounded budget (set tiny limits in the test); (d) *prescan/parse agreement*: whenever prescan passes and protobuf parses, `counts` match `len(table)` (catches wire/parse divergence); (e) *monotone caps*: lowering any cap never turns reject into accept.
- **Boundary cases**: 0-byte, 1-byte, only-meta, 10-byte varint overflow, length = 2^63, tag field 0, nested groups depth 150, packed vs unpacked repeated ints, int32 negative (`-1` encoded as 10-byte varint) indexes, uint64 max addresses, empty-string meta, NUL bytes in strings, lone-surrogate UTF-8 bytes, 5 MiB string.
- **Isolation tests (Linux+Windows CI)**: fake worker via env-injected small `memory_bytes` -> `worker_oom`; sleeping worker -> `worker_timeout` and no leftover process; cancel mid-prescan -> `PT-SECONDARY-CANCEL` and private dir removed; worker writes garbage/oversized/`NaN` JSON -> `worker_bad_result`.
- **Nightly/offline (not CI-gating)**: `atheris` (Linux/macOS only; it does not support Windows, so the nightly job is Linux-only and Windows relies on the hypothesis tests) or a libFuzzer-style harness over `inspect_binexport` with a seed corpus from the goldens, 30 min, crashes triaged into regression tests; differential testing against upstream C++ parsing is out of scope. CI fuzzing is time-boxed `hypothesis` only.

## 11. Threat model

| # | Threat | Vector | Control |
|---|---|---|---|
| T1 | Memory exhaustion | huge counts, 11x-85x amplification, giant strings | size/record/count caps checked in the pre-scan **before** parse; upb required; worker with Job Object / `RLIMIT_AS`; summary cap |
| T2 | CPU exhaustion | O(n^2) consumers via overlapping ranges, repeated blocks, deep/cyclic expression trees | coverage-amplification caps, iterative memoised depth/cycle pass, per-pass `Budget.tick`, wall deadline + process kill |
| T3 | Parser memory-safety bug in upb C code | crafted wire data | worker process isolation (a crash is `worker_crash`, the GUI survives), pinned recent protobuf, nightly fuzz, no other native parser in-process |
| T4 | Pure-Python fallback silently enabled | env var, unsupported platform | `Type()=='upb'` assertion, scrubbed env, inventory check, frozen smoke |
| T5 | Wrong-pair / swapped files | user error or malicious file claiming another id | `executable_id` vs artifact SHA-256 (PAIR), `check_pair` orientation, identical-pair and same-file guards, unbound ids need explicit assertion and are labelled |
| T6 | Hostile strings reaching UI/log/CLI | names, comments, control chars, bidi overrides | summary carries **no strings** from the file except meta fields (<= 4096 B, NUL-free); any later display must escape; error text never echoes file strings |
| T7 | Lookalike / non-BinExport file | renamed JSON/SQLite/PE | full parse + structural checks; prescan wire-type checks; advisory sniff gives clearer message |
| T8 | TOCTOU / swap after validation | file replaced between check and BinDiff run | open-once + fstat + bounded copy into private 0700 dir; hash recorded; C4 uses the snapshot only |
| T9 | Path tricks | symlink, device, FIFO, UNC, `..` | `O_NOFOLLOW` where available, regular-file check on the open handle, no path concatenation from file content, worker cwd = private dir |
| T10 | Supply chain | compromised/yanked `protobuf`, typosquat, sdist build hooks | exact pin, `--only-binary`, recorded wheel hashes, zero transitive deps, dedicated bump PR re-running gates; descriptor+golden-field-table test |
| T11 | Stale/regenerated descriptor drift | proto changes upstream, silent descriptor edit | `PROTO_SHA256`/`PROTO_COMMIT` constants, golden field table test, provenance file |
| T12 | Producer-phase code execution (Phase E) | `-scriptPath`, extension zips | §8 controls; separate spec; user-supplied only until then |
| T13 | Cancellation leaves state | killed mid-run | private per-call dir removed in `finally`; no writes to project store until `accept_pair` succeeds |

## 12. Unknowns only live runs can resolve (each gets a `docs/qa.md` line; none may be silently defaulted)

- U1 Real size/RSS ratio: how large are genuine BinExports (e.g. a 10 MB driver, a 30 MB kernel image) and what is their upb RSS/size ratio? Decides `max_file_bytes` (256 vs 512 MiB) and the `14x` memory formula.
- U2 Checker wall time per pass on real files (Windows vs Linux) -> `wall_seconds`, tick granularity.
- U3 Do real Ghidra exports satisfy the strict rules: strictly increasing vertex addresses (duplicates for thunks/imports?), `entry_basic_block_index` always in `basic_block_index`, flow edges only between member blocks, non-empty blocks, all optional index fields present on edges? Each rule here is a hypothesis; any false reject downgrades that rule to a warning with a test. Same for IDA output.
- U4 **Resolved (measured 2026-10-14, upb 7.36.2)**: invalid UTF-8 in a proto2 `string` parses and the field reads back as `bytes` (the pure-Python runtime raises instead); the checker maps `bytes` to `utf8_invalid`.
- U5 Does Ghidra's `executable_id` equal the artifact file SHA-256 for PEs imported normally (and when the project was created from a different copy, or a fat/trimmed import)? IDA ids for PEs (MD5 fallback frequency)? Decides whether `accept_unbound` is common.
- U6 Exact `architecture_name` strings per exporter for x86/x64/ARM64 PEs (Ghidra: `<processor>-<size>` from language id; IDA unknown) for the advisory check.
- U7 Windows: Job Object `ProcessMemoryLimit` behaviour with `jobs.run_process`. The limit counts **committed** memory and makes allocations fail rather than killing the process [doc], but what the child sees (MemoryError, `Arena alloc failed`, abnormal exit code) is undocumented: measure with `tools/qa_binexport_memcap.py` on the Windows runner (pipeline and `--alloc` modes; `ProcessResult.peak_memory_bytes` reports `PeakProcessMemoryUsed`); also the idle commit of the frozen worker, which bounds the 512 MiB floor, and whether upb `_message.pyd` loads in the frozen onedir worker with `--hide-console hide-early` build.
- U8 Frozen Windows size delta and AV false-positive behaviour for the new `.pyd`.
- U9 Whether any real tool emits multiple `call_graph`/`meta_information` records, packed repeated ints, or unknown fields (`unknown_fields_excess`, `duplicate_singleton` strictness).
- U10 `protobuf` 7.x abi3 wheel behaviour on Python 3.12 Windows runner in this repo's CI (and Python 3.13/3.14 later).
- U11 Latest BinExport release/tag state (GitHub API unreachable from this session) and whether the Ghidra extension for the user's Ghidra version exists (headless Phase E).
- U12 BinDiff v8 acceptance of files PatchTrace accepted (any accepted-but-BinDiff-rejected file is a validator gap; any rejected-but-BinDiff-accepted file is a false reject: both become regression tests).

## 13. PR breakdown (each small; spec -> red tests -> code -> focused tests -> full gate -> CI Linux+Windows -> merge)

| PR | Content | Size | Model tier |
|---|---|---|---|
| C3-1 | Dependency + descriptor: pin `protobuf`, `tools/gen_binexport_descriptor.py`, `binexport_descriptor.py`, `binexport_proto.py` (private pool, upb assertion), notices dirs, build-script notice lists, golden field-table test, frozen self-test import (Linux+Windows). Decides DR-C3-1 final (fallback B only if Windows frozen fails) | S-M | mid (packaging judgment); low for notice copying |
| C3-2 | `contracts.SecondaryError.reason`, `binexport_limits.py`, `binexport_prescan.py` + tests (wire edge cases, caps, no protobuf needed) | M | mid |
| C3-3 | `binexport_check.py` refactor of today's `check_message` into the §6.5 passes + new checks, `binexport_identity.py`, facade `binexport.py` keeping the old test file green (update 2 monkeypatch tests deliberately); duck-typed `SimpleNamespace` tests extended | M | mid |
| C3-4 | `binexport_snapshot.py`, `binexport_pipeline.py` (in-process `inspect_binexport` with real runtime class), synthetic builder `tests/binexport_builder.py`, mutation table tests | M | mid (builder fixtures: low) |
| C3-5 | Isolation: `jobs.run_process(memory_limit_bytes=...)` (Windows `JOB_OBJECT_LIMIT_PROCESS_MEMORY` 0x100 in `ExtendedLimits`, POSIX `RLIMIT_AS` via `preexec_fn`/`prlimit`), `binexport_worker.py`, `binexport_run.py`, hidden CLI subcommand, frozen worker smoke, isolation tests | M-L | mid; **top tier only** if the Windows job-memory/exit-code semantics fail a lower-tier attempt (AGENTS.md escalation rule) |
| C3-6 | Property/fuzz tests (§10.2), boundary cases, nightly harness script (not gating) | M | low-cost for tables; mid for oracle design |
| C3-7 | Real-plugin goldens + provenance + README (needs a human with Ghidra/IDA; blocked item until done) and `docs/qa.md` live rows U1-U6, U9, U12 | S code / manual | low for plumbing; human for production |
| C3-8 | SPEC-10 §2 text update (size cap, new reasons, snapshot rule) and `docs/modules.md`/`tasks/todo.md` entries; `binexport-check` user CLI | S | low |
| Phase E (not C3) | `GhidraHeadlessProducer` spec + PRs (§8) | L | mid; spec review top tier only if a security invariant is disputed |

C3-1 and C3-2 can proceed in parallel (disjoint files); C3-3 needs C3-2; C3-4 needs C3-1+3; C3-5 needs C3-4; C4 (BinDiff runner) consumes `AcceptedBinExport` and may start after C3-4 using in-process acceptance, switching to C3-5's worker without API change.

## 14. Needs a product-owner decision

1. Accept the new `protobuf==7.36.2` runtime dependency (+~1 MB frozen, BSD-3) in the core dependency list (alternative: optional extra, which would make BinDiff features absent from the standalone alpha).
2. Lower the default `.BinExport` cap from 512 MiB (SPEC-10) to 256 MiB until live evidence exists.
3. Policy for MD5/empty `executable_id` (IDA fallback): reject by default with an explicit "I confirm this belongs to this artifact" override (recommended), or reject always.
4. Who produces real-plugin goldens (needs Ghidra with BinExport and, optionally, a licensed IDA) and where larger non-redistributable corpora may live.

## 15. Implementation record (C3 build, 2026-10-14)

Built in worktree branch `worktree-agent-ae86fadb5f83ab3b5` as PR slices C3-1..C3-6, C3-7 (synthetic part) and C3-8, in pure modules under `secondary/`. Labels: [run] measured here on Linux x86-64 (CPython 3.13.16, protobuf 7.36.2 upb, PyInstaller 6.22.3); [ci] can only be verified on the Windows runner; [open] needs a human, Ghidra/IDA or a later PR.

**Pin re-verified [run]:** PyPI latest is still `protobuf` 7.36.2, uploaded 2026-09-17, license BSD-3, no dependencies. The wheel SHA-256s are in `third_party/notices/protobuf-7.36.2/MANIFEST.txt`. The installed runtime reports `upb`. The descriptor set was generated with grpcio-tools 1.84.0 (bundled protoc) in a throwaway directory: 4144 bytes, SHA-256 `1c8b2bc1...6fba`, byte-identical to the §1 claim.

**Measurements [run]:**

| What | Result |
|---|---|
| 13.35 MiB file, 2 M tiny `string_table` records (the §1 DoS shape), in-process | Pre-scan 1.34 s (about 1.5 M records/s, slower than the 3.5 M/s tag-only walk because every cap is checked). Parse 0.08 s. Checker 0.78 s. VmPeak 137 MiB, RSS high-water mark 126 MiB, so address space ≈ RSS + 11 MiB. |
| 10.1 MiB file, 100 k functions | Pre-scan 0.34 s, parse 0.07 s, checker 1.48 s. |
| End-to-end worker (`python -m patchtrace`), tiny file | About 0.6 s. |
| End-to-end worker, 13.35 MiB file | About 2.4 s. |
| Same 13.35 MiB file, worker under explicit caps | 48-120 MiB caps give `worker_oom`; 140 MiB and above succeed (`tools/qa_binexport_memcap.py`). |
| Allocation failure modes under a cap | At caps of 64-120 MiB, upb raised `DecodeError: ... Arena alloc failed`. At a 120 MiB cap the peak was only 97 MiB (0.81 x cap). At a 96 MiB cap, pydantic-core (Rust) aborted with SIGABRT: `memory allocation of 656 bytes failed`. All of these are now `worker_oom` (§7 text above). |
| `bytearray` child under `run_process` | `MemoryError` at the cap: 192 MiB held at a 256 MiB cap, 448 MiB at a 512 MiB cap. |
| Linux frozen build (`tools/build_linux.py`) | Built. The new inventory guard found `_internal/google/_upb/_message.abi3.so` (412 KiB; the protobuf Python modules sit inside the PYZ). The notice directories were copied. `dependency-versions.json` records protobuf 7.36.2. |
| Linux frozen smoke (`tools/frozen_smoke.py`) | 30/30 PASS, including B1/B2: the frozen exe spawns itself as the capped worker, upb is active and the reasons are correct. |
| Fuzz | 1.6 M random-mutation inputs in 60 s, seeded from the goldens: 0 findings. Hypothesis: 2000 arbitrary-byte and 1000 flip/truncate/splice examples per run. |

**Deviations and additions (all additive; frozen seam unchanged):**
- New reason slugs, all `PT-SECONDARY-INPUT`: `call_target_arity`, `block_ranges_excess`, `flow_edge_incomplete`, `reference_incomplete`. `md_index` count above the vertex count is `PT-SECONDARY-LIMIT count_cap:md_index`. An allocation failure during parse is `PT-SECONDARY-RUN worker_oom`.
- The `meta_field_empty` check applies to `executable_name`/`architecture_name` only. An empty `executable_id` is an identity question: `executable_id_empty`, overridable through `accept_unbound`. The facade `binexport.check_message` keeps the legacy rejection.
- `comment`/`address_comment`: an absent operand or expression index on an instruction (or operand) with nothing to point at is accepted as a plain instruction comment. The proto documents these indexes as operand-level markup, and rejecting them would be a likely U3 false reject on `ret`-style instructions. An explicit index must be in range. `string_reference`/`expression_substitution` stay strict.
- `BinExportLimits` adds `max_meta_bytes` 4096, `max_call_targets` 1024 and `coverage_slack` 1024. `memory_bytes` defaults to `None`, meaning `memory_for(file_size)` per file; the parent passes the concrete value to the worker.
- After parsing, the pipeline asserts that wire counts equal table sizes (`parse_failed` on divergence).
- `sniff_lookalike` only explains an already-rejected file. Its JSON test is stricter, because a genuine export can start with `0x0a 0x5b` ("newline, `[`"). A regression test covers this.
- `PeLayout` gains an optional `machine` label for the advisory architecture warning.
- `BinExportSummary`, `WorkerRequest` and `WorkerResult` live in `binexport_models.py`.
- Worker isolation on POSIX has two layers. The parent sets `RLIMIT_AS` with `prlimit()` right after spawn and fails closed if it cannot. The worker also lowers its own `RLIMIT_AS` before opening the input, which closes the window between spawn and `prlimit`. No `preexec_fn` is used on Linux.
- On Windows, `jobs.run_process` sets `JOB_OBJECT_LIMIT_PROCESS_MEMORY` before resume and returns `PeakProcessMemoryUsed` as `ProcessResult.peak_memory_bytes`. A module lock now spans CreatePipe through closing the child-end handles, so concurrent runs cannot inherit each other's pipe write ends.
- CLI exit codes for `secondary binexport-check`: 0 valid; 2 for INPUT/PAIR/ORIENTATION/LIMIT/UNSUPPORTED; 3 for RUN (worker timeout, OOM, crash or bad result); 5 for cancel. The reason slug is printed in brackets.
- A PyInstaller hook `hook-patchtrace.secondary.binexport_proto.py` names `google._upb._message` and the descriptor-pool modules. It is a guard, not a fix: the measured build collected them anyway. Both build scripts check the pin and upb before freezing, require the new notices, and refuse to publish without the upb extension.

**Open gates:**
- [ci] Windows: U7 behaviour at the Job Object limit, the idle commit of the frozen worker, and the frozen `PatchTrace.exe` B1/B2 run (`qa-windows.yml` already runs `frozen_smoke.py`).
- [ci] CI workflow steps from §9.5, owned by the integration owner because `.github` is outside C3 ownership:
  - `pip install --only-binary=:all:`;
  - `pip check`;
  - a pin + upb assertion step;
  - `tools/qa_binexport_memcap.py` on Windows;
  - a Linux-only nightly `tools/fuzz_binexport.py`.
- [open] C3-7 real-plugin goldens and U1/U3/U5/U6/U9/U12. `tests/fixtures/binexport/` holds synthetic goldens only, so they are not live-compatibility evidence.
- [open] GUI wiring, and the C4 swap of `bindiff_inputs`' Protocol to the real `AcceptedBinExport`.
- [open] Phase E producer spec (§8 recipe corrected to `-preScript`).
