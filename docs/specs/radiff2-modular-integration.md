# SPEC-RD-02 — radiff2 build-safe integration, dependency and CI contract
Status: proposed companion to SPEC-RD-01, 2026-10-14.

## Constraints and existing architecture
PatchTrace targets Python >=3.12, PySide6==6.12.0 and pydantic==2.13.5 with separately configured Ghidriff/Ghidra backend, SQLite projects, supervised cancellable jobs and portable Windows x64 packaging. Do not modify the working Ghidriff native import/normalization path; its results and corrections stay authoritative. The raw binary comparator works without radiff2. Enable optional external radiff2 only in advanced analysis after capability preflight. No system PATH changes, silent downloads, package-manager installs, bundled binary until cross-platform testing and license audit.

## Version-critical hazards
The official radiff2 man page changed CLI meanings relative to old tutorials: modern `-n` counts differences, `-c cmd` invokes an r2 command; modern `-i type` accepts metadata selectors; modern `-B addr` is a base address, not old GDIFF. Require `radiff2 -v` and `-h` probe; explicitly supported versions+flags and output parsers. Reject ambiguous/unrecognized versions and output mode. Never pass a user string to arbitrary r2 command `-c`, eval `-e` or shell. Disable experimental `-T`. Some formats produce output on stdout while diagnostics may use stderr; capture both with bounded buffers and use return code + validated payload.

## Layer boundaries
1. Pure code: streaming I/O, byte alignment, PE layout, immutable typed result schema.
2. Optional executable adapter: radiff2 subprocess and versioned JSON parser, no Qt imports.
3. Orchestrator: request budgets and cancellation, sanitized log/provenance.
4. Storage: additive tables and schema versions, transactionally persist only fully validated report, linked by immutable artifact digest.
5. GUI/report: present only validated layers; lazy loading and virtualization of changed spans; missing optional engine shows explanation. No independent mutation of existing Ghidriff match rows.

Suggested contracts:
`ByteComparator.compare(old_path,new_path,limits,cancel)->ByteComparison`
`PERangeResolver.resolve(file_sha,range)->AddressMapping|Unmapped`
`OptionalEngine.probe(executable)->EngineCapabilities`
`OptionalEngine.analyze(request,cancel,budget)->RawEngineResult`
`LayerNormalizer.normalize(raw,manifest)->ComparisonLayerResult`
`LayerStore.commit_validated(project_id,run)->int`
`EvidenceNavigator.lookup(layer_id,range)->list[EvidenceLink]`
No code module may import desktop widgets from comparison core; optional adapter does not import matcher/QBinDiff implementation.

## Storage
Add new `comparison_layers`, `comparison_spans`, `comparison_provenance`, `comparison_cfg_nodes` tables if not already present; migration idempotent, foreign-keyed to analysis run and binary digests. Store bounded snippets + cryptographic digests, not unlimited bytes. Distinguish file offsets from RVA and virtual address. Save layer completion status, profile, selected sections, tool/executable hash, caps, serializer version, output size and elapsed time. Old projects open identically. Explicit opt-in rerun invalidates only that optional layer's cache, not manual findings or existing comparisons. Back up db before migrations and test upgrade/rollback.

## Child execution and security
Absolute executable path selected by operator or verified bundled runtime; hash and version recorded. Pass list-of-strings argv to supervised Windows Job Object (already in PatchTrace job tooling) with kill-on-close and cancellation; no shell, no execution of target PE. Run under private scratch without network intentionally enabled; consider OS isolation separately. Reject paths outside approved project inputs and oversized file lengths. Zero trust of upstream output including invalid Unicode, CRLF, JSON nesting, huge arrays, DOT payloads and ANSI codes. Sanitize logs. Prefer streaming outputs to bounded disk files rather than retaining gigabytes in RAM.

## PRs and release gates
PR1 additive pure contracts, byte changes, exact range validator, unit/property tests; existing CI unchanged.
PR2 PE layout delta and address mapping, signed PE/overlay tests.
PR3 GUI Byte & Layout inspector and virtualized navigation, existing controls untouched.
PR4 optional radiff2 provider probe + raw/metadata + fixture-normalizers; feature flag off.
PR5 operand and CFG diagnostic modes and feature-by-feature capability matrix.
PR6 candidate evidence reconciliation with SPEC-QB-01, opt-in exports and persistence; distinguish raw evidence from function matching.
PR7 benchmark, Windows native and frozen ZIP smoke; license/SBOM notice audit if shipping executable.
Gate each PR on Python 3.12 tests, Ruff, UI offscreen smoke, old project reopen, Ghidriff native/import golden sample, Windows CI, cancellation-failure rollback and clean Windows installer. Cap memory/CPU/time. Run binary-hash-specific fixture pairs through installed radiff2 in CI and verify JSON parser backward compatibility. If optional component missing or crashes, baseline must continue unaffected.

## Measurable non-regression
Default Ghidriff-only output, UI and SQLite bytes semantically unchanged. No hard radiff2 requirement. Compare on 0B, 1B, 4K, 20MB and sparse large files; verify change span precision and address mapping. Reproduce important operand-only fix and changed code on same-length files. Simulate modified binaries during scanning: detect source file change before commit. Cancellation/failure preserves committed analysis and analysts' data. Advanced module can be fully disabled without DB failures, import failures or PyInstaller dynamic-import breakages.
