# Local runtime discovery (SPEC-05)

PatchTrace's backend installation remains outside the frozen Qt desktop. On the first visit to Setup, discover an existing external Python/Ghidriff environment and a Ghidra installation through read-only bounded local filesystem probes. This feature is detection and prefill only; it never executes another program, downloads packages, installs components, or grants administrator privileges.

## Pure module contract

`discover_local_runtimes(environ: Mapping[str, str] | None = None, search_roots: Sequence[Path] = ()) -> RuntimeCandidates` returns frozen sorted tuples `python_executables` and `ghidra_roots` of absolute, deduplicated readable candidates. The defaults are a dedicated `%LOCALAPPDATA%/PatchTrace-backend/Scripts/python.exe` venv and per-user `%LOCALAPPDATA%/PatchTrace/runtimes/` installs; explicit `PATCHTRACE_BACKEND_PYTHON` and `GHIDRA_INSTALL_DIR` may be discovered as hints; directories such as `C:/Tools`, `%USERPROFILE%/Downloads`, and optional `search_roots` are searched only one level for `ghidra_*` installations. All candidates must be existing non-symlink files under existing non-symlink roots. Ghidra roots must contain `Ghidra/application.properties`. Never walk arbitrary disk roots recursively; never trust `python` on PATH or `PatchTrace.exe` as an analysis interpreter.

A Ghidra candidate directory can be registered directly by explicit env, or discovered as a child of a searched root. The routine must not mutate environment variables or user's files. It must remain usable without Qt and must accept injected environments and roots for deterministic tests.

## Desktop integration

Setup first checks the persisted path in QSettings. For each empty field, populate it only if discovery yields **exactly one** valid candidate. Existing manually configured paths are not replaced. Multiple or missing candidates are listed in plain-text diagnostics with instruction to choose using existing Browse controls. A **Find existing installations** button rescans on demand. Setup's existing independent **Diagnose dependencies** action is still required for metadata validation and never claims a complete Ghidriff comparison has been performed.

No automatic network, auto-install, or executable launch should occur as a side effect of displaying Setup. Selecting a candidate is not a compatibility guarantee: actual `BackendConfig` and `diagnose` validate paths and runtime readiness before comparison.

## Tests

- Fake dedicated venv and fake Ghidra home are detected with an injected environment.
- Alternate installs, spaces, Unicode and duplicates are handled without recursion.
- Nonexistent files, unrelated python binaries and symlink directories are ignored.
- UI prefill preserves manually selected paths and does not silently pick one of multiple candidates.
- Existing Windows, Linux, Qt, Ruff, PyInstaller and native Ghidriff jobs remain passing.

## Future provisioning

A checksum-verified portable offline runtime pack and user-initiated guided installer are separately specified in the runtime reliability audit. Discovery does not perform those operations.
