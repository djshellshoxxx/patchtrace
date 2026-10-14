# Independent packaging audit: codex/audit-2

Snapshot: `main` at `c2070cf8b4e7b0ade76cb000a5805009754eec55`. Package 2 follows the workflow report in package 1. Packaging findings: **2 High, 4 Medium, 1 Low**. Combined: **2 High, 9 Medium, 4 Low** (15 root-cause findings).

Read tools/build_windows.py, tools/build_linux.py, all five tools/pyinstaller_hooks files, tools/frozen_smoke.py, pyproject.toml, third_party/notices inventory/provenance, and docs/notices.md. Also inspected CLI registration, optional dependency probing, the full-bundle pin manifest and the relevant backend builder license/source rules to distinguish embedded desktop dependencies from external engines. The four missing requested documents and no-live-build limitation are recorded in codex-workflows-1.md.

No Windows/Linux release archive was built or inspected, no target binary was executed, and no upstream binary/license was downloaded. License copying from installed wheels is assessed as code, not claimed as a successful artifact compliance review. Qt's dual-license texts and PyInstaller's bootloader exception are not evidence that forbidden GPL application code was copied.

## Findings

### CODEX-9 — Medium: the runtime closure is not exactly locked

Evidence: `pyproject.toml:9,14-15` exactly pins PySide6, shiboken6, pydantic, protobuf and optional rapidfuzz, but yara-x is a range. `tools/build_linux.py:27-29,295-298` and `tools/build_windows.py:85-89` record installed versions after freezing rather than constraining the complete dependency closure. Pydantic's pydantic-core/annotated-types/typing-extensions/typing-inspection versions are described as environment resolutions at `docs/notices.md:17`, not committed runtime pins. There is no desktop runtime lock file. Python's patch version is also selected by setup-python '3.12'.

Fix: exact, hash-locked Windows/Linux wheel closures including installed optional runtimes; assert each collected distribution matches the resolved lock. Distinguish build-only dependencies and system libraries. Regression: `test_runtime_requirements_have_exact_pins`, strict xfail CODEX-9, directly checks the unpinned rules runtime. Transitive closure is a separately documented portion of this same finding, not guessed from a synthetic environment.

### CODEX-10 — Low: build/dev dependencies have unbounded upgrades

Evidence: `pyproject.toml:2,11-12,17` allows setuptools>=75, pytest>=8, pytest-qt>=4, ruff>=0.12, hypothesis>=6.100, pefile>=2024.8.26 and scikit-learn>=1.5 without upper bounds. These can change lint/test/build behaviour across otherwise identical CI runs. Networkx and pygments have upper bounds; PyInstaller is exactly pinned.

Fix: exact pins in the build lock, or supported upper bounds with reviewed upgrades. Regression: `test_all_declared_dependencies_have_pin_or_upper_bound`, strict xfail CODEX-10; covers build-system and every extra, excluding requires-python (an interpreter support constraint).

### CODEX-11 — Medium: bundled optional runtimes have no notice rows

Evidence: `tools/build_linux.py:29,296` and `tools/build_windows.py:87` include rapidfuzz/yara-x when installed; `qa-windows.yml:27,66` installs both extras. `docs/notices.md:13-31` has no rapidfuzz or yara-x row. `third_party/notices/` has no matching upstream license inventory for either. The scripts attempt to copy installed licenses, but that does not add a source/version/license/disposition row to the shipped docs.

Fix: add distinct notice rows for both, including exact resolved version, license expression, source and bundled status; validate their wheel license texts at build time. Regression: `test_optional_runtime_dependencies_have_notice_rows`, strict xfail CODEX-11. This proves an inventory gap, not that their licenses are incompatible.

### CODEX-12 — Medium: per-distribution license copying can silently copy nothing

Evidence: `tools/build_windows.py:88-96` and `tools/build_linux.py:297-305` iterate `dist.files or []` and copy filename matches, with no assertion that any license/notice was found for each distribution. Both fixed REQUIRED_NOTICES inventories protect selected upstream texts only. An installed pydantic/rapidfuzz/yara-x wheel with no listed license files passes this loop. Selected fixed Qt/protobuf/BinExport/BinDiff source notices do not cover an arbitrary dependency's missing text. Linux's required set is also narrower than Windows's (e.g. OpenSSL/PySide/PyInstaller texts can be absent without tripping that Linux gate).

Fix: require a distribution-to-license inventory whose resolved paths are nonempty and exist, with explicit reviewed upstream fallback for wheels lacking texts. Cross-check every collected runtime distribution and native component, not only hardcoded names. Regression: `test_license_copy_loops_require_nonempty_license_sets`, strict xfail CODEX-12; statically checks the concrete empty file-list fallback. It is not a complete license scanner.

### CODEX-13 — High: full attachment accepts an invalid, unlicensed payload

Evidence: `tools/build_linux.py:105-126,201-225`, called by `tools/build_windows.py:129-131`, checks only manifest-file existence, payload-directory existence, path length/link rules and Windows filenames. It does not parse/validate the manifest, check its declared digests, validate component licenses or enforce a component allowlist before copying the backend into a distributable folder. A temporary directory containing `manifest.json` with `{}` and an empty `payload/` is accepted by payload_problems and attach_backend. New SHA256SUMS records the supplied bytes, not their trustworthiness. The later frozen lite smoke already ran before attachment.

Fix: before copying, invoke the canonical strict manifest/complete tree verifier and component/license-policy validator, reject invalid/unlicensed payloads, and compare manifest files to the exact copied tree. Existing backend-bundle CI acceptance provides another defense, but manual `--full --backend-payload DIR` bypasses the producer and cannot rely on it. Regression: `test_full_payload_validation_parses_manifest`, strict xfail CODEX-13. This is a statically proven missing build gate; no malicious runtime was executed or supplied.

### CODEX-14 — Medium: Linux release does not run the full frozen CLI smoke

Evidence: `tools/frozen_smoke.py:47-49,119-121` dynamically takes names() and checks every top-level verb. Windows QA invokes this tool at `.github/workflows/qa-windows.yml:42-44`. Linux build only invokes --self-test and rank --help (`tools/build_linux.py:325-326`), and downstream linux-smoke only runs --self-test in offscreen/xcb modes (`qa-windows.yml:101-106`). Thus Linux release never proves the other ten top-level verbs load in its frozen runtime.

Fix: run frozen_smoke against the unpacked Linux artifact on supported distributions, retaining the Qt mode checks. Extend subcommand help coverage separately: the current A1 list covers top-level verbs, not every nested parser; this audit does not pretend otherwise. Regression: `test_linux_package_runs_full_cli_smoke`, strict xfail CODEX-14.

### CODEX-15 — High: the configured full bundle exceeds the supplied GPL exception

Evidence: full build copies the entire supplied backend payload (`tools/build_linux.py:213`, Windows uses the same helper). `tools/backend_pin.json:53,63` selects JDK components with SPDX `GPL-2.0-only WITH Classpath-exception-2.0`; line 176 explicitly keeps `GPL/**`. The BUNDLE plan section 7.4 says to retain Ghidra GPL decompiler/demangler sources. These are additional GPL components beyond the sole exception in this audit brief, Ghidriff as a separate unmodified component. `docs/notices.md:7,22-23` describes conditional review rather than enforcing that narrower rule, and attach_backend has no license filter.

Fix: keep these additional runtimes/components user-managed and external under the current brief, or obtain an explicit changed product rule before distributing them. Retaining licenses/exception texts is good practice but does not satisfy a rule forbidding the bundle itself. Do not delete upstream license/source obligations while continuing to ship their binaries. Regression: `test_full_bundle_pin_has_no_other_gpl_components`, strict xfail CODEX-15, checks the known JDK SPDX entries only. This is a configured build-policy violation, not a claim a full archive was successfully published, a legal compatibility verdict, or proof of GPL code copied into PatchTrace source.

## Dependency and notice assessment

| Component group | Version control in source | License/notice evidence | Result |
|---|---|---|---|
| PySide6, shiboken6 | Exact direct 6.12.0 | docs/notices row; upstream PySide/Qt license and attribution trees | Direct declaration passes; final collected DLL licensing unverified |
| PySide Essentials/Addons and Windows WebEngine/Pdf metadata | Installed versions recorded, no desktop closure lock | Build copies installed notices; excluded WebEngine/Pdf binaries checked | Closure/empty-copy gaps CODEX-9/12; no claim excluded binaries ship |
| pydantic | Exact 2.13.5 | docs/notices row; build copies installed license | No committed pydantic text fallback; build must verify actual copy, CODEX-12 |
| pydantic-core, annotated-types, typing-extensions, typing-inspection | Environment resolutions only | Group notice row; build copy loop | CODEX-9/12 |
| protobuf | Exact 7.36.2 | Checked-in LICENSE, wheel-digest MANIFEST, notice row, build upb guard | Good source evidence; final wheel inventory unverified |
| rapidfuzz | Exact 3.14.6 | Conditional installed-wheel copying; no notice row | CODEX-11/12 |
| yara-x | >=1.0,<2 | Conditional installed-wheel copying; no notice row | CODEX-9/11/12 |
| CPython/OpenSSL/PyInstaller | CPython patch floats; PyInstaller 6.22.3 pinned; OpenSSL copies reference two versions | Python license required; upstream OpenSSL/PyInstaller texts present; broad docs renderer/runtime rows | Requires artifact/native closure reconciliation, not a full SBOM |
| BinExport descriptor and re-expressed BinDiff MD-index | Full source revisions and provenance files | Apache-2.0 texts/provenance required by both builders | No GPL copied-code finding in these modules |
| Ghidriff | Separate backend component with full source revision pin | GPL source/notice/process-boundary rules in backend builder | External for lite; only allowed GPL exception in this brief; exact unmodified built artifact unverified |
| Full Ghidra/JDK payload | Backend pins, separate payload | Mixed inventory including additional GPL components | CODEX-13/15; no archive acceptance claim |

## Hidden imports and smoke list

All five hooks were inspected:

- QtGui: calls the standard Qt collection helper, filters desktop/offscreen/platform integration plugins. No actual plugin load test performed here.
- cli_commands: collect_submodules(..., on_error='raise') plus source-file completeness check; avoids silently omitting future dynamically discovered verb files. This snapshot has only the registry __init__.py.
- optional_deps: collects rapidfuzz dynamic backends and yara_x; copies distribution metadata when installed. No proven missing hidden import; optional absence is supported.
- binexport_proto: explicitly lists upb and descriptor/message modules. Both builders require the extension in their final file inventory.
- unified.extract: explicitly ships the external Ghidra Python script as data. Builders require exactly one byte-identical copy.

Core CLI verbs at this snapshot: rank, flags, correlate, cache, acquire, series, secondary, intelligence, unified, intel-tools, backend. frozen_smoke COMMANDS=names() includes all eleven and future discovered extensions. It also exercises synthetic ranking, paths, series, BinExport, intelligence and unified worker paths. Help coverage is not live engine compatibility evidence. No fabricated disassembly/evidence was produced by this audit; smoke fixtures are explicitly labelled synthetic.

No copied AGPL engine was found in the audited packaging/hook code; Diaphora remains a candidate row, not a bundled import. GPL license text files alone are not executable code. No Microsoft binary/PDB/Winbindex corpus was added. Runtime egress beyond the requested packaging scope was not independently re-audited.

## Regression disposition and reproduction

Strict xfail IDs: CODEX-9, CODEX-10, CODEX-11, CODEX-12, CODEX-13, CODEX-14, CODEX-15. Tests encode the stated source facts, not unverified artifact claims. Passing controls cover exact core pins, hook coverage, dynamic smoke enumeration and engine exclusions. Together with package 1, all CODEX-1 through CODEX-15 have an expected-failure check.

```bash
python -m pytest tests/test_codex_pkg_*.py -q
ruff check tests/test_codex_pkg_*.py
python -m pytest tests/test_codex_pkg_packaging.py -rx -q
```

These checks are hermetic source/AST inspections. No install, network call, target execution, secret or process launch occurs in the tests. Full project QA is not substituted by these targeted checks, and clean Windows/Linux artifact acceptance remains unverified. The tests are supplied in the third commit.

## Recorded verification

- Required targeted suite: **8 passed, 16 xfailed**, exit 0. CODEX-8 has two trailer spellings, explaining 16 cases for 15 IDs.
- `ruff check tests/test_codex_pkg_*.py`: passed.
- `python -m ruff check src tests tools`: passed.
- AGENTS.md full-suite command `QT_QPA_PLATFORM=offscreen python -m pytest -q`: attempted, exit 2, **41 collection errors**, caused by unavailable PySide6 and Hypothesis. No full-suite pass claimed; no production dependency changes were made for this bounded static audit.
- CODEX-13 also reproduced outside pytest with runpy-loading the stdlib-only build_linux helpers and a temporary `{}` manifest/empty payload. Both payload_problems (empty problem list) and attach_backend accepted it and produced provenance. GITHUB_SHA was supplied as synthetic zeros to avoid git execution. No build or binary was run.
