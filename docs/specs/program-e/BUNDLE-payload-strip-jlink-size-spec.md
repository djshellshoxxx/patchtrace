# BUNDLE payload: strip rules, jlink runtime, FID databases, size budgets, split parts and the PT-BUNDLE code table

Status: approved for build (documents only). Date: 2026-10-15. Base commit: `54fd085`. Extends `docs/specs/program-e/BUNDLE-integration-plan.md` section 7.4 and replaces its size estimates with measured ones; evidence base `docs/research/ghidra-headless-large-pe.md` sections 3, 5, 6. Game plan steps: G5 to G8. Code: `tools/backend_pin.json` (`strip`, `jlink`), `tools/build_backend_bundle.py` (`glob_regex`, `expand_strip_patterns`, `strip_tree`, `reduce_jdk`, `gate_*`, `gate_size`, `split_file`, `join_parts`), `tools/build_linux.py` (`FULL_SIZE_LIMIT`, `check_archive_size`).

## 1. Purpose and non-goals

Purpose: say exactly what the payload contains, what is removed and why, how the JDK is reduced, which sizes are acceptable, and how an oversized importer archive is split. Non-goals: processor stripping, replacing Ghidra's Java runtime, UPX or executable compression, a signed installer.

## 2. Definitions

- **Payload**: `backend/payload/{python,ghidra,jdk,LICENSES,SOURCES,config}`; `config/runtime-policy.json` is written by `write_runtime_policy`.
- **Strip rule**: a glob in `strip.ghidra`, `strip.ghidra_fid` or `strip.jdk`, matched against the component-relative POSIX path of every regular file. Glob dialect (`glob_regex`): `**/` any number of directories, `**` any characters, `*` within one path component, `?` one character; no character classes.
- **`{other-OS}`**: expanded by `expand_strip_patterns` to `linux_*` and `mac_*` for a Windows target, `win_*` and `mac_*` for a Linux target (native directories `os/<platform>_x86_64/`).
- **Keep gate** (`strip.keep`): globs that must still match at least one file after stripping if they matched one before (`PT-BUNDLE-STRIP`). A regression gate, not an override.
- **Protected list** (`strip.protected`, new in this spec): globs a strip rule must never match; checked before any file is deleted.
- **FID**: Function ID databases, `Ghidra/Features/FunctionID/data/*.fidbf` (10 Visual Studio databases, 204.1 MB uncompressed, 79.5 MB zipped; research table 5.1).
- **jlink runtime**: the JDK replaced by `jlink` output containing only the pinned module list.

## 3. Contract

### 3.1 Current strip configuration (VERIFIED in `tools/backend_pin.json`)

```
strip.ghidra     : docs/**, Extensions/**, **/os/{other-OS}/**, GPL/**,
                   Ghidra/Features/Base/data/typeinfo/golang/**, Ghidra/Features/Jython/**,
                   Ghidra/Features/BSim/**, Ghidra/Features/GhidraServer/**, Ghidra/Debug/**
strip.ghidra_fid : Ghidra/Features/FunctionID/data/*.fidbf        # appended unless keep_fid
strip.jdk        : lib/src.zip, jmods/**                            # no-op after jlink (the old tree is replaced)
strip.keep       : LICENSE, licenses/**, Ghidra/Processors/**, Ghidra/Features/**, legal/**, bin/javac*
jlink.modules    : java.base, java.desktop, java.xml, java.logging, java.datatransfer, java.management, java.sql,
                   java.naming, java.rmi, java.scripting, java.compiler, java.net.http, java.security.jgss,
                   java.prefs, java.instrument, jdk.unsupported, jdk.xml.dom, jdk.security.auth, jdk.net,
                   jdk.management, jdk.crypto.ec, jdk.zipfs, jdk.charsets, jdk.jdi, jdk.jshell, jdk.compiler
```
jlink flags (`JLINK_FLAGS`): `--strip-debug --no-man-pages --no-header-files --compress=zip-6`; invocation `jdk/bin/jlink[.exe] --module-path jdk/jmods --add-modules <comma list> <flags> --output <work>/jlink-runtime`.

### 3.2 What is removed and what is kept

| Removed | Size (uncompressed, Linux research) | Reason | Risk |
|---|---|---|---|
| `docs/**` | 105.6 MB | Javadoc, stubs | none |
| `Extensions/**` | 46.9 MB | Eclipse GhidraDev, BSim Elastic, examples | none headless |
| other-OS `os/` natives | about 9 MB | wrong platform | none |
| `GPL/**` | about 8 MB | policy: `ghidra-GPL-dir` not owner-approved; GNU demangler lost for non-PE | non-PE demangling only |
| `Features/Base/data/typeinfo/golang/**` | 96.2 MB | Go type info JSON | Go binaries only |
| `Features/Jython/**` | 75.9 MB | Jython scripting (PyGhidra uses CPython) | Jython scripts |
| `Features/BSim/**` | 36.5 MB | BSim server/client | BSim not used |
| `Features/GhidraServer/**` | 25.5 MB | shared-project server | not used |
| `Ghidra/Debug/**` | 24.9 MB | debugger | not used headless |
| FID `.fidbf` | 204.1 MB | library function identification | fewer library names on static CRT code (UNVERIFIED effect on kernel images) |
| JDK `jmods`, `src.zip`, unlisted modules | about 270 MB of 350 MB | jlink | missing module at run time (G8) |

Kept by rule: `LICENSE`, `licenses/**`, all `Ghidra/Processors/**` (26 MB; stripping saves little and risks loader errors), `Decompiler`, `PDB`, `Base`, `PyGhidra` (including `pypkg/dist` about 25 MB of wheels, harmless), `VersionTracking` (needed by Ghidriff's `VersionTrackingDiff`), `Framework`, `support/**`, JDK `legal/**` and root licence files (copied explicitly by `reduce_jdk`), `javac` via module `jdk.compiler`.

Measured by the research (Linux only, one small non-MSVC PE, no PDB): 847 MB as shipped, 394 MB after FID+typeinfo+docs+Extensions+other-OS, 234 MB after also Jython+BSim+GhidraServer+Debug; analysis output hashes identical at each step. A 26-module jlink image: 78 MB on disk, 52.3 MB gz, versus 346 MB. Windows numbers: UNVERIFIED (no run has exercised these rules; VERIFIED that the pin at run heads `4f56b9f` and `9fbeba9` lacks them).

### 3.3 FID decision

Default (VERIFIED in code): FID stripped; `build_backend(keep_fid=False)`; no CLI flag today. Contract after G7: `--keep-fid` on `build`, workflow boolean input `keep_fid` (default false), transported only via `env:`. The 2026-10-15 handoff recommendation "keep FID for the first prerelease" conflicts with the code; this spec makes "ship without FID, evidence the A/B" the default and leaves the flip to an owner decision with a measured result (same `read_item` match with and without; compare function-name coverage on a kernel image if one is available to the owner; Microsoft binaries must not be committed).

## 4. Algorithms

### 4.1 Strip (`strip_tree`)

```
files = sorted relative file paths under root
keepers = compile(keep globs); before[i] = any(keeper[i] matches some file)
rules = expand_strip_patterns(strip, target)       # + ghidra_fid unless keep_fid
for file in files: if any rule matches: delete file; removed.append(file); freed += size
remove empty directories bottom-up
for each keeper i: if before[i] and no remaining file matches: PT-BUNDLE-STRIP
```
New protected check (G7): before deleting, for every matched file `f` and protected glob `p`: if `p` matches `f` then `PT-BUNDLE-STRIP: strip rule <rule> would remove protected path <f>` and nothing is deleted. Note the keep gate alone is weak: `Ghidra/Features/**` still matches after Jython, BSim and GhidraServer are removed (VERIFIED by reading), so the protected list is what protects individual features.

### 4.2 jlink (`reduce_jdk`)

```
run jlink with the pinned module list      # PT-BUNDLE-TOOL on non-zero exit (tail of stderr)
require image/lib/modules is a file          # else PT-BUNDLE-JLINK
copy jdk/legal -> image/legal; copy root files matching ^(licen[cs]e|copying|notice) -> image/
rmtree(jdk); move image -> jdk
modes: on a Windows host every file under bin/ is 0755 and the rest 0644 (NTFS has no x bit; fix 0268517);
       on POSIX the mode comes from stat
```
Gate (`gate_pin`): `jlink.modules` must be a list of names matching `[a-z][a-z0-9.]*` including `java.base`.
Verification (G8): per Ghidra jar, `jdeps --multi-release 21 --ignore-missing-deps -summary -R --module-path jdk/jmods <jar>`; union of `java.*`/`jdk.*` must be a subset of the pin list, else `PT-BUNDLE-JLINK: modules required by Ghidra jars but missing from jlink.modules: [...]`. `jdk.compiler` is kept by choice (PyGhidra compiles a Java launcher plugin into the user settings directory when its jar is missing; removal untested).

### 4.3 Mode, path, size gates (order in `build_backend`)

1. `gate_modes(modes, target)` (Linux only): each of `ghidra/support/analyzeHeadless`, `ghidra/support/*.sh`, `ghidra/Ghidra/**/os/linux_x86_64/{decompile,sleigh*,demangler_gnu*}`, `jdk/bin/*`, `python/bin/*` must match at least one file and every match must have an execute bit (`PT-BUNDLE-MODE`).
2. `gate_paths(payload)`: SPEC-06 path policy for every path, casefold/NFC collisions, `MAX_RELATIVE_PATH = 150` characters counted from `payload/` (so the installed prefix stays under Explorer's 260), no symlinks or special files, file <= 2 GiB, files <= 60,000, total <= 8 GiB.
3. `gate_manifest_size`: estimated manifest size (about 190 bytes per file) must stay under the importer cap `policy.MAX_MANIFEST = 16 MiB`.
4. `apply_modes` (POSIX): directories 0755, files 0755 iff recorded executable else 0644.
5. After packaging, `gate_size` and (full builds) `check_archive_size`.

## 5. Error codes: complete `PT-BUNDLE-*` table

| Code | Side | Raised by | Meaning |
|---|---|---|---|
| `PT-BUNDLE-MISSING` | runtime | `backend_bundle`, `backend.py`, `build_linux.payload_problems` | no `backend/manifest.json` / file missing |
| `PT-BUNDLE-MANIFEST` | runtime, build | `_load_manifest`, `build_linux` | manifest malformed, too large, tree differs |
| `PT-BUNDLE-PLATFORM` | runtime | `_load_manifest` | bundle is for another OS |
| `PT-BUNDLE-SIZE` | runtime | `_fast_walk` | file size differs from manifest |
| `PT-BUNDLE-EXTRA` | runtime | `_fast_walk` | file not in manifest |
| `PT-BUNDLE-HASH` | runtime | `_hash_files` | full verification digest mismatch |
| `PT-BUNDLE-LINK` | runtime, build | many | symlink/junction/special file or unresolvable link |
| `PT-BUNDLE-WORKDIR` | runtime | `check_work_dir`, `_bundle_errors` | work/cache/temp path inside the install tree |
| `PT-BUNDLE-PIN` | build | `gate_pin`, `fetch_verified`, `rebuild_ghidriff_tarball` | pin refused or unresolved |
| `PT-BUNDLE-PIN-MISMATCH` | build | digests, Ghidra version, wheelhouse, `join_parts` | digest/size/version differs from the pin |
| `PT-BUNDLE-FETCH` | build | `download`, git fetch | network/HTTPS/redirect failure |
| `PT-BUNDLE-ARCHIVE` | build | `_Extractor`, `_extract_*` | unsafe archive member, layout, member count > 120,000, duplicate |
| `PT-BUNDLE-PATH` | build | `gate_paths`, `_guard_host_fs`, `build_windows` | name unsafe on NTFS or collides |
| `PT-BUNDLE-PATH-LENGTH` | build | `gate_paths`, `payload_problems` | relative path > 150 |
| `PT-BUNDLE-SIZE-LIMIT` | build | `gate_size`, `_Extractor.file`, `check_archive_size` | asset > 1.9 GiB, file > 2 GiB, too many files |
| `PT-BUNDLE-MANIFEST-SIZE` | build | `gate_manifest_size` | manifest estimate > 16 MiB |
| `PT-BUNDLE-MODE` | build | `gate_modes` | lost execute bit or pattern matched nothing |
| `PT-BUNDLE-STRIP` | build | `strip_tree` | strip removed a keep (or protected) path |
| `PT-BUNDLE-JLINK` | build | `reduce_jdk`, `gate_pin` | jlink failed or module list invalid |
| `PT-BUNDLE-TOOL` | build | `run_tool`, `install_wheels` | pip/jlink/compile subprocess failed |
| `PT-BUNDLE-WHEEL-MISMATCH` | build | `compare_wheel_to_source`, `build_wheel_from_source` | wheel differs from the source tarball |
| `PT-BUNDLE-PYTHON-MISMATCH` | build | `require_host_python` | builder Python minor differs from the bundle's |
| `PT-BUNDLE-OUT` | build | `build_backend` | output directory not empty |
| `PT-BUNDLE-LICENSE` | build | gates | licence file/policy failure |
| `PT-BUNDLE-SOURCE-DIGEST` (new) | build | build | quoted source digest differs from shipped bytes |
| `PT-BUNDLE-REPRO` (new) | CI | `repro-check` | two builds disagree |

Contradiction recorded: `src/patchtrace/backend_bundle.py` `CODES` lists only twelve of these (it includes four build-only ones); the table above is authoritative and `CODES` must be extended or documented as "runtime subset" (G12 housekeeping).

## 6. Size budgets and split parts

| Quantity | Value | Source |
|---|---|---|
| Hard release-asset gate | `ASSET_LIMIT` = `int(1.9 * 1024**3)` = 2,040,109,465 bytes; GitHub's limit is 2 GiB | `build_backend_bundle.ASSET_LIMIT`, `build_linux.FULL_SIZE_LIMIT` |
| Investigate threshold | `SIZE_WARN` = 1.2e9 bytes (warning) | builder |
| New budget (proposed) | full archive <= 700 MB, importer ZIP <= 700 MB: warning, failure with `--release` | this spec; research estimate stripB+jlink about 0.31 GB extracted Ghidra+JDK, about 0.15 GB zipped (HYPOTHESIS) |
| Members | <= 60,000 files in the manifest (`MAX_MEMBERS`); archive extraction bound 120,000 | offline_bundle, builder |
| Extracted size | <= 8 GiB total, <= 2 GiB per file | `MAX_TOTAL`, `MAX_FILE` |
| Relative path | <= 150 characters under `backend/` (install check refuses >= 248 on Windows) | `MAX_RELATIVE_PATH`, `install_offline_bundle` |
| Manifest | <= 16 MiB | `MAX_MANIFEST` |
| Observed (pre-B7, Windows, run 38676664372) | artifact `bundle-windows-assets` = 1,125,774,418 bytes holding three files; per-file sizes not logged | VERIFIED artifact size; per-file UNVERIFIED |

**Split parts** (importer ZIP only; `--split` is passed by both build steps): if the importer archive exceeds `asset_limit`, `split_file` writes `<name>.001`, `<name>.002`, ... each at most `asset_limit` bytes (1 MiB read chunks), deletes the original, and the builder writes `<name>.sha256` (whole-file digest of the **joined** archive, computed before splitting) plus `<name>.parts.sha256` (digest of each part). Rejoin: concatenate in numeric order (`cat name.zip.* > name.zip`, or PowerShell `Get-Content -Encoding Byte -ReadCount 0` is discouraged for size; use `copy /b name.zip.001+name.zip.002 name.zip`), then verify with the `.sha256`. `join_parts(parts, dest, expected_sha256)` deletes the output and raises `PT-BUNDLE-PIN-MISMATCH` on a wrong digest. The **full** archives (`PatchTrace-<ver>-windows-x64-full.zip`, `...-linux-x86_64-full.tar.gz`) are never split: above the gate the build fails with `split or fall back to lite + backend ZIP pair`. With the planned reductions the split path should never run; it is kept and tested for growth.

Recorded ~sha: every run must log the size and sha256 of each asset (build-report `sizes` and the `ls -l assets` listing already in the workflow) in `docs/qa.md` BUNDLE-5; no digest in this spec is a promise for a future build.

## 7. Determinism

Strip and jlink are deterministic given the inputs, except that `jlink` output embeds no timestamps with `--strip-debug` only if the JDK version is identical (HYPOTHESIS: the `lib/modules` image and `release` file may contain build time; the repro job in G15 decides; if not, exclude `jdk/lib/modules` from the byte comparison but compare `java --list-modules`).

## 8. Security invariants

1. Stripping never removes licences (`licenses/**`, `legal/**`, `LICENSE`) or the source offer files.
2. `GPL/**` stays removed unless `license_policy.ghidra-GPL-dir` is `shipped: true` and `owner_approved: true` (checked in four places: `check_backend_pin`, builder, `build_linux.license_problems`, notice).
3. The builder never executes a payload binary other than `jlink` and `pip`; `javac` is not run at build time.
4. No removal is accepted without an acceptance run on the same commit.

## 9. Test plan

Existing (VERIFIED names): `test_strip_rules_remove_docs_and_other_os_natives`, `test_strip_keep_gate_blocks_a_rule_that_removes_licences`, `test_strip_removes_fid_golang_jython_bsim_server_and_debug_but_keeps_the_core`, `test_keep_fid_pin_flag_retains_the_function_id_databases`, `test_jlink_replaces_the_jdk_with_the_pinned_module_set`, `test_pin_without_jlink_keeps_the_full_jdk`, `test_jlink_that_produces_nothing_fails_loudly`, `test_jlink_without_java_base_is_refused`, `test_lost_execute_bit_fails_the_linux_mode_gate`, `test_overlong_relative_path_fails_with_the_length_code`, `test_archive_above_the_asset_limit_fails_without_split`, `test_split_archive_parts_fit_the_limit_and_join_back`, `test_manifest_larger_than_the_importer_cap_fails_loudly`.
To add: `test_strip_rule_matching_a_protected_path_is_refused`, `test_committed_strip_list_matches_no_protected_path`, `test_keep_fid_cli_flag_reaches_build_backend`, `test_size_budget_is_enforced_only_in_release_mode`, `test_jlink_module_gap_is_reported`, `test_full_archive_is_never_split`.

## 10. Open questions

1. Is a 700 MB budget realistic on Windows? Default: measure in G5/G6 and set the budget to 120 percent of the first accepted size.
2. Keep or drop FID? Owner decision (default drop).
3. Do Windows MSVC kernel images need `PDB` helpers beyond `Features/PDB`? Kept, so unaffected.
4. Should `Ghidra/Features/FunctionGraph`, `Sarif` be stripped? Not proven; default keep.

## 11. Acceptance

One accepted run per OS with the committed strip/jlink pin; sizes recorded; protected-path test green; `PT-BUNDLE-STRIP`, `-JLINK` and `-MODE` have red tests; no code in the table lacks a test or a documented reason.
