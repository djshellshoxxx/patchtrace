# BUNDLE reproducibility: what is deterministic, what is not, and the double-build check

Status: approved for build (documents only). Date: 2026-10-15. Base commit: `54fd085`. Game plan: `docs/plans/backend-bundle-finish-gameplan.md` step G15. Code: `tools/build_backend_bundle.py`, `tools/verify_backend_pins.py`, `tools/build_windows.py`, `tools/build_linux.py` (`write_tar_gz`, `attach_backend`, `build_provenance`), `src/patchtrace/offline_bundle.py` (`build_offline_bundle`).

## 1. Purpose and non-goals

Purpose: an auditor can rebuild the payload from the pin and the commit and obtain the same file inventory (paths, sizes, SHA-256), and the project states honestly which artifacts are not byte-reproducible. Non-goals: bit-for-bit reproducible PyInstaller output, reproducible compression across zlib builds, reproducibility of third-party vendor archives (they are pinned by hash instead).

## 2. Definitions

- **Reproducible layer**: a value that is a pure function of (commit, pin, `SOURCE_DATE_EPOCH`).
- **Inventory**: sorted list of `(path, size, sha256)`; the manifest is its canonical JSON.
- `SOURCE_DATE_EPOCH` (SDE): seconds since the epoch; the builder passes it to pip/setuptools (default `315532800`, 1980-01-01, VERIFIED `run_tool`) and uses it for `built_at` when set (`_utc_text`).

## 3. Contract: layers

| Layer | Reproducible? | Mechanism (VERIFIED unless noted) |
|---|---|---|
| Downloaded components | yes, by hash | `fetch_verified` re-hashes every use |
| Ghidriff source tarball | yes, after the canonical writer (G2); **no today across zlib builds** | normalised tar + zlib-independent gzip (canonical-form spec) |
| Wheels from sdist/tarball (mdutils, ghidriff) | members yes; wheel file bytes no (zip mtimes) | `compare_wheel_to_source`; do not compare wheel digests |
| Installed site-packages | yes for the same CPython/pip | `--target`, `--no-compile`, stubs removed, `compileall unchecked-hash` |
| Strip result | yes | sorted globs on sorted file lists |
| jlink image | UNVERIFIED (`lib/modules` and `release` may embed build info) | compare `java --list-modules`; decide by experiment |
| `manifest.json` | yes if the inventory is equal | records sorted by path, `json.dumps(sort_keys=True, separators=(',',':'))` |
| `THIRD-PARTY.json`, `NOTICE.txt` | yes with SDE set | sorted keys; `built_at` from SDE; `git_commit` from `GITHUB_SHA` |
| Importer ZIP | member contents yes; bytes only for one zlib build | sorted members, date 1980-01-01, `external_attr 0o100644`, deflate level 6 (zlib-dependent) |
| Full Windows zip | **no** | `shutil.make_archive` keeps filesystem mtimes and directory order |
| Full Linux tar.gz | **no** | `write_tar_gz` sorts entries and zeroes owners/modes but keeps mtimes; gzip mtime 0 |
| `build-provenance.json` | no (`built_at` = now) | add `source_date_epoch`, derive `built_at` from it |
| PyInstaller lite app | no | documented non-goal |

The workflow today never sets `SOURCE_DATE_EPOCH` (VERIFIED by grep of `.github` and `tools`).

## 4. Algorithms

### 4.1 Normalised archives (G15)

Windows zip writer: walk `package` in sorted POSIX order, directories first by path, `ZipInfo(name, date_time=from SDE clamped to >= 1980)`, `external_attr` `(0o100755 or 0o100644) << 16` for files, `0o040755 << 16` for directories, `compress_type=ZIP_DEFLATED`, level 6; no extra fields. Linux tar: `tar_filter` additionally sets `info.mtime = SDE`; `format=PAX_FORMAT` with no pax time headers (`PAX_FORMAT` adds `mtime` records only for non-integer times: assert none).

### 4.2 Double build check (job `repro-check`, ubuntu-latest)

```
checkout; setup-python 3.12; export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
build payload A into dir A (cache dir shared to avoid re-downloads, hash-verified anyway)
build payload B into dir B (fresh output dir, fresh work dir)
compare manifest.json bytes A == B
compare the sorted (path, size, sha256) lists; report first 20 differences
exclude by explicit list ONLY: jdk/lib/modules, jdk/release (if the jlink experiment shows build info) - then compare 'java --list-modules'
write repro-report.json; fail with PT-BUNDLE-REPRO listing differences
```
Windows payload comparison runs the same on `windows-latest` as an optional job (cost: 5 minutes plus downloads).

### 4.3 Sorting and fixed mtimes

Anything that enumerates the filesystem must sort (`os.walk` + `names.sort()`, `sorted(entries)`, `records.sort(key=path)` are present; `_tree_files` returns sorted). Fixed times: tarball members `315532800`, importer ZIP `1980-01-01 00:00:00`, gzip header mtime `0`, pip/setuptools SDE.

## 5. Error codes

`PT-BUNDLE-REPRO` (new): `PT-BUNDLE-REPRO: manifest.json differs between builds: payload/python/Lib/site-packages/mdutils/__pycache__/x.cpython-312.pyc sha256 <a> vs <b>`. Existing related: `PT-BUNDLE-PIN-MISMATCH`, `PT-BUNDLE-WHEEL-MISMATCH`.

## 6. Determinism risks and mitigations

1. `.pyc` hash-based invalidation embeds the source hash only (unchecked-hash writes flags and the hash, not mtime) - stable for one CPython build; the builder pins the minor version, the workflow pins 3.12 (the exact patch may drift: record `sys.version` in the report).
2. Windows host paths in `dist-info/RECORD`: pip writes relative paths; the console-script stubs, which embed absolute paths, are deleted.
3. Directory iteration order differs between NTFS and ext4: all enumerations sorted.
4. Line endings: `core.autocrlf=false` for git operations; `.gitattributes` pins LF for the pin and locked files.
5. Locale/time zone: `LANG`/`LC_ALL` kept only as passed; no time-zone dependence in outputs (`datetime.UTC`).

## 7. Security invariants

Reproducibility checks never download anything unverified, never publish, and never relax a digest gate. A differing inventory blocks release.

## 8. Budgets

`repro-check` <= 25 minutes; report < 1 MB; no additional release assets.

## 9. Test plan

Add: `test_full_zip_is_byte_identical_for_two_builds_of_the_same_tree`, `test_tar_gz_member_mtimes_equal_source_date_epoch`, `test_two_payload_builds_have_equal_manifest_bytes` (fake components), `test_built_at_comes_from_source_date_epoch`, `test_workflow_sets_source_date_epoch_from_the_commit`, `test_repro_report_names_the_first_differences`. Existing: `tests/test_offline_bundle.py::test_producer_is_byte_deterministic_across_distinct_destinations`, `tests/test_build_full_variants.py::test_tar_gz_modes_owners_and_determinism`, `tests/test_verify_backend_pins.py::test_rebuild_is_deterministic_across_commit_dates`.

## 10. Open questions

1. Is jlink output reproducible for one JDK build? Run the experiment in G15 before excluding anything.
2. Should the full zip be re-packed from the importer inventory so one writer serves both? Default: no.
3. Publish `repro-report.json` with the release? Default: attach to the run only.

## 11. Acceptance

`repro-check` green on Linux with an empty exclusion list or a justified, tested one; archives written by the normalised writers are byte-identical for two builds of one tree; docs state that PyInstaller output and zlib-dependent compression are not claimed reproducible.
