# Calibration licences and redistribution rules (C9)

Status: draft, 2026-10-14. Owner: calibration integrator. Scope: every data source and tool that feeds label training, the Tier R corpus and the Tier W local corpus. Parent: `docs/specs/calibration-corpus-and-model.md` sections 3, 11 and 16 (O1). Companion: `docs/plans/c9-preregistration-v1.md`. This is an engineering reading of the recorded licence evidence, not legal advice. Decision O1 (owner) still governs anything about Microsoft-derived data.

Evidence used: `corpus/catalog/*.json` (`license_spdx`, `license_evidence`, with commit pins), `tools/calibration/tier_r/catalogue/releases.json`, `tools/calibration/tier_r/catalogue/recipes.json`, the allow-list `PERMISSIVE_SPDX` in `tools/calibration/tier_r/contracts.py`, the licence notes in `docs/specs/program-e/LBL-integration-plan.md` (note A and 7.3), `tools/calibration/guidelines/g1.md`, and the file headers of `tools/calibration/corpus.py` and `tools/calibration/tier_r/fetch.py`. Entries marked [unverified] were not read against a primary licence file in this pass.

## 1. Rules that apply everywhere

R1 Microsoft-derived material is never committed. This covers Microsoft binaries, PDBs, symbol maps, Winbindex-derived labels, Tier W labels and any Tier W report cell that names files, RVAs, hashes or KB numbers. Tier W stays on the owner's machine under `PATCHTRACE_CALIB_ROOT`, which must lie outside the work tree (`corpus.py guard`).

R2 The only Tier W output that may leave the owner's machine is the `tier-w-aggregate/1` file, with cells of at least 30 items, and only if the owner decides so (O1). Its Markdown rendering carries the banner "Derived from Microsoft binaries. Local only (O1). Review before quoting."

R3 Tier R: the repository holds source pins (URL, commit, licence-file SHA-256), build recipes, expected output SHA-256 values and our own suite sources. It does not hold third-party source copies or built binaries (`corpus/README.md`; spec 3.1). Built outputs may be cached only as CI artifacts.

R4 Permissive licences only, per `PERMISSIVE_SPDX` (`tools/calibration/tier_r/contracts.py`). Copyleft, unknown or unread licences are "do not use". Each upstream pin is re-read by its licence-file SHA-256 (`fetch.py` `license_sha256`); a changed licence file stops the fetch.

R5 External tools run as unmodified, separately installed processes. No code is copied from them. GPL or AGPL tools are never vendored, linked or bundled.

R6 Numeric model parameters trained on Tier W data ship only after the owner's review (spec 11, O1). Their derived form contains coefficients and thresholds only, never bytes or names.

R7 Notices: any third-party text that the repository does ship (for example a licence header copied into a fixture) keeps its notice. The packaged Windows application ships no calibration data or tools (spec 11).

## 2. Tier R upstream projects (catalogue set)

Permitted use for all rows: build from a pinned commit as a diff-engine test input, in CI and locally, and read the function-level truth from source. Redistribution of source copies or binaries: no. Commit of the pin, recipe and expected hashes: yes.

| Project | SPDX as recorded | Notes on the recorded licence |
|---|---|---|
| zlib, zlib-contrib-minizip | Zlib | licence header in `zlib.h` at each pin |
| libpng | Libpng-2.0 | `LICENSE` at each pin |
| miniz | MIT | |
| libdeflate | MIT | |
| lz4 | BSD-2-Clause | only `lib/` is BSD-2-Clause; `programs/`, `tests/` and `examples/` carry another licence and are not built (LBL note A) |
| libarchive | BSD-2-Clause | |
| curl | curl | the curl licence is on the allow-list |
| libsodium | ISC | |
| c-ares | MIT | |
| libssh2 | BSD-3-Clause | |
| openssl | Apache-2.0 | |
| mbedtls | Apache-2.0 | upstream is dual Apache-2.0 OR GPL-2.0-or-later; the elected licence is Apache-2.0 (LBL note A, spec 11 Q4). Record the election in the pin's receipt. |
| nghttp2, libuv, lua, cJSON, expat, jansson, libyaml | MIT | Lua text is in `lua.h`; libyaml licence in `License` |
| postgresql-libpq | PostgreSQL | **Blocked**: `PostgreSQL` is not in `PERMISSIVE_SPDX`, so the Tier R validator rejects this pin. Do not use it until the owner or integrator decides on the allow-list (open item 7). |
| libevent | BSD-3-Clause | |
| libwebp | BSD-3-Clause | |
| pcre2 | BSD-3-Clause (catalogue) | **Discrepancy**: LBL note A records `BSD-3-Clause WITH PCRE2-exception`. The catalogue value must be fixed to match the licence file before any pin is used. Until then the entry is "do not use". |
| stb | MIT | upstream reads `MIT OR Unlicense`; record MIT (spec 11 Q4) |

Used in label training today: `recipes.json` holds one recipe (zlib). The other recipes are planned under LBL-01 to LBL-03. The three excluded projects (sqlite3, bzip2, giflib) are not used: sqlite3 needs generated host tools, which the build must not execute; bzip2 and giflib had no verified pins.

## 3. Own suites (`corpus/ours/`)

| Item | Licence | Use and redistribution |
|---|---|---|
| Freestanding C suites written in this repository (`suite/1`) | MIT (`suite.json` `license_spdx`) | committed; the repository owns them; no third-party code copied into them (`corpus/README.md`) |
| `_template` suite and generated synthetic worlds | MIT, CC0-1.0 or Unlicense (allow-list in `tier_r/contracts.py`) | committed as source; generated binaries are not committed |

## 4. Tools and external components

| Component | Recorded licence | Role in label training or runs | Permitted use | May be committed? |
|---|---|---|---|---|
| Ghidriff | GPL-3.0 (its `LICENSE`) | engine run for Ghidriff candidates (symbols off) | run as an unmodified external process; use its output facts | No code, no binaries. Output facts may be stored as features. |
| Ghidra 12.0.4 | Apache-2.0 (`LICENSE`) | analysis backend for Ghidriff and the unified extraction | external process; installed by the user or the runner | No (distribution payload, JDK included) |
| rizin / rz-diff 0.9.1 | GPL-3.0 (`COPYING`) | engine run (`R`) and raw-byte baseline M0b | external process only; pinned SHA-256 assets | No |
| BinDiff 8 | Apache-2.0 (`LICENSE`) | engine run only from supplied BinExport pairs | external process only | No |
| BinExport / BinDiff outputs | derived from the above | `D_symbols`, `D_ghidra` features | outputs as facts | Only synthetic or Tier R outputs, as CI artifacts |
| capa 9.4.0, capa-rules, FLOSS 3.1.1 | Apache-2.0 (`LICENSE.txt`) | capability channel (LBL-13), not yet in label training | external process | No. Rule text is not vendored. |
| yara-x 1.21.0 | BSD (`LICENSE`) | rule channel (LBL-13), blocked until the YARA-X slice | pinned wheel, `--only-binary` | No binaries committed |
| LLVM / clang / clang-cl / opt / llvm-pdbutil | Apache-2.0 WITH LLVM-exception (`LICENSE.TXT`) | compilers for Tier R and the `opt` layer; `llvm-pdbutil` for Tier W symbol maps (local only) | installed toolchain, not redistributed | No |
| mingw-w64 gcc/clang | [unverified] | Tier R build toolchain (decision O6) | installed toolchain | No |
| MSVC `cl` and Windows SDK | Microsoft licence terms [unverified] | Tier R MSVC leg on the Windows runner (LBL-08); Tier W targets are Microsoft-built | runner-installed only; not redistributed | No. Outputs of third-party code are CI artifacts only. |
| Microsoft symbol server (PDB download) | terms read only in part; the quoted scope is "debugging and testing your software with Microsoft software" [unverified for full terms] | Tier W labels only (`pdb.used_for = labels-only`) | local only; the owner decides (O1) | No. PDBs and symbol maps are never committed. |
| Winbindex | GPL-3.0 reported; UNCONFIRMED (`corpus.py` header) | identity metadata for Tier W; no data vendored | fetch metadata at run time for the owner's local corpus only | No data, no copies |
| scikit-learn 1.9.1 | BSD-3-Clause (PyPI classifier) | optional `calibration-dev` extra for tests only | `pip --only-binary=:all:` | No. Not shipped. |
| universalmutator, python-Levenshtein | universalmutator: conflicting PyPI (MIT) and repository (Apache-2.0) notices; python-Levenshtein and Levenshtein 0.27.5: GPL-2.0-or-later | not used (rejected, LBL 1) | none | No |
| Mull | Apache-2.0 | rejected as a dependency (runtime-switched mutants, C++ plugin); taxonomy only | reference only | No |
| Diaphora, PatchDiff2, Turbodiff | recorded as references only | not run; no code copied | reference only | No |
| BinKit / TikNib, BinaryCorp, REFuSe-Bench, Assemblage, DeepHistory | UNCONFIRMED (no licence read) | not used for label training | do not use until the licence or data card is read (guideline g1) | No |

## 5. Tier W (Microsoft-derived, local only)

| Item | Rule |
|---|---|
| Binaries from Winbindex identity (`calibration-corpus/1` Tier W entries) | local only under `PATCHTRACE_CALIB_ROOT`; `redistribution: none`; hash-verified fetch that never executes the file (`corpus.py`) |
| Labels (`calibration-labels/1`, Tier W) | local only (default, O1); no names, RVAs, bytes or disassembly leave the machine |
| Symbol maps (`symbol-map/1`) and PDB-derived data | local only; `pdb.used_for = labels-only` |
| Aggregate (`tier-w-aggregate/1`) | export only at the owner's decision; cells under n = 30 suppressed; no names, RVAs, file hashes or KB numbers |
| Model parameters trained on Tier W | ship only after owner review (R6) |
| Enforcement | `corpus.py guard` fails on any PE/ELF image outside `tests/fixtures/` and on any work-tree file whose SHA-256 matches a Tier W manifest entry; a repository test runs it over tracked files |

## 6. Open items (owner or integrator)

1. O1 (owner): confirm the legal position on publishing Tier W labels and on shipping parameters derived from them. Until confirmed, R1 and R2 apply as written.
2. Fix the catalogue licence for `pcre2` (section 2) to match its licence file, or record the exception text.
3. Record the mbedtls election (Apache-2.0) in its pin receipt.
4. Read the licence files of BinKit, BinaryCorp, REFuSe-Bench, Assemblage and Winbindex before any of them is used (currently "do not use").
5. Read the full Microsoft symbol-server terms (owner, O1); the quoted scope above is partial.
6. Re-read the licence-file hash of every pin before a build (R4), as `fetch.py` already requires.
7. Allow-list gap: the catalogue records `PostgreSQL` for postgresql-libpq, which is not in `PERMISSIVE_SPDX`. Owner or integrator decides whether to add it (after reading its licence file) or drop the pin.
