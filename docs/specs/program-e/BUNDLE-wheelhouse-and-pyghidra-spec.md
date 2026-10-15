# BUNDLE wheelhouse: hash-locked, index-free installation and the PyGhidra 3.0.2 versus 3.1.0 decision

Status: approved for build (documents only). Date: 2026-10-15. Base commit: `54fd085`. Game plan: `docs/plans/backend-bundle-finish-gameplan.md` step G9. Code: `tools/build_backend_bundle.py` (`WheelRequirement`, `pip_platform_args`, `pip_install_argv`, `write_requirements`, `install_wheels`, `build_wheel_from_source`, `compare_wheel_to_source`, `compile_site_packages`), `tools/backend_pin.json` `wheels`, `tools/check_backend_pin.py` (`REQUIRED_DISTRIBUTIONS`, `_wheel_tag_ok`).

## 1. Purpose and non-goals

Purpose: the Python packages inside the bundle's private interpreter are exactly the pinned set, installed without an index, without dependency resolution, with every artifact hash-checked, and Ghidriff (GPL-3.0) is installed as a wheel built from, and byte-compared with, its source tarball. Also: decide which PyGhidra the bundle ships.
Non-goals: shipping `pip` to the user, runtime installs, virtual environments (an embedded interpreter with a `._pth` file is used), pure-Python vendoring of Ghidra's own `pypkg/dist` wheels.

## 2. Definitions

- **Wheelhouse**: the directory `.work/wheelhouse` filled by the builder with (a) verified wheels from the pin and (b) wheels built in this run.
- **Lock file**: `requirements.lock.txt`, lines `<distribution>==<version> --hash=sha256:<digest>`, written by `write_requirements`, LF, never committed.
- **Locked-by-pin**: wheel with a pinned PyPI digest (`kind: wheel`): `jpype1`, `pyghidra`, `packaging`.
- **Locked-by-source**: wheel built from a hash-verified source (`mdutils` sdist `kind: sdist-built-to-wheel`; Ghidriff from the canonical tarball). Their wheel digest is computed in the build and recorded in `THIRD-PARTY.json`; they are trusted through the source digest plus byte comparison.

## 3. Contract

Pinned set (VERIFIED in the pin):

| Distribution | Version | Lane | Kind | sha256 (pin) | SPDX |
|---|---|---|---|---|---|
| jpype1 | 1.5.2 | windows `cp312-cp312-win_amd64` | wheel | `c7b1c2d76d211cab60be16505d32a6b3c9fffc51ce79c68e81a3d48e5effff2d` | Apache-2.0 |
| jpype1 | 1.5.2 | linux `cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64` | wheel | `b5b1fb2b430a50f081ea0ee24d19232ae0d03dbfe3dd076ec5f8ae42b30a656f` | Apache-2.0 |
| pyghidra | 3.0.2 | any | wheel | `1bd49496e90d67b8aa06adeb3d80e0a5be6f5582f754e83625197a326772ebfe` | Apache-2.0 |
| packaging | 25.0 | any | wheel | `29572ef2b1f17581046b3a2227d5c611fb25ec70ca1ba8554b24b0e69331a484` | Apache-2.0 OR BSD-2-Clause |
| mdutils | 1.6.0 | any | sdist | `647f3cf00df39fee6c57fa6738dc1160fce1788276b5530c87d43a70cdefdaf1` | MIT |
| ghidriff | commit `4f5d895` | any | built from the tarball | tarball digest per the canonical-form spec | GPL-3.0 |

Cross-check (`ghidra_pypkg_crosscheck`, read 2026-10-14): Ghidra 12.0.4's own `pypkg/dist` carries `pyghidra-3.0.2-py3-none-any.whl` (sha256 `8a24363632998a25c26052ced504f1937d0bad2ed22970e014a87c97933434b9`, same 50,728 bytes, identical members, different zip container so a different file digest), the identical `jpype1-1.5.2` and `packaging-25.0` wheels. `mdutils` is not in Ghidra's directory.

Installation contract (VERIFIED in `pip_install_argv`): `python -I -m pip install --no-index --find-links <wheelhouse> --no-deps --only-binary=:all: --require-hashes --no-compile --target <site> --platform <win_amd64 | manylinux_2_17_x86_64 + manylinux2014_x86_64> --python-version 3.12 --implementation cp --abi cp312 -r requirements.lock.txt`, run with a scrubbed environment (`PIP_CONFIG_FILE=<devnull>`, `PIP_NO_INPUT=1`, `PIP_DISABLE_PIP_VERSION_CHECK=1`, `PIP_NO_INDEX=1`, `PYTHONDONTWRITEBYTECODE=1`, `SOURCE_DATE_EPOCH` defaulting to 315532800; kept: `PATH`, `SYSTEMROOT`, `TEMP`, `TMP`, `TMPDIR`, `HOME`, `USERPROFILE`, `LANG`, `LC_ALL`, `COMSPEC`, `PATHEXT`). After installation: each `<dist>-<version>.dist-info` must exist (case-insensitive) or `PT-BUNDLE-TOOL`, and `bin/` / `Scripts/` stub directories are deleted (their launchers embed the builder's absolute interpreter path).

Target directories: Windows `payload/python/Lib/site-packages`, interpreter `python/python.exe`, `python312._pth` = `python312.zip\n.\nLib/site-packages\nimport site\n` (LF, ASCII); Linux `payload/python/lib/python3.12/site-packages`, interpreter `python/bin/python3`. At run time the app starts `python -I -X utf8 -m ghidriff` (the `._pth` file also disables `PYTHONPATH`, `PYTHONHOME`, registry and user site on Windows).

Bytecode: `compileall.compile_dir(site, invalidation_mode=UNCHECKED_HASH)` so a read-only tree never writes `.pyc`; requires the builder's Python minor to equal the bundle's (`PT-BUNDLE-PYTHON-MISMATCH`, the workflow uses `actions/setup-python` 3.12).

## 4. Algorithms

### 4.1 Build wheel from source (`build_wheel_from_source`)

```
extract tarball/sdist (link-free extractor; PT-BUNDLE-ARCHIVE on unsafe members) into work/src/<dist>
python -I -m pip wheel --no-deps --no-index --no-build-isolation --wheel-dir work/built/<dist> work/src/<dist>
require exactly one wheel and name  <dist>-<ver>-py3-none-any.whl       # else PT-BUNDLE-WHEEL-MISMATCH / PT-BUNDLE-TOOL
compare_wheel_to_source(wheel, src, package):
   for every non-dist-info file in the wheel: bytes must equal src/<package>/... (or src/src/<package>/...)
   for every *.py of the package in the source: it must be in the wheel
   at least one file compared
```
`--no-build-isolation` requires `setuptools`/`wheel` in the builder's interpreter and needs no network (the builder environment sets `PIP_NO_INDEX=1`).

### 4.2 Lock verification

Before pip runs, `install_wheels` re-hashes every wheelhouse file against the lock (`PT-BUNDLE-PIN-MISMATCH: wheelhouse file X does not match its lock hash`); pip's `--require-hashes` checks again.

### 4.3 Dependency closure test (new)

For each locked wheel read `*.dist-info/METADATA`; every `Requires-Dist` without an `extra ==` marker and with a marker valid for CPython 3.12/win32|linux must be satisfied by a locked distribution at an acceptable version (use `packaging.requirements`). Expected: `pyghidra 3.0.2` requires `jpype1==1.5.2` and `packaging`; `ghidriff` requires `pyghidra>=3.0.0,<4` and `mdutils==1.6.0` (VERIFIED in the pin `requires`). Failing closure raises `PT-BUNDLE-PIN: unpinned dependency <name>`.

## 5. PyGhidra 3.0.2 versus 3.1.0

Facts: PyPI has 3.1.0 (2026-05-14) and 3.0.2 (2026-01-15) (parent plan section 2, retrieved 2026-10-14). Ghidra 12.0.4 ships 3.0.2 and `MINIMUM_GHIDRA_VERSION = "12.0"`. Ghidriff at `4f5d895` accepts `>=3.0.0,<4`. The live CI lane installs PyGhidra unpinned, so it may run 3.1.0 (the resolved version of the recorded CI run is UNVERIFIED; `ci_lane_freeze.status = unverified`). JPype1 is pinned to 1.5.2 because PyGhidra 3.0.0 pinned it to avoid a Windows crash with 1.6.0 (handoff section 5).

Decision procedure:
1. Default: ship **3.0.2** (the vendor-matched version).
2. Candidate test: a candidate pin file `tools/backend_pin.pyghidra31.json` identical to the main pin except `pyghidra` = 3.1.0 with its PyPI digest (`kind wheel`, `digest_source pypi-json`) and any new `Requires-Dist` pinned; build and accept both OS with workflow input `pin_file`.
3. Compare: acceptance JSON passes in both; the Ghidriff result JSON for the fixture pair has the same matched/modified function sets (normalise volatile fields such as timestamps and paths); runtime of `ghidriff-compare` within 20 percent.
4. Adopt 3.1.0 only if (a) 3.0.2 fails an acceptance step that 3.1.0 passes, or (b) the owner wants parity with the CI lane; otherwise keep 3.0.2 and pin the CI lane to 3.0.2 so both agree (`.github/workflows/live-backend.yml` change, separate PR).
5. Record the decision in `docs/plans/owner-decisions-<date>.md` and in `jdk_decision`-style `pyghidra_decision` pin note.

Open risk: PyGhidra locates the JDK through `JAVA_HOME_OVERRIDE` (set by the app in bundle mode: VERIFIED in `backend.py` line 202) and otherwise runs bare `java` from `PATH` and writes `lastrun`/Extensions into the settings directory; the app points `XDG_CONFIG_HOME` to a per-run scratch directory.

## 6. Error codes

`PT-BUNDLE-PIN` (unresolved/unpinned), `PT-BUNDLE-PIN-MISMATCH` (wheelhouse hash), `PT-BUNDLE-TOOL` (pip failure; the message tail contains pip's own `THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE` when pip refuses a hash), `PT-BUNDLE-WHEEL-MISMATCH` (built wheel differs), `PT-BUNDLE-PYTHON-MISMATCH`.

## 7. Determinism

Wheel builds use `SOURCE_DATE_EPOCH`; `setuptools` embeds file mtimes in wheel zip entries, so wheel file digests are **not** compared across builds, only member contents (`compare_wheel_to_source` and the repro job compare installed file bytes). `.pyc` files use unchecked-hash mode and are deterministic for one CPython build. The lock file lists distributions in a fixed order (lane first, then `any`, then built wheels).

## 8. Security invariants

1. No network access during install (`--no-index`, `PIP_NO_INDEX=1`, no proxy variables in the child environment).
2. No dependency resolution (`--no-deps`): an unpinned transitive dependency fails the closure test instead of being fetched.
3. No sdist build for third-party code except `mdutils` and Ghidriff, both hash-verified; no build backend downloads (`--no-build-isolation`).
4. No console-script stubs that embed absolute builder paths.
5. The GPL Ghidriff wheel is unmodified: the wheel's files equal the tarball's files.

## 9. Budgets

Site-packages under 120 MB (JPype natives dominate); install step under 2 minutes; wheelhouse download total about 1 MB.

## 10. Test plan

Existing (VERIFIED names): `test_pip_install_is_hash_locked_wheels_only_and_index_free`, `test_requirements_file_lists_every_wheel_with_a_hash`, `test_pip_platform_args_windows_and_linux`, `test_downloads_stay_inside_the_pin_and_site_packages_are_complete`, `test_wheel_not_byte_equal_to_the_tarball_fails`, `test_binary_tagged_built_wheel_fails`, `test_real_pip_installs_a_hash_locked_wheel_offline`, `test_real_wheel_build_from_a_source_tarball_is_byte_compared`, `tests/test_backend_pin.py::test_every_dependency_closure_member_pinned_per_lane`, `::test_ghidriff_requirements_match_the_pins`.
To add: `test_requires_dist_closure_of_locked_wheels`, `test_pin_file_input_is_regex_validated_and_not_shell_interpolated`, `test_pyghidra_decision_note_exists_in_the_pin`.

## 11. Open questions

1. Does pyghidra 3.1.0 change the launcher's JDK discovery (`JAVA_HOME_OVERRIDE`) or the `javac` plugin compilation? UNVERIFIED; read the 3.1.0 `launcher.py` before the A/B.
2. Should the bundle also carry Ghidra's own `pypkg/dist` PyGhidra wheel as a second source? Default: no.
3. Windows long-path handling of the `jpype` natives under `Patch Trace é中`-style paths is exercised by acceptance only.

## 12. Acceptance

The lock is regenerated from the pin and equals the build's `requirements.lock.txt`; the closure test passes; the decision record exists with A/B evidence or an explicit statement that 3.0.2 was kept by default.
