# `patchtrace doctor`

Prints one health report of this PatchTrace installation. Run it first when something does not work, and attach its output to a bug report.

```
patchtrace doctor
patchtrace doctor --json
patchtrace doctor --bundle-dir DIR --work-dir DIR --profiles-dir DIR
```

Doctor starts no program and uses no network. It reads version numbers, looks at files and folders, and reports what it finds. It does not run the analysis runtime, so it cannot tell you that a comparison will succeed.

## Worked example

A source installation on Linux without an analysis runtime. Long paths are shortened here.

```text
> patchtrace doctor
ok              version: PatchTrace 0.1.0
ok              python: Python 3.12.3 (cpython, 64-bit, source install)
ok              platform: linux (posix), x86_64
ok              optional-deps: present=rapidfuzz=3.14.6,yara-x=1.21.0,iced-x86=1.21.0 missing=none
ok              cli-verbs: all 15 verb files load
not-applicable  bundle: no bundled runtime next to PatchTrace (no backend directory)
warning         runtimes: no Python and no Ghidra candidate found; comparing two files needs an analysis runtime, everything else works without one - remedy: install an offline runtime archive with `patchtrace runtime install-zip`, or set the paths in the desktop Setup dialog
ok              work-dir: ~/.local/state/patchtrace/work does not exist yet and can be created under ~
ok              profiles-dir: ~/.config/PatchTrace/profiles does not exist yet and can be created under ~
doctor: no problem found (7 ok, 1 warning, 0 problem, 1 not-applicable)
Not checked here because it starts the runtime: run `patchtrace backend diagnose` for a bundled runtime, or Diagnose dependencies in the desktop Setup dialog.
```

Each line is one check: its status, its name, what was found and, when something needs doing, a remedy.

## The checks

| Check | What it looks at | When it is not `ok` |
|---|---|---|
| `version` | The PatchTrace version. | - |
| `python` | The Python version, 32 or 64 bit, source install or packaged executable. | `problem` for a 32-bit interpreter. |
| `platform` | The operating system and processor type. | - |
| `optional-deps` | The optional packages for search and detection rules. | `warning` when one is missing. The features that need it say so; the remedy names the package group to install. |
| `cli-verbs` | Whether every command file loads. | `problem` when one cannot be loaded. |
| `bundle` | The runtime in the `backend` folder next to PatchTrace: every listed file is present with the right size. Files are not hashed here. | `not-applicable` without a `backend` folder. `problem` with a `PT-BUNDLE-` code when the folder is incomplete; see [troubleshooting](52-troubleshooting.md#bundle-verification-errors). |
| `runtimes` | Python and Ghidra installations in the known places, as **Find existing installations** in Setup does. | `warning` when none or only one kind is found, or when `PATCHTRACE_BACKEND_PYTHON` or `GHIDRA_INSTALL_DIR` is set and does not name a usable file or folder. |
| `work-dir` | Whether the per-user work folder can be written. | `problem` when it cannot. |
| `profiles-dir` | Whether the profile folder can be written. | `warning` when it cannot; profiles are optional. |

A runtime that doctor finds is a candidate, not a verified runtime. To check that it starts and has the right packages, run [`patchtrace backend diagnose`](63-cli-backend.md) for a bundled runtime, or **Diagnose dependencies** in **Setup**.

To test whether a folder can be written, doctor creates one unnamed temporary file in it and removes it at once. When the folder does not exist yet, the test runs in the nearest existing parent and the folder is not created. Nothing else is written.

## For scripts

`--json` prints one `enrichment-cli/1` document. `result.healthy` is the verdict, `result.checks` holds the same checks as the text (`id`, `status`, `detail`, `remedy`), and `result.facts` holds the values behind them: versions, optional packages, the runtime candidates as path lists, and the two folders.

| Exit code | Meaning |
|---|---|
| 0 | No check is a `problem`. Warnings do not change the exit code. |
| 2 | Wrong arguments. |
| 4 | At least one check is a `problem`. The report is complete; `result.healthy` is false. |
| 5 | Cancelled. |

The report contains local paths, which can include your user name. It contains no environment dump and no credential. Read it before you share it.

Desktop equivalent: none as one report. The parts are in **Setup**: **Find existing installations**, **Verify bundle files** and **Diagnose dependencies**.

Sources: `src/patchtrace/doctor_cli.py`, `src/patchtrace/cli_commands/doctor.py`, `src/patchtrace/runtime_discovery.py`, `src/patchtrace/optional_deps.py`, `docs/specs/cli-profile-doctor-runtime.md` section 3.
