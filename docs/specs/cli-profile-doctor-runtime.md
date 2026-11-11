# CLI configuration, health and offline-runtime verbs: `patchtrace profile`, `patchtrace doctor`, `patchtrace runtime`

Status: implementation contract, 2026-11-11 (slice CLI-C). Built in the same commit series: `enrichment/profile_cli.py`, `doctor_cli.py`, `runtime_cli.py` and their registry adapters `cli_commands/{profile,doctor,runtime}.py`. Owner specs of the wrapped services stay authoritative: `enrichment.md` section 12 (profiles), `runtime-discovery.md` (SPEC-05), `offline-backend-installer.md` (SPEC-06), BUNDLE plan section 7 (bundle fast check). This file supersedes the `doctor` row of `cli-umbrella.md` section 7 ("not in alpha"); the umbrella itself is edited by its owner.

Evidence class of the tests: hermetic and synthetic. Profiles are small JSON files in a temporary directory; runtime archives are the stub archives of `tests/test_offline_bundle.py` (text files named like a runtime, never an operational Python, Java or Ghidra); discovery and the bundle check run over temporary directories and an injected environment. None of it is live evidence that an installed runtime can compare two binaries.

## 1. Common rules

- One registry adapter per verb (`cli_commands/<verb>.py`, at most 25 lines, feature imported inside `build` and `run`) over a Qt-free dispatcher. `cli.py` and `cli.COMMANDS` are unchanged. No path of the three verbs imports Qt or `patchtrace.ui`.
- Output: the `enrichment-cli/1` envelope through `emit`. With `--json` stdout carries exactly one document; `command` is `profile <leaf>`, `doctor` or `runtime <leaf>`. Each `result` names its own shape in `contract` (`profile-cli/1`, `doctor/1`, `runtime-cli/1`); these change additively only.
- Exit codes: 0 success; 2 invalid arguments, environment or a refused input file (raised as `CliError`, so `--json` carries `status: failed` and `error`); 3 runtime or storage failure, or a partial result; 4 the command worked and has no positive result; 5 cancelled. Per-leaf tables below.
- No verb prompts, reads stdin, starts a process, opens a socket or executes anything found in an input. Confirmation is a flag (`--confirm`); without it the destructive leaf exits 2 and changes nothing.
- Text that comes from an input file (profile field names in validation messages, archive names) is bounded and escaped before it is printed; a refusal reason is cut to 400 characters.

## 2. `patchtrace profile`

Headless management of the analysis profiles of `enrichment.md` section 12. Wraps `enrichment.profiles` (`ProfileStore`, `load_file`, `build`, `resolve`, `profile_digest`, `default_profiles_dir`) without changing it. That module imports pydantic and no Qt (checked: `import patchtrace.enrichment.profiles` loads no `PySide6` module).

Every leaf takes `--profiles-dir DIR` (default: `default_profiles_dir()`, the directory the desktop uses when its settings are not file-backed) and `--json`. A `--profiles-dir` that exists and is not a directory exits 2. A profile file is untrusted input: it is read through `load_file` (at most 64 KiB, strict `profile/1` model, unknown keys and coerced values refused) and must be a regular file; a refusal exits 2 with one line.

| Leaf | Does | Writes |
|---|---|---|
| `profile list` | The built-in `default` first, then every stored profile by name (case-insensitive order): name and digest. A stored file that does not validate is reported as a warning and under `result.invalid`; valid profiles are still listed. At most 1,000 stored names are read; more sets `result.truncated` and a warning. | nothing |
| `profile show NAME\|FILE` | One profile and its digest. The argument is a file when it ends in `.json` or contains a path separator (the rule of `--profile`), otherwise a stored name; `default` is the built-in. `result.source` is `built-in`, `stored` or `file`. | nothing |
| `profile validate FILE` | Validates a file without storing it: name, digest, and whether the name is reserved (`default`) or already stored (`result.name_taken`; each is also a warning). | nothing |
| `profile save FILE [--name NAME] [--force]` | Validates FILE and stores it as `<name>.json` (atomic write by `ProfileStore.save`). `--name` stores it under another name (validated by the same model). A name that is already stored, compared case-insensitively, is refused without `--force`; with `--force` the stored profile is replaced, including one whose name differs only in case. The name `default` is always refused. | `<profiles-dir>/<name>.json` (the directory is created when missing) |
| `profile delete NAME --confirm` | Deletes one stored profile. Without `--confirm` it exits 2 and says what would be deleted. `default` cannot be deleted. | removes `<profiles-dir>/<NAME>.json` |

Result fields (`contract: profile-cli/1`): `list` - `profiles_dir`, `profiles` (`name`, `digest`, `builtin`), `invalid` (strings), `truncated`; `show` - `source`, `name`, `digest`, `profile` (the `profile/1` document); `validate` - `valid` (always true in a success document), `name`, `digest`, `reserved`, `name_taken`; `save` - `name`, `digest`, `path`, `replaced`; `delete` - `name`, `deleted`.

Text output: `list` prints one line per profile, `<name>  <digest>` with `(built-in)` after the default; `show` prints the profile JSON exactly as it is stored, then `digest: <digest>`; the other leaves print one sentence.

| Leaf | 0 | 2 | 3 | 4 |
|---|---|---|---|---|
| list | all stored files are valid | bad `--profiles-dir` | at least one stored file is invalid (`status: partial`; the valid ones are still printed) | - |
| show | found and valid | unknown name, invalid name, unreadable or invalid file | - | - |
| validate | valid | missing, not a regular file, over 64 KiB, or refused by the model | - | - |
| save | stored | invalid file or `--name`; reserved name; name taken without `--force` | the directory or file cannot be written | - |
| delete | deleted | no `--confirm`; invalid name; `default` | the file cannot be removed | no stored profile has that name (`status: no-results`) |

Not done: no profile is selected for the desktop (the selected name lives in QSettings, `app-settings.md`), no secret can be stored (the model has no such field), and the profile's `cache_dir` is shown but never created or checked.

## 3. `patchtrace doctor`

One health report that needs no process and no network: `patchtrace doctor [--json] [--bundle-dir DIR] [--work-dir DIR] [--profiles-dir DIR]`. The three directory flags override the defaults (the directory of a frozen executable or `PATCHTRACE_BUNDLE_DIR`; `runtime_discovery.bundle_work_dir()`; `default_profiles_dir()`) so the report is testable and usable for a portable layout.

`result` (`contract: doctor/1`): `healthy` (no check is a `problem`), `summary` (count per status), `checks` and `facts`. A check is `{id, status, detail, remedy}` with `status` one of `ok`, `warning`, `problem`, `not-applicable`; `detail` and `remedy` are one line each and `remedy` is empty when nothing needs doing. Checks are always present and in this order:

| id | Source | ok | warning | problem | not-applicable |
|---|---|---|---|---|---|
| `version` | `patchtrace.__version__` | always | - | - | - |
| `python` | `sys.version_info`, implementation, pointer width, frozen or source | 64-bit | - | a 32-bit interpreter (the analysis runtime and the limits assume 64-bit) | - |
| `platform` | `sys.platform`, `os.name`, machine from `os.uname()` or `PROCESSOR_ARCHITECTURE` (the `platform` module is not used: it can start `uname`) | always | - | - | - |
| `optional-deps` | `optional_deps.probe()`; `detail` is `optional_deps.summary_line()` | all present | one or more missing (the features that need them say so; remedy names the pip extra) | - | - |
| `cli-verbs` | `cli_commands.discover()` | every verb file loads | - | a verb file cannot be loaded (module and exception class) | - |
| `bundle` | `runtime_discovery.check_bundle` (fast check: file presence, type and size; no hashing, no process) | fast check ok | - | a `backend` directory exists and fails (first `PT-BUNDLE-` code) | no `backend` directory next to PatchTrace |
| `runtimes` | `runtime_discovery.discover_local_runtimes` | at least one Python and one Ghidra candidate | none or only one kind found; or `PATCHTRACE_BACKEND_PYTHON` / `GHIDRA_INSTALL_DIR` is set and was not accepted as a candidate | - | - |
| `work-dir` | writability probe of the per-user work directory | writable, or absent and creatable | - | not writable | - |
| `profiles-dir` | writability probe of the profiles directory | writable, or absent and creatable | not writable (profiles are optional) | - | - |

A discovered candidate is not a verified runtime: `runtimes` says so in its detail, and the report ends by pointing to `patchtrace backend diagnose` (bundled runtime) or the desktop's Setup > Diagnose dependencies for the checks that start the runtime. Doctor never calls `backend.diagnose`. A missing runtime is a warning, not a problem, because PatchTrace stays usable without a backend (import of existing results, ranking, reports).

Writability probe: for an existing directory one unnamed temporary file is created in it and removed at once (`tempfile.TemporaryFile`); for a missing directory the same probe runs in the nearest existing ancestor and the directory itself is not created. Nothing is left behind; the directory tree is identical before and after.

`facts`: `version`; `python` (`version`, `implementation`, `bits`, `frozen`); `platform` (`system`, `os`, `machine`); `optional_deps` (list of `name`, `extra`, `available`, `version`); `verbs` (`loaded` count, `failed` map of module to exception class); `bundle` (null, or `runtime_id`, `ok`, `code`, `files`, `bytes`); `runtime_candidates` (`python`, `ghidra`, `bindiff`, `bundle_roots` path lists and `verified: false`); `directories` (`work`, `profiles`). The report contains local paths (they are what `--python` and `--ghidra-dir` take); it contains no environment dump and no credential.

Text output: one line per check, `<status>  <id>: <detail>` followed by ` - remedy: <remedy>` when there is one, then a verdict line and the pointer to the process-starting diagnosis.

Exit codes: 0 no check is a problem (warnings never change the exit code; `status: complete`); 4 at least one check is a problem (`status: no-results`); 2 invalid arguments; 5 cancelled during the bundle walk. Why 4 and not 3: in the contract 3 means the command itself failed and 4 means it worked and has no positive result. Doctor that finds a problem has worked; the positive result it could not report is a healthy installation. This is the reading `backend selftest` already uses when its expectation is not met. A script reads `result.healthy` or the per-check `status` for more than the verdict.

## 4. `patchtrace runtime`

The offline backend archive of SPEC-06 from the command line. Wraps `offline_bundle.inspect_offline_bundle` and `install_offline_bundle` only; the archive rules, limits and the `PT-OFFLINE` / `PT-CANCEL` codes are theirs and no code is added.

`patchtrace runtime inspect-zip FILE [--sha256 HEX] [--json]` - read-only. Verifies the archive exactly as the desktop does before it offers installation (archive digest, strict manifest, every member's size and SHA-256, path and ZIP safety rules) and reports `archive` (file name), `sha256`, `sha256_expected`, `sha256_matched` (null without `--sha256`), `runtime_id`, `platform`, `architecture`, `versions`, `files`, `bytes`, `python`, `ghidra`, `java` (paths inside the installed runtime), `host_platform`, `installable_here` and `authenticity`. Archives for either supported platform (`windows`, `linux`) are inspected; `installable_here` says whether the platform is this host's.

`patchtrace runtime install-zip FILE --sha256 HEX --confirm [--runtimes-dir DIR] [--json]` - installs the runtime under `<runtimes-dir>/<runtime id>/`.

- `--sha256` is required for installation: the SHA-256 of the archive obtained from a source the user trusts. It is checked before the archive is parsed. It proves integrity only (the archive is the one the digest was computed from), not who published it; the output repeats this (`authenticity`). Upper-case hexadecimal is accepted and compared in lower case.
- `--confirm` is required; without it nothing is read or written and the command exits 2.
- `--runtimes-dir` defaults to the per-user directory that runtime discovery scans: `%LOCALAPPDATA%\PatchTrace\runtimes` on Windows (the desktop's installation directory), `$HOME/.local/share/patchtrace/runtimes` elsewhere. When the variable is unset the flag is required. It must be absolute. (The slice card spelled this flag `--work-dir`; that name already means the backend's scratch directory in `patchtrace backend`, a different directory, so the flag is named after `install_offline_bundle(plan, runtimes_root)`.)
- Only an archive for this host's platform is installed (`backend_bundle.host_platform()`); another platform's archive is refused at inspection.
- An already installed runtime id is never overwritten: the command exits 2 and changes nothing.
- Result: `runtime_id`, `platform`, `root`, `python_executable`, `ghidra_dir`, `java_home`, `manifest`, `archive_sha256`, `files`, `bytes`, `authenticity`. The text output adds the next step: installation is not a compatibility check; diagnose the runtime before relying on it.

| Leaf | 0 | 2 | 3 | 5 |
|---|---|---|---|---|
| inspect-zip | archive verified | FILE is not an existing regular file; malformed `--sha256`; the archive is refused (`PT-OFFLINE: ...`: digest differs, manifest, member hash or size, unsafe path, unsupported platform) | - | cancelled (`PT-CANCEL`) |
| install-zip | runtime published | as inspect-zip; missing `--sha256` or `--confirm`; relative or undeterminable `--runtimes-dir`; archive for another platform; runtime id already installed | the installation was refused or failed after inspection (`PT-OFFLINE: ...`: destination not allowed, link in the destination, lock present, disk space, archive changed after inspection, I/O failure) | cancelled (`PT-CANCEL`) |

The refusal text always starts with the service's code (`PT-OFFLINE` or `PT-CANCEL`), on stderr and in the `error` field of the `--json` envelope. The rule behind 2 versus 3: 2 is decided before anything is written (arguments and the inspected input), 3 is a refusal or failure of the installation step.

Nothing is left behind on refusal, failure or cancellation: the service removes its staging directory and lock, and the command removes the directories it caused to be created (`--runtimes-dir` and missing parents) when they are still empty, so the directory tree is the one from before the call. A staging directory that cannot be removed is named in the error by the service and is left for manual review (SPEC-06 section 6).

Not done: no download, no execution of anything in the archive, no change to desktop settings (the desktop reads its runtime paths from QSettings; use the printed paths with `--python` / `--ghidra-dir`, or let Setup > Find existing installations pick the runtime up), no removal of an installed runtime, no repair of a stranded staging directory.

## 5. Help pages and tests

Help: `docs/help/81-cli-profile.md`, `82-cli-doctor.md`, `83-cli-runtime.md`, linked from `docs/help/README.md`. Tests: `tests/test_profile_cli.py`, `tests/test_doctor_cli.py`, `tests/test_runtime_cli.py` drive `patchtrace.cli.main` in process: every leaf in text and `--json`, every refusal with its exit code, directory trees unchanged by read-only leaves and by refusals, no process and no socket in doctor, no Qt import for the three dispatchers, and one subprocess run of `python -m patchtrace doctor --json`.

Open and unverified by this slice: a real offline runtime archive (none has been published; SPEC-06 gate D), the Windows default directories on a real Windows machine (the tests inject them), and the frozen executable (the registry collects new verb files through the existing PyInstaller hook; the Windows frozen smoke runs in CI only).
