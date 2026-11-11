# CLI reference

Generated 2026-10-14 from `argparse` (`patchtrace.cli._parser`) and the `cli_commands` registry, and organised by verb as in `docs/specs/cli-umbrella.md` (SPEC-44), which is the contract (per-verb exit-code table in its section 4, flag owners in section 5). Run any verb with `--help` for the live text. Internal worker verbs (`secondary _binexport-worker`, `unified _worker`, `rules _rules-worker`) are omitted. Launch `patchtrace` without arguments to open the desktop.

## Conventions

- Invocation: `PYTHONPATH=src python -m patchtrace <verb> ...` from a checkout (`src/patchtrace/__main__.py`; `cli.py` has no `__main__` guard, so `python -m patchtrace.cli` does nothing), or `patchtrace <verb> ...` from an install (`pyproject.toml` `[project.scripts]` points at `patchtrace.__main__:main`).
- Output: the `enrichment-cli/1` envelope; `--json` where listed emits one JSON document on stdout.
- Exit codes (`cli.py` module docstring, SPEC-44 section 4): 0 success; 2 invalid arguments, configuration or environment, including argparse errors; 3 runtime failure; 4 legitimate no result (complete evidence, zero rows); 5 cancelled. A `status: partial` result exits 0 for `rank` and `correlate`, and 3 for `flags`, `series create`, `secondary run`, `unified run`, `intelligence explain` and `intel-tools run`. Some verbs map these differently, see SPEC-44 section 4.
- "Required: yes" covers positional arguments and required options. Examples show only the required arguments; replace placeholders with real values.
- Verbs are either built in (`cli.py`) or discovered from `src/patchtrace/cli_commands/<verb>.py` (stdlib only, exports `COMMAND`; a file that fails to load is listed as unavailable and exits 3). Today the registry holds five verbs: `fabric`, `kev`, `panels`, `pilot` and `rules` (listed by `python -m patchtrace --help`). Built-in verbs `unified`, `intelligence`, `intel-tools` and `backend` register through package hooks.

## `patchtrace rank`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |
| `--cache-dir CACHE_DIR` | no | global derived-stage cache (default: the profile cache_dir, else no cache) |
| `--refresh` | no | recompute cached stages (no network implied) |
| `--profile NAME|FILE` | no | analysis profile name from the desktop profiles directory, or a profile JSON file |
| `--run RUN` | no | analysis run ID (default: latest completed) |
| `--weights WEIGHTS` | no | JSON object of detector weights (integers 0..100) |
| `--disable DETECTOR` | no |  (default []) |
| `--limit LIMIT` | no | show at most N entries (0 = all) |
| `--dry-run` | no | do not persist results in the project |

Example: `patchtrace rank <project>`

## `patchtrace flags`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |
| `--cache-dir CACHE_DIR` | no | global derived-stage cache (default: the profile cache_dir, else no cache) |
| `--refresh` | no | recompute cached stages (no network implied) |
| `--profile NAME|FILE` | no | analysis profile name from the desktop profiles directory, or a profile JSON file |
| `--run RUN` | no |  |
| `--feature-id FEATURE_ID` | no |  |
| `--dry-run` | no |  |

Example: `patchtrace flags <project>`

## `patchtrace correlate`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |
| `--cache-dir CACHE_DIR` | no | global derived-stage cache (default: the profile cache_dir, else no cache) |
| `--refresh` | no | recompute cached stages (no network implied) |
| `--profile NAME|FILE` | no | analysis profile name from the desktop profiles directory, or a profile JSON file |
| `--cve CVE-YYYY-NNNN` | yes |  |
| `--snapshot SNAPSHOT` | no | previously saved CVE snapshot JSON (offline) (default []) |
| `--fetch` | no | retrieve from providers (requires consent) |
| `--consent-providers CONSENT_PROVIDERS` | no | comma list, e.g. nvd,msrc; must match --providers (default ) |
| `--providers PROVIDERS` | no | comma list (default: profile cve_providers, else nvd,msrc) |
| `--api-key-env API_KEY_ENV` | no | environment variable holding an NVD API key (default ) |
| `--save-snapshot SAVE_SNAPSHOT` | no | write normalized snapshots to this JSON file |
| `--run RUN` | no |  |
| `--dry-run` | no |  |

Example: `patchtrace correlate <project> --cve <cve>`

## `patchtrace cache`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `action` | yes | one of `status`, `verify`, `prune` |
| `--cache-dir CACHE_DIR` | yes |  |
| `--target-bytes TARGET_BYTES` | no |  |

Example: `patchtrace cache <action> --cache-dir <cache_dir>`

## `patchtrace acquire`

### `patchtrace acquire search`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `name` | yes | lowercase file name, e.g. afd.sys |
| `--consent-hosts CONSENT_HOSTS` | no | must be exactly winbindex.m417z.com (default ) |

Example: `patchtrace acquire search <name>`

### `patchtrace acquire fetch`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `name` | yes |  |
| `--older SHA256` | yes |  |
| `--newer SHA256` | yes |  |
| `--project PROJECT` | yes | new project directory |
| `--project-name PROJECT_NAME` | no |  (default ) |
| `--consent-hosts CONSENT_HOSTS` | no | must be exactly winbindex.m417z.com,msdl.microsoft.com (default ) |

Example: `patchtrace acquire fetch <name> --older <older> --newer <newer> --project <project>`

## `patchtrace series`

### `patchtrace series create`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `--builds FILE` | yes | 3-8 builds in analyst order, oldest first (order is never inferred) |
| `--root ROOT` | yes | directory holding series.json and pair projects |
| `--labels LABEL` | no |  |
| `--direct` | no | also create a first-to-last pair project used to confirm/contradict chains |
| `--replace-corrupt` | no | if series.json is damaged, keep a series.json.corrupt-* copy and replace it |
| `--run` | no | run Ghidriff for pair projects without a completed run (otherwise none runs) |
| `--python PYTHON` | no | external Python executable for --run (default ) |
| `--ghidra-dir GHIDRA_DIR` | no | Ghidra installation root for --run (default ) |
| `--timeout TIMEOUT` | no | per-pair analysis timeout seconds (default 3600) |
| `--cache-dir CACHE_DIR` | no | raw-output cache for --run |

Example: `patchtrace series create --builds <builds> --root <root>`

### `patchtrace series chains`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `series_json` | yes |  |
| `--function NAME` | no |  |
| `--address HEX` | no |  |

Example: `patchtrace series chains <series_json>`

## `patchtrace secondary`

### `patchtrace secondary import-bindiff`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |
| `bindiff` | yes |  |

Example: `patchtrace secondary import-bindiff <project> <bindiff>`

### `patchtrace secondary run`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |
| `--engine {rz-diff|bindiff}` | no | repeatable; default: every engine that probes as supported |
| `--rz-diff RZ_DIFF` | no | rz-diff executable (absolute path or on PATH) (default rz-diff) |
| `--bindiff BINDIFF` | no | absolute path of the BinDiff 8 `bindiff` executable |
| `--older-binexport OLDER_BINEXPORT` | no | .BinExport of the older artifact (BinDiff primary) |
| `--newer-binexport NEWER_BINEXPORT` | no | .BinExport of the newer artifact (BinDiff secondary) |
| `--accept-unbound-binexport` | no | I confirm these .BinExport files belong to this project's artifacts even though they record no SHA-256 executable id (recorded in provenance) |
| `--max-parallel {1|2}` | no |  (default 1) |
| `--timeout TIMEOUT` | no | per-engine seconds (60..86400) (default 1800) |
| `--no-cache` | no | ignore stored engine runs |

Example: `patchtrace secondary run <project>`

### `patchtrace secondary rzdiff`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |
| `--rz-diff RZ_DIFF` | no | rz-diff executable (absolute path or on PATH) (default rz-diff) |
| `--timeout TIMEOUT` | no |  (default 1800) |

Example: `patchtrace secondary rzdiff <project>`

### `patchtrace secondary reconcile`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |

Example: `patchtrace secondary reconcile <project>`

### `patchtrace secondary binexport-check`

Validates a .BinExport (Ghidra: File > Export > Binary BinExport (v2) for BinDiff; IDA: Edit > Plugins > BinExport) in a memory/time-capped worker. Choose "Subtract Imagebase" identically for both files of a pair. Nothing is uploaded and the file is never modified.

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `file` | yes |  |
| `--artifact-sha256 ARTIFACT_SHA256` | yes | SHA-256 of the binary this export claims to describe |
| `--role {older|newer}` | yes |  |
| `--accept-unbound` | no | I confirm this file belongs to the artifact although its executable_id is not a SHA-256 (MD5/empty ids from IDA); recorded as id_binding |

Example: `patchtrace secondary binexport-check <file> --artifact-sha256 <artifact_sha256> --role <role>`

## `patchtrace intelligence`

Advisory facts are vendor claims with provenance; rule hypotheses are search guidance. Neither is verification of a vulnerability in a function.

### `patchtrace intelligence import`

Validates a CSAF 2.0 document (strict JSON, schema, mandatory tests) and stores its exact bytes and normalized facts in the project, append-only. The document must list the CVE. Nothing is sent anywhere; local paths are never stored.

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |
| `file` | yes | CSAF 2.0 JSON file |
| `--cve CVE-YYYY-NNNN` | yes | a CVE the document must list |

Example: `patchtrace intelligence import <project> <file> --cve <cve>`

### `patchtrace intelligence fetch`

Reads the provider metadata and the directory index, selects index entries whose file name contains the CVE ID, downloads them, checks the .sha256 file when present and validates the document. HTTPS to msrc.microsoft.com only, bounded and cancellable. Nothing about the project or any binary is sent. --offline reads only the cache and opens no socket.

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |
| `--cve CVE-YYYY-NNNN` | yes |  |
| `--consent-hosts HOSTS` | no | must be exactly msrc.microsoft.com (not needed with --offline) (default ) |
| `--provider-metadata URL` | no | provider-metadata.json URL inside the same allowlist (the default location is unverified) |
| `--cache-dir CACHE_DIR` | no | opt-in content-addressed cache of every response |
| `--offline` | no | use only --cache-dir; no network, no consent needed |

Example: `patchtrace intelligence fetch <project> --cve <cve>`

### `patchtrace intelligence explain`

Joins the stored advisories that list the CVE with the project's two artifacts: product applicability (verified identity only; a file name never maps), the CWE profile, rule hypotheses and search anchors, with explicit unknowns. It restates vendor claims; it does not show that any function contains or fixes the CVE. Never uses the network.

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |
| `--cve CVE-YYYY-NNNN` | yes |  |
| `--older-product PID` | no | analyst assertion: this advisory product ID describes the older artifact (repeatable) |
| `--newer-product PID` | no | analyst assertion for the newer artifact (repeatable) |
| `--export FILE` | no | also write the report; the suffix chooses the format (.json or .md, escaped, LF) |

Example: `patchtrace intelligence explain <project> --cve <cve>`

## `patchtrace unified`

Derived, ordinal fusion of the stored engine outputs (experimental, derived, ordinal). It never changes the project, the Ghidriff results or any other stored result.

### `patchtrace unified run`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |
| `--no-extract` | no | S0 mode: no instruction-level extraction (the only mode in this build) |
| `--no-residual` | no | skip the residual passes P16-P19 of the ladder (another result, another id) |
| `--no-decompile` | no | skip the on-demand decompile of review pairs (the constant-only pairs stay in review) |
| `--python PYTHON` | no | external Python executable of the extractor (with `--ghidra-dir` it enables the decompile of review pairs) |
| `--ghidra-dir GHIDRA_DIR` | no | Ghidra installation root (with `--python`) |
| `--sources LIST` | no | comma list of ghidriff, bindiff, rz-diff, manual (default: all) (default ghidriff,bindiff,rz-diff,manual) |
| `--isolate` | no | run the worker as a capped child process (default) (default True) |
| `--in-process` | no | run in this process (tests and debugging) (default True) |
| `--timeout TIMEOUT` | no | worker seconds (60..86400) (default 3600) |
| `--refresh` | no | recompute even when a stored result has these inputs |
| `--fail-on-none` | no | exit 4 when no row is material or review |

Example: `patchtrace unified run <project>`

### `patchtrace unified show`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |
| `--decision {matched|tentative|candidate|contested|ambiguous|older-only|newer-only|unknown}` | no |  (default []) |
| `--change {unchanged|cosmetic|material|review|unknown|not-applicable}` | no | materiality: unchanged, cosmetic, material, review, unknown, not-applicable (listing one always shows its rows) (default []) |
| `--class {constant|comparison|condition|callee|call-added|call-removed|data-ref|struct-offset|cfg|block-added|block-removed|string|size-only|refcount-only|address-only|register-only|layout-only|name-only|frame|eh|unknown}` | no |  (default []) |
| `--source SOURCE` | no | only rows with a record from this source (repeatable) (default []) |
| `--search TEXT` | no | function names or hexadecimal RVAs, with or without 0x (default ) |
| `--all` | no | also list the unchanged rows and the cosmetic rows with a structural proof, which are collapsed by default |
| `--limit LIMIT` | no | rows printed (default 200; totals are always given) (default 200) |

Example: `patchtrace unified show <project>`

### `patchtrace unified explain`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |
| `--row ROW_ID` | yes | a row id or a prefix of at least 8 digits |

Example: `patchtrace unified explain <project> --row <row>`

### `patchtrace unified status`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |

Example: `patchtrace unified status <project>`

## `patchtrace intel-tools`

### `patchtrace intel-tools probe`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `--capa EXE` | no |  |
| `--floss EXE` | no |  |
| `--diec EXE` | no |  |
| `--diec-db DIR` | no |  |
| `--diec-lib DIR` | no |  |
| `--capa-rules DIR` | no |  |
| `--capa-sigs DIR` | no |  |
| `--capa-accept-untested` | no | accept a capa build that is not the pinned release (recorded as untested) |
| `--floss-accept-untested` | no | accept a floss build that is not the pinned release (recorded as untested) |
| `--diec-accept-untested` | no | accept a diec build that is not the pinned release (recorded as untested) |

Example: `patchtrace intel-tools probe `

### `patchtrace intel-tools run`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |
| `--profile {basic|context|full}` | no |  (default basic) |
| `--engines ENGINES` | no | subset of the profile, e.g. capa,floss |
| `--floss-deobfuscate` | no | also run FLOSS stack/tight/decoded extraction (CPU emulator; prints the consent text) |
| `--floss-min-length N` | no |  |
| `--floss-large-file` | no | pass -L (emulate files above 16 MiB) |
| `--diec-heuristic` | no |  |
| `--capa-backend {vivisect|ghidra}` | no |  (default vivisect) |
| `--ghidra-dir GHIDRA_DIR` | no |  |
| `--java-home JAVA_HOME` | no |  |
| `--timeout TIMEOUT` | no | seconds per job (10..86400) |
| `--memory-mb MEMORY_MB` | no | per-process memory cap in MiB (default: FLOSS emulation 4096, otherwise none) |
| `--max-parallel {1|2}` | no |  (default 1) |
| `--no-cache` | no |  |
| `--scratch SCRATCH` | no | parent folder for the private per-job scratch directories |
| `--capa EXE` | no |  |
| `--floss EXE` | no |  |
| `--diec EXE` | no |  |
| `--diec-db DIR` | no |  |
| `--diec-lib DIR` | no |  |
| `--capa-rules DIR` | no |  |
| `--capa-sigs DIR` | no |  |
| `--capa-accept-untested` | no | accept a capa build that is not the pinned release (recorded as untested) |
| `--floss-accept-untested` | no | accept a floss build that is not the pinned release (recorded as untested) |
| `--diec-accept-untested` | no | accept a diec build that is not the pinned release (recorded as untested) |

Example: `patchtrace intel-tools run <project>`

### `patchtrace intel-tools delta`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `project` | yes |  |
| `--engines ENGINES` | no |  |
| `--show-secrets` | no |  |

Example: `patchtrace intel-tools delta <project>`

## `patchtrace backend`

### `patchtrace backend status`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `--bundle-dir DIR` | no | directory that contains backend/ (default: next to the executable) |
| `--work-dir DIR` | no | per-user writable work directory (default: the platform user state directory) |

Example: `patchtrace backend status `

### `patchtrace backend verify`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `--bundle-dir DIR` | no | directory that contains backend/ (default: next to the executable) |
| `--work-dir DIR` | no | per-user writable work directory (default: the platform user state directory) |
| `--full` | no | also hash every file (slow, cancellable) |

Example: `patchtrace backend verify `

### `patchtrace backend selftest`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `--bundle-dir DIR` | no | directory that contains backend/ (default: next to the executable) |
| `--work-dir DIR` | no | per-user writable work directory (default: the platform user state directory) |
| `--older OLDER` | yes | older PE x64 artifact (never executed) |
| `--newer NEWER` | yes | newer PE x64 artifact (never executed) |
| `--expect-function NAME` | yes | function name that must appear in the result (repeatable) |
| `--project-dir DIR` | no | new empty project directory (default: under the work directory) |
| `--timeout TIMEOUT` | no | analysis timeout seconds (10..86400) (default 3600) |

Example: `patchtrace backend selftest --older <older> --newer <newer> --expect-function <expect_function>`

### `patchtrace backend diagnose`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |
| `--bundle-dir DIR` | no | directory that contains backend/ (default: next to the executable) |
| `--work-dir DIR` | no | per-user writable work directory (default: the platform user state directory) |

Example: `patchtrace backend diagnose `

## `patchtrace panels` (registry verb, `cli_commands/panels.py`)

List the reserved GUI panels, or lint the manifest and every built panel spec (ids, shortcuts, tab groups, tooltip prefixes, claims, imports). Runs without a display.

### `patchtrace panels list`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |

Example: `patchtrace panels list `

### `patchtrace panels check`

| Flag | Required | Meaning |
|---|---|---|
| `--json` | no | emit exactly one JSON document on stdout |

Example: `patchtrace panels check `

## `patchtrace fabric` (registry verb, `cli_commands/fabric.py`)

Read the anchor fabric (read-only).

| Verb | Flags |
|---|---|
| `fabric list` | `--project` (required), `--json`, `--kind`, `--side`, `--role`, `--subject`, `--limit` |
| `fabric show` | `--project` (required), `--json`, `anchor_id` (required) |
| `fabric resolve` | `--project` (required), `--json`, `--kind` (required), `--side`, `value` (required) |
| `fabric stats` | `--project` (required), `--json` |

## `patchtrace kev` (registry verb, `cli_commands/kev.py`)

CISA KEV catalog: status, plan, fetch, import, lookup, diff, prune.

| Verb | Flags |
|---|---|
| `kev status` | `--kev-dir`, `--json`, `--max-age-days` |
| `kev plan` | `--json`, `--source` (required: `cisa-github` or `cisa-site`) |
| `kev fetch` | `--kev-dir`, `--json`, `--source` (required: `cisa-github` or `cisa-site`), `--consent-hosts`, `--accept-shrink` |
| `kev import` | `--kev-dir`, `--json`, `file` (required), `--accept-shrink` |
| `kev lookup` | `--kev-dir`, `--json`, `cve`, `--from-cve-snapshot`, `--catalog`, `--md` |
| `kev diff` | `--kev-dir`, `--json`, `--from`, `--to` |
| `kev prune` | `--kev-dir`, `--json`, `--keep` (required), `--yes` |

## `patchtrace pilot` (registry verb, `cli_commands/pilot.py`)

Rank changed functions against an advisory: leads, why, review.

| Verb | Flags |
|---|---|
| `pilot leads` | `project` (required), `--json`, `--cve`, `--assume-applies`, `--class` (`fit`, `review`, `partial`, `code`, `queue`), `--limit`, `--no-unified`, `--show-dismissed`, `--dry-run`, `--export` |
| `pilot why` | `project` (required), `--json`, `--candidate` (required), `--cve` |
| `pilot review` | `project` (required), `--json`, `--candidate` (required), `--action` (required: `pin`, `unpin`, `dismiss`, `restore`, `note`), `--cve`, `--text` |

## `patchtrace rules` (registry verb, `cli_commands/rules.py`)

Detection rules: probe, propose, show, decide, test, export, history.

| Verb | Flags |
|---|---|
| `rules probe` | `--json` |
| `rules propose` | `project` (required), `--json`, `--match` (required), `--direction` (`older`, `newer`, `both`), `--confirm-material` |
| `rules show` | `project` (required), `--json`, `--candidate`, `--version` |
| `rules decide` | `project` (required), `--json`, `--candidate` (required), `--accept`, `--reject`, `--defer`, `--archive`, `--label`, `--cve`, `--kb`, `--cwe`, `--note` |
| `rules test` | `project` (required), `--json`, `--version` (required), `--series`, `--extra`, `--clean-dir`, `--expect`, `--timeout` |
| `rules export` | `project` (required), `--json`, `--version` (required), `--out` (required), `--include-names`, `--allow-git-tree`, `--with-warnings` |
| `rules history` | `project` (required), `--json`, `--lineage` |

## Built verbs without a section here

These verbs are in `python -m patchtrace --help`. Their flags are in the parser, and each has a user page in [docs/help](help/README.md). The command-line forms are listed there.

| Verb | Subcommands | Help page |
|---|---|---|
| `build-env` | `show`, `delta`, `timeline` | [64](help/64-cli-build-env.md) |
| `graph` | `neighbours`, `delta`, `leads`, `paths`, `export`, `series` | [66](help/66-cli-graph.md) |
| `kb` | `index`, `search`, `attach`, `explain`, `export`, `products`, `components`, `pairs`, `import-pair`, `plan`, `leads`, `acquire` | [67](help/67-cli-kb.md) |
| `search` | (flags only; `--status`, `--rebuild`, `--probe` are modes) | [72](help/72-cli-search.md) |
| `strings` | `list`, `delta`, `explain`, `scan`, `export` | [73](help/73-cli-strings.md) |

## Specified but not built (planned)

None of these exist in the parser today; each will arrive as a `cli_commands/<verb>.py` adapter and owns its own spec. Do not rely on them.

| Verb | Source |
|---|---|
| `patch`, `pe-meta`, `calibration` | planned verbs listed in SPEC-44 section 9 (GUI plan 8.12) |
| `doctor`, `export`, `import`, `show`, `project` | proposals in SPEC-44 section 7 |
