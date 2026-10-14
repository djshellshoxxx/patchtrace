# CLI umbrella contract (SPEC-44)

Status: draft, 2026-10-14. Describes the headless `patchtrace` CLI at worktree HEAD `fd6cdba` (local refs only; GitHub not queried). Envelope `enrichment-cli/1` unchanged; no version bump proposed. Number as briefed: section 10, item 1.

## 0. Scope and basis

This umbrella fixes the rules every headless verb follows and lists each verb's flags. Per-verb behaviour stays in the owner specs named in the tables. It adds no verb and changes no code. The headless path imports no Qt: `import patchtrace.cli` and parser construction load no PySide6 or `ui` module (checked). `python -m patchtrace` sends any first argument other than `--self-test`, `-platform` or `-style` to `cli.main` before Qt loads (`__main__.py:13-15`).

Basis: `cli.py` (869 lines) and the modules it registers: `secondary/cli_bindiff.py`, `secondary/cli_binexport.py`, `secondary/cli_run.py`, `intelligence/cli.py`, `intelligence/tools/cli.py`, `unified/cli.py`, `backend_cli.py`. `nway/` has no dispatcher; `series` is in `cli.py:646-732` over `nway/series.py`. All 36 parser paths, including actions and hidden workers, were run with `python -m patchtrace <path> --help` and exited 0; types and defaults come from an argparse dump of the same parsers. `kbcorrelation/cli_index.py:84` builds a `patchtrace kb index` parser that nothing registers, so it is unreachable.

Drift: `docs/specs/REGISTRY.md` snapshots `main` at 1560531. HEAD is 8 commits ahead (`git rev-list 1560531..HEAD`), with #42, #46, #48, #49 and #50 merged. `unified/`, `intelligence/tools/`, `kbcorrelation/` and `backend_cli.py` exist at HEAD, where the registry still says planned. The worker brief named by the task (`docs/plans/worker-brief.md`) is absent at HEAD; its sections 1-3 were read from commit `cf1862d`, which is not an ancestor of HEAD.

## 1. Naming, dispatch and global flags

Verbs (`cli.COMMANDS`, `cli.py:21-22`): `rank`, `flags`, `correlate`, `cache`, `acquire`, `series`, `secondary`, `intelligence`, `unified`, `intel-tools`, `backend`. Handlers: `HANDLERS` (`cli.py:827-831`); `unified` registers its own (`unified/cli.py:69`). Names are lower-case with hyphens. Actions: `acquire` search, fetch; `series` create, chains; `secondary` import-bindiff, run, rzdiff (an alias of run), reconcile, binexport-check; `intelligence` import, fetch, explain; `unified` run, show, explain, status; `intel-tools` probe, run, delta; `backend` status, verify, selftest, diagnose. `cache` takes a positional action (`cli.py:99`). With no arguments the desktop opens (`__main__.py:17-54`).

Hidden actions begin with `_` and are left out of help: `unified _worker` (`unified/cli.py:65`). `secondary _binexport-worker` also uses `help=argparse.SUPPRESS`, but `secondary --help` prints it as `==SUPPRESS==` (`cli_binexport.py:40`; section 8, item 12).

There are no global flags. `--json` is added to each leaf (`cli.py:50-52`); `patchtrace --json rank x` exits 2 with "unrecognized arguments: --json" (checked). `--help` exits 0 (`cli.py:861-862`). Shared groups: `common` (`--json`), `profiled` (`--profile`), `cached` (`--cache-dir`, `--refresh`) (`cli.py:50-63`); `secondary run` adds the BinDiff options (`cli_bindiff.py:22-29`).

## 2. The enrichment-cli/1 envelope

With `--json`, stdout carries exactly one document with sorted keys and a final newline (`cli.py:177-180`): `{"command", "contract": "enrichment-cli/1", "result", "status", "warnings"}`. A failure adds `"error"` (`cli.py:848-853`, `866-868`). Cancellation emits `status: "cancelled"` with `result: null` and no `error` (`cli.py:857-859`). `command` is the verb, plus the action for every verb except `rank`, `flags`, `correlate` and `cache` (`cli.py:533, 649, 747, 820`; `unified/cli.py:155`; `backend_cli.py:56`; failure form `cli.py:834-835`). `warnings` are strings; text mode prints each as `warning: <text>` on stderr (`cli.py:182-183`). Unified puts its standing NOTE first in every envelope (`unified/cli.py:7-8`).

Evolution rule (additive only). Within `enrichment-cli/1` a change may add an optional `result` key, add `warnings` entries, add a verb or action (section 9), or add a flag whose default keeps the old behaviour. It may not remove or rename a key, change a key's type or an exit code's meaning, or add a status outside section 4. Anything else needs `enrichment-cli/2`. Consumers ignore unknown keys.

## 3. Streams, environment and executable lookup

- stdin: no verb reads it. Child processes get `stdin=DEVNULL` (`jobs.py:275`). There are no prompts; consent is given by flag (section 8, item 10).
- stdout: UTF-8 with `errors=replace` (`cli.py:840-842`). With `--json` the only stdout content should be the envelope (help excepted); every path was not exercised [unverified].
- stderr, in every mode: `request: <METHOD> <url>` before each network request (`cli.py:415, 516, 579, 588`; `intelligence/cli.py:226`); progress (`cli.py:277`; `unified/cli.py:114-116`); `error: <message>` (`cli.py:849, 864`); `cancelled` (`cli.py:856`); extra validation findings (`intelligence/cli.py:139-146`); diagnostics (`cli_binexport.py:63-64`). A JSON consumer reads stdout only.
- Untrusted text (advisory fields, file names, worker stderr) is made terminal-safe first: `plain_text` (`intelligence/cli.py:103-108`), `sanitize_text` (`unified/cli.py:99-102`).
- Environment read: `PATCHTRACE_BINDIFF` (`cli_bindiff.py:19, 71`); `PATCHTRACE_CAPA`, `_FLOSS`, `_DIEC`, `_DIEC_DB`, `_DIEC_LIB`, `_CAPA_RULES`, `_CAPA_SIGS` (`intelligence/tools/cli.py:17-19`); the variable named by `--api-key-env` (`cli.py:93, 174, 416`), never printed. Analysis profiles come from the desktop profile directory (`enrichment.md` section 12).
- Executables: `rz-diff` is looked up on PATH (`cli.py:143`). BinDiff and the intel-tools binaries must be absolute; PATH is never searched (`cli_bindiff.py:3-4`; `intelligence/tools/cli.py:75-77`). Engines get the filtered environment from `engine_env` (`cli_run.py:71`).

## 4. Exit codes and status

Contract (`cli.py:1-6`, `23`): 0 success; 2 invalid arguments, configuration or environment, argparse errors included (`cli.py:34-35`); 3 runtime failure; 4 legitimate no result (complete evidence, zero rows); 5 cancellation (Ctrl+C maps here, `cli.py:854-860`). An unexpected exception prints one line and exits 3 (`cli.py:863-869`). Visible verbs return only 0, 2, 3, 4 or 5. Hidden workers do not: `unified _worker` returns 0, 1, 2, 3, 5 or 22 (`unified/worker.py:20`) and `secondary _binexport-worker` returns 0, 2, 20, 21 or 22 (`binexport_worker.py:14`), which reach the process exit code unchanged (`cli.py:847`).

Observed `status` values: `complete`, `partial`, `failed`, `cancelled`, `unavailable` (`cli.py:467`), `stale` (`cli.py:726`), `no-results` (`backend_cli.py:90, 277`). Section 8, item 4.

| Verb (action) | 0 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| rank | ranking, incl. partial (`cli.py:327-330`) | bad weights, detector, profile (`cli.py:197-234`) | no ranking (`cli.py:311-313`) | complete, zero entries (`cli.py:328-329`) | `cli.py:308-310` |
| flags | WIL complete (`cli.py:354`) | feature ID not uint32 (`cli.py:337-338`) | WIL not complete (`cli.py:352-353`) | complete, zero transitions (`cli.py:354`) | `cli.py:350-351` |
| correlate | any status (`cli.py:480`) | consent mismatch (`cli.py:408-409`); bad snapshot (`cli.py:398-399`) | fetch failed, no response (`cli.py:441`); no result (`cli.py:468`) | no result and no snapshot (`cli.py:468`) | `cli.py:440, 464` |
| cache | always (`cli.py:497`) | bad cache config (`cli.py:495`) | runtime (`cli.py:495`) | none | none |
| acquire search | usable candidate (`cli.py:553`) | name, consent (`cli.py:535-537, 541`) | other (`cli.py:508`) | no downloadable candidate (`cli.py:553`) | `cli.py:507` |
| acquire fetch | project created (`cli.py:607`) | equal SHAs, existing project, consent (`cli.py:554-559`) | promote or other (`cli.py:508, 594-595`) | not found, update-only (`cli.py:507, 582`) | `cli.py:507` |
| series create | complete (`cli.py:701`) | `--run` needs python and ghidra (`cli.py:655-656`); NwayError (`cli.py:664-665`) | a pair failed, partial (`cli.py:699-701`); write error (`cli.py:685`) | none | `cli.py:671, 677` |
| series chains | rows or stale reasons (`cli.py:732`) | bad `--address` (`cli.py:714`) | none | no chain and no stale reason (`cli.py:732`) | none |
| secondary import-bindiff | matches stored (`cli.py:822`) | input, pair, orientation, format (`cli.py:806-810`) | other (`cli.py:815-816`) | zero matches (`cli.py:822`) | `cli.py:807` |
| secondary run, rzdiff | complete with matches (`cli_run.py:58`) | timeout range (`cli.py:739-740`); no run (`cli.py:798-799`); no engine (`cli_run.py:75-77`); input-class failures (`cli_run.py:61-62`) | partial; other failures (`cli_run.py:59-63`) | complete, no matches (`cli_run.py:58`) | `cli_run.py:55-56` |
| secondary reconcile | complete (`cli.py:797`) | none | assessment error (`cli.py:777-778`) | no stored sets (`cli.py:771-772`) | none |
| secondary binexport-check | valid (`cli_binexport.py:80`) | other codes (`cli_binexport.py:61`) | PT-SECONDARY-RUN (`cli_binexport.py:61`) | none | `cli_binexport.py:60` |
| intelligence import | complete (`intelligence/cli.py:197`) | malformed file, validation, CVE not listed, over 16 MiB (`:37, 77, 174, 190`) | other (`:79`) | none | `:95-97` |
| intelligence fetch | stored, or offline read (`:289`) | consent missing; `--offline` without cache (`:239-244`) | none acceptable (`:278-282`) | no index entry (`:263-268`) | `:95-97` |
| intelligence explain | complete (`:365`) | export path, product IDs (`:313-330`) | partial: warnings (`:347-349, 365`) | no stored advisory (`:350-352`) | `:95-97` |
| unified run | complete (`unified/cli.py:159`) | ENVIRONMENT codes, bad `--sources` (`:83-86, 110`) | partial (`:157-158`) | `--fail-on-none`, no material row (`:159`) | `:140-142` |
| unified show | rows match (`:245`) | no result yet (`:183-184`) | unusable result (`:185-187`) | zero matching rows (`:245`) | none |
| unified explain | row shown (`:330`) | `--row` under 8 hex digits; no row (`:295-296, 253-255`) | `UnifiedError` (`:306`) | none | none |
| unified status | always (`:369`) | none | none | none | none |
| intel-tools probe | a supported engine (`intelligence/tools/cli.py:122`) | none supported (`:122`) | none | none | none |
| intel-tools run | all evidence (`:146`) | no engine runnable; PT-TOOL-INPUT or CONSENT (`:141, 173`) | partial or failed (`:144`) | ran, no evidence (`:146`) | `:138-139` |
| intel-tools delta | comparable changes (`:240-241`) | no stored evidence, literal 2 (`:203-205`) | rejected engine: partial (`:236-237`) | no changes (`:241`) | none |
| backend status | fast check ok (`backend_cli.py:126`) | none | none | no bundle (`:89-92`) | bundle failed (`:95-99`) |
| backend verify | verified (`:153`) | none | none | no bundle (`:89-92`) | failed (`:155-158`); cancel (`:129-131`) |
| backend selftest | expectations met (`:275`) | timeout range, paths, no bundle, dir not empty, identical builds (`:198-205, 224-225, 238-239`) | run failed (`:255`) | expected function absent (`:279`) | bundle not ok (`:207`); cancel (`:255`) |
| backend diagnose | no problems (`:187`) | no bundle (`:176`) | backend problems (`:187`) | none | bundle problems (`:178, 187`) |

## 5. Flags per verb

One table per verb. `--json` is on every leaf and is not repeated. Defaults are argparse defaults; `none` means no default. Sources are the `add_argument` lines unless stated. Shared flags are listed once, in 5.1.

### 5.1 rank (owner: `enrichment.md` sections 11-12)

| Action | Flag | Type, default | Meaning (source) |
|---|---|---|---|
| - | `PROJECT` | path, required | project directory (`cli.py:66`) |
| - | `--cache-dir DIR` | path, none | derived-stage cache root; else the profile `cache_dir` (`cli.py:60-61`). Shared with flags, correlate |
| - | `--refresh` | flag, off | recompute cached stages; needs `--cache-dir` (`cli.py:62, 253-254`). Shared |
| - | `--profile NAME or FILE` | string, none | analysis profile; excludes `--weights`, `--disable`, `--feature-id` (`cli.py:55-56, 193-196`). Shared |
| - | `--run ID` | string, latest completed | analysis run; help on rank only (`cli.py:69`); `flags`, `correlate` lack help (`cli.py:79, 95`) |
| - | `--weights FILE` | path, RankingConfig defaults | JSON object: eight detector IDs to integers 0..100; unknown ID exits 2 (`cli.py:70, 215-226`) |
| - | `--disable DETECTOR` | string, repeatable, `[]` | turns a detector off; unknown ID exits 2 (`cli.py:71, 227-229`); no help text |
| - | `--limit N` | int, 0 | at most N entries; 0 = all (`cli.py:72, 314`) |
| - | `--dry-run` | flag, off | publish nothing to the project (`cli.py:73, 283`) |

### 5.2 flags (owner: `enrichment.md` section 11)

| Action | Flag | Type, default | Meaning (source) |
|---|---|---|---|
| - | `PROJECT`, `--cache-dir`, `--refresh`, `--profile`, `--run` | as rank (5.1) | shared; `--run` has no help text here (`cli.py:79`) |
| - | `--feature-id N` | int, repeatable, none (all) | keep these WIL feature IDs, 0..4294967295; no help text (`cli.py:80, 336-338`) |
| - | `--dry-run` | flag, off | as rank; no help text (`cli.py:81`) |

### 5.3 correlate (owner: `enrichment.md` section 11)

| Action | Flag | Type, default | Meaning (source) |
|---|---|---|---|
| - | `PROJECT`, `--cache-dir`, `--refresh`, `--profile`, `--run`, `--dry-run` | as rank (5.1) | shared; `--run` and `--dry-run` lack help text (`cli.py:95-96`) |
| - | `--cve CVE-YYYY-NNNN` | string, repeatable, required | no parse-time check (`cli.py:87`); the fetch path checks it (`cli.py:411`) |
| - | `--snapshot FILE` | path, repeatable, `[]` | offline snapshot JSON read to its size cap; marked unverified (`cli.py:88-89, 390-399`) |
| - | `--fetch` | flag, off | retrieve from providers; needs `--consent-providers` (`cli.py:90, 402-409`) |
| - | `--consent-providers LIST` | string, `''` | must equal `--providers`; ignored without `--fetch` (`cli.py:91, 407-408`) |
| - | `--providers LIST` | string, profile or `nvd,msrc` | providers to query (`cli.py:92, 385-386`) |
| - | `--api-key-env VAR` | string, `''` | environment variable holding the NVD key (`cli.py:93, 174, 416`) |
| - | `--save-snapshot FILE` | path, none | write normalized snapshots as JSON (`cli.py:94, 455-457`) |

### 5.4 cache (owner: `enrichment.md` section 9 and 11)

| Action | Flag | Type, default | Meaning (source) |
|---|---|---|---|
| status, verify, prune | `action` | choice, required | operation (`cli.py:99`) |
| all | `--cache-dir DIR` | path, required | cache root (`cli.py:100, 487`) |
| prune | `--target-bytes N` | int, none | prune target; ignored by status and verify (`cli.py:101, 493`) |

### 5.5 acquire (owner: `acquisition.md`, SPEC-08)

| Action | Flag | Type, default | Meaning (source) |
|---|---|---|---|
| search, fetch | `NAME` | string, required | lowercase file name, validated (`cli.py:106, 109, 535-537`) |
| search | `--consent-hosts HOST` | string, `''` | exactly `winbindex.m417z.com` (`cli.py:107, 541`) |
| fetch | `--older SHA256`, `--newer SHA256` | string, required | lowercased; must differ and be in the Winbindex record; no format check at parse time (`cli.py:110-111, 555-557, 567-568`) |
| fetch | `--project DIR` | path, required | new project directory; refused when a project exists (`cli.py:112, 558-559`) |
| fetch | `--project-name NAME` | string, `''` | default `<name> (symbol server)` (`cli.py:113, 592-593`); no help text |
| fetch | `--consent-hosts HOSTS` | string, `''` | exactly `winbindex.m417z.com,msdl.microsoft.com` (`cli.py:114-115, 554`) |

### 5.6 series (owner: `nway.md` SPEC-09; `series-window.md` SPEC-09b)

| Action | Flag | Type, default | Meaning (source) |
|---|---|---|---|
| create | `--builds FILE...` | path, 3 to 8 values, required | analyst order, oldest first; never inferred (`cli.py:120-121`; `nway/contracts.py:14`; `nway/series.py:168-169`) |
| create | `--root DIR` | path, required | holds `series.json` and the pair projects (`cli.py:122`) |
| create | `--labels LABEL...` | strings, none | labels for the builds; count not checked here (`cli.py:123`); no help text |
| create | `--direct` | flag, off | also a first-to-last pair (`cli.py:124-125`) |
| create | `--replace-corrupt` | flag, off | keep a `series.json.corrupt-*` copy, then replace (`cli.py:126-127`; `nway/series.py:234`) |
| create | `--run` | flag, off | run Ghidriff on pairs without a completed run; needs `--python` and `--ghidra-dir` (`cli.py:128-129, 653-656`) |
| create | `--python PATH` | string, `''` | external Python for `--run` (`cli.py:130`) |
| create | `--ghidra-dir DIR` | string, `''` | Ghidra installation for `--run` (`cli.py:131`) |
| create | `--timeout S` | int, 3600 | per-pair timeout; no range check here (`cli.py:132, 657-659`) |
| create | `--cache-dir DIR` | path, none | raw-output cache; only with `--run` (`cli.py:133, 660-661`) |
| chains | `SERIES_JSON` | path, required | (`cli.py:160`) |
| chains | `--function NAME` or `--address HEX` | mutually exclusive, none | filter chains; bad hex exits 2 (`cli.py:161-163, 711-714`) |

### 5.7 secondary (owners: `multi-engine-orchestration.md` SPEC-28; `bindiff-execution.md` SPEC-29; `binexport2-support.md` SPEC-10b)

| Action | Flag | Type, default | Meaning (source) |
|---|---|---|---|
| import-bindiff | `PROJECT BINDIFF` | paths, required | a genuine `.BinDiff` for this exact pair; the project needs a completed run (`cli.py:136-138, 798-799`) |
| run | `PROJECT` | path, required | (`cli.py:140`) |
| run | `--engine rz-diff or bindiff` | choice, repeatable, every supported engine | default probes each engine (`cli.py:141-142`; `cli_run.py:72-73`) |
| run | `--rz-diff EXE` | string, `rz-diff` | absolute path or PATH lookup (`cli.py:143`) |
| run | `--bindiff EXE` | string, none | absolute BinDiff 8 path; else `PATCHTRACE_BINDIFF` (`cli.py:144`; `cli_bindiff.py:71-73`) |
| run | `--older-binexport FILE`, `--newer-binexport FILE` | paths, none | BinExport2 inputs for BinDiff (`cli_bindiff.py:23-26`) |
| run | `--accept-unbound-binexport` | flag, off | accept a BinExport with no SHA-256 executable id; recorded (`cli_bindiff.py:27-29`) |
| run | `--max-parallel {1,2}` | int, 1 | engines in parallel (`cli.py:147`) |
| run | `--timeout S` | int, 1800; 60..86400 | per-engine limit, enforced (`cli.py:148, 739-740`) |
| run | `--no-cache` | flag, off | ignore stored engine runs (`cli.py:149, 744`) |
| rzdiff | `PROJECT`, `--rz-diff`, `--timeout` | as run; timeout 1800 | engine fixed to rz-diff, one at a time, cache on (`cli.py:150-154`); `--timeout` has no help text (`cli.py:153`) |
| reconcile | `PROJECT` | path, required | no flags (`cli.py:155-156`) |
| binexport-check | `FILE` | path, required | the export to validate (`cli_binexport.py:33`) |
| binexport-check | `--artifact-sha256 HEX64` | 64 hex digits, required | SHA-256 of the binary the export describes (`cli_binexport.py:21-22, 34-35`) |
| binexport-check | `--role {older,newer}` | choice, required | (`cli_binexport.py:36`) |
| binexport-check | `--accept-unbound` | flag, off | confirms an executable id that is not SHA-256; recorded as `id_binding` (`cli_binexport.py:37-39`) |
| _binexport-worker | `--request FILE` | string, required; hidden | internal request handle (`cli_binexport.py:40-41`) |

### 5.8 intelligence (owner: `csaf-cve-interpretation-engine.md`, draft)

| Action | Flag | Type, default | Meaning (source) |
|---|---|---|---|
| import | `PROJECT FILE` | paths, required | CSAF 2.0 JSON; strict; at most 16 MiB (`intelligence/cli.py:157-158, 30, 174`) |
| import, fetch, explain | `--cve CVE-YYYY-NNNN` | `_cve`, required | import: a CVE the document must list (`:159, 190`); fetch and explain (`:210, 302`) |
| fetch | `PROJECT` | path, required | (`:209`) |
| fetch | `--consent-hosts HOSTS` | string, `''` | exactly `msrc.microsoft.com`; not needed with `--offline` (`:211-212, 242-246`) |
| fetch | `--provider-metadata URL` | string, none | index location inside the allowlist; default location unverified (`:213-214, 247`) |
| fetch | `--cache-dir DIR` | path, none | opt-in cache of every response (`:215`) |
| fetch | `--offline` | flag, off | read the cache only; no socket (`:216, 238-240`) |
| explain | `PROJECT` | path, required | (`:301`) |
| explain | `--older-product PID`, `--newer-product PID` | repeatable; at most 64 per side | analyst assertion of product identity (`:303-306, 311-316`) |
| explain | `--export FILE` | path, none | `.json` or `.md`; parent must exist (`:307-308, 319-330`) |

### 5.9 unified (owner: `unified-engine/07-ui-and-cli.md`, SPEC-31/07)

| Action | Flag | Type, default | Meaning (source) |
|---|---|---|---|
| run, show, explain, status | `PROJECT` | path, required | (`unified/cli.py:39, 54, 61, 64`) |
| run | `--no-extract` | flag, off | silences the no-extraction warning only (`:40-41, 154`) |
| run | `--no-decompile` | flag, off | accepted and unused (`:42`) |
| run | `--sources LIST` | string, all four | subset of ghidriff, bindiff, rz-diff, manual (`:43-44, 105-111`) |
| run | `--isolate` (default) or `--in-process` | mutually exclusive | capped child worker, or in-process for tests (`:45-49`) |
| run | `--timeout S` | int, 3600; help 60..86400 | worker limit; checked by `limits.checked_timeout` (`:50`; `pipeline.py:291`) |
| run | `--refresh` | flag, off | recompute although inputs match; not in owner spec (`:51`) |
| run | `--fail-on-none` | flag, off | exit 4 when no row is material or review (`:52, 159`) |
| show | `--decision`, `--change`, `--class` | choices, repeatable, none | filters; choice sets at `:21-25` (`:55-58`) |
| show | `--limit N` | int, 200 | rows printed; totals always shown (`:59`) |
| explain | `--row ID` | string, required; 8+ hex digits | row id or unique prefix (`:62, 294-296`) |
| _worker | `--request`, `--result-dir`, `--self-check` | hidden | internal (`:65-68`) |

### 5.10 intel-tools (owner: `three-tool-evidence-adapters.md`, SPEC-36)

probe and run share the tool locations `--capa`, `--floss`, `--diec` (absolute paths), `--diec-db`, `--diec-lib`, `--capa-rules`, `--capa-sigs` and `--{capa,floss,diec}-accept-untested` (`intelligence/tools/cli.py:29-39`). Environment fallbacks: section 3.

| Action | Flag | Type, default | Meaning (source) |
|---|---|---|---|
| probe | the shared tool locations | paths or env, none | runs `--version` or `--help` on each tool (`:45-46, 112-122`) |
| run | `PROJECT` | path, required | (`:48`) |
| run | `--profile {basic,context,full}` | choice, basic | engines per profile (`:49`) |
| run | `--engines LIST` | none (profile) | subset of capa, floss, diec (`:50, 22-26`) |
| run | `--floss-deobfuscate` | flag, off | FLOSS stack, tight and decoded extraction; prints consent text on stderr (`:51-52, 157-159`) |
| run | `--floss-min-length N` | int, none | (`:53`); not in owner spec |
| run | `--floss-large-file` | flag, off | pass `-L` (emulate above 16 MiB) (`:54`); not in owner spec |
| run | `--diec-heuristic` | flag, off | (`:55`) |
| run | `--capa-backend {vivisect,ghidra}` | choice, vivisect | (`:56`) |
| run | `--ghidra-dir DIR`, `--java-home DIR` | paths, none | (`:57-58`) |
| run | `--timeout S` | int, none (engine default) | 10..86400 enforced (`:59`; `runner.py:99`); defaults capa 1800, floss 600, diec 120 (`capa.py:41`, `floss.py:41`, `diec.py:40`) |
| run | `--memory-mb N` | int, none (FLOSS emulation 4096) | per-process cap (`:60-61`); not in owner spec |
| run | `--max-parallel {1,2}`, `--no-cache` | int 1; flag off | (`:62-63`) |
| run | `--scratch DIR` | path, none | parent of per-job scratch directories (`:64`) |
| delta | `PROJECT` | path, required | never runs a tool (`:66-67`) |
| delta | `--engines LIST`, `--show-secrets` | none (engines with stored runs); off | `--show-secrets` turns off redaction (`:68-69`) |

### 5.11 backend (owner: `offline-backend-installer.md` SPEC-06; `program-e/BUNDLE-integration-plan.md`)

status, verify, selftest and diagnose all take `--bundle-dir DIR` (default: next to the executable) and `--work-dir DIR` (default: platform user state directory) (`backend_cli.py:27-33`); neither is in any spec (section 6, row 13).

| Action | Flag | Type, default | Meaning (source) |
|---|---|---|---|
| verify | `--full` | flag, off | hash every file; slow, cancellable (`backend_cli.py:37`) |
| selftest | `--older PATH`, `--newer PATH` | files, required | PE x64 artifacts; never executed (`:39-40, 200-202`) |
| selftest | `--expect-function NAME` | string, repeatable, required | must appear in the result (`:41-42`) |
| selftest | `--project-dir DIR` | path, none | new or empty; default under the work dir (`:43-44, 224-225`) |
| selftest | `--timeout S` | int, 3600; 10..86400 | enforced (`:45, 198-199`); not in owner spec |

## 6. Flag registry: flags no owner spec documents

The owner check searched each owner spec for the literal flag; "not named" means no line of that file contains it. Rows 1 and 4-9 are the audit's twelve flags (`docs/audits/spec-gaps-20261014.md:35-40`); row 10 is a naming gap the audit missed; rows 2, 3 and 11-14 are new; row 15 is a help gap.

| # | Verb | Flag(s) | Owner spec | Origin |
|---|---|---|---|---|
| 1 | rank, flags, correlate | `--dry-run` | `enrichment.md`: not named | audit |
| 2 | rank, flags, correlate | `--run` | `enrichment.md`: not named (`nway.md` names it for `series create`) | new |
| 3 | rank, flags, correlate | `--cache-dir` | `enrichment.md:139` names it for `cache` only; the others reach it through the profile (sections 12-13) | new, partial |
| 4 | cache | `--target-bytes` | `enrichment.md`: not named | audit |
| 5 | correlate | `--providers`, `--api-key-env`, `--save-snapshot` | `enrichment.md`: not named | audit |
| 6 | acquire fetch | `--project-name` | `acquisition.md`: not named | audit |
| 7 | series create | `--direct`, `--python`, `--timeout`, `--cache-dir` | `nway.md`: not named; `windows-acceptance-and-milestone-builds.md:89` uses `--python` in a planned step | audit |
| 8 | series create | `--ghidra-dir` | `nway.md`: not named; `windows-acceptance-and-milestone-builds.md:89` uses it in a planned step | audit |
| 9 | series create | `--replace-corrupt` | `nway.md`: not named; `series-window.md:76,168,175` (SPEC-09b, not the owner) | audit |
| 10 | secondary binexport-check | `--accept-unbound` | `binexport2-support.md` names the parameter `accept_unbound` (`:136, :166`), not the flag | audit says none; naming gap |
| 11 | intel-tools run | `--floss-min-length`, `--floss-large-file`, `--memory-mb` | `three-tool-evidence-adapters.md`: not named | new |
| 12 | unified run | `--refresh` | `unified-engine/07-ui-and-cli.md`: not named | new |
| 13 | backend (four actions) | `--bundle-dir`, `--work-dir` | no file under `docs/specs/` names them | new |
| 14 | backend selftest | `--timeout` | `BUNDLE-integration-plan.md`: not named | new |
| 15 | several | no help text: `rank --disable` (`cli.py:71`); `flags --run`, `--feature-id`, `--dry-run` (`:79-81`); `correlate --cve`, `--run`, `--dry-run` (`:87, 95-96`); `cache --target-bytes` (`:101`); `acquire fetch --project-name` (`:113`); `series create --labels` (`:123`); `secondary rzdiff --timeout` (`:153`); `intel-tools run --floss-min-length`, `--diec-heuristic`, `--no-cache`, `--ghidra-dir`, `--java-home` (`intelligence/tools/cli.py:53, 55, 63, 57-58`) | none | help gap |

## 7. Decisions on doctor, export, import, show, project [proposal]

Default for all five: not in the alpha. The audit left them open (`spec-gaps-20261014.md:41`); `completeness-audit.md:40` records them as not implemented.

| Verb | State at HEAD | Source | Proposal |
|---|---|---|---|
| doctor | no verb | `completeness-audit.md:40` | [proposal] not in alpha. Diagnosis stays with `backend diagnose` (`backend_cli.py:46`) and `intel-tools probe`. |
| export | no verb; RPT2 specifies `export PROJECT --format json\|md\|html` with exits 0/2/3/4/5 | `RPT2-report-export-contract-v2.md:121` (status: draft for build) | [proposal] not in alpha. If the RPT2 build slice is approved it ships as `cli_commands/export.py` (section 9). Owner decision: RPT2 build or alpha. |
| import | no verb; the two imports are `intelligence import` (`intelligence/cli.py:151`) and `secondary import-bindiff` (`cli.py:136`) | `cli.py:136` | [proposal] not in alpha. A generic `import` would hide two different inputs. |
| show | `unified show` and `unified explain` exist (`unified/cli.py:53-62`) | `unified/cli.py` | [proposal] not in alpha. A top-level `show` would duplicate them. |
| project | no code | `completeness-audit.md:40` | [proposal] not in alpha. Projects come from `acquire fetch`, `series create` and the desktop. |

Open, not briefed: `diff`, `config`, `interpret` (`completeness-audit.md:40`). Default: not in alpha; owner to decide.

## 8. Inconsistencies between verbs

1. Partial exit code. `rank` (`cli.py:327-330`) and `correlate` (`cli.py:480`) exit 0 with `status: partial`; `flags` (`cli.py:352-353`), `series create` (`cli.py:701`), `secondary run` (`cli_run.py:60`), `unified run` (`unified/cli.py:157-158`), `intelligence explain` (`intelligence/cli.py:365`) and `intel-tools run` (`intelligence/tools/cli.py:144`) exit 3. [proposal] keep existing codes (additive rule); new verbs use 3.
2. Zero results. `rank` exits 4 for zero entries (`cli.py:328-329`); `correlate` exits 0 for zero contextual entries (`cli.py:480`). [proposal] document; change only in `enrichment-cli/2`.
3. No bundle. `backend status` and `verify` exit 4 (`backend_cli.py:89-92`); `selftest` and `diagnose` exit 2 (`:176, 205`). [proposal] 4 for "no bundle" everywhere.
4. Status vocabulary. `enrichment.md:32` closes the set at complete, partial, unavailable, cancelled, failed; `stale` and `no-results` are outside it. [proposal] add both to `enrichment.md` section 2 as observed v1 values (a note, not a version bump).
5. `intel-tools delta` with no stored evidence exits 2 with `status: complete` (`intelligence/tools/cli.py:203-205`); `intel-tools run` reports `failed` for the same class (`:141`). [proposal] `failed`.
6. `unified status` exits 0 with no result (`unified/cli.py:369`); `unified show` exits 2 (`:183-184`). [proposal] keep; document.
7. Cache names. `--refresh` recomputes (`cli.py:62`; `unified/cli.py:51`); `--no-cache` ignores stored runs (`cli.py:149`; `intelligence/tools/cli.py:63`); `--cache-dir` means a derived-stage cache (`cli.py:60`), an HTTP response cache (`intelligence/cli.py:215`) or a raw-output cache (`cli.py:133`). [proposal] keep names; section 5 states the meaning per verb.
8. Timeouts. 60..86400 for secondary (`cli.py:739-740`) and unified (help only); 10..86400 for intel-tools (`runner.py:99`) and backend (`backend_cli.py:198-199`); `series create --timeout` has no check (`cli.py:132`) [unverified in `BackendConfig`]. [proposal] one range per engine family, stated in section 5.
9. Inert flags. `cache --target-bytes` does nothing outside prune (`cli.py:493`); `correlate --consent-providers` does nothing without `--fetch` (`cli.py:402-407`); `unified run --no-decompile` is unused (`unified/cli.py:42`); `--no-extract` only hides a warning (`unified/cli.py:154`). [proposal] new verbs reject inert flags with exit 2; existing ones are documented.
10. Consent. `acquire` and `intelligence fetch` require an exact host list (`cli.py:500-503`; `intelligence/cli.py:242-246`); `correlate` requires a provider list equal to `--providers` (`cli.py:408`); `--floss-deobfuscate` prints its consent text and proceeds (`intelligence/tools/cli.py:157-159`). [proposal] new network verbs use an exact host list and a `request:` line on stderr.
11. PATH policy. `rz-diff` is looked up on PATH (`cli.py:143`); BinDiff and intel-tools are not (`cli_bindiff.py:3-4`; `intelligence/tools/cli.py:75-77`). [proposal] keep; say so in the `--rz-diff` help.
12. Hidden workers. `secondary _binexport-worker` prints `==SUPPRESS==` in `secondary --help` (`cli_binexport.py:40`); `unified _worker` is hidden correctly (`unified/cli.py:65`). Worker codes (section 4) lie outside 0/2/3/4/5; the BinExport parent maps 0, 20 and 22 itself (`binexport_run.py:91, 142`). [proposal] drop the `help=` argument, as `unified` does.
13. Minor. `cache` has no action in `command` (`cli.py:496`); alias `secondary rzdiff` reports its own name (`cli.py:747`); `rank --limit` 0 means all (`cli.py:72`) while `unified show --limit` defaults to 200 (`unified/cli.py:59`); `cache` prints JSON in text mode (`cli.py:496`). [proposal] keep (additive rule); document.

## 9. Extension rule: the cli_commands registry (F1b) [proposal]

Status: F1b is being built in a parallel slice (`docs/specs/program-e/GUI-integration-plan.md` section 8.12). `src/patchtrace/cli_commands/` is absent at HEAD. Until it merges, these rules govern new verbs and each new verb is an integrator ask.

- A verb is `src/patchtrace/cli_commands/<verb>.py`: an adapter of at most 25 lines over the feature's own Qt-free `<package>/cli.py` (`GUI-integration-plan.md:396`). File `build_env.py` gives verb `build-env`; the name matches `^[a-z][a-z0-9-]{1,23}$`, is unique and is not in `cli.COMMANDS` (section 8.12).
- The adapter exports `COMMAND = CliCommand(name, summary, build, run)`: `summary` at most 80 ASCII characters, `build(sub)` returns the parser, `run(args, cancel)` returns 0, 2, 3, 4 or 5 (section 8.12). It re-exports `CliError`, `emit` (= `cli._emit`) and the exit constants from `cli`.
- Discovery is `cli_commands.discover()` (sorted; `_private.py` skipped), `names()` for smoke tests and `register_all(sub, invoked)` (section 8.12). A new verb edits none of `cli.py`, `tools/frozen_smoke.py` or `tests/test_acceptance_smoke.py`, and adds no PyInstaller hook (`GUI-integration-plan.md:396`).
- Built-in verbs stay in `cli.py`; the default in section 8.12 is no move (`GUI-integration-plan.md:446`). Existing package hooks keep working: `intelligence_cli.register` (`cli.py:164`), `cli_unified.register` (`:166`), `intel_tools_cli.register` (`:167`), `register_backend` (`:168`), `cli_binexport.register` (`:158`).
- Plans written before HEAD list `unified` and `intelligence` as new verbs (`GUI-integration-plan.md:322`); both exist at HEAD. The line numbers in section 8.12 (`cli.py` L16, L817, L821) are stale (HEAD: L21, L827, L834).
- Planned verbs that this umbrella does not define (section 8.12): `panels`, `patch`, `search`, `graph`, `strings`, `kb`, `kev`, `build-env`, `rules`, `pe-meta`, `calibration`. Each owns its spec. KBC has no registration today (`kbcorrelation/cli_index.py:84`); when built, its verb is a `cli_commands/kb.py` adapter [proposal].

## 10. Integrator asks

No existing file was edited for this spec. The integration owner applies these.

1. REGISTRY row. Add to `docs/specs/REGISTRY.md` Table A. `tests/test_spec_registry.py` fails until the file is cited (REGISTRY section 1, rule 7):

```
| `docs/specs/cli-umbrella.md` | SPEC-44 (as briefed; proposed) | SPEC-44 | draft | cli.py, backend_cli.py, secondary/cli_*.py, intelligence/cli.py, intelligence/tools/cli.py, unified/cli.py (dispatch) | Umbrella CLI rules, per-verb flags, flag registry (section 6); doctor, export, import, show, project proposed not in alpha (section 7) |
```

The number needs a decision. REGISTRY section 1, rule 4 names SPEC-41 as the next free number. Either reserve 41 to 43 and keep SPEC-44, or rename this file and title to SPEC-41.
2. Owner-spec flag amendments (section 6), each in its own slice: `enrichment.md` section 11 (rows 1-5); `nway.md` (rows 7-9); `acquisition.md` (row 6); `binexport2-support.md` (row 10); `three-tool-evidence-adapters.md` (row 11); `unified-engine/07-ui-and-cli.md` (row 12); `BUNDLE-integration-plan.md` (rows 13-14); help text (row 15).
3. `enrichment.md` section 2: status note for `stale` and `no-results` (section 8, item 4).
4. Owner decisions: the export row in section 7, and the partial exit code (section 8, item 1).
5. Audit row 10 (`spec-gaps-20261014.md:125`) can cite this file. No code change is requested here. A future verb needs one adapter ask under section 9.

## 11. Acceptance and tests

- Existing CLI tests at HEAD (11 files): `tests/test_cli.py`, `test_cli_secondary.py`, `test_cli_secondary_run.py`, `test_cli_bindiff.py`, `test_binexport_cli.py`, `test_rzdiff_cli_env.py`, `test_acquisition_cli.py`, `test_intel_cli.py`, `test_intel_tools_cli.py`, `test_unified_cli.py`, `test_backend_cli.py`. Per-flag coverage was not measured [unverified].
- [proposal] One contract test: every parser path in section 5 exists; every flag is in section 5 or section 6; `import patchtrace.cli` loads no Qt module; the exit table of section 4 holds for one case per verb. Hermetic, no network, no target execution.

## 12. Unverified items

- GitHub state (default-branch SHA, open PRs, checks) was not queried; this spec uses local refs only. The REGISTRY snapshot predates HEAD.
- The range and path checks in `BackendConfig` (for `series create --timeout` and `--python`) and the timeout limit in `limits.checked_timeout` (`unified/limits.py`) were not read.
- Exit 1 from an interpreter failure before `main` was not exercised.
- `intel-tools run --floss-large-file` means `-L` according to its help text only.
- `intelligence fetch` default provider-metadata location (`discovery.DEFAULT_PROVIDER_METADATA`) was not read; its help calls it unverified.
- The status values of the unified result manifest were not enumerated; `unified run` uses only `complete` or `partial` (`unified/pipeline.py:174`).
- Whether `kbcorrelation/cli_index.py` is the intended KBC verb was not read (no registration, no spec reference).
