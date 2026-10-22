# App settings and persistence contract (SPEC-43)

Status: draft, 2026-10-14; the session-key scan of section 7 landed in slice CONSENT (`tests/test_network_consent_secrets.py`), the refusal of secret-shaped model and endpoint text (G1, G2) and sections 9 and 10 are open.

This is the registry of record for user settings that `src/patchtrace` persists, and the rules for naming, defaults, reset, format and boundaries. Card: `docs/audits/spec-gaps-20261014.md:124` (row 9). Basis: commit `fd6cdba`, which is this worktree's HEAD and the local `origin/main` ref. `docs/specs/REGISTRY.md` is a 1560531 snapshot, and open PR state was not checked. Sections 1 and 10 describe the code as built. The other sections are normative. `[proposal]` marks rules not yet built; `[unverified]` marks claims not run here.

## Scope and method

In scope: the QSettings store `QSettings('PatchTrace', 'PatchTrace')` (`ui.py:1492`), analysis profile files (`profile/1`, `enrichment.md:141-147`), and credentials, which are never persisted (section 7). Out of scope: project data, per-run records (`AnalysisRun.settings`, `backend.py:495-498`), the enrichment cache, and engine-owned directories (`backend.py:227`).

Method: grep of `src/patchtrace` for `settings.value(`, `setValue(`, `_save(`, `QSettings(`, `SETTING_`, `PROFILE_SETTING` and the key prefixes. All QSettings reads and writes are in `ui.py`, `ui_evidence.py`, `ui_series.py`, `ui_engine_setup.py` and `__main__.py:36` (self-test). Other hits are run-record dictionaries (`backend.py`, `reports.py`, `models.py:182`) or docstrings. `enrichment/profiles.py` writes JSON, not QSettings. No settings `remove` or `clear` call exists; `ui.py:3137` is `sync()` only.

## 1. Inventory as built

27 keys in 25 rows (the three splitter keys share one row). Types and bounds are those the readers enforce. `r` marks a read site and `w` a write site. Classes: `UI` is an interface or layout preference with no effect on results; `PATH` is an engine executable or directory, probed before use; `POLICY` is engine run policy or network consent; `PROVIDER` is a non-secret interpretation setting; `SELECT` names a profile file. No row is a credential or an analysis-profile field (profile fields are JSON, section 6).

| Key | Type and bounds | Default | Sites | Class |
|---|---|---|---|---|
| `analysis/profile` | string, profile name | `default` | r `ui.py:713, 990`; w `ui.py:3045` | SELECT |
| `backend/python` | string, path | `""` | r `ui.py:1000, 2566`; w `ui.py:3048` | PATH |
| `backend/ghidra` | string, path | `""` | r `ui.py:1001, 2567`; w `ui.py:3049` | PATH |
| `backend/java_home` | string, path | `""` | r `ui.py:1002, 2570`; w `ui.py:3050` | PATH |
| `backend/allow_symbol_downloads` | bool | `False` | r `ui.py:1018, 2562`; w `ui.py:3054` | POLICY (network consent) |
| `backend/restrict_env` | bool | `False` | r `ui.py:1021, 2571`; w `ui.py:3051` | POLICY (experimental) |
| `backend/env_passthrough` | string, comma or semicolon separated names | `""` | r `ui.py:1023, 2572`; w `ui.py:3052` | POLICY (names only) |
| `backend/timeout` | int seconds, 10 to 86400 | `3600` | r `ui.py:1028, 2568`; w `ui.py:3053` | POLICY |
| `desktop/font_size` | int points, 8 to 28 | `11` | r `ui.py:1032, 3123`; w `ui.py:3055` | UI |
| `desktop/sync` | bool | `True` | r `ui.py:1039, 3124`; w `ui.py:3057, 3135` | UI |
| `desktop/geometry` | QByteArray | unset | r `ui.py:3106`; w `ui.py:3132` | UI (layout) |
| `desktop/workspace`, `desktop/vertical`, `desktop/code` | QByteArray (splitter state) | unset | r `ui.py:3119`; w `ui.py:3134` | UI (layout) |
| `provider/kind` | string, `ollama` or `openai` | `ollama` | r `ui.py:1302`; w `ui.py:2933` | PROVIDER |
| `provider/endpoint` | string, URL | `http://127.0.0.1:11434` | r `ui.py:1303`; w `ui.py:2934` | PROVIDER |
| `provider/model` | string, at most 200 characters | `""` | r `ui.py:1304`; w `ui.py:2935` | PROVIDER (free text, G1) |
| `provider/context_budget` | int characters, 512 to 200000 | `24000` | r `ui.py:1036, 2924`; w `ui.py:3056` | PROVIDER |
| `recent/project` | string, path | `""` | r `ui.py:1965`; w `ui.py:1889` | UI |
| `recent/projects` | list of strings, at most 8 (`ui.py:1892`) | `[]` | r `ui.py:1890, 1897, 1904`; w `ui.py:1892, 1905` | UI |
| `series/geometry` | QByteArray | unset | retired by F9 (M3); no reader or writer, a stored value is ignored | UI (layout) |
| `evidence/geometry` | QByteArray | unset | r `ui_evidence.py:1338`; w `ui_evidence.py:1410` | UI (layout) |
| `evidence/filter` | int index into `FILTERS` (`ui_evidence.py:110`) | `0` | r `ui_evidence.py:907`; w `ui_evidence.py:986` | UI |
| `evidence/hide_agreed` | bool | `False` | r `ui_evidence.py:910`; w `ui_evidence.py:987` | UI |
| `evidence/show_index` | bool | `False` | r `ui_evidence.py:913`; w `ui_evidence.py:1000` | UI |
| `engines/bindiff/path` | string, path, at most 4096 characters | `""` | r `ui_engine_setup.py:512`; w `ui_engine_setup.py:616` (after a successful probe only) | PATH |
| `engines/bindiff/setup_open` | bool | `False` | r `ui_engine_setup.py:338`; w `ui_engine_setup.py:430` | UI |

Undocumented keys: of the eleven `backend/*` and `provider/*` keys, only `backend/allow_symbol_downloads` is named by key in any document (`docs/specs/ghidriff-launcher-symbols.md:100`), and `provider/model` appears once in `docs/research.md:58`. `GUI-integration-plan.md:120` lists existing keys by glob and omits both groups. `desktop/*` and `recent/*` appear only in prose or as globs (`ui.md:3`; `GUI-integration-plan.md:120`).

Not persisted (no key exists): the Evidence panel's "Parallel engines" and "Timeout" (`ui_evidence.py:805, 812`; limits from `secondary/evidence_panel_service.py:48-50`), and the export options (`ui.md:15`).

Planned, not in code: `layout/schema`, `layout/state`, `layout/state_sha256` and `gui/palette/recent` (`GUI-integration-plan.md:120`); `desktop/code_colors` and `desktop/token_marks` (`docs/specs/program-e/WBQ-integration-plan.md:186`).

## 2. Key registry and naming [normative]

N1. A key is `group/name`, or `engines/<engine>/<name>` for engines. Segments are lowercase ASCII matching `[a-z][a-z0-9_]*`. All 27 current keys comply.
N2. Groups in use: `analysis`, `backend`, `desktop`, `engines`, `evidence`, `provider`, `recent` and `series`. The GUI plan also defines `layout`, `theme` and `gui` (`GUI-integration-plan.md:120`). A panel's settings prefix is its id (`GUI-integration-plan.md:173`), so a new panel may not claim a group already in use.
N3. Each key has one writer, the owner in section 1. Dynamic names (`desktop/<splitter>`, `<id>/...`) are listed as patterns in the registry.
N4. `[proposal]` One record per key in a pure module, `src/patchtrace/app_settings.py`, with no Qt import (the pattern of `enrichment/profiles.py`). A record holds key, type, default, bounds, class and owner. Readers take defaults only from the record (D3).
N5. `[proposal]` A planned key is registered when its feature merges, not earlier.
N6. `[proposal]` Writing an unregistered key raises in tests, and is logged and skipped in the app (`PT-SETTINGS-KEY`).

## 3. Defaults, validation and migration [normative; additive only]

D1. Reads are typed and never raise. The three existing bool coercions differ: `ui_evidence.py:153-165` accepts bools and the strings `true`, `false`, `1` and `0`; `ui_engine_setup.py:120-127` treats only `true` and `1` as true; `ui.py:1018` uses Qt's `type=bool`. Int reads clamp to bounds or return the default (`ui.py:149-156`; `ui_evidence.py:168-173`). Text is sanitised and capped (`ui_engine_setup.py:110-117`, `PATH_LIMIT` at line 61). Corrupt values fall back (`tests/test_audit_desktop.py:110-115`; `tests/test_evidence_ui.py:331-333`).
D2. Writes follow a confirmed user action: Setup accept (`ui.py:3041-3057`), Send in the context preview (`ui.py:2931-2935`), project open (`ui.py:1889-1892`), a successful BinDiff probe (`ui_engine_setup.py:615-616`), and panel controls (`ui_engine_setup.py:430`; `ui_evidence.py:986-1000`). Discovery never writes (`tests/test_ui_bundle_setup.py:101-105`, `237-239`).
D3. One default per key. Four keys have their default at two read sites: `backend/timeout` (`ui.py:1028`, `2568`), `desktop/font_size` (`ui.py:1032`, `3123`), `provider/context_budget` (`ui.py:1036`, `2924`) and `desktop/sync` (`ui.py:1039`, `3124`). The values agree today. `[proposal]` Take them from the N4 record.
D4. Migration is additive. A new key gets a new name and a default. A key whose meaning changes gets a new name; the old key is read once as a fallback and never deleted, as the legacy `evidence/geometry` is (`GUI-integration-plan.md:299`). Upgrade code deletes no key. No global schema key exists. A group that needs a version owns one, as `layout/schema` does (`GUI-integration-plan.md:120`).
D5. A stored path is a hint. It is probed before use (`ui_engine_setup.py:615-616`). Reading a path never runs it (`docs/specs/runtime-discovery.md:3`).

## 4. Reset to defaults

R1. As built there is no reset. No settings removal or clear call exists. The only `reset` hits are Qt model resets (`ui_evidence.py:202-213`; `ui_series.py:110-142`).
R2. `[proposal]` `Setup > Reset preferences` opens a confirmation that lists the keys. It calls `remove(key)` for each registered key, never `clear()`, so keys written by a newer build survive a downgrade. It clears the `recent/*` keys too. It never touches profile files, because nothing is deleted automatically (`docs/plans/program-e-research-brief.md:9`, analyst control).
R3. `[proposal]` `View > Reset panel layout` removes `layout/*` only (`GUI-integration-plan.md:208`).
R4. Reset cannot expose a credential, because none is persisted (section 7).

## 5. QSettings format and location

Q1. Production: `QSettings('PatchTrace', 'PatchTrace')` (`ui.py:1492`), with the organisation and application names set in `__main__.py:25-26`. On Windows the store is the registry (`enrichment/profiles.py:146-147`). `[unverified]` Linux and macOS locations were not run here.
Q2. The `--self-test` path uses IniFormat in a temporary directory (`__main__.py:36`).
Q3. Tests use IniFormat under `tmp_path` (for example `tests/test_ui.py:24`, `tests/test_ui_profiles.py:23`, `tests/test_ui_engine_setup.py:65`, `tests/test_tooltips.py:126`). All 22 `MainWindow(` calls in `tests/` pass an explicit settings object. `[proposal]` A fixture asserts `settings.format() == IniFormat` and that the file lies under `tmp_path`, so no test can reach the registry.
Q4. IniFormat returns strings for bools (`tests/test_evidence_ui.py:322` accepts `True` or `'true'`), so getters coerce both forms. Native typed values need a `[unverified]` Windows check.
Q5. `[proposal]` Lowercase names keep registry and INI keys identical across formats. `[unverified]` Qt's key-case rules were not re-checked.
Q6. Profiles live in `<settings file dir>/profiles` when the settings are file-backed, and otherwise in the per-user config directory (`ui.py:699-707`; `enrichment/profiles.py:145-154`). Tests pass that directory explicitly (`tests/test_ui_engine_setup.py:613`).

## 6. Boundary: profiles, engine paths and UI preferences [normative]

B1. An analysis profile (`profile/1`, `enrichment.md:141-147`) holds run semantics only, one JSON file per profile. Fields and defaults: `name`, `weights`, `enabled`, `feature_ids`, `symbol_policy` (`disabled`, `local`, or `online`), `cve_providers` (`nvd`, `msrc`), `snapshot_max_age_days` (30), `cache_dir` (`null`) and `cache_budget_gib` (20) (`enrichment/profiles.py:41-49`). The model is strict and forbids extra fields (`profiles.py:39`). Files are capped at 64 KiB (`profiles.py:24`, `140-141`). The only path a profile may hold is `cache_dir`, which must be absolute (`profiles.py:63-65`).
B2. In this domain QSettings holds only the selected profile name (`analysis/profile`, `ui.py:696`, `3045`; `tests/test_ui_profiles.py:95-97`).
B3. Engine paths (`backend/python`, `backend/ghidra`, `backend/java_home`, `engines/bindiff/path`) live only in QSettings. They never enter a profile, the project, a log or an export. Exports never read QSettings; run settings reach them only through `SAFE_SETTING_KEYS`, which holds no path or environment key (`reports.py:15-16`, `55-58`, `194`).
B4. Engine run policy (`backend/timeout`, `backend/restrict_env`, `backend/env_passthrough`, `backend/allow_symbol_downloads`, `backend/symbol_mode`, `backend/symbol_dirs`) lives in QSettings. `env_passthrough` holds variable names, validated by `_passthrough_error` (`backend.py:90-99`, applied at `130` and `174`). A profile can only narrow the configured Setup symbol mode: `online` requires Setup consent, `local` uses only the configured local PDB folders, and `disabled` shuts symbols off. The default profile follows Setup; named profiles cannot enable a mode above Setup (`enrichment.md:143`).
B5. UI preferences (`desktop/*`, `evidence/*`, `series/geometry`, `engines/bindiff/setup_open`, `recent/*`) never affect results and are never exported.
B6. Provider settings (`provider/*`) are not profile fields (`profiles.py:41-49`). They are remembered per user (`ui.md:13`).
B7. Environment variables are inputs and are never written to QSettings: `PATCHTRACE_BINDIFF` (`secondary/cli_bindiff.py:19`; `runtime_discovery.py:201-202`); `PATCHTRACE_BACKEND_PYTHON` and `GHIDRA_INSTALL_DIR` as discovery hints (`runtime_discovery.py:269-272`); and `PATCHTRACE_CHILD_ENV=inherit`, which overrides `backend/restrict_env` (`backend.py:212-213`).
B8. Run records (`AnalysisRun.settings`, `backend.py:495-498`) are project data, not app settings.

Conflict: `enrichment.md:145` says QSettings keeps "only presentation preferences and the selected profile name". As built it holds 27 keys (section 1). See X1.

## 7. Credentials: never persisted

C1. Two credentials exist. The provider API key is typed in the context preview and is session-only (`ui.md:13`; `ui.py:1305-1311`). The NVD key comes from the environment variable named by `--api-key-env` (`cli.py:93`, `172`). Neither has a write path.
C2. Enforcement, by layer:
- Storage: the key is read only in `ContextDialog.config()` (`ui.py:1325-1327`) and passed to the interpretation closure (`ui.py:2936`). The provider writes (`ui.py:2933-2935`) take only kind, endpoint and model.
- Widget: password echo and the placeholder "Session only; never saved" (`ui.py:1305-1307`).
- Object: `ProviderConfig.api_key` is `repr=False`, and its length and control characters are checked (`providers.py:33`, `39-40`).
- Ordering: provider fields reach QSettings only after `ContextDialog.accept()` has built a valid `ProviderConfig` (`ui.py:1329-1338`, `2931-2935`). Endpoints may not carry userinfo, a query or a fragment; OpenAI-compatible endpoints need HTTPS; Ollama needs loopback (`providers.py:49-59`).
- NVD: the key goes only into the `apiKey` header (`enrichment/intelligence.py:58`, `288-289`).
- Profiles: no credential field; the rejection set includes `api_key` (`profiles.py:3-5`, `39`; `tests/test_profiles.py:72`, `127-132`).
- Output: logs and reports redact credential-shaped text (`backend.py:609`; `reports.py:24-39`; `tests/test_jobs.py:175-180`).
C3. Tests: `tests/test_ui.py:105-113` (the key appears in no saved value); `tests/test_interpretation.py:191-199` (userinfo, query and fragment endpoints rejected) and `202-204` (repr hides the key); `tests/test_enrichment_intelligence.py:126-135` (the NVD key appears only in the header, not in the result or URL).
C4. Gaps found while writing this spec:
- G1. `provider/model` is saved as free text (`ui.py:2935`). The only check is non-empty and at most 200 characters (`providers.py:37-38`). A key typed into Model would be saved, and no test covers it.
- G2. `provider/endpoint` rejects userinfo, query and fragment, but not a secret-shaped path segment.
- G3. `tests/test_ui.py:105-113` checks the key field only, not the model or endpoint, nor the whole interpret flow.

`[proposal]` Before any provider save, run the secret patterns over model and endpoint (`intelligence/tools/common.py:421-437`; `diagnostics.py:8-19`) and refuse with `PT-PROVIDER`. Extend the test to the full flow, with a fake key in Model and in an endpoint path.

## 8. Future toggles [proposal]

All three follow `GUI-integration-plan.md`: the host owns layout, QSettings is the only store, getters range-check, and no credential is stored. Once approved, T1 replaces the theme notes in `ui.md` (lines 3 and 13), T2 the redaction note (line 15), and T3 the worker-count note (line 13).

T1. Theme, `theme/variant`, default `dark`. Values `dark` and `system`; any other value reads as `dark` (`GUI-integration-plan.md:120`). No `light` variant in alpha (`:433`). High contrast stays automatic and unsaved (`:245`). `dark` stays byte-identical to `ui.DARK_STYLE` (`:244`). Entry point in the View menu (`:208`); slices F3 and F7 (`:383`, `:388`).
T2. Redaction, `export/redaction_profile`, default `local`, values `local`, `share` and `custom`. It sets the export dialog default only; the report contract owns the semantics (`docs/specs/report-export-contract-v2.md:90`). Asymmetry rule: a saved default may only reduce disclosure. `export/include_code` and `export/include_raw_provider_text` stay per export and are never saved (`ui.md:15`; `docs/specs/report-export-contract-v2.md:19`). The key stays inert until RPT2 v2 is the default (`docs/specs/report-export-contract-v2.md:3`).
T3. Worker count, `engines/max_parallel`, default 1, bounds `PARALLEL_RANGE` (`secondary/evidence_panel_service.py:50`). It is the saved default of the per-run "Parallel engines" control (`ui_evidence.py:803-805`), not a second scheduler. Background `TaskRunner` lanes stay fixed (`GUI-integration-plan.md:382`; `ui.md:13`). Heavy Python work stays in a subprocess or calls `checkpoint()` (`GUI-integration-plan.md:240`). `[proposal]` Test: identical results for 1 and N engines.

## 9. Tests [proposal; hermetic]

- `test_app_settings_registry`: every literal key under `src/patchtrace` is registered (dynamic patterns listed); each reader's default equals its record; corrupt values of every type fall back.
- `test_app_settings_credentials`: a fake key in Model or in an endpoint path is refused before any write; after the full interpret flow, no saved value contains it.
- `test_app_settings_reset`: removes registered keys only; an unregistered key survives; profile files are untouched.
- `test_app_settings_format`: every window fixture uses IniFormat under `tmp_path`.
- `test_app_settings_migration`: a legacy key is read once and never deleted.
- Native Windows round trip of bool, int and QByteArray in the Windows CI job (external; not run here).

## 10. Conflicts and drift

X1. `enrichment.md:145` overstates the QSettings scope; see B2 and section 1.
X2. `bindiff-execution.md:12` (D2) defers `engines/bindiff/path` to "QSettings ... later". It is written at `ui_engine_setup.py:616`.
X3. `GUI-integration-plan.md:120` says "Existing keys stay valid" and omits `backend/*` and `provider/*` (11 keys).
X4. The macOS profile directory differs: the GUI yields `<plist dir>/profiles` (`ui.py:704-706`); the CLI uses `~/Library/Preferences/PatchTrace/profiles` (`enrichment/profiles.py:151-154`). `[unverified]` Code reading only; macOS is not a target platform.
X5. `REGISTRY.md:14` names SPEC-41 as the next free number. This file is SPEC-43, as requested. `docs/specs/program-e/GDE-integration-plan.md:3` and `:285` propose SPEC-41.
X6. Four defaults are duplicated (D3). Planned keys have no registry entry (N5).

## 11. Integrator asks (no existing file was edited)

1. `docs/specs/REGISTRY.md`, Table A: add one row. Until then `tests/test_spec_registry.py` fails for this file (REGISTRY section 1, rule 7). Suggested row:

```
| `docs/specs/app-settings.md` | none (requested SPEC-43; rule 4 names SPEC-41) | SPEC-43 | draft | ui.py, ui_evidence.py, ui_series.py, ui_engine_setup.py, enrichment/profiles.py | 27 QSettings keys and profile fields inventoried; section 8 proposals |
```

2. Amend `enrichment.md:145` (X1), `bindiff-execution.md:12` (X2) and `GUI-integration-plan.md:120` (X3).
3. After owner approval of section 8, replace `ui.md` lines 3, 13 and 15 with links to section 8.
4. When WBQ merges, register `desktop/code_colors` and `desktop/token_marks` in section 1.
5. Decide the number (open question 1).

## 12. Open questions (recommended default)

1. SPEC-43 or SPEC-41? Default: SPEC-43, as requested. A grep of `docs/`, `tasks/` and `README.md` finds no use of SPEC-42 or SPEC-43 at this base. Open PRs were not checked.
2. Keep `cache_dir` in shareable profiles? Default: yes, with a warning on share, because it is a local path.
3. Should Reset preferences clear engine paths? Default: yes, after the confirmation lists them.
4. macOS profile directory (X4)? Default: align the GUI with `default_profiles_dir` when settings are native. macOS is not a target platform.
