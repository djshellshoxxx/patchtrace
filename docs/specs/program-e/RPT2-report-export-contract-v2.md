# RPT2: Report and export contract v2

Status: draft for build, written 2026-10-14 (Program E, E-1). Additive over `docs/specs/architecture.md` "Reports" and `src/patchtrace/reports.py` (`export_project`, `_snapshot`, `_render`, `_clean`, `_redact`, `_markdown_escape`, `_cell`), `ExportManifest` in `src/patchtrace/models.py`, and the UI export dialog (`docs/specs/ui.md` line 15). Report contract v1 output stays byte-for-byte producible: v2 is opt-in until the GUI and CLI default is switched by the owner.

Source-access note: `www.w3.org`, `spec.commonmark.org` and `arxiv.org` were not reachable from the sandbox on 2026-10-14 (DNS failure). Standards claims below are `[unverified: host blocked]` and must be re-checked in the build slice. Code claims were read from this repository on 2026-10-14; two defects found in `reports.py` were reproduced locally (section 6).

## 1. Verdict and scope

Build: a `report/2` contract with (a) a versioned envelope (`report_version`, `content_digest`, `sections_present`), (b) explicit provenance and consent blocks, (c) new optional sections for engine evidence (D5), series, unified result references, build facts (SPEC-26 D2), symbol mode (GHR), advisory citations (CSAF/KB) and leads (FAB), (d) a **calibration display level** computed by the exporter, always `ordinal` unless a valid calibration artifact permits more, (e) a redaction profile and a per-format **escaping matrix** with fixed normalization of untrusted text, (f) a fix for two reproduced defects (lone-surrogate crash; unneutralized bidi controls).

Not built: PDF/DOCX/SARIF/CSV exporters (CSV would need formula-injection guards; listed as a future format, section 8), AI-written narrative (separate spec, rank 6 of the 2026-10-14 gap audit), automatic upload or publishing of any report, signing of reports, any new network behaviour. Reports derive only from persisted project snapshots (unchanged rule).

## 2. Sources and facts

| claim | source | retrieved | confidence |
|---|---|---|---|
| v1 JSON has `schema_version: 1`, stable key order (`sort_keys=True`), `ensure_ascii=False`, 20 MiB cap, atomic write via sibling temp then `os.replace`; formats `json | html | md` | `src/patchtrace/reports.py` | 2026-10-14 | high |
| v1 HTML escapes all values with `html.escape`, sets a CSP meta `default-src 'none'; style-src 'unsafe-inline'`, no scripts or external assets; Markdown escapes `\ ` * _ { } [ ] ( ) # + . ! | > ~ : -` after HTML-escaping, tables flatten whitespace via `_cell` | same | 2026-10-14 | high |
| Defaults: code excluded, notes included, raw provider text excluded, absolute source paths redacted; `_Verbatim` marks code and evidence text (credentials redacted, paths kept) | same; `docs/specs/architecture.md` line 49 | 2026-10-14 | high |
| `ui.md` line 15: "no separate redaction controls exist yet (future work)" | `docs/specs/ui.md` | 2026-10-14 | high |
| **Defect 1 (reproduced)**: `json.dumps(..., ensure_ascii=False)` followed by `.encode('utf-8')` raises `UnicodeEncodeError` for a lone surrogate (`'x\ud800y'`); `export_project` catches only `OSError` around the write, so the error escapes as a non-`ExportError`. Whether upstream model validation prevents such strings in a persisted project was not established | local run of Python 3.12 against `reports.py` helpers, 2026-10-14 | 2026-10-14 | high that the encode fails; reachability [unverified] |
| **Defect 2 (reproduced)**: `_markdown_escape('‮evil')` returns the string unchanged; bidi control characters pass through all three formats | same local run | 2026-10-14 | high |
| `calibration.policy.display_level()` returns `'ordinal' | 'bands' | 'numeric'`, and `'ordinal'` whenever no valid loaded artifact with passing gates exists (also on any exception); no artifact ships yet | `src/patchtrace/calibration/policy.py`, `calibration/__init__.py` | 2026-10-14 | high |
| Engine evidence verdicts `corroborated | contested | single-engine | insufficient`, tiers `high | moderate | low | unassessed`, an index capped at 83 described as "uncalibrated triage aid"; absence is not contradiction; upstream similarity values are never used | `src/patchtrace/secondary/evidence.py` | 2026-10-14 | high |
| `ranking` export is `attention/1` with a config digest, input digest, stale flag and the note "Attention scores prioritize research; they do not establish exploitability or CVE relevance." | `reports.py` `_ranking_section` | 2026-10-14 | high |
| `ExportManifest(Record)` has `extra='forbid'`, `schema_version: Literal[1]`, fields `project_id, revision, format, sha256, finding_ids, include_code, include_notes, created` | `src/patchtrace/models.py` | 2026-10-14 | high |
| Bidirectional control characters can make source and rendered text diverge ("Trojan Source", arXiv 2111.00169) | https://arxiv.org/abs/2111.00169 | host blocked | [unverified: host blocked] |
| CSP3 allows hash sources for inline `<style>`; delivery via `<meta http-equiv>` is supported but `frame-ancestors`, `report-uri` and `sandbox` are not honoured there | https://www.w3.org/TR/CSP3/ | host blocked | [unverified: host blocked] |
| CommonMark: a closing code fence must use at least as many fence characters as the opening one; raw HTML is passed through by default; extended autolinks (GFM) turn bare `https://` text into links | https://spec.commonmark.org/0.31.2/ ; GitHub Flavored Markdown spec | host blocked | [unverified: host blocked] |

## 3. Standalone baseline versus PatchTrace value

Standalone: Ghidriff writes `.ghidriff.md/json` and an HTML side-by-side view with no provenance, no consent record, no stale marking and no escaping guarantees; BinDiff writes its own database; none carry a combined verdict.

PatchTrace adds a single exported artifact that: names the older and newer file hashes and orientation; carries every channel (Ghidriff match, secondary engine rows, ranking, advisory claims, build facts) **side by side, never merged or averaged**; states what was not run; records consent, symbol mode and tool pins; marks stale content; and is safe to open in a browser or paste into an issue tracker even when function names, strings and advisory text were hostile. Workflows: a triage hand-off to a colleague (share profile: no code, no paths, no notes); an evidence appendix for a vulnerability write-up (local profile with code); a regression record that a later PatchTrace run can diff (v2 `content_digest` and sorted keys).

## 4. Cross-feature links

| Section / anchor | Direction | Producer track | Rule in the export |
|---|---|---|---|
| `engine_evidence` rows (verdict, tier, supporting/contradicting/missing engines, alternative ranks) | consume | SPEC-28/C6 `secondary/evidence.py` | Engines listed separately; `missing` is "unknown", never a negative vote; shared-origin engines noted once in `limitations` |
| `change_ranking` (`attention/1`) | consume (existing) | SPEC-07 | Key stays; add `display_label: "attention index (ordinal)"` |
| `build_facts` (file/product version, PDB GUID/age, signer, manifest level) | consume | SPEC-26 D2 | Facts with `source` and `claim_level: observed-in-file`; timestamps tagged "claimed" |
| `symbols` (mode, servers contacted, staged PDB hashes, launcher version) | consume | GHR | Always present when a run exists; `servers` empty unless `online` |
| `advisories` (CVE, KB, CWE, vendor phrase) | consume | KB-CVE, CSAF, KEV | `claim_level: vendor-claim`; text inert; CVE/KB ids pass a strict regex before display; KEV flag shown as external context, not as a finding |
| `series` (N-way chains, gaps) | consume | SPEC-09 | Orientation by ordinal; gaps shown as unknown |
| `unified_result` (reference only) | consume | SPEC-31 | `{result_id, manifest_sha256, engines, status}`; bulk data stays on disk |
| `leads` | consume | FAB | Each lead lists its independent channels; never a combined number |
| report `tool` and `provenance` | emit | WIN policy | PatchTrace version, release tag, signed state of the running build |

## 5. Synergy test

Fixture: a synthetic project with two matches. Match A: Ghidriff matched; BinDiff agrees; rz-diff absent; the hostile function name is `‮gnidnuf<script>alert(1)</script>\n# Injected`. Match B: BinDiff disagrees. Plus an advisory citation whose text contains `[click](https://evil.example/x)` and a bare `https://evil.example/y`, a build-facts block whose vendor string contains `<b>`, and a calibration directory containing no artifact.

Expected `report/2` JSON: `calibration.display_level == "ordinal"`, no `shown_p` anywhere; match A `verdict: corroborated`, `missing_engines: ["rz-diff"]` labelled unknown; match B `verdict: contested`; `sections_present` lists exactly the sections with data; hostile name appears with U+202E rendered as the visible token `<U+202E>` and the newline flattened in headings and cells. Expected HTML: no `<script`, no `href=`, no attribute built from data, one `<style>` covered by a CSP hash. Expected Markdown: the heading is a single line, the advisory text is inside a code fence longer than any backtick run it contains, no live link or autolink, table rows intact. The combined export shows the contested match B and the corroborated match A together with hostile text neutralized; no single channel (ranking only, evidence only, escaping only) proves all three. Tests: `test_report2_synergy_hostile_names_and_channels`, `test_report2_display_level_ordinal_without_artifact`, `test_report2_markdown_has_no_live_links`.

## 6. Traps and guards

| Trap | Guard |
|---|---|
| Uncalibrated number shown as vulnerability confidence | The exporter calls `calibration.display_level()` itself and caps any caller request; `ordinal` removes every numeric probability field; `evidence_index` and `attention` values are exported only under keys `ordinal_index` / `attention_index` with the fixed note; `bands`/`numeric` additionally require `model_id`, artifact digest and gates in the `calibration` block or the numbers are dropped |
| Averaging engines or channels | No cross-engine aggregate field exists in the schema; a test asserts no key named `mean`, `average`, `combined_score`, `confidence` under `engine_evidence` |
| Missing treated as negative | Each channel row has `state: present | absent | not_run | not_comparable`; `absent` and `not_run` render as "unknown" |
| Markdown injection (headings, lists, links, HTML, autolinks, fences) | Escaping matrix (7.4); evidence and code only inside fences with computed fence length; `:` escaping already defeats bare autolinks and stays |
| HTML injection | All untrusted text via `html.escape(quote=True)`; no untrusted value in any attribute except generated ids matching `^[a-z0-9-]{1,64}$`; no `href`, `src`, `srcset`, `style=`, event attributes; CSP by hash (no `unsafe-inline`) plus `<meta name="referrer" content="no-referrer">` |
| Bidi and control-character spoofing (Defect 2) | Normalization (7.3): replace bidi controls with visible `<U+XXXX>` tokens, strip other C0/C1 controls except `\n`/`\t` in verbatim blocks |
| Lone surrogates crash the export (Defect 1) | Normalize with `encode('utf-8', 'replace')` round-trip (U+FFFD) before serialization; catch `UnicodeError` and raise `ExportError('PT-EXPORT-ENCODING')`; regression test with `'x\ud800y'` |
| Secrets and paths leaking | Existing `_redact` stays; add `redaction.profile`; redaction report lists counts per rule, never matched text |
| Microsoft-derived data leaving the machine | Share profile excludes code, assembly, PDB names beyond basename, original paths; the local profile warns once in the dialog; reports never embed binaries or PDBs |
| Report presented as current when stale | Per-section `stale: bool` and top-level `stale_sections`; stale content is labelled, never omitted silently |
| Hash of report depends on time | `content_digest` is computed over canonical JSON with `generated_at` and `created` removed |
| Oversize | 20 MiB cap kept; per-section caps (7.3); truncation recorded as `truncated: {section, omitted_count}` |

## 7. Contracts

### 7.1 Envelope (JSON; v1 keys unchanged, new keys additive)

Top level keeps every v1 key (`schema_version: 1`, `project_id`, `name`, `revision`, `created`, `sample`, `limitations`, `selection`, `artifacts`, `analysis_runs`, `matches`, `interpretations`, `change_ranking`, `annotations`) and adds: `report_version: 2`, `content_digest` (SHA-256 hex of canonical JSON without `generated_at`, `created`, `content_digest`), `generated_at`, `sections_present: [str]`, `stale_sections: [str]`, `tool` {`name`, `version`, `release_tag | null`, `signed: "yes"|"no"|"unknown"`}, `orientation` {`older_sha256`, `newer_sha256`}, `calibration`, `redaction`, `provenance`, `unknowns: [str]` (human-readable list of what was not run: engines absent, advisories not fetched, build facts not parsed), and any of the optional sections below. A v1 consumer that ignores unknown keys keeps working. `analysis_runs[].settings` allow-list (`SAFE_SETTING_KEYS`) gains `symbol_mode`, `symbol_servers`, `symbol_input_digest`, `launcher_version` (GHR) with validators.

### 7.2 Optional sections (Pydantic models in new `src/patchtrace/report2/contracts.py`, all `extra='forbid'`, frozen)

- `calibration`: `display_level: Literal['ordinal','bands','numeric']`, `profile: str | None`, `model_id: str | None`, `artifact_digest: str | None`, `gates: dict[str,str] | None`, `note` (fixed). Invariant validator: `display_level == 'ordinal'` implies the other four are `None`.
- `engine_evidence`: `engines: list[{name, version}]`, `rows: list[EvidenceRow]` with `match_id`, `verdict`, `tier`, `channels: list[{engine, state, note}]`, `alternative_ranks`, `limitations`, `ordinal_index: int | None` (present only if the option `include_ordinal_index` is on; default off), `explanation`.
- `series`: `builds: [{ordinal, label, sha256}]`, `pairs`, `chains` summaries, `gaps`.
- `unified_result`: `{result_id, manifest_sha256, engines, status, stale}`.
- `build_facts`: `[{side, fact, value, source, claim_level, truncated}]` with `fact` from a closed list (`file_version`, `product_version`, `original_filename`, `pdb_guid_age`, `signer_subject`, `timestamp_claim`, `manifest_exec_level`, ...).
- `symbols`: `{mode, servers: [str], staged: [{pdb_name, guid_age, sha256}], launcher_version, consent: {...}|null}`.
- `advisories`: `[{kind: 'cve'|'kb'|'cwe'|'phrase', id, vendor, url_text, fetched_at, snapshot_digest, claim_level: 'vendor-claim', text, truncated}]`.
- `leads`: `[{lead_id, kind, channels: [str], statement, evidence_ids}]`.
- `redaction`: `{profile: 'local'|'share'|'custom', paths: bool, code: bool, notes: bool, urls: 'text'|'defanged'|'removed', rules_applied: {rule: count}}`.

### 7.3 Normalization and caps (applied once, before any renderer; function `normalize_text(value, *, verbatim=False, max_chars)`)

1. Round-trip through UTF-8 with `replace` (lone surrogates to U+FFFD); 2. NFC is **not** applied (identifiers must stay byte-faithful); 3. bidi controls U+200E, U+200F, U+202A-U+202E, U+2066-U+2069 and U+061C replaced by `<U+XXXX>` tokens; 4. other C0/C1 controls and U+FEFF replaced by `?` except `\n` and `\t`, which are kept only when `verbatim=True`; 5. length caps: names 512, evidence text 8192, advisory text 4096, notes 16384 characters, with a trailing marker `[truncated N chars]`; 6. section caps: 10000 matches, 1000 advisories, 5000 build facts, 2000 evidence rows (rest summarized as `truncated`). Applied to JSON values too (so JSON consumers also receive neutralized text); the original is not recoverable from the report, by design, and the report states `normalization: "report/2 text normalization applied"`.

### 7.4 Escaping matrix (one function per cell, exhaustively tested)

| Context | Untrusted source classes | Treatment |
|---|---|---|
| JSON string | all | `json.dumps(..., ensure_ascii=False, sort_keys=True)` after 7.3; no further escaping |
| HTML text node | all | 7.3 then `html.escape(quote=True)`; newlines become `<br>` only in generated structure, not from data |
| HTML attribute | none allowed | only generated ids; test greps output for `=\"` followed by data |
| HTML `<pre>` evidence | code, assembly, evidence text | `html.escape`; no syntax highlighting markup from data |
| Markdown heading | summaries, names | 7.3, whitespace collapsed to one line, `_markdown_escape` |
| Markdown table cell | names, evidence, notes | `_cell` (collapse whitespace, escape, replace `|` with `\|`) |
| Markdown paragraph | explanations | 7.3 then `_markdown_escape` |
| Markdown fenced block | code, assembly, advisory text, JSON appendix | fence = backtick run of `max(3, longest_run_in_text + 1)`, info string empty, text unescaped but 7.3 applied |
| Displayed URL | advisory and source URLs | shown as inert text; `urls: defanged` replaces `http` with `hxxp` and `.` with `[.]`; never a link |
| Filename in export path | project name | existing destination handling; reserved Windows names rejected |

### 7.5 Error codes and exit mapping

`PT-EXPORT` (existing prefix kept): `PT-EXPORT-FORMAT`, `PT-EXPORT-INPUT` (malformed enrichment or section input; existing messages kept), `PT-EXPORT-SIZE`, `PT-EXPORT-IO`, new `PT-EXPORT-ENCODING`, `PT-EXPORT-CONTRACT` (unknown `report_version` requested), `PT-EXPORT-SECTION` (section failed validation; the export is refused, never silently dropped).

### 7.6 Manifest and versioning

`ExportManifest` gains additive fields with defaults: `report_version: Literal[1,2] = 1`, `content_digest: str | None = None`, `sections: list[str] = []`, `redaction_profile: str = 'local'`. Because `extra='forbid'`, a v1 reader rejects v2 manifests (fails closed, matching "future schema versions fail closed"); regenerate `docs/schemas/ExportManifest.json` with `tools/generate_schemas.py`. `export_project(..., report_version: int = 1, sections: SectionInputs | None = None, redaction: RedactionProfile | None = None)` keeps positional compatibility. Cache/digest inputs: none (exports are not cached). Size/time: 20 MiB, expected under 2 s for 10000 matches without code.

## 8. CLI and GUI

CLI: `patchtrace export <project> --format json|md|html --report-version 1|2 --profile local|share --include-code --include-notes --finding <id>... --out <path> [--include-ordinal-index] [--urls text|defanged|removed]`; envelope `enrichment-cli/1` with the manifest as `data`; exit codes 0, 2 invalid arguments, 3 export failure, 4 nothing to export, 5 cancelled. `share` profile forces code off, notes off, paths removed, urls defanged. (This command is the first of the "export" family the CLI umbrella spec lists as undecided; the build slice implements only this subcommand.)

GUI (Export dialog in the main window, `ui.py` export dialog; no new window): add a "Contract" combo (`Report v1 (current)`, `Report v2`), a "Profile" combo (`Local analysis`, `Share with others`), and a checklist of sections with counts (checked when data exists, disabled with reason when not: "Not available: no secondary engine ran."). A read-only preview pane (`QPlainTextEdit`, plain text, never rich text) shows the exact bytes to be written, truncated at 200 KiB with the note "Preview truncated; the file will contain the full report." Keyboard: Tab order contract, profile, sections, preview, Export; Enter activates Export only when focus is on the button. Accessible names `export.contract`, `export.profile`, `export.sections`, `export.preview`; tooltip ids with the same stems (WHAT/WHY/SOURCE). Copy: share-profile hint "Share profile removes code, notes and file paths and writes web addresses as inert text."; local-profile warning shown once per dialog "This report may contain code and file names from the binaries you analysed. Do not publish Microsoft-derived content."; calibration line in every report header "Scores are ordinal triage indices, not probabilities of a vulnerability." States: empty project "Nothing to export: no matches yet."; error "Export failed: <code>. The previous file, if any, is unchanged." Pitfalls: build the preview off the GUI thread for 10000 matches; a `QPlainTextEdit` with 20 MiB text freezes the UI, so the preview is capped as above. Offscreen tests: dialog model is a pure view-model (`export_vm.py`); 20x repeat.

## 9. Slice plan

| Slice | Scope | Exclusive files | Depends | Tier | Size | Gate | Fallback |
|---|---|---|---|---|---|---|---|
| RPT2-1 | `normalize_text`, escaping functions, fence helper, defect fixes | `src/patchtrace/report2/__init__.py`, `text.py`, `tests/test_report2_text.py` | none | sonnet (property tests) | S | hypothesis: no output contains raw bidi controls, `<`, live links; lone-surrogate regression red then green | ship fixes only |
| RPT2-2 | Contracts and `calibration` computation | `report2/contracts.py`, `calibration_block.py`, tests | RPT2-1 | sonnet | S | ordinal invariant validator tests; no artifact gives `ordinal` | none |
| RPT2-3 | Renderers v2 (json, md, html) and digest | `report2/render_json.py`, `render_md.py`, `render_html.py`, goldens under `tests/golden/report2/` | RPT2-1, RPT2-2 | sonnet | M | synergy test, golden files LF-pinned, CSP hash test | json only |
| RPT2-4 | Section builders (engine evidence, series, unified ref, symbols, build facts, advisories, leads) behind Protocol ports; each returns `None` when the producer track is absent | `report2/sections/*.py`, tests | RPT2-2; producer tracks optional | sonnet | M | each builder tested with fake ports; absent producer gives `unknowns` entry | subset |
| RPT2-5 | Integrate into `reports.export_project` and `ExportManifest` | `reports.py`, `models.py` (single-line additive fields), `docs/schemas/ExportManifest.json` regen | RPT2-3 | sonnet | S | all existing report tests unchanged and green; v1 output byte-identical | none |
| RPT2-6 | CLI `export` subcommand and GUI dialog | `cli.py` hunk, `export_vm.py`, `ui.py` export dialog (serialized by the integration owner), tooltips, tests | RPT2-5 | sonnet | M | offscreen tests, 20x repeat | CLI only |

## 10. Amendments, test and QA plan

Amendments: `docs/specs/architecture.md` "Reports": add the `report/2` paragraph and defect fixes; `docs/specs/ui.md` line 15: replace "no separate redaction controls exist yet" with the profile controls; `docs/specs/schemas.md` ExportManifest row; `docs/specs/multi-engine-evidence-panel.md` D5 ("evidence status in exported reports: later slice") now points to `engine_evidence`; the "What NOT to claim" section of `docs/specs/unified-engine/07-ui-and-cli.md` (present in the shared main checkout's newer copy, section 11 there; this worktree's older copy lacks it, re-check on the integration branch) should govern the export header wording; `docs/specs/calibration-corpus-and-model.md` section 10.3: exports carry the calibration block defined here; `docs/modules.md`: new package `report2/`; `tasks/todo.md`: add RPT2 rows. Registry untouched (program-e excluded).

Tests: goldens (JSON, MD, HTML) for the synergy fixture; hypothesis properties over arbitrary Unicode (including surrogates, bidi, fence runs, `|`, `<`, `]()`): output encodes to UTF-8, contains no raw bidi controls, Markdown renders (parsed by a tiny in-test checker) without links, headings or HTML introduced by data; HTML parsed with `html.parser` shows no `script`/`a` tags and no attribute whose value derives from data; `content_digest` stable across two runs and across LF/CRLF checkout of goldens; v1 byte-identical regression against a frozen v1 golden; size cap behaviour; atomic write failure leaves the previous file. Windows pitfalls: `.gitattributes` pinning LF for goldens, `os.replace` on a file held open by a viewer (existing error path), destination names with reserved device names, `PYTEST_CURRENT_TEST` length (short ids). Live or manual gates reported separately: opening the HTML in Edge/Firefox with the console open (no CSP violations from the hash), rendering the Markdown on GitHub and in VS Code preview, screen-reader pass of the dialog, DPI 200%.

## 11. Open questions (defaults, none blocking)

1. May the 0..83 evidence index appear at all? Default no (opt-in `--include-ordinal-index`, off, as in unified-engine D1).
2. Make v2 the default? Default: after one release cycle and owner approval; v1 remains selectable.
3. Defang URLs by default in the `local` profile? Default `text` (inert) locally, `defanged` in `share`.
4. Include `raw_response` of providers? Default never (unchanged); a future AI-narrative spec decides.
5. Add CSV for the ranking table? Default no; if added, prefix cells starting with `=`, `+`, `-`, `@`, tab or CR with a single quote and test it.
