# CAP integration plan: capa capability deltas on matched function pairs

Status: Program E phase E-1 research plan, 2026-10-14 (Sonnet 5.5). Built so far: CAP-1 (parser v2), CAP-2 (`capa_pairs.py`), CAP-3 (`capa_view.py`), CAP-5 (`intel-tools pairs` in `intelligence/tools/cli.py`), CAP-7 (`capa_hints.py`, inventory extractor; inventory is derived and unverified); the rest is not built. Charter: `docs/plans/program-e-roadmap.md` section 3. Builds on SPEC-29 tools (`docs/specs/three-tool-evidence-adapters.md`, contract `tool-evidence/1`) and the built adapter `src/patchtrace/intelligence/tools/{capa,common,normalize,delta,process}.py` (baseline: `tests/test_intel_tools_common.py` + `test_intel_tools_parsers.py` = 30 passed, 2026-10-14). Every source below was retrieved 2026-10-14.

## 1. Verdict and scope
- **Verdict: build it as a context and noise-attribution channel, never as a vulnerability detector.** capa rules describe behaviours, so the channel is silent for most memory-safety fixes; silence is unknown, never evidence against a hypothesis.
- **Build:** `capa_pairs.py` (capability deltas per matched function pair, contract `capa-pairs/1`); `capa_view.py` + `ui_capabilities.py` (Capabilities dock: old/new columns, gained/lost/moved/unchanged filter, namespace grouping, jump to pair); `capa_hints.py` (context-only observations for the hypothesis engine); parser upgrades (coverage, feature refs, taxonomy labels), raw-first cache, memory cap, rules provenance.
- **Core rules:** a function capa skipped (FLIRT library) or never found is *not compared*, never "lost"; behaviour that moved between functions is *moved*, never a gain plus a loss; differences on unchanged pairs are *detection noise*.
- **Backend and packaging:** vivisect (capa default) in the GUI, Ghidra CLI/advanced, BinExport2 deferred. Provision the pinned external capa 9.4.0, do not bundle (section 3).
- **Not built:** scores, ranking or severity from capabilities; ATT&CK/MBC as risk labels; attribution by guessing; in-process or pip capa; dynamic flavors; automatic rule or tool downloads; persisted pair deltas (derived data); a new enrichment kind.

## 2. Sources and facts
Aliases: CAPA=`https://raw.githubusercontent.com/mandiant/capa/v9.4.0/`, RULES=`https://raw.githubusercontent.com/mandiant/capa-rules/v9.4.0/`, PYPI=`https://pypi.org/pypi/`, QT=`https://raw.githubusercontent.com/qt/qtbase/v6.12.0/`.

| # | claim | source URL | retrieved | confidence |
|---|---|---|---|---|
| 1 | capa 9.4.0 is the newest release (2026-04-01; wheel `py3-none-any` 1,207,044 B, sdist 21,237,530 B; Python >=3.10; Apache-2.0). Cadence: 9.0.0 2025-02-05, 9.1.0 2025-03-04, 9.2.0 2025-06-05, 9.3.0 2025-11-12 (about 2 per year) | PYPI`flare-capa/json` | 2026-10-14 | high |
| 2 | capa and capa-rules are Apache-2.0 (the two `LICENSE.txt` are byte-identical, sha256 cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30); FLIRT `sigs/` are Mandiant-generated, not derived from IDA, Apache-2.0 | CAPA`LICENSE.txt`, RULES`LICENSE.txt`, CAPA`sigs/README.md` | 2026-10-14 | high |
| 3 | Windows asset `capa-v9.4.0-windows.zip` 35,994,071 B, sha256 670ab1a58b81f59cb57533bf4021ac1e7033fbe9b5d5cc180f796976081e3bb5; one member `capa.exe` 36,616,388 B, sha256 356db59a7f0d22b00ee63bda6ebb5b05149530eec5dd84101caef6d6bae94dfd; PE32+ x86-64, console subsystem, **no Authenticode signature** (security directory empty). Size equals the earlier session's `docs/qa.md` row; hash prefix and suffix equal | `https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-windows.zip` (own download, headers read in memory, never run) | 2026-10-14 | high (same egress proxy as the earlier session) |
| 4 | Linux asset `capa-v9.4.0-linux.zip` 47,477,971 B, sha256 07800a1d20a21eb18fc98716e2ae81b668e0c9a04defd588c8aa17ea3d3281e4; member `capa` 47,976,360 B, sha256 cb57c9ea27dda4a6aefb368caca35c3177495e611ad9af64c801d51561035218 (equals `tests/fixtures/intel_tools/manifest.json`) | `.../releases/download/v9.4.0/capa-v9.4.0-linux.zip` | 2026-10-14 | high |
| 5 | Release workflow: six assets (linux, linux-arm64, linux-py312, windows, macos, macos-arm64); Windows built on windows-2022 with Python 3.10 and PyInstaller 6.19.0, onefile, `upx=True`, `console=True`, embedding rules, sigs and a prebuilt rule cache. No checksum, signature or attestation step. GitHub's own per-asset digest field was unreadable (API and HTML blocked) [unverified] | CAPA`.github/workflows/build.yml`, CAPA`.github/pyinstaller/pyinstaller.spec`, CAPA`pyproject.toml` (extra `build`) | 2026-10-14 | high |
| 6 | Upstream tests the Ghidra backend only on ubuntu-22.04 (Ghidra 12.0, Temurin JDK 21, Python 3.10/3.13); the packaged-binary Ghidra smoke test is Linux-only. PatchTrace's stack is Ghidra 12.0.4 + JDK 25, so capa on JDK 25 is untested [unverified] | CAPA`.github/workflows/tests.yml`, `build.yml`; `docs/specs/offline-backend-installer.md` L12 | 2026-10-14 | high |
| 7 | Standalone pins: vivisect 1.3.1, viv-utils 0.8.0, python-flirt 0.9.2, pefile 2024.8.26, pydantic 2.12.4, protobuf 7.34.0 (PatchTrace pins protobuf 7.36.2). Library bounds are loose (`protobuf>=5`, `pydantic>=2`); cp312 win_amd64 wheels exist (python-flirt 0.10.0, msgspec 0.22.0; vivisect, viv-utils, dnfile are pure), so `pip --only-binary=:all:` would work, but the wheel carries no rules or sigs | CAPA`requirements.txt`, CAPA`pyproject.toml`, CAPA`doc/installation.md`, PYPI`python-flirt/json`, `vivisect/json`, `msgspec/json` | 2026-10-14 | high |
| 8 | Result document = `ResultDocument.model_dump_json(exclude_none=True)`: keys are field names (`attack`, `mbc`, `lib`, `is_subscope_rule`); address `{type, value}` with types absolute, relative, file, dn token, dn token offset, no address; `rules[name].matches` = list of [address, match tree]; attack item {parts, tactic, technique, subtechnique, id}; mbc item {parts, objective, behavior, method, id}. Real goldens agree | CAPA`capa/render/result_document.py`, `capa/render/json.py`, `capa/features/freeze/__init__.py` | 2026-10-14 | high |
| 9 | Scopes: function match key = function VA; basic block = BB VA; instruction = instruction VA; file = `no address`. Only `meta.analysis.layout.functions[].matched_basic_blocks` links a BB to its function, and only for functions with a matched BB (subscope rules included, hence it is not the evaluated set); instruction and file matches name no function. Lower-scope features merge upward | CAPA`capa/loader.py` L760-799, CAPA`capa/capabilities/static.py`, RULES`doc/format.md` L385-387 | 2026-10-14 | high |
| 10 | Coverage: `feature_counts.functions` lists exactly the functions capa evaluated; FLIRT-identified library functions are skipped and listed in `library_functions`; FLIRT runs only on the vivisect backend; any other function is absent from the document | CAPA`capa/capabilities/static.py` L152-254, CAPA`capa/main.py` L820-823 | 2026-10-14 | high |
| 11 | Upstream limitations: no handling of wrapper functions or matches in child functions (capa does not follow calls); packed programs and installers give misleading or incomplete results | CAPA`doc/limitations.md` | 2026-10-14 | high |
| 12 | Limitation rules are those with namespace exactly `internal/limitation/static`; with `-j` capa still analyses fully. Exit codes: 10 rules missing, 11 file missing, 12 rule invalid, 13 corrupt file, 14 file limitation, 15 sig invalid, 16/17/18 unsupported type/arch/OS, 20/24 Ghidra version/mode, 23 empty report, 25/26 input format/extractor | CAPA`capa/capabilities/common.py` L102-103, CAPA`capa/main.py` L122-138, L1047-1054 | 2026-10-14 | high |
| 13 | Rule cache is zlib + **pickle** (`pickle.loads`) under `$XDG_CACHE_HOME` or `%LOCALAPPDATA%\flare\capa\cache`; the standalone exe with default rules reads its embedded cache | CAPA`capa/rules/cache.py`, CAPA`capa/main.py` L664-681 | 2026-10-14 | high |
| 14 | Ghidra backend needs Ghidra >=12.0, imports and analyses into its own temp project (no reuse of Ghidriff output), the exe loads Java/Ghidra at runtime. BinExport2 backend needs the `.BinExport` and the sample (found by sha256 of `executable_id` next to it or in `CAPA_SAMPLES_DIR`), skips thunks, has no FLIRT | CAPA`capa/ghidra/README.md`, CAPA`capa/loader.py` L372-380, L422-484, CAPA`capa/features/extractors/binexport2/__init__.py` L62-92 and `extractor.py` | 2026-10-14 | high |
| 15 | vivisect analysis includes an instruction emulator for code discovery (interpretation in a Python CPU model, never native execution) | `https://raw.githubusercontent.com/vivisect/vivisect/master/vivisect/analysis/generic/emucode.py` | 2026-10-14 | high |
| 16 | PyInstaller one-file starts extract to `_MEIxxxxxx` in the temp folder every run and leave it behind when killed | `https://raw.githubusercontent.com/pyinstaller/pyinstaller/v6.19.0/doc/operating-mode.rst` | 2026-10-14 | high |
| 17 | ATT&CK: royalty-free licence for research, development and commercial use if MITRE's copyright designation and licence are reproduced in copies; MBC: perpetual royalty-free copy/derive licence on the same condition. Text taken from MITRE's repositories | `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/LICENSE.txt`, `https://raw.githubusercontent.com/MBCProject/mbc-markdown/main/tou.md` | 2026-10-14 | high |
| 18 | capa-rules top-level namespaces: anti-analysis, collection, communication, compiler, data-manipulation, executable, host-interaction, impact, internal, lib, linking, load-code, malware-family, nursery, persistence, runtime, targeting. Library rules are not rendered; nursery rules are matched by default and may lack metadata or fidelity | RULES`README.md` L74-163 | 2026-10-14 | high |
| 19 | Time on tiny synthetic PEs: 8.38-9.51 s per file (Linux, onefile start + embedded cache + vivisect). Real-binary time and memory unmeasured [unverified] | `tests/fixtures/intel_tools/manifest.json` `elapsed_s` | 2026-10-14 | high for the synthetic, none for real |
| 20 | Existing strict parser, 27.8 MB document with 20,000 matches: JSON load 1.95 s, pydantic 2.61 s, `parse()` 5.61 s, peak RSS 745 MiB (Python 3.13.16, pydantic 2.13.5, shared container; throw-away script, not committed) | own measurement | 2026-10-14 | medium |
| 21 | Prototype two-level custom `QAbstractItemModel` with model-owned filter/sort (no proxy), PySide6 6.12.0 offscreen, 100,000 rows: reset 6 ms, first paint 25 ms with 1,650 `data()` calls (identical at 10,000 rows), filter 10 ms, sort 25-40 ms, `expandAll` 0.4 s; a model reset collapses expansion and selection | own measurement (not committed) | 2026-10-14 | medium |
| 22 | Qt 6.12.0 defines `Qt::AccessibleTextRole` and `Qt::AccessibleDescriptionRole` and ships a Windows UI Automation backend | QT`src/corelib/global/qnamespace.qdoc` L2862, QT`src/plugins/platforms/windows/uiautomation/qwindowsuiaaccessibility.cpp` | 2026-10-14 | high for the cited lines |
| 23 | `.pdata` facts for the deferred extent attribution (RUNTIME_FUNCTION, chained entries, leaf functions have no entry) come from the repo's own spec | `docs/specs/unified-engine/03-extraction.md` L141 | 2026-10-14 | medium |
| 24 | No primary source found that validates capability deltas as a patch-mechanism signal (web search found capa articles and generic patch-diffing work only). Treat as a hypothesis; the SPEC-29 value gate stays `unvalidated` | web search | 2026-10-14 | n/a (absence) |
| 25 | Pages not retrievable from the sandbox (hosts blocked), cited by name only: Qt accessibility `https://doc.qt.io/qt-6/accessible.html`; Microsoft UI Automation `https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-uiautomationoverview`; x64 exception handling `https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64`; WCAG 2.2 `https://www.w3.org/TR/WCAG22/` (criteria 1.4.1, 1.4.3, 1.4.11, 4.1.3 as used by the C6 spec); PowerShell `Get-FileHash` `https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash`; ATT&CK terms `https://attack.mitre.org/resources/terms-of-use/` | not retrieved | 2026-10-14 | [unverified] |

**How capa reports a match at each scope** (rows 8-10, confirmed on the committed REAL goldens; base 0x140000000, RVA = VA - base):
| rule scope | key in `rules[name].matches` | function named by the document | PatchTrace attribution | golden example |
|---|---|---|---|---|
| function | function VA (absolute) | yes, the key; feature locations (instruction VAs) sit in the match tree | `function-start` | `get hostname` at rva:0x1053, API location 0x1065 |
| basic block | BB VA | only through `layout.functions[].matched_basic_blocks` | `basic-block-in-function`, else none | `encode data using XOR` BB 0x10be, owner function 0x10bc |
| instruction | instruction VA | no | none (CAP-9 may attribute through verified extents) | `link function at runtime on Windows` at 0x108b |
| file | `{"type": "no address"}`; evidence locations only inside the tree | no | none; listed as unattributed | `contain a thread local storage (.tls) section`, location 0x3000 |

Correction to the feature card: "capa is heavy" holds at run time (minutes, GBs, onefile start-up), not on disk (36.6 MB). The reasons to provision rather than bundle are provenance, notices, cadence, blast radius and opt-in value (section 3).

## 3. Standalone baseline versus PatchTrace value
**capa alone:** `capa -j file` gives one file's inventory of rule matches with VAs that shift between builds. It knows nothing of older/newer or of which functions changed; a hand diff keyed by rule name misses behaviour that moved between functions and mixes real change with detection noise; FLIRT-skipped and unrecovered functions are silent; provenance is argv plus a timestamp; every run starts cold.

**PatchTrace adds:**
- Pairs and explicit orientation from the stored Ghidriff/BinDiff matches (`FunctionMatch`, `FunctionPairing`), including n:m split/merge.
- The unknown/absent distinction from capa's coverage lists; noise attribution (`moved`, `detection-difference`, `not-compared`, unattributed scopes).
- Tool, rules, backend, hashes and run record in every row; a raw-first cache so each build runs once per (sha256, capa version, rules, backend), also across pair projects.
- One click to the pair in the navigator; deterministic "what this means / next" text for the E-5 guide.
- A context-only channel for hypotheses with canonical observation keys and lineage tags, so shared-origin evidence counts once.

**Workflows:** W1 "which behaviours did this update touch?" (filter Gained/Lost, open the pair). W2 "is this new capability new code?" (new function or modified pair, versus detection difference, versus moved). W3 "the advisory names CWE-X; did a changed function change behaviour in that domain?" (context lines in the detail pane and CLI). W4 CI: `intel-tools pairs --json` as a pipeline artifact. W5 (later) series: first build where a behaviour appears.

**Decision record, provision versus bundle (Windows):** provision.
1. Provenance: upstream publishes no checksum, signature or attestation and the exe is unsigned (rows 3, 5), so PatchTrace would vouch for a binary it cannot attest; BinDiff is provisioned the same way.
2. Notices: the exe embeds Python, about 20 packages, rules and FLIRT sigs; `tools/build_windows.py` refuses to publish without every notice file.
3. Cadence: capa releases about twice a year and rules change results; the pin plus `untested_version` absorb drift without a PatchTrace release.
4. Blast radius: an unsigned UPX-compressed onefile exe inside the package could taint the whole ZIP in antivirus [unverified].
5. Opt-in value for 36.6 MB; and the invariant that executables are explicit absolute paths, never PATH.
6. End users of the standalone build have no Python, so `tools/provision_intel_tools.py` serves CI and developers; users get documented manual steps with the pinned sha256 shown in the Setup tab, and optionally a consented in-app download (CAP-11).

**Backend choice and cost** (PatchTrace has Ghidra 12.0.4 + Ghidriff, BinExport2 acceptance C3, planned unified extraction S1; it has no vivisect):

| backend | extra analysis cost | independence from Ghidriff | function-id join | library skipping | verdict |
|---|---|---|---|---|---|
| vivisect (default) | one full analysis per file inside capa; 8.4-9.5 s measured for a tiny file, real files unmeasured | independent (own disassembly and function recovery) | exact start-RVA join; boundaries may differ, shown as coverage | yes (FLIRT) | GUI default |
| ghidra | second full Ghidra import and analysis per file (cannot reuse Ghidriff's); needs Ghidra >=12.0 and a JDK | shares Ghidra origin with Ghidriff and Ghidra BinExport2: correlated, counts once | closest to Ghidriff addresses | none, so more library noise | CLI/advanced; live gate L4 |
| binexport2 | none if an accepted `.BinExport` exists (BinDiff users) | shares the exporter's origin | identical to BinDiff's functions | none; thunks skipped | defer (CAP-10), experimental |

**Where SPEC-29 and the built adapter are wrong or thin (verified against code and upstream):**
1. Tool-selection text says signatures are "localized to functions and instructions": instruction and file scope name no function in the document (row 9). T5.3 already forbids guessing, but the header misleads.
2. T6.2 keys capabilities by (rule, scope) over the whole file: behaviour that moved between functions looks unchanged and detection noise on unchanged code looks like change.
3. The parser keeps only the counts of `feature_counts.functions` and `library_functions`; coverage per function is dropped, so unknown versus absent cannot be decided per pair.
4. Match-tree feature identities (API names, numbers, strings) are dropped (only RVAs kept): no "why capa matched", no exact API-hint join. ATT&CK/MBC keep only ids, not the tactic/objective names used for grouping.
5. `probe` checks that Ghidra's properties file exists, not that it is >=12.0 (capa exits 20 later); exit codes 11 and 13 fall to generic `PT-TOOL-RUN`; `process.execute` never passes `memory_limit_bytes`; when output is truncated, which matches survive depends on JSON order.
6. T7 caches normalized sets keyed by the parser contract only: a parser improvement leaves old sets valid but incomplete. Raw-first caching fixes this.
7. T1 "embeds capa-rules v9.4.0": the embedded pack is the rules submodule at build time (spec `datas`), probably equal to the tag but not byte-compared [unverified]; label it "built-in rules of capa 9.4.0".

**Rejected or deferred (fails the charter or the evidence):** whole-build capability inventory view (standalone duplicate; only deltas are shown); API/number feature deltas through capa `freeze` (not in the standalone exe, needs in-process capa, duplicates the unified engine's call-set deltas); capability counts as a score or ranking (false precision); `--restrict-to-functions` targeted runs (analysis dominates run time and file-scope rules need all functions); capa inside Ghidra via `ghidra_main` reusing the S1 program (version coupling, revisit after S1); sandbox/dynamic flavors (would need execution); capa Explorer, IDA or web uploads (duplicate UI, network).

## 4. Cross-feature links
| item | direction | anchor/evidence kind | other tracks | how used |
|---|---|---|---|---|
| matched function pairs, orientation, `match_id` | consumes | function | UE, PIL, GUI | pair groups; navigator jump through `WindowPort.select_match` |
| capability change (rule id, namespace, scope, change) | emits | capability, rule | PIL, FAB, GDE, reports | `CapabilityObservation` with key `capobs/1`; context only |
| capa rule identity (name, `rule_sha256`, pack identity) | emits | rule | YRX | provenance; YARA-X discoveries may cite it as derived, never independent |
| API features of a matched rule (`api` leaf nodes) | emits and consumes | import/API | PIL, WB2, UE | exact join to hypothesis `api_hints`; the same observation as a unified-engine call-set delta, so FAB dedupes by key `apiobs/1` |
| string features of a matched rule | emits | string | WB3 (FLOSS) | dedupe by value hash; secret-looking values redacted; different tools, same bytes |
| `compiler/*`, `runtime/*`, `executable/pe/*` rule matches | emits; consumes DIE flags | build fact | DIE | informational chip; DIE `toolchain-changed`/`packed` flags annotate rows, never reclassify |
| `HypothesisSet` families, `api_hints`, `AnchorSet` api/module | consumes | CWE, advisory phrase, API | K, PIL | highlight and context lines (bridge below) |
| CVE, KB article | neither in v1 | CVE, KB | KB, PIL | capa has no advisory or patch-date input; a KB entry may later carry a capability summary through the fabric as context only |
| ATT&CK/MBC labels | emits | grouping label | reports, GDE | grouping only; never ordering, counts or risk |
| function extents (`.pdata`, unified IR) | consumes (CAP-9) | function | UE S1 | attribution of instruction-scope matches without guessing; absent until S1 |
| raw capa output (`DerivedCache` stage `capa-raw`) | emits | provenance | series (N-way), CLI | one run per build across pair projects |
| lineage tags: `D_vivisect` or `D_ghidra`, plus `D_pe_tables`, `D_capa_rules` | emits | provenance | FAB, PIL | vivisect is independent of the Ghidra families; the ghidra backend joins them and counts once (vocabulary of `docs/specs/unified-engine/05-fusion-and-noise.md` s1.1); CAP never votes on function identity |

**Hypothesis-engine bridge (how the channel feeds SPEC-30):**
- Reads, never writes, the K-track modules: `hypotheses.RULES` (`family`, `api_hints`), `PatchHypothesis`, `AnchorSet` kinds `api` and `module`.
- Two joins, strongest first: (1) exact API-hint hit: a gained or lost capability whose matched `api` features include a hypothesis `api_hint`; (2) domain tag: the capability's namespace prefix carries a tag listed in `FAMILY_TAGS[family]`.
- Initial tags (unvalidated; CAP-7 resolves each against the committed rules inventory and removes entries that do not resolve): path to file-access (`host-interaction/file-system/*`); search-path to dynamic-linking and file-access (`linking/runtime-linking`, `load-code/*`); injection to process-launch (`host-interaction/process/create`); authorization and authentication to privilege-identity; crypto-verify to crypto-primitive. **6 of the 20 lexicon families get a tag; the 14 memory-safety, lifetime, integer, input, race and similar families get none by design**, because capa has no honest behaviour for them.
- Output `MechanismContext(support='context')`. PIL may rate a pair at most `tentative` from it, and only for a stored changed pair, a change that is not `moved`, no `toolchain-changed`/`packed`/`protected` flag, and lineage counted once with other Ghidra-origin evidence. CAP never yields `strong` or `moderate`, never a contradiction.
- CAP does not evaluate `required_observations` or `contradictions` text (data-flow facts capa cannot see). SPEC-30 negative tests covered: error strings are not capability evidence; a missing rule is absence; shared Ghidra origin is correlated; a compiler-only rebuild (control pair) gives 0 changes.
- Keys: `capobs/1 = domain_id('capobs', 1, {kind, rule_id, scope, pair: group_id})`; `apiobs/1 = domain_id('apiobs', 1, {api: api_key(name), pair: group_id, side})`; `api_key` = lower case, no module prefix, trailing A/W folded when >= 4 characters remain (dedupe and join only, never shown). Keys are project-scoped because `group_id` uses the match id.

## 5. Synergy test
Module `tests/test_capa_synergy.py`, synthetic and committed-fixture-friendly. Inputs: the real capa 9.4.0 goldens `capa-api-{older,newer}.json` (REAL output on a SYNTHETIC PE pair); a synthetic pairing; a synthetic `HypothesisSet` (from `hypotheses_for` on a hand-built `CweProfile` for CWE-73, family `path`, rule `R-PATH`, tag `file-access`). Pairing (RVAs): modified main 0x1000-0x1000 and log 0x108b-0x1096; added env newer 0x1030; removed term older 0x104d; unchanged host 0x1030-0x1053, dyn 0x1065-0x1070, xor 0x108e-0x10bc.

| channel alone | what it gives |
|---|---|
| Ghidriff pairing | 4 changed pairs (main, log, env added, term removed), no reason to look at one first |
| advisory/hypothesis | R-PATH expectations and API hints, no location |
| capa inventory (existing `delta.compute`) | 4 rule changes across the whole file (2 `newly-introduced`, 1 `removed-with-code`, 1 `unlocalized`) with per-side locations, but no grouping by pair, no unknown state (a skipped library function is invisible) and no moved detection |

**Combined expected output** (golden `expected-pairs-capa-api.json`, contract `capa-pairs/1`):
- gained 2: `query environment variable` in the added pair env (newer 0x1030) and `write file on Windows` in the modified pair log (0x108b to 0x1096, with that pair's `match_id`).
- lost 1: `terminate process` in the removed pair term (older 0x104d). unchanged 2: `get hostname` (host) and `encode data using XOR` (xor, attributed through capa's layout). moved 0, not-compared 0.
- unattributed, outside the pairs: `link function at runtime on Windows` (instruction scope, both sides) and `contain a thread local storage (.tls) section` (file scope, newer only). Library-kind `contain loop` is hidden.
- hypothesis context: exactly one `MechanismContext(R-PATH, pair log, gained write file on Windows, support='context')`; none for env, term or the unattributed items.
- Result: from 4 undifferentiated changed pairs to 1 explained lead plus 3 "no capability link" notes, with zero leads from noise. A plumbing proof, not accuracy evidence (value gate stays `unvalidated`).

**Companion tests:**
- `test_moved_capability_is_candidate_not_gain_or_loss` on a new REAL pair `capa-move` (older `host` calls `GetComputerNameA`; newer `host` calls a new helper that does): `get hostname` is lost in the modified pair host and gained in the added helper; both rows are classified `moved` and the summary counts one moved candidate, gained 0, lost 0, because capa does not follow calls (row 11). The rules were checked in a throw-away prototype on DERIVED variants of the real goldens: relocating `get hostname` from host to dyn gives two `moved` rows; marking the older host as a FLIRT library function gives `not-compared` instead of `gained`; swapping orientation swaps gained and lost.
- `test_control_pair_has_no_pair_changes` on `capa-control` (all RVAs shift by 0x40, every pair unchanged): 0 changes.
- `test_library_function_is_not_a_lost_capability` and `test_unrecovered_function_is_not_compared` on DERIVED goldens (hand-edited from the real ones, labelled).
- `test_swapping_orientation_swaps_gained_and_lost`; `test_absence_never_contradicts`.

## 6. Traps and guards
| trap | guard (test) |
|---|---|
| UI implies a vulnerability, fix, risk or intent | neutral words (Gained, Lost, Moved, Same, Not compared); no red/green; no severity or importance ordering; always-visible footer; capa's rules are written mainly for hostile software, so a Cautions line says ordinary code can match them; banned-stem sweep over all UI-authored strings: prefixes `probab`, `likelihood`, `vulnerab`, `exploit`, `risk`, `threat`, `malicious`, `malware`, `suspicious`, `dangerous`, `severity`, `critical`; whole words `safe`, `secure`, `fix`, `fixed`, `verified`, `proven`, `certain` (`test_banned_strings_never_appear`) |
| ATT&CK/MBC tactic names read as accusations ("Defense Evasion") | labels only in the detail pane and the optional group-by modes, prefixed "Rule label (grouping only)"; `test_labels_never_change_classification_or_order` |
| capa does not follow calls: wrappers, inlining, outlining move behaviour | `moved` candidate state with counterpart rows; net counts per rule; standing caution (row 11) |
| FLIRT-skipped or vivisect-unrecovered function read as "no capability" | coverage model: side state `not-evaluated`, pair `not-compared` |
| same code, different detection on an "unchanged" pair | `noise='detection-difference'`, collapsed group; never counted as gain or loss |
| instruction and file-scope matches name no function | separate `unattributed` list; never in pair rows; no nearest-preceding-start guess (functions can consist of chained non-contiguous chunks, `docs/specs/unified-engine/03-extraction.md` L141) |
| engines disagree on function boundaries | exact start-RVA join only; coverage counts shown ("capa evaluated both sides of N of M matched pairs"); live gate L2 |
| comparing runs with different capa, rules, backend or options | `comparability()` refuses with reasons (`PT-TOOL-MISMATCH`), no entries |
| packed or protected code, layered runtimes (Go, Rust) | `capa-limitation` and DIE `packed`/`toolchain-changed` flags annotate; chip when `compiler/*` or `runtime/*` rules match; rows capped, never hidden |
| shared-origin double counting (ghidra backend with Ghidriff) | lineage tags; contexts carry them; FAB counts once |
| absence of a capability change used against a hypothesis | contexts only add; no code path emits a contradiction from absence (`test_absence_never_contradicts`) |
| hint table is an unvalidated semantic claim | versioned, tagged `unvalidated`, each entry must resolve in the committed rules inventory (`test_every_hint_resolves_in_pinned_inventory`); contexts only in the detail pane and CLI |
| hostile rule names, strings, function names, stderr | `display_text`, `PlainLabel`, `QPlainTextEdit.setPlainText`, template tooltips; hostile-string tests |
| secret-looking string features | `secret_kind` redaction by default; `--show-secrets` only in the CLI |
| capa's rule cache is a pickle | never share a cache dir: private HOME/XDG/LOCALAPPDATA per run (already), custom rule dirs digested; `test_capa_cache_dir_is_private` |
| raw capa output embeds scratch paths (`meta.analysis.rules`, `meta.argv`, `meta.sample.path`; goldens show `/tmp/_MEIxxxx/rules`) | parser never stores them; exports never copy raw sidecars; identities exclude them |
| vivisect emulates instructions on hostile input; DoS | private scratch, env allow-list, timeout 1800 s, stdout 64 MiB, new `memory_limit_bytes` cap; disclosure line in the run preview (no FLOSS-style consent gate, Q6) |
| onefile extraction path length on Windows (`_MEI` tree under the scratch TEMP) | scratch path guard for capa (proposed limit 90 characters up to `tmp`, to be confirmed at live gate L6) |
| stale or partial evidence | stale only when artifact, cache key or contract differ (a pairing change recomputes the derived delta); partial result means no comparison |
| untested capa version; quarantined `capa.exe` | `untested_version` banner and golden refresh on pin bump; blocked state names the pinned sha256, never silently skipped |

## 7. Contracts
Additive only; models frozen, `extra='forbid'`, strict.

**`common.py` additions (CAP-1):**
- `FeatureRef{kind: api/number/string/substring/regex/bytes/mnemonic/offset/characteristic/section/export/import/function-name/class/namespace/property/com/operand/match, value <= 120 via display_text, rva|None}`; global features (os, arch, format) are not kept.
- `TaxonomyLabel{scheme: attack/mbc, group <= 80, name <= 120, ident <= 32}`.
- `CapabilityEvidence += features <= 16 (successful leaf nodes, sorted, deduped), labels <= 32`.
- `FunctionCoverage{evaluated: sorted RVAs, library: sorted RVAs, truncated}`, caps 262,144 each; `ToolEvidenceSet += coverage: FunctionCoverage | None`.
- `Attribution += 'contained-in-function'` (reserved for CAP-9, never emitted in v1); `ErrorCode += 'PT-TOOL-PAIRING'`.
- Old rows stay readable (defaults). A stored set without `coverage` is re-parsed in memory from its hash-verified raw sidecar, else state C13.

**`capa_pairs.py` (contract `capa-pairs/1`, derived, never persisted, schema generated):**
- `PairGroup{group_id ('m:<match id>' or 'u:<older rva>:<newer rva>'), match_id|None, category (modified/added/removed/unchanged/ambiguous/split/merged/unmatched), older_rvas, newer_rvas, older_names, newer_names}`, built by `groups_from_project(matches, raw_matches, bases, sizes)` with the same RVA rules as `FunctionPairing`; n:m groups compare side unions.
- `PairCell{state: present/absent/not-evaluated/no-function, reason|None, matches, links <= 4 (EvidenceLink), features <= 16}`.
- `PairChange{change_id, group_id, match_id, category, rule_id, namespace, scope, kind (capability/library), change: gained/lost/moved/unchanged/not-compared, noise: none/detection-difference, relocation: none/candidate, older, newer, labels, observation_key}`; unchanged rows are materialized only on request (counts always present).
- `Unattributed{rule_id, scope, namespace, change, older_matches, newer_matches, reason: file-scope/instruction-scope/basic-block-without-layout/address-rejected}`; `CoverageSummary{matched_groups, both_evaluated, older_library, newer_library, older_not_recovered, newer_not_recovered, ambiguous_groups, attributed_matches, total_matches}`.
- `PairCapabilityDelta{contract, comparable, reasons, engine='capa', older_run_id, newer_run_id, pairing: available/unavailable, changes, unattributed, coverage, flags (existing QualityFlag), counts, notes, truncated, value_gate='unvalidated'}`. Limits: rows 100,000, groups 200,000.
- Rules (prototyped on the real goldens, section 5): gained/lost only when both sides are `evaluated` (or one side is `no-function` and the other evaluated); `moved` needs the same (rule, scope) gained and lost in different non-noise groups; every involved row becomes `moved` and `counts['moved']` counts distinct (rule, scope) candidates; pairs categorised `unchanged` with differences are noise; ambiguous and unmatched groups give no rows; orientation swap is exact.

**`capa_hints.py` (`capability-hints/1`):** `Hint{id, namespace_prefix, tag, note}`; tag vocabulary file-access, process-launch, dynamic-linking, privilege-identity, crypto-primitive; `FAMILY_TAGS{family: tags}`; `capability_context(hypotheses, observations) -> tuple[MechanismContext]`, `MechanismContext{hypothesis_id, rule_id, group_id, observations, api_hint_hits, support='context', lineage, limitations}`.

**Rule-set pinning, provenance, consent:**
- Default rules are the ones embedded in the pinned exe; identity `embedded:<executable sha256>` (existing `ToolManifest.rules_identity`); label "built-in rules of capa 9.4.0 (Apache-2.0)". Upstream pairs capa and capa-rules releases with the same tag (CHANGELOG raw diffs), but the embedded pack was not byte-compared with the tag [unverified].
- A custom rules folder is advanced and explicit: copied into the scratch, `tree/1` digest recorded as `rules_sha256`, label "custom folder, digest abcd1234"; it must match capa's major version (otherwise capa exits 12, `PT-TOOL-INPUT`); PatchTrace does not review rule text (YAML and regular expressions) and says so in Setup; rules are never fetched automatically.
- Comparison needs the identical rules identity on both sides (existing `comparability`); a capa or rules change is a cache miss and a new run, never a rewrite of stored evidence.
- Consent: running capa is an explicit button with an exact preview and no network; any download (tool or rules) is never automatic: v1 offers manual steps or the CLI provisioning tool, CAP-11 adds a dialog that shows URL, size and SHA-256 before a byte is fetched.
- Licences recorded in the pin: capa, capa-rules and FLIRT sigs Apache-2.0. ATT&CK and MBC text is displayed only as capa emits it; if a taxonomy table is ever vendored, MITRE's copyright designation and licence are reproduced (row 17).

**Errors, store, cache, limits:**
- Errors: existing `PT-TOOL-*` plus `PT-TOOL-PAIRING` (no completed analysis run or unusable pairing; the panel still shows per-side totals).
- Store: reuse kinds `tool-run` and `tool-evidence` (frozen seam); no new kind.
- Cache: raw-first in the existing `enrichment/cache.py` `DerivedCache`, stage `capa-raw`, key = existing `cache_key(artifact_sha256, manifest, options)`, i.e. (binary sha256, capa version + executable sha256, rules identity, signatures, backend + version, options, contract); payload = zlib(raw stdout) with those inputs (str to str, as `DerivedCache.put` requires) in the manifest; admission failure is a soft miss, never an analysis failure. A hit re-parses with the current parser, so parser changes never invalidate raw output; options token `argv: capa/2` when argv or parse semantics change. Cross-project reuse needs a profile `cache_dir` (opt-in, like Ghidriff raw output). Derived pair deltas: in-memory LRU(4) keyed by (older evidence content id, newer evidence content id, pairing digest, `capa-pairs/1`).
- Limits: timeout 1800 s per side (10..86,400), stdout 64 MiB, stderr 256 KiB, `max_parallel` 1, `memory_limit_bytes` default 8 GiB (RLIMIT_AS counts virtual memory; to be measured; 0 = off; a kill is `PT-TOOL-LIMIT`); parse budget 20,000 matches in <= 15 s and <= 1.5 GiB peak (measured 5.6 s, 745 MiB); pair delta for 20,000 items <= 5 s; view-model build for 100,000 rows <= 2 s.

## 8. CLI and GUI
**CLI** (envelope `enrichment-cli/1`, exit 0/2/3/4/5; dispatcher hook planned by T0): `patchtrace intel-tools pairs PROJECT [--engine capa] [--change gained,lost,moved,unchanged,not-compared] [--namespace PREFIX] [--include-noise] [--include-library] [--show-features] [--hypothesis CVE-ID] [--show-secrets] [--json]` reads stored evidence and the stored pairing and never runs a tool. Exit 0 = comparable with gained/lost/moved rows, 4 = comparable without, 2 = evidence missing for a side or no completed analysis (stderr says which), 3 = rejected (mismatch, stale, corrupt), 5 = cancelled. `intel-tools probe` also prints the rules label ("built-in rules of capa 9.4.0 (embedded)" or "custom folder, digest abcd1234") and the pin status. Running capa stays `intel-tools run` (T0). Abbreviated output:
```
{"command":"intel-tools pairs","contract":"enrichment-cli/1","status":"complete","warnings":[],"result":{"contract":"capa-pairs/1",
 "comparable":true,"engine":"capa","pairing":"available","counts":{"gained":2,"lost":1,"moved":0,"unchanged":2,"not-compared":0},
 "coverage":{"matched_groups":7,"both_evaluated":7},"value_gate":"unvalidated","changes":[{"rule_id":"write file on Windows",
 "namespace":"host-interaction/file-system/write","scope":"function","change":"gained","category":"modified","older":{"state":"absent"},
 "newer":{"state":"present","matches":1,"links":[{"function_id":"rva:0x1096","rva":4246,"attribution":"function-start"}]}}]}}
```
**Placement:** `QDockWidget` "Capabilities" (object name `capabilities.dock`), right area, tabified with `evidence.dock`, hidden until opened; opening it never runs capa (analyst control: Run is an explicit button) and never deletes anything; action `capabilities.action` in the Analysis menu, shortcut Ctrl+Shift+A (free: window uses Ctrl+E/I/N/O/R/S, F1, F5; evidence Ctrl+Shift+E; unified Ctrl+Shift+U); layout stored by the host (no `capabilities/geometry` key). Tabs `capabilities_tabs`: [Changes] (default) and [Setup and run]. Registered as `PANEL` through the GUI panel registry (GUI plan F5); `create_panel(ctx)` in `ui_capabilities.py` builds the widgets.

**Changes tab (typical 900 px):**
```
Filter: [Changes (gained, lost, moved) v]  Group by: [Namespace v]  [search rule, namespace, function...]
[ ] Show detection differences  [ ] Show not attributed to a function  [ ] Show building-block rules  [Copy]
Summary: 2 gained | 1 lost | 0 moved | 2 unchanged | 0 not compared | capa evaluated both sides of 7 of 7 matched pairs
Capability                     | Older              | Newer               | Change   | Function pair (older -> newer)
v host-interaction/file-system (1)
  write file on Windows        | absent             | present, 1 match    | + Gained | modified: 0x108b -> 0x1096
v host-interaction/environment-variable (1)
  query environment variable   | no function        | present, 1 match    | + Gained | added: -> 0x1030
Detail (read-only): Change / Where / Older / Newer / Why capa matched / Rule / Cautions / Next steps / Provenance
Footer (always visible): Capabilities are behaviours that capa rules recognise in code. A change means a recognised
behaviour appeared, disappeared or moved between functions. It does not say what the change is for, and it says
nothing about defects or about the intent of the code. capa does not follow calls, so a behaviour may only have moved.
```
- Cell texts: `present, N match(es)`, `absent`, `not evaluated: library function`, `not evaluated: function not found by capa`, `no function` (added or removed side). Glyphs ASCII: `+` Gained, `-` Lost, `~` Moved (candidate), `=` Same, `?` Not compared. Badge fills neutral (blue-grey, lavender, amber, grey; never red or green), text always present; contrast >= 4.5:1 for text and >= 3:1 for non-text by a pure test (C6 `contrast_ratio`).
- Group by: Namespace (default; first two path components), Function pair, ATT&CK tactic label, MBC objective label, None. Filter: Changes (default), Gained, Lost, Moved, Unchanged, Not compared, All. A flags banner lists DIE/capa flags in words ("Comparison may be distorted: ...").
- Anti-deception rules: default order is namespace then rule name (never by count or "importance"); counts are called "changes", never "findings"; "Same" means recognised on both sides, not identical code; a detection difference is never called new or removed; ATT&CK/MBC labels are absent from the table unless chosen as the grouping; every row can show the features that made capa match so a reader can judge a false match; no colour carries meaning alone.
- Detail pane (plain text, fixed headers): Change; Where (pair, match id, category); Older and Newer (function, matches); Why capa matched (up to 16 feature refs per side, secrets redacted); Rule (namespace, scope, `rule_sha256` first 12, library flag); Rule labels (ATT&CK/MBC, grouping only); Cautions; Next steps (teach hook); Provenance.
- Teach hooks (charter 8, `explain(change)`, fixed templates, no AI): `capabilities.gained` "capa recognises this behaviour in the newer function but not in the older one. Next: open both functions and look for the calls or constants listed under Why capa matched on the other side." `capabilities.moved` "capa saw this behaviour in different functions in the two files. Usually code moved: a helper was added, inlined or split. Next: open the counterpart rows and compare the calls they contain; if the same calls appear, nothing new was added." `capabilities.not_compared.library` "capa skipped this function because it looks like a known library routine, so nothing can be said about it. Next: compare the function text in the code panes." `capabilities.not_compared.not_found`, `capabilities.detection_difference` ("the matched functions are unchanged, yet capa's result differs; the difference comes from analysis, not from new code"), `capabilities.unattributed.file`, `capabilities.unattributed.instruction`, `capabilities.new_function`, `capabilities.removed_function`.
- Copy provenance (Ctrl+C, LF, plain text, <= 16 KiB, deterministic): `PatchTrace capability change (behaviours recognised by capa rules; says nothing about defects)` / `Project, analysis run, STALE` / `Pair: group id, match id, category, older 0x.. name -> newer 0x.. name` / `Change, rule, scope, namespace` / `Older and Newer cell text` / `capa version, executable sha256, rules label and identity, backend, options` / `Older and newer run ids and artifact sha256` / `Cautions` list.

**Model/view:** `CapabilityTreeModel(QAbstractItemModel)` (feature-owned, GUI plan open question 14), two levels (group, row); order held in model-owned index lists (`view: list[(group, list[row])]`); `sort()` override over precomputed keys; a filter rebuilds the lists with one reset; no `QSortFilterProxyModel`, no `ResizeToContents`, no `expandAll`; `setUniformRowHeights(True)`; selection and expansion restored by key after every reset (measured: a reset collapses everything); `CapabilityDelegate` draws text only; rows are prebuilt short strings, detail and tooltips built on demand. Budgets: `data()` calls for first paint, a sort and a filter each <= 7 x visible cells x 1.2 + 20 and independent of row count (asserted at 10k and 100k); first paint <= 200 ms, filter <= 100 ms, sort <= 150 ms (5x CI slack); memory <= 64 MiB per 10k rows. Caps: rows 100,000 (state C11), detail 4,000 characters, clipboard 16 KiB; groups start expanded only when <= 20 rows are shown.

**Keyboard and accessibility** (Qt 6.12 `AccessibleTextRole` and `AccessibleDescriptionRole`, UI Automation backend, WCAG criteria as in C6, see row 25): arrows, PageUp/PageDown, Home/End in the tree; Enter = go to the pair; Ctrl+C = copy provenance; Space = focus the detail pane; tab order filter, group-by, search, three checkboxes, Copy, tree, detail, Copy provenance, Go to pair, Setup tab.
- Accessible names (exact): dock "Capabilities panel"; tabs "Capability views"; tree "Capability changes by function pair"; filter "Filter capability changes"; group "Group capability changes by"; search "Search capabilities by rule, namespace or function"; detail "Selected capability change details"; copy "Copy provenance of selected capability change"; goto "Go to selected function pair in the navigator"; run "Run capa on both files"; cancel "Cancel capa run"; path "capa executable path".
- Item `AccessibleTextRole`: "Capability write file on Windows, gained, older absent, newer present 1 match, function pair 0x108b to 0x1096"; group: "Namespace host-interaction/file-system, 1 change". Status text is announced through `ctx.announce` (GUI plan F6), not by `setText` on an empty accessible name (C6 rule). Real NVDA/Narrator output is a manual gate.
- Tooltip ids (WHAT/WHY/EFFECT/SOURCE/Availability, unique, no angle brackets, one appended block): `capabilities.dock`, `.action`, `.tabs`, `.filter`, `.group_by`, `.search`, `.show_noise`, `.show_unattributed`, `.show_library`, `.table`, `.detail`, `.goto`, `.copy`, `.refresh`, `.retry`, `.copy_error`, `.stale_banner`, `.footer`, `.run`, `.cancel`, `.probe`, `.path`, `.browse`, `.backend`, `.rules`, `.timeout`, `.preview`, `.log`; templates `capabilities.row`, `.cell`, `.group` (untrusted values only as parameters).

**States and exact copy** (plain text; status line role Status; precedence C6 > C7 > C5 > C10 > C4):
| id | trigger | text |
|---|---|---|
| C0 | no project | "Open a project to compare capabilities." |
| C1 | capa not set up (blocked) | "capa is not set up. Capability comparison needs the separate program capa 9.x. PatchTrace never downloads it by itself. Choose an installed capa on the Setup tab or follow the setup steps there." |
| C2 | no results yet | "No capability results for this project yet. Run capa on the Setup tab to compare the behaviours capa recognises in the older and the newer file." |
| C3 | running | "Running capa on the {older/newer} file ({n} of 2). This can take several minutes per file." plus indeterminate bar and elapsed time |
| C4 | ready | table, summary strip, detail |
| C5 | one side did not finish | "capa did not finish for the {side} file ({reason}). A missing result is unknown, not 'no capabilities'. No comparison is shown." |
| C6 | assembly failed | "Capability results could not be assembled: {code}: {message}. Stored capa results are unchanged." with Retry and Copy details |
| C7 | stale | "These results describe a different file pair, capa setup or analysis than the one on screen. Values are kept for reference only. Run capa again to refresh." |
| C8 | pairing unavailable | "Function pairs are not available for this project (no completed comparison), so changes cannot be tied to functions. Totals per side are shown without pairs." |
| C9 | compared, no changes | "capa recognises the same behaviours in the matched functions of both files. This does not mean the code is the same: capa only recognises behaviours its rules describe." |
| C10 | tool unusable | "The configured capa cannot be used: {probe reason}." |
| C11 | too many rows | "Too many rows to display ({n}). Narrow the filter." |
| C12 | truncated | "capa reported {m} matches; PatchTrace kept {n}. The list is incomplete." |
| C13 | needs refresh | "Stored capa results predate this panel's coverage data. Refresh re-reads the saved capa output; capa is not run again." |

Setup steps shown under C1 (values come from the pin file at run time): "1. Download capa-v9.4.0-windows.zip from the capa releases page (35,994,071 bytes). 2. Check that its SHA-256 is 670ab1a5...3bb5 (PowerShell: Get-FileHash). 3. Unzip capa.exe into a folder you control. It is not signed, so Windows or your antivirus may warn about it. 4. Press Browse, choose capa.exe, then press Probe capa." Run preview: "Will run: capa 9.4.0 (built-in rules, vivisect backend) on private copies of the older and newer files (SHA-256 abcd..., 1234...). Time limit 1800 s per file. capa reads the files as data and may interpret small parts of the machine code in a Python model to find code; the files are never started by Windows and nothing is uploaded."

**Setup and run tab:** executable combo + Browse + Probe (candidates from `runtime_discovery` extended with `capa_executables`; never PATH; discovery never executes; path remembered in `QSettings` `capabilities/tool/path` only after a successful explicit probe); probe lines follow the BinDiff P0-P5 table of `multi-engine-evidence-panel.md` s16.3 with capa wording and pin status pinned/tested/untested-newer; backend (vivisect; Ghidra offered only with a probed Ghidra >= 12.0 directory and a Java home); timeout spin; Run; Cancel; bounded log (200 lines); pin facts (URL, size, sha256). Run uses the T0 runner on an unparented `QThread` held in a module registry; rows are persisted in a GUI-thread slot; generations drop stale results; shutdown cancels and joins; workers receive immutable requests only.

**Qt/PySide6 pitfalls:** unparented threads kept in `_LIVE_THREADS` (destroying a running QThread aborts); proxy models are too slow (C6 measured); a reset drops expansion and selection; `QSettings` values may come back as str (parse defensively); late signals after dock deletion need `shiboken6.isValid`; labels must be PlainText; `createIndex` internal ids encode the group in the two-level tree; offscreen cannot test UI Automation, DPI or glyph fonts (manual gate).

**Offscreen tests** (pytest-qt, `QT_QPA_PLATFORM=offscreen`, standalone panel plus one through `MainWindow`): `test_state_c0` to `test_state_c13`, `test_untrusted_names_are_plain_text`, `test_filter_group_search_sort_update_rows`, `test_selection_and_expansion_survive_reset`, `test_enter_emits_pair_activated`, `test_ctrl_c_copies_provenance`, `test_accessible_names_and_text_roles`, `test_badges_have_text_and_contrast`, `test_data_calls_independent_of_row_count_10k_100k`, `test_run_persists_on_gui_thread`, `test_cancel_discards`, `test_project_switch_drops_results`, `test_close_cancels_and_joins`, `test_worker_never_touches_widgets`, `test_mainwindow_seam_is_minimal`; the suite runs 20 times in one session without abort (`--keep-duplicates`, faulthandler).

## 9. Slice plan
Prerequisite **T0** (not CAP-owned, assign to one builder first): completion of the shared SPEC-29 core (`intelligence/tools/{runner,store,cli}.py`, `tools/provision_intel_tools.py`, `tools/intel_tools_pin.json` seeded with rows 3-4, `tools/generate_intel_tools_schemas.py`, `docs/schemas/intel-tools/`, `tests/test_live_intel_tools.py`, `.github/workflows/live-intel-tools.yml`).

| slice | scope | exclusive files | deps | tier (reason) | size | gate | fallback |
|---|---|---|---|---|---|---|---|
| CAP-0 | spec amendments, modules/todo/qa rows (section 10) | docs only | none | haiku (docs) | S | links valid, no code | integration owner applies |
| CAP-1 | contracts + parser upgrade: coverage, features, labels, exit 11/13, Ghidra >=12.0 probe check, memory-cap option, in-memory re-parse | `intelligence/tools/common.py` (additive), `intelligence/tools/capa.py`, `tests/test_capa_parser_v2.py`, `tests/fixtures/intel_tools/capa/capa-library-derived-*.json` (DERIVED), `capa/MANIFEST.capa-v2.json` | none | sonnet (spec-driven, additive) | M | the 30 existing tool tests unchanged and green; new tests red then green; ruff; suite twice | land the `common.py` hunk alone first on conflict |
| CAP-2 | pair groups, pair delta, observations | `intelligence/tools/capa_pairs.py`, `tests/test_capa_pairs.py`, `tests/test_capa_synergy.py`, `tests/capa_pairs_pe.py` (builder of the `capa-move` pair), fixtures `capa-move-*.json`, `expected-pairs-capa-api.json` | CAP-1 | sonnet (pure algorithm with property tests) | L | synergy and property tests green; 20,000-item bound; no Qt import | derive `capa-move` goldens (labelled) if the pinned capa is unavailable |
| CAP-3 | view-model, filters, grouping, provenance block, teach hooks | `intelligence/tools/capa_view.py`, `tests/test_capa_view.py` | CAP-2 | sonnet (pure view-model, table-driven tests) | M | banned-string sweep, 100k data-cost test, subprocess no-Qt test | none |
| CAP-4 | raw-first cache + memory-cap glue | `intelligence/tools/capa_cache.py`, `tests/test_capa_cache.py` | CAP-1, T0 runner Protocol | sonnet (cache protocol, corruption tests) | M | corrupt entry is a miss, private cache dir, hit re-parses without spawning | skip the cache (runner still works) |
| CAP-5 | CLI `intel-tools pairs`, probe rules label | `intelligence/tools/cli.py` (after T0), `tests/test_capa_cli.py` | CAP-2, T0 | sonnet (small CLI on the existing envelope) | S | envelope, exit codes, redaction | none |
| CAP-6a | Capabilities dock, Changes tab (stored data only) | `src/patchtrace/ui_capabilities.py` (`create_panel(ctx)`), `PANEL.tips` (no `tooltips.py` block and no `ui.py` seam, GUI plan F5), `tests/test_capabilities_ui.py` | CAP-3, GUI framework E-2 | sonnet, capable tier (C6 pattern, thread and a11y rules are written down) | L | states C0-C13, 20x repeat, data-cost gates, accessible names; the `PANEL.tips` entries need no shared-file edit | ship without the registry hook |
| CAP-6b | Setup and run tab, probe, discovery, run thread | same file, `runtime_discovery.py` (`capa_executables`), `tests/test_capabilities_run.py` | CAP-6a, T0 | sonnet, same builder as 6a (one file, sequential) | M | thread tests, no widget in workers | CLI-only run |
| CAP-7 | capability hints + hypothesis context | `intelligence/tools/capa_hints.py`, `tools/capa_rules_inventory.py`, `tests/test_capa_hints.py`, `tests/fixtures/intel_tools/capa/rules-inventory-9.4.0.json` (names, namespaces, scopes, lib flag, rule sha256; no rule text) | CAP-3 | sonnet for the table; haiku for the inventory extractor (mechanical) | M | every hint resolves in the inventory; absence never contradicts | ship an empty table, API-hint join only |
| CAP-8 | live acceptance | `tests/test_live_capa_pairs.py`, `.github/workflows/live-capa.yml` | CAP-2, T0 pin | sonnet (mirrors `live-bindiff`) | M | Linux required leg green, Windows advisory; blocked statuses recorded | record BLOCKED |
| CAP-9 | extent attribution of instruction-scope matches via unified IR | `intelligence/tools/capa_extent.py` | SPEC-31 S1 | sonnet (isolated adapter over the S1 reader) | M | no guessing; leaf functions stay unattributed | deferred |
| CAP-10 | BinExport2 backend (experimental) | `capa.py` backend token, tests | C3, live validation | sonnet (flag plus live parity) | M | live parity with vivisect on the synthetic pair | deferred |
| CAP-11 | consented in-app "Set up capa" download | `src/patchtrace/ui_capabilities_setup.py` | CAP-6b, owner decision | sonnet (consent flow modelled on SPEC-08) | M | exact URL, size, sha256 preview; verify before use | manual steps only |

Order: T0 and CAP-0 first; CAP-1; then CAP-2 and CAP-4 in parallel; then CAP-3, CAP-5, CAP-7; then CAP-6a and CAP-6b; then CAP-8; CAP-9 to CAP-11 later. Opus only for a demonstrated cross-thread Qt crash or a disputed hint-table semantic.

## 10. Amendments required, test and QA plan
**Amendments (integration owner applies):**
- `docs/specs/three-tool-evidence-adapters.md`: status line; tool-selection text on "localized to functions and instructions"; T2 add `FeatureRef`, `TaxonomyLabel`, `FunctionCoverage`; T4 add `memory_limit_bytes` and the scratch path guard; T5.3 note that `layout.functions` is not the evaluated set and that coverage comes from `feature_counts` and `library_functions`; T6.2 keep the inventory delta and add the pair delta `capa-pairs/1`; T7 raw-first cache; T10 update open items.
- `docs/specs/patch-intent-localization-engine.md` scoring contract: capability observations are context only (`support='context'`), never mechanism support alone, never a contradiction from absence, carry lineage tags and a canonical `observation_key`.
- `docs/modules.md` rows `capa pairs`, `capa view`, `capa hints`, `capa cache`, `capabilities UI`; `tasks/todo.md` and `docs/qa.md` CAP blocks (append only) including rows 19-21 above.
- Code (owners per section 9): `capa.py` `classify_exit` maps 11 and 13 to `PT-TOOL-INPUT`, the probe requires Ghidra >= 12.0, `execute` passes `memory_limit_bytes`, truncation keeps localized scopes first; `runtime_discovery.py` gains `capa_executables`; `tools/frozen_smoke.py` imports `capa_pairs`, `capa_view`, `ui_capabilities`; `tools/build_windows.py` ships the pin file as package data; `pyproject.toml` registers the marker `live_capa`; MITRE ATT&CK and MBC notice lines enter `third_party/notices` only if a taxonomy table is ever vendored (not planned). `.gitattributes` already covers `tests/fixtures/intel_tools/**` and `docs/schemas/**/*.json`.
- Pin entries (T0): rows 3-4 values with executable members, `trust: trust-on-first-use`, and a comparison with GitHub's per-asset digest when reachable.

**Test and QA plan.**
- Fixtures: only synthetic PEs from `tests/test_intel_tools_pe.py` (new builder `tests/capa_pairs_pe.py`), real capa output on them (labelled), derived goldens labelled DERIVED; no Microsoft binary, PDB or Winbindex label.
- Properties (`hypothesis`): orientation swap swaps gained and lost; pair order is irrelevant; identical evidence gives no changes; `not-compared` never counts as lost; `moved` needs both a gain and a loss; JSON key order is irrelevant; labels never change classification.
- Goldens: `expected-pairs-capa-api.json`, `expected-pairs-capa-move.json`, CLI JSON goldens (timestamps and paths ignored).
- Windows pitfalls (roadmap checklist): CRLF (covered by `.gitattributes`); 32,767-character `PYTEST_CURRENT_TEST` (short explicit parametrize ids); coarse `time.monotonic()` (`>=`); YAML plain scalars with `: ` in the workflow; wheels-only installs (no new dependency); hermetic tests (fake executables from `tests/fake_exe.py`; live tests declared and never skipped silently).
- **Live gates only CI or the owner can close:** L1 Linux required leg (probe, pinned version text, end-to-end pair delta on the synthetic pairs equals the goldens) and Windows advisory leg (first Windows run of any tool); L2 coverage on a self-built real-ish DLL (Tier W fixtures): share of capa function starts equal to a Ghidriff function start on the same side; L3 time and memory of vivisect on a real driver on the owner's machine (the Microsoft binary stays local); L4 Ghidra backend with Ghidra 12.0.4 + JDK 25; L5 antivirus and SmartScreen behaviour for unzipping and running `capa.exe`; L6 onefile extraction under 60- and 120-character scratch roots; L7 NVDA/Narrator, 125/150/200% DPI, glyph fonts, frozen-EXE dock smoke.

**Charter evidence map (feature done = all nine evidenced):**
| charter item | evidence |
|---|---|
| 1 pair-aware | `test_pair_delta_*`, group tests for split/merge/ambiguous; orientation columns |
| 2 delta not inventory, unknown versus absent | `test_library_function_is_not_a_lost_capability`, `test_unrecovered_function_is_not_compared`, inventory view not built |
| 3 anchors in and out | cross-feature table; `capobs/1`, `apiobs/1` key tests; hint join tests |
| 4 triage value, no averaging | `test_absence_never_contradicts`, lineage tests, no score fields (schema test) |
| 5 one click to the code | `test_enter_emits_pair_activated`; jump only for stored match ids, address copy otherwise |
| 6 provenance | provenance block golden, cache key tests, stale tests |
| 7 offline, degrade | states C1, C5, C10; no network code path (import test) |
| 8 teachable | `explain()` table test, ids registered |
| 9 synergy | `tests/test_capa_synergy.py` |

## 11. Open questions (recommended default; never blocks)
- Q1 Who builds T0? Default: one Sonnet builder first, with CAP-1 serialised against any `common.py` edit by WB3 or DIE.
- Q2 Separate dock tabified with the Evidence dock, or a fourth tab in it? Default: separate dock (different meaning: behaviour, not pairing; no edit to `ui_evidence.py`); move to the registry when E-2 lands.
- Q3 In-app download of capa (CAP-11)? Default: not in v1; manual steps with the pinned sha256 shown in Setup.
- Q4 Pin cadence and rule updates? Default: the owner bumps the pin after a golden refresh (about twice a year); no automatic rules or tool updates.
- Q5 ATT&CK/MBC display? Default: detail pane and optional group-by only.
- Q6 FLOSS-style consent gate for capa because vivisect emulates instructions (row 15)? Default: no gate; disclosure line in the run preview; the owner may raise it.
- Q7 May capability observations influence `attention/1` ranking? Default: no; PIL may use them as an independent channel.
- Q8 Memory cap default 8 GiB RLIMIT_AS? Default yes, re-measured at L3.
- Q9 Persist pair deltas or analyst notes on capability rows? Default no (derived, read-only panel); notes belong to FAB.
- Q10 Shortcut Ctrl+Shift+A (KB keeps Ctrl+Shift+K; GUI plan section 10) and the label "Capabilities" versus "Behaviours"? Default as written.
- Q11 Series hop counts (W5)? Default: after CAP-8, read-only counts through `nway.pair_access`.
