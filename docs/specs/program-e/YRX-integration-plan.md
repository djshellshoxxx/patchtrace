# YRX integration plan: analyst-reviewed discoveries to tested YARA-X rules

Status: E-1 research plan, 2026-10-14 (worker YRX, Sonnet 5.5). Slice R1 (synthesis) built in `yarax/synth.py`. No ChatGPT spec exists for YRX; this is the draft the integration owner reconciles.
Status: E-1 research plan, 2026-10-14 (worker YRX, Sonnet 5.5); R0-R3 built (R3: candidates without bytes, `yarax/{features,gates,candidates}.py`). No ChatGPT spec exists for YRX; this is the draft the integration owner reconciles.
Status: E-1 research plan, 2026-10-14 (worker YRX, Sonnet 5.5). No ChatGPT spec exists for YRX; this is the draft the integration owner reconciles. Built so far: R0, R2, R4 (byte windows and masks, 2026-10-14).
Conventions: every source was retrieved 2026-10-14. `[measured]` = produced in the research sandbox (Linux x86-64, Python 3.12.3, yara-x 1.21.0, iced-x86 1.21.0, PyInstaller 6.22.3) by throwaway scripts that are NOT committed, on the repo's SYNTHETIC images (`tests/test_intel_tools_pe.py`). `[unverified]` = not confirmable here.
Hosts blocked from this sandbox: virustotal.github.io, pyo3.rs, doc.qt.io, learn.microsoft.com, api.github.com (403). Upstream sources were read from raw.githubusercontent.com and github.com instead.

## 1. Verdict and scope
GO, as a small, local, analyst-driven "Rules" feature.
- From ONE accepted changed-function pair, PatchTrace proposes at most 3 older-build and 3 newer-build rule candidates from verified evidence: address-masked bytes of the changed region, static strings the changed code references, imports and call targets, capa capabilities. It shows the evidence side by side and stores a rule only after an explicit Accept.
- An accepted version is tested (YARA-X 1.21.0, in a capped worker process) against the N-way series builds, extra builds and a local clean set. Results are a tri-state grid (Match / No match / Not scanned) with raw counts, never a score. Export is a local `.yar` with a provenance header; storage is append-only and project-local.
- Deliberately NOT built: a free-text YARA editor or generic rule scanner; any "all functions" or bulk mode (CLI and GUI take exactly one pair); publish, upload, share or clipboard-to-network; flaw or fix verdicts; rule hits as triage votes (rules derive from the same bytes as the match; SPEC-29 already classes YARA-X as derived evidence); process or memory scanning; regex, `include` or non-`pe` modules in generated rules; AI-written rules.
- Three decisions that differ from the card: (1) every YARA-X call runs in a worker process, never in the GUI process (GIL held for a whole scan, `unsendable` classes, panics are `BaseException`); (2) byte features need instruction decoding, because x64 code reaches data and functions through RIP-relative displacements that have no relocation entries, so `.reloc` alone leaves them unmasked (how much `.reloc` covers in a real Windows image is [unverified]; Tier W check): a `MaskSource` port, default `iced-x86`, unified-engine IR preferred once S1 lands; (3) a miss is "No match", never a negative vote, and matches never feed `attention/1` or the evidence panel.

## 2. Sources and facts
| Claim | Source | Confidence |
|---|---|---|
| `yara-x` 1.21.0 (2026-09-29) is latest; Python >=3.9; 10 wheels, NO sdist: `cp38-abi3` for win_amd64 (8,338,610 B), manylinux_2_28 x86_64 (9,624,829 B) and aarch64, macOS, PyPy; no musllinux (Alpine unsupported) | https://pypi.org/pypi/yara-x/1.21.0/json | high |
| Provisioning: `pip download --only-binary=:all: --platform win_amd64 --python-version 3.12` resolved `yara_x-1.21.0-cp38-abi3-win_amd64.whl`; `pip install --only-binary=:all: yara-x==1.21.0` worked on Linux/3.12 [measured]. No runtime download, no admin rights, offline after install | PyPI + sandbox | high |
| Licence BSD-3-Clause (repo LICENSE, Cargo.toml `license`, wheel SBOM root); PyPI shows only the classifier "BSD License" | https://raw.githubusercontent.com/VirusTotal/yara-x/main/LICENSE, `.../Cargo.toml` | high |
| Wheel SBOM: 303 Rust crates, all permissive (172 `MIT OR Apache-2.0`, 35 MIT, 26 `Apache-2.0 WITH LLVM-exception`, ...); `r-efi` is `MIT OR Apache-2.0 OR LGPL-2.1-or-later` (take MIT). Per-crate licence texts are NOT in the wheel | wheel member `yara_x-1.21.0.dist-info/sboms/yara-x-py.cyclonedx.json` | high |
| Windows wheel = `yara_x/yara_x.pyd` (24,549,376 B unpacked) + `__init__.py(i)`, `py.typed`, SBOM; Linux `yara_x.abi3.so`; a Linux one-folder freeze adds ~36 MB. No other DLL shipped; MSVC runtime need [unverified] | `unzip -l` of the wheel, freeze probe [measured] | high |
| Embedded JIT: the `.pyd` contains wasmtime 45.0.3 and cranelift-codegen 0.132.3 (source paths in strings; SBOM). It emits executable memory for RULE conditions, never for target code. Behaviour under Windows Arbitrary Code Guard or EDR [unverified, owner machine] | wheel strings [measured] | high / unverified on Windows |
| API (wheel introspection): `Compiler(relaxed_re_syntax, error_on_slow_pattern, includes_enabled, ignore_invalid_rules)` (docs show only the first: docs stale); `allowed_metadata/allowed_rule_name/allowed_tags(..., error=True)`; `warnings()/errors()` dicts `type code title line column labels footers text`; `Scanner.scan/set_timeout/max_matches_per_pattern/fast_scan`; `Rules.serialize_into`; `Formatter`; `Module(name).invoke` | https://raw.githubusercontent.com/VirusTotal/yara-x/main/site/content/docs/api/python.md + [measured] | high |
| Not in the Python API: `__version__`, profiling, a list of non-matching rules. Modules in the wheel: console crx cuckoo dex dotnet elf hash lnk macho math pe string time vt zip (no `magic`) | introspection [measured] | high |
| Frozen app [measured]: `importlib.metadata.version("yara-x")` raises PackageNotFoundError unless `--copy-metadata yara-x` is given; the extension imports `json`, `io`, `datetime` at run time (one via `unwrap()`), so a minimal probe failed at the first `scan()` with "No module named 'json'" until they were declared. PatchTrace probably bundles `json` already; the hook must still declare all three | https://raw.githubusercontent.com/VirusTotal/yara-x/main/py/src/lib.rs lines 49, 200, 755, 771, 1571, 1630 | high |
| GIL: `Scanner.scan` holds the GIL for the whole scan (a ticker thread stalled exactly the scan time: 0.35, 1.0, 2.9, 5.2, 8.0 s [measured]; the binding calls `self.inner.scan(data)` with no detach). `Compiler`, `Scanner`, `Formatter`, `RulesIter` are `#[pyclass(unsendable)]` (use from another thread panics); module `gil_used(true)` | `.../py/src/lib.rs` lines 107, 483, 1006, 1363, 1707 | high |
| A Rust panic surfaces as `PanicException`, derived from `BaseException` so it "propagate[s] all the way through the stack"; `except Exception` misses it | https://raw.githubusercontent.com/PyO3/pyo3/main/src/panic.rs | high |
| Upstream history: panic, memory-safety or crash fixes in 1.12 to 1.20 (1.13 use-after-free; 1.16 panic on bad reader input; 1.17 out-of-memory; 1.19 undefined behaviour deserializing untrusted rules; 1.20 regex-size panics); 1.21 fixes shared-pattern false positives and negatives and Python module features. Releases are roughly monthly | https://github.com/VirusTotal/yara-x/releases, `.../releases/tag/v1.21.0` (years inferred from 1.21.0 = 2026-09-29) | high / medium |
| Limits [measured]: `set_timeout(1)` aborts at 1.00 s in condition loops and in pattern matching; default 1,000,000 matches per pattern; RLIMIT_AS 256 MiB suffices for a 32 MiB scan; compile of a 6.9 KB rule 7 ms; frozen import+compile+scan probe ~170 ms cold (Linux). Docs: E035 max 64,000 patterns per rule, E044 includes off, E045 leading `.*`, E018 slow pattern | `.../site/content/docs/errors_and_warnings/errors.md` | high |
| Static only: YARA-X has no process scanning. `scan_file` memory-maps large files and a concurrent truncation raises SIGBUS (CLI `--no-mmap` text), so scan in-memory bytes | `.../docs/intro/yara_vs_yara-x.md`, `.../docs/cli/commands.md` | high |
| Quality signals exposed: typed compile warnings. `slow_pattern`/E018 fires for `{ 48 }` and `{ 00 [1-10] 01 }` but NOT for `{ ?? ?? ?? ?? }`, 2-byte or wildcard-heavy patterns [measured]: not a sufficient gate. `for any i in (1..#b)` raises `potentially_slow_loop`, a bounded `(1..8)` does not [measured]. `build()` resets the compiler, so `warnings()` must be read before it [measured]. Atom listing is a CLI debug command (1.21.0); profiling needs the `rules-profiling` Cargo feature; neither is in the Python API | `.../docs/errors_and_warnings/warnings.md`, `.../releases/tag/v1.21.0` | high |
| Compiler linters enforce provenance at compile time [measured]: missing meta E038, wrong type or hash E037, rule name E039, unlisted tag E040; `includes_enabled=False` gives E044 | errors.md | high |
| Language differences that matter: regex `{` must be escaped and bad escapes are errors; base64 >= 3 chars; `of` takes boolean tuples, no rule-name wildcards; hex jump bounds may be hex/octal; each modifier once. Hex: nibble wildcards, `~`, `[a-b]` jumps, alternatives, `consecutive_jumps` warning. Generated rules use no regex | `.../writing_rules/differences.md`, `hex_patterns.md` | high |
| `pe` module [measured]: `pe.imports()` is case-insensitive; `pe.import_details[].functions[].rva` equals the IAT slot RVA; `rva_to_offset`, `section_index(offset)` exist; `pe.offset_to_rva` is in the main-branch docs but E008 in 1.21.0 (docs ahead of the wheel). `hash` and `math` exist and are left out (Section 7) | `.../docs/modules/pe.md` + wheel | high |
| Speed [measured]: 64 MiB PE of random code, 200 rules 0.06 s; one adversarial low-atom rule over 96 MiB of zeros 4.8-5.2 s; rules gated first by `uint16(0) == 0x5A4D and pe.is_pe` skip pattern search on non-PE data | sandbox | medium |
| Decoders [measured]: iced-x86 1.21.0 (MIT; `cp38-abi3` incl. win_amd64, 886 KB) gives `get_constant_offsets()` (displacement/immediate offset and size), `is_ip_rel_memory_operand`, `flow_control`, `near_branch_target`; capstone 5.0.9 (BSD classifier; `py3-none-win_amd64`, 1.3 MB) gives `disp_offset/imm_offset`. They agree on 12 test instructions, including `cmp dword [rip+d], imm8` where the displacement is not last | https://pypi.org/project/iced-x86/, https://pypi.org/project/capstone/, https://github.com/icedland/iced | high / medium (licence from installed metadata) |
| Uniqueness sizing [measured, libc 2.39, 250 random functions, instruction-aligned interior windows, RIP and branch displacements masked]: unique in the file for 8/12/16/24/32/48-byte windows in 38/52/60/72/77/80 % of cases; function prefixes are worse. libc has many near-duplicate ifunc variants, so this understates typical code. Sizing evidence only | sandbox | medium |
| Repo facts (code read): `FunctionRecord` holds decompiler/assembly TEXT only, no bytes, sizes or extents (`normalization.py`); `FunctionMatch.review`; `pe_overview` has sections, imports, exports and data-directory entries but not `.pdata`/`.reloc` contents (dev-only `tools/calibration/tier_w/pe_tables.py` parses both, bounded); series = 3..8 builds (`nway/contracts.py`); `StringChange.display_value` is an escaped <= 256-char display form (`intelligence/tools/delta.py`) | `src/patchtrace/*` | high |
| Unified IR (spec, S1 not built): `h1` zeroes the `address` operand fields, `h2` also immediates and displacements; `extent_src` 1 = `.pdata`-confirmed; `ChangeFacts.verdict` unchanged/cosmetic/material/review/unknown | `docs/specs/unified-engine/02-data-model.md` | high (spec only) |
| Accessibility: Qt's Windows UI Automation bridge ships Grid, GridItem, Table, TableItem, Selection, Text, Value and Invoke providers; item views implement table/cell interfaces; `NameChanged`/`DescriptionChanged` events (qtbase `dev`, not the 6.12.0 tag). Microsoft: composite controls keep one tab stop with arrow keys inside; anything pointer-invokable must be keyboard-invokable; visible focus | https://github.com/qt/qtbase/tree/dev/src/plugins/platforms/windows/uiautomation, `.../src/gui/accessible/qaccessible.cpp`, `.../src/widgets/accessible/itemviews.cpp`, https://raw.githubusercontent.com/MicrosoftDocs/windows-dev-docs/docs/hub/apps/design/accessibility/keyboard-accessibility.md | medium |

## 3. Standalone baseline versus PatchTrace value
| YARA-X alone gives | PatchTrace context adds |
|---|---|
| Compile, lint, format and scan rules you wrote over files you choose; `pe` module; fast scanning; typed warnings | Rules come from an ACCEPTED pair and are checked on that pair before you see them (gate `sep`): the older-build rule must hit the older build and miss the newer one |
| No idea which bytes depend on addresses | Masks from decoded instructions and PE facts (RIP and branch displacements, relocations), so a rule survives a rebuild at another layout (Section 5: exact bytes miss it) |
| No notion of what changed | Delta features only: older-only versus newer-only from the pair, CAP classes `newly-introduced`/`removed-with-code`, WB3 string add/remove; unchanged and `cosmetic` code is excluded |
| One file, bare booleans | Rule x build grid over the series with ordinals, KB labels and file versions; flip points ("older-build rule stops matching between builds 2 and 3") comparable with the advisory without averaging |
| Rule text is the only record | Provenance (project, run, artifact SHA-256, function RVAs, tool pins, label, CVE/KB/CWE), staleness, append-only versions |
| No guard rails for hostile input | Capped worker process, in-memory scans of hash-verified bytes, closed-grammar rule text, compiler linters as a second gate |

Workflows enabled:
- W1 fingerprint a reviewed fix: propose, read the evidence, Accept, test, Export.
- W2 survives rebuilds: series neighbours (dev: Tier R A/A and toolchain-noise pairs).
- W3 fires on clean files: any hit in the clean folder is a false positive to review.
- W4 re-test when a build arrives or YARA-X is bumped: the grid goes stale, the rule text does not.
- W5 explain a flip: open the pair project and RVA where the pattern last appears.

Charter check (roadmap section 3):
1. Pair-aware: input is one accepted match with older/newer artifacts; every record carries orientation.
2. Delta, not inventory: only older-only/newer-only features are included; `both-sides` features are shown greyed and excluded; an absent tool channel reads `unavailable`, not "none".
3. Anchors in and out: Section 4.
4. Triage: rules never enter `attention/1` or the evidence panel; the value is the series flip point and clean-set false positives with raw counts; a rule counts once because it derives from the matched bytes.
5. One click to code: features, cells and hits open the pair (navigator `select_match`), the raw view at the RVA, or the other build's pair project at the hit RVA.
6. Provenance: `EngineStamp`, hashes, cache keys, staleness (Section 7).
7. Offline-first: no network imports in `rules/` (AST test); engine or decoder absent gives state R1; no target executes.
8. Teachable: `teach` hooks (Section 8). 9. Synergy: Section 5.

## 4. Cross-feature links
| Anchor | Dir | Counterpart track | Use |
|---|---|---|---|
| function (`rva:0x..`, match id, both sides) | in/out | UE/Ghidriff, unified `ChangeFacts` | Source pair; eligible only if `review=accepted` and verdict `material` (or analyst-confirmed when no unified facts: candidate flagged `unvetted`). Rules emit function anchors back |
| string (`value_sha256`, offset, `static`) | in | WB3 (`StringChange`, `workbench-strings/1`), FLOSS | File-level add/remove; `linked_by=xref` when a decoded RIP target equals the string RVA; exact bytes re-read from the verified artifact; `secret_kind` strings never used; decoded/stack strings are not in file bytes, so never patterned |
| import/API (dll, name) | in/out | `pe_overview`, CAP `api` features, `Anchor` kind `api` | Positive gates and call-target pins; emits import anchors for WB1 search |
| capability (rule, namespace, ATT&CK) | in | CAP (`CapabilityChange`) | Only `newly-introduced`/`removed-with-code`; becomes metadata plus API gates, never a condition alone; `newly-detectable`/`unlocalized` ignored |
| build fact (`toolchain-changed`, `packed`, `protected`) | in | DIE (`QualityFlag`) | packed/protected: bytes features blocked; toolchain-changed: banner, and the grid marks columns across the boundary `expected-unstable` |
| advisory phrase, module, api, component | in | CSAF `Anchor` kinds | Suggestions in the Accept dialog, never auto-filled |
| CVE, KB, CWE | in (analyst confirms) / out in metadata | KB-CVE correlator, CSAF applicability, `Finding.cwe` | Column "advisory says" beside the rule's own result; a disagreement reads "Rule and advisory disagree", never merged |
| series (ordinal, label, SHA-256) | in | nway `Series.builds` | Grid rows, max 8 |
| rule (`rule:<lineage>.v<n>`) | out | FAB, WB1 search, WB2 badge "has accepted rule", GUI shell, E-5 guide | Provenance record and navigation target |
| release transition (rule, from, to, kind) | out | KB track (channel "series bytes"), optional Series-window column | Derived only from scanned cells; unscanned builds between read "between i and j, k not scanned" |
| clean-set false positive (rule, sha256) | out | Calibration/QA | Counts and hashes only, never paths |
| KEV flag | in (future) | KEV | Copied into export metadata only; never changes generation |

## 5. Synergy test (known answer)
Fixtures, all SYNTHETIC and built at test time:
- `tests/test_intel_tools_pe.py` pairs: `capa-api` (older V1, newer V2); `capa-control` newer (V1r: V1's code rebuilt, +0x40 shift, other timestamp); `diec-toolchain` newer (V1t: V1's code, GNU-style layout); `floss-static` and `floss-decode` (4 clean files).
- Three NEW images from `tests/rules_fixtures.py`: LA (a function with `term`'s register setup that calls `CloseHandle`), IMP (imports and uses `TerminateProcess` in unrelated code), BOTH (LA's function plus IMP's code).
- Recorded real capa 9.4.0 output already exists (`tests/fixtures/intel_tools/capa/`): `terminate process` only in V1 (function `term`, RVA 0x104d); `write file on Windows` and `query environment variable` only in V2.

Expected candidates for the accepted `capa-api` pair [measured]:
- Older-build: `term` (removed; 24 B, 20 literal, longest run 15, one masked RIP displacement, pin `KERNEL32.dll!TerminateProcess`) passes; the old `log` (3 B) fails gate `len`.
- Newer-build: `log` (modified; 38 B, 30 literal, run 14, two masked, pin `WriteFile`) and `env` (added; 35 B, 23 literal, run 8, one hit in V2, none in V1 or V1r) pass.
- `host`, `dyn`, `xor` and `main` have equal masked bytes on both sides (`main` differs only by masked call targets): no candidates. The pair `capa-control` yields none (every function equal after masking).

Measured grid for the older-build rule built from `term` (1 = rule matches; yara-x 1.21.0 + iced-x86 1.21.0, Linux; CI must confirm on Windows):
| rule | V1 | V1r | V1t | V2 | LA | IMP | BOTH | 4 other clean |
|---|---|---|---|---|---|---|---|---|
| exact bytes | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| masked bytes | 1 | 1 | 1 | 0 | 1 | 0 | 1 | 0 |
| import only | 1 | 1 | 1 | 0 | 0 | 1 | 1 | 0 |
| masked + import | 1 | 1 | 1 | 0 | 0 | 0 | 1 | 0 |
| masked + call-target pin | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |

Reading:
- Exact bytes miss the rebuild (recall 2 of 3). Masking fixes that but hits LA and BOTH, because the masked call target no longer says which API is called. Imports alone hit IMP and BOTH. The conjunction still hits BOTH (shape in one function, import used in another).
- Only the pin, which re-ties the masked `call [rip+disp]` to the TerminateProcess IAT slot, gives 3 of 3 with no false positive.
- The string channel is silent for this pair (`PATCHTRACE_SYNTHETIC` is in both `.rdata`): reported "unavailable", not a negative. The newer-build rule from `log` hits V2 only.
- Hits resolve to RVA 0x104d (V1, V1t) and 0x108d (V1r = +0x40). Series order V1, V1r, V1t, V2 gives the flip "older-build rule ends between builds 2 and 3" and "newer-build rule begins at build 3".

Tests: `tests/test_rules_synergy.py::{test_combined_rule_beats_each_channel_alone (grid vs tests/fixtures/rules/synergy-matrix.json), test_masks_make_rebuild_stable, test_call_pin_removes_conjunction_false_positive, test_flip_between_build_2_and_3, test_short_window_rejected_with_reason, test_cosmetic_pair_yields_no_candidates}`.

## 6. Traps and guards
| Trap | Guard |
|---|---|
| A match read as "affected" or "fixed" | Copy says "pattern", directions are "older-build"/"newer-build"; banned stems (`vulnerab`, `exploit`, `safe`, `secure`, `fixed`, `verified`, `proven`, `probab`) swept over every view-model string (the copy is written to need no whitelist); analyst labels shown verbatim as the analyst's words |
| A miss read as negative | Cells are Match / No match / Not scanned / Timed out / Error; `verdict` exists only against an explicit expectation; unscanned files are never counted as clean |
| Compiler or layout noise becomes a "separator" | Only `material` unified facts (or analyst confirmation); DIE `toolchain-changed` banner; same-source rebuild (V1r) is a standing test; Tier R A/A as dev benchmark |
| Over- or under-masking | Policy = unified L1 (positive evidence only): RIP displacement and out-of-function branch displacement (prototyped), operand fields covered by a base relocation (`reloc`, needs the R4 table reader), unified-IR address references (`addr-ref`); immediates are kept (they carry bound constants); golden masks per fixture; parity test against the unified IR when it exists |
| Generic windows (prologues) | Window anchored on the changed instruction range, grown to gates `len` (>= 16 literal, i.e. unmasked, bytes and a longest literal run >= 6), `wild` (<= 40 % wildcards), `uniq` (exactly 1 hit in the source build, grown to <= 128 B, else rejected); thresholds provisional until calibrated on Tier R |
| `slow_pattern` is not a gate | Own metrics (literal bytes, longest run, wildcard ratio) plus `error_on_slow_pattern=True` plus per-target timeouts |
| Strings leak secrets or lie | `secret_kind` strings excluded; exact bytes re-read from the verified artifact (the display form is escaped); only `static` strings; escapes for every non-printable; non-ASCII label exported as `?` |
| Microsoft-derived bytes reach git | Rules live in the project; export only on explicit action to an analyst-chosen path; header notice; warning when the path is inside a Git working tree; function names off by default (they may come from symbol files); repo guard fails on the export marker outside `tests/fixtures/rules/`; fixtures synthetic only |
| Auto-publish or bulk | No network imports in `rules/`; `--match` required; no `--all`/`--yes` flags; no delete, only archive; accept and export are separate explicit actions |
| Injection through rule text | Closed grammar, values whitelisted or escaped, one serializer; compiled with the linters, `Rules.imports() == ['pe']` asserted, `Formatter` output equals the text (fixed point); hypothesis tests with hostile strings (`"`, `\`, newlines, `*/`, `}`, NUL, bidi) |
| Engine hang, crash, panic | Worker process (`jobs.run_process`, memory cap, timeout, tree kill), `except BaseException` in the worker, exit code 23; rules compiled from our own text only, never `deserialize_from` |
| GUI freeze or thread panic | `yara_x` imported only by the worker; the parent never loads the `.pyd`; no scan on a Qt thread |
| Stale results | Derived on read: artifact hash mismatch = hard stale; run id change = notice; engine or grammar bump = grid stale, rule text kept |
| Series mislabel | Expectations unknown by default (the pair's own two builds derive theirs from the rule direction); advisory in a separate column; disagreement displayed, not resolved |
| False precision | No score, percent or "accuracy"; counts per state only; thresholds shown as pass/fail checks with the measured number |
| Double counting | Rule hits are derived evidence and never raise corroboration of the match; the series flip is the only new observation and counts once as channel "series bytes" |
| Non-determinism | Canonical feature order, content-addressed ids, LF-only ASCII rule text, no timestamps in the hashed body (dates only in header comments) |

## 7. Contracts (package `src/patchtrace/rules/`, contract `yara-rules/1`, errors `PT-RULE-*`)
Layout:
- Pure modules: `contracts.py`, `limits.py`, `errors.py`, `ports.py`, `features.py`, `window.py`, `masks.py`, `synth.py`, `candidates.py`, `matrix.py`, `store.py`, `export.py`, `view.py`, `panel_service.py`, `cli.py`.
- Only `engine.py`, `worker.py` and `adapters/mask_iced.py` import `yara_x`/`iced_x86`; `ui_rules.py` is the only Qt module. Models are Pydantic v2 `extra='forbid'`, strict, frozen (pattern of `tool-evidence/1`).
- Ports (Protocols): `PairSource`, `MaskSource` (adapters `iced`, later `unified-ir`), `StringSource` (WB3), `CapabilitySource` (CAP), `ImportSource` (`pe_overview`), `BuildSource` (series + extra + clean), `AdvisorySource`.

| Model | Fields |
|---|---|
| `EngineStamp` | `engine='yara-x'`, `version`, `version_source` (`metadata`/`pin`), `decoder`, `decoder_version`, `grammar='yrx-gen/1'`, `worker='rules-worker/1'` |
| `PairSource` | `project_id`, `revision`, `run_id`, `older_sha256`, `newer_sha256`, `match_id`, `category` (modified/added/removed), `review='accepted'`, `materiality`, `analyst_confirmed_material`, `finding_id`, `cwe`, `older`/`newer` `FunctionRef{name, rva, size, extent (pdata/unified-ir/unknown)}` |
| `BytesFeature` | `side`, `window_rva`, `length` (16..512), `pattern` (hex tokens with `??`), `literal`, `longest_run`, `mask` (subset of `rip-disp`, `branch-ext`, `reloc`, `addr-ref`), `mask_source` (`iced-x86`/`unified-ir`), `pins` (<= 4 `CallPin{disp_offset, end_offset, dll, name}`), `source_hits`, `other_hits`, `separation` |
| `StringFeature` | `side`, `value_sha256`, `length`, `text` (escaped form as emitted), `encoding` (`ascii`/`wide`/`ascii-wide`), `offset`, `evidence_run_id`, `linked_by` (`xref`/`file-level`), `separation` |
| `ImportFeature`, `CapabilityFeature` | `dll`, `name`/`ordinal`, `delay`, `origin` (`pe-imports`/`capa-api`), `separation`; `rule_id`, `namespace`, `attack`, `classification`, `api_gates` |
| `Gate` | `gate_id` (`elig len wild uniq sep compile secret dist`), `state` (`pass fail unknown waived`), `measured` (number or text), `detail` |
| `RuleCandidate` | `candidate_id`, `lineage_id`, `direction` (`older`/`newer`), `source`, `features` (each with `included`), `rule_name` (`PT_<12 hex>_<older/newer>`), `rule_text` (<= 64 KiB), `rule_sha256`, `gates`, `compile_warnings`, `engine`, `unvetted` |
| `RuleDecision` | `decision_id`, `candidate_id`, `action` (`accept reject defer archive`), `analyst_label` (1..120, required to accept), `note`, `cve[]`/`kb[]`/`cwe[]` (regex-validated), `decided_at` |
| `RuleVersion` | `version_id`, `lineage_id`, `version`, `supersedes`, `candidate_id`, `decision_id`, `rule_text`, `rule_sha256`, `source`, `engine`, `created_at`; immutable, a revision is a new version |
| `TargetRef` | `target_id`, `label`, `role` (`older-anchor newer-anchor series extra clean control`), `sha256`, `size`, `ordinal`, `expect` (anchors derived from the rule direction, others unknown until the analyst sets them), `advisory_says`, `file_version`, `kb`, `toolchain_flag` |
| `CellResult` | `state` (`hit no-hit not-scanned timeout error`), `hits`, `offsets[<=8]`, `rvas`, `reason`, `elapsed_ms`, `verdict` (`as-expected unexpected-hit unexpected-miss unscored`) |
| `MatrixRun`, `ExportRecord` | `run_id`, `cache_key`, `engine`, `status` (`complete partial cancelled failed`), `targets`, `cells`, `limits`, `anomalies`; `export_id`, `version_id`, `basename`, `sha256`, `exported_at`, `warnings` |
| `WorkerRequest`, `WorkerResult` | `op` (`probe lint scan`), rules `[{name, text}]`, targets `[{target_id, path, sha256 or null, size}]`, limits, `result` path; result `kind` (`ok`/`error`), `engine`, `lint`, `cells` |

Candidate generation (R3 strings, imports, capabilities; R4 bytes):
1. Eligibility: `review=accepted` and verdict `material` (else analyst confirmation, flagged `unvetted`); DIE `packed`/`protected` blocks bytes features.
2. Bytes: take the extent from `.pdata` or the unified IR (else `PT-RULE-MASK`: leaf functions have no `.pdata`), decode both bodies, tokenise each instruction as masked hex, run `difflib.SequenceMatcher(autojunk=False)`. Delete/replace spans on the rule's side (the whole body for removed/added) are grown by context instructions until the gates pass (cap 128 B); keep up to 3 windows, ranked by literal bytes, that are unique in the source build and absent from the other build.
3. Strings: `StringChange` added/removed with exact bytes re-read at the recorded offset; `linked_by=xref` when a decoded RIP target equals the string RVA. Imports: differing `pe_overview` imports, API gates from capa `api` features, and one pin per masked `call [rip+disp]` whose target is an IAT slot. Capabilities: metadata and gates only.
4. Compose per direction: features whose `separation` is that side only; default included = the bytes window, its pins, linked strings, import gates; other features are offered unticked; toggling re-runs the checks (a revision, never free text).
5. In the worker: compile with the linters, then scan the pair (`sep`: hit at the expected RVA in its own build, no hit in the other).

Rule grammar (`yrx-gen/1`; one rule per candidate):
- Header comments (export only), `import "pe"`, `rule PT_<lineage12>_<older|newer>: patchtrace <older_side|newer_side> {`.
- `meta:` `patchtrace_rule_id` (`<lineage12>.v<n>`), `patchtrace_version`, `patchtrace_project_id`, `older_sha256`, `newer_sha256`, `side`, `change`, `function_older`/`function_newer` (RVAs; names only if opted in), optional `cve kb cwe capability analyst_label`, `statement`.
- `strings:` one hex pattern (`??` wildcards only, no jumps) and up to 4 text patterns (`ascii`/`wide`).
- `condition:` `uint16(0) == 0x5A4D and pe.is_pe and pe.machine == pe.MACHINE_AMD64`; executable-section scoping `for any s in pe.sections : (s.characteristics & pe.SECTION_MEM_EXECUTE != 0 and $b in (s.raw_data_offset .. s.raw_data_offset + s.raw_data_size))`; positive `pe.imports(...)` gates; call pins `for any i in (1..8) : (i <= #b and ... == f.rva)` built from `pe.sections[pe.section_index(@b[i])]` (no `offset_to_rva`; the bounded range is required because `(1..#b)` raises `potentially_slow_loop` [measured]; only the first 8 matches are checked, and `uniq` makes one match the normal case).
- Text layout: the serializer emits exactly the layout of `yara_x.Formatter` (aligned `=`, `rule X: tags`, blank line between sections), which is idempotent and keeps comments and `import` lines [measured]; `test_synth_is_formatter_fixed_point` pins it, so a YARA-X bump that changes the layout is caught in the bump PR.
- Compile gate: zero warnings, except the style warning `text_as_hex`. Read `Compiler.warnings()` BEFORE `build()`: `build()` resets the compiler and the lists come back empty [measured].
- Compiler: `Compiler(error_on_slow_pattern=True, includes_enabled=False)` with `allowed_metadata(..., required=True, error=True)`, `allowed_rule_name`, `allowed_tags`. `hash` and `math` are evaluated and left out: `hash` duplicates artifact identity, `math.entropy` duplicates `pe_overview` and DIE packing flags.

Export header (exact lines; no paths, no user names; names only with `--include-names`):
```
// patchtrace-rule-export/1
// Rule PT_0123456789ab_older version 2, label "<analyst label, ASCII>"
// Built by PatchTrace <ver> with YARA-X 1.21.0 (BSD-3-Clause) and iced-x86 1.21.0
// Project <project id>, analysis run <run id>
// Older build <basename> sha256 <64 hex>; newer build <basename> sha256 <64 hex>
// Source change: removed function at older RVA 0x104d, reviewed as material; function names omitted
// Accepted <UTC>. Tested <UTC>: 4 builds, 12 clean files, 0 unexpected matches, 0 not scanned (or "Not tested")
// Advisory anchors given by the analyst and not checked by this rule: CVE-YYYY-NNNN KBNNNNNNN CWE-NNN
// Origin: byte patterns copied from the analysed files on the analyst's computer. If those files are third-party software, check its licence before sharing this rule or committing it to a repository.
// A match means a file contains this pattern. It does not show whether the file is affected by a flaw.
```

| Code | Meaning (state) |
|---|---|
| `PT-RULE-INPUT` / `-LIMIT` / `-STALE` / `-INTEGRITY` | bad selection or contract; a cap hit; artifact or project moved; hash or row/sidecar mismatch |
| `PT-RULE-UNAVAILABLE` / `-ENGINE` / `-TIMEOUT` / `-CANCEL` | `yara_x` or decoder missing or probe failed (blocked state R1); worker crash, panic or non-zero exit; deadline; cooperative cancel |
| `PT-RULE-MASK` / `-DECODE` / `-COMPILE` / `-GATE` | no verified extent or mask source (bytes unavailable); invalid instruction; generated rule failed compile (bug or engine drift); accept or export refused by a hard gate |
| `PT-RULE-STORAGE` / `-EXPORT` | row write failed; export path or policy refused |

Storage, keys, limits:
- Reserved enrichment kinds `rule-candidate`, `rule-decision`, `rule-version`, `rule-test`, `rule-export`, none in `DERIVED_KINDS`, so retention never deletes them. Rows are append-only, ids `<kind>:<id>`, `Guard(project_id, 'rules', sha256(older:newer), row digest)`. A matrix over 1 MiB goes to the hash-verified sidecar `<project>/rules/tests/<sha256>.json` (pattern of `tool-evidence`).
- Ids: `domain_id('rule-candidate'|'rule-lineage'|'rule-version', 1, ...)`. Matrix cache key = `domain_id('rule-test', 1, {rule_sha256s, target sha256s, engine version, worker contract, limits})` (hashes only, never paths). The proposal key adds run id, tool-evidence cache keys, decoder version, grammar and limits digest.
- Limits (`limits.py`, one frozen dataclass whose digest enters the keys): rule text 64 KiB; patterns per rule 12 (ceilings hex 4, text 8; v1 uses 1 hex and at most 4 text); hex pattern 512 B; text pattern 256 B; meta string 512 chars; function for bytes <= 64 KiB; candidates 3 per direction, 200 per run; versions per lineage 50; targets: series 8, extra 64, clean 2,000, file 128 MiB, 8 GiB per run; rules per run 50; cells 105,000; per-target timeout 30 s (5..300), run wall 1 h; `max_matches_per_pattern` 64; worker memory 1 GiB (hard max 2 GiB); stderr tail 8 KiB sanitized.
- Rule quality metrics, all raw and never combined into a score: from the engine only compile warning codes, match offsets and lengths, and timeouts; computed by PatchTrace: literal bytes, longest literal run, wildcard ratio, pin count, hits in the source build (`uniq`), in the other build (`sep`), in the series and in the clean set, unexpected-match counts, wall milliseconds per target, and (dev only, R8) A/A rebuild re-hit fraction.
- Versioning is additive only: readers ignore unknown fields on rows written by a newer client; a new grammar id regenerates goldens in its own slice.

## 8. CLI and GUI
CLI (`rules/cli.py`, envelope `enrichment-cli/1`, `--json` = one document; exits 0 ok / 2 invalid or unavailable / 3 runtime or partial / 4 complete but empty / 5 cancelled):
```
patchtrace rules probe
patchtrace rules propose PROJECT --match ID [--direction older|newer|both] [--confirm-material]
patchtrace rules show PROJECT [--candidate ID | --version ID]
patchtrace rules decide PROJECT --candidate ID (--accept --label TEXT [--cve --kb --cwe --note] | --reject | --defer | --archive)
patchtrace rules test PROJECT --version ID [--series DIR] [--extra FILE...] [--clean-dir DIR] [--expect FILE.json] [--timeout S]
patchtrace rules export PROJECT --version ID --out FILE.yar [--include-names] [--allow-git-tree]
patchtrace rules history PROJECT [--lineage ID]
patchtrace rules _rules-worker --request REQ.json        (hidden; request and result JSON files, exits 0/20/21/22/23/2, frozen-aware argv, pattern of _binexport-worker)
```
`propose` exits 4 when the pair is eligible but no candidate passes the gates; `test` exits 3 when any target is not scanned.

GUI placement: page "Rules" in the shared Workbench dock (`ui_workbench.py`, registered through the GUI-track panel registry). Until that registry exists, `ui_rules.py` ships `RulesController` with the C6 seam (<= 8 lines in `ui.py`) and a dock `rules_dock` (`Ctrl+Shift+R`, hidden until a project is open) tabified with the evidence dock; migrating to the registry changes only the controller. Never a separate window.
```
+- Detection rules ---------------------------------------------------------[float][x]-+
| Pair: ParseHeader 0x1400A1F00 > 0x1400A2010 (modified, accepted)  [Propose rules] [Cancel] |
| [Candidates] [Test grid] [Saved rules]                                                    |
| Rules (2)                   | Older build                        | Newer build           |
| > Older-build rule Proposed | bytes 48 83 EC 28 .. ?? ?? ?? ?? .. | -  not present        |
|   Newer-build rule Proposed | import KERNEL32.dll!TerminateProc.. | -  not present        |
|                             | string "..." (referenced by code)  | -                     |
|                             | capability terminate process (removed) | -                 |
| Checks: Long enough pass | One place in source build pass | Misses other build pass | Compiles pass |
| Rule text (read-only)            [Copy text]   [Accept...] [Reject] [Defer] [Open function pair] |
| A match means the file contains this pattern. It does not show whether it is affected by a flaw. |
+-------------------------------------------------------------------------------------------+
```
Tabs and models:
- Candidates: `CandidateListModel(QAbstractListModel)` (name, state chip: Proposed / Accepted v2 / Rejected / Deferred / Needs review); `FeatureTableModel` columns Include (checkbox, only for features on the rule's side), Kind, Feature (escaped), Older build, Newer build, Source, Where (RVA link); a side cell reads `present`, `absent` (the producing tool completed) or `unknown` (tool missing or failed), each with glyph and text; `ChecksModel` (one row per gate with the measured number); read-only `QPlainTextEdit` (monospace, `setPlainText` only, no highlighter, no HTML).
- Test grid: `GridModel(QAbstractTableModel)`, rows = builds (ordinal, label, KB, file version, role, expectation, "advisory says"), columns = rule versions; a summary row per rule (Match / No match / Not scanned / Unexpected counts); filters: role, state, unexpected only. The model owns its row order and filter (no `QSortFilterProxyModel`, no `ResizeToContents`, as measured in C6); fixed row height from `QFontMetrics`; cells are precomputed strings, detail built on demand. Gate: `data()` calls for first paint, sort and filter <= 7 x visible cells x 1.2 + 20, independent of row count, asserted at 10k and 100k cells (cap 105,000).
- Saved rules: lineages with version, label, tested state ("Tested on {date}: 4 builds, 12 clean files" / "Not tested" / "Grid stale: YARA-X version changed"), Export, Archive, History; no delete.
- `AcceptDialog` and `ExportDialog` are plain `QDialog`s; native file dialogs sit behind a `FilePort` so tests inject paths.
- Threads: `RulesWorkerThread(QThread)` runs the pure orchestration that spawns the capped child; threads are parentless and held in `_LIVE_THREADS` until `finished` (a destroyed running QThread aborts the process); a generation counter drops stale results; SQLite writes (`publish`) happen on the GUI thread only; `shutdown()` from `closeEvent` sets cancel and waits; no `terminate()`.

Keyboard and accessibility (Microsoft keyboard guidance: one tab stop per composite control, arrows inside, everything pointer-invokable also keyboard-invokable, visible focus; Qt ships UIA Grid/Table/TableItem providers, so the grid is a model-driven `QTableView` with no per-cell widgets [inferred from the provider list; confirm with NVDA/Narrator on Windows]):
- Tab order: Propose, candidate list, feature table, checks, rule text, Copy, Accept, Reject, Defer, Open pair, tabs. Enter on a candidate = Open function pair; Ctrl+Enter = Accept dialog; Ctrl+C copies the stored rule text exactly; there is no Delete key action.
- Every control sets `setAccessibleName` and `setAccessibleDescription` (via `apply_tooltip`): dock "Detection rules panel"; list "Proposed rules for the selected function pair"; features "Features of the selected rule, older and newer build"; checks "Rule checks"; text "Generated rule text, read-only"; accept "Accept the selected rule and give it a label"; grid "Rule test grid, builds by rules".
- Grid cell `AccessibleTextRole` = "Build 3 of 8, KB5034123, rule PT_0123456789ab_older: No match, expected a match". The status label keeps an EMPTY accessible name so its text change is announced (C6 rule). Nothing is colour-only; the focus ring uses the theme text colour. Screen-reader and DPI behaviour stay a manual Windows gate.
- Tooltip ids (registry `rules.*`, unique What/Why/Effect, no angle brackets, Availability where relevant): `dock action pair propose cancel candidates features checks rule_text copy_text accept reject defer archive open_pair grid targets series extra clean run_test export include_names saved history stale_banner retry copy_error`; templates `rules.feature`, `rules.cell`, `rules.row` (values escaped via `clean_value`).

States (exact text; each also drives a `Status` line):
| ID | Trigger | Text |
|---|---|---|
| R0 | no project | "Open a project to work with detection rules." |
| R1 | engine or decoder unavailable | "The rule engine (YARA-X) is not available in this installation. Rules cannot be proposed or tested. Saved rules stay readable." |
| R2 | no accepted pair selected | "Select a function pair you have accepted. Rules are only proposed for pairs you have reviewed." |
| R3 | ready, nothing proposed | "No rules proposed for this pair yet. Choose Propose rules. Nothing is generated or saved until you ask." |
| R4 | proposing / testing | "Proposing rules from the selected pair..." / "Testing N rules against M files. Files that cannot be read are reported as Not scanned, never as No match." |
| R5 | no candidate passes | "No rule passed the checks for this pair: {first failing check}. Bytes are unavailable when the function size is not known (leaf functions without exception data)." |
| R6 | stale | "These rules describe an earlier analysis or engine version ({reason}). Test again before relying on them." |
| R7 | failed | "Rule work could not finish: {code}: {message}. Saved rules are unchanged." with Retry and Copy details |
| R8 | too large | "Too many files or cells (N). Narrow the folder or the build list." |

Key copy:
- Grid cells: "Match", "No match", "Not scanned: {reason}", "Timed out", "Error"; verdicts "as expected", "unexpected match", "unexpected no match", "no expectation". Footer (always visible): "A match means the file contains this pattern. It does not show whether the file is affected by a flaw. No match does not show that it is unaffected. Counts are raw numbers, not scores."
- "Not scanned" reasons (closed list): "file is larger than the limit", "file could not be read", "not a PE image", "file changed while reading", "run was cancelled". Check labels (gate ids `elig len wild uniq sep compile secret dist`): "Change reviewed as material", "Long enough", "Not mostly wildcards", "Appears in one place in its own build", "Does not appear in the other build", "Compiles with YARA-X", "No secret-looking strings", "Builds share one toolchain"; each shows its measured number, e.g. "Long enough: 20 literal bytes, longest run 15".
- Accept dialog: "Accepting saves this rule version in the project. It does not publish or export anything." Required "Label"; optional CVE, KB, CWE, Note; button "Accept rule".
- Export dialog: "This saves a .yar text file on this computer. PatchTrace does not upload it." Checklist (hard: separates the pair, compiles, no secret strings; informational: tested on builds, checked on clean files, unexpected matches, stale grid; informational failures need the box "Export with these warnings"). Option "Include function names (they may come from symbol files)", off. Warning: "The rule contains byte patterns copied from the analysed files. If those files are third-party software, check its licence before sharing the rule or committing it to a repository." For a Git path: "I understand and want to save it inside a Git working tree".
- Teach hooks (`teach.rules.*`, each `meaning` + `next`, consumed by E-5): `candidate.separating`, `candidate.too_short`, `grid.unexpected_hit`, `grid.flip`, `grid.not_scanned`, `export.checklist`.

Qt (PySide6 6.12.0) pitfalls and test approach:
- No widget or `QSettings` access in workers; no `terminate()`; settings reads wrapped in try/except; the menu action is the dock's `toggleViewAction`.
- Offscreen tests (`QT_QPA_PLATFORM=offscreen`): panel built standalone and once via `MainWindow`, fake worker injected into `RulesWorkerThread`, 20 consecutive runs without abort (feature-done gate).
- Budget: propose <= 3 s for one pair excluding worker start (frozen start ~0.2 s on Linux, Windows [unverified]); an 8-build x 20-rule grid <= 10 s on 20 MB files (engine ~1 GiB/s); first paint <= 200 ms; filter and sort <= 150 ms.

## 9. Slice plan (no two builders edit one file; integrator-only files are in Section 10)
| Slice | Scope and exclusive files | Deps | Tier (why) | Size | Gate | Fallback |
|---|---|---|---|---|---|---|
| R0 | Contracts, limits, errors, ports: `rules/{__init__,contracts,limits,errors,ports}.py`, `tools/generate_rules_schemas.py`, `docs/schemas/rules/`, `tests/test_rules_contracts.py` | none | Sonnet (strict models, drift test) | S | regenerate-and-compare, valid/invalid examples | none |
| R1 | Closed-grammar synthesis and escaping: `rules/synth.py`, `tests/test_rules_synth.py`, `tests/fixtures/rules/golden/*.yar` | R0 | Opus (injection and escaping are security-nuanced) | M | goldens, `Formatter`-stable, hypothesis hostile strings | hex and imports only, no text patterns |
| R2 | Engine facade, hidden worker, runner: `rules/{engine,worker,runner}.py`, `tests/test_rules_engine.py` (real yara-x), `tests/test_rules_worker.py` (fake child: timeout, cancel, panic, out-of-memory) | R0 | Sonnet | M | grid on fixtures equals golden; parent never imports `yara_x`; `BaseException` path tested | none (core) |
| R3 | Candidates without bytes: `rules/{features,candidates,gates}.py`, `rules/adapters/{tools_delta,pe_imports}.py`, `tests/rules_fixtures.py`, `tests/test_rules_candidates.py` | R0-R2; SPEC-29 normalize/delta (built), runner/store (track T) for live data | Sonnet | M | string/import/capability candidates on `floss-static` and `capa-api` goldens; gates unit-tested | ship R3 alone as v1 |
| R4 | Bytes: new `pe_overview/tables.py` (copy, do not move, the `.pdata`/`.reloc` readers of the dev-only module), `rules/{window,masks}.py`, `rules/adapters/mask_iced.py`, `tests/test_rules_masks.py`, `tests/test_rules_synergy.py`, `tests/fixtures/rules/synergy-matrix.json` | R3 | Sonnet (Opus reviews masks) | M | Section 5 grid exact; leaf function without `.pdata` gives `PT-RULE-MASK` | R3-only rules |
| R5 | Matrix, store, export, CLI: `rules/{matrix,store,export,cli}.py`, `tests/test_rules_{matrix,store,export,cli}.py` | R2, R3 | Sonnet | M | append-only, resume after a crash, export golden, no-bulk-flag test | none |
| R6a | Pure view-model and service: `rules/{view,panel_service}.py`, `tests/test_rules_view.py` | R5 | Sonnet | M | all states, banned strings, hostile text, no Qt import | none |
| R6b | Qt panel: `ui_rules.py`, `tests/test_rules_ui.py`, additive `rules.*` block in `tooltips.py` (integrator sequences it against other tracks) | R6a, GUI registry or C6 seam | Sonnet | L | R0-R8 states, tooltip enumeration, hostile text, 20x offscreen runs | read-only list and grid |
| R7 | Integrator: hooks, packaging, frozen smoke and repo guard of Section 10 | R2, R5 | Haiku/Sonnet (mechanical) | S | Linux and Windows CI, frozen worker scan | none |
| R8 | Dev benchmark: `tools/rules/stability.py` on Tier R A/A, layout and toolchain-noise pairs (needs clang) and `cwe-patterns` truth labels, `tests/test_rules_tier_r.py` (BLOCKED, never skipped, when tools are missing) | R4, R5 | Sonnet | M | thresholds calibrated and recorded in `docs/qa.md` | thresholds stay provisional |

## 10. Amendments and test and QA plan
| File and section | Change (integrator applies) |
|---|---|
| `src/patchtrace/enrichment/storage.py` `KINDS` | add `rule-candidate`, `rule-decision`, `rule-version`, `rule-test`, `rule-export` (not in `DERIVED_KINDS`) |
| `src/patchtrace/cli.py` | `COMMANDS` += `rules`; `_command_name` set += `rules`; `HANDLERS` entry; `rules.cli.register` (<= 6 lines) |
| `pyproject.toml` | `dependencies` += `yara-x==1.21.0`, `iced-x86==1.21.0` (exact pins, wheels only); CI `pip check`; bumps only in a dedicated PR that re-runs the Section 5 grid |
| `tools/build_windows.py`, `tools/build_linux.py` | assert installed versions equal the pins; `REQUIRED_NOTICES` += `yara-x-1.21.0/LICENSE`, `iced-x86-1.21.0/LICENSE`; fail if `yara_x/yara_x.pyd` / `yara_x.abi3.so` is missing from the inventory; record both versions in `dependency-versions.json` |
| `tools/pyinstaller_hooks/hook-patchtrace.rules.engine.py` (new) | `hiddenimports = ['yara_x', 'iced_x86', 'json', 'datetime', 'io']`; `datas = copy_metadata('yara-x') + copy_metadata('iced-x86')` (equivalent CLI flags verified with PyInstaller 6.22.3) |
| `tools/frozen_smoke.py` | checks R1 (`rules probe`: versions equal pins, 15 modules) and R2 (worker scan of a built-in sample, exit 0, one JSON document) |
| `third_party/notices/yara-x-1.21.0/`, `iced-x86-1.21.0/`, `docs/notices.md` | LICENSE, `MANIFEST.txt` with wheel SHA-256s, the wheel SBOM copy; rows for both; open item: per-crate licence texts |
| `src/patchtrace/tooltips.py`, `tests/test_tooltips.py` | `rules.*` registry entries and templates; add `window.rules_dock` to the enumeration roots |
| `.gitattributes` | `tests/fixtures/rules/** text eol=lf`, `*.yar text eol=lf` |
| `tools/calibration/tier_w/guard.py`, `tests/test_tier_w_guard.py` | fail when a tracked file contains the marker `patchtrace-rule-export/1` outside `tests/fixtures/rules/`, or a rule header with Microsoft vendor strings |
| `docs/modules.md`, `tasks/todo.md`, `docs/qa.md` | append rows per slice and the live gates below |
| `docs/specs/three-tool-evidence-adapters.md` (rejected list, YARA-X) and `docs/plans/csaf-patch-intelligence-implementation.md` line 62 | point to this plan: YARA-X is built as a derived-evidence consumer, not a new detection channel (their classification stands) |
| `docs/specs/workbench/README.md`, `docs/plans/workbench-search-graph-floss-implementation.md` | add page "Rules" to the Workbench dock |
| `docs/specs/unified-engine/01-architecture.md` (S1 `ir/pe_tables.py`), `03-extraction.md` | reuse `pe_overview/tables.py` (R4); expose `FunctionMaskView(rva, size, extent_src, bytes, l1_mask)` from `ir/reader.py` so `adapters/mask_unified.py` can replace `mask_iced` |
| `src/patchtrace/intelligence/contracts.py` `Anchor.kind` (FAB track) | add `rule`; optional later column in `nway/view_model.py` for release transitions |

Claims checked against code and sources: confirmed that SPEC-29 classes YARA-X as derived evidence. Thin: `StringEvidence.display_value` is escaped and cannot seed a pattern (exact bytes are re-read instead). Wrong or stale: the YARA-X docs list one `Compiler` parameter (the wheel has four) and `pe.offset_to_rva` (absent in 1.21.0).

Test and QA plan:
- Fixtures never use Microsoft binaries: synthetic images from `tests/test_intel_tools_pe.py` plus `tests/rules_fixtures.py`; Tier R builds only where clang exists (BLOCKED otherwise, never skipped).
- Goldens: rule texts, masks per function, grid JSON; the grid must be byte-identical on Linux and Windows.
- Properties (hypothesis): any feature set serializes, compiles and is `Formatter`-stable; masking is idempotent; feature order does not change `rule_sha256`; hostile strings never alter the grammar.
- Named tests: `test_parent_never_imports_yara_x` (subprocess), `test_rules_have_no_network_imports` (AST), `test_cli_has_no_bulk_flags`, `test_accept_and_export_are_separate_actions`, `test_export_header_has_no_paths_or_names_by_default`, `test_secret_strings_never_exported`, `test_repo_guard_rejects_rule_exports`, `test_worker_timeout_kills_child_tree`, `test_worker_baseexception_exit_23`, `test_grid_cells_never_negative_for_unscanned`, `test_banned_strings_never_appear`.
- Windows pitfalls (roadmap checklist): CRLF (`.gitattributes`; exports written with `newline='\n'`); short explicit parametrize ids (`r01`...); `>=` on coarse `time.monotonic()`; no YAML plain scalars containing `: `; wheels-only installs; hermetic tests; scratch paths <= 200 characters; the worker exits before scratch deletion (mapped files); the Job Object memory limit counts committed memory (the RLIMIT_AS evidence is Linux only).
- Live gates that only CI or the owner can close, reported separately and never counted as done: Windows CI run of the Section 5 grid and frozen worker scan; Windows start-up time, Defender or EDR behaviour and antivirus scan of `yara_x.pyd` (JIT); real Microsoft series through Tier W (local only); NVDA/Narrator announcement and 125/150/200 % DPI of the panel; Tier R stability numbers (R8); capstone fallback if iced-x86 fails the frozen smoke.

## 11. Open questions (defaults; never blocking)
| Question | Default |
|---|---|
| Package name `rules/` overlaps in meaning with `patch-rules/1` in `intelligence` | keep `rules/`; contract `yara-rules/1`, classes `Rule*`, errors `PT-RULE-*` |
| Decoder: iced-x86, capstone, or unified IR only | `MaskSource` port; iced-x86 first (Rust, MIT, abi3), capstone documented fallback, unified IR preferred when S1 lands, mask parity test then |
| Both pins in the Windows alpha or an optional extra | base dependencies (the feature is part of the standalone alpha); state R1 covers installs without them |
| Several changed functions of one finding in one rule | no in v1 (one pair per candidate); revisit after R8 |
| "Variant hunting" in a non-clean scan set | out of scope in v1 (drifts toward a generic scanner) |
| Where the clean set is defined | project-level folder pointer; hashes and basenames recorded; files never copied |
| More than 8 builds | grid takes the series (<= 8) plus <= 64 extra builds from the acquisition store or a file picker |
| Cross-project rule library | no; project-local only |
| Expectations for series builds | analyst sets them; CSAF/KB applicability is shown separately as "advisory says" |
| Per-crate licence texts for the 303 Rust crates | ship the SBOM and upstream LICENSE now; the owner decides whether `cargo-about` output is required |
| A blocked JIT (ACG/EDR): defect or limitation | documented limitation: state R1 with the probe's reason |
