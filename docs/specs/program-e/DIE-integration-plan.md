# DIE integration plan: build-environment fingerprint, delta and noise attribution (Detect It Easy `diec` 3.21 plus PatchTrace PE facts)

Status: D1, D2, D3, D4 built, D7 pure timeline built, D9 gate tool built (synthetic goldens), D8 live test and dispatch job written (not yet run) (D3: `buildenv` core; D4: store, CLI, report section, 2026-10-14); Program E E-1 research plan, docs only (worker DIE, 2026-10-14), base `d972125` (`prep/program-e`). Every external fact was retrieved 2026-10-14. Edits to other files are listed in section 10 for the integration owner. Abbreviations: "T-spec" = `docs/specs/three-tool-evidence-adapters.md`; "UE" = `docs/specs/unified-engine/`; "[repo]" = measured or recorded in this repository; "[unverified]" = not confirmed from a primary source (reason given).

## 1. Verdict and scope
- Build `src/patchtrace/buildenv/` (Qt-free) plus additive `pe_overview` files. Per side: a **build-environment fingerprint** from two independent channels. Channel A is PatchTrace PE facts (linker/OS/subsystem header fields, Rich header, debug-entry types, GUARD_CF/GuardFlags/SecurityCookie, CLR header, runtime import families, entropy). Channel B is pinned `diec` 3.21 signature detections. Per pair: a **delta** (toolchain same/differs/unknown, changed build options, pre-flight warnings).
- Consumers: a card plus notice bar in the PE overview; a **view-layer overlay** on unified rows ("Build differs" tag, a small ordering effect, nothing hidden, no verdict touched); a notice line on the primary navigator; a series timeline; `build-env` CLI; a report section.
- Channel A works with no external tool. DiE adds names and signature-level corroboration. Header-only differences stay `unknown` because linker fields are forgeable (`lld-link` hard-codes 14.0).
- Why an overlay and not a new `ChangeFacts` channel (C9) or evidence atom: `ChangeFacts`, `result_key` and the A/A gate G-U1 are code-derived and cached, so tool evidence that arrives later or changes (a new DiE run) must not invalidate results or move a verdict. The build-fact channel is a port read at display time (`BuildFactsProvider`: stored result + current `BuildEnvDelta` -> tags), so evidence order never matters.
- Fix first: today's `diec.py` rejects valid upstream JSON (nested file parts, empty result) and files 16 of 24 probed upstream record types under `other` (compressor, crypter, obfuscator, protection, ...), so packing can go unflagged. `tool-evidence/1` has no stored row yet, so the contract can still change.
- Not built: in-process `die-python`; DiE inside the installer; automatic DiE runs (opt-in until value gate T6.4); `-g -r -a -x -S` modes; unpacking; any numeric noise score or false-lead-reduction claim; compiler-option inference (optimization level cannot be read from a PE); network access.
- Invariant: no `ChangeFacts` verdict, `result_key`, attention/1 score or stored result changes because of this feature.

## 2. Sources and facts
| claim | source URL | retrieved | confidence |
|---|---|---|---|
| DiE is MIT, "Copyright (c) 2012-2026 hors". Releases and console source: `horsicq/DIE-engine`; signatures, docs, changelog: `horsicq/Detect-It-Easy` (submodule `dep/Detect-It-Easy`) | https://raw.githubusercontent.com/horsicq/Detect-It-Easy/master/LICENSE ; https://raw.githubusercontent.com/horsicq/DIE-engine/master/LICENSE ; https://raw.githubusercontent.com/horsicq/DIE-engine/master/.gitmodules | 2026-10-14 | high |
| 3.21 is the latest stable (release page "21 Apr 22:44", no year shown; changelog dates it 2026-04-22, "Fix console output"). 3.20 added a PEiD scan method. A `Beta` pre-release (03 Jun) exists. Changelog 4.0.0 (undated) replaces Qt Script by a custom DiE-JS engine, adds "false-signature countermeasures" and a new PE heuristic module, so output will move: pin 3.21 | https://github.com/horsicq/DIE-engine/releases ; https://raw.githubusercontent.com/horsicq/Detect-It-Easy/master/changelog.txt | 2026-10-14 | high |
| 3.21 assets: `die_win64_portable_3.21_x64.zip` (Win7-Win11), `die_3.21_Ubuntu_22.04_amd64.deb` (also 20.04, 24.04, 26.04, Debian 10-13), `die_3.21_portable_Ubuntu_20.04_amd64.tar.gz`, AppImage, macOS pkg. The page shows no sizes or digests; `api.github.com` answers 403 here, so pins stay trust-on-first-use | https://github.com/horsicq/DIE-engine/releases/tag/3.21 | 2026-10-14 | high |
| Provisioning: Windows = extract the portable zip into a tools folder outside the PatchTrace install (no installer, no admin). Linux = the `.deb` needs system `libqt5core5a libqt5script5` and is extracted without root by the T provisioner (`dpkg-deb --fsys-tarfile` plus stdlib tar); the portable tarball is an alternative whose contents are [unverified]. PatchTrace never runs an installer. No PyPI wheel exists for `diec` | [repo] T-spec T1, T9; release page above | 2026-10-14 | medium |
| Repo pins (trust-on-first-use): Windows zip 25,197,854 B, Linux 22.04 deb 11,806,884 B; database 1,511 files; Linux and Windows trees differ only by CRLF (tree/1 digests `301b24a7..` vs `a862337e..`) | [repo] `docs/qa.md` lines 210-211, `diec.KNOWN_DATABASES` | 2026-10-14 | medium (second-path re-hash open) |
| The shipped `db` = repo `db` plus every `db_extra/*` subfolder merged (Windows `xcopy` loop, Linux `cp -Rf`). README calls `db_extra` rules "not approved for the main database": unreviewed rules are active by default | https://raw.githubusercontent.com/horsicq/DIE-engine/master/build_win_generic.cmd ; https://raw.githubusercontent.com/horsicq/DIE-engine/master/build_dpkg.sh ; https://github.com/horsicq/Detect-It-Easy | 2026-10-14 | high |
| No database version file was found in the sources read (identity = release + tree digest) [unverified]. DIE-engine `master` was 793 commits past the 3.21 tag. README says the bundled DB "preserves ... material imported from the original PEiD rules" and gives no licence for it: never redistribute or commit the DB | https://github.com/horsicq/DIE-engine/releases/tag/3.21 ; https://raw.githubusercontent.com/horsicq/Detect-It-Easy/master/README.md | 2026-10-14 | medium |
| Static analysis: README "The file is never launched" (scoped to the PE heuristic engine). `main_console.cpp` has no process or network code. The `diec` CMake target links Qt Core/Concurrent/Script (Qt6: Qml), capstone_x86, xsimd and, on Windows, Wintrust and Crypt32; not Qt Network, XUpdate, XGithub, XOnlineTools or XYara | https://raw.githubusercontent.com/horsicq/DIE-engine/master/src/console/main_console.cpp ; https://raw.githubusercontent.com/horsicq/DIE-engine/master/src/console/CMakeLists.txt | 2026-10-14 | high for files read, medium overall (no whole-engine audit) |
| Script API is read-only: `Global.md`, `Binary.md`, `Util.md` document no process, file-write, network or native-load function. `decompressBytes` inflates in memory (bomb risk: timeout and memory cap). Extra and custom databases are script code, hence `-E`/`-C` stay empty folders and `-D` is a pinned copy | https://raw.githubusercontent.com/horsicq/Detect-It-Easy/master/help/Global.md ; .../help/Binary.md ; .../help/Util.md | 2026-10-14 | medium-high |
| Offline run time: 8 real runs under `unshare -rn` took 0.13-0.23 s on 2-4 KiB synthetic PEs. Real binaries are not measured; memory use is unknown | [repo] `tests/fixtures/intel_tools/manifest.json` | 2026-10-14 | high (synthetic), [unverified] (real) |
| Windows `diec` links Wintrust/Crypt32; a search hit says XEmulator attributes them to XPE Authenticode parsing. Whether `WinVerifyTrust` ever runs with revocation (network) inside `diec` is [unverified]: live gate with a blocked-network run | https://github.com/horsicq/XEmulator (search snippet only) | 2026-10-14 | low |
| JSON writer `ScanItemModel::_toJSON`: root array `detects`; header nodes carry `parentfilepart, filetype, info, offset, size` (decimal strings) and a `values` array that can hold leaves `{type,name,version,info,string}` **and nested header nodes**; a childless root is a leaf whose `string` is "Result"; empty fields stay `""` | https://raw.githubusercontent.com/horsicq/XScanEngine/master/scanitemmodel.cpp (quoted lines) | 2026-10-14 | high |
| 57 `RECORD_TYPE` names (Compressor, Crypter, Cryptor, Obfuscator, .NET compressor, .NET obfuscator, Virtual machine, Protection, Dongle protection, Joiner, Stub, Loader, Language, Operation system, Sign tool, PE Tool, ...). Scripts emit lower-case types; `~` marks a heuristic, `!` an aggressive heuristic; display strings get `(Heur)` / `(A-Heur)` | https://raw.githubusercontent.com/horsicq/XScanEngine/master/xscanengine.cpp | 2026-10-14 | high |
| `diec --help` 3.21 lists -j -D -E -C -d -u -b -g -U -e -i -S -x -c -t -p -s -w -r -a -l -M --test --addtest. Upstream `docs/RUN.md` documents none of them, so the help text is the contract | [repo] `tests/fixtures/intel_tools/diec/help.stdout.txt` ; https://raw.githubusercontent.com/horsicq/Detect-It-Easy/master/docs/RUN.md | 2026-10-14 | high |
| Real 3.21 output on synthetic PEs: an MSVC-like Rich header gives `Linker: Microsoft Linker(14.38.33134)`, `Compiler: Microsoft Visual C/C++(19.38.33134)[C]`, `Tool: Microsoft Visual Studio(2022, 17.8)` although the same file's header field says 14.36. A plain MinGW PE gets `(Heur)Protection: Generic` with `-d -u`. A GNU-ld-like header gets no linker line in the non-verbose output (whether `-b` adds one is untested) | [repo] goldens `diec-same-older.json`, `diec-toolchain-newer.json`, `diec-toolchain-newer.heuristic.json` | 2026-10-14 | high (synthetic only) |
| Microsoft toolchain names come from `_Microsoft.6.sg`: Rich via `PE.getRichID/getRichVersion`, a hard-coded `richIdMap`, build-number thresholds ending in a "Future versions" catch-all, string-compared versions. `_linkers.6.sg` guesses linkers from header version fields and has no LLD detection | https://raw.githubusercontent.com/horsicq/Detect-It-Easy/master/db/PE/_Microsoft.6.sg ; .../db/PE/_linkers.6.sg | 2026-10-14 | high |
| `lld-link` hard-codes `MajorLinkerVersion=14`, `MinorLinkerVersion=0` ("matches VS2015 output"); OS and subsystem versions come from options; the excerpt read (100 KB of 117 KB) shows no Rich header | https://raw.githubusercontent.com/llvm/llvm-project/main/lld/COFF/Writer.cpp | 2026-10-14 | high (fields), medium (Rich) |
| PE fields (Microsoft docs source repo): MajorLinkerVersion @2, OS version @40/42, image version @44/46, subsystem version @48/50; DllCharacteristics GUARD_CF 0x4000; debug types incl. REPRO 16 and EX_DLLCHARACTERISTICS 20; PE32+ LoadConfig SecurityCookie @88, GuardCFCheck @112, GuardCFDispatch @120, GuardFlags @144 and the flag values. The page never mentions the Rich header. `learn.microsoft.com` is DNS-blocked here | https://raw.githubusercontent.com/MicrosoftDocs/win32/docs/desktop-src/Debug/pe-format.md | 2026-10-14 | high |
| Debug types 12 VC_FEATURE, 13 POGO, 14 ILTCG, 15 MPX are named by LLVM but absent from Microsoft's table: record the entry TYPE only and never interpret payloads | https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/include/llvm/BinaryFormat/COFF.h | 2026-10-14 | high (names), [unverified] (meaning) |
| Rich header: undocumented by Microsoft. pefile parses it only in `full_load()`, returns flat words, catches only `PEFormatError` and caps nothing; `parse_rich_header()` can be called after `fast_load=True`. A link switch that omits it (`/emittoolversioninfo:no`) is [unverified] (third-party discussions only): absence means unknown | https://raw.githubusercontent.com/erocarrera/pefile/master/pefile.py | 2026-10-14 | medium |
| pefile 2024.8.26 (2024-08-26), MIT, `py3-none-any` wheel 74.8 kB, Python >=3.6, so `--only-binary=:all:` works; no release in the 2 years before retrieval | https://pypi.org/project/pefile/ ; https://raw.githubusercontent.com/erocarrera/pefile/master/LICENSE | 2026-10-14 | high |
| `die-python` 0.5.0 (2026-02-20): wheels cp312 win_amd64 and manylinux_2_34_x86_64; bundles Qt (LGPL) plus DiE and die_library (MIT); licence metadata contradicts itself (Apache-2.0 text, MIT classifier). It is in-process native code with its own Qt 6: rejected for the GUI process (Qt DLL collision with PySide6 is design reasoning; no job object, memory cap or timeout) | https://pypi.org/project/die-python/ | 2026-10-14 | medium-high |
| CLR: `IMAGE_COR20_HEADER` = 72 bytes (sum of the listed fields); flags ILONLY 1, 32BITREQUIRED 2, STRONGNAMESIGNED 8, NATIVE_ENTRYPOINT 0x10. Metadata root and version string layout is ECMA-335 [unverified: not fetched] | https://raw.githubusercontent.com/dotnet/runtime/main/src/coreclr/inc/corhdr.h | 2026-10-14 | high / medium |
| Compiler docs: /GS on by default and calls a check helper; /guard:cf off by default, sets the Guard DLL characteristic and checks every indirect call; /JMC inserts `__CheckForDebuggerJustMyCode`. Helper names for the GS check and CFG dispatch are not on those pages: measure, do not assume | https://raw.githubusercontent.com/MicrosoftDocs/cpp-docs/main/docs/build/reference/gs-buffer-security-check.md ; .../guard-enable-control-flow-guard.md ; .../jmc.md | 2026-10-14 | high |
| One toolchain, many shapes: the same source differs 14 -> 151 instructions (`lp_add_sat_u8`, -O1 -> -O2) and 41 -> 7 (`st_tlv_payload_len`, -O0 -> -O1) under one clang; signatures cannot see optimization level | [repo] `corpus/ours/compiler-noise/PROFILES.md` | 2026-10-14 | high (own measurement) |
| Accessibility: `QAccessible::Event::NameChanged` and `Alert` exist. Repo rule: a fixed accessible name suppresses status announcements. WCAG 2.2 1.4.1, 1.4.3, 1.4.11, 4.1.3 are cited as the repo's C6 spec does | https://raw.githubusercontent.com/qt/qtbase/dev/src/gui/accessible/qaccessible.cpp ; [repo] `docs/specs/multi-engine-evidence-panel.md` lines 108-110 | 2026-10-14 | medium |
| Pins and licences (SPDX): `diec` 3.21 (MIT; databases pinned by tree digest above); pefile 2024.8.26 (MIT, dev/test only); no new runtime dependency. LLVM `COFF.h` and `Writer.cpp` Apache-2.0 WITH LLVM-exception and `corhdr.h` MIT: names and numbers only, no code copied. Qt 5 Core and Script, as linked by `diec`: LGPL [unverified: licence text not fetched]. `die-python` Apache-2.0 vs MIT conflict unresolved (not used). DiE's `richIdMap` is not copied: PatchTrace stores raw Rich tuples. No GPL or AGPL code was read for or copied into this design | [repo] `diec.py`; links in the rows above | 2026-10-14 | medium |
| Blocked from this sandbox: `learn.microsoft.com`, `doc.qt.io`, `www.w3.org` (DNS), `api.github.com` (403). ECMA-335, Qt licence text and Microsoft UI Automation pages were not read | - | 2026-10-14 | - |

## 3. Standalone baseline versus PatchTrace value
**DiE alone:** one file at a time; a flat list of type, compiler, linker, tool, packer and protector strings (plain, JSON, CSV, XML) and a GUI. No pair, no delta, no link to functions, provenance limited to a version string, noisy opt-in heuristics, no "what next".

**PatchTrace adds:**
1. Two channels fused per side with labelled certainty (`exact-field`, `derived`, `signature`, `heuristic`, `unknown`); disagreements are listed (`sources-disagree`) and never silently resolved.
2. A pair delta with explicit orientation, unknown-versus-absent semantics, strong/weak basis and a corroboration flag that counts shared origins once.
3. A pre-flight list (packed, protected, managed, installer, one-sided packing, large overlay) shown while Ghidra is still starting; the analyst can dismiss or cancel, nothing blocks.
4. Noise attribution on engine output: tags with reasons on unified rows and a notice on the primary navigator; every row stays visible and every verdict unchanged.
5. A build-environment timeline over 3-8 builds; provenance (tool version, database label and digest, argv version, artifact hash, cache key); report and CI output.

**Workflows:**
- W1 before the run: the notice bar and card appear on Run comparison (packed? .NET? different toolchain?), so a multi-hour run can be cancelled early.
- W2 "why are 400 functions modified?": the card shows the toolchain change, matching unified rows are tagged, the detail panel says why.
- W3 "when did the toolchain change?": the series strip points at the hop.
- W4 "is this capability or string delta real?": CAP and WB3 notes reuse the same delta.
- W5 evidence for a ticket or CI: `build-env delta --json` and the report section with provenance.

## 4. Cross-feature links
| anchor / evidence | direction | other tracks | use |
|---|---|---|---|
| build fact (`BuildFactAnchor`: compiler, linker, tool, runtime family, language, target OS, packer, protector, installer, obfuscator, managed, GS cookie, CFG, ASLR, REPRO, Rich signature, debug-entry types) | emits, per side | FAB, UE, CAP, WB3, PIL, YRX, GDE | FAB stores and links; UE read model tags rows; CAP and WB3 add notes; PIL treats a build-only delta as context and never as a negative vote; YRX records the builds a rule was validated on; GDE teaches from `teach_id` |
| pre-flight warning (11 codes) | emits | GUI, reports, CLI, GDE | notice bar, card, report, exit code, "what to do next" text |
| noise attribution (row id -> reason + classes; view data, never stored in `unified-result`) | emits | UE, FAB lead list | tag chip, reason text, optional order |
| function pair (`row_id`, materiality, change classes, `deltas_omitted`, `limits_hit`, F10 edit groups) | consumes | UE | overlay input, read-only |
| import/API (DLL names), sections, overlay, entropy, CLR directory | consumes | `pe_overview` | runtime family, managed, packing hints |
| string (FLOSS static and decoded) | consumes | WB3 | a string equal to a DiE detect string or version banner gets a display tag "build string"; it is never removed from the delta |
| capability delta (capa `quality_flags`) | aligns | CAP | `delta.quality_flags` keeps its DiE-only flags; a parity test asserts agreement with `BuildEnvDelta.toolchain` |
| version info / FileVersion | consumes | WBQ (`version_resources`) | optional timeline column labels |
| build labels (`BuildRef.label`, KB product and build names) | consumes | N-way, KB | timeline column titles; no KB or CVE inference from builds |
| CVE, CWE, advisory phrase | none | KB, PIL | build facts never create or remove such a link |

## 5. Synergy test
`tests/test_buildenv_synergy.py::test_toolchain_swap_explains_shape_only_rows` (pure, offline, under 1 s; no Ghidra, no `diec` at test time, no Microsoft binary).

**Inputs (all committed):**
- PE pair `diec-toolchain-older.exe` / `-newer.exe`, rebuilt by `tests/test_intel_tools_pe.py::write_pairs()`. Older: MSVC-like Rich header, header linker field 14.36. Newer: GNU-ld-like 2.38, no Rich header, MinGW-style sections.
- The committed real diec 3.21 goldens for both.
- `tests/fixtures/buildenv/rows-toolchain-swap.json`: hand-authored `unified-match/1` + `change-facts/1` subset, synthetic.

| row | truth | engine alone |
|---|---|---|
| Init | changed (call added) | `material` |
| ParseHeader | changed (compare bound 0x100 -> 0x200) | `material` |
| ValidateLen | changed (comparison), S3b off | `review: comparison` |
| BuildMessage | changed (retry constant 3 -> 5) | `review: constant` elsewhere |
| CopyBuf | cosmetic (frame size, register allocation) | `review: frame, register-only` |
| Crc32Update | cosmetic (unrolled) | `review: cfg, block-added` |
| LogMessage | cosmetic (unwind data) | `review: eh` |
| Main | same | `unchanged` |

**Each channel alone:**
- Engine alone: 7 leads (2 material, 5 review), 3 of them not source changes, default order Init, ParseHeader, ValidateLen, Crc32Update, LogMessage, BuildMessage, CopyBuf (UE 05 s2.6 severity), with no hint why.
- DiE alone: names two toolchains, says nothing about functions.
- PE facts alone: Rich present -> absent and linker field 14.36 -> 2.38 differ, but both are forgeable, so toolchain `unknown` and zero tags.

**Combined, expected:**
- `BuildEnvDelta.toolchain == 'differs'` (strong: DiE signatures differ on both sides), `toolchain_corroborated` true (diec plus Rich presence), basis `diec, rich-header, pe-header`. OLDER carries anomaly `linker-version-sources-disagree` (header 14.36 vs DiE 14.38.33134), shown as a row status, not in the notice bar.
- Tags: CopyBuf and LogMessage (effect `order`), Crc32Update (effect `tag`). No tag on ParseHeader, Init, ValidateLen, BuildMessage, Main. Summary text: "3 of 5 review rows are of kinds a toolchain change can produce".
- Default order: Init, ParseHeader, ValidateLen, Crc32Update, BuildMessage, LogMessage, CopyBuf (only LogMessage moved). With "Group build-tagged rows last" on: Init, ParseHeader, ValidateLen, BuildMessage, Crc32Update, LogMessage, CopyBuf (all real changes first).
- All eight rows stay listed. Every `verdict`, `proof` and `row_id` is byte-equal to engine alone. The `result_key` inputs are unchanged.

**Controls:**
- `diec-same` pair: `toolchain == 'same'`, zero tags, `sort_keys` byte-equal to engine alone, state B3.
- `diec-unknown` pair: `unknown`, zero tags, state B5.
- DiE not configured on the swap pair: `unknown`, zero tags, state B2 text and the tool-unavailable notice.
- A same-toolchain pair whose rows differ only in shape (the -O0 versus -O2 situation): zero tags, and the B3 text says code can still differ.

**Second scenario** (`test_synergy_packed_newer_raises_one_sided_warning`): a synthetic pair whose newer file has UPX-like sections (UPX0 raw size 0, high-entropy UPX1) gives a `pe_overview` medium hint plus a DiE golden (captured by the live gate; BLOCKED until then) and the `packed-one-side` caution, with no change to any verdict.

**Claim discipline:** a behaviour test on synthetic data. It asserts annotation, counts and ordering rules, not effectiveness. Effectiveness is gate G-DIE-1 (section 10).

## 6. Traps and guards
| trap | guard | test |
|---|---|---|
| "Same toolchain" read as "no build noise" (optimization level, LTO and PGO are invisible to signatures; `PROFILES.md`) | B3 copy states code can still differ; tags need `toolchain == 'differs'`; same-toolchain shape-only pairs get zero tags | `test_same_toolchain_says_no_change_detected_not_no_noise`, `test_opt_level_pair_is_not_explained` |
| Forgeable linker field (`lld-link` writes 14.0) taken as a brand | header facts carry `certainty exact-field`; brand claims need DiE or Rich; header-only differences give `unknown` | `test_header_only_difference_is_unknown`, `test_lld_style_header_has_no_rich_and_linker_14_0` |
| DiE version mapping saturates ("Future versions", string-compared versions) | store raw Rich `(product_id, build)` pairs and diff those; show DiE text as "reported as"; counts are excluded from the Rich signature because they track code size | `test_rich_counts_alone_never_differ` |
| Rich header absent, stripped or forged | absence is `unknown`; present -> absent is a weak change only; a failed checksum downgrades strength | `test_rich_absent_is_unknown`, `test_rich_checksum_failure_is_weak` |
| Channels reach opposite strong verdicts | verdict becomes `unknown` and `sources-disagree` is listed; neither channel is preferred | `test_channels_contradict_downgrades_to_unknown` |
| One origin counted twice (DiE derives non-Rich linker names from the same header field PatchTrace reads) | corroboration needs two distinct sources and counts {pe-header linker field, diec linker name} once | `test_shared_origin_counts_once` |
| Heuristic detections drive warnings (`(Heur)Protection: Generic` on a plain MinGW PE) | heuristics off by default, shown only under "weak hints", never raise a caution | `test_heuristics_never_raise_caution` |
| Unreviewed `db_extra` rules are active | provenance names database label and digest; copy says "matched by signature", never "is" | `test_provenance_names_database` |
| Valid upstream JSON rejected (nested parts, empty result) or mis-typed | recursive node model flattened with a path and depth cap 8; a childless root with `string` "Result" is `none-found`; any other shape stays `PT-TOOL-OUTPUT`; `!` and `(A-Heur)` count as heuristic | `test_nested_file_part_nodes_flatten_with_path`, `test_empty_result_document_is_none_found`, `test_aggressive_heuristic_markers_are_heuristic` |
| Record types fall into `other` | total table over the 57 pinned names, `raw_type` always kept, every name is in a warning set or explicitly neutral, unknown names raise a vocabulary-drift anomaly | `test_every_upstream_record_type_has_a_category` (ids `t00`..`t56`) |
| Down-weighting buries a real fix | overlay never touches `material`, `contested`, semantic classes or rows with `deltas_omitted > 0` or `limits_hit`; `cfg` and `block-*` are tag-only by default; the toggle is the analyst's | `test_material_and_contested_never_tagged`, `test_rows_with_omitted_deltas_never_tagged` |
| One side has evidence, the other not | per-fact `one-sided-unknown`, never a difference | `test_one_sided_is_unknown_not_difference` |
| Stale or foreign evidence (other artifact, database, argv, executable) | `PT-TOOL-STALE` upstream, `PT-BUILD-STALE` here, state B7; Linux and Windows evidence is not comparable (executable hash differs, T6.1): re-run | `test_stale_evidence_is_reference_only` |
| Hostile strings in names, versions, info | `display_text` plus `sanitize_text`, 200-char caps, plain-text labels, no markup, C6 hostile list | `test_hostile_detection_strings_plain_text` |
| Overclaiming copy ("compiler-induced", "safe", "certain") | copy deck in code, banned-word sweep (`evidence_view.BANNED`), wording "may", "can", "matched by signature" | `test_buildenv_banned_strings_never_appear` |
| `diec` parses hostile input in native code | child process via `jobs.run_process`, scratch, allow-listed env, timeout 120 s, stdout 1 MiB, memory cap min(4 GiB, 50 % of RAM) as in UE L-42 (new for diec), Linux leg run under `unshare -rn` | `test_live_buildenv_offline_and_capped` (live) |
| A cache or database write by `diec` leaks outside the scratch | HOME, XDG and LOCALAPPDATA are already redirected into the scratch (`_saveDatabaseCache` exists upstream; location [unverified]) | fake-executable runner tests (T next wave) plus a live check with an empty profile |
| Banner shown as colour only, stale banner reused, dismissal hiding a new warning | glyph plus word, banner rebuilt per delta id, dismissal scoped to one delta id | `test_banner_not_colour_only`, `test_dismiss_scoped_to_delta` |

## 7. Contracts
Package `src/patchtrace/buildenv/`: strict frozen Pydantic v2 (`extra='forbid'`), `contract: 'build-environment/1'`, additive changes only. Schemas come from `tools/generate_buildenv_schemas.py` into `docs/schemas/build-environment/` with a regenerate-and-compare test. The `pe_overview` additions are stdlib frozen slotted dataclasses, like that package.

**Records**
- `RichEntry{product_id u16, build u16, count u32}`; `RichFacts{offset, key, checksum_ok bool|None, entries <=1024, truncated, signature}`. `signature` is the SHA-256 of the sorted unique `(product_id, build)` pairs; counts are excluded.
- `ClrFacts{header_size, runtime_major, runtime_minor, flags (names), il_only, has_native_header, metadata_version <=64|None}`.
- `PeBuildFacts{facts_version 'pe-build-facts/1', linker_field, os_field, image_field, subsystem_field (major, minor)|None, subsystem, dll_characteristics (names), guard_flags (names)|None, security_cookie_set bool|None, debug_entry_types tuple[int] <=16, repro, rich, clr, runtime_families <=8, entropy_exec_max, overlay_size, overlay_entropy, sampled, anomalies <=16 codes}`. `runtime_families` come from a closed table by DLL name (`msvc-crt-14`, `ucrt`, `msvcrt-legacy`, `mingw`); no version claims.
- `BuildFact{key, value <=200, version <=120, source, certainty, ref <=64, raw <=4 pairs}`. `key` is a closed set of 26: compiler, compiler_version, linker, linker_field, linker_rich, build_tool, runtime_family, language, target_os, subsystem, os_version_field, subsystem_version_field, image_version_field, rich_signature, packer, protector, installer, obfuscator, managed, gs_cookie, cfg, aslr, repro, debug_entry_types, entropy_exec, overlay. `source` in {pe-header, rich-header, debug-directory, load-config, imports, clr-header, sections, diec}. `certainty` in {exact-field, derived, signature, heuristic, unknown}.
- `DieSummary{status, run_id, tool_version, db_label, db_sha256, argv_version, heuristics, cache_key}`; `BuildFingerprint{contract, artifact_sha256, side, pe, die, facts <=128, anomalies <=16, built_from{pe_facts_version, die_cache_key|None, fingerprint_version 'buildenv/1'}}`.
- `BuildChange{key, older, newer, change (added, removed, changed, unchanged, one-sided-unknown), kind (toolchain, option, descriptive), strength (strong, weak), basis <=4}`.
- `PreflightWarning{code, side, severity (notice, caution), summary <=160, detail <=400, basis, teach_id}`; `code` in {packed, protected, managed, installer, overlay-large, packed-one-side, toolchain-differs, tool-unavailable, heuristic-only, stale-evidence, sources-disagree}.
- `NoiseReason{code 'toolchain-differs', classes <=12 (UE `ChangeClass` names), effect (tag, order), why <=200}`; `BuildEnvDelta{contract, older_sha256, newer_sha256, orientation 'older->newer', comparable, reasons, toolchain (same, differs, unknown), toolchain_corroborated, options_changed <=8, changes <=128, preflight <=16, noise <=4, map_version 'noise-map/1', limits_hit, counts}`.
- `BuildFactAnchor{anchor_id = domain_id('build-fact', 1, {artifact_sha256, key, value, source}), key, value, side, artifact_sha256, source, certainty}` for FAB. Amended by FAB-0 (2026-10-14): `BuildFactAnchor` gets a converter to the fabric `build_fact` anchor (key `<key>=<value>`, FAB-2 `fabric/convert.py`); its own `anchor_id` is not the fabric identity. `TeachHook{id, meaning, next_steps <=4}`; texts live in one copy table in `buildenv/copy.py`.

**Rules**
- Verdict: `differs` needs one strong toolchain change and no opposite strong verdict from the other channel. Strong = DiE compiler/linker/tool signature on both sides differing, or Rich `(product_id, build)` sets differing with valid checksums on both sides. Header-only or heuristic-only differences give `unknown`. Equal comparable strong facts give `same`. Nothing comparable gives `unknown`. `toolchain_corroborated` = changes from at least two distinct sources, counting {pe-header linker field, diec linker name} once.
- Pre-flight severity: `packed` is a caution when a DiE signature-level type is in `PACKED_TYPES` {packer, compressor, .net compressor, cryptor, crypter} or a `pe_overview` hint is medium (wording "may be packed (hint)" without DiE); a low PE hint is a notice. `protected` is a caution for signature-level `PROTECTED_TYPES` {protector, protection, obfuscator, .net obfuscator}. Types such as virtual machine, dongle protection, joiner, stub, loader are listed but neutral. `managed`: `il_only` is a caution, mixed or ReadyToRun (native header present) a notice. Heuristics (`~`, `!`) never raise a caution.
- `noise-map/1` (data, versioned, tested): effect `order` for `eh, frame, register-only, address-only, layout-only, size-only, refcount-only, name-only`; effect `tag` for `cfg, block-added, block-removed`; never for `constant, comparison, condition, callee, call-added, call-removed, data-ref, struct-offset, string, unknown`. A row qualifies only if its verdict is `review`, every delta class is in the map, `deltas_omitted == 0`, there is no `limits_hit`, and `BuildEnvDelta.toolchain == 'differs'` for the same pair and orientation. A mixed row takes the weakest effect. Ordering: rows with effect `order` (and, when the analyst turns on "Group build-tagged rows last", effect `tag` as well) move after the untagged rows of the same materiality group, keeping engine order inside each part (stable partition). No row crosses a materiality group. Options deltas (GS, CFG, REPRO, debug types) are context only in v1.
- Rich header source: the stdlib parser is authoritative (bounded, fed by `VerifiedArtifactReader`). When `pefile` happens to be importable (WBQ ships it), a cross-check on the same header bytes (`fast_load=True`, then `parse_rich_header()`, inside try/except) may add the anomaly `rich-pefile-mismatch`; it never changes a fact. pefile is also the test oracle.
- Errors: `PT-BUILD-INPUT` (artifact unreadable or not PE), `PT-BUILD-LIMIT`, `PT-BUILD-STALE`, `PT-BUILD-MISMATCH` (same hash, wrong orientation), `PT-BUILD-STORE`. DiE failures stay `PT-TOOL-*`.
- Persistence: one additive enrichment kind `build-env` (in `KINDS`, not in `DERIVED_KINDS`). Entry id `domain_id('build-env', 1, {artifact_sha256, pe_facts_version, die_cache_key|None})`; body = `BuildFingerprint` inline, at most 64 KiB; guard `(project_id, 'build-env', artifact_sha256, input_digest)`; written on the GUI thread; no sidecar. Deltas are always recomputed and never stored. `tool-run` and `tool-evidence` rows are only read.
- Cache-key inputs: artifact SHA-256, `pe_facts_version`, `fingerprint_version`, the DiE `cache_key` (T-spec T7: artifact, engine, version, executable, database, backend, options, parser contract). Delta identity adds both ids, orientation and `noise-map/1`.
- Limits: Rich region <= 64 KiB (existing `max_lfanew`), <= 1,024 entries; debug entries <= 16; extra reads <= 100 KiB per side; PE facts <= 2 s per side with cancel polled; diec stdout 1 MiB, stderr 256 KiB, timeout 120 s, nesting depth 8, <= 512 detections (existing `max_environment`); timeline <= 8 builds (`MAX_BUILDS`); report section <= 64 KiB.

**Adapter changes (slice D1, before the first stored row)**
- Recursive `Node` model; empty-result rule; `!` and `(A-Heur)` count as heuristic; `memory_limit_bytes` passed by `process.execute` for diec.
- Total type table over the 57 names, `raw_type` kept. Category mapping: Compressor and .NET compressor -> packer; Crypter -> cryptor; Obfuscator, .NET obfuscator, Protection -> protector; Installer data -> installer; SFX data -> sfx; Language -> language; Operation system -> os; Archive -> archive; Sign tool -> signtool; PE Tool -> petool; everything else -> other. New additive `EnvCategory` values: language, os, archive, signtool, petool.
- `delta.quality_flags` uses the same `PACKED_TYPES` and `PROTECTED_TYPES` sets; installer and sfx become their own flag.

## 8. CLI and GUI
**CLI** (`buildenv/cli.py`; adapter `cli_commands/build_env.py` (<= 25 lines), no `cli.py` hook; envelope `enrichment-cli/1`; no Qt import):
```
patchtrace build-env show     PROJECT [--side older|newer|both] [--technical] [--json]
patchtrace build-env delta    PROJECT [--json]
patchtrace build-env timeline SERIES_DIR [--json]
```
- The CLI never spawns a tool. DiE results come from stored `tool-evidence` rows (written by `intel-tools run --engines diec`); otherwise the output says `"die": "not-run"`. The GUI button runs the T runner.
- Exit codes. show: 0 all requested sides read; 3 a side unreadable (the other is printed); 2 invalid arguments or nothing readable; 5 cancelled. delta: 0 toolchain `differs`, options changed or a caution warning; 4 comparable with nothing found; 3 partial (a side missing or stale, the rest compared); 2 invalid; 5 cancelled. timeline: 0 all builds present; 3 some `not-run` or unreadable; 2 invalid series; 5 cancelled.
- Default output shows basenames only, no stderr excerpts or paths; `--technical` adds raw Rich entries, database digest and argv version.

**GUI placement (one main window)**
1. `BuildEnvCard(QGroupBox)` as the first block of the existing "Preliminary file comparison" dialog, below the explanation label (it opens on Run comparison). It is a plain widget: its `PANEL` keeps `area='none'` until the card moves into a dock (GUI plan F5), and then the GUI track moves it unchanged.
2. `PreflightBanner(QFrame)` notice bar at the top of the central workspace (posts through `ctx.shell.notice`, GUI plan F5) and the same class at the top of the dialog.
3. Unified view: chip "Build differs" after the Change text, a "Build environment" section in the detail tab, filter checkbox "Group build-tagged rows last" (QSettings `build_env/group_last`, default off). Primary navigator (Rank changes order): one notice line above the list, no per-item tag in v1 because the attention detectors have no measured build-cause rule.
4. `BuildTimelineStrip(QTableView)` above the chain table of the existing Series window (no new window).
```
+- Build environment ------------------------- [Read with Detect It Easy] [Set up...] -+
| [!] Caution: NEWER looks packed (UPX 3.96, matched by signature). ...  [Details][Dismiss]
| Toolchain differs between OLDER and NEWER: compiler MSVC 19.38 -> MinGW GCC 10 ...
| Fact          | OLDER                  | NEWER             | Status  | Basis
| Compiler      | Microsoft Visual C/C++ | MinGW (GCC 10)    | changed | Detect It Easy 3.21, signature
| Linker field  | 14.36                  | 2.38              | changed | PE header field
| Technical details [+]                                              [Copy details]
+------------------------------------------------------------------------------------+
```

**Model/view**
- `buildenv/view_model.py` (Qt-free): `BuildEnvViewModel{state, state_text, banners, rows <=128, summary, provenance, technical}`, `build_view`, `banner_views`, `provenance_block <= 8 KiB`.
- `ui_build_env.py`: `BuildFactModel(QAbstractTableModel)` (no proxy, fixed headers, order: changed, unknown, unchanged), `BuildEnvCard`, `PreflightBanner`, `BuildEnvController`. DiE runs on an unparented `TaskThread` held in a module registry until `finished`, with a generation counter; rows are published only in GUI-thread slots.
- Virtualization: the card is bounded (<= 128 rows). The overlay adds a precomputed `build_tag` to `UnifiedRowView`, so `data()` stays O(1) at 100k rows.

**Keyboard and accessibility**
- Tab order: card, table, buttons. Arrow keys in the table; Enter on a row focuses its line in Technical details; Ctrl+C copies the selected row; no new global shortcut.
- Accessible names: "Build environment", "Build environment facts for the older and newer file", "Build environment notice". Status text is announced through `ctx.announce` (GUI plan F6), not by `setText` on an empty accessible name. Glyph plus word, never colour only (`[!]` caution, `[i]` notice; ASCII only).
- Pure contrast test with `ui_evidence.contrast_ratio` (text >= 4.5:1; border and 2 px focus ring >= 3:1); row height from font metrics.
- Basis: Qt `QAccessible::Event::NameChanged` (reaches UIA only when focused) and `Alert` (a sound only, GUI plan F7), so announcements go through `ctx.announce`; WCAG 2.2 1.4.1, 1.4.3, 1.4.11, 4.1.3. Real screen-reader output is a manual gate (G-L4).

**States (exact copy; untrusted values pass `sanitize_text`)**
| id | trigger | text |
|---|---|---|
| B0 | no project | "Open a project to see the build environment." |
| B1 | reading | "Reading build environment: {side} ({done} of {total})..." |
| B2 | DiE not set up | "Detect It Easy is not set up. Showing the checks PatchTrace makes itself (headers, Rich header, sections, imports). Names of compilers, packers and protectors need Detect It Easy." |
| B3 | toolchain same | "No toolchain change detected between OLDER and NEWER. Compiler options such as the optimization level cannot be read from a file, so code can still differ without source edits." |
| B4 | toolchain differs | "Toolchain differs between OLDER and NEWER: {summary}. Some code differences can come from the build rather than from source edits. Matching rows are marked 'Build differs'; none are hidden." |
| B5 | unknown | "The toolchain could not be compared: {reason}. Unknown is not treated as a difference." |
| B6 | a side failed | "Build environment is incomplete for {side}: {reason}. The other side is shown." |
| B7 | stale evidence | "These build-environment results belong to a different file or tool setup and are shown for reference only." + [Read again] |
| B8 | error | "Build environment could not be read ({code}). Earlier results are unchanged." + [Retry] [Copy details] |
| B9 | blocked: unsupported DiE | "Detect It Easy {version} is not supported by this PatchTrace build (accepted: 3.21). Showing the checks PatchTrace makes itself." |

**Notice bar copy** (`{SIDE}` is OLDER or NEWER)
| code | text |
|---|---|
| packed (signature) | "[!] Caution: {SIDE} looks packed ({name}, matched by signature). Function-level results may be incomplete or misleading for this file. PatchTrace does not unpack files." |
| packed (hint) | "[!] Caution: {SIDE} may be packed (hint: {hint}). Hints from section layout or entropy can be wrong. Function-level results may be incomplete." (a low hint uses "[i] Notice:") |
| packed-one-side | "[!] Caution: only {SIDE} looks packed. Comparing a packed file with an unpacked one does not show source changes." |
| protected | "[!] Caution: {SIDE} shows signs of a protector or obfuscator ({name}, matched by signature). Results may be incomplete or misleading." |
| managed | "[!] Caution: {SIDE} is a .NET assembly with managed code only. PatchTrace compares native x64 code, so function results will be empty or misleading." |
| managed (mixed) | "[i] Notice: {SIDE} is a .NET image that also holds native code. Only the native part is compared." |
| installer | "[i] Notice: {SIDE} looks like an installer or self-extracting archive ({name}). The program code may be inside its payload, which is not analyzed." |
| overlay-large | "[i] Notice: {SIDE} has {size} of data after its last section. That data is not analyzed." |
| toolchain | "[i] Notice: the toolchain differs between OLDER and NEWER ({short}). Some code differences may come from the build, not from source edits." |
| tool-unavailable | "[i] Notice: Detect It Easy is not set up, so only PatchTrace's own checks ran." |
| heuristic-only | "[i] Notice: {n} weak hints on {SIDE} were found and are not used as evidence." |

Row chip detail: "This row's change classes ({classes}) can appear without a source edit when the toolchain differs. Context only: the verdict is unchanged and the row is not hidden."

**Teach hooks** (`teach_id`, consumed by the E-5 guide; text in `buildenv/copy.py`)
| id | meaning | next steps |
|---|---|---|
| `build_env.toolchain_differs` | "Code can differ because the build tools differ." | "Read rows marked Material first." "Open the Build environment card to see what changed." "If a pair built with the same toolchain exists, compare that pair too." |
| `build_env.packed` | "A packed file stores its code in compressed or encrypted form." | "Treat function results as incomplete." "Look for unpacked builds of the same file; PatchTrace never runs or unpacks it." |
| `build_env.managed` | "A .NET assembly holds intermediate language, not native code." | "Use a .NET-aware tool for the managed part." "Native results cover only the native part." |
| `build_env.installer` | "An installer carries the program in a payload." | "Compare the installed files instead of the installer." |
| `build_env.unknown` | "No toolchain information could be read for one side." | "Set up Detect It Easy for names." "Unknown is not a difference." |
| `build_env.tool_missing` | "Names of compilers and packers come from Detect It Easy." | "Open Setup and choose the console program." |

**Tooltips** (registry ids, each with What, Why, Effect, Source, Availability, no angle brackets; entries in `PANEL.tips` (GUI plan F5; no `tooltips.py` line): `build_env.card`, `.status`, `.table`, `.banner`, `.banner_details`, `.banner_dismiss`, `.setup`, `.read_die`, `.weak_hints`, `.copy`, `.technical`, `.reread`, `.group_last`, `.timeline`; templates `build_env.row`, `build_env.tag`, `build_env.timeline_cell`; `unified.build_section`. A prefix-completeness test mirrors `test_evidence_ids_prefix_complete`.
- `build_env.card`. What: "Compiler, linker, runtime and packaging signs read from the older and newer file." Why: "A different toolchain can change code without any source edit, and a packed file can make function results unreliable." Effect: "Read-only. Nothing is run from the files and nothing is sent anywhere." Source: "PatchTrace header checks on the hash-checked project copies and, if set up, stored Detect It Easy 3.21 results." Availability: "Needs an open project; names of compilers and packers need Detect It Easy."
- `build_env.tag` (template). What: "Marks a change row whose change classes ({classes}) can appear without a source edit when the toolchain differs." Effect: "Read-only. The row stays listed and its verdict is unchanged." Availability: "Shown only when the toolchain is reported as different on both sides."
- `build_env.setup`. Effect: "Probe runs only the program's version and help text, never your files. No download happens."

**Qt/PySide6 pitfalls:** join or retain every `QThread` (destroying a running one aborts); untrusted text only in `PlainLabel`; no fixed accessible name on the status label; construct every control eagerly so the tooltip enumeration finds it (`test_every_registry_id_is_applied_somewhere` needs the dialog among its roots); queued connections to bound methods; word-wrapped labels need minimum-width checks (the Engines-page regression); persist rows only on the GUI thread; read QSettings in try/except.

**Offscreen tests:** one per state B0-B9, each notice variant, dismiss scope, tooltip audit, accessible names, contrast, thread join, 20x repeat with `PYTHONFAULTHANDLER=1`.

**Budget:** card first paint <= 100 ms after data; PE facts add <= 100 KiB of reads and <= 2 s; overlay <= 50 ms at 100k rows (5x slack); DiE <= 120 s (timeout), typical <= 1 s [unverified for real files].

**Timeline** (`buildenv/timeline.py`, pure): builds `TimelineView{builds (BuildRef + label), rows per fact family (toolchain, runtime, packing, managed, options), cells {value, unknown, not-run}, change_after}` from per-pair `build-env` rows read through an optional `BuildEnvReader` port added to `PairSnapshot`. Non-adjacent builds are never compared. A tool-version change between columns shows "tool versions differ" instead of a comparison. A hop with a toolchain change gets a "Build differs" note beside its attention score; the score is untouched.

**Report** (`buildenv/report.py`): a validated section in JSON, Markdown and HTML text with findings, notices and provenance (versions, database label and digest) and the disclaimer "Names come from signatures and header fields; they are not proof of how a file was built". It goes through the existing redaction and escaping (`_clean`, `_markdown_escape`).

## 9. Slice plan
| slice | scope | exclusive files | depends | tier (reason) | size | acceptance gate | fallback |
|---|---|---|---|---|---|---|---|
| D1 | diec adapter hardening (section 7 list) | `intelligence/tools/diec.py`; the `EnvCategory`/`EnvironmentEvidence` hunk of `common.py`; the `process.execute` hunk; `tests/test_diec_adapter_hardening.py`; `tests/fixtures/intel_tools/diec/{nested-overlay,empty-result,vocabulary}.json` (hand-authored from the upstream writer, labelled "not captured") | none (before any stored row) | Sonnet (strict parsing, moderate) | M | the red tests of section 6 turn green; existing `test_intel_tools_*` green; ruff; full suite twice | flatten and category fixes only |
| D2 | PE build facts: Rich (stdlib, bounded), header versions, debug entry types, LoadConfig fields, CLR header, runtime families | new `pe_overview/{rich_header,build_facts,clr_header,debug_entries}.py`; `tests/pe_build_fixtures.py`; `tests/test_pe_build_facts.py` (pefile 2024.8.26 pinned in the dev extra as oracle; optional runtime cross-check) | none | Sonnet (binary parsing) | M | oracle equality on generated headers; hypothesis never-raise; limit tests; zero edits to existing `pe_overview` files | ship Rich and header fields only |
| D3 | `buildenv` core: contracts, fingerprint, delta, pre-flight, `noise_map`, anchors, copy, view model, schemas | `buildenv/{contracts,fingerprint,delta,preflight,noise_map,anchors,adapters,copy,view_model}.py`; `tools/generate_buildenv_schemas.py`; `docs/schemas/build-environment/*`; `tests/test_buildenv_*.py`; `tests/fixtures/buildenv/*` | D1 and D2 types (stubs allowed) | Sonnet (pure, spec-driven) | L | synergy test, delta and pre-flight tests, schema drift, banned-word sweep, `quality_flags` parity | defer anchors and teach hooks |
| D4 | store, CLI, report, inspection seam | `buildenv/{store,cli,report}.py`; seams: `cli_commands/build_env.py` (adapter, no `cli.py` edit), `KINDS`, `reports.py` extras, `artifact_inspection.py` side inspector | D3 | Sonnet | M | CLI exit-code tests; store round trip with `test_old_reader_ignores_build_env_kind`; report injection fixtures | CLI and JSON only |
| D5 | GUI card, notice bar, controller, tooltips | `ui_build_env.py`; `PANEL.tips` (replaces `tooltips_buildenv.py`); `tests/test_ui_build_env.py`; no `ui.py` seam (GUI plan F5) | D3 | Sonnet | L | states B0-B9, tooltip audit, contrast, thread tests, 20x repeat without abort | card only, no workspace bar |
| D6 | overlay (pure now) and wiring later | `buildenv/overlay.py`; `tests/test_buildenv_overlay.py`; wiring in `unified/read_model.py` and `ui_unified.py` by the UE S4 owner | D3 (pure part); S4 (wiring) | Sonnet | M | overlay tests including 100k rows; S4 adds `build_tag` and the partition | navigator notice only |
| D7 | series timeline | `buildenv/timeline.py`; `ui_build_timeline.py`; seams in `nway/pair_access.py`, `nway/view_model.py`, `ui_series.py` (recorded exception until M3; `area='none'` until the strip moves into the `series` dock) | D4 | Haiku to Sonnet (glue) | M | pure timeline tests; offscreen strip test | CLI and report only |
| D8 | live acceptance | `tests/test_live_buildenv.py`; one job in the T live workflow | T runner and provisioning | Sonnet | S | passed/failed/blocked status JSON; goldens captured | stays BLOCKED |
| D9 | value gate G-DIE-1 | `tools/buildenv_value_gate.py` over Tier R M4 pairs | D6, UE S2/S3, known-answer factory | Sonnet (counts only) | M | report with tag coverage and leakage | publish raw counts only |
| D10 | stretch: explain F10 edit groups by compiler-support callees (`__CheckForDebuggerJustMyCode` documented; GS and CFG helper names measured first) | `buildenv/support_callees.py` | D6, UE S3/S4 | Sonnet | S | names measured on Tier R builds | not built |

Order: D1 and D2 in parallel, then D3, then D4/D5/D6 in parallel, then D7, then D8/D9; D10 last. D1 owns its `common.py` and `process.py` hunks until merged; CAP and WB3 builders must not edit those hunks meanwhile. Shared prerequisite not in this plan (needed by CAP, WB3 and DIE): the T runner, store, `intel-tools` CLI and provisioning (T-spec T7-T9, "next wave"). D1-D7 use stored-row fakes until it lands. Escalate to Opus only for a demonstrated blocker (CLAUDE.md).

## 10. Amendments required, test and QA plan
| file, section | change |
|---|---|
| T-spec T2, T5.1, T6.4, T10 | `EnvironmentEvidence.raw_type` and the new categories; nested and empty JSON shapes; shared type sets; separate `installer` flag; pointer to this plan for gate G-DIE-1 |
| `unified-engine/10-amendments.md` A-23 | replace "no change" by: DiE and PE facts are build-fact providers to the read model through a port, not source atoms; `result_key` and `config_digest` unchanged |
| `unified-engine/05-fusion-and-noise.md` s3, s2.6 | add F19 "build-environment tag: view only, `noise-map/1`, never `material` or `contested`, never hides"; ordering: stable partition inside the materiality group |
| `unified-engine/07-ui-and-cli.md` s3, s4, s7, s8 | `UnifiedRowView.build_tag` and `build_reason`, sort-key extension, filter checkbox, ids `unified.build_section` and `unified.build_tag` |
| `docs/specs/pe-overview.md` | new "Build facts" section (fields, limits, Rich semantics, "undocumented by Microsoft"); update "Not done" (CLR header basics now read) |
| `docs/specs/gui-preflight-inspection.md` D | card and notice bar inside Preliminary file comparison |
| `docs/specs/nway.md` / SPEC-09b s5 | timeline strip and optional `PairSnapshot.build_env` |
| `enrichment/storage.py` `KINDS`; `docs/specs/enrichment.md` s10 | add `'build-env'` (one line; merge-prone, coordinate with KB, KEV, YRX) |
| `artifact_inspection.py`, `ui_inspection.py` | one shared additive side-inspector seam (`SideInspection.extras`) used by DIE and WBQ; the first builder to land adds it, the other rebases |
| `cli_commands/build_env.py`, `reports.py`, `ui.py`, `tooltips.py`, `tools/frozen_smoke.py` | adapter file <= 25 lines (no `cli.py` hook); `extras` parameter; seam <= 12 lines; one merge line; import of the `patchtrace.buildenv` modules |
| `docs/specs/known-answer-corpus.md` s9, s10 | the M4 evaluation reports build-environment tag coverage and leakage (G-DIE-1) |
| `.gitattributes`, `docs/modules.md`, `docs/notices.md`, `docs/reuse-matrix.md`, `tasks/todo.md`, `docs/qa.md` | `tests/fixtures/buildenv/** text eol=lf`; module rows; DiE MIT, pefile MIT (test-only), LLVM constant names (Apache-2.0 WITH LLVM-exception, facts only); ledger and QA rows |

**Tests and fixtures**
- Synthetic PEs only: reuse the `tests/test_intel_tools_pe.py` builder (Rich variants, lld-style header, hand-built COR20 header, UPX-like sections). No Microsoft binary, PDB or Winbindex label is committed.
- Goldens: the existing real diec JSON, plus the nested-part, empty-result and vocabulary files labelled "derived from the upstream writer" until the live gate replaces them.
- Properties (hypothesis): random header bytes never raise; the Rich parse equals pefile on generated headers; swapping orientation inverts every `BuildChange`; unknown never yields `differs`; the delta is idempotent; overlay output is a pure function of its inputs; tagged rows are a subset of qualifying rows.
- Windows checklist: CRLF (`.gitattributes` line above), short explicit parametrize ids for the 57 type names, `>=` for monotonic clocks, no YAML, `--only-binary=:all:` with no new runtime dependency (pefile only in the dev extra), hermetic tests, scratch path <= 200 characters, `diec.exe` loads its own Qt 5 DLLs because the child `PATH` starts with its folder.

**Live and manual gates (never counted as done by automation)**
- G-L1 Linux required leg: real `diec` 3.21 on Tier R `msvc-free`, `mingw-gcc`, `mingw-clang` images at -O0 and -O2: capture goldens, confirm the nested and empty-result shapes, run under `unshare -rn` and the memory cap, record the lld-style fingerprint.
- G-L2 Windows advisory leg: zip extraction, `diec.exe --version`, the same images, a blocked-network run for the Wintrust question, antivirus and VC runtime behaviour.
- G-L3 owner machine: `build-env show` and `delta` on real servicing pairs (counts only; binaries never leave the machine).
- G-L4 manual: NVDA and Narrator announcement of status and banner, 125/150/200% DPI, keyboard-only walk.
- **G-DIE-1 (value gate, T6.4):** on Tier R M4 pairs report tag coverage of truth-`same` and truth-`cosmetic` functions the engine flags, leakage onto truth-`changed` functions (target 0 for semantic classes), and zero tags on A/A and -O0-vs-O2 pairs. Targets are [inf] proposals to preregister. No false-lead-reduction claim until it is reported.

## 11. Open questions (defaults; never blocking)
1. pefile as a runtime dependency? Default: no. The stdlib parser is authoritative; pefile is the test oracle in the dev extra and an optional runtime cross-check when it is importable (revisit when WBQ ships it).
2. Add `-b` (verbose) to the argv? Some linker lines may appear only then [unverified]. Default: no in v1; evaluate in G-L1; adoption bumps argv to `diec/2`.
3. Bundle DiE in the installer? Default: no (unreviewed rules, PEiD-derived data without licence text, LGPL Qt); later a consented, pinned download.
4. Auto-run DiE when configured? Default: off (`buildenv/auto_diec`) until G-DIE-1.
5. Confirm-before-run on a caution notice (`buildenv/confirm_before_run`)? Default: off; notice bar only.
6. Where does the diec setup row live? Default: the shared external-tools setup panel; fallback one row in Setup.
7. "Group build-tagged rows last" default? Default: off; only the eight shape-only classes use effect `order`.
8. `.NET` severity? Default: IL-only caution, mixed or ReadyToRun notice.
9. Timeline in the Series window now, or report and CLI first? Default: strip behind the seam; fallback report and CLI.
10. Treat the Linux and Windows 3.21 database digests as one label? Default: show one label from `KNOWN_DATABASES` and keep evidence non-comparable across executables (T6.1).
