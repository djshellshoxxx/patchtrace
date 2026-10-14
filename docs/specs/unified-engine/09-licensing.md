# SPEC-31 / 09 Licensing: per technique source, licence, reuse method, notices

PatchTrace is MIT (`LICENSE`). Not legal advice; U-01 asks for a review before the first release that ships ported code. Licence facts come from the research notes, which read the primary LICENSE/SPDX files: BinDiff and BinExport Apache-2.0 (`LICENSE` 11,358 bytes, no NOTICE file at `v8`, R02 s12; binexport2-support.md s1), Ghidra Apache-2.0 (R03 s6), ghidriff GPL-3.0 (`LICENSE`, `setup.cfg`, PyPI, R03 s6), rizin LGPL-3.0-only per-file SPDX with GPL-2.0-or-later ISA plugins (`REUSE.toml`, R03 s6), QBinDiff Apache-2.0 (`LICENSE`, R05 S5), Diaphora AGPL-3.0 (R02 s13, R04 s9), PatchDiff2 GPL-2.0 and Turbodiff GPL-3.0 (R04 s2), DarunGrim BSD-style, binkit no licence file found (R04 s9), angr BSD-2, LLVM Apache-2.0 WITH LLVM-exception, System Informer MIT (R04 s9), capstone BSD (R05 s10). No new licence check was performed by this author (gap recorded for the reviewer: QBinDiff and binkit SHAs were not pinned).

## 1. Reuse methods
- **Port with attribution**: we derive code from reading Apache-2.0 source. Obligations (Apache-2.0 s4): ship the licence text, keep a prominent "modified" notice in each derived file, keep copyright attribution; s6: no trademark use ("BinDiff-style", never "BinDiff engine"); s3 patent grant covers the Work as distributed by the licensor [inf; no patent review done].
- **Clean-room**: implemented from documentation, papers or observed behaviour only; no source of that project open while writing.
- **Runtime use**: we call a tool's API or CLI in a separate, user-installed process; nothing of it is distributed by PatchTrace.
- **Ideas only**: concepts named in research notes; neither code, SQL, tables nor thresholds copied; our own thresholds come from our evaluation (08).

## 2. Per technique

| Technique (SPEC-31 place) | Origin | Licence | Method | Notice action |
|---|---|---|---|---|
| MD index formula, BFS levels, parity quirks (`ir/mdindex.py`) | google/bindiff v8 `graph_util.h`, `flow_graph.cc`, `call_graph.cc` | Apache-2.0 | port with attribution | header "Portions derived from google/bindiff v8 (Apache-2.0); modified for PatchTrace"; `third_party/notices/bindiff-v8/{LICENSE, PROVENANCE.txt}` |
| drill-down step semantics, step order, strongest-first uniqueness (`ladder/engine.py`, `ladder/passes.py`) | bindiff `differ.cc`, `match/call_graph.cc`, `bindiff.json`; also Flake DIMVA 2004, Dullien-Rolles SSTIC 2005 | Apache-2.0 + papers | port with attribution | same files list in PROVENANCE |
| call-reference matching subsumed by implied matches (`ladder/propagate.py`) | bindiff `call_graph` matching; Ghidra VT implied matches | Apache-2.0 | port (BinDiff part) + clean-room (VT part) | as above |
| mnemonic multiset key (exact, not the 12.5k prime table) | idea of BinDiff prime signature, D&R 2005 | Apache-2.0 idea / paper | clean-room (own exact multiset hash); the prime table is NOT copied (R02 s12) | none |
| Ghidra ExactBytes / ExactInstructions / ExactMnemonics hashers (optional parity fields), SLEIGH masks, BasicBlockModel, decompiler | Ghidra `Features/Base/.../plugin/match`, SLEIGH | Apache-2.0 | runtime use in the external process (03 s4) | none distributed; Ghidra stays user-installed (docs/notices.md row exists) |
| VT reference-vector weights `sqrt(-ln p)`, cosine, confidence x10, refine rules (P16); implied matches >= 2 votes / 0 conflicts (L-19) | Ghidra VT help `VT_Correlators.html`, `VT_AutoVT.html` | Apache-2.0 docs | clean-room from the help text (D-22) | none |
| masked-byte levels L1-L3, operand classes (`ir/ingest.py`, `facts/operands.py`) | R04 s5 checklist (Ghidra FID/VT, PatchDiff2, binkit ideas) | mixed | clean-room; own code | none |
| `.pdata` / base-relocation parsing (`ir/pe_tables.py`) | Microsoft PE format (public specification) | n/a | own stdlib code | none |
| rarity gates, constant filter idea, tier ceilings (L-14..L-16) | Diaphora | AGPL-3.0 | ideas only; thresholds are ours | none |
| residual assignment with reject cost and margin (P19) | QBinDiff LAP over unassigned nodes; BinSlayer Hungarian | Apache-2.0 / paper | clean-room (own Jonker-Volgenant); no QBinDiff code or dependency | none |
| BB-first voting (P17) | DarunGrim/binkit | BSD-style / none | ideas only | none |
| change-classification taxonomy | BinDiff `change_classifier.cc` (Apache-2.0), Turbodiff tiers (GPL-3.0) | mixed | ideas only (our classes differ) | none |
| canonical pseudo-code (C6) | R05 R7 (own design; Ghidriff normaliser read for behaviour only) | GPL-3.0 behaviour knowledge | clean-room; no ghidriff code | none |
| Ghidriff itself | clearbluejar/ghidriff | GPL-3.0 | runtime use (external process, unchanged) | existing docs/notices.md row |
| rz-diff / rizin | rizinorg/rizin | LGPL-3.0-only (+ GPL-2.0+ plugins) | runtime use (external process); never link `librz` | existing SPEC-11 notes |
| BinDiff CLI (oracle) | google/bindiff | Apache-2.0 | runtime use (SPEC-29); never bundled | existing |
| Diaphora results | joxeankoret/diaphora | AGPL-3.0 | data import of user-produced files only (DA-01) | DA-01 owns it |
| Windows ABI facts (RTTI, XFG, DVRT) for later slices | LLVM, System Informer, angr | Apache-2.0-LLVM / MIT / BSD-2 | facts only (not used in v1) | none |
| capstone, pyvex/angr, z3, torch | - | BSD / GPL(libVEX) / MIT / BSD | not used (no new dependency, D-20; pyvex excluded by licence, R05 s6) | none |

## 3. Notices and build
1. Add `third_party/notices/bindiff-v8/LICENSE` (Apache-2.0 text copied from `google/bindiff` at tag `v8`) and `PROVENANCE.txt` (URL, tag, commit SHA, list of files consulted, date, "modified: algorithms re-expressed in Python"). Add the directory to the `required` notice list of `tools/build_windows.py` and `tools/build_linux.py` (they already copy `third_party/notices` and refuse to publish when a required notice is missing, build_windows.py:49-50).
2. Add one row to `docs/notices.md` ("BinDiff-derived algorithms, Apache-2.0, bundled as source-derived Python modules") and to `docs/reuse-matrix.md`.
3. Test `test_ported_modules_carry_attribution_header` (scans the module list of s2 for the header) and `test_notice_directory_listed_in_build_required`.
4. GPL/AGPL guard: `test_no_gpl_sources_vendored` extends the existing corpus guard idea: fails on any file under `src/` whose header names ghidriff, Diaphora, PatchDiff2 or Turbodiff as origin.

## 4. Data and corpus licences
Tier R recipes reference zlib (Zlib), libpng (libpng licence), SQLite (public domain), Lua (MIT), mbedTLS (Apache-2.0 or GPL-2.0-or-later dual) at pinned tags; only recipes and expected SHA-256 live in the repository, binaries only as CI artifacts. Microsoft binaries, PDBs and Tier W labels stay local (spec-decisions O1, USER). Licences of BinKit, BinaryCorp, REFuSe-Bench, Assemblage and Winbindex remain UNCONFIRMED (calibration spec s15): do not use until read.
