# Additional engine/runtime reuse research for Claude

Research date: **2026-11-03 America/Vancouver (2026-11-04 UTC)**. Repository baseline: `main` / `b77d84e5decf736b031f0a24094001274de41178`. This is a source-inspected integration note, **not implemented runtime support or a native acceptance result**. No target binaries were executed, imported into analysis tools, or transmitted; only public source/documentation was retrieved. Recommendations are labeled **[recommendation]**, source observations **[verified]**, and behavior requiring experiments **[untested]**.

## 1. Decision and relationship to existing work

The highest-value reuse is upstream **lifecycle APIs, export schema knowledge, independent static-parser oracles, and report-tree concepts**. PatchTrace already has supervised subprocesses, immutable artifacts, strict parsers, private work directories and source adapters. Replacing those with another engine's convenience wrapper would lose project-specific guarantees. Complete qualification around the existing seams first.

Read before implementation: `AGENTS.md`, `CLAUDE.md`, `docs/modules.md`, SPEC-31 chapters 03/06/09, `docs/specs/runtime-discovery.md`, `docs/specs/binexport2-support.md`, `docs/specs/bindiff-adapter.md`. Relevant prior research includes `docs/research/unified-engine/{02-bindiff,03-ghidriff-rizin}.md`, `docs/research/phase-c/{bindiff-automation,binexport2-hostile-input}.md`, and `docs/research/ue-open-questions.md`. The older phase-C C17 uncertainty about Ghidra's executable hash was already answered by unified-engine R02; the source inspection below re-verifies it rather than claiming a discovery.

Also inspected without checking out: R2 `07-native-rizin-findings.md`, R3 `methods-and-tools.md`, and R8 `03-integration-handoff-and-release-risk.md` on their research refs. Their orientation, semantic-proof and alias uncertainty findings remain controlling context. This note adds runtime/export/report qualification rather than repeating matching algorithms or suggesting new semantic equivalence claims.

Active ownership observed in local refs after the coordinator's fetch:

| Work | Observed head | Consequence for Claude |
|---|---|---|
| PR174, `origin/claude/ws-bc-20261104` | `b1411fb57774233ef909fabf4afab34ab4b67dff` | Already owns native Rizin producer/red controls and Java probe retry. Coordinate; do not reimplement its C patch or reinterpret tests as acceptance. |
| PR176, `origin/claude/ws-p-20261104` | `db0a0b05d48e4c8fb394ec4e221677b5efb37954` | Owns investigation/replay and report boundaries. New report adapters must preserve its project/revision ownership. |
| PR173 tracker repair | Coordinator-owned | `tasks/todo.md` is corrupt UTF-8 at this baseline. Supply proposed tasks in this note; do not repair or overwrite that tracker. |
| Integration PRs163–168 | See PR174 handoff ancestry | Native producer qualification is an existing gate. Draft/open state and local head are observations, not evidence of green CI or successful native runs. |

## 2. Shortlist, revisions and reuse decisions

| Candidate | Inspected revision / license evidence | Decision and practical value |
|---|---|---|
| Ghidra/PyGhidra | Ghidra `12.0.4`, commit `e40ed13014025f82488b1f8f7bca566894ac376b`; Apache-2.0 source headers and root license [E1], [E2], [E3], [E4] | **Adapt** documented lifecycle/monitor usage; keep current isolated child. |
| JPype | Current official guide; exact guide build unpinned [E5] | **Reference** JVM lifecycle constraints; no additional wrapper dependency. |
| BinExport Ghidra builder/schema | Commit `9648cacb21a71aa6c21b3fca504f146c39164a53`; Apache-2.0 plus bundled notices [E6], [E7], [E8], [E9] | **Adapt** producer qualification and schema interpretation. Keep hardened C3 parsing. |
| Rizin | `0.9.1`, commit `c3a90e9226d977f58f4e9c75f78fa6b07afe13c7`; inspected files LGPL-3.0-only [E10], [E11] | **Defer acceptance** until existing producer gates pass. Version alone is inadequate. |
| diffoscope, Debian/Salsa project | Debian source `297+deb13u1`; GPL-3+ with per-file exceptions [E12], [E13], [E14], [E15] | **Reference**, optionally **adapt** an offline report importer later. Do not copy its subprocess wrapper. |
| LLVM Object Reader | `llvmorg-20.1.8`; Apache-2.0 WITH LLVM-exception [E16], [E17], [E18], [E19] | **Adopt for developer experiments** as a second parser oracle, not a new mandatory desktop runtime. |
| Sourceware libabigail | Live official manual/homepage; exact installed release **unknown**, no executable obtained [E20], [E21], [E22] | **Reference** status and coverage contracts; **defer** ELF ABI tooling because current scope is PE AMD64. |

Licenses apply to particular source/files, build outputs and dependencies. Reading external JSON is different from copying a parser; launching a separate executable does not automatically remove distribution or combined-work obligations. A patched redistributed Rizin build needs its own complete license/source review. BinExport's root license contains additional component notices; LLVM and libabigail exceptions must travel with applicable reused code. No copying authorization or legal conclusion is inferred merely from an SPDX label. [E4], [E9], [E10], [E11], [E12], [E19], [E22]

## 3. PyGhidra: qualify the existing worker rather than adopting another launcher

**[verified]** The pinned PyGhidra README and `core.py` deprecate `open_program()` and `run_script()` in favor of explicit project/program APIs. `program_context()` releases its consumer in `finally`; `transaction()` commits only successful bodies and closes the transaction in `finally`. `analyze()` acquires/releases the Ghidra script bundle host around `AutoAnalysisManager`. The launcher exposes VM arguments before startup. These are source-level API observations at the pinned Ghidra commit, not claims about every separately installed PyGhidra package. [E1], [E2], [E3]

PatchTrace already follows much of this model in `src/patchtrace/unified/extract/ghidra_script.py`: explicit `HeadlessPyGhidraLauncher`, `add_vmargs(-Xmx...)`, private `GhidraProject`, `pyghidra.analyze(program)`, `project.close()` in `finally`, and decompiler disposal. `unified/extract/runner.py` uses one external child per side, separate output limits, deadlines and cleanup. Consequently, introducing `open_program()` from an online example is a regression in API direction, not useful reuse.

**[verified]** JPype's official guide documents that a stopped JVM cannot be restarted in the same process, and that multiple JVMs in one process are unsupported by its current implementation. **[recommendation]** Preserve PatchTrace's child-process boundary for retries, cancellation and runtime switching. A persistent in-process Qt/JVM integration would need separate design and memory/teardown evidence; it is not justified by reduced startup cost alone. [E5]

A subtle acceptance distinction deserves a test: **[verified]** the pinned `api.py::analyze` calls `startAnalysis(monitor, True)` and subsequently `markProgramAnalyzed(program)` without a separate cancellation-refusal condition around that marking. This source inspection does **not** establish that any particular cancelled PatchTrace run produces an accepted GZF. It shows that the analyzed flag is not, by itself, a completion receipt. [E2]

**[recommendation]** For `gzf`/`decompile`, retain the current artifact SHA check and require provenance from the originating completed run: GZF digest, producer versions, extractor script, symbol policy and analysis options. Keep the process outcome independent of a project flag. If cancellation or timeout wins publication, preserve diagnostic artifacts as incomplete and publish no usable IR. Passing a cooperative monitor could improve cancellation latency, but the parent timeout/tree termination remains the authority. Changes to public provenance must start in SPEC-31 chapter 03, not in Qt.

**[untested] Acceptance experiments:** on a qualified Ghidra environment, run synthetic A/A imports, then cancel during import, analysis, GZF writing and decompilation. Verify no completed IR/cache result survives cancellation; a failed child cannot publish merely because a GZF is readable/analyzed. Open and close one program repeatedly in separate children, retain source hashes, measure process/Java child exit and Windows cleanup. Test a deliberately mismatched external PyGhidra install with the same Ghidra directory: the current `_self_check`/class probes should return typed unsupported status, not silent fallback. Metadata discovery remains distinct from native readiness.

## 4. BinExport/BinDiff: useful reuse is producer semantics and reproducibility checks

**[verified]** At E6, `buildMetaInformation()` writes `program.getExecutableSHA256()`, language-derived architecture and a wall-clock timestamp. `getMappedAddress()` subtracts an explicit offset. `buildInstructions()` emits both calls and jumps to known function entries in `call_target`. `build()` invokes `promoteUndefinedFunctions()`, which can create functions, before generating flow/call graphs. External functions are mapped to linkage addresses; unresolved linkage is skipped. [E6]

These observations have three concrete consequences **[recommendation]**:

1. **Raw-file identity and semantic replay identity serve different purposes.** Two exports from unchanged analyzed input can differ in timestamp. Preserve the actual raw digest as evidence; do not overwrite it with a normalized digest. A separate, versioned structural comparison used only by a replay test may disregard a documented volatile field. Specify the transformation and retain both originals.
2. **Export is potentially mutating.** Run it against a private imported/cloned program, never an analyst's authoritative retained GZF/project. Compare function inventories before/after export, recording promotions and skipped imports. Same Ghidra installation does not imply that Ghidriff, PatchTrace IR and BinExport used identical function boundaries.
3. **Edge kinds are producer-limited.** BinExport `call_target` alone cannot distinguish all source call/jump kinds. Preserve the limitation already recognized by `callgraph/source_binexport.py`; never reinterpret every exported target as a normal call or count it as independent Ghidra evidence.

The Java README at the inspected commit still describes Ghidra 11.0.3, JDK 21 and Gradle 8.7 build requirements. **[verified]** This is the README's stated build recipe; it is not a demonstrated compatibility matrix for PatchTrace's Ghidra 12.0.4. **[untested]** Build the extension against the actual selected installation and qualify its archive/JAR, rather than claiming compatibility from the repository's main branch. [E7]

Integration remains `secondary/binexport_{prescan,check,identity,snapshot,pipeline,worker,producer}.py` and `secondary/bindiff_{probe,inputs,run}.py`. If implementing SPEC-31's planned `ir-export` worker mode, translate only inside the existing bounded worker after the C3 structural checks. Preserve producer kind/version; no SLEIGH operand-mask claim may be inferred from a valid protobuf. Do not substitute a general Python BinExport reader for the hostile-input acceptance boundary.

**[untested] Acceptance experiments:** same private GZF exported twice with raw hashes retained; image-base subtraction on/off; imported/thunk functions with and without linkage; an undefined basic block eligible for promotion; reversed pair inputs; missing or mismatched executable hash; cancellation mid-export. Require stable *declared* structural fields, complete inventory accounting, explicit edge limitations, and no cross-exporter feature pooling. Follow with real BinDiff output on independently authored pairs using the existing `tests/test_live_bindiff.py` seam. Synthetic proto acceptance is not extension compatibility evidence.

This supplements rather than replaces old R02's BinDiff algorithm analysis. Its important new integration question is whether the producer snapshot used by a match really equals the snapshot assumed by the rest of the run.

## 5. Rizin: version compatibility needs a qualified producer receipt

**[verified]** Independent reading of the pinned upstream `similarity.c` confirms the singleton branch reverses the list arguments passed to its helper. The CLI serializes the resulting pair fields into `original`/`modified`. This corroborates R2's already documented conditional orientation finding; it is not a new native reproduction. [E10], [E11]

At the baseline, `secondary/rzdiff.py::probe` accepts recognizable versions >=0.9.0 and reduces the version to numeric major/minor/patch. This establishes CLI availability only. It cannot distinguish stock 0.9.1, a local patched 0.9.1 or differently packaged libraries. Existing active producer work correctly separates C-wrapper/list-double tests, native API tests and production JSON acceptance.

**[recommendation]** Feed PR174's producer qualification, not a generic semver check, into the engine's eventual acceptance receipt. A receipt should bind the resolved executable digest, relevant dynamic-library identities or a build manifest, source/patch identity, exact adapter options, per-side input hashes, inventory witness and native qualification result. Define its schema and cache treatment before implementation. Changing only a suffix or CLI banner must not unlock trusted matching, navigation, calibration or cached rows.

The current active handoffs explicitly say their native matrix and all-equal-NOP controls are insufficient for production JSON acceptance. **[recommendation]** Preserve that boundary: qualify distinct-byte and distinct-IO-context fixtures in 1:1, 1:N, N:1, N:N and zero-function cases, both input directions, with overlapping address/name controls and unmatched partitions. A crash or missing output must not count as expected stock-red. No JSON-row count or Ghidra/export count can stand in for the exact recovered Rizin list that controls its branch.

The public matching/CLI files carry LGPL-3.0-only headers, while a full tool build includes more components. **[recommendation]** Keep source modifications outside PatchTrace until upstream/package distribution obligations and component notices are reviewed; separate-process invocation is an engineering boundary, not a blanket licensing exemption. [E10], [E11]

## 6. diffoscope: a substantive non-GitHub report-format reference

The Debian/Salsa project's actual packaged sources were retrieved from **Debian Sources**, not a GitHub mirror. **[verified]** In 297+deb13u1, `presenters/json.py` emits `diffoscope-json-version:1` and recursive nodes containing `source1`, `source2`, optional `comments`, `unified_diff` and `details`; `difference.py` treats comments and nested details as meaningful even when a unified diff is absent. It also supports reversed report trees. [E12], [E13]

**[recommendation]** This is a useful model for PatchTrace's artifact/PE/report comparisons: a section can communicate “unavailable,” “tool missing,” “truncated,” or “different metadata” without inventing line hunks or forcing a function match. A future importer should map it to a **display-only report tree**, never directly to `Atom`s, match confidence or semantic verdicts. An absent hunk is not an equality proof. Reject unsupported format versions, cap recursive depth/nodes/text, and escape labels/comments through existing `reports.py` rendering. Bind the imported raw report to the ordered artifact hashes and tool receipt outside the format; source labels are not authenticated file identities.

There is also a concrete non-reuse finding. **[verified]** `comparators/utils/command.py` uses `subprocess.run` with captured stdout/stderr and inherited environment by default; its base call does not supply PatchTrace's tree-cancellation, parent time/memory/output guard or environment contract. Limiting stderr display lines occurs after collection. **[recommendation]** Do not copy this wrapper into `jobs.py`; the inspected code is useful as contrast for qualification, not a superior runtime. [E14]

The JSON presenter and command wrapper are GPL-3+; Debian's machine-readable copyright identifies file-level exceptions and separately licensed fixtures. **[recommendation]** Read the format and implement PatchTrace's small domain model independently, or review copyleft compatibility before copying code. Do not import the entire recursive comparator/plugin dependency graph for one report view. [E12], [E14], [E15]

**[untested] Acceptance experiments:** import a version 1 tree with comments-only nodes, empty-vs-null hunks, asymmetric sources, Unicode/control text, excessive depth and swapped orientation. Round-trip the PatchTrace representation with unchanged raw bytes. Display failure/truncation prominently. Scope a possible experiment to `reports.py`, `models.py` and a new pure importer registered in `docs/modules.md`; coordinate destination/replay ownership with PR176. No required production module is proposed here.

## 7. LLVM Object Reader and libabigail: reuse independent observations, not a replacement matcher

**[verified]** LLVM 20.1.8 `llvm-readobj.cpp` chooses a shared `JSONScopedPrinter` when JSON style is selected, while dispatching COFF objects to `COFFDumper`. `COFFDumper.cpp` contains dedicated imports, exports, base-relocation, debug-directory, TLS, resource and load-config readers. The public option is named `--elf-output-style=JSON`; this awkward name should not be generalized into a guaranteed stable PE JSON schema. [E16], [E17], [E18]

**[recommendation]** Use the pinned tool as a developer-only differential oracle for `pe_overview`, `unified/ir/pe_tables.py` and `symbols/pdbid.py` fixtures. Ask for a bounded, fixed field subset, parse under a version-specific adapter, and record actual output/error behavior before relying on PE JSON. Preserve disagreements: agreement between independent parsers is evidence about those fields, not proof of complete binary semantics. A malformed-image rejection by LLVM does not establish that PatchTrace should accept or reject every other field.

**[untested] Acceptance experiments:** test header sizes, RVA/file-offset boundaries, overlapping sections, imports, relocation types and CodeView identity on existing synthetic PE cases. Retain both readers' raw outputs and classify disagreement versus unavailable data. Enforce `jobs.run_process` budgets. LLVM's license allows reuse subject to its terms, but linking its C++ libraries would materially enlarge packaging; an optional developer executable is the smaller first experiment. [E19]

**[verified]** Sourceware's `abidiff` manual defines an ELF ABI comparison using debug types when present and symbols when richer debug information is absent. It documents bitwise exit statuses: 1 error, 2 usage error, 4 ABI change, 8 incompatible ABI change. Default user/system suppression files can affect results. This is a substantive tool contract, not an ordinary “nonzero means process failure” interface. [E20]

**[recommendation]** Reuse those design lessons now: declare which evidence tier a producer actually observed, isolate ambient suppression/configuration, and separate successful difference detection from execution failure. **Defer** an abidiff adapter until ELF scope exists; it would not supply PE function matching. Sourceware's homepage and API source state Apache-2.0 WITH LLVM-exception; the exact executable/version and complete dependency license closure were not obtained, so no packaging recommendation is made. [E21], [E22]

## 8. Concrete next slices and unresolved questions

1. **Runtime receipt experiment, existing owner:** pair process outcome with GZF/IR publication and cancellation evidence using the current extractor. Answer whether a readable analyzed GZF from interrupted work can reach a completed result under actual current paths.
2. **BinExport producer qualification, C3 owner:** pin a build against Ghidra 12.0.4; measure timestamp-only differences, promotion/inventory differences, rebasing and imported-edge coverage. Extend the spec only after these observations.
3. **Rizin acceptance, PR174 owner:** finish its native/API/production-JSON and downstream refusal gates. This note offers no alternative gate and no approval to change quarantine.
4. **Independent PE oracle, optional developer slice:** qualify LLVM 20.1.8 on a fixed fixture subset. Record which fields have parity and where both parsers are incomplete; do not add it to frozen runtime requirements.
5. **Neutral report tree, optional product slice:** prove comments-only/partial/truncated report rendering and orientation binding before considering an external report importer.

Unresolved: exact installed PyGhidra versus Ghidra compatibility; native Windows cleanup/cancellation; BinExport extension build on the selected Ghidra; promotion impact on existing saved analysis; stable COFF JSON fields; qualification receipt/library identity format; report-tree reuse value compared with existing reports. Each remains **untested**, rather than implicitly accepted because upstream code is mature. No numeric matching/calibration improvement is claimed.

## Primary sources inspected

Commit/tag links below identify source inspected by raw retrieval. Live official documentation is explicitly unpinned. Debian packaged-source URLs are versioned and retain the upstream Salsa provenance.

- **E1:** [PyGhidra README, Ghidra commit e40ed130](https://github.com/NationalSecurityAgency/ghidra/blob/e40ed13014025f82488b1f8f7bca566894ac376b/Ghidra/Features/PyGhidra/src/main/py/README.md).
- **E2:** [PyGhidra explicit API implementation](https://github.com/NationalSecurityAgency/ghidra/blob/e40ed13014025f82488b1f8f7bca566894ac376b/Ghidra/Features/PyGhidra/src/main/py/src/pyghidra/api.py).
- **E3:** [PyGhidra deprecated core contexts](https://github.com/NationalSecurityAgency/ghidra/blob/e40ed13014025f82488b1f8f7bca566894ac376b/Ghidra/Features/PyGhidra/src/main/py/src/pyghidra/core.py) and [launcher](https://github.com/NationalSecurityAgency/ghidra/blob/e40ed13014025f82488b1f8f7bca566894ac376b/Ghidra/Features/PyGhidra/src/main/py/src/pyghidra/launcher.py).
- **E4:** [Ghidra Apache-2.0 license](https://github.com/NationalSecurityAgency/ghidra/blob/e40ed13014025f82488b1f8f7bca566894ac376b/LICENSE). Third-party distribution inventory is a separate obligation.
- **E5:** [JPype official guide: restarting/multiple JVMs](https://jpype.readthedocs.io/en/latest/userguide.html#restarting-the-jvm), live development guide; exact documentation revision unknown.
- **E6:** [BinExport2Builder.java, commit 9648cacb](https://github.com/google/binexport/blob/9648cacb21a71aa6c21b3fca504f146c39164a53/java/src/main/java/com/google/security/binexport/BinExport2Builder.java).
- **E7:** [BinExport Ghidra build/usage README at same commit](https://github.com/google/binexport/blob/9648cacb21a71aa6c21b3fca504f146c39164a53/java/README.md).
- **E8:** [BinExport2 protobuf schema at same commit](https://github.com/google/binexport/blob/9648cacb21a71aa6c21b3fca504f146c39164a53/binexport2.proto).
- **E9:** [BinExport license and component notices](https://github.com/google/binexport/blob/9648cacb21a71aa6c21b3fca504f146c39164a53/LICENSE).
- **E10:** [Rizin 0.9.1 matching implementation and LGPL-3.0-only header](https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/arch/similarity.c).
- **E11:** [Rizin 0.9.1 CLI/serializer and LGPL-3.0-only header](https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/main/rz-diff.c).
- **E12:** [Debian Sources diffoscope 297+deb13u1 JSON presenter](https://sources.debian.org/src/diffoscope/297%2Bdeb13u1/diffoscope/presenters/json.py/).
- **E13:** [Same release Difference model](https://sources.debian.org/src/diffoscope/297%2Bdeb13u1/diffoscope/difference.py/).
- **E14:** [Same release command runner](https://sources.debian.org/src/diffoscope/297%2Bdeb13u1/diffoscope/comparators/utils/command.py/).
- **E15:** [Debian machine-readable copyright, including Salsa upstream origin](https://sources.debian.org/src/diffoscope/297%2Bdeb13u1/debian/copyright/); [upstream Salsa project](https://salsa.debian.org/reproducible-builds/diffoscope). Salsa blob browsing was unavailable; versioned Debian source bytes were inspected successfully.
- **E16:** [LLVM 20.1.8 Object Reader source](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/llvm/tools/llvm-readobj/llvm-readobj.cpp).
- **E17:** [LLVM 20.1.8 COFF dumper](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/llvm/tools/llvm-readobj/COFFDumper.cpp).
- **E18:** [LLVM 20.1.8 command guide source](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/llvm/docs/CommandGuide/llvm-readobj.rst); [official rendered guide](https://llvm.org/docs/CommandGuide/llvm-readobj.html), live/unpinned.
- **E19:** [LLVM 20.1.8 license with exception](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/LICENSE.TXT).
- **E20:** [Sourceware abidiff manual](https://sourceware.org/libabigail/manual/abidiff.html), live/unpinned; scope, suppressions and return values inspected.
- **E21:** [Sourceware libabigail project and license statement](https://sourceware.org/libabigail/), live/unpinned.
- **E22:** [Sourceware libabigail API header with SPDX license](https://sourceware.org/libabigail/apidoc/abg-ir_8h_source.html), live/unpinned. A guessed 2.6 COPYING URL returned 404 and is not license evidence; no source-release tarball was verified.

[E1]: https://github.com/NationalSecurityAgency/ghidra/blob/e40ed13014025f82488b1f8f7bca566894ac376b/Ghidra/Features/PyGhidra/src/main/py/README.md
[E2]: https://github.com/NationalSecurityAgency/ghidra/blob/e40ed13014025f82488b1f8f7bca566894ac376b/Ghidra/Features/PyGhidra/src/main/py/src/pyghidra/api.py
[E3]: https://github.com/NationalSecurityAgency/ghidra/blob/e40ed13014025f82488b1f8f7bca566894ac376b/Ghidra/Features/PyGhidra/src/main/py/src/pyghidra/core.py
[E4]: https://github.com/NationalSecurityAgency/ghidra/blob/e40ed13014025f82488b1f8f7bca566894ac376b/LICENSE
[E5]: https://jpype.readthedocs.io/en/latest/userguide.html#restarting-the-jvm
[E6]: https://github.com/google/binexport/blob/9648cacb21a71aa6c21b3fca504f146c39164a53/java/src/main/java/com/google/security/binexport/BinExport2Builder.java
[E7]: https://github.com/google/binexport/blob/9648cacb21a71aa6c21b3fca504f146c39164a53/java/README.md
[E8]: https://github.com/google/binexport/blob/9648cacb21a71aa6c21b3fca504f146c39164a53/binexport2.proto
[E9]: https://github.com/google/binexport/blob/9648cacb21a71aa6c21b3fca504f146c39164a53/LICENSE
[E10]: https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/arch/similarity.c
[E11]: https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/main/rz-diff.c
[E12]: https://sources.debian.org/src/diffoscope/297%2Bdeb13u1/diffoscope/presenters/json.py/
[E13]: https://sources.debian.org/src/diffoscope/297%2Bdeb13u1/diffoscope/difference.py/
[E14]: https://sources.debian.org/src/diffoscope/297%2Bdeb13u1/diffoscope/comparators/utils/command.py/
[E15]: https://sources.debian.org/src/diffoscope/297%2Bdeb13u1/debian/copyright/
[E16]: https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/llvm/tools/llvm-readobj/llvm-readobj.cpp
[E17]: https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/llvm/tools/llvm-readobj/COFFDumper.cpp
[E18]: https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/llvm/docs/CommandGuide/llvm-readobj.rst
[E19]: https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/LICENSE.TXT
[E20]: https://sourceware.org/libabigail/manual/abidiff.html
[E21]: https://sourceware.org/libabigail/
[E22]: https://sourceware.org/libabigail/apidoc/abg-ir_8h_source.html
