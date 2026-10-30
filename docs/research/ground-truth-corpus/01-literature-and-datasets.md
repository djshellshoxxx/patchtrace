# R1 literature, dataset decisions, and limits of ground truth

Research date: 2026-10-30. Scope: primary literature and authoritative tool/dataset documentation; no target binary was executed, no external dataset was imported, and no published accuracy result was reproduced for this note. This is research evidence, not a compatibility or corpus acceptance report.

## 1. Decisions for the pilot

Use the existing PatchTrace corpus machinery to build a small source-pinned corpus, retain debug evidence privately in the build bundle, and give stripped artifacts to the engine. Treat public datasets as supplementary stress tests and methodological precedents. None of the resources examined here establishes an independently audited, ready-to-import answer key for PatchTrace's full Windows patch correspondence and material-change task. This is a bounded finding about the sources inspected, not proof that no such resource exists.

The most useful precedents are QBinDiff's adjacent-release manual review, DeepBinDiff's explicit partial-label coverage, TikNib's debug/source filtering, Assemblage's binary-to-source metadata, and REFuSe-Bench's leakage controls. Their answer keys address different questions. Function retrieval relevance, source lineage, binary correspondence, and security patch classification must remain separate labels.

Research reuse is intentional. Read first: [pre-existing labelled data](../calibration/preexisting-labelled-data.md), [prior-art corpus factories](../calibration/prior-art-corpus-factories.md), and [unified-engine research](../unified-engine/). Those notes already inventory acquisition and implementation ideas. The additions here are directly readable paper methods, correction of overly broad prior summaries, explicit verification boundaries, and a decision record for R1.

Three consequential corrections to the earlier inventory:

1. DeepBinDiff's paper-level answer key is **partial basic-block correspondence from matched unchanged source lines and debug information**, rather than simply joining symbol names. A locally computed name join in an earlier note is a different experiment. [S09]
2. QBinDiff acknowledges name-based wrapper/core mistakes and errors propagated through composed release mappings. Its oracle is informed human judgment. [S07]
3. REFuSe-Bench's official datasheet resolves the broad license question: its experiment code is MIT; binaries keep their original licenses. A statement that the entire benchmark is MIT is insufficient for redistribution. [S14]

## 2. Evidence and verification vocabulary

**P** means the author paper was opened and the relevant method read. **D** means official documentation, README, or datasheet content was opened. **R** means a release/tag and, when available, linked commit were inspected. **L** means license text was read; a repository badge alone is described as a badge. **H** means a fact is carried forward from the earlier repository research and was not independently rechecked here. **U** means unresolved. None of P/D/R/L means experimental reproduction.

Mutable `main`/`master` links identify the inspected page, not an immutable experimental input. A short SHA below is exactly the short identifier displayed by the release page; it is not padded or represented as a full pin. Full commits are supplied only when opened. Failed direct GitHub API reads returned `Operation not permitted`; raw-content pages were unavailable through the web reader. GitHub HTML, official papers and documentation were still readable. Do not silently treat these as equivalent access paths or infer a missing license from a failed fetch.

## 3. Comparison tools: useful baselines, unsuitable answer keys

| Tool | Reproducible identifier observed | Coverage and construction | Rights and PatchTrace decision | Verification |
| --- | --- | --- | --- | --- |
| **BinDiff / BinExport** | BinDiff `v8`, displayed commit `aecc14d`; release bundles BinExport `f908beb`. Separately, BinExport `v12-20240417-ghidra_11.0.3`, full commit `d45f4457387ee8098e582347d0be0f3e3f601646`. [S01–S04] | BinExport takes disassembly from IDA, Binary Ninja or Ghidra. Architecture coverage depends on the chosen frontend and successful analysis, not the exporter name. Matching and function recovery are algorithmic predictions; no external labels are generated merely by exporting. | BinDiff Apache-2.0 license text read. BinExport Apache-2.0 is carried forward from prior source inspection; its current license page failed to load here. Neither tool license grants rights in target binaries or copied source. Keep as optional comparison baseline; hash export and analysis configuration. | D/R/L for BinDiff; D/R plus H-license for BinExport. No local run or cross-version extension compatibility check. |
| **Ghidra Version Tracking** | Official release `Ghidra_12.2_build`, commit `8ca9077040cc43cd790babcfccf19475622a3e9a`; this is an observed upstream release, not the environment version. [S05] | Official help distinguishes associations, scored matches, accepted matches and implied matches. Auto-VT code combines exact symbol/data/function byte/instruction/mnemonic correlators, then duplicate disambiguation and further correlation. Supported architectures depend on Ghidra loaders/languages and analysis options. | Apache-2.0 status carried from previous code review. A user clicking Accept is review provenance, not independent proof. Same-name correlation leaks the answer if names derived from the oracle are left in the benchmark input. Use as a baseline and review aid; avoid treating Auto-VT acceptance as truth. | D/R; H-license. No GUI, headless, or dataset run. [S06] |
| **Ghidriff** | Official release `v1.0.0`, displayed commit `85c74a7`, described as Ghidra 11.4 support. [S08] | README describes Python/PyGhidra orchestration, function added/deleted/modified output, JSON and reports, with `VersionTrackingDiff` default. Binary coverage follows Ghidra and the implementation. Published support for 11.4 does not establish support for 12.2. | Repository GPL-3.0 badge; prior source review agrees. Use the existing external baseline integration. Ghidriff and Ghidra VT share analysis and matching ancestry, so agreement is correlated evidence. Neither supplies an independent corpus oracle. Target/data rights remain separate. | D/R; current badge, H-license text. No new engine acceptance result. |
| **Diaphora** | Current official README names `3.5` and installation tag `3.5.0`; full tag commit not resolved. [S10] | IDA plugin: assembly, CFG/callgraph, pseudocode, manual matching and batch automation. README states IDA >=7.4 and Python 3; actual processor coverage depends on IDA and exported features. Pseudocode features additionally depend on available decompilation. | Repository AGPL-3.0 badge; previous license review agrees. Optional separately installed baseline, subject to its dependencies and terms. No Diaphora code copied. Its heuristics and analyst overrides are predictions/review evidence, not ground truth. | D, badge plus H-license text. No IDA, Hex-Rays, or Diaphora execution. |
| **QBinDiff** | Release `v1.2.3`, commit `eac842094ac614cfa4ee99bcf9ab295d0cb6cdec`. Paper baseline is the earlier ASE 2021 prototype, not this release. [S07, S11] | Current repo supports exported disassembly through BinExport/Quokka and configurable features/anchors. Paper studies one-to-one callgraph alignment. Upstream calls the tool experimental and parameter tuning significant; loader support does not prove tested cross-ISA patch accuracy. | Apache-2.0 repository badge; prior license-file review agrees. Use as optional ablation/assignment baseline if installed. Freeze features, parameters and anchors on validation data. Never tune on the locked test set. | P/D/R; badge plus H-license text. No implementation benchmark reproduced. |

BinDiff similarity, Diaphora ratio, VT score and QBinDiff objective have different meanings. R1 should retain the raw engine field and its producer/version instead of converting all scores into a probability. This is a proposed evaluation rule, consistent with the existing repository contract.

## 4. Datasets and construction methods

### 4.1 QBinDiff's release lineage benchmark

Mengin/Rossi, ASE 2021, `arXiv:2112.15337v1`: 18 zlib, 33 libsodium and 17 OpenSSL versions, GCC 7.5 x86-64 `-O3`, symbols retained for truth then stripped before IDA 7.2/BinExport. Human adjacent-release mappings use source/changelogs/symbols, then are composed. [S07]

**Rights/status:** the promised benchmark release/license was not verified; the tool license does not cover project binaries. **Fit:** Tier E methodology with narrow build coverage. **Verification:** P only, no reproduction. The printed §V-C precision/recall denominators appear transposed. Our recommendation: derive metrics from explicit TP/FP/FN definitions and never use these published scores as PatchTrace targets.

### 4.2 DeepBinDiff

Duan et al., *DeepBinDiff: Learning Program-Wide Code Representations for Binary Diffing*, NDSS 2020, DOI `10.14722/ndss.2020.24311`. Its oracle matches unchanged source lines with Myers diff, maps lines to addresses using debug information, and excludes statements yielding ambiguous multiple blocks. Evaluation distinguishes known correct, known incorrect and unknown predictions because the label set is incomplete. This is partial basic-block truth; it does not certify every function pair or classify all material changes. [S09]

The official repository has BSD-3-Clause metadata and an `experiment_data` tree. Earlier local inspection found x86-64 ELF coreutils/diffutils/findutils versions and O0–O3 fixtures. The paper specifies GCC 5.4 for its compiler-variation set; this session did not bind those settings to each repository artifact or resolve a release/full commit. GNU fixture binaries require their own license/source-compliance review; BSD code metadata does not replace it. **Fit:** optional ELF cross-version stress tests and the partial-coverage scoring precedent. **Weakness:** selection excludes exactly the changed/ambiguous regions most relevant to patches, so high accuracy on the covered subset cannot be presented as patch detection recall. **Independent verification:** P/D; H for local fixture counts/details; no rerun. [S09, S09a]

### 4.3 BinaryCorp / jTrans

Wang et al., *jTrans: Jump-Aware Transformer for Binary Code Similarity Detection*, ISSTA 2022, DOI `10.1145/3533767.3534367`, `arXiv:2205.12713`. The paper describes Arch/AUR package builds, compiler wrappers enforcing optimization, suppressed stripping for symbol collection, and stripping before evaluation. BinaryCorp-26M contains 48,130 binaries; train/test are split by entire projects. The large dataset uses GCC/G++ and five compilation options; §7 limits the study to one architecture, giving x86 as its example. Exact compiler version and a fuller architecture manifest were not resolved here. The corpus is Linux; its published task is ranked function retrieval. [S12]

Official code has MIT license text. README dates BinaryCorp publication to 2022-06-09 and addition of original binaries to 2022-07-07; neither is a content-addressed dataset release. Download contents, archive hashes, per-package binary licenses and complete compiler manifest remain U. **Fit:** optional scale/retrieval experiments, not initial patch oracle. **Leakage concern:** a project split does not by itself exclude copied library code, common runtime code or forks across projects. Require our own lineage/duplicate grouping. **Independent verification:** P/D/L, no artifact fetch or reproduction. [S13]

### 4.4 BinKit and TikNib

Kim et al., *Revisiting Binary Code Similarity Analysis using Interpretable Feature Engineering and Lessons Learned*, IEEE TSE, DOI `10.1109/TSE.2022.3187689`; official BinKit/TikNib repositories. Observed release: BinKit `v2.0.0`, displayed commit `82bc979`. BinKit 2.0 README reports 371,928 binaries and 1,904 configuration combinations; x86 32/64, little-endian ARM 32/64 and little/big-endian MIPS 32/64; O0/O1/O2/O3/Os/Ofast; GCC through 11 and Clang through 13, plus O-LLVM variants. It separately lists no-inline, PIE, LTO and obfuscation datasets. These are Linux cross-compilation recipes, not PE/MSVC validation. [S15]

TikNib documentation explicitly parses `-g` debug information for source paths/line numbers, filters compiler intrinsic functions and removes within-package duplicates. Source-file/line coordinates are therefore part of its filtering procedure, not just display metadata. [S16]

**Rights/status:** MIT badges and previously read MIT files cover tooling; compiled packages need per-project review. No complete binary-redistribution grant was independently established. **Fit:** Tier B matrix and deduplication precedent; select a small pinned subset, not the entire matrix. **Weakness:** many variants of relatively few packages inflate sample counts; inline elimination, same-file static names, reused source lines and Ofast/undefined behavior complicate identity. **Independent verification:** D/R; H-license text; no download, cross-toolchain build, or reported accuracy reproduction. Package count and historical fixture counts in prior notes are not new measurements here.

### 4.5 Assemblage and temporal DeepHistory

Liu et al., *Assemblage: Automatic Binary Dataset Construction for Machine Learning*, NeurIPS 2024 Datasets and Benchmarks, `arXiv:2405.03991v2` (2024-11-02). The paper reports 890k PE and 428k ELF outputs across 29 configurations, records build provenance, and describes function names/byte hashes, RVA ranges, source-line addresses and binary/PDB association tables. These constitute richer raw evidence than names alone, but not reviewed cross-version semantic truth. Source/build metadata must still be joined to the exact hashed binary. [S17]

The current official README says code MIT and published data is a permissively licensed subset. It describes a newer Linux C/C++/Rust framework, while Windows/MSVC is in a legacy component and DeepHistory is separate. Do not substitute the current source tree for the paper's original Windows build environment. No immutable code revision or complete current dataset license manifest was resolved here. [S18]

**New candidate:** official `Assemblage-Dataset/DeepHistory-Eval` documents bundled CVE inputs, affected-binary mappings, patch YAML and a source-checkout manifest, with binaries/DuckDB/source trees external. It links the `changliu8541/assemblage-deephistory` Hugging Face dataset, whose card returned an anti-bot page here. No root license was visible on the opened evaluation landing page; that observation is not an exhaustive tree audit. [S19]

**Fit:** highest-priority external candidate for Windows temporal diversity after a small local pilot. **Risk:** recipe/code MIT assertions do not establish each artifact's rights; CVE mappings are candidates until independently reviewed. Older `packages.json` counts/pins in calibration notes remain H, not fresh proof. **Independent verification:** P/D only; no dataset card, manifests, builds, CVE labels or metrics independently reproduced. No external model/API or evaluation script was run.

### 4.6 REFuSe-Bench

Saul et al., *Is Function Similarity Over-Engineered? Building a Benchmark*, NeurIPS 2024 Datasets and Benchmarks, `arXiv:2410.22677v1` (2024-10-30). It combines Windows Assemblage, MOTIF and Common Libraries with Linux Marcelli Dataset-1 and BinaryCorp. The paper separates training labels from evaluation labels; normalizing project/source identity and parameter types changes the measured retrieval result. It identifies overlap between common libraries and jTrans training material. These are relevance labels and retrieval experiments, not strict patch lineage proof. [S20]

The official datasheet specifies project-disjoint Assemblage train/test splits, function-byte deduplication and separation of functions occurring in more than half the binaries. It also explicitly retains each binary's original license while making experiment code MIT. This resolves the earlier broad data-license uncertainty, but not the per-file redistribution review. [S14]

**Identifier:** paper v1; repo `main` content read, no immutable commit/full dataset snapshot resolved. **Fit:** leakage-control checklist, Windows retrieval stress and raw-byte baseline idea. **Weakness:** project grouping plus exact hashes can miss near duplicates/shared code; permissive relevance normalization is inappropriate for precise old/new identity. A malware family benchmark does not become a benign patch oracle. **Independent verification:** P/D; code MIT badge; no model training, data download, split audit, family inspection, or published score reproduction. [S21]

### 4.7 Other compiler-variation and structural benchmarks

**Marcelli et al. / Cisco-Talos**, *How Machine Learning Is Solving the Binary Function Similarity Problem*, USENIX Security 2022. Official artifact supplies binaries/build scripts, selected function datasets/features, IDA analysis scripts and result code. Its README explicitly distinguishes MIT experiment code from compiled-binary licenses under `Binaries/LICENSES`. Prior research describes ELF architecture/compiler/optimization variants over 17 projects; exact compiler matrix and full source pin were not re-audited in this session. **Fit:** optional reproducible Tier B comparator with stronger licensing organization than a bare badge. **Weakness:** IDA-based recovery and selected-function filtering condition the measured population; retrieval metrics do not measure patch classification. **Status:** D; H for detailed matrix; no build/score reproduction. [S22]

**Jia et al.**, *1-to-1 or 1-to-n? Investigating the effect of function inlining on binary similarity analysis*. Official dataset DOI `10.5281/zenodo.6675280`, version `v1-initial_release`, published 2022-06-23. Landing page lists source, binaries and ground-truth archives for three datasets, explicitly welcomes label corrections, and links Dataset I to BinKit's normal dataset. The displayed rights field does not expose a clear license value; do not infer one. Exact architecture/compiler coverage and labeling implementation were not verified. **Fit:** Tier D research candidate; its overlap with BinKit means these are not independent dataset families. **Status:** official landing/repository documentation read; no archive download, truth audit or execution. [S23]

There is no uniquely identified dataset called “BINDIFF-style compiler variation” in the request. For R1 it denotes an experiment design: fixed source identity, controlled toolchain/flags, hidden symbols, independent identity extraction. BinKit, BinaryCorp and Marcelli cover parts of that design; QBinDiff primarily varies release history. Keep version variation and compiler variation as separate axes rather than silently labelling one as evidence for the other.

## 5. Proposed label rules derived from the review

These are recommendations for implementation, not claims about completed R1 code.

1. **Distinguish identity from behavior.** Store source lineage and compiled instances separately. A renamed function can preserve lineage while changing behavior; unchanged source can emit different instructions; a changed source expression can compile to identical bytes. Neither equal names nor equal bytes proves all semantic properties.
2. **Bind all evidence to artifacts.** The debug/PDB file must belong to the exact binary under evaluation; preserve its hash and binary association. Record raw ranges rather than assuming one contiguous start/size. Normalize absolute paths only when constructing a stable source identity, preserving the original provenance record.
3. **Represent transformation explicitly.** An inline instance belongs to a caller location and an abstract source identity. Folded functions may share a binary range. A split may create a wrapper and core. Use relation sets or ambiguity groups; do not force a unique one-to-one edge or count every unchosen alternative as false.
4. **Keep labels outside engine input.** Build a debug-bearing artifact and derive a stripped counterpart; verify the intended executable bytes/ranges after stripping. Store truth separately. Record whether exported names, import names, strings, paths or sidecar symbols were available in each run. Oracle annotations embedded as strings or special sections can also leak identity and should not reach the matcher.
5. **Promote with multiple independent evidence types.** A source annotation or unique debug name produces a candidate. Acceptance additionally needs correct artifact association, mapped executable ranges, duplicate/folding/inline checks, and static binary verification. Material-change acceptance needs proof that the intended mutation survived compilation in the stated region. Human review must record reviewer, evidence and decision, without pretending to be a formal semantic proof.
6. **Preserve unknown coverage.** For partial truth, record the covered function/range population. Report known-pair precision, covered recall, unknown predictions and coverage separately. Full closed-world FP/FN rates are valid only where truth is exhaustive. DeepBinDiff's exclusion rule is an example to inspect, not an automatic proof that every uncovered prediction is correct.
7. **Freeze identity policy before scores.** Name normalization, thunk collapse, runtime filtering, source-file matching and template/type treatment change the task. Version the policy and report counts at each filter. Do not adjust policy after looking at locked-test failures merely to raise a score.
8. **Build partitions on connected lineage groups.** Group all compiler/optimization variants, adjacent versions, source forks and copied functions, mutation-template relatives and exact/near duplicate binary regions before assigning splits. Detect forbidden overlap after artifact generation too. Public benchmark provenance must travel with imported cases so BinKit-derived inlining data is not mistaken for a fresh independent holdout.

Two authoritative implementation constraints reinforce these rules. Microsoft documents that `/OPT:ICF` can assign the same address to different functions; distinct PDB names are not sufficient for distinct binary instances. LLVM documents that debug information coexists with inlining, block reordering/merging, tail duplication and optimized-away functions; a debug record is a compiler mapping, not an unchanged source-to-function bijection. [S24, S25]

Reproducibility must be observed, not inferred from a recipe. Record the complete environment and repeat a build; report byte-identical, executable-content-identical with documented metadata differences, or non-reproducible. The Reproducible Builds definition separates documented inputs/environment from independent verification, and explicitly cautions that recorded build information alone does not establish reproducibility. [S26]

## 6. Priorities and open evidence gaps

| Priority | Concrete next action | Acceptance evidence | Unresolved dependency |
| --- | --- | --- | --- |
| P0 | Extend existing local Tier A/C fixtures with reviewed source, independent symbol/range extraction, explicit oracle coverage and mutation survival | Repeated build hashes, validated artifact bindings, static disassembly evidence, real engine result | Integration owner reports actual execution status separately |
| P0 | Version identity/metric policy and lock lineage partitions before calibration | Hand-computed metric examples, overlap detector failures for compiler/version/template duplicates | Must fit existing corpus contracts |
| P1 | Add MSVC/PDB, clang-cl and MinGW variants of the same pilot | Exact toolchain/SDK/linker versions, PDB identity, linker maps, stripped-input audit | Windows runner and compiler availability; no Linux inference of MSVC compatibility |
| P1 | Audit one pinned Assemblage/DeepHistory slice | Accessible license manifest, source/build pins, content hashes, audited CVE source changes and ranges | HF card/archive access and per-file terms remain unverified |
| P1 | Construct explicit ICF/inline/split/outline cases | Multiple source identities/ranges, transformation evidence, ambiguity-aware labels | Do not count synthetic cases as real release coverage |
| P2 | Import small reviewed ELF subsets from BinKit/DeepBinDiff/Marcelli | Per-project license/notices, archive hashes, independent re-extraction, provenance overlap checks | Published archive availability and exact compiler manifest |
| P2 | Recover QBinDiff published answer key and review wrapper/core cases | Dataset snapshot/license plus review of a sampled mapping chain | Complete release not located in inspected sources |
| P2 | Reproduce REFuSe-style deduplication and compare strict vs relevance labels | Report both populations with no threshold tuning on holdout | Model/data costs are optional and outside pilot acceptance |

Research cannot resolve semantic equivalence in general. It can establish bounded, auditable claims about controlled builds, reviewed transformations and particular patch cases. The practical R1 target is a reproducible evidence chain with abstention and measured coverage, not a universal oracle.

## 7. Primary source register

All URLs below were consulted on 2026-10-30 unless explicitly marked H. Web reader reference IDs are included only to help the integration owner recover the exact retrieval; stable URLs remain the durable citations. These IDs are not archive hashes.

| ID | Authoritative URL / publication | Read evidence and retrieval reference |
| --- | --- | --- |
| S01 | https://github.com/google/bindiff/releases | `v8`, `aecc14d`, bundled exporter `f908beb`; `turn0search0` |
| S02 | https://github.com/google/bindiff/blob/main/LICENSE | Apache-2.0 text, `turn11view0` / `turn13view5` |
| S03 | https://github.com/google/binexport/blob/main/README.md | Exporters/frontends/headless documentation, `turn0search1`; license URL failed this session, prior review H |
| S04 | https://github.com/google/binexport/releases ; https://github.com/google/binexport/commit/d45f4457387ee8098e582347d0be0f3e3f601646 | Release identifier and linked full commit, `turn18view5` / `turn19view0` |
| S05 | https://github.com/NationalSecurityAgency/ghidra/releases ; https://github.com/NationalSecurityAgency/ghidra/commit/8ca9077040cc43cd790babcfccf19475622a3e9a | Ghidra 12.2 tag and full commit, `turn16view6` / `turn19view2` |
| S06 | https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/VersionTracking/src/main/help/help/topics/VersionTrackingPlugin/Version_Tracking_Intro.html ; https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/gui/actions/AutoVersionTrackingTask.java | Help definitions and code correlator description, `turn1search1` / `turn1search0`; mutable master, not release-pinned audit |
| S07 | https://arxiv.org/pdf/2112.15337 | Mengin/Rossi ASE 2021 manuscript; §V-A construction, §V-C metrics/split case, §V-E threats; `turn3view2`, `turn5view2`, `turn16view0` |
| S08 | https://github.com/clearbluejar/ghidriff ; https://github.com/clearbluejar/ghidriff/releases | README and `v1.0.0` support description, `turn1search2` / `turn1search3` |
| S09 | https://www.ndss-symposium.org/wp-content/uploads/2020/02/24311-paper.pdf | DeepBinDiff NDSS 2020, §V-B ground truth, known/unknown scoring, GCC 5.4 set; `turn3view4` / `turn5view3` / `turn33view6` |
| S09a | https://github.com/yueduan/DeepBinDiff | Official repository, experiment directory and BSD badge, `turn11view8` / `turn13view3`; exact binaries/counts are H from calibration note |
| S10 | https://github.com/joxeankoret/diaphora | Current README version/tag/features and AGPL badge, `turn2view0` / `turn9view7` |
| S11 | https://github.com/quarkslab/qbindiff ; https://github.com/quarkslab/qbindiff/releases ; https://github.com/quarkslab/qbindiff/commit/eac842094ac614cfa4ee99bcf9ab295d0cb6cdec | Current README, release and linked full commit, `turn9view6` / `turn16view5` / `turn19view1` |
| S12 | https://arxiv.org/pdf/2205.12713 | Wang et al., ISSTA 2022, §4.5 construction, §5.1 corpus, §6 split and stripping; `turn18view0` / `turn19view3` / `turn19view4` |
| S13 | https://github.com/vul337/jTrans ; https://github.com/vul337/jTrans/blob/main/LICENSE | Dataset publication history, requirements and MIT text, `turn9view0` / `turn13view4` |
| S14 | https://github.com/FutureComputing4AI/Reverse-Engineering-Function-Search/blob/main/datasheet.md | Split/deduplication and explicit original-binary-license rule, `turn11view6` / `turn13view0` / `turn16view4` |
| S15 | https://github.com/SoftSec-KAIST/BinKit/blob/master/README.md ; https://github.com/SoftSec-KAIST/BinKit/releases | Matrix and release; `turn23search3`, `turn1search6`; associated TSE DOI `10.1109/TSE.2022.3187689` from existing research, paper not newly audited |
| S16 | https://github.com/SoftSec-KAIST/TikNib | Debug/source filtering instructions, `turn2view6` / `turn9view3` |
| S17 | https://arxiv.org/html/2405.03991v2 | Liu et al., NeurIPS 2024; pipeline/data schema and recipe distinction, `turn3view1` / `turn13view6` |
| S18 | https://github.com/assemblage-dataset/assemblage | Current official README code/data statements and legacy Windows distinction, `turn16search1` / `turn18view4` |
| S19 | https://github.com/Assemblage-Dataset/DeepHistory-Eval ; https://huggingface.co/datasets/changliu8541/assemblage-deephistory | Official evaluation README `turn18view1` / `turn19view6`; linked card blocked by anti-bot response `turn18view2` |
| S20 | https://arxiv.org/html/2410.22677v1 | Saul et al., NeurIPS 2024, dataset composition, label-policy experiments, leakage discussion; `turn3view0` / `turn5view0` |
| S21 | https://github.com/FutureComputing4AI/Reverse-Engineering-Function-Search | Official experiment-code README and MIT badge, `turn2view3` / `turn9view1` |
| S22 | https://github.com/Cisco-Talos/binary_function_similarity | Official USENIX Security 2022 artifact/README, `turn2view5` / `turn9view2`; current README code/binary license separation independently read in `turn33view3` |
| S23 | https://zenodo.org/records/6675280 ; https://github.com/island255/TOSEM2022 | Official inlining dataset description/version/file manifest and repository, `turn16search0` / `turn18view3`; rights value U |
| S24 | https://learn.microsoft.com/vi-vn/cpp/build/reference/opt-optimizations?view=msvc-180 | Official Microsoft `/OPT` documentation, ICF aliasing and defaults; English prose in retrieved page, `turn23search0` |
| S25 | https://llvm.org/docs/SourceLevelDebugging.html | Official LLVM debug/optimization mapping documentation, `turn23search1` |
| S26 | https://reproducible-builds.org/docs/formal-definition/ | Official build provenance/reproduction distinction, `turn23search2` |

## 8. Verification ledger and handoff

This note verifies access to the cited documentation/papers and selected release identifiers. It does **not** verify any external corpus archive hash, artifact license manifest, compiler reproducibility, debug-to-binary association, author ground-truth accuracy, current engine compatibility, or reported performance. Published dataset counts are attributed reports, not newly measured facts. No benchmark result should cite this literature review as live engine evidence.

Next executable research step: inspect a content-addressed sample of the selected local fixture build bundle, trace one accepted correspondence and one material mutation from source through debug/linker evidence to executable bytes, then score the existing genuine Ghidriff output under a frozen identity policy. External corpora remain optional expansion until their acquisition, license and oracle checks pass.
