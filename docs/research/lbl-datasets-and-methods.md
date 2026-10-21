# LBL research: datasets, evaluation methods and comparable numbers

Research note, 2026-10-15 (all URLs accessed 2026-10-15 via web search/fetch unless stated). Not legal advice. `[U]` = unverified: stated by a search summary or secondary source, primary text not read. `[D]` = derived by us (arithmetic or recommendation, no external source). Direct fetches of arxiv.org failed from the sandbox (DNS), so paper numbers come from search-result excerpts of the arXiv PDFs and are `[U]` unless noted. Read against `docs/specs/program-e/LBL-integration-plan.md`, `docs/specs/calibration-corpus-and-model.md` (SPEC-28), `docs/plans/ledger-C.md`, `docs/plans/calibration-licences.md`.

## Datasets (table: name, size, licence, usable?)

| Name | Size / content | Licence | Usable for us? |
|---|---|---|---|
| BinKit 2.0 (Kim et al.) https://github.com/SoftSec-KAIST/BinKit | 371,928 ELF binaries, 8 architectures, 6 opt levels (O0-O3, Os, Ofast), GCC 4.9.4-11.2.0 and Clang 4.0.0-13.0.0, O-LLVM variants, 1,904 option combinations (v1.0 in the paper: 243,128 binaries, 1,352 combos, 13 compilers) | Repo MIT (scripts and README). Licence of the compiled data not stated on the page [U] | Evaluation of function matching under compiler/opt change (ELF only). Not Windows PE, so a robustness cross-check, not a Tier R substitute. Build from scripts rather than redistribute. |
| BinaryCorp-3M / 26M (jTrans, Wang et al.) https://arxiv.org/pdf/2205.12713 | Binaries from Arch Linux packages at several opt levels; 3M-function subset used for evaluation [U] | Unknown; the OSUSecLab repo URL tried returned 404, so check the release [U] | Reference numbers only until the licence is read. Arch packages carry mixed (including copyleft) licences, so training use is "do not use" under our rule R4 until verified. |
| Assemblage / Assemblage-DeepHistory https://assemblagedocs.readthedocs.io/en/latest/dataset.html | Paper: 890k Windows PE and 428k Linux ELF binaries; released Windows sets about 62k (GitHub) and 29k (vcpkg) entries; PDBs on request only. Counts conflict across pages [U] | Code MIT. Binaries released only for repos with a detectable licence; users must follow each upstream licence | Best PE source with ground truth. Per-project filtering to our `PERMISSIVE_SPDX` list required. No pair labels, so we still build pairs ourselves (as the LBL plan s3 already assumes). |
| Debian / Alpine build corpora (snapshot.debian.org, Alpine aports) | Whole-distribution source and binary history | Per-package licences, mixed; infrastructure terms not read [U] | Source of consecutive-release ELF pairs, only as pinned recipes (like Tier R) filtered to permissive packages. Not fetched this pass. |
| CVEfixes https://zenodo.org/records/13118970 , https://github.com/inksong/cvefixes | v1.0.8 (to 2024-07-23): 12,107 fix commits, 4,249 projects, 11,873 CVEs, 272 CWEs, 51,342 files, 138,974 functions | Code MIT; data CC BY 4.0 per the GitHub README [U for the Zenodo record field]. Underlying source keeps its own licences | Source-side answer keys (which function a fix touched) and CWE mapping. Store commit pins and ids, not upstream code. Many projects will not build for Windows. |
| BigVul (Fan et al., MSR 2020) | Paper describes 3,754 vulnerabilities, 91 types, 348 projects; surveys cite 264,919 functions (11,823 vulnerable) [U, figures conflict] | Not found [U] | Function-level vulnerable/fixed labels with known label noise. Read licence first; low priority. |
| Devign | 27,318 functions (12,460 vulnerable, 14,858 not), 4 C projects, via CodeXGLUE | Not found [U] | Not useful: classification not localisation, 4 projects, noisy. |
| Winbindex https://github.com/m417z/winbindex | Index of Microsoft PE hashes/KBs with links to the Microsoft symbol server | Metadata repo GPL-3.0 per LBL note A (not re-verified here). The binaries are Microsoft's | Tier W only, local: fetch at runtime on the owner's machine. Never committed or redistributed (rule R1, owner decision O1). |
| Public Windows patch-diff datasets with answer keys | None found. Searches returned blog case studies (https://www.alex-ionescu.com/2015/05/ on Diaphora and MS15-050) and tools (WinDiff built on Winbindex), not a benchmark | n/a | Gap in the literature. Tier W (owner-local) plus Tier R planted fixes is the substitute; state this in claims. |

Microsoft data rule: nothing derived from Microsoft binaries (PDBs, symbols, Winbindex-derived labels, Tier W cells naming files/RVAs/hashes/KBs) goes into git (`docs/plans/calibration-licences.md` R1/R2). The symbol-server terms page was unreadable in the earlier pass, so the legal reading stays with the owner.

## Methodology recommendations

Unit and splits
- Unit of analysis is the lineage (project plus pair series), not the function; functions in one lineage are strongly dependent. Split, bootstrap and permute by lineage (SPEC-28 s4.3 already requires it).
- Leakage control: split by project first (never the same upstream in train and test), then by time (train older, test newer) for any learned part. Deduplicate near-identical functions across projects before splitting, since vendored copies (zlib, lz4) leak across "different" projects [D]. BinKit's authors report compile settings and analysis-tool correctness change BCSA results materially (https://arxiv.org/pdf/2011.10749, excerpt), so freeze and record toolchains per fold.
- Never tune thresholds, weights or calibration on locked-test lineages; nested grouped CV as in SPEC-28 s8.

Ranking metrics
- Report hit@1, hit@3, hit@10 (fix function within top-k of the flagged list), MRR and nDCG@10 with graded relevance (fix function highest, co-changed callers lower) [D]. State the denominator (lineages with a truth fix; abstentions count as misses) and flagged-pool size. zlib v1.3 to v1.3.1 shows about 1.6 percent of functions truly change (LBL plan s2, one pair), so random and "sort by engine similarity ascending" baselines are mandatory.
- Matching tasks (BinKit-style): Recall@1 and MRR over a candidate pool; always state pool size, because scores collapse as the pool grows (jTrans pool 32 vs 10,000 below).

Significance and intervals
- Primary: lineage-level paired comparison of two rankers on the same lineages: paired permutation (sign-flip) test on per-lineage metric differences plus a percentile cluster bootstrap CI (B=2000) of the difference. In IR evaluation bootstrap, randomization and t-test agree closely at ordinary sizes (Smucker, Allan, Carterette, CIKM 2007, https://ciir-publications.cs.umass.edu/getpdf.php?id=744), but they disagree more as topics shrink, with randomization giving smaller p-values than the t-test below p=0.1 (SIGIR 2009 short paper, https://ir.webis.de/anthology/2009.sigirconf_conference-2009.82). Parapar et al. (https://ar5iv.org/html/1901.10696) report bootstrap with few type-I errors but less power than permutation or sign tests [U, excerpt]. Our n is the small-topic regime, so pre-register the permutation test as primary and the bootstrap CI as secondary.
- Pre-register one primary metric (hit@3 or MRR) and one primary contrast; all else descriptive; Holm if more than one primary contrast [D].
- SPEC-28 sets a 30-lineage floor for headline intervals and notes cluster bootstrap is anti-conservative with few groups; add a leave-one-lineage-out jackknife and report the minimum.

Power for 30-100 lineages [D, normal approximation]
- One proportion (hit@k): 95 percent half-width = 1.96*sqrt(p(1-p)/n). At p=0.5: 0.18 (n=30), 0.14 (n=50), 0.098 (n=100). At p=0.8: 0.14, 0.11, 0.078.
- Paired difference on binary hit@k depends on discordant lineages only. With n=100 and about 20 discordant, an 8-vs-12 split gives an exact two-sided McNemar p of about 0.5; about 15-vs-5 is needed for p of about 0.04. At n=30 only very large, one-directional flips are detectable.
- Conclusion: at n<=100 lineages LBL can detect regressions and large effects (roughly 10 or more percentage points), not 2-3 point improvements. Use per-lineage reports as regression gates; keep improvement claims descriptive.

A/A and negative controls
- A/A: compare an engine with itself on rebuilt or rerun inputs; the difference should centre on 0 and the permutation test should reject about 5 percent at alpha=0.05. It checks the harness, not the engine. Keep the existing A/A and planted-fix gates (LBL plan s1) as hard gates.
- Shuffled-label control: a ranker with shuffled lineage labels must fall to the random baseline.

Label noise
- Separate "unknown" from "negative": abstain, do not vote (LBL charter). Source-level truth (commit pins, CVE records) is cleaner than binary-level truth; inlining makes function-level truth one-to-many (https://arxiv.org/pdf/2112.12928, excerpt).
- Audit a random sample (the LBL plan budgets about 150 items), report agreement, and run a sensitivity band recomputing metrics assuming x percent of positives mislabelled [D]. Cohen's kappa only if the owner supplies a second annotator (O2 default: none).
- Ground-truth quality varies by source and matters more once models train on it (https://ar5iv.labs.arxiv.org/html/2210.15079, excerpt).

Calibration with small samples
- Platt scaling (2 parameters) is the default at small n; isotonic needs more data. Niculescu-Mizil and Caruana (ICML 2005, https://mlanthology.org/icml/2005/niculescumizil2005icml-predicting) compare the two and study data requirements; the specific 1000 cutoff was not confirmed [U], and SPEC-28 already labels it a project heuristic. Keep SPEC-28's rule (isotonic only if it beats Platt by more than one SE of inner-CV Brier).
- Beta calibration (Kull et al.): no source retrieved [U]; ablation candidate only.
- With about 100 lineages and about 20 real-fix cards, the honest ceiling is ranks and bands, never a probability display (matches LBL plan s1). Reliability diagrams with intervals; ECE only with the bin-count caveat in SPEC-28 s9.
- Conformal / Learn-then-Test is a cross-check only; exchangeability fails under toolchain shift (SPEC-28 s9.4).

## Numbers to target (with sources)

| Tool / benchmark | Metric | Figure | Source | Comparable to ours? |
|---|---|---|---|---|
| jTrans on BinaryCorp-3M, pool 32 | MRR / Recall@1 | about 0.970 / 0.949 (jTrans); Genius 0.583 / 0.478 [U] | https://arxiv.org/pdf/2205.12713 (excerpt) | Context only. SimCLF reports SAFE 0.902 / 0.843 and Asm2Vec 0.768 / 0.701 on the same setup, far above jTrans's own SAFE/Asm2Vec figures, so baselines differ by paper (https://arxiv.org/pdf/2209.02442) [U] |
| jTrans on BinaryCorp-3M, pool 10,000 | MRR / Recall@1 | Gemini 0.165 / 0.132; SAFE 0.320 / 0.246; Asm2Vec MRR 0.072 [U] | https://arxiv.org/pdf/2205.12713 | Shows the pool-size effect |
| jTrans recall correction | Recall@1 | FastBCSD says jTrans's reported Recall@1 had an error and recomputes 0.538 (pool unstated) [U] | https://arxiv.org/pdf/2306.14168 | Published numbers get corrected; cite versions |
| BinDiff vs DeepBinDiff (VEXIR2Vec table, ARM, Clang 12) | precision | Diffutils BinDiff 0.37/0.41 vs DBD 0.24/0.27; Findutils 0.11/0.34 vs 0.31/0.32; Coreutils 0.08/0.08 vs 0.17/0.18 (column meaning unconfirmed) [U] | https://arxiv.org/pdf/2312.00507 | Indicative only: cross-ISA/opt, not patch diffs |
| DeepBinDiff (authors) | recall / precision vs BinDiff, cross-version | claims +23 percent recall and +7 percent precision [U] | https://www.ndss-symposium.org/wp-content/uploads/24311-slides.pdf | Author claim; nearest to version diffing |
| Asm2Vec | Precision@1 / Recall@1 | third-party study found it below BinDiff in several opt pairings (Recall@1, five programs) [U] | https://arxiv.org/pdf/2103.12357 (excerpt) | Different metric from lead-list hit@k; do not pool |
| QBinDiff | precision / recall vs ground-truth mappings | Paper says it beats other methods on both, biggest gap on more different programs; no numbers retrieved [U]. BinDiff is the only compared tool that can leave pairs unmatched, so they stress recall | https://arxiv.org/pdf/2112.15337 , https://arxiv.org/pdf/2112.15336 | Same abstention issue as ours: report coverage next to precision |
| Diaphora | none found as a benchmark | n/a | search found only case studies and a maintainer claim | No external number to target |
| Windows patch-diff localisation | none found | n/a | no benchmark found | We would set a first small local baseline; claim no parity with any published number |

Our own targets [D]: hit@1/3/10, MRR, nDCG@10 per engine with lineage-level CIs; random and similarity-sort baselines in the same table; A/A rejection rate near alpha; coverage-vs-precision curve for abstaining engines; pool size and denominators in every table. No published number is a pass/fail bar for patch localisation; function-matching figures (jTrans, Asm2Vec, DeepBinDiff) answer cross-compiler identity and appear as context only.

## Pitfalls

- Compiler/optimisation confounds: compile options and tool correctness materially change BCSA results (https://arxiv.org/pdf/2011.10749). In patch diffing the confound is a toolchain or flag change between old and new builds, which makes thousands of functions look changed. Record `toolchain_changed`; keep a same-source/different-flags control (nuisance controls and `BuildInfo` truth, LBL plan s4).
- Inlining: binary functions are often one-to-many with source functions (inlining ratio 30-40 percent at O3, up to 70 percent with LTO, about 4 inlined source functions per binary function: https://arxiv.org/pdf/2112.12928, excerpt). A fix in an inlined helper shows up in every caller. Score localisation as "fix lies among changed binary functions covering the fixed source", and make the one-to-many rule explicit.
- LTO: whole-program cross-unit inlining reshapes the call graph (https://arxiv.org/pdf/2608.10043, excerpt); BinKit has an LTO subset. Keep LTO on/off as a stratum; do not average.
- PGO: no source found [U]. Mechanically, profile-guided builds change block layout, hot/cold splitting and inlining between builds differing only in profile [D, hypothesis]; treat as a nuisance stratum and test a PGO-on vs PGO-off planted pair before claiming robustness.
- Function boundaries and tool error: boundary recovery is hard (TSE paper above); use PDB/DWARF for answer keys but evaluate stripped images.
- Benchmark comparability: private benchmarks, different pool sizes and baselines, later corrections (FastBCSD note). Never compare across papers without matching task, pool and split.
- Duplication: vendored libraries, repeated rebuilds of one upstream and identical functions across versions leak across splits [D].
- Label noise in source-side vulnerability datasets (BigVul, Devign) is widely discussed [U]; do not treat them as localisation ground truth.
- Selection bias in our cards: CVE-fix cards are the ones with clean public fixes; say the population is not Windows patch-diff reality.
- Small n: intervals are wide (see power); single-lineage wins are anecdotes.

## Recommendations for our plan

1. Keep Tier R (pinned permissive upstreams, our own builds) as the training/eval corpus. Use BinKit and Assemblage only as optional external robustness checks, built from scripts or fetched locally, never redistributed, after a per-item licence read.
2. Add dedup-by-hash and project-first, then time, splits to the evalcore spec. Add the lineage-level paired permutation test, Holm correction and jackknife minimum to `docs/plans/c9-preregistration-v1.md` as the primary contrast.
3. Pre-register hit@3 per lineage as primary, MRR and nDCG@10 as secondary; require random and similarity-sort baselines in every report.
4. Define localisation truth so inlining counts (source fix mapped to covering binary functions). Tag lineages by LTO, opt level, PGO and toolchain-change strata; add LTO and PGO planted pairs to the mutation operators if the toolchain allows.
5. Treat results at n<=100 lineages as regression gates plus descriptive; put "cannot detect improvements below about 10 percentage points" in the honest-scope artifact.
6. Calibration: Platt or bands; isotonic and beta only as ablations when pooled effective positives are far larger; no probability display (consistent with the current verdict).
7. Report coverage with precision for every abstaining engine (the QBinDiff/BinDiff abstention distinction is the reference).
8. Cite published figures only as context with their pool, task and version.
9. Tier W stays local; the only exportable item is the owner-approved aggregate.

## Open questions

- Licences of BinaryCorp, BinKit data, BigVul, Devign and Debian/Alpine tooling were not read at primary sources.
- Primary-paper numbers (jTrans, QBinDiff, DeepBinDiff, Asm2Vec) could not be fetched; check the PDFs before quoting anything in a report.
- Is there any public benchmark scoring patch localisation (fix-function rank) on binaries? None found; a further search on security-patch identification (e.g. BinGo, https://arxiv.org/pdf/2312.07921) may help.
- PGO effects on diffing: no source; needs a small experiment.
- Isotonic-vs-Platt sample cutoff unconfirmed; beta calibration reference not retrieved.
- Owner decisions still open: O1 (what Tier W aggregates may leave the machine), O2 (second annotator), how much of the Assemblage licensed subset may be used locally.
- Do about 20 real-fix cards in 13 lineages give enough variety per CWE for any stratum claim? Probably not; confirm with evaluator output.
