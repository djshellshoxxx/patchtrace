# Phase C research: calibrated function-match confidence and reproducible ground truth

Date: 2026-10-14. Scope: how other projects handle binary function-similarity benchmarks, Windows coverage, calibration with grouped CV, and reusable fitters. Input spec: `docs/specs/calibration-corpus-and-model.md` (SPEC-28 draft).

Method and limits: about 13 sources, skimmed. arxiv.org was unreachable from this sandbox (DNS failure), so every arXiv claim below is either from a search-result snippet or marked unverified. No code was run and no repository was cloned.

## 1. Findings table

Status key: **V** = checked in this session (page or search snippet); **U** = not verified, from memory or spec only.

| # | Source | Link | License | Status | Relevance to PatchTrace |
|---|---|---|---|---|---|
| 1 | BinKit (SoftSec-KAIST) | https://github.com/SoftSec-KAIST/BinKit | Not confirmed (read LICENSE before reuse) | V (coverage via jTrans snippet), U (license) | 51 GNU packages, 1,352 compile options, about 243k binaries, about 36M functions, ELF/Linux. No Windows. Useful as a compiler-option grid for profile strata, not as a Windows truth set. |
| 2 | jTrans / BinaryCorp, arXiv 2205.12713 (ISSTA 2022) | https://arxiv.org/abs/2205.12713 | Unknown (check repo) | V (title), U (venue, dataset details) | BinaryCorp is the usual large function-pair corpus. Check how its train/test split groups functions. Its split is likely function-level, which is the leakage pattern section 4.1 of the spec warns about. |
| 3 | REFuSe-Bench, "Is Function Similarity Over-Engineered? Building a Benchmark" (Saul et al.), arXiv 2410.22677, NeurIPS 2024 poster | https://arxiv.org/html/2410.22677v1 | Unknown | V (abstract via search snippet) | Explicitly targets Windows data, deduplication and labelling problems, and includes real malware. Its raw-bytes baseline is competitive. Use it as (a) a calibration control model, and (b) a dedup protocol reference. This contradicts the spec's "no Windows benchmark" claim (section 17). |
| 4 | Winbindex | https://github.com/m417z/winbindex | GPL-3.0 (verified on repo page) | V | Indexes metadata and download links only. Binaries are served from the Microsoft public symbol server (msdl.microsoft.com). Matches the spec's Tier W design (manifest of hashes plus fetch recipe). Copying its code into a non-GPL tree would be a license decision. |
| 5 | scikit-learn | https://github.com/scikit-learn/scikit-learn | BSD-3-Clause (verified, COPYING) | V | Dev-only cross-check for LR, isotonic and Platt, as the spec's optional `calibration-dev` extra proposes. Its isotonic code is Cython, not pure Python. |
| 6 | Niculescu-Mizil & Caruana, "Predicting Good Probabilities with Supervised Learning", ICML 2005, pp. 625-632, doi:10.1145/1102351.1102430 | https://mlanthology.org/icml/2005/niculescumizil2005icml-predicting | Paper (no code license) | V (metadata, abstract summary) | Isotonic beats Platt when data is plentiful; Platt is better with little data. Supports choosing a calibrator by sample size. The 1000/1000 threshold in spec section 8 is a project heuristic, not a number from this paper. |
| 7 | Angelopoulos, Bates, Candès, Jordan, Lei, "Learn then Test: Calibrating Predictive Algorithms to Achieve Risk Control", arXiv 2110.01052 | https://arxiv.org/abs/2110.01052 | Paper | V (authors, title, content via search snippet) | Treats a risk target (for example precision >= 0.95 on a threshold grid) as multiple hypothesis tests on a held-out set, with finite-sample guarantees. This is the cleanest way to pick the tau in spec section 9 with a stated error rate. |
| 8 | Angelopoulos & Bates, "A gentle introduction to conformal prediction...", arXiv 2107.07511 | https://arxiv.org/abs/2107.07511 | Paper | U (fetch failed) | Standard reference for split conformal and its exchangeability assumption. Relevant to the spec's conformal cross-check (section 9.4). |
| 9 | Pure-Python isotonic options | (search) | Not found | V (negative result) | No permissively licensed, maintained pure-Python PyPI isotonic package was found. R `isotone` is GPL-2. sklearn is BSD-3 but Cython. PAVA is about 40 lines, so writing it in-repo, as the spec decides in section 7.1, is the right call. |
| 10 | Haq & Caballero, "A Survey of Binary Code Similarity", arXiv 1909.11424 (ACM CSUR 2021) | https://ar5iv.labs.arxiv.org/html/1909.11424 | Paper | V (existence and title via search) | Survey of the benchmark landscape. Use it to map which corpora cover PE. |
| 11 | Kim et al., "Revisiting binary code similarity analysis using interpretable feature engineering and lessons learned", arXiv 2011.10749 | (arXiv, mirror via search) | Paper | V (title via search), U (body) | Argues that simple, interpretable features are competitive. Supports the spec's per-engine feature-family approach (section 6). |
| 12 | Diaphora | https://github.com/joxeankoret/diaphora | GPL-2.0 (U, check repo) | U | Practical diff engine. Its match-quality heuristics are a useful reference for the feature-family schema, but there is no published calibration. |
| 13 | BinDiff concepts doc | https://github.com/google/bindiff/blob/main/docs/concepts.md | Apache-2.0 (U) | U | Reference for what the engine's similarity and confidence fields actually mean. Spec section 1 relies on this. |

Not found within budget: a verified public source for ground truth from PDB/debug symbols on PE binaries, and for a Diaphora-style evaluation protocol. Both stay open (see section 5).

## 2. Ideas worth adopting

1. **Dedup before splitting (REFuSe-Bench, row 3).** Identical bodies across lineages are the main leakage route. The spec's 4.5 already counts them in a "seen-body" stratum. Make the dedup key relocation-masked body hash, and report pairs removed by dedup separately from pairs removed by label rules.
2. **Raw-bytes baseline as a control (row 3).** Add a model that only uses function bytes (or a normalized byte n-gram) as M0 next to the spec's M0/M1/M2. If the engine-feature model cannot beat it under grouped CV, the calibrated confidence adds little.
3. **Fixed-sequence risk control for tau (row 7).** Sort candidate thresholds from strict to loose, and test each on the locked-test set at level alpha. Stop at the first failure. This gives the spec's "precision >= 0.95" target a stated error rate and replaces ad hoc threshold search. Keep it dev-only for choosing the grid.
4. **Calibrator choice by sample size (row 6).** Keep the spec's rule but record the cutoffs as project constants with a sensitivity table (for example 300, 1000, 3000 effective positives), not as literature facts.
5. **Compiler-option grid as a stratum (row 1).** BinKit's design (many compile options from the same sources) maps to the spec's profile axis. Build Tier R strata the same way, and never mix profiles inside one lineage.
6. **Metadata-only corpus (row 4).** Keep the Winbindex model: publish hashes, identity and a fetch recipe, never binaries or PDBs. This is what section 3.4 requires.

## 3. Pitfalls

1. **Function-level splits in disguise.** A function appears in several candidate pairs (many-to-one, one-to-many). If the group is the lineage but not the function, one function can sit in both train and test through a different pair. Group by lineage AND union the function identities that link candidates (union-find over function endpoints, not just binaries).
2. **Lineage collapse.** Shared CRT and statically linked code can merge all Windows system DLLs into one component (spec section 4.2 already flags this). A single giant component gives one fold and makes grouped CV unusable. Report the component size distribution before any threshold is chosen.
3. **Few-group bootstrap.** Cluster bootstrap with few lineages is anti-conservative (spec section 15). The spec's G0 of 30 is a reasonable floor. Also report the jackknife, as it does.
4. **Calibration on symbol-derived labels.** If PDB-derived labels coexist with features computed from the same symbols (names, types), the model learns the labeller, not the function. Spec section 4.5 covers this. Keep a symbol-free feature set for the headline.
5. **Exchangeability breaks under lineage shift.** Split conformal (row 8) assumes exchangeable data. Lineage-level shift breaks that, so conformal coverage on the locked test does not carry over. Treat conformal as a cross-check only, as the spec says, or use weighted variants (Tibshirani et al. 2019, Barber et al. 2023; spec S17, unverified).
6. **Selective classification on the test set.** Choosing the abstention rule after seeing risk-coverage curves on the locked test is the same error as choosing tau there. The spec's section 2.6 forbids it; keep it in code review.
7. **Benchmark numbers on ELF are not Windows evidence.** BinKit and BinaryCorp results (rows 1-2) do not transfer to PE with MSVC or clang-cl code. Use them only as method references.
8. **Engine version drift.** The model's `calibration_domain` (spec section 10) must include engine versions. A BinDiff or rz-diff update changes scores without changing the code.

## 4. Citation verification (spec section 17)

| Spec ref | Claimed | Status |
|---|---|---|
| S1 | BinDiff concepts doc and differ.cc | Concepts doc URL is plausible (U). differ.cc not checked. |
| S3 | Platt 1999, "Probabilistic outputs for SVMs..." | U. Believed correct (Advances in Large Margin Classifiers, 1999). |
| S4 | Niculescu-Mizil & Caruana, ICML 2005 | **V** (title, venue, pages). Zadrozny & Elkan KDD 2002 is U; the isotonic paper is "Transforming classifier scores into accurate multiclass probability estimates". Spec lacks the title. |
| S5 | Brier 1950; Murphy 1973; DeGroot & Fienberg 1983 | U. Believed correct. |
| S6 | Naeini et al. AAAI 2015 (ECE) | U. Believed correct. |
| S7 | Guo et al. ICML 2017 | U. Believed correct. |
| S8 | Nixon et al. CVPR-W 2019; Kull et al. 2017; Van Calster et al. 2019 | U. Believed correct. Venue details unchecked. |
| S9 | El-Yaniv & Wiener JMLR 2010 | U. Believed correct. |
| S10 | Geifman & El-Yaniv NeurIPS 2017 | U. Believed correct. |
| S11 | Cameron, Gelbach, Miller 2008; Efron & Tibshirani 1993 | U. Believed correct. |
| S12 | Roberts et al. Ecography 2017 | U. Believed correct. |
| S13 | Kapoor & Narayanan, Patterns 2023; Allamanis, Onward! 2019 | U. Believed correct. |
| S14 | Vovk, Gammerman, Shafer 2005 | U. Believed correct. |
| S15 | Angelopoulos & Bates 2021 | Title matches arXiv 2107.07511 per memory (U, fetch failed). |
| S16 | Learn then Test (2021); conformal risk control (2022) | **V** for Learn then Test (authors, arXiv 2110.01052, 2021). Conformal risk control is U. |
| S17 | Barber et al. Ann. Stat. 2023; Tibshirani et al. NeurIPS 2019 | U. Believed correct. |
| S18 | Lee et al. NeurIPS 2018; Hendrycks & Gimpel 2017 | U. Believed correct. |
| Binary | Flake DIMVA 2004; Dullien & Rolles SSTIC 2005; Diaphora | U. Believed correct. |
| Binary | Haq & Caballero, CSUR 2021 | **V** (exists, arXiv 1909.11424). |
| Binary | Kim et al. arXiv 2011.10749 | **V** (title matches). The spec calls it "BinKit/TikNib"; the paper is about interpretable features, and BinKit is the dataset. Reword. |
| Binary | jTrans / BinaryCorp arXiv 2205.12713 | **V** (title). Spec's ISSTA 2022 venue is U. |
| Binary | Marcelli et al. USENIX Security 2022 | U. Believed correct. |
| Binary | "Is function similarity over-engineered?" arXiv 2410.22677 | **V** ID is right, but the full title is "...Building a Benchmark" (REFuSe-Bench, Saul et al.). |

**Wrong or misleading in the spec:**
- Section 15 and 17 say published benchmarks "none supplies ... Windows". REFuSe-Bench (2410.22677) does use Windows data. The lesson must be narrowed to "no public corpus with Windows patch-pair labels for calibration was found" (not verified beyond row 3).
- Section 8 attributes the 1000/1000 isotonic threshold to [S4]. S4 does not state that number. Mark it as a project heuristic.
- Section 15 says BinKit "has no Windows binaries". Consistent with jTrans's description (GNU packages), but the license is not confirmed. Mark as unverified.
- Section 4.1 cites S12 for "block/cluster CV is the standard remedy". Roberts et al. is an ecology paper. It supports the idea, but a binary-similarity or ML-leakage source (S13) is the stronger citation.

## 5. Ideas the spec should change

1. Group by function identity as well as by lineage (pitfall 1).
2. Add a raw-bytes baseline (adopt idea 2).
3. Replace the open-ended tau search with a fixed-sequence test (adopt idea 3), and cite row 7.
4. Add the REFuSe-Bench reference as a Windows comparison point, and cite it for dedup.
5. Add the Winbindex license (GPL-3.0) to the legal section (O1), since the spec's Tier W tool depends on its approach.
6. Replace "none on Windows" with a narrower claim.

## 6. Open questions

1. Read the LICENSE and README of SoftSec-KAIST/BinKit and the jTrans/BinaryCorp repository. Does either allow redistribution of derived labels?
2. Read REFuSe-Bench's data license and whether its Windows binaries are redistributable. Check whether its dedup key matches spec section 4.5.
3. Is PatchTrace's own license compatible with reusing Winbindex code (GPL-3.0)? Current plan is to reimplement, not copy. Confirm this with the owner (O5 area).
4. Verify the arXiv citations (2107.07511, 2208.02814, 2205.12713, 2011.10749) from a reachable mirror or export.arxiv.org in PR C9-0.
5. Is there a verified public PE ground truth built from PDB/debug info? Not found in this pass. Needs a dedicated search.
6. Does a PE/Windows-specific calibration result exist that supports the 1000/1000 cutoff? Probably not. Treat as a parameter.
7. Engine versions: BinDiff and rz-diff version pinning (spec section 10) should be checked against the Windows test set before C9-6.
