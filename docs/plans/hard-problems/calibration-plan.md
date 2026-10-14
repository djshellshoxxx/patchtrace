# Calibration plan (C9): calibrated P(function pair is correct) without redistributable Microsoft binaries

Date 2026-10-14. Specs: SPEC-28 `docs/specs/calibration-corpus-and-model.md` (wins on methodology), SPEC-27. Evidence base and tags (V/M/X): `docs/research/phase-c/matching-calibration-ground-truth.md`. Fixes when something misbehaves: `calibration-troubleshooting.md`. GUI stays at display level L0 until a locked-test gate passes (SPEC-28 sect. 12).

## 1. What can and cannot be done
| Work | Zero real data | Needs people / budget / legal |
|---|---|---|
| Contracts, loaders, schemas, artifact safety, policy ordering | yes | - |
| `mathcore` (IRLS, PAV, Platt), metrics, cluster bootstrap, OOD, report/gates | yes, on synthetic worlds | - |
| Proof that grouped CV detects planted leakage; gates fail on a miscalibrated model; ECE null simulation | yes | - |
| Tier R pipeline end to end (build, engines, PDB truth, fit, report, load) | yes, open-source code only (needs a Windows runner for MSVC; clang-cl/mingw on Linux) | CI runner time |
| Honest numeric gate G1 (pipeline on Tier R) | yes | - |
| Claim about real Windows patch pairs (G2/G3 on Tier W) | no | Winbindex downloads, legal answer O1, labelling ~150 h (O4), second annotator (O2) |
| Any user-visible number or band | no | G2/G3 pass + owner sign-off |
Rule: zero-data work may reach "pipeline proven, display L0". It can never justify L1/L2.

## 2. Ordered steps with decision points
| # | Step | Output | Done when (measurable) |
|---|---|---|---|
| 0 | Read LICENSE/data cards: BinKit, BinaryCorp, REFuSe-Bench, Assemblage, FuncPEval, Winbindex, upstreams of every Tier R pin; read the Microsoft symbol-server licence text | `calibration-licences.md` table with URL + date + reading | Each source is `ok-redistribute`, `ok-local`, or `no`; unknown counts as `no` |
| 0b | **Decision D0** (owner O1/O2/O4/O6) | Written answers in docs/qa.md | No answer = Tier W labels local-only, claim cap L1, clang-cl/mingw allowed in CI |
| 1 | Ratify SPEC-28 with corrections (research note sect. 7); draft preregistration | `c9-preregistration-v1.md` with SHA | Citation table has no `M` in claims that gate decisions |
| 2 | Contracts C9-1 and tools C9-2 | strict loaders, negative tests, in-tree-PE guard | Duplicate keys/NaN/oversize/bad digest tests red then green |
| 3 | `mathcore`, metrics, bootstrap (C9-6/7) | stdlib fitter | Within 1e-4 of scikit-learn LR, isotonic knots equal, PAV property tests; ECE null simulation script |
| 4 | Simulations (leakage, shift, miscalibration, weights) | pass/fail tests | Grouped-CV gap vs random-CV exceeds preset on planted dependency; gates flag the broken model |
| 5 | Tier R corpus (C9-3): patch-tag pairs of 8-12 permissive C libraries x {MSVC or clang-cl, mingw} x {O1,O2,/GL} x {with/without PDB}; PDB-derived labels; symbols-hidden engine runs | manifest + labels + report | >= 40 lineages in total is not required here; require >= 12 lineages, >= 2000 natural candidates, symbol-label audit error <= 2% |
| **DP1** | Tier R G1: do H1-H5 numbers hold on Tier R? | go / fix / stop | **go**: all pass with cluster CIs. **fix**: troubleshooting. **stop**: Ghidriff-only M0/M1 is not beaten (H4) on Tier R; then calibrate M1 only and ship bands at most |
| 6 | Shipped `features/predict/policy/artifact` (C9-5, C9-9) behind hidden flag | `experimental` artifact only | Train/serve golden vectors identical; frozen EXE loads it |
| **DP2** | Acquire Tier W? Only if D0 answered, budget allocated, DP1 = go | proceed / park | Park is a valid end state: ship L0 with experimental Tier R model labelled "open-source code only" |
| 7 | Tier W manifest, lineage clustering, sampling (committed list) | lineage report | Component-size distribution reported before any threshold; >= 40 lineages, >= 10 families or the run is `insufficient-data` |
| 8 | Labelling: symbol-hidden PDB labels + blind human strata; kappa study | label set SHA | kappa >= 0.80 (CI lower >= 0.70), indeterminate <= 5% |
| **DP3** | Freeze preregistration (hash), then **one** locked-test run | report SHA | No look at locked-test before this; second run refused |
| 9 | Gates G2 (L1 bands), G3 (L2 number) | promote or publish blind spots | Numbers in SPEC-28 sect. 12 plus the changes below |

Gate additions to SPEC-28 sect. 12 (from research): (a) H2 uses fixed-sequence Learn-then-Test over descending taus on locked-test with design-effect n, in addition to cluster CI; (b) ECE threshold set from a null simulation at the observed weights/effective n, with debiased l2 reported; (c) add raw-bytes baseline M0b; H4 must beat max(M0, M1, M0b) at equal coverage; (d) group by function identity as well as lineage.

## 3. Data-acquisition options (ranked: legality first, then cost)
| Rank | Option | Legality | Cost | Fidelity to Windows patch pairs | Note |
|---|---|---|---|---|---|
| 1 | Patch-tag builds of permissive C libs, PDB truth, built locally | publish recipe + hash only | low (CI) | medium: real small patches, not system code | Tier R backbone |
| 2 | Microsoft open-source repos built with MSVC (dotnet/runtime native, terminal, WIL, STL) | recipe only; licences to be read | low-medium | medium-high: real MSVC output and idioms | add after 1 |
| 3 | vcpkg ports, ReactOS, Wine PE modules | recipe only; upstream licences vary | medium | medium | breadth and Windows-API shape |
| 4 | Assemblage / REFuSe-Bench / DeepHistory downloads | **unknown until step 0** | low | high for Windows PE, but no patch-pair labels | use as control, cross-version lineage design, raw-bytes baseline |
| 5 | Winbindex-guided Microsoft binaries, PDBs from the symbol server, local-only | local research use; terms unread; never published | medium (download, disk, labelling 150 h) | highest | only route to the real claim; needs D0 |
| 6 | Third-party or partner corpora under NDA | contract | unknown | varies | out of scope without owner |
Never: scraping redistribution sites, committing PE/PDB, AI-written labels.

## 4. Risks
| Risk | Effect | Mitigation / fallback |
|---|---|---|
| Ghidriff-only already near target precision | H4 unreachable; calibration adds nothing | Report honestly; ship ordinal labels; consider cheap abstention features instead |
| Lineage collapse (shared CRT) | too few groups | Raise overlap threshold stepwise (recorded); outcome "cannot reach G0" is valid |
| Symbol circularity | inflated accuracy | symbols-hidden runs; audit; demote symbol labels at > 2% error |
| ICF/thunks/PGO corrupt PDB truth | label noise | build flags (`/OPT:NOICF`, `/INCREMENTAL:NO`) in one profile and keep ICF in another with its own subtype |
| Tier R unrepresentative | numbers do not transfer | label as "open-source code only"; no L2 from Tier R |
| Toolchain / engine drift | model invalid | calibration_domain with versions, expiry, soft OOD flag; drift test (troubleshooting) |
| Few annotators | kappa unmeasurable | test-retest + symbol agreement; cap at L1 |
| Legal unknowns (O1, symbol-server terms) | cannot ship or publish | keep Tier W local; ship only coefficients after review; park at DP2 |
| Cluster bootstrap with few lineages | intervals too narrow | G0 >= 30; jackknife; design-effect binomial bounds |
| Single-implementation numerics bug | wrong fit | scikit-learn cross-check; property tests |

## 5. Acceptance (all measurable, computed by `report.py`)
- Zero-data milestone: Tier R end-to-end under 60 s in CI; report byte-identical on rerun; simulations (a)-(e) of SPEC-28 sect. 13 pass; no artifact above `experimental`.
- L1 (bands): precision >= 0.95 (CI lower >= 0.90, width <= 0.10), coverage >= 0.40 (CI lower >= 0.30), Brier skill CI lower > 0, FDR reduction vs best baseline CI lower > 0, stratum precision lower >= 0.85 where n >= 200, OOD risk ratio CI lower > 1 or hard flags reduced, locked-test run once.
- L2 (number rounded down to 5%): L1 plus ECE point <= 0.03 and upper <= 0.05 **and** above null-simulated ECE by margin, slope/intercept CIs contain 1/0, shift-test precision >= 0.90, independent rebuild reproduces the report SHA, owner sign-off.
- Anything failing or `insufficient-data` keeps the highest fully passed level; failure is published as a blind spot.

## 6. Fallbacks
1. Cannot reach L1 on Tier W: ship L0 ordinal labels plus contested/unknown logic (already implemented); publish the Tier R report and corpus recipe as the contribution.
2. Only Ghidriff data: calibrate profile `G` alone; multi-engine profiles abstain (`no-model`).
3. Labels too costly: restrict to a narrower population (one product family) and say so in `calibration_domain`; do not generalise.
4. Bands without numbers: choose bands-only forever (O3) if CI width never reaches <= 0.06.
5. Isotonic unstable: Platt only; Venn-Abers as a later option.
