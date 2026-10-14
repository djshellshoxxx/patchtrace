# SPEC-28 (proposed number): Calibration corpus, model pipeline and numeric-confidence gate (plan step C9)

Status: DRAFT methodology for review. Amended 2026-10-14 by the C9 build (section 18): tooling and the shipped runtime exist and are validated on synthetic data only; no real-data claim and no labelling campaign yet. Refines SPEC-27 research items 2-10; where this file and SPEC-27 differ on module placement, this file wins once ratified (SPEC-27 must then be edited in the same PR). Nothing here authorises showing a probability in the GUI; section 12 is the only door to that.

Research caveat: the web fetch tool could not reach arxiv.org from the authoring sandbox, so citations in section 15 are from the author's knowledge of the primary literature and MUST be spot-checked (title/venue/year) in PR C9-0 before ratification. Claims below that depend on a source are marked [S#].

## 1. Scope, unit of prediction, outcome
- Unit: one Ghidriff `FunctionMatch` (candidate pair of function endpoints, SPEC-10 `reconcile._endpoints`; many-to-many and unparsable ones are `not-comparable` and are out of the model, always abstain).
- Target (pre-registered, only this one): `A = 1` iff the older and newer endpoints are the same logical (source-level) function, one-to-one. `P(A=1 | evidence, profile, population)`.
- B (block/edge identity), C (patch mechanism), D (root cause) are reserved in the label schema as `null` and are NOT analysed, NOT calibrated, NOT shown. Any B/C/D work needs a new pre-registration.
- Out of scope forever: P(vulnerability), P(patch is security-relevant), exploitability. High P(A) is never evidence of a bug (SPEC-27 item 8).
- Unaffected invariants: no averaging of engine confidences; `contested` is decided by `reconcile`/`evidence`, never by the model; missing match = unknown; no target binary is executed; nothing uploaded.

## 2. Pre-registered evaluation protocol
Frozen by committing `docs/plans/c9-preregistration-v1.md` (generated from this section + section 12 numbers) and recording its SHA-256 in every report. Any change after the first look at locked-test data creates `v2`, is reported as an amendment, and the v1 result stays in the report.

2.1 Data roles (assigned once, deterministically, by lineage, section 4.4):
- `dev` (about 60% of lineages): model selection, hyper-parameters, calibrator choice, threshold. Nested grouped CV only.
- `locked-test` (about 25%): touched exactly once, by `tools/calibration/run_locked_test.py`, which refuses to run twice for one preregistration SHA (writes a `.lock` receipt in the local corpus dir and the report).
- `shift-test` (about 15%): held-out toolchain/era/product class chosen BEFORE labelling (e.g. one Windows servicing era, one non-MSVC toolchain). Reported separately; failure here is a documented blind spot, not a retry trigger.
2.2 Strata inside each role: `natural` (probability sample of Ghidriff matches, with known inclusion probabilities, section 5.3) and `adversarial` (hand-picked hard negatives, section 5.4). Primary metrics use `natural` only with inverse-probability weights. `adversarial` is a stress test, reported separately, never pooled into the headline.
2.3 Candidate models (the full list; no others may be added after freeze): M0 Ghidriff-only rule (`ratio >= t`); M1 Ghidriff-only L2 logistic; M2 current SPEC-27 index (55/20/8/83) used as a scorer (tests whether the placeholder has any ranking value); M3 multi-family L2 logistic per profile (section 6.3); M4 M3 minus one feature family (leave-one-family-out ablations); M5 optional gradient-boosted ranker, dev-only exploratory, cannot be shipped in v1 artifacts.
2.4 Primary hypotheses (all must hold, section 12 gives numbers): H1 calibration, H2 auto-accept precision, H3 usable coverage, H4 marginal benefit over M0/M1 at equal coverage, H5 no catastrophic stratum.
2.5 Secondary/reporting only: AUC (weighted), log-loss, top-K precision, FDR/recall, per-profile and per-stratum tables, leave-one-engine-out deltas, shift-test results, OOD flag rate vs error rate, annotator agreement, conformal comparison (section 9.4).
2.6 Forbidden: re-using locked-test for any choice; choosing the calibrator, C, bins or threshold after seeing locked-test; dropping groups after labelling for being "noisy" (exclusions only by rules written in the label guideline, counted in the report); training on AI-generated labels (SPEC-27 item 10). LLM tools may be used to build UI/tooling, never to produce or suggest a label that is stored.

## 3. Legal, reproducible corpus design
Assumption: Microsoft binaries and PDBs cannot be redistributed. The repository, releases and CI artifacts never contain them.
3.1 Two tiers.
- Tier R (redistributable, CI-runnable): PE/ELF-free small corpus built from permissively licensed open source (zlib, libpng, sqlite, lua, mbedTLS/others chosen by license check) compiled by a pinned toolchain (clang-cl/mingw-w64 or MSVC on Windows runners) at several versions x optimisation profiles x stripped/with-PDB. Distributed as source pins + build recipe + expected SHA-256 of outputs; outputs themselves may be cached as CI artifacts. Ground truth is exact (debug info/source names) and legal to publish. Weakness: not MSVC-Windows-system-code-like. Used for pipeline CI, regression, ablation, and a labelled public benchmark.
- Tier W (local-only Windows): binaries obtained via Winbindex acquisition already in `src/patchtrace/acquisition/winbindex.py`, stored under a git-ignored root (`PATCHTRACE_CALIB_ROOT`, default `~/.patchtrace-calibration/`). Repo carries only manifests (hashes + identity + fetch recipe) and optionally label files in the reduced form of 3.3.
3.2 Manifest `calibration-corpus/1` (strict JSON, same loader discipline as `acquisition.winbindex.strict_json`: duplicate keys and NaN rejected, pydantic strict `extra=forbid`). Key fields:
```
{ "contract":"calibration-corpus/1","corpus_id":"...","created":"2026-..","tool_git":"<sha>",
  "binaries":[{"id":"b001","tier":"W","file_name":"ntdll.dll","arch":"x64","sha256":"<64hex>","size":N,
     "winbindex":{"timestamp":N,"virtual_size":N,"version":"10.0.x","kb":["KB.."]},   // identity used by existing acquisition
     "pdb":{"guid_age":"...","used_for":"labels-only"|"none"},
     "toolchain":"msvc-unknown","redistribution":"none"},
    {"id":"b101","tier":"R","source":{"git":"<url>","commit":"<sha>","license":"Zlib"},
     "recipe":{"toolchain_digest":"<sha256>","argv":[...],"opt":"O2","strip":true,"env_digest":"<sha256>"},
     "sha256":"<64hex expected>","redistribution":"cc0-derived|license-id"}],
  "pairs":[{"id":"p001","older":"b001","newer":"b002","kind":"adjacent-patch|cross-version|unrelated-control",
     "lineage":"L-ntdll","family_tags":["usermode-dll"],"role":"dev|locked-test|shift-test"}],
  "lineages":[{"id":"L-ntdll","members":["b001","b002"],"cluster_rule":"filename+bodyhash-overlap","cluster_evidence_sha256":"..."}],
  "split":{"salt":"c9-v1","method":"sha256(lineage_id|salt) -> u; table in 4.4"} }
```
`tools/calibration/corpus.py verify` re-hashes every local file against the manifest and fails on any mismatch or on a Tier-W file found inside the git work tree (guard against accidental commit; also a pre-commit/CI grep on PE magic under `tests/` and `docs/` outside `tests/fixtures` allow-list).
3.3 Label files `calibration-labels/1` (JSONL, one record per candidate pair; sidecar to the manifest):
```
{"pair":"p001","match_id":"<ghidriff id>","older":{"rva":N,"size":N,"body_sha256":"<hash of function bytes with relocs masked>"},
 "newer":{...},"A":"same|different|no-counterpart|indeterminate","subtype":"N1..N12|null",
 "B":null,"C":null,"D":null,"source":"human|symbol-derived|synthetic-exact","annotators":["a1","a2"],
 "adjudicated":false,"guideline":"g1","sampling":{"stratum":"natural|adversarial","stage":"S1","p_incl":0.0123},"notes":"free text no MS-derived code"}
```
Published form for Tier W: RVA + body hash + label only; no symbol names, no disassembly, no bytes. Whether even that may be published is a legal question (decision O1); default is local-only for Tier W labels and published for Tier R. Labels are keyed by body hash so they survive Ghidriff re-runs and can be re-joined to a locally acquired binary.
3.4 Reproduction contract: from manifest alone a third party with network access reconstructs Tier R bit-exactly (or reports toolchain drift) and Tier W via Winbindex identity (hash verified; missing files reported, not substituted). Reports state which Tier-W files were unavailable.

## 4. Splitting, groups, leakage
4.1 Why: functions inside one binary, adjacent builds of one product, and statically linked shared code are highly dependent; random function-level splits inflate performance [S12,S13]. Block/cluster CV is the standard remedy [S12].
4.2 Group = lineage: connected components of the union graph over binaries where an edge exists if (a) same `file_name` across builds, (b) same source project (Tier R), (c) >= 15% overlap of relocation-masked function-body hashes (shared CRT/static libs/ATL/WIL code), (d) same PDB name. Computed by `tools/calibration/lineage.py` (union-find, deterministic order); evidence digest stored in the manifest. If clustering merges everything into one component (likely for Windows system DLLs via shared statically-linked code), raise the overlap threshold in steps (15, 30, 50%) and record it; never split a component to improve balance.
4.3 Every metric, CV fold, bootstrap resample and threshold is by lineage. Candidates from the same Ghidriff run never cross folds.
4.4 Role assignment: `u = int(sha256(lineage_id + "|" + salt)[:8],16)/2^32`; `u<0.60` dev, `<0.85` locked-test, else shift-test, then override only to satisfy the shift-test declaration made before labelling (recorded in the preregistration). Minimum content per role in section 12.
4.5 Extra leakage rules: engine-feature standardisation statistics, C, calibrator and OOD statistics are fit inside training folds only; labels derived from symbols must never coexist with symbol-derived features (section 5.2); duplicates across lineages (identical body hash in train and test) are counted and, for the headline, the test candidate is kept but reported in a "seen-body" stratum; a leakage unit test (section 14) proves grouped CV is more pessimistic than random CV on a planted-dependency synthetic set.

## 5. Labelling workflow, tooling and quality
5.1 Guideline `g1` (versioned in `tools/calibration/guidelines/`): A=same iff both endpoints implement the same source-level function, tolerating compiler differences and patch-sized edits; `different` if different functions; `no-counterpart` if the true counterpart is absent from one side (added/removed/inlined away) so any pairing is wrong; `indeterminate` if after the time budget (10 min) the annotator cannot decide; split/merge/partial-inline pairs are `different` with subtype N4 and also reported as their own stratum. y = 1 iff `same`; `different` and `no-counterpart` -> 0; `indeterminate` excluded from fitting but counted: if indeterminate > 5% of a stratum the stratum is flagged and the headline gets a worst-case bound (indeterminate all treated as 0).
5.2 Label sources and circularity.
- `symbol-derived`: private/public PDB names equal and unique in both images, body-size ratio within a bound. Fast and plentiful, BUT Ghidriff matches by names when symbols exist, so symbol-derived labels with symbol-visible engine runs are circular. Rule: symbol-derived labels are valid only for engine runs executed on images with symbols NOT loaded (`symbols-hidden` condition, recorded in `EngineRun`/features as `symbol_provenance="none"`). Audit: 5% random plus 100% of pairs with body-size change > 40% reviewed by a human; report the symbol-label error rate; if > 2% the source is demoted to `weak` and excluded from headline.
- `human`: used for the `symbols-visible` condition and for all adversarial pairs. Annotators see: bytes/disassembly side by side, callers/callees, strings, imports, sizes; they do NOT see any engine's score, verdict or name-match (blinding against anchoring on Ghidriff). Symbol names may be shown only in a second pass after the blind label is recorded; a change after reveal is recorded.
- `synthetic-exact` (Tier R): exact from debug info/source.
5.3 Sampling: per binary pair, stratify candidates by Ghidriff match type x ratio decile x size tercile; sample with recorded inclusion probability `p_incl` (small pairs fully enumerated, p=1). Weights `w = 1/p_incl`. Sampling is seeded by `det_uniform`; the sample list is generated before labelling and committed (hash) to prevent label-dependent stopping. Also sample from `secondary_only` (engine pairs Ghidriff lacks) for diagnostics, outside the headline.
5.4 Negative taxonomy (adversarial stratum quotas, each >= 5% of adversarial items, >= 30 items per subtype in dev before any claim about it): N1 near-duplicate/cloned/template-instantiated functions; N2 thunks, import stubs, jump wrappers; N3 statically linked library/CRT code shared by unrelated functions; N4 inlined/split/merged/partial; N5 address-coincident (same RVA different function after layout shift); N6 similar CFG different semantics (e.g. one changed comparison/constant); N7 added/removed function paired to unrelated; N8 unrelated-binary control pairs (sanity, must be ~all 0); N9 compiler-generated (CFG-guard dispatch, security-cookie, SEH helpers); N10 PGO hot/cold split pieces (`$cold`-like); N11 identical-constant tables/switch/jump-table dominated bodies; N12 same function, large legitimate rewrite (a positive hard case: label `same`, stratum "hard-positive").
5.5 Tooling (`tools/calibration/`, dev-only, no network except `corpus fetch`): `corpus.py {init,fetch,verify,build}`, `sample.py`, `label.py` (local-only static HTML + tiny stdlib HTTP server on 127.0.0.1, or terminal mode; writes append-only JSONL with annotator id, timestamp, time-spent; Qt-free), `agree.py`, `lineage.py`, `fit.py`, `run_locked_test.py`, `report.py`. All write append-only files with SHA-256 chains so edits are detectable.
5.6 Inter-annotator checks: >= 20% of each stratum (min 300 items overall, min 60 per N-subtype where the subtype has >= 60) labelled blindly by two independent annotators; require raw agreement >= 0.95 and Cohen's kappa >= 0.80 on A (kappa and 95% bootstrap CI reported, also per subtype); disagreements go to a third pass/adjudication, recorded `adjudicated=true`. If kappa < 0.80, the guideline is revised, the batch relabelled, and the old batch kept in the report. Also report annotator-vs-symbol agreement as an independent source. If only one annotator exists (decision O2): replace with test-retest on 15% after >= 14 days plus symbol agreement, and the claim level is capped at "stage 2 bands" (section 12).
5.7 Estimated effort (order of magnitude, for planning only): about 6,000 human labels at roughly 1.5 min = about 150 h incl. audits and second-annotator overlap; symbol-derived and Tier R labels are free by comparison.

## 6. Feature-family schema
6.1 Principle: every feature is tagged `{family, engine, depends_on, kind(num|cat|flag), missing_ok}`. Engine-native values are stored RAW and separate (BinDiff similarity and confidence and rz-diff Levenshtein ratio are different algorithms and scales; they are inputs, never averaged, never pre-combined) [S1,S2]. Feature extraction is one shipped pure module (`features.py`) used by both training and the app to prevent train/serve skew.
6.2 Families (v1; schema `features/1`):
- `G` Ghidriff: match type (one-hot from the observed enum), match ratio/quality as persisted in `FunctionMatch`, one-to-one flag, rank of alternatives (exact field names to be confirmed in C9-5 against `models.py`/the Ghidriff export).
- `B` BinDiff: similarity_milli, confidence_milli (from `SecondaryMatch`), algorithm id one-hot (top-K levels plus `other`), flags (G I O J E L C) as 7 booleans, matched blocks/edges ratio and call-neighbourhood agreement only when the importer exposes them (v1: omit, add in v2).
- `R` rz-diff: similarity_milli only; no confidence exists (contract enforces None).
- `S` structure: log function size (both sides), size ratio, basic-block/edge counts and deltas when available, call-out count, is-thunk flag.
- `P` provenance/context: symbol provenance (none|public|private; as an explicit categorical, `none` for symbols-hidden), image arch, toolchain class (msvc|clang|gcc|unknown), engine version bucket.
- `X` cross-engine consistency: `agree_B`, `agree_R` (reconcile status as booleans), `n_alternatives`. `contested` rows are never given to the model; they are routed by policy (section 9.5) and evaluated only as a diagnostic stratum.
6.3 Profiles: the set of engines that produced a comparable row defines the profile: `G`, `G+R`, `G+B`, `G+B+R`. One independent model (and calibrator, threshold, OOD stats) per profile. No imputation, no zero-fill: a profile with no trained model abstains. Profile-specific minimum data in section 12.
6.4 Circular-dependency groups (SPEC-27 item 4). Each feature declares `depends_on` from: `D_ghidra` (Ghidra database/analysis), `D_symbols` (PDB/export names), `D_compiler` (compiler-signature/FLIRT-like identification), `D_callgraph` (matched call graph used by the producing algorithm), `D_bytes` (raw bytes only). Initial table: G -> {D_ghidra, D_symbols, D_callgraph, D_compiler}; B -> {D_ghidra if the BinExport producer is Ghidra else D_ida, D_symbols, D_callgraph}; R -> {D_bytes}; S -> {D_ghidra}. Consequences: (a) report an `independence_index` per profile = number of disjoint dependency sets among engines; G+B with Ghidra-exported BinExport has none, so agreement is not independent corroboration and `X` features are tagged with the union; (b) required ablations: drop all features sharing `D_ghidra`, drop `D_symbols`, and the leave-one-family-out set; (c) any "agreement" claim in UI text derives from the model's marginal gain in those ablations, not from engine count. Also record the BinExport producer in features (`P.binexport_producer`).
6.5 Missing values inside a present family (e.g. optional BinDiff fields): the per-feature `missing_ok` indicator is added as its own flag; numeric value set to the training median stored in the artifact. If a required field is missing, the family is treated as missing and the profile changes.

## 7. Model pipeline modules
7.1 Recommendation (decision, with rationale): implement a tiny pure-Python, stdlib-only fitter in-repo (L2 logistic via Newton/IRLS; PAV isotonic; Platt sigmoid) and treat scikit-learn as an OPTIONAL dev cross-check extra, not as the engine.
| Concern | In-repo pure Python | scikit-learn (+numpy/scipy) |
| Packaging/offline | zero new wheels; PyInstaller unchanged | ~100 MB+ with scipy/numpy in a frozen EXE; hooks, size, notices |
| Determinism | bit-reproducible with fixed op order and `math.fsum` | depends on BLAS/solver versions; lbfgs tolerance differences |
| Runtime need | inference is a dot product + interpolation (needed in app anyway) | not needed at runtime; adds attack surface |
| Fit speed | n up to ~1e5 rows x d<=40: tens of seconds per fit | far faster |
| Correctness risk | must be tested; mitigated by cross-check | vetted |
| Features beyond LR/isotonic | none | gradient boosting, CalibratedClassifierCV |
Mitigation of in-repo risk: `[project.optional-dependencies] calibration-dev = ["scikit-learn>=1.5"]`; tests `pytest.importorskip("sklearn")` assert coefficient agreement (weighted LR within 1e-4 relative at matched regularisation; isotonic knots equal; Platt within 1e-3). Gradient-boosted ranker (M5) is exploratory, dev-only; it ships only if a later spec defines a JSON tree format and shows material benefit. Runtime never imports numpy/sklearn.
7.2 Layout.
Ships in the app (`src/patchtrace/calibration/`, per the frozen build seam; pure, no Qt, no network, no numpy): `features.py` (schema + extraction from `ReconciliationReport`/`SecondaryMatch`/`FunctionMatch`), `artifact.py` (strict pydantic model of the artifact, loader, digest check), `predict.py` (standardise, logit, Platt/isotonic apply, profile select), `ood.py` (apply stored OOD spec), `policy.py` (accept/review/abstain given p, flags, contested, thresholds), `provenance.py` (builds the export block). Total target < 600 lines.
Dev-only (`tools/calibration/`, not imported by `src/`, excluded from PyInstaller): corpus/label/sampling/lineage tools, `mathcore.py` (logistic, PAV, Platt, solvers), `cv.py`, `metrics.py`, `bootstrap.py`, `ood_fit.py`, `fit.py`, `report.py`, `run_locked_test.py`, guidelines, synthetic generators. This amends SPEC-27's "future secondary/calibration/{labels,train,metrics,drift}" placement: training and labels do not ship. `predict`/`drift` stay in src.
Tests of tools: add `tools` to a test-only import path (e.g. `tests/conftest.py` inserts it, or put the shared code under `tools/calibration/__init__.py` as a package); follow whatever the existing tool tests do (check in C9-6).
7.3 Determinism rules: no `random` module state; `det_uniform(seed, *key) = int(sha256("|".join(map(str,(seed,)+key)))[:13],16)/2**52` (52 bits: exact and strictly < 1.0; the earlier `[:16]/2**64` form can round to 1.0); sort every iteration by stable ids; sums with `math.fsum`; fixed iteration counts; no threading in fit; floats serialised with `repr` rounded to 12 significant digits; prediction output rounded to 1e-6 before any threshold comparison, and thresholds stored with 6 decimals.

## 8. Full pseudocode: fit, calibration, CV
```python
def det_uniform(seed, *key):                       # platform-independent PRNG substitute
    h = sha256(("|".join(map(str, (seed,) + key))).encode()).hexdigest()
    return int(h[:13], 16) / 2**52                 # 52 bits: exact, strictly < 1.0 (amended)

# ---- rows: dict(id, group, x:list[float], y:0|1, w:float, stratum, profile) ----
def grouped_kfold(rows, k, seed):                   # balanced greedy over groups, deterministic
    groups = {}                                     # group -> (weight_sum, n_neg_weight)
    for r in rows: groups.setdefault(r.group, [0.0, 0.0]); groups[r.group][0] += r.w; groups[r.group][1] += r.w*(1-r.y)
    order = sorted(groups, key=lambda g: (-groups[g][0], det_uniform(seed, "g", g), g))
    folds = [[] for _ in range(k)]; load = [0.0]*k; neg = [0.0]*k
    for g in order:                                 # LPT: place in fold with least (load, neg)
        f = min(range(k), key=lambda i: (load[i] + 0.5*neg[i]*K_NEG, i))
        folds[f].append(g); load[f] += groups[g][0]; neg[f] += groups[g][1]
    assert all(folds), "fewer groups than folds -> refuse (see section 12 minimums)"
    return folds                                    # list of group-sets

def standardise_fit(X, w):                          # per column weighted mean/sd; sd floor 1e-9; flags untouched
    ...
def fit_logistic_l2(X, y, w, C, iters=50, tol=1e-10):
    n, d = len(X), len(X[0]); beta = [0.0]*(d+1)    # beta[0] intercept, unpenalised
    lam = 1.0 / C
    for _ in range(iters):
        g = [0.0]*(d+1); H = [[0.0]*(d+1) for _ in range(d+1)]
        for xi, yi, wi in zip(X, y, w):
            z = beta[0] + fsum(b*v for b, v in zip(beta[1:], xi))
            p = sigmoid(z); s = wi*p*(1-p); r = wi*(p-yi)
            u = [1.0] + xi
            for a in range(d+1):
                g[a] += r*u[a]
                for b in range(a, d+1): H[a][b] += s*u[a]*u[b]
        for a in range(1, d+1): g[a] += lam*beta[a]; H[a][a] += lam
        symmetrise(H); H[0][0] += 1e-9
        step = cholesky_solve(H, g)                 # raises if not SPD -> increase ridge, never silently continue
        beta = [b - s for b, s in zip(beta, step)]
        if max(abs(s) for s in step) < tol: break
    return beta                                     # loss = weighted logloss + lam/2*|beta[1:]|^2

def logit_score(beta, x): return beta[0] + fsum(b*v for b, v in zip(beta[1:], x))

def fit_platt(s, y, w):                             # Platt 1999 with target smoothing
    Np = fsum(wi for wi, yi in zip(w, y) if yi); Nn = fsum(w) - Np
    tp, tn = (Np+1)/(Np+2), 1/(Nn+2)
    t = [tp if yi else tn for yi in y]
    # minimise weighted cross-entropy of sigmoid(a*s+b) against soft targets t (2-param Newton, 100 iters, backtracking)
    return a, b

def fit_isotonic(s, y, w):                          # weighted PAV, then clip
    pts = sorted(zip(s, y, w), key=lambda t: t[0])  # tie-break: merge equal s first (weighted mean)
    blocks = [[sv, wy := w_*y_, w_] for sv, y_, w_ in merge_ties(pts)]   # [score_max, sum_wy, sum_w]
    stack = []
    for b in blocks:
        stack.append(b)
        while len(stack) > 1 and stack[-2][1]/stack[-2][2] >= stack[-1][1]/stack[-1][2]:
            top = stack.pop(); stack[-1][0] = top[0]; stack[-1][1] += top[1]; stack[-1][2] += top[2]
    knots = [(blk[0], clip(blk[1]/blk[2], EPS, 1-EPS)) for blk in stack]   # EPS = 1/(sum_w+2)
    return knots                                    # predict: linear interp between knots, clamp outside (monotone)

def predict_iso(knots, s): ...                      # bisect, linear interpolation, clamp

# ---- nested grouped CV: outer for honest estimate, inner for OOF scores to fit calibrator ----
def nested_cv(dev_rows, profile, cfg):              # cfg frozen by preregistration
    outer = grouped_kfold(dev_rows, cfg.K_OUTER, cfg.seed)             # K_OUTER = 5
    oof_final = {}                                                      # row.id -> calibrated p (outer OOF)
    for i, test_groups in enumerate(outer):
        tr = [r for r in dev_rows if r.group not in test_groups]; te = [r for r in dev_rows if r.group in test_groups]
        best = None
        for C in cfg.C_GRID:                                            # (0.01, 0.1, 1, 10)
            inner = grouped_kfold(tr, cfg.K_INNER, cfg.seed + 1)       # K_INNER = 5
            sc = []                                                     # inner OOF logits
            for j, ig in enumerate(inner):
                a = [r for r in tr if r.group not in ig]; b = [r for r in tr if r.group in ig]
                mu, sd = standardise_fit([r.x for r in a], [r.w for r in a])
                beta = fit_logistic_l2(norm(a, mu, sd), ys(a), ws(a, mode="train"), C)
                sc += [(r, logit_score(beta, norm1(r.x, mu, sd))) for r in b]
            ll = weighted_logloss_calibrated(sc)                        # logloss of Platt-on-OOF (natural rows only, weights w)
            best = min_by(best, (ll, C))                                # ties -> smaller C (more regularised)
        C = best.C
        # final fit of base model on all outer-train; its OOF scores (from inner loop at chosen C) fit the calibrator
        oof_scores = inner_oof_scores(tr, C, cfg)                       # natural stratum only for calibrator input
        cal_type = choose_calibrator(oof_scores, cfg)                   # rule below
        cal = fit_platt(...) if cal_type == "platt" else fit_isotonic(...)
        mu, sd = standardise_fit(...); beta = fit_logistic_l2(norm(tr, mu, sd), ys(tr), ws(tr, "train"), C)
        for r in te: oof_final[r.id] = apply(cal, logit_score(beta, norm1(r.x, mu, sd)))
    return oof_final                                                    # used for metrics, threshold selection, bootstrap

# training weights: natural rows weight w (inverse prob) clipped at 20x median to bound variance; adversarial rows weight 1 for
# discrimination only. Calibrator is fitted on NATURAL OOF rows with weights w, so the intercept shift from adversarial
# enrichment is corrected there. choose_calibrator (1000/1000 is a PROJECT HEURISTIC, not a number from [S4]): isotonic only if natural effective n_pos >= 1000 AND n_neg >= 1000
# [S4]; else Platt. If isotonic, require inner-CV Brier improvement > 1 SE over Platt (one-SE rule); otherwise Platt.
def final_model(dev_rows, profile, cfg):            # exactly the inner procedure on ALL dev rows; produces the shipped artifact
    ...
```
Class prevalence note: Ghidriff-only accept-all may already be about 90-99% correct on natural pairs; therefore precision alone is meaningless without the baseline comparison in H4.

## 9. Metrics, abstention, bootstrap, OOD, conformal
9.1 Metrics (all weighted by `w`, natural stratum, computed on out-of-fold or locked-test predictions).
```python
def brier(p, y, w): return fsum(wi*(pi-yi)**2 for pi,yi,wi in zip(p,y,w)) / fsum(w)   # [S5]
def bin_index(p, B=15): return min(int(p*B), B-1)                  # FIXED equal-width bins on [0,1], B=15 (primary) [S6,S7]
def reliability(p, y, w, B=15):
    rows = []
    for b in range(B):
        idx = [i for i in range(len(p)) if bin_index(p[i], B) == b]
        W = fsum(w[i] for i in idx)
        rows.append(dict(bin=b, lo=b/B, hi=(b+1)/B, n=len(idx), w=W,
            conf=fsum(w[i]*p[i] for i in idx)/W if W else None,
            acc=fsum(w[i]*y[i] for i in idx)/W if W else None))
    return rows
def ece(p, y, w, B=15):
    rel = reliability(p, y, w, B); Wt = fsum(w)
    return fsum(r['w']/Wt*abs(r['acc']-r['conf']) for r in rel if r['w'])
def ece_equal_mass(p, y, w, B=10): ...                              # secondary: sort by p, B weight-equal bins (adaptive) [S8]
def mce_topbins(p, y, w): ...                                       # max |acc-conf| over bins with n >= 30 and conf >= .8
def calib_slope_intercept(p, y, w):                                 # logistic regression of y on logit(p): slope~1, intercept~0 [S8]
    return fit_logistic_l2([[logit(clip(pi))] for pi in p], y, w, C=1e6)
def brier_skill(p, y, w): b = brier(p,y,w); prev = fsum(wi*yi for wi,yi in zip(w,y))/fsum(w); return 1 - b/(prev*(1-prev))
def coverage_precision_curve(p, y, w, flags_abstain):               # selective-classification risk-coverage [S9,S10]
    idx = sorted((i for i in range(len(p)) if not flags_abstain[i]), key=lambda i: (-p[i], i))
    Wall = fsum(w); cum_w = cum_pos = 0.0; out = []
    for k, i in enumerate(idx):                                     # ties: advance whole tie block before emitting a point
        cum_w += w[i]; cum_pos += w[i]*y[i]
        if k+1 == len(idx) or p[idx[k+1]] != p[i]:
            out.append(dict(tau=p[i], coverage=cum_w/Wall, precision=cum_pos/cum_w, fdr=1-cum_pos/cum_w, n=k+1))
    return out
```
Coverage is relative to ALL comparable natural candidates (abstentions from OOD/contested/missing count against coverage).
9.2 Cluster (group) bootstrap [S11]: resample LINEAGES with replacement (B=2000, `det_uniform`-seeded), recompute every metric on the resample WITHOUT refitting the model (OOF/locked predictions are fixed); percentile intervals; requires >= 30 lineages for the headline intervals (otherwise the report states the intervals are anti-conservative and criteria G3 cannot pass). Additionally report the leave-one-lineage-out jackknife: worst-lineage precision and maximum influence of any lineage on the precision lower bound.
```python
def cluster_bootstrap(rows, preds, stat_fn, B, seed, alpha=0.05):
    by_g = group_rows(rows); gs = sorted(by_g); vals = []
    for b in range(B):
        draw = [gs[int(det_uniform(seed, "bs", b, j)*len(gs))] for j in range(len(gs))]
        vals.append(stat_fn([r for g in draw for r in by_g[g]], preds))   # duplicates of a group are all included
    vals = sorted(v for v in vals if v is not None)                       # None when the stat is undefined (e.g. empty accept set); count them
    lo = vals[int(alpha/2*len(vals))]; hi = vals[min(len(vals)-1, int((1-alpha/2)*len(vals)))]
    return dict(lo=lo, hi=hi, undefined=B-len(vals))

def paired_delta(rows, predsA, predsB, stat_fn, B, seed):                 # model vs baseline, same resamples
    ...                                                                    # CI of stat(A)-stat(B) at EQUAL coverage (match tau_B to coverage of A)
```
9.3 Abstention threshold selection (done on dev OOF only, then FROZEN into the artifact; locked-test merely evaluates it):
```python
def choose_tau(dev_rows, oof_p, abstain_flags, target_precision, B, seed):
    best = None
    for pt in coverage_precision_curve(oof_p, y, w, abstain_flags):       # candidate taus = unique OOF scores
        ci = cluster_bootstrap(rows_for(pt), oof_p, lambda R,P: precision_at(R,P,pt.tau), B, seed)
        if ci.lo >= target_precision - MARGIN_DEV:                         # dev margin: lower bound >= 0.96 so locked-test target 0.95 point-est has slack
            best = pt if best is None or pt.coverage > best.coverage else best
    return best                                                            # None -> no auto-accept band exists; artifact ships tau=None (all review)
```
Additionally one lower band `tau_low` with `P < tau_low` labelled "likely mismatched / review first" chosen the same way for NPV (precision of predicting y=0) >= 0.90 lower bound; if unreachable it is omitted. Policy outputs: `auto-accept`, `review`, `likely-wrong`, `abstain(reason)`.
9.4 Conformal as a cross-check, not the primary: split-conformal / conformal risk control or Learn-then-Test over the threshold grid [S14,S15,S16] gives finite-sample guarantees on accepted-set error under exchangeability; our deployment shifts across product/compiler, so exchangeability fails [S17]. Report the conformal threshold computed with lineage-held-out calibration folds (Mondrian per profile) next to the empirical tau; large disagreement is a documented warning. It does not replace group-bootstrap evidence and is not shipped in v1.
9.5 Decision policy order (shipped `policy.py`, pure): (1) not-comparable/many-to-many -> abstain(`not-comparable`); (2) any engine disagrees (`contested`) -> `manual` regardless of p (no p shown); (3) no model for the profile or required family missing -> abstain(`no-model`/`missing-family`); (4) any hard OOD flag -> abstain(`ood`); (5) p >= tau and artifact status `numeric-ok` or `bands-ok` -> auto-accept; (6) p <= tau_low -> likely-wrong; (7) else review. A model can never override rule (2).
9.6 Out-of-distribution detection (fit on dev-train features per profile; stored in the artifact):
```python
def ood_fit(Xtr, w):                               # continuous features only
    mu = wmean(Xtr); S = wcov(Xtr, mu); S = (1-SHRINK)*S + SHRINK*diag(S)    # SHRINK=0.1 fixed; Cholesky
    d2 = [maha2(x, mu, S) for x in Xtr]
    return dict(mu=mu, chol=cholesky(S), d2_cut=wquantile(d2, 0.995),        # soft: warn at 0.99, hard at 0.995 (preregistered)
                ranges={j: (q(Xtr[:,j], 0.001), q(Xtr[:,j], 0.999)) for j in cont},
                cat_levels={j: set(levels)}, engine_versions=seen_versions, toolchains=seen, arch=seen)
def ood_flags(x, spec):
    f = []
    if maha2(x, spec.mu, spec.chol) > spec.d2_cut: f.append("hard:mahalanobis")
    if any(not lo - 0.05*(hi-lo) <= x[j] <= hi + 0.05*(hi-lo) for j,(lo,hi) in spec.ranges.items()): f.append("hard:range")
    if any(x[j] not in spec.cat_levels[j] for j in cats): f.append("hard:unseen-level")
    if engine_version not in spec.engine_versions: f.append("soft:engine-version")   # soft flags are shown, not abstained, unless validation says otherwise
    return f
```
Mahalanobis OOD is a heuristic [S18]; it is validated, not assumed: on leave-one-lineage-out folds and the shift-test, the flagged subset must have higher error rate than the unflagged one (reported as a risk ratio with cluster CI); if not, hard flags reduce to range/unseen-level only.
9.7 Report generation (`report.py`, deterministic; same inputs -> byte-identical `report.json`; `report.md` rendered from it):
```python
def make_report(prereg_sha, corpus_manifest_sha, label_set_sha, tool_git, cfg, results):
    R = {contract:"calibration-report/1", prereg_sha, corpus_manifest_sha, label_set_sha, tool_git, python_version,
         dataset:{n_pairs_by_role_stratum_profile, n_groups, n_lineages, prevalence_weighted, indeterminate_rate, label_sources, annotator_kappa+CI},
         per_profile:{ for p in profiles: {
             models: {M0..M4: {brier, brier_skill, ece15, ece_eqmass10, slope, intercept, auc, logloss, each with cluster CI}},
             reliability_curve: rows from reliability(), coverage_precision_curve: points (downsampled to <=200 by coverage),
             chosen: {C, calibrator, tau, tau_low, mean_coverage, precision_ci, fdr_ci, n_accepted, n_groups_contributing},
             ablations: {drop_family -> paired_delta CIs at equal coverage},
             strata: {stratum/subtype/tier/toolchain -> n, precision_ci, ece} with n<MIN_N flagged "insufficient",
             ood: {flag_rate, risk_ratio_ci}, confusion_at_tau (weighted and raw), jackknife worst group,
             baselines: M0, M1, M2 same fields, conformal_crosscheck}},
         gates: evaluate_gates(results, section12_table) -> {G0..G3: pass|fail|insufficient-data, reasons},
         blind_spots: auto-list of strata failing or insufficient + hand-written known limits,
         amendments: [] }
    R["report_sha256"] = sha256(canonical_json(R without this key)); return R
```
No gate may be evaluated as `pass` when its data minimum is unmet: the value is `insufficient-data`, which is treated as fail.

## 10. Versioned model artifact and safe loading
10.1 Format `patchtrace-calibration-model/1`: strict JSON, UTF-8, no comments, no NaN/Infinity (loader reuses the strict loader approach of `acquisition/winbindex.py`: duplicate-key and constant rejection), max 512 KiB, canonical-JSON SHA-256 recorded.
```
{ "contract":"patchtrace-calibration-model/1","model_id":"c9-g-b-r-2026xx","status":"experimental|bands-ok|numeric-ok",
  "target":"A","feature_schema":"features/1","profile":["G","B","R"],
  "features":[{"name":"G.ratio","kind":"num","median":..,"mean":..,"sd":..,"coef":..}, ...],   // order is the contract
  "intercept":..,"base":"l2-logistic","C":..,
  "calibrator":{"type":"platt","a":..,"b":..}|{"type":"isotonic","knots":[[s,p],...]},
  "policy":{"tau":..,"tau_low":..|null,"display":"none|band|number","bands":[{"lo":..,"hi":..,"label":"..."}]},
  "ood":{...section 9.6...},
  "calibration_domain":{"engines":{"bindiff":["8.0"],"rz-diff":["0.8.x"]},"toolchains":[..],"arch":["x64"],"corpus_id":"..","n_pairs":N,"n_lineages":N,"prevalence":..,"known_blind_spots":[..]},
  "evidence":{"preregistration_sha256":"..","report_sha256":"..","corpus_manifest_sha256":"..","label_set_sha256":"..","tool_git":".."},
  "created":"..","expires":"<date>","digest_sha256":"<canonical json without this key>"}
```
10.2 Loading rules: model files ship inside the package data (read-only, hashed in the build manifest); the app NEVER loads a model from a project, report, network or user-supplied path in v1 (a developer override flag requires an explicit environment variable and forces `status` to `experimental` display, labelled in the UI). Loader: size cap -> strict JSON -> pydantic strict `extra=forbid` -> verify `digest_sha256` -> check `feature_schema` equals the installed `features.py` schema version (mismatch = refuse, `no-model`) -> numeric sanity (finite, monotone knots, p in [0,1], tau in (0,1), feature count bounds <= 64, knots <= 5000) -> check `expires` and `status`. No pickle, joblib, eval, dynamic imports, or code in the artifact. A bad artifact degrades to "no model" (ordinal labels only), never crashes and never falls back to a looser model.
10.3 Prediction provenance (extends SPEC-27 reproducibility): every shown or exported prediction records model_id + digest, feature vector (names+values), profile, engine versions, artifact hashes of both binaries, flags, tau. Exports carry the calibration domain and "not calibrated outside it" text.
10.4 Status gating is inside the artifact AND the code: `numeric-ok` is only written by `tools/calibration/fit.py --promote` after `report.gates` G3 = pass with a matching `report_sha256`; the loader additionally refuses `numeric-ok` whose evidence block is missing. A repository test asserts that no shipped artifact has `status=numeric-ok` unless a docs/qa.md entry cites its report SHA (prevents silent promotion).

## 11. What ships vs stays dev-only
Ships: section 7.2 src modules, one or more model JSON files (initially none, or `experimental` only), schema generation for the artifact contract (per AGENTS.md: update spec first, run `tools/generate_schemas.py` after contract edits), tooltips/UI text via C6 owner. Model files trained on local-only Windows data contain only numeric coefficients/thresholds derived from Microsoft binaries; no bytes or names. Whether such derived parameters are redistributable is confirmed in decision O1.
Dev-only: everything in `tools/calibration/`, corpora, labels (Tier W), sklearn extra, bootstrap/report code, labelling UI. Windows packaging excludes `tools/`.
CI: Tier R end-to-end synthetic pipeline runs on Linux+Windows; Tier W work never runs in CI (no binaries); its report is attached to the PR by hash and recorded in docs/qa.md as externally produced evidence, labelled as such (not mocked, not CI).

## 12. Go / no-go for ever showing a numeric confidence
Display levels: L0 ordinal labels only (today). L1 "auto-accepted / review / likely-wrong / abstain" bands with no number. L2 numeric "estimated chance this pairing is correct", rounded down to the nearest 5%, shown with profile, model id, N and calibration domain, hidden whenever policy abstains/contested. Default is L0; levels are per-profile and stored in `policy.display`.
Data minimums (G0, checked before any claim; failing means the report is `insufficient-data`):
- Labelled natural candidates: >= 12,000 total, of which locked-test >= 3,000 and >= 150 weighted-effective `y=0`; profile-specific: each profile that claims L1/L2 needs >= 2,000 natural dev candidates with >= 100 `y=0` and >= 12 lineages.
- >= 40 lineages in total across >= 10 distinct product/project families; locked-test >= 12 lineages from >= 5 families; Windows (Tier W) must include >= 6 families spanning kernel, user-mode DLL and driver code; >= 2 toolchain/optimisation profiles total; at least one shift-test lineage set.
- Inter-annotator kappa >= 0.80 (CI lower >= 0.70) and indeterminate rate <= 5%; symbol-label audit error <= 2%.
- All adversarial subtypes N1-N11 present with >= 30 items in dev.
Primary criteria (G1 = pipeline on Tier R passes the same H1-H5 numbers on synthetic/OSS data; G2 = L1; G3 = L2), evaluated on locked-test (natural, weighted, cluster-bootstrap 95% two-sided CIs, B=2000):
| id | criterion | L1 (G2) | L2 (G3) |
| H2 | auto-accept precision, point estimate | >= 0.95 | >= 0.95 |
| H2 | precision CI lower bound | >= 0.90 | >= 0.93 |
| H2 | precision CI full width | <= 0.10 | <= 0.06 |
| H3 | coverage of comparable natural candidates (point / CI lower) | >= 0.40 / >= 0.30 | >= 0.50 / >= 0.40 |
| H1 | ECE (15 equal-width bins) | not required | point <= 0.03 and CI upper <= 0.05 |
| H1 | calibration slope CI contains 1; |intercept| CI contains 0 | not required | required |
| H1 | Brier skill vs prevalence predictor CI lower | > 0 | > 0 |
| H4 | at equal coverage, FDR reduction vs best of M0/M1: paired-bootstrap CI lower bound | > 0 | > 0 and relative reduction >= 25% |
| H5 | any stratum/subtype/lineage family with n >= 200 weighted: precision CI lower | >= 0.85 | >= 0.88; strata below n are labelled `insufficient` and abstain by default |
| shift | shift-test precision at frozen tau, point | reported | >= 0.90, else the numeric display is restricted to the calibration domain with explicit text |
| OOD | flagged subset error rate > unflagged (risk ratio CI lower > 1) or hard flag reduced to range/unseen only | required | required |
| ablation | contribution of each non-G family reported; a family that does not improve H4 is removed from the profile | required | required |
Other conditions for L2: independence caveat shown for any profile whose engines share `D_ghidra` (UI text must not say "confirmed by two engines"); calibration tested to hold after the artifact is rebuilt from the manifest by an independent run (reproducibility check: report SHA stable); product owner sign-off recorded in docs/qa.md; Windows frozen-EXE smoke test loads the artifact. If any criterion fails or is `insufficient-data`: the level stays at the highest level fully passed, and the failure is published as a blind spot, never papered over by re-tuning on locked-test. Expiry: models expire 12 months after creation or on a new engine major version in the domain, falling back to L0 until re-validated.

## 13. Test plan
Unit (pure, tools and src): `det_uniform` fixed vectors across platforms; grouped_kfold never splits a group, is deterministic, balanced within tolerance, refuses too few groups; Cholesky/IRLS on a known closed-form case; logistic vs sklearn (importorskip); PAV vs sklearn isotonic on random + tie-heavy data, monotone output, weights respected; Platt sanity on perfectly separable data (smoothing prevents infinite coefficients); Brier/ECE/reliability on hand-computed tiny sets, bin-edge cases (p=1.0 -> last bin, p=0), empty bins; coverage curve ties and monotone coverage; bootstrap determinism, cluster resampling keeps groups whole, undefined-statistic accounting; OOD on synthetic Gaussian with shift; features golden vectors from real `ReconciliationReport` fixtures (train/serve identity); policy ordering table test (contested overrides everything); artifact loader negatives (duplicate keys, NaN, oversize, bad digest, wrong schema, unknown fields, non-monotone knots, expired, `numeric-ok` without evidence).
Property (hypothesis, already a dev dep): calibrator output in [0,1] and non-decreasing in score; permuting row order does not change fits; scaling weights uniformly does not change coefficients (up to tolerance).
Simulation: (a) well-specified synthetic world -> ECE of OOF predictions small and coverage-precision matches the oracle; (b) planted group leakage -> grouped CV materially more pessimistic than random-split CV (assert gap > preset); (c) mis-specified world with lineage shift -> shift-test gates fail correctly; (d) intentionally miscalibrated model -> gates flag H1; (e) sampling-weight correctness: oversampled negatives with weights recover the true prevalence-weighted precision.
Integration: Tier R end-to-end (build -> Ghidriff/rz-diff runs where available -> labels from debug info -> fit -> report -> artifact -> load -> predict) on a tiny corpus (< 60 s); `corpus verify` detects tampered file and an in-tree PE; locked-test runner refuses a second run; report byte-identical on re-run; frozen-EXE smoke (C8) loads a bundled test artifact. Live engine evidence is recorded separately from mocks (AGENTS.md).
Docs/QA: gates recorded in docs/qa.md with report SHA; schemas generated for `patchtrace-calibration-model/1`, `calibration-corpus/1`, `calibration-labels/1`, `calibration-report/1`.

## 14. PR breakdown (each: spec -> red tests -> code -> focused tests -> full gate; model tier per CLAUDE.md cost policy)
| PR | Content | Tier |
|---|---|---|
| C9-0 | Ratify this spec; fix SPEC-27 placement; citation check; generate `c9-preregistration-v1.md` draft (docs only) | top-tier methodology review once, low-cost for citation checks |
| C9-1 | Contracts: corpus manifest, label set, report, artifact (pydantic strict + schemas + strict loaders) with negative tests | mid |
| C9-2 | `tools/calibration` corpus verify/fetch (reuse acquisition.winbindex), in-tree-PE guard | mid |
| C9-3 | Tier R recipes + tiny synthetic fixtures and generators (no Microsoft data) | low (fixtures), mid (recipes) |
| C9-4 | Sampling + labelling tool + agreement stats | mid |
| C9-5 | Shipped `features.py` + family/dependency tags + golden vectors (needs C5 stable reconcile) | mid |
| C9-6 | `mathcore.py` (IRLS, PAV, Platt) + sklearn cross-check + property tests | mid |
| C9-7 | `cv.py`, `metrics.py`, `bootstrap.py`, `ood_fit.py`, simulations incl. leakage test | mid |
| C9-8 | `report.py` + gate evaluator + locked-test runner | mid |
| C9-9 | Shipped `artifact.py`/`predict.py`/`ood.py`/`policy.py`, experimental CLI flag (hidden), no GUI | mid |
| C9-10 | Labelling campaign and first full dev report (human work, not a model task); lineage tool before it | human + low-cost helpers |
| C9-11 | Freeze preregistration, one locked-test run, publish report; promotion `--promote` only on pass | top-tier review of results only if gates are ambiguous |
| C9-12 | GUI display level L1/L2 through C6 evidence panel (after C6) | mid |
C9 never blocks a release; until C9-11 passes, GUI stays L0.

## 15. Risks and mitigations
- Label cost/quality and annotator availability (5.6, O2): mitigated by symbol-derived labels in symbols-hidden condition, audits, test-retest fallback; cap claim level.
- Circular symbols/labels: addressed by the symbols-hidden rule; residual risk where hidden-symbol behaviour differs from deployment (users often have symbols): the symbols-visible human stratum is the check and its n will be small.
- Lineage clustering collapses (shared CRT/static code) -> too few groups; mitigated by thresholds, recorded; may force a "cannot reach G0" outcome which is a valid result.
- Prevalence: natural Ghidriff precision may already be near target, making H4 the real hurdle; negative enrichment is adversarial, so calibration uses natural weights only.
- Cluster bootstrap with few groups is anti-conservative; G0 minimum of 30 for headline intervals plus jackknife.
- Tier R unrepresentativeness of MSVC system code; Tier W cannot be shared, so third-party reproduction is partial (stated).
- Pure-Python numerics bugs or slow fits: sklearn cross-check, caps on rows via deterministic weighted subsampling documented in report.
- Engine drift (Ghidriff/BinDiff/rizin versions, `rz-diff` JSON drift, C2/C3 unknowns): model bound to engine versions in `calibration_domain`; OOD soft flag; expiry.
- Researcher degrees of freedom: preregistration hash, single-use locked-test, closed model list, amendment log.
- Users reading P(A) as P(bug): UI copy gated by C6 owner; artifact `known_blind_spots`; display level rules; no number for contested.
- Legal: Microsoft binary/PDB terms, Winbindex terms, and even RVA+hash label publication are unreviewed (O1); BinKit/BinaryCorp/Cisco-style public corpora were considered as extra Tier R sources but: BinKit is ELF-only; REFuSe-Bench (arXiv 2410.22677), Assemblage (arXiv 2405.03991) and FuncPEval (arXiv 2504.21520) do supply Windows PE data, but none was found with patch-pair match labels for calibration; the licences of BinKit, BinaryCorp, REFuSe-Bench, Assemblage and Winbindex are UNCONFIRMED and must be read before any reuse (unknown counts as do-not-use).
- Model on stale OOD: only bundled, expiring artifacts.

## 16. Decisions needed from the product owner
- O1 Legal: may label files (RVA + body hash + label) for Microsoft images be published, and may numeric parameters trained on them ship? Default if unanswered: Tier W labels local-only; parameters ship after review.
- O2 Annotators: is a second independent annotator available for >= 20% overlap? Without one, claims cap at L1.
- O3 Acceptance of the preregistered targets (95% precision, coverage >= 0.5, ECE <= 0.03, FDR reduction >= 25%) and of "number rounded to 5%" display; or choose bands-only forever.
- O4 Labelling budget (~150 h) and who owns it; which Windows product families are in scope (kernel, user-mode DLL, drivers).
- O5 Approve in-repo pure-Python fitter plus optional `calibration-dev` sklearn extra (vs making sklearn a dev dependency of the tool code).
- O6 Tier R toolchain: is clang-cl/mingw acceptable as a stand-in for non-redistributable MSVC-built code in CI?

## 17. Sources (verify before ratification; see caveat above)
- S1 BinDiff concepts: https://github.com/google/bindiff/blob/main/docs/concepts.md ; S2 BinDiff differ.cc (both from SPEC-27) and rz-diff man page.
- S3 Platt, "Probabilistic outputs for SVMs and comparisons to regularized likelihood methods", 1999. S4 Niculescu-Mizil & Caruana, "Predicting good probabilities with supervised learning", ICML 2005 (isotonic vs Platt by sample size); Zadrozny & Elkan, KDD 2002 (isotonic calibration).
- S5 Brier, Monthly Weather Review 78, 1950; Murphy 1973 decomposition; DeGroot & Fienberg 1983 (reliability).
- S6 Naeini, Cooper, Hauskrecht, "Obtaining well calibrated probabilities using Bayesian binning", AAAI 2015 (ECE). S7 Guo, Pleiss, Sun, Weinberger, "On calibration of modern neural networks", ICML 2017 (15-bin ECE, reliability diagrams).
- S8 Nixon et al., "Measuring calibration in deep learning", CVPR-W 2019 (adaptive-bin ECE, binning sensitivity); Kull et al. 2017 (beta calibration); Van Calster et al. 2019 BMC Med (calibration slope/intercept).
- S9 El-Yaniv & Wiener, "On the foundations of noise-free selective classification", JMLR 2010. S10 Geifman & El-Yaniv, "Selective classification for deep neural networks", NeurIPS 2017.
- S11 Cameron, Gelbach, Miller, "Bootstrap-based improvements for inference with clustered errors", Rev. Econ. Stat. 2008; Efron & Tibshirani, An Introduction to the Bootstrap, 1993.
- S12 Roberts et al., "Cross-validation strategies for data with temporal, spatial, hierarchical, or phylogenetic structure", Ecography 2017. S13 Kapoor & Narayanan, "Leakage and the reproducibility crisis in machine-learning-based science", Patterns 2023; Allamanis, "The adverse effects of code duplication in machine learning models of code", Onward! 2019.
- S14 Vovk, Gammerman, Shafer, Algorithmic Learning in a Random World, 2005. S15 Angelopoulos & Bates, "A gentle introduction to conformal prediction and distribution-free uncertainty quantification", 2021. S16 Angelopoulos, Bates, Candes, Jordan, Lei, "Learn then Test", arXiv 2110.01052 (2021; journal version reported as Ann. Appl. Stat. 2025, verify); Angelopoulos et al., "Conformal risk control", arXiv 2208.02814 (ICLR 2024, verify). S17 Barber et al., "Conformal prediction beyond exchangeability", Ann. Stat. 2023; Tibshirani et al., "Conformal prediction under covariate shift", NeurIPS 2019.
- S18 Lee, Lee, Lee, Shin, "A simple unified framework for detecting out-of-distribution samples and adversarial attacks", NeurIPS 2018; Hendrycks & Gimpel 2017 (baseline).
- Binary diffing/benchmarks: Flake, "Structural comparison of executable objects", DIMVA 2004; Dullien & Rolles, "Graph-based comparison of executable objects", SSTIC 2005; Diaphora (J. Koret, github.com/joxeankoret/diaphora); Haq & Caballero, "A survey of binary code similarity", ACM CSUR 2021; Kim et al. BinKit/TikNib "Revisiting binary code similarity analysis using interpretable feature engineering and lessons learned" (IEEE TSE 2022, arXiv 2011.10749; the one paper introduces both BinKit and TikNib; BinKit is ELF-only; BinKit licence unverified); Wang et al. jTrans/BinaryCorp (arXiv 2205.12713; ISSTA 2022 venue unverified; BinaryCorp licence unverified); Marcelli et al., "How machine learning is solving the binary function similarity problem", USENIX Security 2022; REFuSe-Bench, "Is function similarity over-engineered? Building a benchmark" (arXiv 2410.22677, NeurIPS 2024 Datasets & Benchmarks; includes Windows data and a strong raw-bytes baseline; licence unverified). Lesson used here (corrected): most published benchmarks are ELF/open-source and compiler-option-driven, but REFuSe-Bench and Assemblage do contain Windows PE data; all of them measure retrieval/similarity rather than calibrated one-to-one match correctness on Windows patch pairs, so none removes the need for the corpus above. All citations in this section remain "verify before ratification".

## 18. Amendments from the C9 build (2026-10-14; synthetic validation only)
Inputs: this spec, `docs/plans/spec-decisions-20261014.md` (O1-O6), the phase-C research note and the calibration plan/troubleshooting notes. Nothing below is a claim about real binaries or engines: every number was produced on generated worlds with known ground truth.
1. **Placement.** Shipped runtime lives in `src/patchtrace/calibration/` (`features`, `artifact`, `predict` incl. provenance, `ood`, `policy`); no `provenance.py`. Dev pipeline in `tools/calibration/` (adds `stats.py`, `threshold.py`, `ece_null.py`, `baselines.py`, `ablation.py`, `evaluate.py`, `gates.py`, `contracts.py`, `synth.py`, `schemas.py`, `guidelines/g1.md`). Schemas for the four contracts are generated by `PYTHONPATH=src python -m tools.calibration.schemas` into `docs/schemas/calibration/` (the shared `tools/generate_schemas.py` is untouched).
2. **`display_level()`** returns `'ordinal'` (L0) unless a loaded, valid artifact has `status` in {bands-ok, numeric-ok}, a matching `policy.display`, and `evidence.gates` with G0+G2 (`'bands'`) or G0+G2+G3 (`'numeric'`) = pass. No artifact, any loader problem, or any exception gives `'ordinal'`. Without a profile it returns the lowest level over loaded profiles. No artifact ships today.
3. **Artifact contract (additive):** `evidence.gates` (`{G0..G3: pass|fail|insufficient-data}`) is recorded by `fit.promote` and checked by the loader (`numeric-ok` needs report + preregistration SHAs and G0=G3=pass; `bands-ok` needs a report SHA and G0=G2=pass; `policy.display` may not exceed the status). Expiry may not exceed 366 days after creation. A developer override (`PATCHTRACE_CALIBRATION_DEV_ARTIFACT`) forces `experimental`/display `none`. Two bundled artifacts for one profile cancel each other (ambiguous -> no model). Package data for `calibration/models/*.json` and the PyInstaller data entry are added only when the first artifact ships.
4. **Features/1:** 63 columns for G+B+R (bound 64). Ghidriff match-type levels and BinDiff algorithm buckets are provisional (others map to `other`). Size comes from Ghidriff `length` metadata, ratio from `upstream_similarity`; categorical P values are one-hots plus a `categories` map used for unseen-level OOD. A two-sided match that any engine pairs differently is `contested` (checked before `one-sided`). Profile = G plus each engine whose row is `agreement`; `absent` engines only set `X.absent_*`.
5. **Policy:** rules (5) auto-accept and (6) likely-wrong apply only to `bands-ok`/`numeric-ok` artifacts; an `experimental` model always yields `review`. The shown number (L2 only) is rounded down to 5 %.
6. **det_uniform** uses 13 hex digits / 2**52 (strictly < 1.0); sections 7.3 and 8 edited accordingly.
7. **Tau and tau_low: fixed-sequence Learn-then-Test** (replaces the bootstrap-margin scan of 9.3). Hypotheses H_tau "error among p >= tau exceeds alpha = 1 - 0.95" on a fixed grid 0.999..0.500, tested strict -> loose with an exact binomial p-value at n = floor(n_eff), k = ceil(risk * n_eff), n_eff = Kish n / design effect (1 + (m_bar - 1) * rho; rho = lineage ICC of the error indicator, 1.0 when undefined), delta = 0.05; stop at the first non-rejection (FWER control without a union penalty). Two label-free rules: the sequence starts where the accepted Kish n reaches the size at which a true risk of alpha/2 is certified with 80 % power (361 for alpha = delta = 0.05), and a grid point selecting the same set as the previous one is skipped (no extrapolation into empty score ranges). tau_low likewise with NPV target 0.90. Locked-test evaluates the frozen tau as a one-element sequence; gate H2 additionally requires `ltt.certified` (L1 and L2). Guarantees assume exchangeability within the design-effect approximation; lineage shift is still tested separately.
8. **ECE gate from a null simulation.** The plug-in ECE of a perfectly calibrated model is not 0. `ece_null.py` simulates the 15-bin ECE under perfect calibration at the observed bin confidences with per-bin n_eff = Kish / (1 + (m_bar - 1) * rho), rho = lineage ICC of residuals (0 when undefined, the strictest choice here). H1 for L2 now reads `excess = ECE - null_mean <= 0.03` and `ECE CI-upper - null_mean <= 0.05`; the null p-value and a debiased squared-error estimate are reported, not gated. Binomial draws use exact inverse CDF when n p q < 50, else a rounded normal approximation.
9. **Baselines:** M0b raw-bytes baseline = `R.similarity` (rz-diff raw-byte Levenshtein, D_bytes), defined for profiles containing R; H4 compares against the best of M0, M0b, M1 (optional, nested CV on G columns) and M2 at equal coverage. A PatchTrace-computed body-bytes similarity for every profile is a later slice.
10. **Grouping by lineage AND function identity:** `lineage.identity_groups` unions lineages that share a function identity (e.g. relocation-masked body hash); identities present in more than `hub_max_lineages` lineages (shared CRT/static code) are not union edges and their candidates are reported as the `seen-body` stratum. `shared_identities` audits a split.
11. **OOD validation:** flags are fitted on outer-train lineages only and applied to held-out lineages; if the lineage-bootstrap risk-ratio lower bound (misclassification at 0.5, flagged vs unflagged) is not > 1, the shipped spec drops the Mahalanobis test (range/unseen-level only; `ood_reduced=true`). With few flagged lineages this lower bound is legitimately near 0.
12. **Ablations:** leave-one-family-out (non-G), drop-D_ghidra and drop-D_symbols (incl. `P.symbols`) are refit with the same nested CV; reported as FDR(ablated) - FDR(full) at the full model's coverage under the same lineage resamples, at the certified tau or, when none exists, at the preregistered reference coverage 0.5.
13. **Gates:** G1 is evaluated on Tier R / synthetic pipeline results with the L2 numbers; G0 needs the dataset minimums (with one annotator: test-retest kappa) and G3 additionally needs a confirmed second annotator (decision O2), reproducibility, owner sign-off, frozen-EXE smoke and the independence caveat. Missing inputs are `insufficient-data`, never `pass`; top-level report gates are the worst status over profiles.
14. **Corpus guard:** `tools.calibration.corpus guard` fails on any PE/ELF image outside `tests/fixtures/` among tracked + untracked-not-ignored files, on any work-tree file whose SHA-256 equals a Tier-W manifest entry, and when `PATCHTRACE_CALIB_ROOT` is inside the work tree; a repository test runs it over tracked files. `fetch` stores only hash-verified bytes and never executes them; Winbindex is used for identity metadata only (its licence is reported as GPL-3.0 but UNCONFIRMED; nothing is vendored).
15. **Labelling:** terminal mode and a hash-chained append-only annotation log are implemented (`label.py`); the 127.0.0.1 HTML front-end is a later slice. `blind_view` strips scores, verdicts, match types and (blind pass) names. Guideline `g1` records the PDB pitfalls (static-name collisions, ICF, incremental thunks, LTCG/PGO splits, compiler-generated functions) and the valid Tier R sources (patch-tag builds of permissive C libraries; locally built Microsoft open-source projects; recipes and hashes only).
16. **Citations:** Marcelli et al. is a reproducibility reference only; the split/dedup leakage critique belongs to REFuSe-Bench. Every source in section 17 remains "verify before ratification" (the researcher could only use search snippets).
