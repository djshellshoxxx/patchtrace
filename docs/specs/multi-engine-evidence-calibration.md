# SPEC-27: Cross-engine evidence fusion and calibration

Status: experimental implementation; index not calibrated and no security-finding confidence score yet. Relates to SPEC-10/11, proposed SPEC-21 and GUI preview plan.

## Decision
Keep Ghidriff as baseline; optional .BinDiff imports and rz-diff function comparisons are already implemented in secondary/. Reconcile their exact pair-oriented addresses against stored Ghidriff records. Do not silently trust raw engine confidence. If any engine pairs a Ghidriff function endpoint differently, output contested: the conflict requires analyst review, even if the other engine agrees. Missing match or unsupported comparison means unknown, NOT a negative vote. An actual Ghidra/IDA BinExport producer and live BinDiff runner, GUI view, reliable stdout isolation for rz-diff and CPU-capped parallel job orchestration are not complete; do not claim automatic parallel engine execution.

## Experimental fusion engine in this branch
Pure secondary/evidence.py accepts ReconciliationReport objects; produces per-match verdict, supporting/contradicting/missing engines and limitations plus an uncalibrated 0–83 evidence INDEX for triage. CLI secondary reconcile exposes this structure. The tiers are operational ordering labels, not probabilities, and say nothing about vulnerability existence. Engine mismatch cancels corroboration; agreement is discounted due to correlated inputs. The constants 55/20/8/83 are illustrative placeholders and MUST be replaced or removed before presenting a 'confidence %' to end users.

## Research and calibrated probability design (before reliability claims)
BinDiff uses graph MD indices, call neighborhoods, function/basic-block match algorithms and a weighted confidence/similarity computation; its scores are algorithm-specific and not empirical P(correct). rz-diff's existing PatchTrace function mode uses raw-byte Levenshtein similarity and has no confidence field. High scores may still result from duplicated functions, thunk wrappers, identical constants, common runtimes, inlining, stripped symbols, imports or compiler artifacts.

Research approach:
1. Define distinct outcomes and labels: (A) matched endpoints genuinely represent the same logical function, (B) changed blocks/edges correspond correctly, (C) evidence supports specific patch mechanism, (D) vulnerability root-cause hypothesis verified. Four separate probabilities; only (A) is initially targeted.
2. Build ground-truth corpus of old/new PE pairs with hand-reviewed function/block identities across Windows versions, compilers, optimization profiles, stripped/PDB images and unrelated binaries. Add negatives deliberately (near duplicates, static libraries, inlined/split, address-coincident, similar CFG but different semantics).
3. Collect engine-native evidence separately: Ghidriff match type/ratio/quality; BinDiff algorithm IDs, structural match coverage, call-neighborhood consistency, matched blocks/edges, confidence and similarity; rz-diff byte-similarity, unmatched and import/section metadata. Add semantic consistency, function size/CFG edits and symbol provenance as separate feature families.
4. Prevent circular confirmation: mark shared disassembler/Ghidra database, symbols, compiler signature and matched-call-graph dependencies; group related evidence. Leave-one-engine-out ablations measure marginal gain.
5. Split training/testing by *binary family/product/build lineage* (not random functions from the same binary) to prevent leakage. Hold out different products and compiler versions.
6. Calibrate P(correct-function-pair | evidence, population) using regularized logistic regression or gradient-boosted ranker followed by isotonic calibration or Platt scaling. Compare against single Ghidriff baseline and simple rule systems. Use cross-validation by binary family and bootstrap confidence intervals.
7. Evaluate precision, recall, false-discovery rate, Brier score, expected calibration error, reliability diagram, top-K precision and abstention/coverage curves. Tune thresholds to minimize false leads, report calibration domain, dataset size and prevalence; never promise universality.
8. Separate risk/relevance ranking from correctness confidence: a low-similarity true match may be a critical patch; a high-similarity unchanged function is generally not a security finding. Never make high similarity evidence of vulnerability.
9. Decision policy: strongly contradictory same-endpoint matches -> contested/manual; out-of-distribution or missing feature family -> abstain; corroborated high-P(match) -> analyze semantic differences; high-P(match) alone does not establish a bug.
10. Do not display a numerical 'confidence probability' until locked held-out calibration meets predeclared target, e.g. >=95% precision for 'auto-accepted matches' with confidence intervals and practical minimum coverage. Publish dataset provenance, metrics, confusion matrix, profile-specific reliability and known blind spots. Never train on AI-generated labels without independently verified ground truth.

## Architecture
- secondary/{bindiff,rzdiff,contracts,reconcile,evidence}.py for pure evidence.
- future secondary/calibration/{features,labels,train,predict,drift,metrics}.py, no Qt imports.
- future secondary/runner.py with opt-in, per-engine process budget, cancellation, immutable cached outputs and failure isolation. No mandatory license/platform assumptions.
- UI: engine badges, source-specific reason, alternative endpoints, unmatched queue, reviewed override, 'not calibrated' message; per-feature evidence display. Provenance exported with reports.
- Any predictions must be reproducible from engine versions/config, artifact hashes, raw outputs, selected model digest, calibration corpus/version and thresholds.

## Tests and gates
Unit: corroboration, disagreement priority, absence vs contradictory, reverse orientation, base normalization, ambiguous/many-to-many, duplicate sets, stale runs, correlated result lineage and disabled secondary adapters.
Integration: round-trip real .BinDiff and rz-diff on paired PE fixtures; verify never rewriting Ghidriff matches; regression when one runner fails. Live Windows Ghidra/WinDbg work is a separate track.
Benchmark: controlled corpus, engine ablations, held-out family accuracy, calibration, runtime and memory costs. Ship opt-in modes only after measurable marginal benefit above baseline.

Sources:
- https://github.com/google/bindiff/blob/main/docs/concepts.md
- https://github.com/google/bindiff/blob/main/differ.cc
- https://manpages.opensuse.org/Tumbleweed/rizin/rz-diff.1.en.html

Placement amendment (2026-10-14, C9 build; see `calibration-corpus-and-model.md` section 18): the "future secondary/calibration/" modules are superseded. The shipped runtime (features, artifact loader, predict, ood, policy) is `src/patchtrace/calibration/`; labels, training, metrics, reports and drift analysis stay dev-only in `tools/calibration/` and never ship. No numeric confidence is displayed: `calibration.policy.display_level()` returns `'ordinal'` until a validated artifact passes the go/no-go gates.
