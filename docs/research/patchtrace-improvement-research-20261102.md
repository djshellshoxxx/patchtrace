# Research to improve existing PatchTrace — 2026-11-02

These are proposed experiments, not completed evaluations or new accuracy claims.
Project observations refer to PR #163 at `6e82fd70f315b99c6798a42c9061a1424a02933e`.
No compared target, locked evaluation, or native analysis was executed for this agenda.

## 1. Reproducible ground truth and cache correctness

Start with harmless authored source families whose function identities and intended
changes can be independently reviewed. Keep identity, material change and unresolved
labels separate. Preserve source revision, recipe, compiler, environment, binary,
debug artifact and label digests in immutable receipts. Compare fresh analysis with
cached analysis under identical context, then vary one source/build input at a time.

Measure receipt completeness, artifact reproduction, wrong-context cache reuse,
normalized warm/fresh agreement, independently supported label coverage, and recovery
of completed evidence after publication failure. Never silently turn an ambiguous
label into a correct prediction. This directly addresses the unintegrated receipt
lineage's build provenance, cache-context and unchecked-label corrections.

References: [Reproducible Builds](https://reproducible-builds.org/docs/definition/),
[SLSA build provenance](https://slsa.dev/spec/v1.2/build-provenance).
Using these ideas does not establish a SLSA assurance level.

## 2. Matching robustness across build conditions

Use a manageable matrix of supported compilers, optimization settings, symbol
availability and inlining/LTO. Keep a distinct Windows/MSVC arm. Include unchanged
source rebuilt differently, known source changes under the same configuration,
duplicate bodies, removed functions and mappings made ambiguous by optimization.
Hold out whole source families and compiler versions from fitting.

Measure discovery recall separately from matching precision/recall; correct-candidate
rank, Recall@1/5 and MRR; false material-change reports on unchanged controls;
abstention/coverage; median and tail latency; memory and timeouts. Report strata and
the worst stratum alongside aggregates. Retain raw outputs and input ownership.

References: [official BinKit benchmark](https://github.com/SoftSec-KAIST/BinKit),
[Marcelli et al., USENIX Security 2022](https://www.usenix.org/system/files/sec22-marcelli.pdf).
These motivate evaluation design; they do not measure PatchTrace's current accuracy.

## 3. Confidence, abstention and engine agreement

Evaluate two claims separately: correct counterpart, and material change conditional
on that counterpart. Fit any score-to-probability mapping on separate project groups.
Keep raw engine scores and calibration identity. Measure reliability with sample
counts, error among accepted decisions versus coverage, high-confidence errors and
unfamiliar-compiler behavior. Predeclare acceptance criteria and keep locked validation
separate. Do not display heuristic scores as correctness probabilities without evidence.

Study engines alone and together against independent truth. Measure shared wrong
matches, correlated errors and incremental useful matches at fixed precision. Account
for shared extraction infrastructure; cached repetitions are not independent votes.
Unavailable, blocked and failed engines remain in the intended-corpus accounting.

References: [Guo et al., ICML 2017](https://proceedings.mlr.press/v70/guo17a/guo17a.pdf),
[official BinDiff score meanings](https://github.com/google/bindiff/blob/main/docs/concepts.md).
Neural-classifier calibration results do not establish a suitable method for PatchTrace.

## 4. Rule usefulness and cost

First complete and qualify the production evidence loader: the reviewed rules CLI
initializes BACKEND to None and no production assignment was found. Then demonstrate
proposal, human review, acceptance, test and export on known cases. Evaluate rules
against intended families, adjacent builds and unrelated benign software. Preserve
per-version observations even when rule text is identical.

Measure intended coverage, unrelated false positives, stability across builds,
scan time, timeouts, rule size and reviewability. Profile pattern matching and condition
evaluation separately where the pinned YARA-X build supports it.

Reference: [YARA-X rule profiling](https://virustotal.github.io/yara-x/blog/profiling-your-yara-rules/).

## 5. Evidence interpretation, reliability and usability

- Review scoped advisory cases with missing/conflicting revisions. Measure citation
  completeness, reproducible scope, unsupported interpretations, stale-context detection
  and reviewer agreement. Documentary correlation must retain its evidentiary limits.
- Qualify persistence on owned temporary projects and clean Windows profiles under
  cancellation, locked files, interrupted saves, Unicode paths and documented synced
  folders. Measure preservation, successful reopen and bounded failures. Distinguish
  SQLite snapshot creation from byte verification and publication; the two-observation
  fingerprint is not an atomic snapshot. [SQLite reference](https://www.sqlite.org/backup.html).
- Observe representative users completing project creation, comparison, verification,
  export and reopen on the same authored cases. Measure task success, time to a verified
  finding, mistaken interpretations and keyboard/accessibility failures.
- Profile representative sizes on recorded hardware with cold/warm caches and isolated
  repeated runs. Improve measured bottlenecks while retaining correctness controls.

## First deliverables

1. A small frozen development benchmark with complete receipts and explicit unresolved cases.
2. A baseline correctness/uncertainty report with denominators and family-level results.
3. A qualified rules workflow pilot with unrelated benign controls and timing evidence.

Finish the release candidate's present correctness and packaging gates in parallel.
Rizin orientation quarantine, BinDiff verification, packaged native qualification and
the unfinished rules evidence loader remain concrete prerequisites for their respective
product claims. Broad historical PR cleanup is not an accuracy or readiness metric.
