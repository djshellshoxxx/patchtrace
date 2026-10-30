# R1 handoff and reproduction

Branch: `codex/r1-ground-truth-research-20261030`.
Research PR: [#128](https://github.com/djshellshoxxx/patchtrace/pull/128).
Integration baseline: `a04f5a299a8d4afef023261e52e08d14678cf1e7`.
The baseline was rechecked during execution and remained unchanged. The first
research checkpoint is `a02a1774a1617441072f4a8770348cc22038eeac`; later PR commits
contain the runner, results and provenance fixes. Consult the PR head for the
current integration revision, not a SHA embedded in a self-referential receipt.

## Start here

Read [the results](05-results-and-failure-analysis.md),
[limitations](06-limitations-and-open-questions.md), and the three source reviews
in `results/`. The literature survey, evidence design and candidate/pin ledger
are numbered 01–03. The preregistered pilot boundary is 04. Existing Tier R/Tier W
and calibration infrastructure remain authoritative; the new modules are small
research adapters over those APIs.

| Deliverable | Location |
|---|---|
| Primary-source literature and dataset decisions | `01-literature-and-datasets.md` |
| Truth admission, metric definitions, leakage design | `02-ground-truth-and-evaluation.md`, `04-pilot-protocol.md` |
| Exact real-case and licence pins | `03-real-world-patch-candidates.md` |
| Reviewed authored fixture | `corpus/ours/r1-pilot/defined/` |
| Build matrix wrapper | `tools/calibration/tier_r/research_build.py` |
| Explicit observations and metric/leakage checks | `research_observers.py`, `research_audit.py` in the same package |
| Primary/rz-diff/unified pilot CLI | `research_pilot.py` in the same package |
| Existing persisted contracts | `suite/1`, `known-answer-labels/1`, `tier-r-build/1`, `unified-outcomes/1`; unchanged |
| Accepted review overlays | `results/acceptance.json`, `acceptance-mingw-gcc-o2.json`, `cjson-acceptance.json` |
| Bounded labels, receipts and metrics | `results/labels/`, `results/build-receipts/`, `results/*.json` |
| Unresolved production evidence defect | `results/failure-analysis-addendum.md` |

Built PE/PDB/GZF files and full native raw projects remain outside the git
worktree. The committed records contain their hashes, source inputs, build
recipes, exact observation arrays, decision counts and review provenance. The
commands below reproduce the artifacts rather than pretending that a temporary
absolute path is a durable download location.

## Environment

Use a separate checkout and environment, preserve other workers' changes, and
check current integration ownership before editing shared files. This run used
Python 3.12.14 on Linux x86-64, Clang/LLVM/LLD 18.1.3, MinGW GCC 13-win32,
Java 21, Ghidra 12.0.4, pyghidra 3.0.2 and pinned Ghidriff. Exact installed Python
versions and archive hashes are in [environment.json](results/environment.json).

The existing dependency installation was:

```bash
python -m venv /absolute/path/r1-venv
/absolute/path/r1-venv/bin/python -m pip install -e '.[dev,search]'
/absolute/path/r1-venv/bin/python -m pip install pyghidra==3.0.2 JPype1==1.5.2
/absolute/path/r1-venv/bin/python -m pip install \
  'ghidriff @ git+https://github.com/clearbluejar/ghidriff.git@4f5d895fcbb1eacd65efd81145922c15bb7e741d'
```

Provision the actual compiler/linker packages, not just the `toolchain` probe.
On the measured Ubuntu system the generic `lld` package was additionally needed
for `-fuse-ld=lld`, and Qt tests required the normal EGL/OpenGL runtime packages.
Do not claim image-hash reproducibility with different compiler, linker, runtime
headers or library versions. A review digest mismatch is a reason to inspect and
re-review a new build, not to edit the expected hash until it passes.

Verified native archives used here:

- [Ghidra 12.0.4 release ZIP](https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip),
  SHA-256 `c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120`.
- [Rizin 0.9.1 static Linux x86-64 archive](https://github.com/rizinorg/rizin/releases/download/v0.9.1/rizin-v0.9.1-static-x86_64.tar.xz),
  SHA-256 `9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf`.

Restore executable mode bits from the verified Ghidra ZIP when extracting with
Python: `zipfile.extractall` alone did not retain them in this experiment. The
live workflow correction records that operation. Do not enable symbol downloads
or trust unverified BinDiff pins to make a gate appear available.

## Build and inspect the pilot

Set task-specific absolute paths outside the repository:

```bash
R1_PY=/absolute/path/r1-venv/bin/python
R1_STORE=/absolute/path/r1-store
R1_RUNS=/absolute/path/r1-runs
R1_GHIDRA=/absolute/path/ghidra_12.0.4_PUBLIC
R1_JAVA=/absolute/path/java-21
R1_RZDIFF=/absolute/path/rizin/bin/rz-diff

"$R1_PY" -m tools.calibration.tier_r toolchain
"$R1_PY" -m tools.calibration.tier_r.research_build \
  --store "$R1_STORE" --output "$R1_RUNS/matrix.json" \
  --profiles msvc-free,mingw-gcc,mingw-clang --opts O0,O1,O2,O3,Os
```

The build wrapper reports `built`, `findings` or `blocked` for every requested
cell. Its process exit codes are 0 for built, 1 for findings/partial availability,
3 for all blocked, and 2 for invalid invocation. It invokes the existing factory;
it does not create alternate compiler recipes or execute targets.

Inspect `<store>/labels/` with the existing strict `C.load_labels` loader. Require
the requested profile/optimization on **both endpoints**, not just in the matrix
entry name. For each side, select its immutable build receipt by recipe digest,
source inputs and artifact hashes under `images/<debug_sha>/builds/`. Do not use
the legacy last-build `build.json` as unique provenance. Repeat into another
scratch build context and compare engine/debug/PDB hashes separately.

The source review covers exact O2 artifacts. Other matrix cells have authored
cross-checks and observed body facts, not automatic independent acceptance.
Preserve optimized-away or ambiguous mutations instead of forcing them into
the material-change population.

## Run actual engines

Run the existing Ghidriff primary first, then secondary/unified adapters. This
single invocation does that for the reviewed name-visible GCC O2 fixture:

```bash
"$R1_PY" -m tools.calibration.tier_r.research_pilot \
  --labels "$R1_STORE/labels/research-mingw-gcc-O2-r1-pilot-defined-v1-v2.json" \
  --store "$R1_STORE" --work "$R1_RUNS/gcc-o2-cold-1" \
  --output "$R1_RUNS/gcc-o2-cold-1/receipt.json" \
  --ghidra-dir "$R1_GHIDRA" --java-home "$R1_JAVA" \
  --rz-diff "$R1_RZDIFF" --unified \
  --review docs/research/ground-truth-corpus/results/acceptance-mingw-gcc-o2.json
```

The receipt must be a new `.json` file directly inside the absolute work
directory. Relative paths, traversal, symlinks and existing destinations are
rejected before engines start; publication uses exclusive creation. Earlier
receipts retain their historical locations, but those locations are not examples
of the hardened CLI's current output policy.

Use a new work directory for an independent repetition. Compare explicit
observation sequences, metrics and unified row digests; raw JSON may include
different timing/project metadata. The runner reports cold analysis and a
subsequent verified unified cache hit separately. Imported or resumed primary
evidence is identified through its backend/run identity; a `cache_origin` marker
also prevents fresh-execution credit, even when no primary project was supplied.
`--primary-project PATH` can consume a previously
completed project after artifact/raw-digest validation.

The pilot CLI returns 1 for an engine failure, 3 if no engine produced a usable
result, 2 for invalid input, and 0 when at least one selected engine produced
usable output without another engine failure. **Read each engine's status:**
BinDiff may remain blocked even when the overall command returns 0. A missing
observation is not an unchanged prediction.

For the reviewed hidden-name case, first emit the original suite pair ID used
by its review:

```bash
"$R1_PY" -m tools.calibration.tier_r build-suite \
  corpus/ours/r1-pilot/defined --store "$R1_STORE" --opt O2
```

Then use `ours-r1-pilot-defined-v1-v2-O2.json` and `results/acceptance.json` in the
pilot invocation. Zero discovery and the rz-diff empty-output failure are
expected observations under the measured stock condition, not successful
accuracy gates.

For cJSON:

```bash
"$R1_PY" -m tools.calibration.tier_r fetch \
  cjson-1.7.16-to-1.7.17 --store "$R1_STORE"
"$R1_PY" -m tools.calibration.tier_r build-card \
  cjson-1.7.16-to-1.7.17 --store "$R1_STORE" --opt O2
```

Run `research_pilot` with that label file and `results/cjson-acceptance.json`.
Only its two reviewed security functions are admitted. Keep the unblinded-review
and export-name visibility caveats with every reported score.

The A/A and structural experiments have their exact independent commands in
[native-aa-control.md](results/native-aa-control.md) and
[controls-and-structure.md](results/controls-and-structure.md). A/A bypasses the
product's deliberate identical-hash shortcut by invoking pinned Ghidriff
directly; two distinct filenames preserve identical bytes without duplicate
ProgramDB naming. Do not alter artifact bytes to evade the shortcut. The
published native A/A label has an explicit compiler-qualified research ID to
avoid the older factory's cross-store `aa-defined-v1-O2-rebuild` name collision;
its original pair ID/digest are retained in `case`.

## Validation and next integration step

Run the repository gates in an environment that allows the local listeners used
by transport tests:

```bash
QT_QPA_PLATFORM=offscreen "$R1_PY" -m pytest -q
"$R1_PY" -m ruff check src tests tools
"$R1_PY" -m pytest -q \
  tests/test_tier_r_research_pilot.py tests/test_tier_r_research_observers.py \
  tests/test_tier_r_research_build.py tests/test_tier_r_research_audit.py \
  tests/test_tier_r_build_receipts_r1.py tests/test_tier_r_session_provenance_r1.py \
  tests/test_tier_r_label_promotion_r1.py tests/test_unified_live_pairs_r1.py
```

`results/integrity-gates.json` records the additional full corpus, licence/card
and canonical schema drift checks. `tools/generate_schemas.py` has no `--check`
option: use the existing regenerate-and-compare tests under temporary directories.
No schema content or version was changed. Native runs and substituted unit tests
are reported separately.

The localhost-enabled full Linux invocation completed with **18,212 passed,
303 skipped, 6 xfailed and one warning in 1,805.40 seconds**. The warning is from
the intentional duplicate-ZIP-entry rejection fixture. Missing optional live
tools and native MSVC remain separately blocked; skips are not acceptance.
The earlier restricted invocation was interrupted after confirmed socket
permission failures and is not a passing run.

The receipt/cache fixes were added during the long full invocation and the final
cached-execution/output-safety corrections followed it. Focused native factory
and provenance/CLI regressions cover those final deltas. Exact-head GitHub CI
remains the integration gate; the full count is not misrepresented as a run of
the final published tree. See `results/final-validation.json` and QA for commands,
log hashes and the final focused result.

At checkpoint `0271f1869ccba0697c5bf6f797432bb7c6ec54d4`, Sonar reported a C security
rating and annotated unchecked receipt publication. The exact annotation is
preserved in `results/sonar-checkpoint-0271-annotation.json`; the CLI now enforces
the output policy above. This supersedes the older duplication-only checkpoint
description, but the repair still needs the final external gate result. No
threshold or analysis exclusion was changed. The unified live workflow is
dispatch-only; this connector has no workflow-dispatch operation, and rerunning
an old run would not validate a new source revision.

Reconcile with current main and coordinator PR #126 before merging shared QA or
task notes. Inspect final Windows/Linux/native checks and obtain the required
independent review. Do not use the owner's GitHub APPROVE identity or weaken a
quality gate. The priority R2 work is the concrete conditional-branch store
classification defect, followed by hidden-name discovery controls, structural
truth and recipe-backed real-project expansion. All R1 examples remain dev-only;
do not tune on a locked test while closing these defects.
