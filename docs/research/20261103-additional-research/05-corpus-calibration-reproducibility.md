# Corpus, calibration and reproducible-build reuse

Research date: **2026-11-03, America/Vancouver**. Repository baseline: `b77d84e5decf736b031f0a24094001274de41178`. This is additional research for Claude, not implementation or a new calibration protocol. Proposed experiments below have **not** been run in this research pass.

## 1. Decision

Use upstream code primarily as **development-time reference implementations, fixture generators and independent checks**. PatchTrace already has a substantial corpus factory, grouped calibration pipeline, deterministic build settings and optional numerical cross-checks. Replacing those systems would discard established contracts and duplicate active work. The highest-value additions are better source-origin support, explicit environment-variation evidence, version-qualified parser oracles, and lifecycle tests for retained outputs.

The existing calibration target remains **function correspondence**, as defined in [SPEC-28](../../specs/calibration-corpus-and-model.md). This note proposes no vulnerability probability, exploitability model, target execution, or new semantic proof claim.

## 2. What already exists, and what is active elsewhere

These observations come from the pinned PatchTrace tree:

| Existing seam | Source | Consequence for additional research |
|---|---|---|
| Controlled compilation, content-addressed images, separate debug and engine images | [build.py](../../../tools/calibration/tier_r/build.py), [toolchain.py](../../../tools/calibration/tier_r/toolchain.py) | Keep explicit compiler argv and the rule against running upstream project build scripts or generated images. |
| Deterministic source timestamp, path mapping, and locale/timezone defaults | `build.py`, `toolchain.py`, [shard.py](../../../tools/calibration/tier_r/shard.py) | These controls are implemented. Measure their effect rather than propose them as absent. |
| Deliberate ICF, timestamp, GUID and path nuisance variants | `NUISANCES`, `nuisance_compile`, `nuisance_link` in `build.py` | Extend measured coverage only where a gap remains. |
| PDB, DWARF and COFF inventories from LLVM tools | [debuginfo.py](../../../tools/calibration/tier_r/debuginfo.py) | Add version-qualified reference outputs and disagreement accounting. |
| Lineage/identity grouping and grouped nested cross-validation | [lineage.py](../../../tools/calibration/lineage.py), [cv.py](../../../tools/calibration/cv.py) | Preserve groups across every fit, calibration and evaluation step. |
| Optional scikit-learn comparisons for logistic, isotonic and sigmoid calibration | [test_calibration_math.py](../../../tests/test_calibration_math.py), [pyproject.toml](../../../pyproject.toml) | The oracle already exists. Record its executed version and non-skipped results. |
| Pinned fetch with license-file digest and permissive recipe policy | [fetch.py](../../../tools/calibration/tier_r/fetch.py), [contracts.py](../../../tools/calibration/tier_r/contracts.py) | Non-GitHub discovery is useful, but present recipe admission does not support arbitrary origins. |

Open [PR #176](https://github.com/djshellshoxxx/patchtrace/pull/176), inspected at `db0a0b05d48e4c8fb394ec4e221677b5efb37954`, already carries retained engine outputs, replay credits and preregistration selection work from earlier PRs #154/#157. Its `tools/calibration/tier_r/output_store.py` is an **active unmerged implementation**, not an absent feature. Coordinate before changing evaluation persistence or training entry points.

Prior [R1 research, PR #128](https://github.com/djshellshoxxx/patchtrace/pull/128), contains native pilot observations, build receipts and corpus admission work. Prior [R5 research, PR #132](https://github.com/djshellshoxxx/patchtrace/pull/132), already covers grouping, sample weighting, probability gates, train/serve consistency and limits of effective-sample risk calculations. Read and preserve those results. The new contribution here is an upstream-reuse and qualification map; it does not relabel prior findings as new discoveries.

## 3. Candidate selection

| Candidate and source origin | Verified useful capability | Reuse decision | Licensing/source qualification |
|---|---|---|---|
| **reprotest**, canonical Debian Salsa; versioned Debian Sources | Varies build environments and compares artifacts; implementation and packaged license available [S1], [S2], [S3], [S4] | Adapt its experiment taxonomy to the existing factory; optional isolated Linux diagnostic | Inspected source package **0.7.30**. Overall GPL-3.0-or-later; `lib/*`/`virt/*` contain GPL-2.0-or-later material. Do not copy wholesale into the MIT runtime. |
| **diffoscope**, Debian Salsa/Debian Sources | Recursive artifact comparison and readable diagnostics [S5] | Optional offline developer diagnostic; see [engine note](02-engine-runtime-reuse.md) | GPL-3.0-or-later. Not a function-correspondence oracle or replacement supervisor. |
| **LLVM `yaml2obj`, `llvm-readobj`, `llvm-pdbutil`** | Generate COFF fixtures and inspect PE/COFF/PDB structures [S6], [S7], [S8], [S9] | Pinned development tools through the existing bounded runner | LLVM core: Apache-2.0 WITH LLVM-exception, subject to third-party inventory [S10]. Selected distribution/tool versions still need qualification. |
| **LLVM test-suite** | Source programs for compiler testing [S11], [S12] | Select individual sources after file-level admission; defer whole-suite import | Its license inventory identifies separately licensed subtrees. A root license is not permission for every benchmark. |
| **scikit-learn** | Group-aware splitting and calibration/reference algorithms [S13], [S14], [S15] | Keep the existing optional dev oracle; extend qualification evidence | Calibration source identifies BSD-3-Clause. Web docs resolved to 1.9.1; this does not establish PatchTrace tested that version. |
| **Hypothesis** | Generates action sequences and checks state-machine invariants [S16], [S17] | Existing dev dependency for small persistence/replay models | MPL-2.0 except identified material; do not copy or ship its implementation. |
| **SOURCE_DATE_EPOCH specification** | Deterministic timestamp exchange [S18] | Reference for already implemented controls | Revision 1.1; own copyright text is MIT-style. A timestamp setting is not a reproducibility result. |

“Adapt” means a small PatchTrace-specific integration or experiment around a documented interface. It does not mean removing notices or assuming a subprocess boundary resolves distribution obligations.

## 4. Non-GitHub corpus origins: the concrete integration barrier

At this baseline, `Recipe.upstream_git` in `tools/calibration/tier_r/contracts.py` requires `https://github.com/<owner>/<repo>`. Separately, `fetch.py` defaults `ALLOWED_HOSTS` to `('github.com',)` and its URL parser accepts exactly an owner/repository path. Changing only the allowlist would not admit all useful origins: a nested GitLab namespace, SQLite Fossil repository, or signed source archive has different identity and transport semantics. This is an observed contract limitation, not a network error.

**Recommended design:** define an explicit source-origin union before implementation. Start with a narrow `git-https` case: approved exact host, full repository path, immutable commit, license-file path/hash, selected source-file hashes and acquisition receipt. Permit nested namespaces through parsed path components and existing path validation. Preserve the existing size, file-count and checkout restrictions, and explicitly define redirect/origin policy for each admitted transport. Add a separately versioned archive/Fossil case only when an approved recipe needs it; an archive digest is not a Git commit, and a Fossil artifact identifier must not be forced into a 40-hex Git field.

Prefer an offline reviewed source snapshot when another transport would cost more than its corpus value. Preserve canonical origin and fetched mirror identity separately. A GitHub mirror is an acquisition location, not proof of upstream authority. Do not enable arbitrary repositories or project build scripts as a shortcut.

**Acceptance:** existing GitHub recipes remain byte-for-byte compatible; one approved nested GitLab repository can be represented and verified; unapproved hosts remain refused; identity mismatch produces no admitted recipe; missing license evidence blocks admission; re-import is deterministic. Use authored fixture metadata and temporary directories. No target execution is needed.

**Ownership:** `contracts.py`, `fetch.py`, `manifest.py` and SPEC-32/schema files. Inspect current PR #176 and R1 branches first. This is a later focused implementation task; the research pass does not alter these controls.

## 5. Reproducibility: reuse experiment design without replacing the factory

The reproducible-builds project recommends isolating differing build steps and varying potential causes. `reprotest` makes environment differences explicit and can retain outputs. Its documented factors include build path, environment, file order, locale, timezone and time. [S1], [S2], [S3] PatchTrace already fixes several of these and deliberately varies others.

Use two reports:

1. **Artifact repeatability:** identical admitted sources, toolchain, profile and declared environment produce the same relevant bytes or an explained difference.
2. **Comparison stability:** a declared nuisance change leaves expected correspondence/change classifications stable, with exclusions and ambiguity retained.

A report can pass one and fail the other. Identical rebuild bytes do not validate matching across optimization levels. Stable matching does not establish byte-identical packaging. Keep original files and full SHA-256 values; never rewrite evidence to make a report pass. Normalized views require their own named rules and identity.

Proposed compact matrix, extending existing nuisance coverage only where absent:

| Variation | Question | Retained evidence |
|---|---|---|
| Different scratch roots, including Unicode/spaces | Do paths enter PE/PDB output or output identity unexpectedly? | Source manifests, compiler/linker argv, raw hashes, declared path mappings |
| Fixed source timestamp, different wall clock | Which artifacts still depend on current time? | Timestamp source and each differing artifact class |
| Different input enumeration/link order | Does permitted ordering alter bytes or matching? | Ordered object lists, expected labels and observations |
| Same content, another locale/timezone | Does the runner enforce its declared environment? | Effective non-secret environment and parser output |
| Supported compiler/LLVM patch versions | Does format drift affect inventories or labels? | Executable identity, version text and compatibility results |

Use `diffoscope` to explain bounded developer-owned artifact differences when simpler structured inspection is insufficient. Do not upload artifacts to its hosted service. Its report is diagnostic material, not ground truth. Retain a fixed source timestamp [S18] in the build receipt, but do not substitute it for measured results.

## 6. LLVM fixture and parser reuse

LLVM documents `yaml2obj` as a YAML-to-object converter with COFF support. `COFFEmitter.cpp` is a concrete format reference; `llvm-readobj` has PE/COFF inspection options, and `llvm-pdbutil` is used by LLVM's PDB tests. [S6], [S7], [S8], [S9] These support small authored fixtures and independent header/debug checks without another desktop parser library.

**Integration:** use existing fixture conventions and `tools/calibration/tier_r/toolchain.py`. Compare selected headers, debug-directory records, section/RVA conversions and symbol fields with `pe_overview`/`debuginfo`. Persist generator input, tool version and output hash. Version observations; never regenerate goldens silently during ordinary tests.

`llvm-readobj` documents JSON formatting under `--elf-output-style`; that is not a general JSON schema promise for Windows PE records. [S8] LLVM 20.1.8's source selects a shared JSON writer for COFF as well. Qualify the selected PE fields and output schema before choosing JSON or a pinned text dialect. Unsupported versions or unrecognized records must create an explicit coverage limitation, not an invented empty inventory. The [engine note](02-engine-runtime-reuse.md) examines the COFF dispatch source; qualify the specific source/version/interface actually selected rather than infer portability from a flag name.

**Acceptance:** independent tools agree on selected fields in authored valid fixtures; ambiguous symbol mappings stay ambiguous; text changes cannot silently reduce inventories to zero; timeout differs from valid no-data output. An independent header check confirms that header, not source-function identity. Do not score a tool against labels derived only from that same tool.

LLVM test-suite is a source pool, not a ready-made labelled PatchTrace corpus. Its normal workflow includes execution and its license inventory has third-party exceptions. [S11], [S12] Only individually reviewed sources fit the explicit-argv/no-execution factory. Compiler test results do not automatically establish before/after correspondence labels.

## 7. Calibration: qualify the oracle already present

`GroupKFold` keeps each supplied group outside the corresponding training fold; it does not discover missing ancestry. [S13] Construct lineage and shared-identity groups first. A library cannot repair group membership or remove duplicated source functions across training/evaluation automatically.

scikit-learn's guidance requires calibration data independent of the base estimator's fit and explains why Brier loss alone does not isolate calibration quality. [S14] Use it as a methodological/numerical check. Do not replace the small runtime with serialized estimator objects or add NumPy/SciPy to the frozen package merely to support a dev oracle.

**Concrete follow-up:** run the existing logistic/isotonic/sigmoid comparisons in a development qualification job with `calibration-dev` actually installed. Record scikit-learn/NumPy/SciPy versions, tolerances, weighting conventions and test counts. Existing `pytest.importorskip` calls mean an ordinary green run does not establish these checks executed. The sigmoid comparison calls the private `_sigmoid_calibration`; pin that check or replace it with a supported-interface comparison before qualifying a new upstream version. A changed private API should fail qualification clearly, not disappear into a skip.

Add **training/runtime feature parity** over benign stored runs: feature schema, missingness, producer identity, transform parameters and vector values. Keep unavailable evidence distinct from zero. Exercise supported engine-presence profiles; a model trained with all engines must not silently consume a different profile. These are acceptance experiments, not a new probability claim.

R5 already identifies an unresolved inference issue: a design-effect-adjusted effective count does not itself establish an exact binomial risk test's assumptions. Learn then Test supplies a hypothesis-testing framework, not a proof of this repository-specific adaptation. [S19] Retain ordinal fallback while that question remains unresolved. Arithmetic agreement with a library is not validation of a statistical guarantee.

## 8. Stateful testing of retained evidence

Hypothesis can generate action sequences and check transition invariants. [S16] It is already a dev dependency, so a narrow model can be cheaper than adopting a workflow framework.

**Proposed actions:** create project; publish a completed synthetic result; start another; cancel before publication; close; reopen; export; restore backup. The oracle is the publication/ownership contract, not copied implementation internals. Assert interrupted attempts retain the last committed result, reopening resolves the same evidence IDs, and exports never mix two projects.

Coordinate with PR #176. Begin with the narrowest lifecycle risk, bound transitions and convert any discovered failure into an ordinary deterministic regression. This is not a request for broad randomized testing of every module. No target or third-party program needs to execute in the model test; separate Windows/native acceptance supplies platform evidence.

## 9. Suggested Claude work packets

| Packet | Priority | Small deliverable | Completion evidence |
|---|---|---|---|
| C1: existing calibration oracle | P1 | Version-recorded dev-only reference run | No optional skips; dependencies/tolerances recorded |
| C2: retained-output lifecycle model | P1, coordinate #176 | Bounded commit/cancel/reopen/export model | Completed evidence survives documented transitions |
| C3: parser compatibility receipt | P1 | LLVM dialect/version record | Unsupported output distinguished; selected fields cross-checked |
| C4: reproducibility/stability reports | P1 | Two reports over existing nuisance factory | Raw hashes, normalized identities and outcomes stay distinct |
| C5: one reviewed non-GitHub origin | P2, spec first | Narrow source contract/adapter | Existing recipes unchanged; host/pin/license admission retained |
| C6: additional upstream corpus | P2, after C5 | A few approved recipes and justified labels | File-level licenses and ancestry verified |
| C7: calibration methodology disposition | Existing R5 gate | Supported population/assumption decision | No guarantee beyond validated assumptions; ordinal fallback |

These are proposals, not newly opened tasks or implementation claims. Owners should avoid PR #176's active files until ownership is coordinated.

## 10. Sources and access limits

Sources were checked during this pass. A release/doc version is an inspection anchor, not an installation commitment. Recheck exact pins/licenses before vendoring. Some Salsa raw views and reprotest 0.7.33 source pages failed; the inspected implementation is the reachable **0.7.30** Debian package. Historical mirrors were not silently substituted as current upstream.

- **S1:** [Reproducible Builds tools](https://reproducible-builds.org/tools/).
- **S2:** [Reproducibility troubleshooting](https://reproducible-builds.org/docs/reproducibility-troubleshooting/).
- **S3:** [reprotest manual](https://manpages.debian.org/testing/reprotest/reprotest.1.en.html).
- **S4:** [reprotest 0.7.30 source](https://sources.debian.org/src/reprotest/0.7.30/reprotest/__init__.py), [file-level copyright](https://sources.debian.org/src/reprotest/0.7.30/debian/copyright), [canonical Salsa](https://salsa.debian.org/reproducible-builds/reprotest).
- **S5:** [diffoscope project/license](https://diffoscope.org/); source evaluation in [02](02-engine-runtime-reuse.md).
- **S6:** [LLVM yaml2obj](https://llvm.org/docs/yaml2obj.html).
- **S7:** [COFFEmitter source](https://llvm.org/docs/doxygen/COFFEmitter_8cpp_source.html), moving doc view; pin before copying.
- **S8:** [llvm-readobj manual](https://llvm.org/docs/CommandGuide/llvm-readobj.html).
- **S9:** [llvm-pdbutil manual](https://llvm.org/docs/CommandGuide/llvm-pdbutil.html).
- **S10:** [LLVM licensing policy](https://llvm.org/docs/DeveloperPolicy.html), [license inventory](https://github.com/llvm/llvm-project/blob/main/LICENSE.TXT).
- **S11:** [LLVM test-suite guide](https://llvm.org/docs/TestSuiteGuide.html), [testing infrastructure](https://llvm.org/docs/TestingGuide.html).
- **S12:** [LLVM test-suite license inventory](https://github.com/llvm/llvm-test-suite/blob/main/LICENSE.TXT).
- **S13:** [GroupKFold](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.GroupKFold.html), docs 1.9.1.
- **S14:** [Probability calibration](https://scikit-learn.org/stable/modules/calibration.html).
- **S15:** [Calibration source/SPDX header](https://github.com/scikit-learn/scikit-learn/blob/main/sklearn/calibration.py).
- **S16:** [Hypothesis stateful tests](https://hypothesis.readthedocs.io/en/latest/stateful.html), docs 6.170.14.
- **S17:** [Hypothesis license](https://github.com/HypothesisWorks/hypothesis/blob/master/LICENSE.txt).
- **S18:** [SOURCE_DATE_EPOCH revision 1.1](https://reproducible-builds.org/specs/source-date-epoch/).
- **S19:** [Angelopoulos et al., Learn then Test, arXiv:2110.01052v5](https://arxiv.org/abs/2110.01052v5). R5 has the broader bibliography; this pass does not repeat it.

[S1]: https://reproducible-builds.org/tools/
[S2]: https://reproducible-builds.org/docs/reproducibility-troubleshooting/
[S3]: https://manpages.debian.org/testing/reprotest/reprotest.1.en.html
[S4]: https://sources.debian.org/src/reprotest/0.7.30/reprotest/__init__.py
[S5]: https://diffoscope.org/
[S6]: https://llvm.org/docs/yaml2obj.html
[S7]: https://llvm.org/docs/doxygen/COFFEmitter_8cpp_source.html
[S8]: https://llvm.org/docs/CommandGuide/llvm-readobj.html
[S9]: https://llvm.org/docs/CommandGuide/llvm-pdbutil.html
[S10]: https://llvm.org/docs/DeveloperPolicy.html
[S11]: https://llvm.org/docs/TestSuiteGuide.html
[S12]: https://github.com/llvm/llvm-test-suite/blob/main/LICENSE.TXT
[S13]: https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.GroupKFold.html
[S14]: https://scikit-learn.org/stable/modules/calibration.html
[S15]: https://github.com/scikit-learn/scikit-learn/blob/main/sklearn/calibration.py
[S16]: https://hypothesis.readthedocs.io/en/latest/stateful.html
[S17]: https://github.com/HypothesisWorks/hypothesis/blob/master/LICENSE.txt
[S18]: https://reproducible-builds.org/specs/source-date-epoch/
[S19]: https://arxiv.org/abs/2110.01052v5
