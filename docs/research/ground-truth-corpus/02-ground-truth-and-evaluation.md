# R1 ground truth, label promotion, leakage and evaluation audit

Research date: 2026-10-30. Baseline inspected: snapshot `95e09548a82202ae4cfd9380522f36513da87a66`; the integration owner verified that live upstream merge `a04f5a2` has the same tree. Subsequent integrated fixes are identified separately below.
Scope: development corpus and evaluation infrastructure; no production matching changes.
This is an evidence and methodology report, not a claim that the proposed additions have shipped.
The integration report and experiment receipts determine the final implemented state.

## 1. Decision

Retain the Tier R factory, `known-answer-labels/1`, Tier W symbol handling and evalcore. The smallest useful R1 addition is a conservative **acceptance audit over existing label documents**, a frozen partition manifest, and explicit coverage/denominator reporting. A second builder, new matching algorithm, or wholesale label-schema replacement would increase the unverified surface without fixing the immediate evidence gaps.

Generated labels are candidates until their source, binary identity and change evidence pass separate checks. A label digest establishes integrity; it does not establish truth. `check == ok` records a particular cross-check and currently must not be read as independent human review or proof of semantic equivalence.

Priority order:

1. Fix the demonstrated ambiguous-control cross-check error; add narrow regressions for the evidence counterexamples below.
2. Use reviewed, pinned small fixtures to establish exact controls and surviving machine-code mutations, independently of the evaluated engine. Publish accepted/excluded/unknown counts.
3. Freeze source-lineage partitions and audit overlaps before any calibration or heuristic tuning. Keep this pilot development-only until enough independent projects exist.
4. Preserve identity when the engine abstains on change; add unconditional detection and coverage metrics beside the existing conditional metrics.
5. Preserve alias sets and structural relationship groups in an additive audit record; expand the parser only when a concrete structural fixture requires it.

## 2. What the existing implementation actually guarantees

| Component | Implemented behavior at baseline | Qualification for R1 |
|---|---|---|
| `tier_r/contracts.py` | Strict frozen models, bounded fields, image/source/build records, unique per-side RVAs, deterministic summary/digest | A valid document can contain `ambiguous`, `unchecked`, or `disagree` records. Validation is not promotion. |
| `tier_r/labeler.py:join` | Join on relative file, debug name and compiler variant; repeated keys may be disambiguated by compilation unit; optional authored rename map | This is a useful candidate identity heuristic. A rename, move, clone or missing debug entry can evade the join. |
| `tier_r/csrc.py` | C tokenizer and definition locator; exact text and significant-token comparison | It does not preprocess translation units, resolve headers, prove defined behavior, or establish semantic equivalence. |
| `tier_r/debuginfo.py` | Reads LLVM DWARF/PDB tool text; resolves selected abstract/specification references; records code ranges and some clone names | It only promotes `DW_TAG_subprogram`, not nested inline sites; PDB parser recognizes procedure records and line blocks. Same-RVA aliases are discarded at inventory finalization. |
| `tier_r/bodyhash.py` | Exact raw-range SHA-256 and aggressively normalized disassembly hash | Raw equality is exact range equality. Mask equality is a heuristic, not proof of unchanged targets or semantics. |
| `label_diff` | Same source span plus masked-equal body becomes unchanged; token change plus body difference becomes changed; conflicts become ambiguous | External data and dependencies can change behavior without changing the span or instruction bytes. |
| `label_construction` | Authored mutation targets retain declared class; same-source/noise controls are unchanged by construction; some induced differences become ambiguous | The same-source construction assumption needs a documented language/ABI/configuration domain. A surviving syntactic mutation need not be behavior-changing. |
| `label_authored` | Keeps authored labels; checks presence and body expectation; split/merged endpoints become ambiguous one-sided records | Some conflicting authored labels remain scoreable because the scorer does not inspect `check`. Structural group identity is flattened into notes. |
| Tier W `labels.py` | Unique, alias-free, sized symbol joins with minimum size ratio; missing names excluded rather than turned into negatives | Stronger caution than Tier R's general one-sided-name handling, but still symbol-derived correspondence evidence, not semantic-change truth. |
| `evalcore/protocols.py` | Can represent paired identity with `flag=None`, explicit unpaired and abstained endpoints | The intermediate `EngineOutput.Prediction` has a Boolean change field and loses some of this expressiveness. |
| `lineage.py` | Union-find over project/file/PDB/body similarities; deterministic roles; identity grouping; overlap audit | Heuristic grouping and optional hub exceptions are not a guarantee of strict unseen-code evaluation. |
| `prereg.py`, `run_locked_test.py` | Verifies preregistration bytes; exclusive-create receipt before the single local locked evaluation | Useful procedural guard. Changing storage or preregistration creates another possible look; reporting must preserve history. |

Relevant contracts were read in `docs/specs/known-answer-corpus.md`, `docs/specs/unified-engine/{02-data-model,04-matching-pipeline,05-fusion-and-noise,06-adapters,08-evaluation}.md`, `docs/modules.md`, the calibration preregistration, and the implementation/tests cited here. Existing research already warns about names, ICF and debug limitations in `tools/calibration/guidelines/g1.md`; R1 must make those cautions executable rather than claim to discover a new labeling framework.

## 3. Primary-source findings and their consequences

### 3.1 DWARF describes source entities and concrete realizations

DWARF v5 distinguishes abstract function information, concrete out-of-line instances and concrete inline instances. Inline instances use `DW_TAG_inlined_subroutine`; `DW_AT_abstract_origin` links back to an abstract entity. A source function can have several realizations and disjoint address ranges. Declaration coordinates and linkage names are useful evidence, not a persistent cross-revision identity token. [S1]

Consequently, preserve two layers: a source entity and its image realizations. A realization has one or more ranges, a concrete debug identity and optional inline call-site context. Never infer deletion merely from the lack of an out-of-line realization. This conclusion is a corpus-design inference from S1, not a compiler compatibility result.

The baseline emits extra ranges as functions with variant `part`. Several parts can have the same join key, becoming ambiguous rather than a validated one-to-many relationship. That conservative exclusion is acceptable for the initial 1:1 pilot; it does not constitute structural-transform coverage. The parser's `inline_only` set is populated from subprograms without ranges and without a declaration attribute; its name overstates what that condition alone proves.

### 3.2 PDB identity and CodeView coverage

LLVM documents executable/PDB association through GUID and Age in CodeView debug information. Verify this association when consuming externally supplied symbols; a matching filename is insufficient. Fresh locally produced build outputs provide a provenance chain, but externally supplied pairs require an explicit binding check. LLVM's CodeView record list includes procedure and inline-site records; parsing only procedures is not full inline provenance. [S2, S3]

The baseline `inventory()` takes a PDB path supplied by its caller; this report does not claim it independently checks GUID/Age there. Store the PE/PDB hashes and binding result in the accepted-evidence audit. Keep inspector version and raw inspector-output hash so parser changes can be reviewed without silently changing prior truth.

### 3.3 Optimization changes the unit being matched

LLVM explicitly permits debug builds to undergo inlining, block restructuring and other optimization, and describes functions disappearing through optimization. GCC 15.2 documents cloning, partial inlining, hot/cold partitioning and interprocedural identical-code folding; enabled passes vary with target/configuration. [S4, S5]

Microsoft documents that `/OPT:REF` removes unreferenced functions and that `/OPT:ICF` can assign multiple functions the same address. `/DEBUG` affects linker defaults, so explicit optimization/link flags are necessary when comparing symbol-visible and symbol-hidden conditions. `/VERBOSE` can identify removal/folding decisions. [S6]

Implication: one function name is not one unique machine-code body, and one machine-code body is not necessarily one source function. Record the compiler, linker, flags, target triple, ABI, library inputs and optimization mode rather than only a compiler family. Pin tools actually used; the presence of an option in current documentation is not evidence that the installed tool accepts it.

### 3.4 Reproducibility is an artifact claim

The Reproducible Builds definition requires matching source, build environment and instructions to produce bit-identical specified artifacts. It is broader than compiling the same source twice in one environment. [S7] GCC's `-fdebug-prefix-map` can make debug paths independent of the build directory; that improves one reproducibility dimension and does not replace dependency/tool pinning. [S8]

Report separately: repeated-build equality on this host; engine-image equality after documented stripping; debug/PDB equality; and independent rebuild by a different operator/environment. A reproducible stripped image does not establish reproducible debug artifacts. A/A failure must remain a recorded result, with section differences, rather than be repaired by omitting unexpected bytes from the claimed artifact set.

### 3.5 Same source and equal bytes are different propositions

The corpus should maintain three independent assertions:

* **Source provenance:** the source entity and exact revision/configuration that produced code.
* **Binary realization:** the ranges, bytes, references and debug/linker evidence associated with it.
* **Expected change:** a scoped statement about code materiality or intended behavior, supported by the mutation/patch and its compiled realization.

Same revision does not imply equivalent builds if macros, generated headers, libraries, target widths, ABI, floating-point settings or undefined/implementation-defined behavior differ. Equal function bytes do not imply whole-program behavioral equality: a global initializer or dynamically resolved callee can change. Conversely, register allocation, instruction scheduling and compiler outlining can change bytes while preserving intended behavior. The initial pilot should use small reviewed unsigned arithmetic and explicit inputs, document its supported domain, and avoid a universal semantic-equivalence claim.

## 4. Demonstrated evidence failures and known limitations

The following observations were reproduced with Python imports of repository functions; no target binary was executed. These are **synthetic helper reproductions**, not live compiler/engine accuracy measurements.

### D1. Address masking erases meaningful distinctions

Command environment: `PYTHONPATH=src python`, baseline above. Using `parse_objdump` on single-instruction text at image base `0x140000000` produced:

| Old/new input | Normalized output on both sides | Result |
|---|---|---|
| `mov eax, dword ptr [rip + 0x10] # ... <g_A>` / same instruction with `+ 0x20` and `<g_B>` | `mov eax, dword ptr [rip+D]` | Equal masked hashes |
| `mov eax, 0x140001111` / `mov eax, 0x140002222`, image end `0x140010000` | `mov eax, R` | Equal masked hashes |

Supplying distinct raw hashes with those equal masked hashes makes `body_fact` return `address-only`. A changed global target or integer literal can therefore be hidden by the same equality used to cross-check label candidates. This disproves the module docstring's implication that equal masked bodies differ only in addresses in a semantically harmless sense. The numbers being inside the image do not establish that an immediate is a pointer.

This does not demonstrate that a particular published corpus case is mislabeled. It does establish that masking alone cannot independently verify one. The production unified-engine review log already recognizes an analogous global-target problem (R-01 and DATA-MAP/1); using that engine's own verdict as truth would introduce circularity. A small corpus should check operand-target identities from independent authored/debug/linker evidence, or leave the candidate unresolved. Retain existing `body` values for compatibility and describe them as heuristic observations.

### D2. An ambiguous unchanged-control record receives `check=ok`

With identical source spans but different body hashes, `label_diff(..., declared_unchanged=('f',))` emitted `identity='same', label='ambiguous', body='different', check='ok'`, with an induced-change explanation. The branch tests only `label != 'changed'`. The corresponding declared-changed branch correctly leaves ambiguity unchecked.

This is a demonstrated provenance/certainty defect: ambiguity is not verification that the card's unchanged assertion holds. The minimal fix is `ok` for verified unchanged/cosmetic outcomes, `unchecked` for ambiguity and `disagree` for a conflicting changed outcome, with a regression preserving the explanation. It should not turn an ambiguous row into a confident negative.

Implemented R1 correction, after specification amendment `0fb71f5`: the unchanged-card branch now uses those three outcomes. `tests/test_tier_r_label_promotion_r1.py` first failed in both ambiguity cases (2 failed, 3 passed), then passed after the one-line fix. Focused verification with the new regression plus Tier R contracts, source comparison, evaluator metrics and unified adapter tests: **57 passed in 1.23 s**. Scoped Ruff passed. These tests use synthetic evidence records and establish labeler behavior, not native compiler/engine accuracy; the integration owner runs the repository-wide gates.

### D3. Rename absence becomes two no-counterpart candidates

`join([before], [after])` with identical relative file/unit/RVA/size but different names yields one old-only and one new-only `Joined`, neither marked ambiguous. The resulting general diff labeling treats those as no-counterpart. Authored rename mapping can avoid this, but automatically absent names do not establish deletion/addition. Treat this as a documented heuristic limitation and exclude unreviewed absence from accepted negatives. Tier W already takes the safer approach of excluding symbol absence.

### D4. Aliases and groups lose evidence

`inventory()` sorts by RVA/project/name, retains the first entry at each RVA and increments `skipped` for the others. This is deterministic but loses the membership of an ICF alias set. `label_authored` also indexes source functions by name alone, so repeated static names can overwrite one another before cross-checking. These are code-inspection findings; this audit did not build a live ICF fixture. Preserve the raw inventory/alias membership and reject ambiguous name-only lookup before claiming ICF accuracy.

### D5. Unknown identity and unknown change are partially conflated

`EnginePair` can carry `identity='paired', flag=None`, but baseline unified adaptation drops a paired row whose materiality is unknown. Candidate/contested/ambiguous endpoints are also counted as unaddressed rather than retained as explicit abstentions. The resulting coverage cannot always distinguish no proposed correspondence from a correspondence with no materiality opinion. This is an acknowledged transport limitation, not a reason to coerce unknown into unchanged.

### D6. Disagreeing authored truth is still eligible for scoring

`score_pair` excludes ambiguous labels/identity, but does not exclude `check='disagree'` or `unchecked`. This is consistent with the old contract retaining authored truth for review; it is inadequate as R1 promotion policy. Apply an accepted-record selection before evaluation, preserving excluded records and reasons, rather than rewriting their class to make results agree.

## 5. Promotion policy over existing contracts

Keep label documents immutable. A small strict audit/acceptance record should reference their digest, input artifact hashes, evidence hashes and stable record keys. It can be stored alongside the existing case provenance and validated before the existing scorer consumes a filtered view. Register any new substantial module/spec/schema before implementation. The following fields are design requirements, not a claim that a new version already exists:

* Stable case/entity/realization keys independent of absolute paths. A key should include project namespace, relative file/compilation unit, language linkage/signature and a reviewed cross-revision entity mapping. A source line is a locator, not the stable identity.
* Evidence categories retained separately: authored construction, source diff, bound debug symbols, exact bytes, operand-target validation, linker map/optimization remarks, and manual review. Several views of the same compiler metadata are not independent reviewers.
* Status `candidate`, `accepted`, `rejected` or `unresolved`; reason codes; reviewer/tool identifier and version; exact evidence digest; and prior decision digest when superseded. Do not invent numeric confidence percentages without validation.
* Separate identity acceptance and change acceptance. Identity may be accepted while change is unresolved, or a transformation may be accepted at group level while 1:1 identity is inapplicable.

Promotion rules:

1. Verify source pin/license/recipe/toolchain and image/debug binding. Require inventory completeness for the advertised fixture scope; count skipped/unmapped/runtime code.
2. Establish identity using authored construction plus independently located image realizations, or reviewed source continuity plus bound debug/linker provenance. Names alone create candidates.
3. Cross-check the expected compiled observation. A mutation that produces identical bytes and targets is an optimized-away/inactive mutation; retain its attempt receipt but exclude it from material-change sensitivity. A byte difference alone is not proof of semantic impact.
4. Verify a material mutation through an input/output or control/data-flow argument over its supported input domain and inspect the changed compiled operands/instructions. Source tests or proofs may inform review, but no target execution is permitted by repository policy.
5. Accept a negative control only for the assertion actually verified: exact same image, defined same-source construction under declared configuration, or independently reviewed cosmetic transformation. Header/data/callee effects must be explicitly bounded.
6. Never promote `disagree`, missing evidence or unresolved identity because an evaluated engine agrees. Store disagreements without altering raw labels. Preserve both numerator and denominator effects of exclusion.

For an initial authored fixture, one researcher can provide mechanically reproducible evidence independent of the engine. That is **independently verifiable**, not automatically independent second-person review. Record second-person review as pending until it occurs.

### Structural relationships

A future group record should carry old/new realization sets, relation (`split`, `merged`, `inlined-into`, `outlined-from`, `icf`, `duplicate`, or unresolved), source entities, evidence and acceptance state. Do not expand an N:M group into its Cartesian product: membership does not assert every pair is equivalent.

For ICF, keep the complete alias/source-entity set attached to one physical realization. For inlining, require evidence of caller/call-site and origin, not only disappearance. For splitting, preserve the complete address-range set. For outlining, require a verified body-origin map or authored transformation plus compiler/linker evidence. A missing function with no such evidence is unresolved absence. Current ambiguous scalar labels remain an appropriate backward-compatible projection while group scoring is unavailable.

Group evaluation must state its equivalence rule: exact relation plus old/new member sets, or a separately reported endpoint-membership precision/recall. A correct group should not be scored as several wrong 1:1 matches, and a merely ambiguous group should receive neither positive nor negative credit.

## 6. Denominators and unknowns

The baseline `score_pair` implements its documented contract: identity precision/recall over scoreable 1:1 truth, and change metrics **conditional on correct identity matching**. `changed_truth` increments only inside `credit()`. `tests/test_tier_r_eval_metrics.py:test_missing_matches_lower_recall_not_precision` explicitly expects undefined changed recall when no changed function was matched. This is not a denominator implementation bug. It is a metric that needs a precise displayed name and complementary unconditional results.

| Measure | Population and denominator | Missing/unknown treatment |
|---|---|---|
| 1:1 identity precision | Correct accepted predicted edges / all predictions touching at least one accepted scored endpoint | Unlabeled-only predictions counted aside; never pretend their precision is known. |
| 1:1 identity recall / FNR | Correct accepted edges / all accepted 1:1 truth edges; FNR is missed truth edges / same denominator | Absent, wrong and abstained identity all fail recall, with separate outcome counts. |
| Conditional changed recall | Flagged correct changed pairs / correctly matched accepted changed pairs | Preserve existing value; report matched coverage beside it. |
| Unconditional material detection | Correctly paired and materially flagged accepted changes / all accepted material changes | Wrong/missing pairing, abstained change and cosmetic classification are distinct misses. |
| Negative false-lead rate | Materially flagged accepted negative controls / all accepted eligible negative controls | An abstention is not a true negative. Report abstention and identity coverage; give selective rate over decided controls separately. |
| Existing `fp_rate` | Flagged correctly paired unchanged/cosmetic rows / all correctly paired unchanged/cosmetic rows | Keep compatibility and label it conditional matched-negative flag rate. |
| Unmatched/ambiguous/unknown rates | Count of each declared endpoint/edge outcome / advertised accepted population | Preserve identity and change unknown separately. Ambiguous truth is excluded from accuracy and counted in truth coverage. |
| Correspondence FPR | False committed edges / independently verified negative candidate edges | Requires an explicit frozen candidate universe; undefined without it. |

Precision alone cannot provide correspondence FPR. The huge Cartesian product of all functions supplies an unhelpful and arbitrary true-negative denominator, especially when inventories differ. Instead freeze a reviewed hard-negative candidate set (same-name different unit, similar body different target, added/removed bait, clone ambiguity), or report false correspondences per 1,000 eligible endpoints. Candidate-selection probability must be retained if a sampled candidate population is used for natural estimates.

Do not call every unobserved cross-pair negative. One-sided absence is a verified negative only after proving the relevant relation cannot be explained by rename, move, inline/outline, folding, missing symbols or extraction failure. A wrong correspondence touching two truth rows is one false predicted edge for edge precision, although it can affect two endpoint outcomes; report those as different units.

For all ratios publish integer counts, zero-denominator `null`, micro aggregation, per-project/lineage macro results and group bootstrap intervals when enough groups exist. A tiny pilot establishes harness operation, not precise population accuracy. Keep the existing small-lineage/anti-conservative interval warnings. Do not combine scores from different engines into a common probability.

Report identity F1 directly as `2 TP / (2 TP + FP + FN)` when its denominator is positive. For change classification preserve the native categories before reducing them to a flag: `material`, `review`, `cosmetic`, `unchanged`, `unknown`, `not-applicable`, and no correspondence. The baseline adapter treats `review` as flagged; that is a useful reviewer lead but does not itself certify a material-change verdict. A confusion table over accepted material/cosmetic/unchanged truth should expose material-to-cosmetic errors, cosmetic-to-material errors, review outcomes and unknowns separately. The unconditional negative flag rate is a workload measure; with abstention it must not be advertised as `1 - specificity` or as accuracy on decided cases.

### Ghidriff omission is an upper bound

The baseline intentionally credits unmentioned truth pairs as correct and unchanged when `implicit_unchanged=True`; both code and report notes call identity results an upper bound. Missing output is not an observed correspondence. Preserve this historical statistic, but show an **explicit evidence** metric beside it and exclude inferred pairs from claims of independently observed matching recall. If complete address-match data is available, use a versioned adapter that reads and binds it rather than assuming omission implies success. The attention baseline inherits the same limitation because its list is built over Ghidriff matches.

## 7. Partition policy and leakage checks

Freeze a partition manifest before tuning. Include source revisions, all source-family/project lineage edges, adjacent releases, compiler variants, stripped/debug copies, layout variants, mutants, alias/group relations, imported fragment provenance, manifest hash and preregistration hash. A case pair's endpoints and every derivative stay in one partition. Assign a future new derivative through its original lineage, not a newly hashed binary ID.

Reuse `lineage.identity_groups` and `shared_identities`; add evidence-backed source/derivation keys missing from their inputs rather than replacing union-find. Audit:

1. Exact binary/debug/PDB digest overlap.
2. Same source entity and base-revision/mutation lineage across partitions.
3. Adjacent version endpoints and compiler/linker variants of the same source project.
4. Copied or vendored function fragments with known provenance; exact body duplicates; reviewed near-duplicate candidates.
5. Reused mutation templates when claiming generalization to unseen transformations. Use a separate leave-operator-family-out experiment rather than presenting template reuse as novelty.

Important existing behavior: `cluster()` can raise the body-overlap threshold when everything forms one component. That deliberately recomputes body edges and can remove earlier weak-overlap edges; explicit project/file/PDB edges remain. The docstring's component-never-split language should not be interpreted as evidence that all weak overlap relationships survive. Record the selected threshold and excluded candidate edges.

`identity_groups(..., hub_max_lineages=...)` intentionally does not union common hub identities and marks associated candidates `seen_body`. This is useful for stratification, but a strict unseen-code test must exclude or explicitly separate cross-partition hub code. Otherwise disclose shared-fragment exposure. Common runtimes should be excluded from the scored project inventory and their presence still counted.

Keep validation inside development groups. The preregistered locked set should have sufficient independent lineages; do not manufacture a locked pilot by splitting a few fixtures or by resalting until balance looks good. The existing single-look receipt protects a local preregistration run; the study log must also record failed attempts, changed preregistrations and any prior access. Any structural/data corrections after a look require a disclosed new evaluation, not silent replacement of the old result.

## 8. Minimal pilot acceptance and open work

The first reproducible evidence should include an exact-image/A/A control; a layout/symbol-stripping control; a constant/branch mutation whose changed instructions are independently inspected; and a reference-target mutation deliberately challenging address masking. A structural fixture may remain accepted only at group level. Store pin/recipe/tool versions, source and artifact hashes, label/audit digests, exact command, raw engine-output digest and engine status for each run. Run Ghidriff first where available; missing tools are blocked with reasons.

Run existing focused label/scorer/schema/lineage tests and new regressions, then repository Linux/Ruff gates. Windows compiler builds and genuine matching-engine runs are separate acceptance rows; Python helper tests cannot satisfy them. Time/memory measurements must distinguish build, extraction and comparison; cold cache and warm cache; elapsed wall time and process-tree peak memory. An absent measurement is `null` with a reason, not zero.

Research conclusions independently checked in this subtask: repository function behavior via the three synthetic reproductions D1–D3 and direct code/spec/test inspection. Not independently checked here: live MSVC/GCC/Clang transformation output, DWARF/PDB parser completeness on those compilers, a genuine engine's pilot accuracy, an external operator's rebuild, or second-person label adjudication. Those belong to integration experiment receipts. R1 completion must remain conditional on those actual receipts and required CI/review gates.

## 9. Source register

All URLs below were opened through web retrieval on 2026-10-30. Online LLVM pages are rolling documentation and are not compiler-version pins. These are primary documentation sources; the report uses short paraphrases and no substantial copied passages. Documentation terms are not permission to redistribute third-party corpus binaries.

| ID | Original source / version | Relevant evidence | License/redistribution and verification status |
|---|---|---|---|
| S1 | DWARF Committee, [DWARF v5 specification](https://dwarfstd.org/doc/DWARF5.pdf), 2017-02-13, especially §3.3.8 | Abstract/concrete/inline instances and address ranges | PDF states GNU FDL 1.3. Primary PDF read; no new compiler-output verification in this subtask. |
| S2 | LLVM, [PDB Info Stream](https://llvm.org/docs/PDB/PdbStream.html), rolling | Executable/PDB GUID and Age association | Official documentation; retrieved, not a redistribution grant for Microsoft PDBs. |
| S3 | LLVM, [CodeView Symbol Records](https://llvm.org/docs/PDB/CodeViewSymbols.html), rolling | Procedure and inline-site record families | Official documentation read; actual installed-tool text grammar requires fixture validation. |
| S4 | LLVM, [Source Level Debugging](https://llvm.org/docs/SourceLevelDebugging.html), rolling | Optimized debug code, inlining and disappearing functions | Official documentation read; no live optimization experiment claimed. |
| S5 | GCC, [Optimize Options, GCC 15.2.0](https://gcc.gnu.org/onlinedocs/gcc-15.2.0/gcc/Optimize-Options.html) | Cloning, ICF, partial inlining, hot/cold splitting; target variation | Versioned official manual read. GCC documentation licensing is separate from a corpus project's license. |
| S6 | Microsoft Learn, [/OPT (Optimizations), MSVC 170 view](https://learn.microsoft.com/en-us/cpp/build/reference/opt-optimizations?view=msvc-170) | REF, ICF, same-address aliases, debug-dependent defaults and verbose linker evidence | Official public article text retrieved. No MSVC binaries/SDK files redistributed or live Windows result asserted. |
| S7 | Reproducible Builds, [Definitions](https://reproducible-builds.org/docs/definition/), rolling | Precise source/environment/instructions/artifact equality claim | Page identifies content CC BY-SA 4.0; definition read. Independent rebuild not performed here. |
| S8 | GCC, [Debugging Options, GCC 15.2.0](https://gcc.gnu.org/onlinedocs/gcc-15.2.0/gcc/Debugging-Options.html) | Debug path remapping and inline-debug options | Versioned official manual retrieved; no assumption that an arbitrary installed compiler supports every documented flag. |

Dataset/tool surveys and patch-source licenses are maintained in the companion R1 literature report and existing `docs/research/calibration/preexisting-labelled-data.md`. Their evidence should not be upgraded from previous search-only or unverified status without retrieving the primary pinned source. The latter report's earlier suggestion that symbol-only absence maps to no-counterpart needs the qualification in D3 before it is used for accepted R1 negatives.
