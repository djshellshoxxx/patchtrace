# Independent Rizin research-adapter review

**Accepted: no remaining blocker for the bounded native identity and recognition repair** at `61b7cfb49a6f496eb85efd091b2820d114e7d444`, tree `b639fb11db07761195fba5c309476474cd19caba`.

This review was independent of implementation. It inspected the complete three-file change from published base `3123b6d447b96e19781094f276cdd84456e5e386`, including both specification-first commits and their additive fixes. Tests ran in detached review worktrees, with source identities recorded before and after. The final checkout remains clean. No remote publication was performed by this reviewer.

## Reproduced defects and regression evidence

The independent minimal authored report contains an unchanged target at old address0x40/new0x50 and an unrelated changed function at old0x500/new0x600, both carrying the same label. The production secondary normalizer preserves both identities; the old research adapter discarded the addresses and unchanged row, returned the target label, and the synthetic scorer returned HIT. A wrapper whose first list held the changed row while a later list held the unchanged conflicting row also returned HIT. A malformed unchanged record with a missing address was silently converted to `[]`, yielding a synthetic no-change HIT. Inputs, normalized rows and outcomes are retained in `baseline-counterexamples.json`.

| Independent invocation | Source | Result |
|---|---|---|
| Original 114 external controls, baseline | `ddb1bb97` / published `3123b6d4` equivalent tree | **94 failed, 20 passed** |
| Original controls, initial repair | `3b22a27c` | **114 passed** |
| Separate 18 recognition controls, red proof | `3b22a27c` | **12 failed, 6 passed** |
| Original controls, final repair | `61b7cfb4` | **114 passed** |
| Recognition supplement, final repair | `61b7cfb4` | **18 passed** |
| Repository adapter/scoring/scorerun/native-identity selection | `61b7cfb4` | **202 passed** |

All these invocations had zero collection/runtime errors and zero skipped cases. The original 114 external controls were not edited after the baseline run. The separate supplement reproduces the initially unrecognized native record with known type but both side keys missing, through direct parsing, CLI handling and scorerun no-change scoring. Its six positive controls preserve explicitly named flat legacy records with all three native-like type values. The original red outcomes and the intermediate recognition failure are retained; they are not replaced by final green results.

Whole-tree `ruff check --no-cache src tests tools` and the full-range Git whitespace check pass. The repository invocation contains the existing adapter, scoring and scorerun modules plus the new native identity module. These overlapping behavioral selections are presented separately, not as an accuracy denominator.

## Source-review findings

The complete change remains limited to `tools/research_qualification/adapters/rizin.py`, the dedicated new test module and `docs/research/adapters.md`. The original source and supplement each follow their specification commit, and the exact published base remains an ancestor. Every new commit retains the literal `[no release]` marker.

The JSON object-pairs loader rejects duplicate keys before a value can be overwritten. It detects native side keys throughout the document before the legacy reader selects its first list. It also recognizes `COMPLETE`, `PARTIAL` and `UNLIKE` records lacking both legacy `name` and `name2` fields. Recognized native data must be a bare array with a closed row/side shape, so neither wrapper selection nor omission of both sides can silently turn those records into a legacy no-change result.

Every native record is checked before any candidate list is returned. This includes unchanged rows, unselected newer names and one-sided rows. Per-side address maps preserve the distinction between older and newer address spaces. A global normalized-label-to-endpoint-pair map catches cross-side reuse, including an unchanged renamed pair whose newer label matches an unrelated changed older function. The same label within one pair remains valid. Repeated addresses must agree on the full validated record, including raw names, sizes, type and numeric similarity. Exact repeats contribute once and remain invariant under row permutation.

The raw native row cap includes unchanged and repeated records and is enforced before identity indexing. Existing loader bounds remain unchanged; JSON is still decoded before that row cap, so this is not a claim of streaming allocation. Indexing uses bounded maps with linear work in native rows, followed by the existing name ranking. Address zero and the maximum uint64 are accepted; booleans and malformed identities are refused. No global prefix stripping, Unicode/case folding, source alias invention, scorer alteration, product parser alteration or external dependency was introduced.

Positive controls preserve valid native ranking, renames, one-sided ordering, exact repeats, normalized names within one pair, literal prefixes/case/Unicode distinctions and recorded native/legacy fixtures. Direct refusal propagates to clean CLI exit2 without partial JSON and to scorerun `BLOCKED: unparseable_report` with zero scored/pass/fail cases.

## Explicit limits and residuals

The documented legacy behavior remains unverified. Arbitrary `[{}]` and explicitly unnamed legacy records can still return `[]`; a caller that bypasses the native prerequisites could still credit that as no-change. This repair does not certify those legacy shapes as native output. A verified native pilot must first pass the production strict normalizer and ownership boundary, and may not use legacy fallback to bypass a failed production parse.

The guard proves only report-visible identity consistency. It cannot prove that a producer included every function, labeled functions correctly, or agrees with prospectively frozen source/binary truth. The case schema, scorer, production secondary parser, common normalizer and recorded native fixture are byte-for-byte unchanged from the published base; hashes are retained in `source-review.json`.

The scorerun tests use its existing Ghidriff-shaped report filename locator with explicit rizin parser dispatch. They demonstrate refusal propagation and blocked-score accounting, not end-to-end native artifact interoperability. Root owns the retained authored-native record replays. This reviewer did not read or rescore the original pilot, download or execute a native engine/target, or establish native accuracy or hosted acceptance.

## Reproduction and evidence

`run_external.py` and `run_supplement.py` retain exact interpreter, argv, environment, source fingerprints and outcome receipts. All raw logs and JUnit files are included. `reviewed-full.patch` and `source/` preserve the reviewed code/spec/test material; `checks-61b7cfb4.json` records ancestry, commit ordering, the three changed paths, Ruff and whitespace checks. `summary.json` and `test-counts.json` provide compact results. The external tests can be rerun against an isolated checkout by supplying its exact head and a fresh output label to the corresponding runner; existing labels refuse overwrite.
