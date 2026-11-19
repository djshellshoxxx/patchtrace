# Independent review of frozen search repair

**Verdict: approved for integration; no blocking source or test finding in the reviewed repair.**

Reviewed commit: `b9fac06b0d9a487acff65fa51c4a98ce53943ab2`
Reviewed tree: `4508e191f09d815ba15a81458739abd4f0b8295f`
Detached checkout: `/workspace/scratch/e83fbf4505c3/review-search-b9fac06b`

## Scope and source findings

Reviewed the full additive diff from current #304 `f69614fa6b5bb9d25d4233b06a4c4ce179964a52`, and the final repair relative to merge `eb74af24`. The exact published PR #305 and #306 heads are ancestors of the candidate, together with #304; none was replaced by a merely similar patch. All three ancestry checks passed.

The guard now preserves original bounded query parsing. Ordinary anchor text remains scope plus quoted phrase; existing string/PDB single-kind text is unchanged. The adapter subsequently reconstructs a validated `QueryPlan` with sorted closed binary kinds. It neither raises the global query limit nor places oversized query text into an unchecked model copy. `SearchKind` validates the allowed values, and the restriction survives the existing changed-to-indexed transition. The `QueryPlan` code change is documentation only: its existing digest already includes typed kinds and excludes display text.

The default CLI source now receives the already-open `ProjectService` retained by the search facade. The injected source continues receiving `SearchService`. There is no new project open, fallback source, network operation, or revised CLI result contract in this repair. The specification amendment distinguishes the historical design from the implemented narrow behavior.

PR #305's inherited AST test remains a direct-call heuristic, as documented in the earlier review. This repair does not claim to extend its call-graph coverage. Its EOF whitespace issue is fixed.

## Independent controls

The original independent `probe_search.py` was copied byte-for-byte and rerun against the frozen source, with the imported module path asserted. Results:

| Previous finding/control | Frozen result |
|---|---|
| Actual parsed advisory-only module | `unknown`, zero hits |
| Advisory-only module/feature/component/API values | All zero hits |
| Token present only in a default-group analyst note | `unknown`, zero hits |
| Actual changed and unchanged function names | Correct statuses retained |
| Actual 160-character CSAF-derived component in changed code | `changed`, one hit |
| Largest ordinary changed-scope payload | 240 characters, restored |
| Real default CLI with stored synthetic CSAF | Structured partial result; no `AttributeError`; no false module hit |

Six additional external tests independently cover:

- A real 240-character component in changed code and in unchanged code: respectively `changed` and `indexed-only`, one hit each; serialized plans revalidate at the original 256-character bound.
- Changed-scope value 241 is rejected before any search executes.
- Indexed-scope value 254 remains accepted and 255 remains rejected, preserving the original separate scope boundary.
- Two real default CLI invocations return identical results, preserve the project model and stored advisory facts, and release the project lock for reopening.

The actual CLI's exit 3 in the constructed incomplete-index case is the established partial/unknown result, not a runtime failure: the JSON contains results, has no error member, and stderr is empty.

## Verification

Independent invocation: **85 passed, zero failures or skips, in 1.78 seconds**. This comprises the four focused repository modules (79 cases) and the six external controls. `acceptance-context.json` retains the exact argv, environment and source SHA; `acceptance.log` and `acceptance.xml` retain the raw result. The import-path guard prevents a pytest configuration from silently selecting another checkout.

Changed source/test Ruff passed. Full `git diff --check f69614fa..b9fac06b` passed. The detached checkout remained clean. The unchanged observational probe and pytest invocation are separate overlapping evidence, not added together as a larger test total.

No product files or remote state were modified. No target binary was downloaded or executed. All fixtures are synthetic and offline. This review approves the source repair; it does not replace exact-head hosted full QA, native Windows, Qt or packaging acceptance.
