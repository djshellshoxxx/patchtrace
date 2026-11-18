# Complementary frozen search repair review

**Disposition: approve the reviewed search boundary and typed-identity behavior at `b9fac06b0d9a487acff65fa51c4a98ce53943ab2`, tree `4508e191f09d815ba15a81458739abd4f0b8295f`.** No product source was edited. This is complementary to the separate stored-advisory/default-CLI and actual long-component review by `consolidation_review`.

## Exact comparison

The same independently authored probe ran against original current #304 `f69614fa6b5bb9d25d4233b06a4c4ce179964a52`, incoming #306 `f6ef1528c15b2281ee7b6f32625d02a5211c926d`, and the frozen repair. All source paths, heads, trees, clean before/after status, commands, environment overrides and raw output hashes are recorded in the three final `*.receipt.json` files. The probe forbids networking and uses production query parsing, validated DTOs and the real `SearchService` over authored temporary project fixtures. Generated fixture PE bytes are parsed for indexing only; no targets are acquired or executed.

`comparison.json` is the result of explicit assertions in `compare_results.py`, not an author-reported test total:

| Controls | Result |
| --- | --- |
| 108 boundary combinations: six anchor kinds × two scopes × ASCII/NFC/decomposed Unicode × below/at/above original bound | Repair exactly preserves original acceptance, rejection reason, parsing text and typed fields except the intended ordinary-anchor kind restriction |
| Same 108 combinations against incoming #306 | 48 previously accepted ordinary-anchor cases are incorrectly refused |
| 36 pdb/string boundary combinations | Complete outputs are identical across all three heads |
| Six anchor kinds with embedded quotes, whitespace, filter-looking text, exclusion-looking text and wildcard characters | One literal phrase; no injected kind, scope, side, exclusion or identity terms |
| Six invalid-input cases | Same refusals as original: zero-width, bidi, private-use, NUL, surrogate and quote-only text |
| Six typed digest/JSON round-trip cases | Canonical sorted kinds equal the manually parsed equivalent explicit closed-kind query; JSON round trip is exact; changed scope changes the digest |
| Five real cursor controls over two changed authored functions | Same typed plan, display-text-only change and explicit equivalent closed-kind query accept page two; changed kind or scope refuses with `PT-SEARCH-STALE` |
| Plain query length 256/257 | 256 accepted and 257 refused on all three heads |

The restored exact normalized payload limits are:

| Anchor kind | Changed scope | Indexed scope |
| --- | ---: | ---: |
| module / feature / component / api | 240 | 254 |
| pdb | 229 | 243 |
| string | 228 | 242 |

These are payload lengths inside the original 256-character total parsing budget, including its original scope/single-kind/quote overhead. NFC normalization remains authoritative: decomposed repeated `e` plus combining acute reaches the same limits as composed `é`, including 508 raw payload characters at the indexed ordinary-anchor limit. Limits were not expanded.

## Identity and compatibility assessment

The repair constructs the restricted `QueryPlan` through full validation and canonical sorted kinds. Its display `text` remains the original bounded parsing text. `digest()` includes typed scope/kind/terms and excludes display text, so a different rendering of the same typed request remains a valid cursor continuation. The actual service confirms that a cursor for the repaired plan can be continued using the equivalent manually parsed closed-kind query and returns the other function. Changing kinds or scope is refused. Original unrestricted ordinary-anchor plans intentionally have a different digest from the restricted plan; old unrestricted cursors are not treated as equivalent. Incoming #306 and repaired short-query cursor outputs are identical.

The probe uses independent expected closed-kind tuples and original overhead constants. It does not depend on the repaired implementation's `kinds_for` helper to generate expected bounds or restrictions. Scripted comparison checks full plan bodies against original behavior with only the intended kind union changed.

## Probe correction retained

The first three runs stopped before producing result JSON because Pydantic rejects an unpaired surrogate at `Anchor` construction, earlier than `plan_for`. This is a probe expectation error, not a product failure. Their exact source, logs and receipts are preserved under `attempt-1-surrogate-admission/`. The corrected probe records this typed admission refusal explicitly, retains the same invalid value and remaining controls, and completes on all three sources. No failed artifact was overwritten.

## Reproduction and limits

Run the retained `run_probe.py <exact checkout path> <fresh label>` with `/workspace/scratch/3a6632a6e5ff/venv/bin/python`; receipts record exact command lines and import paths. Use a fresh output folder or copied scripts to avoid replacing sealed evidence. Then compare the saved JSON with the retained assertion script. Each final run completed within the recorded 60-second timeout. No broad suite or full GUI/native qualification was repeated here. The actual stored-advisory/default-CLI checks are independently attributed to the other reviewer and are not counted as executions in this artifact.
