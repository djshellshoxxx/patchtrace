# Independent final PW merge audit

**Verdict: no merge-preservation or new QA-evidence blocker found.** This is a read-only audit of frozen commit `939d4a9051ecbd6ebc0cc97e20756c1a881ee070`, tree `11358e92063107e484dc30906f55ddeb8a61dd4f`, performed on 2026-11-18. It does not recertify implementation authored by this reviewer or replace hosted acceptance.

## Preservation and ancestry

The actual parents are `d492c0e630c783c287e4143266fd87f7a949317c` and `75ffee3840894adb52aff7f3df28043cc8e832ba`; their merge base is `f69614fa6b5bb9d25d4233b06a4c4ce179964a52`. Reviewed PW source `0be3b9eb`, published search source `2306de3a`, and the specified actual PR303, PR304, PR305 and PR306 heads are ancestors of the merge. The merge message retains `[no release]`.

Independent Git-tree comparison found 38 PW and 11 search changed `src/`, `tests/` or `tools/` paths. Their sets are disjoint, and all 49 resulting blobs and modes exactly equal their owning parent. No path present in either parent is missing from the merge. Across the entire tree, only `docs/qa.md` and `tasks/todo.md` differ from both parents. These are also the only paths changed by both parents relative to the merge base. Every introduced or replacement block from both parents is preserved contiguously in the resolved documents (seven blocks in total).

## QA evidence

Verified outer byte sizes and SHA-256 hashes for the current PW execution archive, PW independent-review archive and search integration archive. Independently verified every manifest payload hash and size: 62 + 23 + 122 = **207 payload files**, with complete archive-member coverage. The adjacent search manifest equals the archived master manifest. All four readable search review copies agree with their exact archived originals after only trailing whitespace is removed.

The local-link scan covered 25 changed QA Markdown documents (including the two conflict documents), examining 103 local links. It found four missing legacy targets in `docs/qa.md`; each link and absent target already exists at the merge base and both parents. There are **no newly missing local targets**. The pre-existing targets are:

- `docs/qa/corpus-safeguards-20261101.md`
- `docs/qa/prereg-markdown-review-20261101.md`
- `docs/qa/corpus-output-persistence-20261101.md`
- `docs/qa/output-credited-replay-20261101.md`

The scan checked local file targets, not heading fragments. The 82 external links were not fetched. Previously reviewed historical large archives were not rehashed.

## Cross-module assessment and limits

No new cross-module source change or concrete integration blocker was identified: product, test and tool content remains exact to the reviewed owning parent. The search default adapter uses the root `patchtrace.service.ProjectService`, which is distinct from the PW `patchtrace.kbcorrelation.service` module. Their relevant service and contract boundaries are preserved. The inherited PR305 worker AST heuristic remains a direct-call check, not a proof of transitive worker safety.

Root reports a combined 63-file gate of 2,121 passed and two Windows-only skips, with whole-tree Ruff and schema checks passing. Those tests were not rerun for this audit. This report makes no full-suite, production-network, or native-Windows acceptance claim. Earlier incomplete or failed local qualification remains incomplete or failed. Exact-head hosted gates remain required.

## Reproducible evidence

- `merge-preservation.json`: exact tree, parents, base, all 49 paths, ownership/mode comparisons and conflict-block preservation.
- `archive-and-links.json`: frozen-blob archive identities, payload counts, readable-copy comparisons and raw local-link results.
- `residual-provenance.json`: each legacy link checked at base, both parents and merge; retained parent-path union; explicit ancestry checks.

No product edits, test reruns, target downloads, or remote writes were performed. The audited checkout was clean.
