# Independent native MSRC adapter review

Reviewed initial commit `1cc7261a5d2fe9fc9763bacf6198436ab740204c` and follow-up `d394780b23c89bb9e9b59e5c159b8d8b78bd4495` in `wt-msrc`. Final tree: `d939391b0f59a833b1c105c67b7738522528b822`. Reviewer made no repository edits. **Both findings are resolved; no remaining concrete blocker was identified in this bounded adapter scope.**

## Findings and disposition

1. **Mixed native MSRC / CSAF dispatch ambiguity (bounded P2 contract gap).** `sources/importer.py::_import_plain` detects CSAF before the mixed-root check in `sources/cvrf.py::parse_json_document`. A valid CSAF document updated with all root fields from the native factual fixture passes the real intelligence validator and public `import_bytes`, producing dialect `csaf/2.0`, two edges, and zero diagnostics. The new native root shape guard is bypassed. This demonstrates ambiguous source interpretation, not a demonstrated fabricated KB edge. Requested a pre-dispatch refusal and a regression using the real advisory port. Reproducer and red result: `msrc-independent-mixed-control.py`, `msrc-independent-mixed-red.txt`.
2. **Standalone test import failure.** `test_fetch_boundary_retains_existing_authenticity_and_month_checks` imports `cvrf_fetch` after `no_sockets` replaces `socket.socket` with a function. A fresh process then imports `ssl` and fails declaring `SSLSocket(socket)`. The larger author's selection preimports transport during collection and hides the problem. Independent subset: 219 passed, one failed; standalone single test also fails. Requested collection-time import; red log: `msrc-independent-order-red.txt`.

## Source and contract observations

The adapter directly consumes original-case native fields and preserves source IDs and pointers into exact imported bytes. Synthetic CVRF adapters remain separate. Type 2 is the only native remediation type that can assert a vendor fix; whole-line KB parsing, product membership and known applicability are required. Other types/prose can at most produce mention-only rows. Unknown/malformed membership withholds native fix edges. No title, notes, URL, product ID, group or CWE ambiguity is promoted into a remediation claim.

Only product status 3 is mapped; other numeric statuses remain unknown. Status 2 for document finality and status 3 for affected products are independently confirmed against the paired captured XML. Native unzoned dates do not become UTC, retrieval time or hash-based ordering. Unknown/tied native revision groups retain snapshots with `REVISION_ORDER_UNKNOWN`. This is deliberately bounded compatibility, not full GT06/history coverage or function-level CVE proof.

Local imports remain `unverified-local-file`; no authenticity promotion, consent or host-policy change was introduced. Original raw snapshots survive store reload. Existing strict JSON and document/node/depth/string/edge limits apply before/through native parsing; no limit was raised. The new remediations reject an oversized description instead of truncating it into a KB.

## Independent evidence

`msrc-independent-review-controls.py` and its `.txt` output record:

- All 394 scalar fields in the factual fixture exactly match the original capture after applying the declared array index maps. The fixture hash is independent of the original capture hash.
- All 2,684 Type 3 CVE/product memberships match `Known Affected` memberships in the paired XML; document status 2 matches `Final`.
- Original 2024-Aug bytes: SHA-256 `adc6f7efbe64e7fe8c23a7a9d69efb1969ed33501c802b3a456812957375d2da`, 2,652,455 bytes; 1,951 edges, 286 problems.
- Original 2026-Oct bytes: SHA-256 `6cc40e5d3f2036d14b0413ad6604ca20a6a3ca9e97079c51ea8cfbc3f0f22c68`, 29,658,577 bytes; 29,694 edges, 3,359 problems.
- Every emitted edge/status/problem pointer resolves against each exact original JSON. Every remediation edge's CVE, KB, Type 2 and product membership independently match that source row.
- Five independent limits (bytes, nodes, depth, overlong string, edge budget) refuse explicitly. Eight unknown numeric statuses, including a large integer, remain unknown and produce no fix edges.

Tests ran with `QT_QPA_PLATFORM=offscreen`, explicit `PYTHONPATH=src`, and `/workspace/scratch/142cb233d750/venv-cancel/bin/python`. No full/performance suite or remote mutations were performed. Native Windows qualification is not claimed by this Linux review.

## Final independent verification

At exact final commit `d394780b23c89bb9e9b59e5c159b8d8b78bd4495`:

- Shared `guard_json_dialect` now runs immediately after strict JSON loading and before the public CSAF dispatch, as well as direct CVRF parsing. The real CSAF baseline remains accepted; the contradictory native/CSAF source is refused with `PT-KBC-SOURCE`. Original independent mixed control is green.
- Fetch imports occur at collection time, before the no-sockets fixture. Native suite alone passes: **60 passed in 0.69s**.
- Independent focused selection (`test_kbc_msrc_cvrf.py`, `test_kbc_cvrf.py`, `test_kbc_index.py`, `test_kbc_store.py`, `test_kbc_csaf_bridge.py`): **242 passed in 3.22s**.
- Scoped Ruff, `git diff --check`, and clean worktree check passed.
- Full capture/factual projection/pointer/limit/unknown-enum controls reran successfully on the final source. Output: `msrc-independent-review-controls-final.txt`.

Final source SHA-256:

| File | SHA-256 |
| --- | --- |
| `sources/cvrf_msrc.py` | `acf58b76e583d84f0408c2e5eb9d57d63ddd0065610fb938a48ec144bc9db1f8` |
| `sources/cvrf.py` | `20d5d41b69902df8d9b776035c8cc6f9b6b07af79af4de34cc11eb2d683c062f` |
| `sources/importer.py` | `94a24ebc36f82d36e2ab885a98cfc81a2a9f276b7caed7acd5489eeaeca99b8a` |
| `index.py` | `ae425d30e3a2979c7e320e68b77da5d2fc265f71d2503956077aacf085fc163b` |

The paths above are relative to `src/patchtrace/kbcorrelation/`. Full CI, native Windows and broad GT06 acceptance remain outside this independent bounded review.

## Coordinator evidence-script verification

The coordinator separately ran 366 adapter/index/store/CSAF/contracts tests (4.01s). Recorded review controls now use explicit RuntimeError checks so `python -O` cannot remove their evidence gates; original assertion-based scripts remain in commit37bea53 history. Both full-capture fidelity controls and mixed-dialect rejection passed under `-O`. The mixed control needs `PYTHONPATH=src:tests`; the first coordinator attempt with only `src` failed importing `kbc_k1_support`, then the corrected command passed. No product source changed during these evidence-only checks.
