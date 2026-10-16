# PatchTrace UE-R3 continuation handoff (2026-10-16)

Status: **code and regression tests committed on an isolated branch; CI not yet verified; not merged**. This is a progress register, not a completed acceptance claim. Follow AGENTS.md, CLAUDE.md, docs/handoff/unified-engine.md and docs/specs/unified-engine/07-ui-and-display.md where present.

## Live repository context at the start of this slice
- Main: `4cf78d64dd542b508fdf89b2bac70ca16630fa29`; integration branch `claude/instance-d-gui`: `53f366e8b50ac60a95bdb3734b815daac82cd63d`, PR #64 draft.
- LBL-31 PR #78 head `5f30a79119b59e337b11a21d81b5e3b12d2bd92a`; Tier R corpus workflow [38883698797](https://github.com/djshellshoxxx/patchtrace/actions/runs/38883698797) succeeded. Current-head QA workflow [38883698492](https://github.com/djshellshoxxx/patchtrace/actions/runs/38883698492): Linux qa success, Windows qa and Linux Qt repeat still in progress at last read; Windows Qt repeat success. **Do not merge PR #78 until all required current-head checks pass.** Then merge into integration with expected-head SHA, as the owner authorized.
- LBL-32 implementation was active on another branch `chatgpt/lbl32-card-controls-20261016` (observed `0bb6290`). This slice deliberately does not touch it. No merge/overwrite of any other worker's branch occurred.

## UE-R3 files, invariant and test register
| Requirement | File | State / evidence |
|---|---|---|
| Write on-demand decompiled C to the sidecar the existing viewer reads | `src/patchtrace/unified/compute.py`: `retain_decompiled_text`; reuses `store.write_part` and `store.add_part` | Implemented, **tests not run yet** |
| Preserve result key and exact older/newer RVA provenance | same | Code path uses `WorkerRefacts.pairs` and verified result manifest, no result-key inputs changed |
| Sanitize untrusted C, cap record and part bytes | `strip_unsafe(keep_layout=True)` and `write_part` | Implemented; hostile oversized live case not verified |
| Allow one-sided decomp text without promoting a verdict | `refacts_stage` early return through retention helper | Implemented, synthetic test committed |
| Avoid inventing C when backend or a requested RVA is absent | helper only persists returned requested text | Implemented, regression committed |
| Detect sidecar tampering and allow standalone code-view loading | `store.verify_result_dir`, `RowCodeSource._read_decomp` | Regression committed, **not executed** |
| Preserve prior readers and contracts | optional `decomp.jsonl.gz` is already an allowed `Part.name` | No new persisted schema; full suite and Windows gates pending |

Tests added test-first to `tests/test_unified_wire_refacts.py`: `test_on_demand_c_is_in_the_published_manifest_and_readable_without_rerunning_ghidra`, `test_no_decompilation_produces_no_claimed_c_part`, `test_decompiled_c_retention_preserves_result_identity_when_refreshing`, `test_single_sided_decompile_retains_only_real_code_without_promoting_a_pair`, `test_changing_the_persisted_c_part_is_detected_before_it_can_be_read`. Test commits precede the implementation commit for the main path. No local checkout could be cloned because the runtime could not resolve github.com; **no RED or GREEN pytest run is claimed**.

## Exact continuation
1. Inspect this branch's PR against integration, check run head SHA; run focused `QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_unified_wire_refacts.py tests/test_unified_pair_text.py tests/test_unified_store.py tests/test_ui_unified_code.py tests/test_ui_unified_pipeline.py` with `PYTHONPATH=src:.`; then `python -m ruff check src tests tools`.
2. Fix any CI failure test-first on this branch, then verify full Linux and Windows QA on its current head; do not merge prematurely. Do not treat synthetic C fixtures as real Ghidra acceptance.
3. In a native Ghidra fixture run, verify that the persisted part exists and the GUI's Code view displays it with a clear origin. Document run/SHA in `docs/qa.md`; this acceptance remains **unverified**.
4. Update `docs/modules.md` and `tasks/todo.md` after current-head tests, retaining append-only concurrent changes; merge this branch only once reviewed and passing. Re-check PR #78 gates and merge it separately when green.
5. Continue UE-R4 G-U5 measurement gaps and UE-R5 integrity attestation from `docs/handoff/unified-engine.md`, or next unowned LBL-33 corpus admission after LBL-32 completes. Never promote the ordinal confidence display without the prescribed real gates.

## Same-session continuation: deep verifier, final branch state

Draft PR [#86](https://github.com/djshellshoxxx/patchtrace/pull/86) targets `claude/instance-d-gui` and is the integration vehicle for this slice. Since the initial handoff above, the code was hardened in `src/patchtrace/unified/store.py`: `_Deep.decomp` now rejects forged rehashed optional C records (bad side/status/code/keys, out-of-row RVA, duplicate record), using the row references from the verified result. This catches malformed optional-part records *before* publication even when their SHA is self-consistent. `_Deep` skips the extra RVA collection entirely when the manifest has no decompiled part, preserving normal memory/performance.

Additional red-first tests in `tests/test_unified_store.py`: parametrized invalid records (six cases), duplicate records and a valid two-sided part with unchanged result ID. Thus eight new regression test functions have been committed (one is six-way parametrized) across two existing test modules. **None is claimed to have passed yet**; CI checks were queued on the latest head and local clone could not resolve GitHub DNS. Head latest known in this handoff: `e378654e6c82cbdba78e0b18a15283bcb3fe243c` (before this documentation commit). Re-read current head before reviewing.

Concurrency update: PR #78's other worker independently fixed both Windows QA failures (quoted COFF string-symbol masking and the 100k-row sort path) while this session was diagnosing them, advancing PR #78 to `1e0b2cd225898f966e979048a1108b4f0e2efa31`. The session opened draft PR #91 for the COFF fix before noticing this concurrent work, **then closed PR #91 as a duplicate without merging or overwriting any other's work**. The parent LBL-31 PR #78 still must pass fresh Linux/Windows Qt, QA, and corpus checks before merging. No direct writes to the integration/main branches and no PR merges were performed this session.

Pending UE-R3 gate: latest draft PR #86 Linux and Windows current-head CI, full test suite, Ruff, frozen smoke, plus separately native Ghidra→saved Code view proof. Avoid adding further commits just to report CI status; instead use a PR comment and record verified results in the normal QA register at the next substantive code/QA commit. Do not count queued/cancelled/stale-head checks as success.
