# B1/B2 candidate component and chronology boundary — 2026-11-05

Base: published PR #218 `afc8a2967ba3dec6b1ac3351d20dd08c193ba9bc`.
Branch: `work/candidate-correlation-20261105`.
Worktree: `/tmp/pt-independent-correlation-20261105`.

## Reproduction and repair

The direct index-pair proposal seam admitted two basenames as grade A even though its resolver normally filters one filename first. It also treated deterministic KB, SHA and BASE-row ordering as evidence of chronology when release date and numeric build/UBR were equal. That allowed two content variants of the same update to appear as an ordered grade A pair.

Initial authored controls produced **5 failed / 1 passed** before production edits: component mismatch, three chronology tie-breakers and swapped-hash orientation failed; numeric build `.9` before `.10` passed. The existing SPEC-31-C hard filters and deterministic-order acceptance establish the intended behavior; the specification was clarified before changing the proposal seam.

The repair adds the existing NAME_MISMATCH hard block for distinct normalized basenames. Orientation compares only the existing release-date/numeric-UBR portion of the timeline key. Equal values carry ORDER_UNVERIFIED, incompatible lineage and grade X; deterministic display sorting is unchanged. Blocked proposals retain their input references and cannot claim a source-supported fix boundary.

A full resolver control retains two target variants with `changed_in_kb=unknown`, preserves equality under reversed input rows, and places the blocked same-build variant after the valid earlier-build proposal. Existing architecture, distinct-hash, cross-product, chronology, availability, fixed-boundary and manual-pair controls remain intact. No new reason codes, serialized fields, schemas, modules or dependencies were introduced. Only `kbcorrelation/resolver.py` changed in production.

## Completed validation

`PYTHONPATH=$PWD/src python -c 'import patchtrace;print(patchtrace.__file__)'` resolved this worktree's source.

`env -u PYTEST_ADDOPTS PYTHONPATH=$PWD/src QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_candidate_correlation_20261105.py tests/test_kbc_resolver.py tests/test_kbc_lineage.py tests/test_kbc_pairs_index.py tests/test_kbc_pairs.py`

**92 passed in 11.04 s.** Initial log: `/tmp/pt-independent-correlation-red.log`; final log: `/tmp/pt-independent-correlation-green.log`.

`python -m ruff check src tests tools` and `git diff --check` passed.

## Source and acceptance limits

The observations use authored fixtures and the existing `parse_rows` → `index_rows` domain seam. Existing Winbindex field research remains at [the historical acquisition note](../research/phase3/acquisition.md), pinned there to upstream `aacec0c2e1c622127dc72123f60c9c986fc94a2f`; that note records GPL-3.0 for the upstream code/data repository. This change copies no upstream code/data and performs no new live verification of that historical research.

This bounds existing proposal eligibility. It does not enumerate alternative predecessors for contemporaneous variants, implement SPEC-31-C's update DAG/supersedence model, establish product verification or calculate vulnerability probabilities. Unknown coverage and the existing metadata-only grade semantics remain. No network calls, binary downloads, target execution, broad qualification or Windows/native tests were run. Existing PR #205 qualification and native workers were untouched. Independent review and current-head integration/full/Windows gates remain separate.
