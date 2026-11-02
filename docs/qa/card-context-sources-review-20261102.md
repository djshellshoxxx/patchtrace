# Independent review: card-source context identity

No blocking findings in the card-contributor context identity and raw-retention repair.

- Source: `76ca406ab51f93c7cd166e575c0aa6cf1ef80b2b`
- Tree: `8777716b279606dd65c88484eeb78936954099fc`
- Parent: `9ae5731cadebd691a1aedc5b5727c3af3fcd58a0`
- QA-only descendant: `443fc8e9410ca9eb8f50acf8ce730c6beac5b3eb`

## Scope and reasoning

- Internal Lookup.card_doc_ids records exactly the selected active documents whose cards enter the per-CVE/source-kind consensus, with deterministic deduplication. It includes card-only agreeing/conflicting documents and warning dependencies, excluding unrelated CVEs and superseded documents.
- Context creation unions those contributor source digests with its selected edge source before the existing service attachment copies raw objects. Changing relevant card-only bytes changes identity even when edges and rendered consensus facts are unchanged.
- Context-key policy advances to version 2 and hashes doc ID, raw digest, kind, and release ID in deterministic order. The persisted ContextBundle wire shape and BUNDLE_VERSION 1 remain unchanged; older keys are loaded without recomputation.
- The separate #118 integration keeps the saved-scope validation and bounded index before contributor lookup. An independently exercised explicit saved scope excludes a later conflicting card-only document from both identity and copied raw sources.
- This is source dependency and identity repair only; it does not redesign card provenance or the separately noted field-pointer/hypothesis attribution.

## Independent validation

- 87 passed in 3.78 seconds. Includes agreement/conflict identity changes, unchanged-edge/raw-byte mutation, deterministic insertion order, excluded and superseded sources, actual conflicting-source project copying, and old-policy bundle loading.
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q --tb=short tests/test_kbc_card_context_sources.py tests/test_kbc_msrc_review_findings.py tests/test_kbc_index.py tests/test_kbc_context.py tests/test_kbc_service.py`
- Independent actual attachment on isolated source passed: agreeing card-only document is retained alongside the edge document, both compressed raw objects decode byte-for-byte with matching digests, and an unrelated CVE document is excluded.
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python /workspace/scratch/142cb233d750/reviews-resume/card_context_source_control.py`
- Independent combined #118 control passed: later unselected conflicting source leaves complete saved-scope bundle/key unchanged; actual project receives exactly the two selected raw objects.
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python /workspace/scratch/142cb233d750/reviews-resume/card_context_source_control.py scoped (cwd wt-card-scope-validation)`
- Passed; four changed source paths; clean source and combined worktrees.
  Command: `Changed source/test Ruff; git diff --check base..source; source equality against QA-only head`

An initial command named a nonexistent context-export test; pytest ran no tests and that attempt is not counted.

## Limits

- No live vendor retrieval, full suite, native Windows, broad provenance-schema redesign, or other #153 closure claim.
- No repository source edits, target execution, remote mutation, or GitHub approval performed.

The JSON sibling binds changed files, combined-tree identity, and retained control artifacts by SHA-256.
