# Card-consensus source identity — fresh reproduction and repair

Source base: published PR #153 head `9ae5731cadebd691a1aedc5b5727c3af3fcd58a0`.
Source repair: `76ca406ab51f93c7cd166e575c0aa6cf1ef80b2b`, tree
`8777716b279606dd65c88484eeb78936954099fc`. Author: `/root/msrc_recover`.

The exact [Qodo review comment 4440348624](https://github.com/djshellshoxxx/patchtrace/pull/153#discussion_r4440348624)
was inspected and independently reproduced on the published head. In a fresh offline real service/SQLite/project
flow, a mutated native factual projection supplied one conflicting card and zero edges. Adding it withheld the
title/CWE and added `CARD_FACT_CONFLICT`, but left the context key and edge-set digest unchanged. Attachment
copied only the edge-producing source; the card-only raw source was absent. This is new evidence, not a recovered
claim from lost workspace results.

The internal lookup now returns the sorted IDs of the same active documents used by card consensus. Context
unions those contributors with its selected edge sources, including source-kind groups whose warnings are shown.
Existing project attachment consumes the expanded source list. Key policy version 2 hashes every source's ID,
raw SHA-256, kind and release ID. `BUNDLE_VERSION` remains 1 and persisted bundle fields are unchanged; the old
key-policy JSON bundle is still readable without rewriting its stored key. Raw cards/edges, source-kind grouping,
acceptance rules and active-revision policy are unchanged. This does not redesign card field pointers or resolve
all advisory ambiguity.

Fresh checks (shared existing venv; explicit worktree `PYTHONPATH=.:src:tests`; offline tests):

- Corrected ten-test regression rerun in a separate unmodified `9ae5731` checkout: **10 failed in 0.99 s**, for
  the intended identity/source omissions and missing contributor API. An earlier draft had an invalid CSAF
  control; it was corrected to a valid known-affected card-only document before this baseline run.
- Repair-focused context/index/native/service selection: **87 passed in 2.59 s**.
- `QT_QPA_PLATFORM=offscreen ... python -m pytest -q tests/test_kbc*`: **1,019 passed in 24.53 s**.
- Changed source/test Ruff and `git diff --check`: passed.
- Actual project attachment/export/reopen regression decodes each copied source envelope and verifies the exact
  original raw JSON and SHA-256. Agreement, conflicts, changed bytes with unchanged facts, insertion order,
  superseded/unrelated sources, secondary source-kind conflicts, and warning-only context are covered.

Combined saved-scope check used a separate clean detached checkout at
`0a920f6f10fc8e03e96f97a182ab1d05bdc28351`, tree `fd82f8bb7dd4f2b862ac4eaeab4f297980f9dd05`:
root integration snapshot `197186a20f48e2a70931a720f4d68950d8a8c8fa` plus the source repair. The only cherry-pick
conflict was adjacent SPEC-31-E paragraphs; both saved-scope and source-identity requirements were retained.
The committed ten source tests, all 44 saved-scope tests, and five new combined controls: **59 passed in 4.02 s**.
The controls exercise actual service/project attachment under saved months, explicit files, mixed and pinned
cached-corpus scopes. Later unselected card-only sources, including a newer same-month revision for files/cache,
cannot change the context or enter copied sources. A newly loaded active card-only snapshot within the saved
month changes the key without changing coverage or edge digest.

Combined control source is available to the integration owner at
`reviews-msrc/test_card_saved_scope_controls_20261102.py`; logs share that directory. These are focused tests,
not a full-suite, performance, native desktop or live-vendor acceptance claim. No network consent, binary
execution, remote mutation or release gate was changed. Independent review and fresh PR CI remain separate.
