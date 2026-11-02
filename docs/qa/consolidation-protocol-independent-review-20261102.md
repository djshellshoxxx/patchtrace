# Independent review of the complete protocol branch merge

**APPROVE** frozen merge `8e7ce2952229f798ac9baec7660361f6b977d8a7`, tree `e2d451516cd0fcd83edc49a6375462bd25a79fc2`.

Parents:

- Integration: `1b23201527fb13b17384e3a8aa94cd08c3869517`.
- Reviewed protocol branch: `bdf214e874f19a8a15382703e5c480e792b3568b`.
- Actual merge-base: `6579ed83211b7ff2039e3152728ac1cddc3e93d6`.

No correctness blocker found in this merge delta. Review used immutable Git objects and an extracted snapshot at `/tmp/patchtrace-protocol-merge-review-8e7ce295`, without relying on the author's changing worktree. No production edits or remote mutations were made.

## Source and history preservation

The only first-parent production delta is the previously reviewed prefix-only fence expression and its comment. `tools/calibration/prereg_gate.py` is byte-identical to the approved `bdf214e` version, SHA-256 `13d050ab8d3b00786f2fcb70e19372dfd32d76bc69c6d2d34c7af1ee6ee747f3`.

Independent AST comparison confirms that `train._prereg_sha`, `train._run`, `train.build_parser`, and `train.run_training` are identical to the reviewed protocol parent. Selection still occurs before `_inputs`; invalid/missing/ambiguous QA records refuse input access, verified protocols cannot claim reduced smoke configuration, and unlocked rehearsal keeps the report/key's unlocked identity. Replay loading and expanded metadata bounds remain the integration parent's implementation, separately reviewed in that slice.

A full tree-entry comparison confirms all 578 integration-only changes and all three protocol-only changes are retained exactly. The five paths modified on both branches resolve as follows: integrated module index, unioned QA/tracker histories, exact reviewed protocol gate, and integrated training reader. Only the two explicit consolidation receipt files are new outside those shared paths.

The protocol module-index addition remains verbatim. Multiset comparisons found zero nonblank lines lost, including multiplicity, from either parent's `docs/qa.md` or `tasks/todo.md`. Historical port and prefix-review receipts are retained. No source-only cherry-pick was substituted for branch preservation.

## Independent validation

```text
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests python3 -m pytest -q \
  tests/test_train_prereg_selection.py \
  tests/test_prereg_tools.py \
  tests/test_prereg_constants.py
138 passed, 3 warnings in 1.53s

python3 -m ruff check src tests tools
All checks passed!
```

The three warnings are explicit `LegacyOutputWarning` messages from constructed compatibility outputs lacking managed credit. They are not failed assertions or evidence of newly credited native output. `git diff --check` against the integration parent passed.

The tests use temporary protocol files and small constructed reports. No real corpus, locked evaluation, owner approval, final-look consumption, native tool, or compared target execution is inferred. Final assembled-candidate hosted and platform gates remain separate.
