# LBL-31 Windows QA repair handoff, 2026-10-16

**Status: implementation committed, Windows verification pending; PR #78 remains unmerged.** Branch: `chatgpt/lbl31-windows-qa-fixes-20261016-a`, based on PR #78 head `5f30a79119b59e337b11a21d81b5e3b12d2bd92a`, NOT on main. This continuation is independent of the other ongoing workers. Read `AGENTS.md`, `CLAUDE.md` and `docs/handoff/lbl31-output-persistence-chatgpt-20261015.md` for policy and contract.

## Actual CI failure evidence
- QA workflow run [38883698492](https://github.com/djshellshoxxx/patchtrace/actions/runs/38883698492), Windows QA job `116916633534`, at `5f30a791`: **17,891 passed, 2 failed, 81 skipped, 6 xfailed, one warning in 3188.08 s**; Linux QA passed, Windows Qt 5 passed, Ubuntu Qt 20 was still running at diagnosis. Tier R corpus workflow run [38883698797](https://github.com/djshellshoxxx/patchtrace/actions/runs/38883698797): both shards, merge, and Windows advisory succeeded; its unlocked `train=true` job was skipped by design.
- Mutation correctness failure: `tests/test_mutations_more.py::test_masked_body_rule_rejects_address_only_changes_and_records_them[string-literal-shout]` expected `NoMutationSite` but mutated Windows Clang string label was interpreted as a changed masked body. Investigated real Clang COFF assembly of `return emit("hello", v)` and `"hello!"` compiled with `-target x86_64-pc-windows-msvc -O2 -S`. LLVM emits RIP-relative quoted MSVC-decorated string references `"??_C@_05..."(%rip)` and `"??_C@_06..."(%rip)`, which the pre-existing `_ASM_SYMBOL` (bare symbols only) did not normalize. This risks false semantic mutation labels.
- Sorting performance failure: `tests/test_unified_read_model.py::test_filter_and_sort_budget_at_100000_rows`, observed t_sort 0.8823358s versus existing 0.75s five-times-slack bound. The default key is always precomputed `row.sort_keys` tuple but the old sort allocated 100k keyed pairs plus additional generators/lists.

## Implementation and completion register
| Slice | Source and tests | Status | Evidence still required |
|---|---|---|---|
| COFF quoted symbol normalization | `tools/calibration/mutations/engine.py` and new `test_masked_body_coff_quoted_rip_string_symbols_are_addresses` in `tests/test_mutations_more.py` | Implemented, red regression authored first | Windows Clang 20 test and full QA green |
| Fast default sorting | `src/patchtrace/unified/read_model.py`, two directional stable-order regressions in `tests/test_unified_read_model.py` | Implemented with default-key-only path, existing non-default None-last unchanged | Windows 100k budget and ordering suite green |
| LBL-31 Tier R artifacts | Existing PR #78; no code replaced | Not reimplemented | Full Linux+Windows QA; `train=true` smoke dispatch acceptance still unverified |
| Unified live accuracy gates | G-U1..G-U8 | Still unverified | Actual live gate reports; do not flip unified feature ON |

## Verification and continuation
1. Focused: `PYTHONPATH=src:. python -m pytest -q -p no:cacheprovider tests/test_mutations_more.py tests/test_unified_read_model.py`, `python -m ruff check tools/calibration/mutations/engine.py tests/test_mutations_more.py src/patchtrace/unified/read_model.py tests/test_unified_read_model.py`.
2. Check Linux and Windows QA on THIS branch's HEAD, with particular attention to the mutation `string-literal-shout` and default sort budget. Do not relax semantic-label validation or performance budgets merely to pass CI.
3. Merge this branch's PR into `chatgpt/lbl31-output-persistence-20261015` only after compatible checks. Verify PR #78 HEAD changes and run current-head QA if merge updates it. Only then consider merging PR #78 into integration `claude/instance-d-gui`; never to main directly. Retain `train=true` smoke proof as a separate open acceptance gate until a dispatch result is real.
4. Keep all corpus artifacts labels correct; never execute target images, invent live oracle proof, or remove skipped/blocked gate status.
