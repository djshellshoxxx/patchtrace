# Branch inventory after foundation merge

**Pinned main:** `fdc2696c23bdbfe7668348f25e3b336ce33039f7`. Remote census observed `2026-11-19 08:39:01 UTC`. All **318 branches** were fetched through pages **100 / 100 / 100 / 18 / 0**; this includes main and **317 topic branches**. The snapshot contains **52 open PRs**.

Main parents are `9c411ca3d7b47f950be5f0c6f01b3c54184554c6` and `88b0b52281dd314aa72f93819145a73135618bc4`. Its tree `af464108043aaa42b527a473985350a4daadc0d2` is exactly the tested PR #317 tree. The original pre-merge report and machine evidence remain frozen and hash-verified unchanged.

## Updated classification

| Topic classification | Before foundation | After foundation |
|---|---:|---:|
| Already integrated | 129 | 144 |
| Exact head ancestry | 113 | 128 |
| Patch-equivalent only | 16 | 16 |
| Dependency blocked in unmerged #316 | 26 across #317/#316 | 11 |
| Requires review / retained residue | 161 | 162 |
| Total topic branches | 316 | 317 |

All topic heads were checked for ancestry and patch equivalence against pinned main, #317 and #316 using the original analysis logic with separate output paths. All topic merge simulations completed: **164 conflicting / 153 nonconflicting**, with **0 execution errors**. The old main simulations were 142 / 174; a new main changes merge compatibility even for untouched historical heads. These are merge-tree observations, not runtime acceptance.

## Heads newly classified as integrated

| Branch | Head | Previous classification |
|---|---|
| `claude/patchtrace-kbf04-fp-tests-20261118` | `16ab88b0626ef05700c4199e926103932312e5c7` | DEPENDENCY BLOCKED |
| `claude/patchtrace-search-anchors-circularity-20261118` | `f6ef1528c15b2281ee7b6f32625d02a5211c926d` | DEPENDENCY BLOCKED |
| `claude/patchtraces-consolidation-trngn0` | `faddea300daf4058d38d24ff04a270be6f3d832b` | DEPENDENCY BLOCKED |
| `claude/sleepy-fermi-cli-parity-1` | `cf50b4e8725cb1291ac6150667f2e136f023aff3` | DEPENDENCY BLOCKED |
| `claude/sleepy-fermi-kbc-1` | `53f5dd2611b38e3f69f8d72c3ca7cf73e9e896ab` | DEPENDENCY BLOCKED |
| `claude/sleepy-fermi-na-rzdiff-ownership` | `aacb984e9d627be051ca8c8c3b88d5ceca0ff505` | DEPENDENCY BLOCKED |
| `claude/sleepy-fermi-rq-l1-runner` | `e88d748cf9846e04c0c81449976f530519da83a9` | DEPENDENCY BLOCKED |
| `claude/sleepy-fermi-security-1` | `1d5a022d2840c5c071ccece503664c8c961d63f1` | DEPENDENCY BLOCKED |
| `claude/sleepy-fermi-test-reliability` | `37d9e47ca202b33f737b15f7af724649db8c3e15` | DEPENDENCY BLOCKED |
| `codex/consolidation-cve-reviewed-20261118` | `d8c02caea407f6d323eecd636735849c1eb31a2d` | DEPENDENCY BLOCKED |
| `codex/consolidation-reviewed-20261118` | `121ffb0bcdd6af4f24e5035389d4709dffddf263` | DEPENDENCY BLOCKED |
| `codex/corpus-integrity-20261116` | `6a5b6f2609604fe34a8da9cf347c713b21578834` | DEPENDENCY BLOCKED |
| `codex/master-foundation-scope-20261118-4a7` | `88b0b52281dd314aa72f93819145a73135618bc4` | DEPENDENCY BLOCKED |
| `codex/post-consolidation-20261116` | `2d330075fbe00209fbe096ee29b60dcfd0e347b4` | DEPENDENCY BLOCKED |
| `codex/release-integration-20261116` | `95db052a11cce162d2d633cae805f28119f783a1` | DEPENDENCY BLOCKED |

## Newly observed remote branch

| Branch | Head | PR | Classification |
|---|---|---:|---|
| `codex/patchtrace-stabilization-20261119` | `2e301a74649e59e27b19a83bc283d646109ccd09` | #318 | REQUIRES REVIEW |

## Foundation and contained PR statuses

Each row was fetched directly after the merge and separately verified by local ancestry: its exact head is contained in the new main. GitHub reported all thirteen as closed and merged. Twelve are the contained source PRs; #317 is the integrating PR. Reported merge-commit fields are preserved as returned; they need not all name the final main merge commit.

| PR | State | Exact source head | Reported merge commit |
|---:|---|---|---|
| [#317](https://github.com/djshellshoxxx/patchtrace/pull/317) | closed; merged | `88b0b52281dd314aa72f93819145a73135618bc4` | `fdc2696c23bdbfe7668348f25e3b336ce33039f7` |
| [#305](https://github.com/djshellshoxxx/patchtrace/pull/305) | closed; merged | `16ab88b0626ef05700c4199e926103932312e5c7` | `a9d1fcfe3a8761c27389bb4d23933a828dd92406` |
| [#306](https://github.com/djshellshoxxx/patchtrace/pull/306) | closed; merged | `f6ef1528c15b2281ee7b6f32625d02a5211c926d` | `9f47bf54a71bc735a1da4a65ca7cfc2bb3f76253` |
| [#301](https://github.com/djshellshoxxx/patchtrace/pull/301) | closed; merged | `faddea300daf4058d38d24ff04a270be6f3d832b` | `faddea300daf4058d38d24ff04a270be6f3d832b` |
| [#292](https://github.com/djshellshoxxx/patchtrace/pull/292) | closed; merged | `cf50b4e8725cb1291ac6150667f2e136f023aff3` | `f403f81b58a0cdc2d3869810294681527f8268a2` |
| [#291](https://github.com/djshellshoxxx/patchtrace/pull/291) | closed; merged | `53f5dd2611b38e3f69f8d72c3ca7cf73e9e896ab` | `f403f81b58a0cdc2d3869810294681527f8268a2` |
| [#293](https://github.com/djshellshoxxx/patchtrace/pull/293) | closed; merged | `aacb984e9d627be051ca8c8c3b88d5ceca0ff505` | `f403f81b58a0cdc2d3869810294681527f8268a2` |
| [#294](https://github.com/djshellshoxxx/patchtrace/pull/294) | closed; merged | `e88d748cf9846e04c0c81449976f530519da83a9` | `f403f81b58a0cdc2d3869810294681527f8268a2` |
| [#290](https://github.com/djshellshoxxx/patchtrace/pull/290) | closed; merged | `1d5a022d2840c5c071ccece503664c8c961d63f1` | `f403f81b58a0cdc2d3869810294681527f8268a2` |
| [#295](https://github.com/djshellshoxxx/patchtrace/pull/295) | closed; merged | `37d9e47ca202b33f737b15f7af724649db8c3e15` | `f403f81b58a0cdc2d3869810294681527f8268a2` |
| [#304](https://github.com/djshellshoxxx/patchtrace/pull/304) | closed; merged | `d8c02caea407f6d323eecd636735849c1eb31a2d` | `d8c02caea407f6d323eecd636735849c1eb31a2d` |
| [#302](https://github.com/djshellshoxxx/patchtrace/pull/302) | closed; merged | `121ffb0bcdd6af4f24e5035389d4709dffddf263` | `36acf7b6f9f6fe8f16f1e785b73c42a21d2d95c4` |
| [#297](https://github.com/djshellshoxxx/patchtrace/pull/297) | closed; merged | `95db052a11cce162d2d633cae805f28119f783a1` | `fd76a20af33d0d492c82c78f59b4781d8b08e465` |

## Complete evidence

- `post-foundation-remote.json`: complete supplied REST census and current open PR snapshot.
- `post-foundation-ancestry.json`: all 318 exact heads, merge bases and ahead/behind counts.
- `post-foundation-residue.json`: all 318 classifications and complete ancestry/patch comparison records.
- `post-foundation-merge-simulations.json`: all 318 merge outcomes and exact conflict paths.
- `post-foundation-contained-pr-states.json`: fresh direct status records for the integrating and twelve contained PRs.
- `post-foundation-inventory-summary.json`: counts, changed classifications/conflicts, source pins and limits.
- `post-foundation-frozen-original-hashes.json`: unchanged SHA-256 values for the original report and machine evidence.
- `refresh_post_foundation_inventory.py` plus its adapted analysis/simulation scripts: reproducible refresh with separate destinations.

No remote mutation or branch deletion occurred during this refresh. A fully contained head or clean merge does not by itself authorize deletion, close a distinct unresolved issue, or substitute for current-candidate CI. The mixed #316/#318 work and remaining historical residue stay preserved.
