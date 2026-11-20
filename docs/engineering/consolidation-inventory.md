# PatchTrace discovery and unique-work handoff — 2026-11-19

## Scope and pinned baseline

This is a fresh repository census and a bounded semantic review, not a claim that
all historical work has been reviewed or that PatchTrace is ready for release.

- Repository: <https://github.com/djshellshoxxx/patchtrace>.
- Current main: `fdc2696c23bdbfe7668348f25e3b336ce33039f7`.
- Engineering baseline: draft PR #322,
  `f2458aae22ea6177be64cfc2fb439a79950f00ff`.
- Inventory worktree: `codex/archaeology-20261119-4c8d`.
- The machine-readable [inventory](consolidation-inventory.json) records every
  branch, comparison identity, PR head and fetched tag.
- The [discovery snapshot](discovery-20261119.json) retains the exact REST
  metadata fields and source URLs. Timestamps are UTC in the JSON records.

## Complete reference discovery

The current snapshot contains **323 branches**, **312 pull requests**, **59
tags** and **59 release records**. There are **56 open PRs**, **172 merged PRs**,
and **84 closed, unmerged PRs**. Every one of the 312 recorded PR head objects is
available locally after fetching `refs/pull/*/head` into read-only tracking refs.
The branch endpoint pages contain 100 / 100 / 100 / 23 / 0 rows; closed PR pages
contain 100 / 100 / 56 / 0 rows; the open PR page contains 56 rows.

The prior census was pinned to the same main SHA. **318 branch comparison rows
were reused only when both the exact branch name and head SHA matched**. Five
new or changed rows received fresh merge-base, divergence, `git cherry` and path
comparisons. Current main and candidate ancestry were independently refreshed
for every row. No remote branch or PR was modified by this worker.

The `/tags` REST collection was refused by the connector. The successful full
Git tag fetch supplies all 59 tag targets instead; this is a recorded tool
limitation, not a claim that tags were absent.

| Current disposition | Branch count | Meaning |
| --- | ---: | --- |
| Baseline | 1 | Main is the comparison baseline. |
| Included in main by ancestry | 128 | The exact historical branch head is already in main. |
| Included in current candidate by ancestry | 2 | The checkpoint and #322 heads are already in the candidate. |
| Patch-equivalent to main | 16 | No unmatched nonmerge patches or unique merge commits in the recorded comparison. |
| Retained for semantic review | 154 | Historical patches or mixed candidates require behavioral comparison. |
| Retained research/documentation | 17 | Scope and current-contract review remain open. |
| Retained experimental | 5 | Automation/skill experiments remain isolated. |

The larger semantic-review count does not imply that new defects were found on
all those branches. Earlier `contained-in-broad-candidate` and `contained-in-pr319`
labels described other unmerged candidates, not the #322 baseline. Those branches
remain explicit review obligations here.

Historical inclusion and patch equivalence establish facts about Git history.
They do not prove that later code still preserves every historical behavior.
Unmatched patches likewise do not establish unique missing functionality.
No branch is approved for wholesale integration by this inventory.

### Changed references since the prior census

| Branch | Earlier head | Current head | Disposition |
| --- | --- | --- | --- |
| `codex/patchtrace-checkpoint-20261119-81e4` | `fdc2696c23bd` | `bdc929ebd3c6` | Included in current candidate. |
| `codex/patchtrace-completion-20261119-81e4` | New | `f2458aae22ea` | Current candidate. |
| `consolidation/patchtrace-reviewed-20261119` | `a56ab13aaf99` | `8d130aefe1be` | Review individual missing repairs. |
| `consolidation/patchtrace-continuation-20261119` | New | `f851d74d134a` | Mixed continuation; extract reviewed slices. |
| `integration/exhaustive-patchtrace-consolidation-20261119` | New | `6096e64d4e7b` | Broad mixed recovery; preserve and inspect. |

## Proven missing repairs and implementation handoff

### Parser-recognized manifest DTD refusal

**Disposition: UNIQUE — INTEGRATE, after focused verification and independent
review.** Source: [PR #315](https://github.com/djshellshoxxx/patchtrace/pull/315),
runtime commit `5f31e8ad`, tests first introduced at `dfa40118`. The current
`src/patchtrace/pe_overview/manifest.py` only screens decoded strings for DTD/entity
tokens before calling `ET.fromstring(text)`. NUL-bearing decoded text can be
reinterpreted by ElementTree as UTF-16, so that screen does not cover all
parser-recognized doctypes.

The retained repair adds a rejecting `TreeBuilder.doctype` callback and the
equivalent callback for the pure-Python Expat fallback. It preserves the existing
warning contract and conservative text screen. The regression file is
`tests/test_pe_manifest_dtd_boundary.py`; the relevant specification is
`docs/specs/pe-version-authenticode.md`.

The root worker owns reproduction, recovery, independent review and cache
invalidation. **Metadata cached before the parser repair must also be invalidated**;
otherwise a current cache hit may reuse facts admitted by the old parser. This
inventory does not implement or qualify that follow-up and does not close PR #315.

### Unsaved profile edits disappear during navigation

**Disposition: UNIQUE — INTEGRATE, after focused verification and independent
review.** Retained source: [PR #319](https://github.com/djshellshoxxx/patchtrace/pull/319)
at `8d130aefe1be6e737cff1d90d2a5b1658d60a3a6`. The same scope is present in its
earlier reviewed core recovery. On #322, `ProfilesPanel` connects
`currentItemChanged` directly to `_show_current`, replacing the active draft.
Creating or duplicating another profile also lacks the retained draft-resolution
step.

The unchanged historical regression file was exported to a temporary test path
and run against the exact #322 source: **8 failed, 1 passed in 1.09 seconds**.
Failures cover selecting another profile, saving before navigation, renaming then
navigating, explicit discard, failed validation/storage, new-profile creation,
and duplication. The unchanged-profile navigation control passes. The asserted
failure is missing draft protection, not an import or environment error.

[Baseline log](evidence/profile-navigation-baseline.log),
[JUnit](evidence/profile-navigation-baseline.xml), and
[receipt](evidence/profile-navigation-baseline.json) retain the original red run.
This is authored offscreen Qt behavior, not native desktop or accessibility
acceptance.

The successor should recover only:

1. `src/patchtrace/ui_profiles.py`: `reload_panel`, `resolve_unsaved_profile`,
   and `change_profile_selection` helpers.
2. The corresponding `ProfilesPanel` wiring, creation/duplication guards and
   save/reload behavior in `src/patchtrace/ui.py`.
3. The `profile.navigation.save|discard|cancel` tooltip entries, the relevant
   profile contract update, and `tests/test_ui_profile_navigation.py`.
4. Existing profile, settings, tooltip and UI integration regressions, plus an
   independent review of rename, failed-save, cancellation and selection lifetime.

Do not copy the entire #319 `ui.py` or tooltip file: they also contain raw
alignment, search and other unrelated contributions. Preserve later source
changes made by the root and other workers. The current inventory commit changes
no runtime code.

## Other recovery candidates still requiring behavioral proof

| Candidate | Source evidence | Remaining work before integration |
| --- | --- | --- |
| Saved-search GUI and CLI actions | #310/#319 contain `search/saved_actions.py` and `search/qt_saved.py`; these files are absent from #322, whose saved stores remain present. | Compare store contracts and actual callers; port coherent UI/CLI behavior with refusal and stale-data controls. |
| Paired physical-offset desktop controls | #309/#319 contain `ui_raw_alignment.py`; #322 already has alignment and view-model backends but lacks that controller. | Verify worker lifecycle, original-byte copy semantics, stale results, cancellation and context changes. |
| Inventory, Strings composition, optional Search | #321 at `f851d74d` differs from #322 in 537 files. | Extract independently reviewed seams. Do not overwrite #322 parser/publication/retention fixes. |
| Broad recovery and saved-plan execution | #320 at `6096e64d` differs from #322 in 1,312 files. | Inspect source provenance, current schemas and outstanding digest/qualification defects. No wholesale merge. |

Source-file absence confirms a missing integration seam; it does not establish
that the entire retained implementation is correct, safe or complete.

## Current CI observation and acceptance boundary

The fresh [CI snapshot](ci-snapshot-20261119.json) for the exact #322 head has
**28 check records: 25 successful, two skipped release gates and one cancelled
Linux rz-diff check**. Linux and Windows QA, the repeated Qt variants, native
variants, Linux packaging and both Linux smoke variants report success. This
supersedes the old observation that these checks were queued; it does not rewrite
the archived local failed and incomplete runs.

Those counts include every returned check record, including repeated native
names. They are not a count of distinct workflows or test cases. A successful job
can still contain a blocked advisory live receipt, so live artifacts require
their own inspection. The cancelled check is `live rz-diff (ubuntu-latest)`, ID
`135615324659`. A retry, if requested by the root, is separate from this snapshot.

The snapshot does not qualify later parser, cache, profile or other changes.
Known source-level blockers also remain independently relevant to the merge gate.
No main merge, release, deployment, branch deletion or force push occurred here.

## Feature and release status

The existing [feature matrix](../consolidation/FEATURE_MATRIX.md) remains the
capability inventory for the baseline. Its source and functional limitations are
still material; its queued-CI observation is historical and replaced by the exact
snapshot above. No broad capability is newly marked complete in this census.

Explicit remaining obligations include successful forced-export ownership,
native Qt advisory remediation, full current-head aggregate qualification,
source-bound native packages/trust and real producer receipts, saved inventory
and acquisition provenance, manual/accessibility acceptance, and separate
L1/L2/L3 accuracy evidence. Retained `facts: unverified` cases remain excluded
from scoring.

## Resume instructions

Read this inventory and the root's latest engineering handoff first. Fetch current
refs and compare them with the exact JSON snapshot; do not assume this baseline
is still the newest head. Preserve original failures and reassess only changed
scope. The next implementation generation should complete profile draft
preservation after the root's manifest/cache slice is integrated, then independently
review the resulting candidate. Historical census status never substitutes for
end-to-end feature evidence.

Useful reproduction commands, with paths adapted to the successor worktree:

```bash
git show 8d130aefe1be6e737cff1d90d2a5b1658d60a3a6:tests/test_ui_profile_navigation.py > /tmp/test_ui_profile_navigation.py
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q /tmp/test_ui_profile_navigation.py
QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_ui_profiles.py tests/test_ui_profile_navigation.py tests/test_tooltips.py
python -m ruff check src tests tools
```

The first command is a discovery reproduction on the baseline; the second
selection applies only after the regression is installed in `tests/`. Final
aggregate and hosted qualification still follow the repository's standing gates.
