# Bounded premerge PR disposition refresh

REST observation window: 2026-11-18T09:11:36.163Z through 2026-11-18T09:11:53.060Z; observations are not atomic.

Main: `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`. Repository `delete_branch_on_merge=false`. Candidate: `1c49199e9333e955e2bd947fda2824d68b7da65d`.

**Blocker: PR #302 moved. Its new tip is not contained in the candidate and must not be marked superseded.** All other requested heads and all recorded base SHAs are unchanged.

| PR | State | Current head | Base ref / SHA | Head moved | Candidate ancestry / scope |
|---|---|---|---|---|---|
| #302 | open | `121ffb0bcdd6af4f24e5035389d4709dffddf263` | `main` / `9c411ca3d7b47f950be5f0c6f01b3c54184554c6` | yes | NOT contained |
| #301 | open | `faddea300daf4058d38d24ff04a270be6f3d832b` | `main` / `9c411ca3d7b47f950be5f0c6f01b3c54184554c6` | no | contained |
| #297 | open | `95db052a11cce162d2d633cae805f28119f783a1` | `main` / `7401078490eb7a447f5ec7274339cb08b051f395` | no | contained |
| #290 | open | `1d5a022d2840c5c071ccece503664c8c961d63f1` | `main` / `882d1ca0b4190bccddb6ce1f66b46c4db856703b` | no | contained |
| #291 | open | `53f5dd2611b38e3f69f8d72c3ca7cf73e9e896ab` | `main` / `882d1ca0b4190bccddb6ce1f66b46c4db856703b` | no | contained |
| #292 | open | `cf50b4e8725cb1291ac6150667f2e136f023aff3` | `main` / `882d1ca0b4190bccddb6ce1f66b46c4db856703b` | no | contained |
| #293 | open | `aacb984e9d627be051ca8c8c3b88d5ceca0ff505` | `main` / `882d1ca0b4190bccddb6ce1f66b46c4db856703b` | no | contained |
| #294 | open | `e88d748cf9846e04c0c81449976f530519da83a9` | `main` / `882d1ca0b4190bccddb6ce1f66b46c4db856703b` | no | contained |
| #295 | open | `37d9e47ca202b33f737b15f7af724649db8c3e15` | `main` / `882d1ca0b4190bccddb6ce1f66b46c4db856703b` | no | contained |
| #268 | open | `b29351d41060f8e9330fc9673457d835e188f993` | `main` / `652677b0be6da09125c89c017e513b6b2baadbb2` | no | selective port; no ancestry claim |
| #281 | open | `cbabc09e9df8a8190c769164ef0fae44f9c5cb1b` | `main` / `882d1ca0b4190bccddb6ce1f66b46c4db856703b` | no | selective port; no ancestry claim |
| #282 | open | `552c29453c5de93e22c65e47ad4187ded91e993a` | `main` / `882d1ca0b4190bccddb6ce1f66b46c4db856703b` | no | selective port; no ancestry claim |
| #283 | open | `6f767ccef8ebfffd1d2373c5124d8a961dc54b41` | `main` / `882d1ca0b4190bccddb6ce1f66b46c4db856703b` | no | selective port; no ancestry claim |

Nine prior ledger tips were local ancestors of the candidate. Eight of the nine fresh ancestor-designated tips remain contained; #302 is the exception. The four selective-port PRs (#268/#281/#282/#283) retain their original scoped review conditions.

No PR was closed, commented on or merged; no branch was deleted and no git object fetch was needed. Closures remain conditional on qualified #304 integration and postmerge verification on main.

## New #302 accounting

New head `121ffb0bcdd6af4f24e5035389d4709dffddf263` has eleven commits beyond `f7e075480999e2f5a3681ddd429dca0fd9cac986`. Six reproduce original #304 patches with identical stable patch IDs. Four add behavior: ZIP normalization, partial-order/explicit-choice handling, predecessor-frontier provenance, and bounded enumeration/cached chronology. The last commit records separate QA/publication identities.

Use [new302-overlap-map.json](new302-overlap-map.json) for all eleven parents/changed paths, six patch-equivalence checks, and all 22 file-level recommendations. Five files are byte-identical across current #304 and new #302, six are incoming-only changes, and eleven changed on both sides.

Preserve current #304 release-hold policy, .tsp support, native winpairs repair and its evidence. Keep current #304 L1 test file, which contains the .tsp corrections. Union the Windows spec (incoming separator rule plus current native-publication appendix), QA and task histories. Retain the unique lineage behavior after independent review.

The [ZIP control receipt](zip-normalization-review.json) records six authored cases / twelve source-version evaluations on Linux. It reproduces the Windows-separator false rejection on current #304 and acceptance on new #302 while preserving NUL and alias rejection; it is not native Windows qualification.

The complete compact refresh is [receipt.json](receipt.json); exact unchanged connector response bodies and request timestamps are in `connector-responses/`. The earlier `gh api` calls failed locally for missing CLI authentication; they are retained separately and supplied no current remote facts.
