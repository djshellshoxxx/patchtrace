# Current #302 integration and preserved Windows repair — 2026-11-18

## Ref movement and decision

A fresh REST review found #302 had advanced from `f7e07548` to
`121ffb0bcdd6af4f24e5035389d4709dffddf263`: eleven commits across 22 paths.
Main remained `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`, all thirteen reviewed
PRs were open, and `delete_branch_on_merge` was false. The other twelve PR heads
matched the preceding disposition ledger. This new #302 could not be closed as
superseded by the original #304.

Six new commits have stable patch IDs identical to earlier #304 repairs. Four
add behavior: ZIP reader separator normalization, partial-order and explicit
pair choice, ambiguous-predecessor provenance, and bounded target enumeration.
The last commit retains separate QA/publication records. The exact eleven
commits, parents, 22-path overlap decisions and REST snapshot are retained in
[the evidence manifest](current302-integration-20261118/manifest.json).

Independent controls reproduced remaining #304 errors: equal-date observations
from different build families could receive an asserted order and source-supported
fix boundary; an unavailable alternative or a truncated list could leave a sole
automatic selection; and hash ordering of ambiguous predecessor bytes could change
the change/last-change claim. The incoming corrections preserve uncertainty and
require explicit selection. They are not duplicate documentation changes.

## Integrated history and preserved behavior

Local merge `22aa4e8f58f69b7d8c90c15b263c732c8c6bdeac`, published as
`36acf7b6f9f6fe8f16f1e785b73c42a21d2d95c4`, has actual parents #304
`6cc6b6b77564e12eaec2917877d94525a69c7102` and current #302 `121ffb0b`.
Its exact tree is `681268b95cb519e6dac75bcc5ffaa9437bf6df7c`.

Conflict resolution retains the incoming lineage/resolver/service/ZIP semantics
and both documentation histories. Independent inspection verified that all forty
paths changed only on #304 remain byte-identical, including native publication,
`.tsp` support, release policy and evidence. The L1 test file retains the valid
`.tsp` fixture correction and missing-metadata BLOCKED control. The Windows
specification contains both the separator clarification and early native gate.
Seven incoming resolver/service/ZIP/test blobs matched #302 exactly before the
following narrowly scoped compatibility correction. All nine fresh
ancestor-designated PR tips are contained; selective ports retain their original
limited scope, not whole-branch equivalence.

## Compatibility correction and test-fixture repair

Independent review found the new identity-keyed chronology cache changed the pure
predecessor helper's value contract: a copied but equal target raised `KeyError`,
and an absent target no longer reliably raised the former `ValueError`. Four
cached/uncached regression cases failed first. Local `237d216f` (published
`63ca886b`) resolves the target to its equal timeline member before cache access.
The specification precedes this two-line production correction. Independent
checks confirm copied-target success and absent-target `ValueError`.

A broader caller run then found four outdated test doubles lacking the new
resolution evidence flags: **946 passed, 4 failed**. Actual service resolution
constructs `Resolution` objects containing those flags. Local `3693ca3b` updates
only the two fixture factories with explicit `ambiguous=False, truncated=False`;
every original assertion and the strict production evidence check remain intact.
An independent copy-only fixture comparison reproduced four failures and then
four passes without modifying production source.

Final local source/test commit: `3693ca3b5332f915c350d31544d9757da6026cf5`.
Published code: `34c06d9ee30779c1950b6af2a1074eeb74f745ea`.
Identical tree: `4232775318839cba7ed7e0e115a33500c4f7be39`.

## Verification and limits

| Check | Observed result |
|---|---|
| Incoming ambiguity/budget controls against old #304 | 22 failed, 3 passed; preserved cross-head evidence |
| Four new predecessor value controls before correction | 4 failed with cache KeyError |
| Fourteen focused lineage/service/ZIP/publication modules | 700 passed, 2 actual-Windows skips in 3.72s |
| Thirty-six additional KBC caller/L1 modules after fixture repair | 950 passed in 11.67s |
| Independent integrated lineage scenarios | Eight scenarios agree with incoming semantics; ordinary unambiguous pair IDs/selection remain compatible |
| Independent focused integrated checks | 397 repository tests and 27 external/cross-head compatibility tests passed |
| Independent ZIP controls | Six authored cases across incoming/integrated source, twelve expected outcomes; NUL and alias rejection retained |
| Whole Ruff, KBC schema check, whitespace check | Passed |

The two local module selections are disjoint: together **1,650 passed and 2
actual-Windows skips**. The 700-test source matches the final production code;
the later commit changes only the two previously failing fixture factories.
These results do not replace full hosted QA, Qt, Windows packaging or native
acceptance. Prior exit-137/incomplete runs and the fifteen-error old Windows
publication failure remain preserved. The Windows publication source is unchanged
from its independently reviewed repair, but a queued job is not a native pass.

No target was downloaded or executed and no accuracy oracle was changed by this
integration. The frozen L1 results remain separate; no new L1/L2/L3 score or bound
is inferred from these regression checks.

## Promotion conditions

Update #304 by a guarded fast-forward, run all required gates on the final head,
and recheck source/base/reviews/settings before a REST merge guarded by that exact
head. Its merge message must contain `[no release]`. Only after the verified main
contains the captured replacement work may the corresponding PRs be accounted
for and closed, with another current-head check. Preserve every remote branch.
