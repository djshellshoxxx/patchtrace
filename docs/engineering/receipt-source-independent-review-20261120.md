# Independent review: recovered receipt source identity

Reviewed on 2026-11-20 by the fresh `generation30_receipt_review` worker, which did not author or integrate the repair.

## Decision

**Accepted within the stated SHA-1, file-backed Git metadata scope. No blocking finding identified.** This is a bounded source/behavior review, not full-repository, Windows, release, or analysis-accuracy qualification.

Reviewed integration commit: `648e508961b4e38cc3a2a005808f6bf819ce0823`.
Original donor: `0f63e0dcb6b53ef4b57550b183b42f80f376eaa8`.

The integrated production blob is `6b826bd41bec664506b10217b867a1bc7cb8bb02`, and the maintained donor test blob is `3766937fa8afa8442b065003c3a5a63874734eb3`. Both match the retained donor. The diff from generation 29 contains only the receipt helper, its new tests, and the source-identity contract amendment. The coordinator retained the current plan's intervening content when resolving the documentation conflict.

## Source review

- The existing `git_head` entry point is extended; no competing receipt store or parallel identity implementation is introduced.
- The selected checkout's private `HEAD` is read separately from shared branch and packed refs. The three private namespaces, `refs/bisect`, `refs/worktree`, and `refs/rewritten`, stay private.
- Relative gitfile and `commondir` pointers resolve against the corresponding metadata location. Loose refs take precedence over packed refs.
- Metadata reads use held descriptors, regular-file admission and read bounds: 64 KiB for ordinary metadata and 8 MiB for packed refs. Invalid or ambiguous content yields `None`; it cannot become arbitrary commit text.
- The helper does not run Git, load configuration, execute hooks, inspect target binaries, or change network behavior.
- Existing callers pass the repository root and accept the same `str | None` result. Receipt schema and storage remain unchanged. New receipts can distinguish linked-worktree source commits; historical receipts are not rewritten.

The layout decisions agree with the official [Git repository layout](https://git-scm.com/docs/gitrepository-layout) and [Git worktree reference rules](https://git-scm.com/docs/git-worktree#_refs), inspected during this review.

## Independent verification

The reviewer ran six additional controls against the integrated source:

1. A real Git-created main checkout and linked branch have distinct commits; the helper returns each correctly before and after `git pack-refs --all --prune`. A detached linked worktree retains its own commit. A process-call trap confirms the helper itself executes no subprocess.
2. A real Git-created checkout with a separate metadata directory resolves correctly.
3. Three parameterized private-ref controls place contradictory values in private/common namespaces and verify private selection for all three exceptions.
4. Invalid UTF-8 metadata returns unknown.

Result: **6 passed in 0.18 seconds; no failures or skips.** These controls use only empty authored Git commits and temporary metadata, not analyzed binaries. JUnit receipt: `receipt-peer-layout.xml`; executable peer controls: `test_receipt_peer_layout.py`.

During the final direct-checkout check, the coordinator advanced integration to `9fdb518f2b322f784fe389b7856a299023f1d901`. An assertion pinned to the earlier `648e5089` failed because the helper returned the new HEAD; this was a stale test expectation, not a helper defect. A subsequent observation bracketed the helper call with `git rev-parse HEAD`, required an unchanged head during the observation, and passed. The production helper blob remained donor-identical. Both observations are retained in `receipt-peer-direct-identity.json`. Scoped Ruff passed for the helper and maintained donor test. The coordinator's donor red/green and wider regression runs are separate evidence and are not counted as this reviewer's executions.

## Limits

The helper observes metadata; it does not attest clean source content, verify commit objects or prove authenticity. Exact tree, working-state and input hashes remain separate requirements. The contract deliberately returns only SHA-1 identities; alternate ref backends, chained symbolic refs and bare-repository discovery are not claimed. Native Windows behavior and the combined candidate's required checks remain separate gates. No release or main merge is authorized by this review alone.
