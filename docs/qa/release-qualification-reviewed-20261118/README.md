# Reviewed publication qualification checkpoint — 2026-11-18

## Result and source

The shared release guard has no remaining blocking finding in the bounded independent source review. Publication remains held. Canonical main was last observed at `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`; no merge, closure, tag, release or deployment was performed.

Root integrated author commits `0bb63363`, `8d090f97`, `05176698` and `d27464d3` onto actual published PR #307 `58fc130631f602b6e907bb054d30c21d810551d4`. The pre-documentation combined source is `ef0398577c97b926259b533c5776e88146244b24`. Guard implementation/tests and backend publisher match independently reviewed `05176698d0265e4e1e577e06fa38bb52d7bbcf43` byte for byte. The desktop QA workflow differs only in the published #307 immutable-publication prerequisite label and its two additional owned-publication tests; its publisher guard is unchanged. Local ports preserve original attribution and source references. The only integration conflict was in the module index; both owned-publication and release-qualification sections were retained.

## Behavior and repaired review findings

Both desktop and backend-bundle publishers require the shared read-only guard immediately before mutation. It checks canonical source bytes and actual commit metadata, exact repository/SHA/workflow/latest-attempt ownership, all required job and critical-step outcomes, bounded owned native BinDiff receipts, and peeled tag/release/asset identity. Literal `[no release]`, missing or stale evidence, blocked native subchecks, failed scans and unreadable API responses refuse qualification. Publishers do not replace existing release assets. Cadence and trigger policies remain separately documented.

Independent review found three defects in the original candidate: Git replacement objects/index flags could hide modified bytes, JSON exponent overflow admitted infinities, and duplicate artifact IDs could credit the same native evidence twice. The original 7 failing and 4 passing controls remain retained. All 11 now pass unchanged; 8 additional independent source-byte controls also pass. See [independent review](independent-review.md). The repaired implementation hashes canonical tracked bytes and modes without index/filter trust, rejects every nonfinite parsed number and requires distinct positive native artifact IDs.

## Executed verification

The root's completed combined-source affected run reports **458 passed, 3 xfailed in 1.92 s**. The command, absolute source import path, source hashes, log and JUnit are retained. Required Ruff over `src tests tools` and whitespace checks pass. Three expected failures remain the existing CODEX-1 action pinning, CODEX-5 pip hashes and CODEX-6 corpus cache requirements; they are not accepted gates.

Independent re-review ran 458 affected tests plus the unchanged 11 original and 8 supplemental controls. Its real CLI invocation refused the committed `[no release]` hold before constructing the API. These are local source/file/contract checks and authored hosted-evidence fixtures, not actual native or package acceptance.

An earlier root command mistakenly ran before the module-index conflict was resolved and before the reviewed repair was applied. That **450 passed / 3 xfailed** run is preserved as `initial-unresolved-*` and explicitly excluded from final candidate acceptance. Its HEAD was #307 with the first patch staged. The successful 458-test run above followed completed conflict resolution and all four ports. No failed or incomplete receipt was overwritten to improve the record.

All original author (34 members), author repair (14 members) and independent (22 members) archives were verified against every manifest member and archive digest. This checkpoint additionally retains the independent archive and both root runs. Historical receipts remain attributed to their original sources.

## Remaining gates

The dependency/security lane is separate work. Its missing evidence and untriaged Ruff security findings remain blockers. Windows BinDiff's real no-network subcheck is still blocked; a green advisory test job cannot qualify it. Full exact-head Linux/Windows QA, repeated Qt, native, fuzzing, package and scan receipts are not supplied by this change. No CVE accuracy, live-source authenticity or beta-readiness claim follows. The guard is a bounded point-in-time check and does not lock future filesystem or remote ref mutations.
