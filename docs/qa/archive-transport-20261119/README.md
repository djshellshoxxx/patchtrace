# Lossless evidence transport — 2026-11-19

The connector rejected the 13,132,985-byte checkpoint archive because its base64
request exceeds the16MiB transport limit. Canonical Git read-only fetch succeeded;
the normal push dry run failed because this checkout has no Git push credentials.
Neither attempt moved a remote ref. This is a transport limitation, not an
approval rejection or a qualification result.

The original local branch `codex/verified-continuation-20261118` remains intact at
`b2b170e343ab4da680b3629b3ab2e89ce6f42774`, retaining all37 local commits since
`361dd495a7e050121f2b3cae4e7678faad7fee35`. Their exact Git commit objects are
retained under `original-local-commits/`. The already prepared33 remote commits
remain unchanged. A new publication branch from their local source parentf16
carries the checkpoint with two lossless parts, followed by the original formatter
spec/source and final Qt observation commits with explicit source attribution.
No existing local or remote history is rewritten; no branch is removed.

The original archive is reproduced byte-for-byte by the bounded verifier in
`../admission-diagnostics-integration-20261119/reassemble_evidence.py`. Part hashes,
the original manifest/README,420 original payload hashes, ZIP CRCs and the full
archive checksum remain available. The compact316-branch inventory is unchanged.
This layout change adds no production code or acceptance claim. The prior9- and
2043-test results retain their original exact sources and limits. Main merge and
release remain blocked. The existing `[no release]` hold is preserved.
