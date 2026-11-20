# Combined-source qualification

Source: `bffcfa99d6a5044024256edbc0457ab20c92cbae`.

The unsplit `QT_QPA_PLATFORM=offscreen python -m pytest -q` run was started in
a separate clean detached checkout, with JUnit output and duration diagnostics.
It is **running at this checkpoint**; this document does not claim a terminal
pass. Original log, JUnit and environment receipt will be retained when it ends.

The integration's later CSV reader-example correction and peer-review evidence
change documentation only. `integration-checkpoint.json` records equal `src`,
`tests`, and `tools` identities, plus the complete local history bundle. The
configured whole-tree Ruff and pip check both pass. Sixteen schema generators
completed without drift; the CSV worker separately rechecked Strings schemas.

## Local history recovery

The REST publication uses a verified tree mapping. To recover the original
local commit history, first fetch the PR #322 prerequisite commit, then:

```sh
git bundle verify docs/engineering/evidence/integration-history-20261119.bundle
git fetch docs/engineering/evidence/integration-history-20261119.bundle \
  refs/heads/codex/maximum-completion-20261119-4c8d:refs/remotes/local-evidence/integration
```

The bundle tip and SHA-256 are recorded in
`evidence/integration-checkpoint.json`. It preserves the exact local source and
review SHAs without pretending that REST-created commits retain local timestamps
or identities. Later status/publication records remain ordinary repository files.

Native, Windows, manual, release and layer-specific accuracy gates remain
separate; consult `release-readiness-20261119.md` and `task-ledger.json`.
