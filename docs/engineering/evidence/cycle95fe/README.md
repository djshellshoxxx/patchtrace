# Cycle 95fe evidence and publication provenance

Local code source: `ccc3664f11a81d3d30f907da36fc3d22da0063d0`.
Remote code counterpart: `406acf96f5b1a299aca940f98eeb69d0b9583729`.
Their complete trees are identical: `a72efdcbf503e0480a182fd323c5c4320d27c098`.
The final documentation/evidence commit adds files without changing the tested
application, tests, tools, configuration or workflows.

| Artifact | Purpose | SHA-256 |
| --- | --- | --- |
| [cycle-95fe-evidence.zip](cycle-95fe-evidence.zip) | 74 unchanged raw files plus six explanatory/manifest entries; 80 entries total | `06e115ed85de8fd85315d2bef465d7eff60833179f520cbd9fa3801f95669525` |
| [local-code-history.bundle](local-code-history.bundle) | Exact nine-commit local code DAG, including three merges | `81d15e5383e3aa7ddd7a8826122f4499789f2c97375525eebaf4316bcdf93517` |
| [member-manifest.json](member-manifest.json) | Archive member sizes and SHA-256 identities | `105d701f56bc35a517e4df072c5edfe2ec195d7a6db71bee6f8502e0710563aa` |
| [pack-validation.json](pack-validation.json) | Independent archive and bundle validation | `d71ce1ae6f2adaa9a48e60aaef1eb719b4786fee44ca155c37b6748c5c27093c` |

[code-commit-mapping.json](code-commit-mapping.json) records all nine local-to-remote
code commits. GitHub Git Data API publication preserves tree contents and parent
topology; author/committer metadata changes commit IDs. The existing base remains
`67f7e08ea9bee61653f8ab5ad66048d3e7141810` (PR #344).

The bundle advertises `refs/heads/cycle95fe-code` and requires that base commit.
In a full clone with the prerequisite, `git bundle verify` validates the bundle.
Fetch that advertised ref into a new local recovery branch if original local
identities are needed. Do not replace main or another worker's branch.

The ZIP retains exact runner commands, source/tree/dirty-state receipts, logs,
JUnit reports, original failed regressions, four interrupted SIGKILL attempts,
donor/source diffs, census inputs and byte-identical inventory replay. Its README,
diagnosis and checks distinguish tested working diffs from clean commit tests.
The two completed combined-source runs have 183 and 50 passes with 21 shared
identities: 212 distinct passing cases. This does not establish full/native
acceptance. The earlier GUI worker's separate 212-case result is not added.

[parent-ci-prepublication.json](parent-ci-prepublication.json) is a separate
23:53:17 UTC observation of PR #344. All five native jobs succeeded; QA and Qt
jobs remained active. It does not qualify the later code or final publication.
Resolve the publication branch and draft PR for their current exact head/checks.

[environment-checks.json](environment-checks.json) separately preserves the
post-audit dependency, protobuf pin/upb, and headless CLI-help receipts. All
three exited zero on clean frozen `ccc3664f`. They were recorded after the ZIP
was frozen and do not change its members or hashes. The runner helper is in the
ZIP. [Publication audit](publication-audit.md) records the independent review
and the corrected handoff-index finding.

[initial-publication.json](initial-publication.json) preserves the first
verified PR346 head/tree, its queued checks and the concurrent PR345 overlap.
The exact runtime comparison prevents duplicate GUI implementation/credit;
subsequent combined integration remains separately gated.
