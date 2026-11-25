# Version and provenance consumer continuation — 2026-11-24 Pacific

The headless `patchtrace version [--json]` consumer is recovered and independently
reviewed at local checkpoint `806ccc4fbe7b26bd854cf64de96bd03bdde36f64`, tree
`a4944cc8e52da915e662f32ecf37e92fa99fbb3c`. Its next local checkpoint,
`cc1a8db8c21651a508abf42e02674ca39407f74c`, changes only QA/task documentation.
This continuation adds documentation and retained evidence only. Exact-source
hosted qualification of the consumer publication is still required.

This is additive to [the combined reliability candidate](consolidation-20261124.md).
Earlier records retain their source bindings. No release, deployment, tag, main
merge or whole-product acceptance is asserted here.

## Source and consumer scope

| Role | Exact source |
| --- | --- |
| Combined base, [PR #364](https://github.com/djshellshoxxx/PatchTrace/pull/364) | `ef66848d92d9b0d4cd58876cb157a5b609e011c5`, tree `64e25d3c8ad2a05aae470cfd55dddceb9517797a` |
| Main observed during qualification | `44c62cbf94c2d25c0c383eeb0072b7adf2bbb415` |
| Retained [PR #320](https://github.com/djshellshoxxx/PatchTrace/pull/320) donor | `6096e64d4e7b8f0ecc6af884f7d220e07790d85a`, branch `integration/exhaustive-patchtrace-consolidation-20261119` |
| Original version feature | `62b9a3de4d1036a6e4b9bd2618372f4042b15f7f` |
| Initial consumer recovery | `ce0e6d585653baf0dba3922d8e89273a1a742260` |
| Corrected, independently reviewed consumer | `806ccc4fbe7b26bd854cf64de96bd03bdde36f64` |

The selected modules are `buildinfo.py`, `version_cli.py` and the lazy
`cli_commands/version.py` adapter, with four consumer test modules. The
[consumer specification](../specs/version-provenance.md) is registered in the
[spec registry](../specs/REGISTRY.md) and [module index](../modules.md). The
maintained `owned_publication.py` reader and process supervisor remain unchanged.
The old whole-file CLI and entry point were not restored.

The two CLI modules retain their donor bytes. `buildinfo.py` adds only the
review-driven final-output correction below. The donor's Git-root tests now
exercise consumer functions directly because their old import required the
excluded metadata producer. `tools/package_buildinfo.py`, builders, Windows
version resources, workflows and release policy remain separate work. The
broader retained #312, #316 and #320 scopes and held branches remain preserved.

## Observable behavior

The command reports package, Python and installed dependency versions, frozen
state, and available source/build facts. JSON uses `enrichment-cli/1` with a
`build-info/1` result. Discovery and execution are headless; the command writes no
project, starts no analysis tool and makes no network request. Unknown optional
facts produce explicit warnings with exit 0/status `complete`; cancellation
exits 5 and malformed CLI input exits 2.

Source installations observe Git root, HEAD and description using fixed read-only
arguments and the existing three-second/4096-byte bounds. Root and HEAD rechecks
refuse unrelated enclosing repositories and moving observations. No `status` or
`describe --dirty` runs because worktree checks can invoke configured clean
filters. `dirty` remains `null` and never implies a clean checkout. The source
fingerprint retains the historical sorted Python-file hash definition, bounded
no-link reading and inventory recheck. It is source-content observation, not
loaded-bytecode identity, package authenticity or native compatibility evidence.

Frozen installations consume only a strict, bounded
`_MEIPASS/patchtrace/build-info.json`. Missing or invalid metadata leaves build
facts unknown with no Git or extraction-directory source fallback. Current
builders do not produce this record; the separately retained producer needs its
own integration and qualification. Frozen provenance is never fabricated.

The coordinator's actual source CLI run at `cc1a8db8` exited 0 with the expected
envelope, `source-tree` basis, the same Git commit, `dirty: null` and the filter
warning. Source SHA-256 was
`a5dae453dfed42d6133644cb51b773744d428c23c3b0aac8db7544ef9e6c0f47`, with Python
3.12.14 and Qt 6.12.0. The [consumer receipt](evidence/version-provenance-20261124/consumer-review-statements.json)
preserves this as an attributed observed-tool-output statement.

## Independent finding and local acceptance

Independent review found a donor defect at the final process-output boundary:
a quick successful process exit could retain only a stdout tail while the final
reported total exceeded 4096 bytes, without an output-limit reason. The consumer
previously trusted that successful tail. It now requires raw stdout to be
present, its length to equal the reported total, and the total to remain within
the existing cap before decoding. The shared supervisor and budgets are unchanged.

Eight deterministic `ProcessResult` controls recorded **six failures and two
passes before correction**, then **all eight passing**. They cover oversized or
inconsistent observations, absent raw bytes, valid output including exactly 4096
bytes, and refusal of an oversized retained HEAD identity. This uses the
process-result seam; no subprocess or target-exploitation reproduction was needed.

| Source-specific verification | Result |
| --- | --- |
| Author: consumer, CLI registry, doctor and spec registry | **233 passed, 1 skipped**, 5.75 s; zero failures/errors. Skip: existing opt-in nightly toy-freeze control requiring `PATCHTRACE_TOY_FREEZE=1`. Whole-tree Ruff and whitespace checks passed. |
| Independent reviewer on `806ccc4f` / tree `a4944cc8` | **40 passed, 0 skipped**, 3.14 s; zero failures/errors. Focused Ruff, full feature whitespace and clean-head checks passed. The output-admission finding is closed; no remaining consumer-scope blocker. |

These selections overlap and must not be added. Neither consumer run saved raw
JUnit or a redirected raw test log. The
[review receipt](evidence/version-provenance-20261124/consumer-review-statements.json)
is explicitly an observed-tool-output statement, not a manufactured test artifact.
Existing historical [author census JUnit](evidence/consolidation-20261124/integration-census.xml.gz),
[independent census JUnit](evidence/consolidation-20261124/combined-census-independent-review.xml.gz)
and [project review JUnit](evidence/consolidation-20261124/pr360-independent-review.xml.gz)
remain byte-identical with their earlier source bindings.

Static review confirms registry discovery automatically includes `version --help`.
The packaging hook verifies adapter collection; the frozen A1 `version --help`
invocation builds its parser and thereby imports `version_cli`/`buildinfo`.
Existing Windows and two Linux frozen smoke paths are configured to cover
discovery when run on the new source. **No native execution of frozen `version --json` or `read_info` is
claimed.** Direct consumer controls establish missing/invalid packaged-record
behavior and refusal of source/Git fallback.

## PR #364 hosted checkpoint

The [REST snapshot](evidence/version-provenance-20261124/pr364-check-snapshot.json)
was captured at **2026-11-25 03:44:26 UTC**. All four runs bind to base head
`ef66848d92d9b0d4cd58876cb157a5b609e011c5`. The independent auxiliary review confirms
synthetic merge `69a0bf8e2dd97165826bdbb2caa700eb57f41076` has the same tree
`64e25d3c8ad2a05aae470cfd55dddceb9517797a` as that head.

| Workflow and run | Snapshot state |
| --- | --- |
| [QA and Windows standalone — 45540193200](https://github.com/djshellshoxxx/PatchTrace/actions/runs/45540193200) | Linux/Windows full QA and five Qt jobs running; dependent package producers/consumers pending. Release-gate skipped. |
| [Native Windows Ghidriff — 45540193242](https://github.com/djshellshoxxx/PatchTrace/actions/runs/45540193242) | All five jobs completed successfully. |
| [Optional dependency probes — 45540193209](https://github.com/djshellshoxxx/PatchTrace/actions/runs/45540193209) | Both Linux and Windows jobs completed successfully. |
| [Corpus Tier R — 45540193257](https://github.com/djshellshoxxx/PatchTrace/actions/runs/45540193257) | Workflow successful; 5/11 completion warning and Windows advisory findings retained. Dispatch-only MSVC job skipped. |

The fresh [independent receipt](evidence/version-provenance-20261124/pr364-independent-qualification-review.json)
and [23-member evidence ZIP](evidence/version-provenance-20261124/pr364-auxiliary-independent-review.zip)
preserve nine provider artifact ZIPs, eleven completed job logs, metadata and the
reviewer's 03:43:38 UTC workflow snapshot. Artifact digest/size/CRC checks and all
eleven checkout bindings pass. Three native project snapshot/raw hash checks and
modified-function controls verify, as does the raw-cache positive control.
Stored JVM identity remains unverified; input binaries were not independently
downloaded/rehashed; cache-hit jobs do not exercise an archive-cache miss. Native
Ghidriff acceptance is separate from frozen version execution.

These results cover their recorded base source and scope. Exact-source hosted QA,
repeated Qt, package/frozen-consumer and native checks for the later consumer
publication remain required. The live PR governs subsequent state.

## Historical auxiliary evidence and ancestry

The separate [PR #358 recapture](evidence/version-provenance-20261124/pr358-auxiliary-independent-recapture.zip)
and [receipt](evidence/version-provenance-20261124/pr358-independent-auxiliary-review.json)
bind to `18edf3012a26eaeb037c2b970a252cc14481fba8`, with observed merge
`d462c9bfbf8f6e1ccfbb86938a41344d7b094043`. The recapture verifies **nine artifacts
and eleven job logs**. Archive SHA-256:
`e29ff9e332bf75a80b093aeb47d0c02218755ff948ffe3a87d88cc3e75711b5e`;
standalone receipt SHA-256:
`dd2e9f2057ea1bd47dbf6d69e37720425da53f4668e399d050e3a695904ccc07`.

The unavailable original `pr358-completed-auxiliary-checkpoint.zip`, previously
described as 147 members with digest
`7e365fffe9d574520d993cc12c2956026afad14ffc0f794c2e9a2ddfb46d3875`, remains
**unverified**. The 22-member independent recapture does not certify that exact
original archive.

Both historical and fresh PR #364 evidence retain **5/11 Tier R engine pairs
completed and 6 failed**, plus **11 Windows advisory findings, exit 1 and zero
reports**. Fresh aggregate, provenance and CI summary replay exactly match the
historical results. Green workflow status does not close this coverage gap,
establish full Tier R acceptance or support an accuracy claim. Historical
source-specific evidence is not current consumer acceptance.

The [ancestry receipt](evidence/version-provenance-20261124/branch-reachability.json)
records **382 remote refs**, **171 contained in main** and **182 in the PR #364
candidate**. Its 11 newly contained refs include the candidate's own new remote
ref, hence **10 previously existing branch heads**. This is an ancestry census,
not proof of complete semantic consolidation. Held scopes and prior decisions
remain intact.

The [manifest](evidence/version-provenance-20261124/manifest.json) records hashes,
sizes and copy checks. Both ZIPs were checked recursively for CRC, member paths,
executable-target names/signatures and credential-value patterns; no flagged
members were found. This bounded screening is not a comprehensive secret audit
or authenticity attestation. No target binary was executed for this checkpoint.

## Publication handoff

Root owns the stacked publication and final independent documentation review.
The implementation/review commits above are local checkpoints, not remotely
addressable commits. Publication creates a new remote commit on `ef66848d`; the
[review receipt](evidence/version-provenance-20261124/consumer-review-statements.json)
records exact runtime/test Git blob identities to bind the published tree to the
reviewed source. Hosted qualification must bind to that new published head.
Keep `[no release] [no deploy]` in publication and eventual merge metadata. Require
all applicable exact-source checks and clear blocking reviews; use the standing
REST expected-head merge guard and verify main ancestry before reconciling donor
PRs. Preserve held branches and historical receipts. Producer integration and
outstanding native/manual release acceptance gates remain separate work.
