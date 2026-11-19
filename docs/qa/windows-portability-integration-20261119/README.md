# Independently integrated Windows fixture portability — 2026-11-19

The reviewed fixture/builder changes are integrated at `11c3ffabf25d8527732b45bc2d949565d91debc5`, tree
`7eb451804373f79f514051b19045ae9ea4a899a4`. The source/test commit is
`49369f41185c8ce4c3ddc75df70bec244160a7a6`; its following commit adds only QA and
tracker updates. Main was last verified at
`9c411ca3d7b47f950be5f0c6f01b3c54184554c6`. This packet does not claim a main merge,
remote publication, complete Windows acceptance or beta readiness. `[no release]`.

## Changes, independent review and original evidence

Authored source/requirements fixtures write exact UTF-8/LF bytes. Tiny authored
Git repositories pin local `core.autocrlf=false` before staging. The Linux builder
uses one changed expression, `relative_path.as_posix()`, for its sorted inventory.
Actual Linux names/bytes, regular-file iteration, forbidden-library rejection,
required resources, complete smoke and refusal-before-archive behavior remain.
The builder change is tool source, not a fixture-only change.

The original chain is spec/red `24651bf5`, source `81590f93`, QA `9e228d84`;
each has an attributed append-only integrated commit. Root reviewed the complete
spec, new controls and source diff, reread relevant existing fixture/validator
paths, and independently verified all **127 author payloads, 74 exact source
snapshots and 264 historical import/source pairs**. Original **144 assertions,
110 test identities/decorators** and existing context-manager predicates remain.
The source-boundary verifier independently confirms the single allowed tool
expression and unchanged production/native/receipt validators.

Original authored evidence stays **19 failures / 1 positive** before the repair.
The focused final gate passes20; its affected gate passes678 with **8 original
native-Windows skips**. The first focused recorder omitted one local read-only
Git command, and the first affected recorder omitted one exact authored-local
HEAD update. Both original errors, runner sources, outputs and corrected finite
allowances are preserved. No original failed run is relabeled. See the
[complete author packet](../autonomous-ci-20261118/windows-fixture-portability/README.md).

## Exact integrated candidate gate

Root's bounded replay at `11c3ffabf25d8527732b45bc2d949565d91debc5` passes **142 tests**, with **zero failures,
errors or skips**, in **1.04 pytest seconds** (1.710 seconds outer recorder):

| Scope | Tests | Evidence |
| --- | ---: | --- |
| Unchanged new portability controls | 20 | CRLF, real local Git normalization and inert builder path models |
| Unchanged authored formatter controls | 9 | Real standard-C formatter and preserved acceptance predicates |
| Complete static specification registry | 113 | Every current registered specification path and nonvacuous walk |

All **42 imported project/tool modules** match current Git and disk. All **69**
modules imported by the author's final affected gate are also byte-identical on
the integrated source. The reviewed child scope is95 authored local Git calls
plus7 compiler/formatter process events. The inherited network filter loads;
there are no inherited sockets or network audit events. Only the owned completed
scratch directory is removed. Complete argv, environment, JUnit, source receipts,
helper scripts and observations are retained in this archive.

Full normal `ruff check --no-cache src tests tools` passes on this source. The
`src` tree remains exactly equal to the prior `1a9942a5` source, where the isolated
strict S scan retained **80 unchanged findings**. That strict scan is not rerun or
waived here. The earlier2,043 combined gate and these142 controls are separate,
overlapping observations attributed to their actual sources, not an additive
test count or a full-platform result.

## Historical/platform limits and publication layout

The old published771e Windows result remains51failed/25155passed/150skipped/
2xfailed. This slice addresses the reproduced newline and Linux-inventory
mechanisms. The original two small Git-source failures did not record the
necessary bytes/settings; the portable normalization reproduction does not prove
their precise historical cause. Core creation/ownership and symlink repairs
continue separately. The formatter failure is still awaiting actual Windows
constituent values. The final old-head Qt jobs are cancelled, not passing.

The preceding complete420-payload checkpoint archive is preserved as two
checksum-verified parts because one encoded connector request exceeded16MiB.
Reassembly reproduces all13,132,985 bytes and SHA-256
`ab11b8c014d5fdf0cfe94b2e29f661bd20974019f7c4f9a91151b7593dce4ece` exactly.
The original branch and all original local commits remain. The separate
publication branch carries attributed source commits and the lossless archive
layout; no existing history is rewritten. The initial layout-count recorder
mistake and transport errors are retained in the
[transport checkpoint](../archive-transport-20261119/README.md).

Pure package contracts, native file ownership and the demonstrated core
observation-family correction are active independent workstreams. Required
full Linux/Windows/Qt/native/frozen/package/security/reproducibility gates and
real CVE/KB/analyst journeys continue to block main merge and release readiness.

This archive contains **22 payloads**, plus its manifest,
**33,904 bytes**, SHA-256 `e33225b90bf5c1efa2d1ce3a8877b5ec3eb05c78e02a797783587534b23f788b`. Every payload hash, length
and ZIP CRC is verified. All author evidence remains separately immutable.
