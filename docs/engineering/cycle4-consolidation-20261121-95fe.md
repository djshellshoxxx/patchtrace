# PatchTrace cycle4 bounded follow-up — 21 November 2026 UTC

## Outcome and integration ownership

Two unowned slices are implemented, independently reviewed and locally qualified:
all five Build environment table headers now expose registered help, and the
Pages build uses a complete hashed site-only environment with explicit pytest
fixture/plugin isolation. Main promotion, release and deployment remain held.

This follow-up starts from PR #349 at `11f51c105bf63946f59373ae605b937c4fee607a`. The parallel 837FE session owns
that PR's integration/qualification, Search headers, two storage repairs and
CODEX-1 Action pins. This session did not modify PR #349, those source scopes,
or their worktrees, and did not dispatch/retry any workflow. Its separate planned
branch is `integration/patchtrace-20261121-95fe-c4`. Resolve its live PR body for the final publication head and
postpublication check state. Source completion is not merge authorization by itself.

## Changes

### Five Build environment headers

Fact, OLDER, NEWER, Status and Basis use five static `build_env.col.*` entries
through the existing registry. Help accurately describes dash placeholders,
all five row comparison states and source provenance; unknown is not a difference.
Both declaration modules remain Qt-free. Removing only the new IDs and entries
restores their original ASTs. No parser, backend, persistence, worker lifecycle,
display/accessibility label, cell, sort/filter or copy behavior changes.

The global registry-coverage test activates Build environment through the real
panel host and checks five actual header sections. No exemption is added. A
fresh independent control removes only Basis and makes that same audit fail,
identifying exactly `build_env.col.basis`.

### Pages site environment and hashes

The original site-only install reproduces a `ModuleNotFoundError: pydantic`
during the application-wide automatic KEV fixture, before a site test body.
The Pages invocation now uses `--noconftest --disable-plugin-autoload` over the
complete `tests/test_site_*.py` selection. Application QA keeps its shared fixtures.

The new lock contains seven reviewed wheels for CPython 3.12/Linux x86-64:
Segno 1.6.6, Pillow 12.3.0, pytest 9.2.0, iniconfig 2.3.1, packaging 26.3,
pluggy 1.7.0 and Pygments 2.21.0. Every SHA-256 matches fresh version-specific
PyPI metadata and actual downloaded bytes; all four active dependency edges
resolve. The workflow requires hashes and binary distributions, keeps dependency
resolution enabled and adds no unpinned package. Portable build-only declarations
remain available. Action references, events, permissions, artifact flow and the
actual-head `[no deploy]` condition are unchanged by this slice.

Both independent Pages reviews passed. Their one P3 documentation finding,
S-PAGES-01, was fixed by naming tested pytest 9.2.0 and the flag's 8.4 minimum in
the local instructions. Both reviewers verified the README-only correction.

## Executed qualification

| Source/scope | Actual result |
| --- | --- |
| Build environment new regressions, unchanged production | 14 failed, 1 passed |
| Same regressions after implementation | 15 passed |
| Author affected selection before host-audit integration | 124 passed, 1 missing-header audit failure |
| Reviewed integrated Build environment selection | 132 passed |
| Original clean Pages environment / unchanged test | 1 setup error: missing pydantic |
| Same source with diagnostic fixture isolation | 243 passed, 1 existing optional GUI skip |
| Four new Pages source-contract tests before implementation | 4 failed |
| Final clean, hashed Pages-only environment | 247 passed, 1 existing optional GUI skip; real build passed |
| Actual wrong-hash and omitted-dependency installations | Both correctly refused; separate fresh environments |
| Combined normal-conftest selection at `8c5e77e2` | **391 passed, 2 expected failures, 0 ordinary skips** |
| Whole-tree Ruff, pip check, isolated source binding, whitespace | Passed |

Counts overlap and must not be summed. The final JUnit has 393 unique identities;
only CODEX-1 and CODEX-5 are expected failures. The optional screenshot case
passes in the combined full-dependency environment. Fifteen author GUI-tip cases
outside the final selection remain historical evidence and are not added.

The early `buildenv-host-audit-baseline` label describes the general control-tooltip
test, not the modified registry-coverage test. The 132/391 selections and the
independent global positive/negative controls establish the host-audit repair.

The hashed install/refusal checks used `--no-index --find-links` with verified
local wheels. They do not establish hosted index resolution. The new source still
requires applicable hosted checks. No new full local aggregate was started after
the prior unrelated unexplained SIGKILL history.

## Exact source and preserved history

| Identity | Value |
| --- | --- |
| Base | `11f51c105bf63946f59373ae605b937c4fee607a` |
| Tested local combined source | `8c5e77e2c1ad3f6cfa62c2e474f7bcc2f4af1dd5` |
| Tree-identical REST code checkpoint | `2162708d86bb655f85410d8064aea04c396d5e6e` |
| Tested complete tree | `6fe242cc10a5e7c3afe74c40a0f701cbab73aef1` |
| Reviewed README correction/local checkpoint | `36584f8153983d64605dd7f4141e88c9fabfa6ef` |
| Tree-identical REST documentation checkpoint | `f1f8ef664fd6ee88bf47a375538e4be0d8f11992` |
| Checkpoint complete tree | `377a07bdde10a13bb46b0f5bef5c2b96af9d7210` |

All eight changed runtime/test/workflow/lock blobs match reviewed sources. The
ten original local commits and ordered parent relationships remain in the
verified bundle; REST mappings preserve complete trees and mapped parents.
Subsequent record additions change engineering documentation/evidence only.

## Remaining work and merge boundaries

- Integrate with the 837FE owner's Search/storage/Action-pin source without
  overwriting its changes. Shared files need both scopes: Build environment and
  Search activation in `tests/test_tooltips.py`; immutable Action references plus
  the two Pages run commands; corresponding workflow test assertions.
- Refresh the resulting exact head and all applicable hosted checks. Preserve
  earlier capa/FLOSS Windows advisory failures and their owner's disposition.
- The Pages slice closes one previously identified unhashed install block.
  CODEX-5 remains open for 41 other textual run blocks, not 41 matrix executions.
- Repair the separately recorded CODEX-5 audit blind spot: flags anywhere in a
  multiline block currently exempt other install commands or comments. This is
  a test limitation demonstrated by synthetic text controls, not evidence of a
  compromised workflow. Coordinate changes to that file with the Action-pin owner.
- Preserve broader manual Windows/trust/accessibility, raw provenance, historical
  semantic and separate L1/L2/L3 release gates. No project-complete claim.

Merge only after all applicable checks and blocking findings are resolved, using
a fresh expected-head REST guard. Any eventual main merge must carry both
`[no release] [no deploy]` in its actual resulting commit. No release, deployment,
tag, force update or branch deletion is included.

## Records

- [Authoritative ledger](task-ledger.json)
- [Evidence, reviews, original failures and source bundle](evidence/cycle4-95fe/README.md)
- [Machine-readable qualification](evidence/cycle4-95fe/qualification.json)
- [Executable handoff](../engineering-handoffs/cycle4-20261121-95fe.md)
