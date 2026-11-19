# Dependency/security scan candidate — failed scans retained

Implementation source: **b61e1593fdb70435ac54b857624e618243f9491f**;
tree **ca5aca5405c12136e0d42306cb222d28e13b5b84**. This checkpoint supplies a
reviewed qualification mechanism and real failing local scans. It does not
supply clean dependency/security qualification, native Windows acceptance, or
release approval.

## Ancestry and bounded changes

The dedicated branch is `codex/dependency-security-20261118`, based on reviewed
release-guard QA tip `d27464d303bd0eaca219416c261ab6ba6869177e` (the guard's
underlying integration base is `9e5a5303da6e9a745e604979932f814de8eca4b0`).
Only the new scanner delta is intended for the parent continuation:

1. `0bc6684a`: specification/module index and authored failing controls.
2. `95bf8f5e`: scan workflow, bounded stdlib helper, four required dependency
   job names, and the matching workflow contract test.
3. `b61e1593`: independently reproduced interpreter/install ownership repairs.
4. This QA checkpoint: receipts and a test-only binary-output fixture correction
   so Windows newline translation cannot alter the authored raw-byte assertion.

The release policy now requires both native OS profiles: runtime and packaging
on `ubuntu-latest` and `windows-latest`, plus `security-scan`. It still checks the
critical steps `Audit installed dependencies` and `Static security scan`. The
actual commit's `[no release]` hold and all existing publication requirements
remain enforced by the separate release guard.

Every scan creates fresh scanner/product environments, preserves pip inspect
and install reports, records source/run/interpreter ownership, and queries the
already-installed pinned dependency closure. The one repository-owned
`patchtrace` distribution is retained with exact editable-origin proof; all
other installed distributions, including bootstrap pip and build dependencies,
are audited. `pip check`, exact scanner exit, complete result coverage, matching
installation/interpreter provenance, finite bounded JSON and intact raw-output
digests are mandatory. There is no dependency upgrade, remediation, ignored
vulnerability, suppression baseline or successful fallback in this candidate.

## Actual local results

All six scans below completed their scanner commands without timeout or output
truncation. Both sets are retained separately and keep their actual source SHA.

| Source | Linux scan | Complete non-owned Python closure | Outcome |
| --- | --- | ---: | --- |
| `95bf8f5e` | Runtime + search/rules | 17 | pip-audit exit 1; bootstrap pip findings |
| `95bf8f5e` | Packaging + dev/search/rules | 32 | pip-audit exit 1; bootstrap pip findings |
| `95bf8f5e` | Static application source | — | Ruff exit 1; 79 untriaged diagnostics |
| `b61e1593` | Runtime + search/rules | 17 | pip-audit exit 1; bootstrap pip findings |
| `b61e1593` | Packaging + dev/search/rules | 32 | pip-audit exit 1; bootstrap pip findings |
| `b61e1593` | Static application source | — | Ruff exit 1; 79 untriaged diagnostics |

Each dependency report contains **12 raw advisory records for pip 25.0.1**.
They represent **six distinct advisory IDs**: PYSEC-2026-1795, PYSEC-2026-1796,
PYSEC-2026-196, PYSEC-2026-2875, PYSEC-2026-2876 and PYSEC-2026-3721. Duplicate
service rows remain in the original scanner JSON. These are scanner observations;
this packet does not establish exploitability or substantively triage each
advisory. Bootstrap pip was not omitted to manufacture a passing scan.

Strict static counts are S608: 34, S105: 14, S110: 13, S101: 9, S310: 6,
S603: 1, S314: 1 and S108: 1. The original 78-finding detector result is preserved.
Disabling inline suppression exposes one additional S608 diagnostic at
`src/patchtrace/kbcorrelation/store.py:306`. All 79 remain untriaged by this
candidate; later independent repairs are separate work and do not retroactively
change these observations.

The repaired validator separately verified actual scanner/product interpreter
and installation origins and exact reported coverage for all six captured
snapshots. That validates their provenance; it does not turn the failed scans
into passes. See `actual-scans-summary.json` and each `linux-*/context.json`,
`*-inspect.stdout`, `*-install.json`, scanner stdout/stderr and process receipt
inside the evidence archive.

## Authored and independent verification

The initial red check recorded 2 workflow/policy failures and 57 absent-helper
errors. Four additional source/receipt controls then reproduced accepted
boolean/integer confusion, missing/stale timing and external source links.
Those failures and the subsequent passing controls remain preserved.

Root's independent identity review reproduced five contradictions with one
positive control: Python patch version, machine and implementation mismatches,
an inconsistent pip version, and an installation report for another platform.
The corrected implementation compares complete required native interpreter
fields, bootstrap/installed/inspection/report pip versions, and the full
installation-report environment. Missing/malformed fields refuse. Unsupported
requirement syntax is also refused before constructing an installer command.
The original independent probes are copied unchanged, with their red receipts.

The exact `b61e1593` affected command reports **599 passed, 3 existing expected
failures**. It includes scanner, release/workflow, bundle, cadence, milestone and
release-verification tests, all eleven original independent release controls,
and the six unchanged scanner identity controls. Root's separate pinned-source
review reports **128 passed** for the scanner module and its six external
controls. Full normal Ruff passes. The later portable raw-output fixture keeps
the original byte assertions and passes its focused check.

The three existing expected failures are CODEX-1 action pinning, CODEX-5 pip
hashes and CODEX-6 corpus cache requirements. They remain expected failures,
not completed qualification gates.

A full unsharded local run on `95bf8f5e` ended with **exit 137**. Its raw log
contains fourteen progress dots, no summary, and no completed JUnit. The cause
was not established. It is explicitly **incomplete** and was not repeated.
Raw path at capture:
`/workspace/scratch/c7a9e8d98848/dependency-security-evidence/full-suite-95bf8f5e.log`.
The parent will qualify the complete integrated tree separately.

An actual pip-audit network-error control with all HTTP proxy variable cases
pointing at a closed local port returned exit 1 with a connection/proxy failure;
the validator refused it. A preceding uppercase-only setup was ineffective
because lowercase proxy variables remained: that run reached the advisory
service and failed on findings. Both original outputs and an explicit
interpretation correction are retained; the ineffective setup gets no
network-denial credit.

## Primary sources and boundaries

Pins and semantics were checked against primary sources:

- [pip-audit 2.10.1 release](https://github.com/pypa/pip-audit/releases/tag/v2.10.1),
  [pinned usage/exit documentation](https://github.com/pypa/pip-audit/blob/v2.10.1/README.md),
  and [pinned JSON formatter](https://github.com/pypa/pip-audit/blob/v2.10.1/pip_audit/_format/json.py).
- [Ruff 0.17.5 release](https://github.com/astral-sh/ruff/releases/tag/0.17.5)
  and [official command-line documentation](https://docs.astral.sh/ruff/configuration/#full-command-line-interface).
- [pip inspect schema](https://pip.pypa.io/en/stable/reference/inspect-report/)
  and [pip installation report schema](https://pip.pypa.io/en/stable/reference/installation-report/).

The archive also preserves official action tag-to-commit observations for
checkout v4.2.2, setup-python v5.6.0 and upload-artifact v4.6.2; the workflow pins
their full immutable SHAs. Scanner tooling has its own retained installation
report and complete observed inventory. `primary-sources.json` maps decisions
to exact primary URLs and the retained original observations.

The scanned environments are the actual Linux environments installed for this
candidate. They do not supply a separate frozen executable's complete BOM or a
Windows inventory. External Ghidra/JDK/Rizin/BinDiff/NSIS, OS and vendored native
code, calibration-dev, scanner-tooling advisories and exploitability remain
explicitly outside this Python product audit. Hosted native OS/profile jobs,
final integrated tests, substantive finding/advisory remediation and all other
publication gates remain required. No remote mutation, release, tag, workflow
dispatch, target-binary execution or automatic upgrade occurred.

## Evidence packet

`manifest.json` lists every archived member's size and SHA-256; `evidence.zip`
contains full raw receipts, unchanged external controls, primary pin evidence,
source snapshots, command/provenance records, failed scans and test outcomes.
Environment directories, downloaded wheel caches and advisory caches are
excluded; their observed inventories, origins, wheel digests and raw scanner
responses are retained. The original predecessor packets are unchanged.
