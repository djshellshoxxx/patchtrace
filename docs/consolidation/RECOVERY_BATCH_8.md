# Recovery batch 8: connection observation health and JUnit admission

## Scope and provenance

This batch repairs two evidence-handling defects found while classifying the supplemental tools scan.
The scan is pinned to `5208c7589495cea749142f57599c4382be9caed5`; its relevant implementation blobs are
unchanged at this branch's base, `cf55415587f996f54a9d957a48d57818ebe9ff42`. These are newly authored
corrections to the observed implementation, not a claimed port from a retained branch.

The source changes are limited to [the bundle acceptance harness](../../tools/bundle_acceptance.py)
and [the unified gate-report CLI](../../tools/unified/gates_u.py). Their existing contracts were amended
before implementation in [the acceptance specification](../specs/program-e/BUNDLE-acceptance-isolation-spec.md)
and [the evaluation specification](../specs/unified-engine/08-evaluation.md). The separate backend HTTPS
repair, runtime source, acquisition/storage changes and frozen consolidation census are outside this batch.

## 1. Failed connection observations could appear successful

The original `ConnectionMonitor.poll` swallowed every sampling exception, then incremented `polls`.
The consumer passed `no-external-connections` whenever `seen` was empty. An offline reproduction used the
exact pinned poll body and consumer expression with an authored callback that raised `OSError` three
times. It produced three attempted polls, zero successful observations, and a passing connection step.
That reproduction started no process, thread, socket, or compared image. The separate OS-block positive
control was not implicated: the defect was in the supplementary observation evidence.

Caller review found two additional ways an unsuccessful observation became empty data: Linux namespace
or connection-table read failures returned an empty list, while the Windows sampler ignored a nonzero
PowerShell exit. The repair makes observation health explicit:

- `polls` retains its historical meaning: attempted samples. Additive fields record `successful_polls`,
  `sample_errors`, `unavailable_polls`, and sorted `seen` endpoints.
- A child that still occupies the host network namespace, or whose namespace/tables have disappeared,
  supplies an unavailable observation. Other read failures supply an error. Partial Linux observations
  retain endpoints already seen in either table, even when the other table cannot be read.
- The Windows query treats command errors as errors, has a two-second sampling timeout, and preserves
  stdout endpoints when a command exits unsuccessfully or times out. Empty successful output remains a
  valid observation. No claim is made here about native Windows behavior.
- The connection step requires at least three successful observations and no observed external endpoint,
  matching the existing acceptance specification's three-poll requirement with explicit success accounting.
  Intermittent failures remain visible; they do not erase earlier endpoints. This sampling result does not
  replace, relax or skip the OS-block positive control.

Independent review reproduced a defect in the first proposed correction: Windows stdout could be lost
when the command failed or timed out, and three later healthy empty samples would then pass. Three
additional regressions cover nonzero exit output and both byte and text timeout output. All three failed
before the final correction. The final implementation retains the observed endpoint and refuses the
connection step in each case.

One existing Windows-branch test runs on POSIX with an authored Python bundle and fake firewall commands.
Its success depended on silently ignoring unavailable PowerShell. That fixture now explicitly supplies
three authored successful observations; every existing ordering, positive-control, command-record and
digest assertion remains. It provides harness evidence only.

## 2. The JUnit byte limit was applied after reading the whole file

`parse_junit` already rejected data larger than 8 MiB and refused invalid UTF-8, NUL, DTD/entity declarations,
unexpected roots and invalid XML. The public CLI first used `Path.read_bytes()` on every selected JUnit
file, retaining all raw bodies before invoking that parser. The parser limit therefore did not limit the
initial read.

The CLI now reads at most 8 MiB plus one sentinel byte for each explicit or discovered JUnit file. An
oversize file raises the existing `ContractError` before XML parsing. Each file is parsed and hashed
before the next file opens, so the CLI no longer retains a list of all raw JUnit bodies. Previously written
JSON and Markdown reports are not replaced when admission or reading fails. Direct parser callers keep
the original defenses and outcome semantics.

Authored virtual-file controls reject an unbounded read without allocating a large file. Other controls
cover both CLI input routes, exact-limit acceptance, the first over-limit byte, sequential parsing and a
read error that preserves prior output. This amendment does not establish an aggregate limit on the
number of files or merged test outcomes, and it does not change other artifact readers.

## Verification and retained receipts

Tests ran from this isolated source checkout using the private source-first interpreter with Pydantic
`2.14.2` and pydantic-core `2.50.2`. The `-I` import-origin receipt identifies this checkout's `src/patchtrace`.
New observation and admission regressions use authored data and mocks; they do not exercise a native
firewall, live network, real PowerShell sampler, external analysis backend or target execution.

| Stage | Result | Receipt under the task workspace's `verification/` |
|---|---|---|
| Exact pinned monitor reproduction | Three errors, zero successful observations, original connection step passed | `tools-monitor-health-red-repro-20261119.json` |
| New regressions and existing gate tests, before implementation | 21 failed, 26 passed in 3.93 s | `tools-evidence-red-20261119.log` and `.xml` |
| First focused repair | 47 passed in 3.21 s | `tools-evidence-green-20261119.log` and `.xml` |
| Existing affected callers, before explicit Windows fixture correction | 1 failed, 107 passed, 3 skipped in 4.30 s | `tools-evidence-affected-first-20261119.log` and `.xml` |
| After the explicit fixture correction, before peer partial-output finding | 108 passed, 3 skipped in 4.88 s | `tools-evidence-affected-final-20261119.log` and `.xml` |
| Independent partial-Windows-output reproduction | Both nonzero and timeout schedules lost an endpoint and passed after three healthy samples | `tools-evidence-independent-partial-windows-20261119.json` |
| Added partial-output controls, before their correction | 3 failed in 0.78 s | `tools-partial-output-red-20261119.log` and `.xml` |
| Final affected group | **111 passed, 3 skipped in 4.48 s** across four files | `tools-evidence-qualified-20261119.log` and `.xml` |
| Configured Ruff on both implementations and three changed test files | Passed | `tools-evidence-ruff-20261119.log` |
| Isolated import origins and dependency versions | Passed | `tools-evidence-env-20261119.json` |

The final group ran `test_bundle_acceptance_monitor_health.py`, `test_bundle_acceptance_unit.py`,
`test_bundle_acceptance_isolation.py`, and `test_unified_gates.py`. Its three skips are the pre-existing
dry-run cases requiring Linux `unshare --net`: successful denial/digest equality, a missing control
baseline, and launcher mutation detection. They remain unavailable in this executor; the green authored
controls do not substitute for them. The test bodies, source, specifications, original failures and peer
finding are retained. No full current-head suite or release acceptance is asserted.

## Remaining limits

Polling is supplementary and can miss short-lived connections. The Windows query still samples the named
child PID; this batch does not expand it to a process-tree monitor. Errors and unavailable intervals are
now disclosed, but three successful observations do not prove continuous coverage. Actual Windows
firewall/ACL/sampler acceptance and Linux namespace acceptance remain separate native gates. Historical
evidence that stored only attempted polls cannot retroactively establish sampler health.

The supplemental static report classifies the original 70 tools findings at their exact recorded source
locations. Classification does not make the scanner clean and does not establish general security of the
developer toolchain, build inputs, executable search paths, native parsers or release environment.

## Preserved evidence archive

The [verified evidence archive](evidence/tools-evidence-20261119.zip) contains all 19 fixed receipt payloads plus their original manifest and the archive manifest. Its SHA-256 is `562beb72e39c12a3208142ba281a516e3cd28984788164d47d612f3857816c9e`; size 36945 bytes. Every payload digest and the ZIP CRC were checked. The separate [70-finding tools audit](evidence/tools-static-review-20261119.zip) retains its original baseline scan and classifications; it is not included in the affected-test count.
