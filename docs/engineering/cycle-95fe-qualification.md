# Cycle 95fe qualification

Frozen local code source: `ccc3664f11a81d3d30f907da36fc3d22da0063d0`.
Verified remote code counterpart: `406acf96f5b1a299aca940f98eeb69d0b9583729`.
Both complete trees are `a72efdcbf503e0480a182fd323c5c4320d27c098`.
Final publication adds documentation and evidence only; its complete tree
therefore differs. The mapping and retained code-history bundle preserve the
source identities used by the actual test receipts.

Environment: Python 3.12.14; PySide6/shiboken6 6.12.0; Pydantic 2.14.2;
protobuf 7.36.2 with upb; pytest 9.2.0; Ruff 0.17.6. Declared dependencies passed
`pip check`. No dependency configuration or persisted schema changed.

## Completed bounded checks

| Check | Result | Scope and source |
| --- | --- | --- |
| Baseline late-stack selection | 105 passed, 1 native Windows skip | Clean `67f7e08e`, five files |
| Candidate admission related selection | 183 passed | Clean worker `649ed46e`; includes its 21 focused cases |
| GUI recovery affected selection | 212 passed | Tested working diff subsequently committed as `2c7f506b`; diff equality verified |
| CSV / diagnostic coverage | 47 passed | Tested working diff subsequently committed as `c71d604e`; diff equality verified |
| Inventory regression selection | 10 passed | Working contents later committed as `076c1ffa`; precommit receipt |
| Real inventory replay | Passed, byte-identical | Fixed tool; captured 353-topic refs and PR metadata; same contents across commit |
| Combined admission selection | 183 passed | Clean frozen `ccc3664f`; seven files; no skips |
| Combined changed cases | 50 passed | Clean frozen `ccc3664f`; no skips; includes all ten inventory cases and both recovered GUI cases |
| Whole-tree Ruff | Passed | Clean frozen combined source `ccc3664f` |
| Dependency / protobuf runtime / CLI help | Passed | Pinned environment and combined source; no target analysis |

The two completed combined-source selections contain **212 distinct passing
cases**: 183 + 50 minus 21 shared cases. Their JUnit `(classname, name)` identities
were reconciled in `qualification-summary.json`. This is a union across two
bounded processes, not a single suite. The earlier GUI worker's 212-case result
is a different selection on a different complete tree and is not added to it.
All preintegration selections may overlap; their counts are not summed.

## Interrupted checks and unverified gates

| Check on clean `ccc3664f` | Actual outcome | Qualification consequence |
| --- | --- | --- |
| Full local pytest | SIGKILL / -9 after 23.089 s; no first test-start event | No full-suite result |
| 27-file combined selection | SIGKILL / -9 after 70.395 s | No terminal summary or JUnit |
| Six-file combined GUI batch | SIGKILL / -9 after 32.827 s | No terminal summary or JUnit |
| Fourteen-file integrity/coverage batch | SIGKILL / -9 after 21.474 s | No terminal summary or JUnit |
| Hosted Windows/Linux/Qt/native/package on final publication | Pending | Parent PR success does not transfer |
| Actual Windows screen-reader / clean-machine trust acceptance | Unverified | Requires supported Windows acceptance |

The admission batch of the three-way split completed; the other two batches
were killed. Progress dots and skip markers from interrupted processes are not
counted as completed acceptance. Tests, budgets and skip rules were not weakened.
No broad retry is justified without information that resolves a concrete risk.

## Diagnosis and evidence limits

An independent read-only diagnosis verified that `run_check.py` has no timeout,
and `run_full.py` samples after a five-second wait without terminating pytest.
The available evidence does not identify the SIGKILL sender or cause. It does
not establish OOM, a fixed runner timeout, a GUI regression, or test-order effects.
The passing worker and interrupted combined GUI selections have identical GUI
source, selected test modules and shared fixtures, but differ in command order,
cacheprovider setting, temporary directory and checkout. Causation is untested.

Post-failure process limits exposed no CPU/address-space/RSS cap. No usable
cgroup memory-event files or kernel kill records were available. A cumulative
`oom_kill` counter lacked a before/after baseline, timestamp or matching PID and
is unattributed. The full-run resource samples and child maximum RSS of 197,080
KiB are retained; these do not establish or exclude memory pressure elsewhere.

## Reproduction and retained receipts

The [evidence directory](evidence/cycle95fe/) contains the raw evidence archive,
SHA-256 manifests, a code-history bundle and the local/remote commit mapping.
The archive preserves exact commands, source/tree/dirty-state receipts, logs,
JUnit where produced, full-run phase/resource samples, donor mappings, original
regression failures, census inputs and its byte-identical replay. Consult the
manifest before relying on a restored artifact.

The [integration queue](INTEGRATION_QUEUE.md) retains all full, native, manual and
source-specific hosted gates. These scoped results do not qualify main promotion
or a release. Original historical failures remain preserved separately even
when a later, different source passes.

Standalone [environment receipts](evidence/cycle95fe/environment-checks.json)
record successful dependency consistency, protobuf pin/upb and headless CLI
help checks on clean `ccc3664f`. These post-audit receipts supplement the frozen
archive without replacing its original evidence.
