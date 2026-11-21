# Full-suite interruption: preserved phase evidence and one isolated control

## Disposition

The full suite is **incomplete**. A clean combined candidate process received
SIGKILL; the origin of that signal remains **unestablished**. The last started
test passes once, unchanged, in isolation. That result does not qualify the
aggregate, explain the kill, or justify changing product code, test sizes,
timeouts, skips, or acceptance thresholds.

This investigation changes documentation and retained evidence only. It ran one
isolated original node, then stopped. No analyzed target binary was executed.

## Exact source and original full run

- Commit: `84798a04da9bc6a823b4b2d7802ea08a322c5367`.
- Complete tree: `bc78fc97c653ae8420338e02c2ed49c40e7a6406`.
- Original run interval: `2026-11-20T23:34:25.685653+00:00` through
  `2026-11-20T23:36:35.758168+00:00`.
- Child return code: **-9**; supervisor exit: **137**.
- Elapsed time: **130.057251967 seconds**. The supervisor imposed no timeout.
- Initial and final commit, tree, and clean working-tree observations match.

The unchanged full command used `QT_QPA_PLATFORM=offscreen`, the existing
Python 3.12.14 / PySide6 6.12.0 environment, disabled bytecode/cache writes,
requested JUnit, and loaded a diagnostic plugin that records pytest phase
boundaries. The complete command, launcher, plugin, stdout, and resource samples
are retained in the archive below. The plugin does not select or skip tests or
change their outcomes.

Collection observed **24,029 tests**. **329 nodes** have successful setup, call,
and teardown reports. The next recorded `logstart` is:

```text
tests/stress/test_gui_stress_table.py::test_a_hundred_thousand_rows_sort_and_filter_with_exact_counts
```

That node has **no setup, call, or teardown report**. There is no session-finish
record, terminal pytest summary, traceback, or requested JUnit file. The last
observed event therefore precedes recorded fixture-setup completion; there is
no observed failing assertion to repair. The 329 completed phase sequences are
partial-run evidence, not a terminal full-suite pass. The remaining 23,700
collected nodes have no completed report in this attempt.

## Resource observations and limits

The supervisor records a child high-water RSS of **943,372 KiB**. Thirteen
ten-second samples include a maximum child RSS of **754,106,368 bytes** and
minimum observed system available memory of **1,911,791,616 bytes**. These are
different measurements: the samples do not cover every instant and system
available memory is not a per-process or container limit.

The exposed environment provides no readable `memory.events`, `memory.current`,
or `memory.max` at `/sys/fs/cgroup`; `/proc/self/cgroup` reports `0::/` and
`/proc/pressure/memory` is absent. The earlier investigation also records that
ordinary kernel-log access was unavailable. This investigation did not obtain
a kernel OOM event, host termination receipt, quota event, or sender identity.

Memory pressure, cumulative process state, a host/process policy, and another
external termination remain hypotheses. Neither the recorded RSS nor a later
available-memory reading proves or rules out those hypotheses. Do not label
this event an OOM kill, test timeout, table defect, or regression caused by this
session's changes without additional evidence.

## One isolated unchanged node

The diagnostic used a separate clean worktree at the same exact commit and
tree, the same interpreter and Qt version, the original 100,000-row fixture,
original assertions, and the same phase plugin. It sampled resources every
0.2 seconds and imposed no launcher timeout.

| Observation | Result |
| --- | --- |
| Pytest | **1 passed in 1.47 seconds** |
| Child return code | **0** |
| Supervisor elapsed | **2.206891530 seconds** |
| Child high-water RSS | **167,720 KiB** |
| Setup/call/teardown and session finish | All recorded successfully |
| JUnit | Present, one case, no failure/error |
| Source before/after | Identical and clean |

The table implementation, pure preparation module, stress test, shared
`tests/conftest.py`, and `tests/qt_support.py` are unchanged between the initial
candidate `67f7e08e` and this frozen combined candidate. The stress test originated
in retained commit `f8d5ab79e9cb1614c7a9d4778e2c61e5c4fe265f`. Its module-scoped
fixture prepares 100,000 synthetic rows; no target files or network calls are
involved.

Isolation removes the preceding collection/process history, so the lower RSS
and success are useful boundaries, not controlled proof of a particular cause.
No further local rerun was performed by this investigation.

## Relation to earlier failures

The prior [aggregate qualification](aggregate-qualification-20261119.md) records
a separate SIGKILL after 1,729.332 seconds on `bffcfa99`; the
[generation 33 receipt](generation33-qualification-20261120.md) records another
after 563.257508 seconds on `a024f9ec`. Their sources, progress observations,
and failure evidence remain distinct. Earlier isolated passes and hosted
successes do not turn this newer attempt into a full-suite pass. This attempt's
phase plugin provides a narrower last-observed interval than progress dots,
but still does not identify the source of SIGKILL.

## Required next step

Qualify the final published candidate on a supported hosted runner using the
existing `.github/workflows/qa-windows.yml` full QA matrix. Resolve its actual
checkout commit and compare its tree with the intended candidate; retain full
JUnit, final exit status, dependency/Ruff results, and source identity. If an
appropriate run already exists, inspect it instead of dispatching duplicates.
The required command remains:

```sh
QT_QPA_PLATFORM=offscreen python -m pytest -q --junitxml=qa-results.xml
python -m ruff check src tests tools
```

If a supported runner also receives SIGKILL, preserve per-node/phase observations,
fine-grained process/container resources, and the runner/kernel termination
receipt before proposing a cause. Do not reduce the 100,000-row fixture, split
the suite and call it an unsplit pass, add a skip, increase a gate budget, or
repeat the same local aggregate blindly. Hosted full QA remains separate from
native Windows, packaging, manual accessibility, and release acceptance.

## Durable evidence

[Self-contained evidence archive](evidence/full-suite-stop-20261120-2bad.zip):

- SHA-256: `3bfe488280ba6cb5f2cf1021c95b153459215772def8a1ebeb144d71fc04029e`.
- **58,108 bytes**, 20 manifest-listed payloads plus `manifest.json`.
- Original full-run logs/receipts and harness; isolated command, launcher,
  phase/resource samples, stdout and JUnit; exact relevant source snapshots;
  and a concise machine-readable summary.
- Every archived payload was read back and verified against its SHA-256.

Original full stdout SHA-256:
`a92fb2a993d8dc3f0163f680e4e563a92f21d4bfa146795bf0aedd83cc396959`.
Isolated stdout SHA-256:
`4dfe735b61f8b1287a31b55abb606b33eb70f91ba8152b17fe8eecb075caf5d8`.

## Follow-up: other selections also interrupted

A later **43-file affected selection** on clean source
`1d0f60f3004db9e32f314518d5be661b85ef4d71`, complete tree
`9d0fdec1a0f88920f1c3786cb9bbcfd6b87ccfae`, collected **1,012 cases** in a
dedicated editable environment. It also returned **-9**, observed by its
supervisor after **130.052113439 seconds**, without terminal summary or JUnit.
Its initial and final source observations match and are clean. Child high-water
RSS was **477,588 KiB**, below the first full run's 943,372 KiB. The original
full-run and isolated-node receipts above remain unchanged.

The new phase log contains 946 passing call reports and four setup skips. The
last node was:

```text
tests/test_ui_kb_investigation.py::test_close_drops_late_search_result_and_keeps_plain_text
```

Its setup **and call passed**, with the call taking 0.109685 seconds. Its teardown
report is absent. These partial outcomes are not a completed affected-selection
result, and they do not establish a failure in that test's assertions or a
specific teardown function.

### Similar displayed durations are coarsely sampled

Both launchers call `child.poll()` followed by a **ten-second sleep**. The
130.057/130.052-second durations are **exit observation times**, not measured
signal-delivery times. Their close agreement on that polling grid does not
establish a 130-second watchdog.

| Run | Last phase event after initial resource sample | Exit observed |
| --- | --- | --- |
| Full, `84798a04` | 125.788 seconds; 100k-table `logstart`, setup not reported complete | 130.057 seconds |
| Affected, `1d0f60f3` | 122.981 seconds; dialog close test call passed, teardown not reported complete | 130.052 seconds |

Neither interval contains an identified sender or a kill-time resource receipt.
Different RSS peaks do not identify a constant memory threshold or rule out
shared host memory pressure; the later run began with less available system
memory. Its minimum sampled available memory was 1,478,868,992 bytes. Neither
launcher retained CPU-time measurements or limit snapshots from the killed child.

### Shorter bounded selections

The coordinator subsequently ran three disjoint portions of the same 43-file
selection on unchanged clean `1d0f60f3`. These receipts are preserved separately
from both aggregates:

| Batch | Files | Supervisor result | Terminal pytest result |
| --- | --- | --- | --- |
| 1 | 13 | **-9 after 22.714 seconds** | No JUnit or terminal result |
| 2 | 14 | **-9 after 18.610 seconds** | No JUnit or terminal result |
| 3 | 16 | **0 after 41.184 seconds** | **429 passed, 2 native Windows skips**, 431 cases; pytest 39.77 seconds |

These shorter kills defeat a single universal 130-second wall-time explanation
for all observations. They do not establish a common cause or exclude multiple
causes. Those commands also omit the `phase_receipts` plugin, so interruption is
observed without that diagnostic plugin. The bounded supervisor imposes no
subprocess timeout.

The bounded receipts' repeated `child_high_water_rss_kib=257264` comes from
`resource.getrusage(RUSAGE_CHILDREN)` in one sequential supervisor. It is a
cumulative child high-water observation, not an independently measured peak for
each batch. The one completed batch does not qualify either incomplete batch or
the 1,012-case/full-suite aggregate. Its counts overlap earlier selections and
must not be added to their partial progress counts.

### Read-only limit and deadline inspection

This follow-up performed **no additional test run** and changed no limits.
Fresh ordinary Python processes in **both recorded virtual environments** report
soft/hard `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_DATA`, and `RLIMIT_RSS` as unlimited.
`ITIMER_REAL`, `ITIMER_VIRTUAL`, and `ITIMER_PROF` are zero. The current
`PYTEST_ADDOPTS` and `PYTEST_TIMEOUT` variables are absent. These later observations
do not reconstruct the limits, timers, or environment inside any dead pytest
process.

The configured pytest entry points are Hypothesis and pytest-qt; no pytest-timeout
entry point is present. Source inspection at `1d0f60f3` found:

- The diagnostic launchers set no subprocess deadline, resource limit, alarm,
  or kill timer. The phase plugin writes observations only.
- Root `tests/conftest.py` has a 30-second modal-dialog watchdog that rejects a
  dialog and raises an assertion. Its Qt cleanup calls `gc.collect()`.
  `tests/stress/conftest.py` only adds the shared test-builder path.
- `tests/qt_support.py` cancels and joins worker threads with a five-second
  budget, flushes deferred deletion, and asserts on survivors. It does not send
  process-kill signals.
- The selected 120-second controls in `test_gui_core_isolation.py` and
  `test_gui_tasks.py` are `subprocess.run(..., timeout=120)` calls for their own
  child commands. They do not install an aggregate timer. The selected
  `threading.Timer` callbacks set test gates; no delayed kill callback was found.
- Repository `RLIMIT_AS` setters belong to explicit worker self-limits or the
  job supervisor's spawned-child limits. The inspected job kill paths address
  owned child process groups. No `RLIMIT_CPU` setter or shared 120/128/130-second
  in-process kill mechanism was found in the searched repository sources.

This is a bounded source review, not proof that every possible external or
compiled-runtime mechanism is absent. The return codes remain unexplained;
no timeout, OOM, leaked timer, Qt defect, or host policy is assigned as the cause.
No product or test change follows from this evidence. Further local execution
stops; final-source hosted full QA remains required, with runner/kernel
termination records if a supported run also receives a kill signal.

### Comparison evidence

The [comparison archive](evidence/full-suite-stop-comparison-20261120-2bad.zip)
preserves the two interrupted aggregates and bounded-batch receipts, launchers,
phase plugin, exact selections, current limit/plugin observations and probe
source, reproducible limit/signal source-search output, relevant `1d0f60f3`
source snapshots, and a machine-readable comparison. Its manifest records every
payload hash, all verified after writing. See the archive's manifest for sizes
and `comparison.json` for the measured distinctions above.

The interrupted 43-file selection's original stdout SHA-256 is
`54924b91daeb00830b47bc31dbc4c8323c1a58d8daad244bbaf2e0d08b80dda6`.
