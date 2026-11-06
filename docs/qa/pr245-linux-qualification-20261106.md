# Exact-head Linux qualification and environment controls — 2026-11-06

## Actual full-run result

[PR #245](https://github.com/djshellshoxxx/patchtrace/pull/245) head
`4465a0492367d08f324e80b290a594791921691c`, tree `6db3490e96da2a8f0a200d834f8816bc41421f57` was tested without source changes:

**3 failed, 19618 passed, 139 skipped, 6 xfailed, 1 warning in 2537.16s (0:42:17)**

Process exit: `1`. Started `2026-11-06T05:38:49.008845+00:00`; finished
`2026-11-06T06:21:13.902940+00:00`. The ending head/tree were unchanged and the worktree
was clean. This full run is **not green**. The passing controls below are
separate observations and do not change its outcome.

The skipped and expected-failure counts are retained as reported. Live/native
and compiler-dependent acceptance remains blocked where the log records
unavailable external tools or platform prerequisites; those cases are not
compatibility evidence.

Environment: Linux, CPython 3.12.14, repository dev/search/rules dependencies,
`QT_QPA_PLATFORM=offscreen`, `PYTHONPATH=src`. The full command was
`python -m pytest -q --junitxml=...`; no test exclusions or injected skips were
used. [Exact metadata and package versions](consolidation-20261106/pr245-linux-result.json).

[Complete pytest log, gzip archive](consolidation-20261106/pr245-linux-pytest.log.gz), uncompressed SHA-256:
`ef5c30d69e0078371b3622ee1df62a93154f16158f83d6f4f8d1aadc0ee8e279`.

## All three failures investigated against frozen #205

The same individual failures reproduce on frozen #205
`f33e2a0aaa3399644367f2419fee21cfe2e8702b`. The relevant test and production
files are byte-identical between that baseline and #245. The
[machine-readable diagnoses](consolidation-20261106/environment-diagnoses.json)
record exact blobs, interpreter prefixes, direct controls and actual outcomes.

| Test | Observed cause | Separate control and remaining requirement |
|---|---|---|
| `test_pure_python_runtime_is_refused_in_a_fresh_interpreter` | `Path(sys.executable).resolve()` escapes the symlink-based venv into its base interpreter, which lacks protobuf. The runtime correctly reports `protobuf_missing` before the intended `protobuf_not_upb` check. | The unchanged complete isolation file passes **28 tests in 30.07 s** under a copied interpreter that retains its venv prefix. Runtime refusal, memory limits, cancellation and concurrent-process isolation remain enforced. |
| `test_a_local_unix_socket_is_not_network` | This execution environment raises `PermissionError: [Errno 1] Operation not permitted` while constructing an AF_UNIX socket, before bind/listen or entering the network guard. | Fresh stdlib-only processes reproduce the restriction in both environments. The test needs a runner that permits local Unix sockets. No enforcement mechanism is inferred and no guard/permission override or skip was introduced. |
| `test_parent_never_imports_yara_x` | The same resolved-interpreter escape leaves the positive-control child without YARA-X although the parent venv has version 1.21.0. The positive control correctly detects that inconsistency. | The unchanged test passes **1 test in 1.89 s** under the copied interpreter, with the engine available to the real worker and the parent-isolation assertions intact. |

The copied environment uses a real Python executable and its own dependency
directory link to the already installed pinned packages. No package install,
shared-environment mutation, test change or production change was needed.
Corrected probes used `PYTHONDONTWRITEBYTECODE=1`.

Raw controls: [Protobuf isolation](consolidation-20261106/binexport-copied-launcher.log),
[YARA parent isolation](consolidation-20261106/rules-worker-copied-launcher.log),
and [stdlib socket construction](consolidation-20261106/unix-socket-stdlib-probe.json).
The socket probe only constructs/closes sockets; it does not bind, listen,
connect or perform DNS.

## Separate combined-candidate verification

The newer #244 consolidation includes #245 plus the reviewed KB admission-index
repair and historical documentation reconciliation. Its tested source tree
`3e5276d6643d784e459264d6cb213082b812c8d4`, published as
`a502c9c241d855dba530160e19215d802ebaf90f`, passed **774 tests in 37.31 s**,
with no skips/expected failures, whole-tree Ruff and no schema drift.
[Combined focused log](consolidation-20261106/combined-focused.log).
That selection overlaps earlier focused runs and is not a full-suite pass.
This complete #245 run must not be attributed to the newer #244 source tree.

## Promotion boundary

The recovery fixes and KB provenance repair have reviewed, passing focused
evidence. Full Linux qualification on a suitable runner, native Windows
qualification, applicable current-head hosted checks, parent Sonar dispositions
and normal review requirements remain distinct gates. No failing status is
waived by this diagnosis. The separate #204 main merge still awaits its two
Linux smoke jobs. No main or frozen owner branch was moved by this task.
