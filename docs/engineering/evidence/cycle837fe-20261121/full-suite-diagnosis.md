# Full-suite diagnosis: recorded failure and termination are separate

## Source and original run

The frozen `b51b17615e2c72e167bfec15727336eaf7cfb57f` run ended with child return **-9**, wrapper exit **137**, after **1,417.602 seconds**, at the last printed **83%** progress. Its source was clean and unchanged. There is no terminal pytest summary or requested JUnit file. The original log and receipt remain unchanged in `../full-suite/`.

## The recorded failure is identified

A clean collection of the same source found 24,106 cases. The default terminal outcome stream maps its only `F` to ordinal 11,212: `tests/test_network_consent_guard.py::test_a_local_unix_socket_is_not_network`.

The isolated case fails at `socket.socket(AF_UNIX)` with `PermissionError: [Errno 1] Operation not permitted`, before it enters the project's `NetworkGuard`. A separate standard-library process using Python `-I -S`, with no PatchTrace or site imports and no bind/connect operation, receives the same denial. This establishes an execution-environment Unix-socket restriction; changing the project guard or weakening the test is not warranted by this evidence.

The same case fails in the same way on final candidate `b880c317add4de3ac22c87cd842abb0e7ccc615d`. The network test and guard blobs are byte-identical across these sources.

## The SIGKILL remains unresolved

The next collected case after the final printed outcome is `tests/test_ui_bundle_setup.py::test_verify_full_success_and_hash_failure`. It passes alone on the frozen source and on the final candidate. Its test and UI implementation blobs match. This is a narrow diagnostic, not evidence that this case caused or explains the termination.

The supervisor has no timeout/alarm/kill/resource-limit call; the original relevant process limits were unlimited. Available follow-up evidence contains no signal-sender identity, kernel OOM record, cgroup memory events, or host termination receipt. Cgroup files are not exposed; dmesg access is denied; no kernel journal is available. Later host memory snapshots cannot reconstruct the killed child. See `signal/README.md` for the independent signal investigation.

No OOM, timeout, Qt-regression or host-policy cause is asserted. The Unix-socket failure has no established causal connection to the later SIGKILL.

## Exact targeted outcomes

| Source | Selection | Outcome |
| --- | --- | --- |
| `b51b1761` | Identified Unix-socket case | 1 failed, EPERM |
| `b51b1761` | Next collected UI case | 1 passed |
| `b880c317` | The same two cases | 1 failed (same EPERM), 1 passed |

These selections are diagnostic and are not summed with author, independent-review, or whole-suite counts. Both checkouts remained clean. No source, assertion, limit, skip policy or fixture changed. No target binary or analysis engine executed.

## Qualification and publication

The full local run remains unsuccessful/incomplete. Inspect exact-final-source supported-runner qualification. If a future required run needs more termination evidence, retain low-overhead per-node phase and child resource observations and obtain runner/kernel/host termination records; preserve all existing test contracts and budgets.

Publish only files listed in `publication-manifest.json`. Exclude `source-final/`, which is the isolated investigation checkout.
