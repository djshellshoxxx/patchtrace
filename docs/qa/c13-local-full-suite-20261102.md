# C13 local full-suite follow-up — 2026-11-02

Source: `c13d3257c88140c23fb585a8a59a4dce81e81928`; tree:
`f2a6d7681c6b7c9508b57ec22387b0f7ad620c25`. The isolated environment passed
`pip check` before the serial run.

## Full-run result

Command:

```text
QT_QPA_PLATFORM=offscreen .venv-continuation/bin/python -m pytest -q \
  --junitxml=/tmp/patchtrace-c13-full-qa.xml
```

Result: **19,497 passed, 128 skipped, 7 xfailed, 3 failed** in 2,238.21 s
(37:18). This run is not a clean pass. The raw console log and JUnit XML are
retained locally; they are not included in this public checkpoint.

## Failure disposition and focused follow-up

1. `test_sigkill_during_creation_is_recycled_by_the_next_create` assumed the
   destination database already existed when an input inspector was paused.
   Current `ProjectService.create` validates artifacts and commits its first
   snapshot in private staging before it touches the destination. The test now
   checks that a hard-killed staged create leaves the chosen destination absent,
   then retries creation successfully. The full stress recovery file passed:
   **7 passed in 1.25 s**.
2. `test_guarded_counts_preserve_raw_text_and_exact_precedence_through_real_ingestion`
   spawned a subprocess that could not import the test helper because this run
   omitted the documented `PYTHONPATH=.:src:tests`. The exact test passed when
   rerun with that environment.
3. `test_a_local_unix_socket_is_not_network` was denied by the container with
   `PermissionError: [Errno 1] Operation not permitted` while creating
   `AF_UNIX`. This is a host restriction, not a PatchTrace assertion; no socket
   guard or test was weakened.

After the test correction, whole-repository Ruff and `git diff --check` passed.
The focused reruns do not replace a full run on the corrected source. A fresh
combined full run and exact-head Windows, Qt, native, package and quality gates
remain required. No release acceptance is claimed.
